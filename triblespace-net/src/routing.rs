//! Bounded, transport-independent XOR routing.
//!
//! The table distinguishes identities merely named by another peer from peers
//! that answered a direct, authenticated request.  The lookup machine likewise
//! makes no network decisions: it yields a bounded batch and waits for its
//! caller to report either an authenticated response or a failure.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::clock::Mono;
use crate::transport::PeerId;

/// An arbitrary point in the 256-bit XOR keyspace.
pub(crate) type RoutingKey = [u8; 32];
/// Number of peers retained in one XOR-distance bucket.
pub(crate) const K: usize = 20;
/// Maximum number of concurrent requests in one iterative lookup.
pub(crate) const ALPHA: usize = 3;
const BUCKET_COUNT: usize = std::mem::size_of::<PeerId>() * 8;
const ROUTING_CAPACITY: usize = BUCKET_COUNT * K;
const MAX_LOOKUP_QUERIES: usize = ROUTING_CAPACITY;
const LEARNED_ROUTE_FAILURE_COOLDOWN: std::time::Duration = crate::RETRY_BACKOFF_CAP;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteState {
    /// The identity was configured locally or named by another peer.
    Candidate,
    /// The peer answered a direct request whose transport and capability were
    /// authenticated by the caller.
    Verified,
}

#[derive(Default)]
struct Bucket {
    entries: BTreeMap<PeerId, RouteState>,
    /// At most K recent local failures, independently of positive-route
    /// retention. Third-party referrals cannot erase or extend these deadlines.
    failed_until: BTreeMap<PeerId, Mono>,
}

/// A deterministic, hard-bounded Kademlia-style routing table.
///
/// Each peer occupies the bucket selected by the most significant bit in its
/// XOR distance from `local`. A bucket retains at most [`K`] positive routes
/// and independently at most [`K`] recent learned-route failure deadlines.
/// Verified peers take precedence over candidates; ties are resolved by XOR
/// distance from the local peer and then by identity.  Consequently inserting
/// the same evidence in a different order produces the same table. Explicit
/// local configuration is retained separately and is expected to be bounded
/// by the caller rather than by rules for hostile learned state.
pub(crate) struct RoutingTable {
    local: PeerId,
    /// Explicit local configuration is trusted provenance, not hostile learned
    /// state. It remains available even if the corresponding learned route is
    /// evicted or a connection attempt fails.
    configured: BTreeSet<PeerId>,
    buckets: [Bucket; BUCKET_COUNT],
}

impl RoutingTable {
    /// Start with locally configured bootstrap identities as unverified
    /// candidates.  Configuration does not manufacture proof of reachability.
    pub(crate) fn new<I>(local: PeerId, configured: I) -> Self
    where
        I: IntoIterator<Item = PeerId>,
    {
        let configured = configured
            .into_iter()
            .filter(|peer| *peer != local)
            .collect();
        Self {
            local,
            configured,
            buckets: std::array::from_fn(|_| Bucket::default()),
        }
    }

    /// Remember an unverified identity without demoting an already verified
    /// route. Cooling learned routes are not admitted. Returns whether the
    /// identity survived admission and the positive-route bucket bound.
    pub(crate) fn note_candidate(&mut self, peer: PeerId) -> bool {
        if !self.query_eligible(peer, crate::clock::mono_now()) {
            return false;
        }
        if self.configured.contains(&peer) {
            return true;
        }
        self.insert(peer, RouteState::Candidate)
    }

    /// Promote a peer only after the caller observed a direct authenticated
    /// response. Returns whether the identity survived the bucket bound.
    pub(crate) fn promote_authenticated(&mut self, peer: PeerId) -> bool {
        if let Some(bucket) = bucket_index(self.local, peer) {
            self.buckets[bucket].failed_until.remove(&peer);
        }
        self.insert(peer, RouteState::Verified)
    }

    /// A local failed request outweighs unverified gossip for a finite window.
    /// Explicit configuration remains eligible, including cold bootstraps.
    /// This predicate is independent of positive-route bucket admission.
    fn query_eligible(&self, peer: PeerId, now: Mono) -> bool {
        self.configured.contains(&peer)
            || bucket_index(self.local, peer)
                .and_then(|bucket| self.buckets[bucket].failed_until.get(&peer))
                .is_none_or(|until| now >= *until)
    }

    fn note_failure(&mut self, peer: PeerId, now: Mono) {
        self.remove(peer);
        if self.configured.contains(&peer) {
            return;
        }
        let Some(bucket) = bucket_index(self.local, peer) else {
            return;
        };
        let failures = &mut self.buckets[bucket].failed_until;
        // Expiry work and eviction inspect at most K entries in this bucket,
        // never a process-wide peer inventory. Positive-route eviction does
        // not erase recent failure evidence, nor does referral insertion.
        failures.retain(|_, until| now < *until);
        failures.insert(peer, now + LEARNED_ROUTE_FAILURE_COOLDOWN);
        if failures.len() > K {
            let oldest = *failures
                .iter()
                .min_by_key(|(peer, until)| (**until, **peer))
                .expect("an overfull failure bucket is nonempty")
                .0;
            failures.remove(&oldest);
        }
    }

    /// Remove failed learned evidence. Explicit local configuration survives
    /// and becomes an unverified candidate again.
    pub(crate) fn remove(&mut self, peer: PeerId) -> bool {
        let Some(bucket) = bucket_index(self.local, peer) else {
            return false;
        };
        self.buckets[bucket].entries.remove(&peer).is_some()
    }

    #[cfg(test)]
    pub(crate) fn state(&self, peer: PeerId) -> Option<RouteState> {
        let learned = bucket_index(self.local, peer)
            .and_then(|bucket| self.buckets[bucket].entries.get(&peer).copied());
        learned.or_else(|| {
            self.configured
                .contains(&peer)
                .then_some(RouteState::Candidate)
        })
    }

    #[cfg(test)]
    /// Number of unique configured and learned identities.
    pub(crate) fn len(&self) -> usize {
        self.all().len()
    }

    #[cfg(test)]
    pub(crate) fn learned_len(&self) -> usize {
        self.buckets.iter().map(|bucket| bucket.entries.len()).sum()
    }

    #[cfg(test)]
    pub(crate) fn configured_len(&self) -> usize {
        self.configured.len()
    }

    /// Return at most `limit` known identities ordered by XOR distance from
    /// `target`. Candidate status does not affect distance order.
    pub(crate) fn closest(&self, target: RoutingKey, limit: usize) -> Vec<PeerId> {
        let mut peers = self.all();
        peers.sort_unstable_by(|a, b| distance_cmp(target, *a, *b));
        peers.truncate(limit);
        peers
    }

    /// Like [`Self::closest`], but excludes identities that have never
    /// answered this process directly.
    pub(crate) fn closest_verified(&self, target: RoutingKey, limit: usize) -> Vec<PeerId> {
        let mut peers: Vec<_> =
            self.buckets
                .iter()
                .flat_map(|bucket| {
                    bucket.entries.iter().filter_map(|(peer, state)| {
                        (*state == RouteState::Verified).then_some(*peer)
                    })
                })
                .collect();
        peers.sort_unstable_by(|a, b| distance_cmp(target, *a, *b));
        peers.truncate(limit);
        peers
    }

    fn all(&self) -> Vec<PeerId> {
        let mut peers = self.configured.clone();
        for peer in self
            .buckets
            .iter()
            .flat_map(|bucket| bucket.entries.keys().copied())
        {
            peers.insert(peer);
        }
        let now = crate::clock::mono_now();
        peers
            .into_iter()
            .filter(|peer| self.query_eligible(*peer, now))
            .collect()
    }

    fn insert(&mut self, peer: PeerId, state: RouteState) -> bool {
        let Some(index) = bucket_index(self.local, peer) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        bucket
            .entries
            .entry(peer)
            .and_modify(|old| {
                if state == RouteState::Verified {
                    *old = RouteState::Verified;
                }
            })
            .or_insert(state);

        if bucket.entries.len() > K {
            let mut ranked: Vec<_> = bucket
                .entries
                .iter()
                .map(|(peer, state)| (*peer, *state))
                .collect();
            ranked.sort_unstable_by(|(a, a_state), (b, b_state)| {
                route_rank(*a_state)
                    .cmp(&route_rank(*b_state))
                    .then_with(|| distance_cmp(self.local, *a, *b))
            });
            let retained: BTreeSet<_> = ranked.into_iter().take(K).map(|(peer, _)| peer).collect();
            bucket.entries.retain(|peer, _| retained.contains(peer));
        }
        bucket.entries.contains_key(&peer)
    }

    #[cfg(test)]
    fn bucket_len(&self, index: usize) -> usize {
        self.buckets[index].entries.len()
    }
}

fn route_rank(state: RouteState) -> u8 {
    match state {
        RouteState::Verified => 0,
        RouteState::Candidate => 1,
    }
}

fn bucket_index(local: PeerId, peer: PeerId) -> Option<usize> {
    for (byte_index, (&local, &peer)) in local.iter().zip(&peer).enumerate() {
        let distance = local ^ peer;
        if distance != 0 {
            let bit_in_byte = 7 - distance.leading_zeros() as usize;
            return Some((std::mem::size_of::<PeerId>() - 1 - byte_index) * 8 + bit_in_byte);
        }
    }
    None
}

pub(crate) fn distance_cmp(target: RoutingKey, a: PeerId, b: PeerId) -> Ordering {
    a.iter()
        .zip(b)
        .zip(target)
        .map(|((&a, b), target)| (a ^ target).cmp(&(b ^ target)))
        .find(|ordering| !ordering.is_eq())
        .unwrap_or_else(|| a.cmp(&b))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupState {
    Pending,
    InFlight,
    Responded,
}

/// A synchronous control plane for one iterative XOR lookup.
///
/// The caller may issue every peer returned by [`Self::next_batch`] in
/// parallel.  It must eventually report each as either an authenticated
/// response or a failure. Candidate replies never verify their named peers;
/// only the peer that directly answered is promoted.
pub(crate) struct IterativeLookup {
    local: PeerId,
    target: RoutingKey,
    shortlist: BTreeMap<PeerId, LookupState>,
    queried: BTreeSet<PeerId>,
    authenticated_responders: Vec<PeerId>,
}

impl IterativeLookup {
    pub(crate) fn new<I>(local: PeerId, target: RoutingKey, seeds: I) -> Self
    where
        I: IntoIterator<Item = PeerId>,
    {
        let mut lookup = Self {
            local,
            target,
            shortlist: BTreeMap::new(),
            queried: BTreeSet::new(),
            authenticated_responders: Vec::new(),
        };
        lookup.add_candidates(bounded_closest(target, local, seeds));
        lookup.trim_shortlist();
        lookup
    }

    /// Mark and return the next closest batch, never exceeding [`ALPHA`]
    /// concurrent requests. An empty batch with `is_finished() == false`
    /// means earlier requests are still in flight.
    pub(crate) fn next_batch(&mut self) -> Vec<PeerId> {
        self.next_batch_up_to(ALPHA)
    }

    /// Mark and return only requests that fit the caller's available slots,
    /// the remaining [`ALPHA`] capacity, and the lookup's query budget. Apply
    /// these limits before marking any peer queried or in flight. An empty
    /// batch can leave pending candidates when the caller has no capacity.
    pub(crate) fn next_batch_up_to(&mut self, available: usize) -> Vec<PeerId> {
        if self.queried.len() >= MAX_LOOKUP_QUERIES {
            self.shortlist
                .retain(|_, state| *state == LookupState::InFlight);
            return Vec::new();
        }

        let in_flight = self
            .shortlist
            .values()
            .filter(|state| **state == LookupState::InFlight)
            .count();
        let available = available.min(ALPHA.saturating_sub(in_flight));
        if available == 0 {
            return Vec::new();
        }

        let mut pending: Vec<_> = self
            .shortlist
            .iter()
            .filter_map(|(peer, state)| (*state == LookupState::Pending).then_some(*peer))
            .collect();
        pending.sort_unstable_by(|a, b| distance_cmp(self.target, *a, *b));
        pending.truncate(available.min(MAX_LOOKUP_QUERIES.saturating_sub(self.queried.len())));
        for peer in &pending {
            self.shortlist.insert(*peer, LookupState::InFlight);
            self.queried.insert(*peer);
        }
        pending
    }

    /// Accept a bounded FIND_NODE reply from a peer in the current batch.
    ///
    /// `candidates` may itself be oversized or duplicate-heavy; only its
    /// deterministic [`K`] closest distinct identities are retained. The
    /// responding peer is promoted, while every identity it names remains a
    /// candidate until that identity answers directly in a later batch.
    pub(crate) fn record_authenticated_response<I>(
        &mut self,
        peer: PeerId,
        candidates: I,
        routes: &mut RoutingTable,
    ) -> bool
    where
        I: IntoIterator<Item = PeerId>,
    {
        if self.shortlist.get(&peer) != Some(&LookupState::InFlight) {
            return false;
        }

        self.shortlist.insert(peer, LookupState::Responded);
        self.authenticated_responders = bounded_closest(
            self.target,
            self.local,
            self.authenticated_responders
                .iter()
                .copied()
                .chain(std::iter::once(peer)),
        );
        routes.promote_authenticated(peer);
        let now = crate::clock::mono_now();
        let candidates = bounded_closest(
            self.target,
            self.local,
            candidates
                .into_iter()
                .filter(|candidate| routes.query_eligible(*candidate, now)),
        );
        for candidate in &candidates {
            routes.note_candidate(*candidate);
        }
        self.add_candidates(candidates);
        self.trim_shortlist();
        true
    }

    /// Complete one in-flight request as failed, remove its stale route, and
    /// retain bounded local failure evidence across subsequent referrals.
    pub(crate) fn record_failure(&mut self, peer: PeerId, routes: &mut RoutingTable) -> bool {
        if self.shortlist.get(&peer) != Some(&LookupState::InFlight) {
            return false;
        }
        self.shortlist.remove(&peer);
        routes.note_failure(peer, crate::clock::mono_now());
        self.trim_shortlist();
        true
    }

    /// Fail issued requests still pending when the routing deadline expires.
    /// Unissued candidates and authenticated responders retain their evidence;
    /// failed configured peers remain available through explicit configuration.
    pub(crate) fn record_timeouts(&mut self, routes: &mut RoutingTable) -> usize {
        let in_flight: Vec<_> = self
            .shortlist
            .iter()
            .filter_map(|(peer, state)| (*state == LookupState::InFlight).then_some(*peer))
            .collect();
        for peer in &in_flight {
            self.record_failure(*peer, routes);
        }
        in_flight.len()
    }

    pub(crate) fn is_finished(&self) -> bool {
        let has_in_flight = self
            .shortlist
            .values()
            .any(|state| *state == LookupState::InFlight);
        let has_pending = self
            .shortlist
            .values()
            .any(|state| *state == LookupState::Pending);
        !has_in_flight && (!has_pending || self.queried.len() >= MAX_LOOKUP_QUERIES)
    }

    /// The at-most-K peers closest to the target that answered this lookup
    /// directly and authenticated successfully. This lookup-local evidence is
    /// independent of later routing-table eviction.
    pub(crate) fn closest_authenticated_responders(&self) -> &[PeerId] {
        &self.authenticated_responders
    }

    #[cfg(test)]
    fn shortlist_len(&self) -> usize {
        self.shortlist.len()
    }

    fn add_candidates<I>(&mut self, candidates: I)
    where
        I: IntoIterator<Item = PeerId>,
    {
        for peer in candidates {
            if peer != self.local && !self.queried.contains(&peer) {
                self.shortlist.entry(peer).or_insert(LookupState::Pending);
            }
        }
    }

    fn trim_shortlist(&mut self) {
        let mut ranked: Vec<_> = self
            .shortlist
            .iter()
            .filter_map(|(peer, state)| (*state != LookupState::InFlight).then_some(*peer))
            .collect();
        ranked.sort_unstable_by(|a, b| distance_cmp(self.target, *a, *b));
        let retained: BTreeSet<_> = ranked.into_iter().take(K).collect();
        self.shortlist
            .retain(|peer, state| *state == LookupState::InFlight || retained.contains(peer));
    }
}

/// Select a bounded, order-independent set from an untrusted iterator without
/// first collecting the whole reply.
fn bounded_closest<I>(target: RoutingKey, local: PeerId, peers: I) -> Vec<PeerId>
where
    I: IntoIterator<Item = PeerId>,
{
    let mut closest = Vec::with_capacity(K);
    for peer in peers {
        if peer == local || closest.contains(&peer) {
            continue;
        }
        let position = closest
            .binary_search_by(|known| distance_cmp(target, *known, peer))
            .unwrap_or_else(|position| position);
        if position < K {
            closest.insert(position, peer);
            closest.truncate(K);
        }
    }
    closest
}

#[cfg(test)]
#[path = "routing/warm_start.rs"]
mod warm_start;

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::Instant;

    use super::*;

    fn id(n: u16) -> PeerId {
        let mut id = [0; 32];
        id[30..].copy_from_slice(&n.to_be_bytes());
        id
    }

    fn drive_lookup(
        local: PeerId,
        target: RoutingKey,
        seeds: Vec<PeerId>,
        network: &BTreeMap<PeerId, Vec<PeerId>>,
    ) -> (RoutingTable, Vec<PeerId>) {
        let mut routes = RoutingTable::new(local, seeds.clone());
        let mut lookup = IterativeLookup::new(local, target, seeds);
        let mut contacted = Vec::new();
        while !lookup.is_finished() {
            let batch = lookup.next_batch();
            assert!(!batch.is_empty(), "driver has no abandoned in-flight work");
            for peer in batch {
                contacted.push(peer);
                if let Some(reply) = network.get(&peer) {
                    assert!(lookup.record_authenticated_response(
                        peer,
                        reply.iter().copied(),
                        &mut routes
                    ));
                } else {
                    assert!(lookup.record_failure(peer, &mut routes));
                }
            }
        }
        (routes, contacted)
    }

    #[derive(Clone, Copy, Debug)]
    enum ProbeTopology {
        Full,
        Ring,
        XorBuckets,
    }

    impl ProbeTopology {
        fn name(self) -> &'static str {
            match self {
                Self::Full => "full",
                Self::Ring => "ring",
                Self::XorBuckets => "xor-buckets",
            }
        }
    }

    enum ProbeNetwork {
        Full(Vec<PeerId>),
        Links(BTreeMap<PeerId, Vec<PeerId>>),
    }

    impl ProbeNetwork {
        fn new(topology: ProbeTopology, peers: &[PeerId]) -> Self {
            match topology {
                ProbeTopology::Full => Self::Full(peers.to_vec()),
                ProbeTopology::Ring => {
                    let mut ordered = peers.to_vec();
                    ordered.sort_unstable();
                    let mut links = BTreeMap::new();
                    for (index, peer) in ordered.iter().copied().enumerate() {
                        let mut neighbors = BTreeSet::new();
                        for step in 1..ordered.len() {
                            neighbors.insert(ordered[(index + step) % ordered.len()]);
                            if neighbors.len() == K {
                                break;
                            }
                            neighbors
                                .insert(ordered[(index + ordered.len() - step) % ordered.len()]);
                            if neighbors.len() == K {
                                break;
                            }
                        }
                        links.insert(peer, neighbors.into_iter().collect());
                    }
                    Self::Links(links)
                }
                ProbeTopology::XorBuckets => {
                    let mut links = BTreeMap::new();
                    for peer in peers.iter().copied() {
                        let mut routes = RoutingTable::new(peer, []);
                        for candidate in peers.iter().copied() {
                            routes.note_candidate(candidate);
                        }
                        links.insert(peer, routes.all());
                    }
                    Self::Links(links)
                }
            }
        }

        fn reply(&self, peer: PeerId, target: RoutingKey) -> Vec<PeerId> {
            let candidates: &[PeerId] = match self {
                Self::Full(peers) => peers,
                Self::Links(links) => links
                    .get(&peer)
                    .expect("every synthetic peer has a routing view"),
            };
            bounded_closest(target, peer, candidates.iter().copied())
        }
    }

    struct ProbeLookup {
        requests: usize,
        rounds: usize,
        contacted: BTreeSet<PeerId>,
        first_batch: BTreeSet<PeerId>,
    }

    fn probe_lookup(network: &ProbeNetwork, local: PeerId, target: RoutingKey) -> ProbeLookup {
        let seeds = network.reply(local, target);
        let mut routes = RoutingTable::new(local, seeds.iter().copied());
        let mut lookup = IterativeLookup::new(local, target, seeds);
        let mut contacted = BTreeSet::new();
        let mut first_batch = BTreeSet::new();
        let mut requests = 0;
        let mut rounds = 0;
        while !lookup.is_finished() {
            let batch = lookup.next_batch();
            assert!(!batch.is_empty(), "probe has no abandoned in-flight work");
            if rounds == 0 {
                first_batch.extend(batch.iter().copied());
            }
            rounds += 1;
            requests += batch.len();
            for peer in batch {
                contacted.insert(peer);
                assert!(lookup.record_authenticated_response(
                    peer,
                    network.reply(peer, target),
                    &mut routes,
                ));
            }
        }
        black_box(lookup.closest_authenticated_responders());
        ProbeLookup {
            requests,
            rounds,
            contacted,
            first_batch,
        }
    }

    fn probe_bytes(domain: &'static str, index: usize) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(&(index as u64).to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    fn probe_targets(count: usize, shared_prefix_bits: usize) -> Vec<RoutingKey> {
        assert!(shared_prefix_bits <= 240 && shared_prefix_bits.is_multiple_of(8));
        let base = probe_bytes("triblespace.net/lookup-probe-target-base/v1", 0);
        let prefix_bytes = shared_prefix_bits / 8;
        let suffix_bytes = 32 - prefix_bytes;
        if suffix_bytes < std::mem::size_of::<usize>() {
            assert!(count <= 1_usize << (suffix_bytes * 8));
        }
        (0..count)
            .map(|index| {
                let mut target = probe_bytes("triblespace.net/lookup-probe-target/v1", index);
                target[..prefix_bytes].copy_from_slice(&base[..prefix_bytes]);
                let index = (index as u64).to_be_bytes();
                let copied = suffix_bytes.min(index.len());
                target[32 - copied..].copy_from_slice(&index[index.len() - copied..]);
                target
            })
            .collect()
    }

    fn adjacent_jaccard(sets: &[BTreeSet<PeerId>]) -> f64 {
        if sets.len() < 2 {
            return 0.0;
        }
        sets.windows(2)
            .map(|pair| {
                let intersection = pair[0].intersection(&pair[1]).count();
                let union = pair[0].union(&pair[1]).count();
                intersection as f64 / union as f64
            })
            .sum::<f64>()
            / (sets.len() - 1) as f64
    }

    fn scale_parameter(name: &str, default: usize) -> usize {
        std::env::var(name).map_or(default, |value| {
            value
                .parse::<usize>()
                .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}"))
        })
    }

    #[test]
    fn bucket_indices_follow_xor_magnitude() {
        let local = [0; 32];
        assert_eq!(bucket_index(local, local), None);
        assert_eq!(bucket_index(local, id(1)), Some(0));
        assert_eq!(bucket_index(local, id(2)), Some(1));
        let mut high = [0; 32];
        high[0] = 0x80;
        assert_eq!(bucket_index(local, high), Some(255));
    }

    #[test]
    fn configured_routes_start_as_candidates_and_self_is_ignored() {
        let local = id(1);
        let table = RoutingTable::new(local, [local, id(2), id(2)]);
        assert_eq!(table.len(), 1);
        assert_eq!(table.configured_len(), 1);
        assert_eq!(table.learned_len(), 0);
        assert_eq!(table.state(local), None);
        assert_eq!(table.state(id(2)), Some(RouteState::Candidate));
        assert!(table.closest_verified(id(2), K).is_empty());
        assert_eq!(table.closest(id(2), K), vec![id(2)]);
    }

    #[test]
    fn direct_response_promotes_only_the_responder() {
        let local = id(0);
        let seed = id(1);
        let named = id(2);
        let mut routes = RoutingTable::new(local, [seed]);
        let mut lookup = IterativeLookup::new(local, named, [seed]);
        assert_eq!(lookup.next_batch(), vec![seed]);
        assert!(lookup.record_authenticated_response(seed, [named], &mut routes));
        assert_eq!(routes.state(seed), Some(RouteState::Verified));
        assert_eq!(routes.state(named), Some(RouteState::Candidate));

        assert_eq!(lookup.next_batch(), vec![named]);
        assert!(lookup.record_authenticated_response(named, [], &mut routes));
        assert_eq!(routes.state(named), Some(RouteState::Verified));
        assert!(lookup.is_finished());
    }

    #[test]
    fn learned_failure_cooldown_survives_gossip_and_expires() {
        let now = crate::clock::mono_now();
        let local = id(0);
        let peer = id(2);
        let mut routes = RoutingTable::new(local, []);
        routes.promote_authenticated(peer);
        routes.note_failure(peer, now);
        let until = now + LEARNED_ROUTE_FAILURE_COOLDOWN;
        let bucket = bucket_index(local, peer).unwrap();
        for _ in 0..3 {
            assert!(!routes.note_candidate(peer));
            assert!(!routes.closest(peer, K).contains(&peer));
            assert_eq!(routes.buckets[bucket].failed_until[&peer], until);
        }
        assert!(!routes.query_eligible(peer, now));
        assert!(!routes.query_eligible(
            peer,
            now + (LEARNED_ROUTE_FAILURE_COOLDOWN - std::time::Duration::from_nanos(1))
        ));
        assert!(routes.query_eligible(peer, until));
    }

    #[test]
    fn direct_authenticated_recovery_clears_learned_failure_cooldown() {
        let now = crate::clock::mono_now();
        let peer = id(2);
        let mut routes = RoutingTable::new(id(0), []);
        routes.note_failure(peer, now);
        assert!(!routes.query_eligible(peer, now));
        assert!(routes.promote_authenticated(peer));
        assert!(routes.query_eligible(peer, now));
        assert_eq!(routes.state(peer), Some(RouteState::Verified));
        assert_eq!(routes.closest(peer, K), vec![peer]);
    }

    #[test]
    fn explicit_configuration_remains_eligible_after_local_failure() {
        let now = crate::clock::mono_now();
        let peer = id(2);
        let mut routes = RoutingTable::new(id(0), [peer]);
        routes.promote_authenticated(peer);
        routes.note_failure(peer, now);
        assert!(routes.query_eligible(peer, now));
        assert!(routes.note_candidate(peer));
        assert_eq!(routes.state(peer), Some(RouteState::Candidate));
        assert_eq!(routes.closest(peer, K), vec![peer]);
        assert!(
            routes
                .buckets
                .iter()
                .all(|bucket| bucket.failed_until.is_empty())
        );
    }

    #[test]
    fn referral_cooldown_is_independent_of_positive_bucket_retention() {
        let local = id(0);
        let seed = id(1);
        let named = id(0xFFFF);
        let mut routes = RoutingTable::new(local, [seed]);
        for n in 0x8000..0x8000 + K as u16 {
            routes.promote_authenticated(id(n));
        }
        assert!(!routes.note_candidate(named));
        assert!(routes.query_eligible(named, crate::clock::mono_now()));

        // Healthy lookup-local referrals remain usable even when the long-lived
        // table's local-distance bucket cannot retain them.
        let mut first = IterativeLookup::new(local, named, [seed]);
        assert_eq!(first.next_batch(), vec![seed]);
        assert!(first.record_authenticated_response(seed, [named], &mut routes));
        assert_eq!(first.next_batch(), vec![named]);
        assert!(first.record_failure(named, &mut routes));
        assert_eq!(routes.state(named), None);

        // The same referral cannot bypass actual local failure evidence just
        // because the positive route was never retained.
        let mut second = IterativeLookup::new(local, named, [seed]);
        assert_eq!(second.next_batch(), vec![seed]);
        assert!(second.record_authenticated_response(seed, [named], &mut routes));
        assert!(second.next_batch().is_empty());
        assert!(second.is_finished());

        // Direct recovery also clears failure evidence independently of whether
        // that verified route survives the positive bucket's distance bound.
        assert!(!routes.promote_authenticated(named));
        let mut recovered = IterativeLookup::new(local, named, [seed]);
        assert_eq!(recovered.next_batch(), vec![seed]);
        assert!(recovered.record_authenticated_response(seed, [named], &mut routes));
        assert_eq!(recovered.next_batch(), vec![named]);
    }

    #[test]
    fn learned_failure_memory_is_bounded_and_expiry_reclamation_is_bucket_local() {
        let now = crate::clock::mono_now();
        let local = id(0);
        let mut routes = RoutingTable::new(local, []);
        let bucket = bucket_index(local, id(0x8000)).unwrap();
        for n in 0..(K * 3) as u16 {
            routes.note_failure(
                id(0x8000 + n),
                now + std::time::Duration::from_nanos(u64::from(n)),
            );
            assert!(routes.buckets[bucket].failed_until.len() <= K);
        }
        assert_eq!(routes.buckets[bucket].failed_until.len(), K);
        assert_eq!(routes.learned_len(), 0);
        assert!(!routes.query_eligible(id(0x8000 + (K * 3 - 1) as u16), now));

        routes.note_failure(
            id(0xA000),
            now + LEARNED_ROUTE_FAILURE_COOLDOWN + std::time::Duration::from_secs(1),
        );
        assert_eq!(routes.buckets[bucket].failed_until.len(), 1);
        assert_eq!(
            routes
                .buckets
                .iter()
                .map(|bucket| bucket.failed_until.len())
                .sum::<usize>(),
            1
        );
    }

    #[test]
    fn routing_bounds_are_hard_and_retention_is_order_independent() {
        let local = [0; 32];
        let mut peers = Vec::new();
        for n in 1..=10_000_u32 {
            let mut peer = *blake3::hash(&n.to_be_bytes()).as_bytes();
            if peer == local {
                peer[31] = 1;
            }
            peers.push(peer);
        }

        let verified: Vec<_> = peers.iter().step_by(7).copied().collect();
        let mut forward = RoutingTable::new(local, []);
        let mut reverse = RoutingTable::new(local, []);
        for peer in &peers {
            forward.note_candidate(*peer);
        }
        for peer in peers.iter().rev() {
            reverse.note_candidate(*peer);
        }
        for peer in &verified {
            forward.promote_authenticated(*peer);
        }
        for peer in verified.iter().rev() {
            reverse.promote_authenticated(*peer);
        }

        assert!(forward.learned_len() <= ROUTING_CAPACITY);
        assert!(reverse.learned_len() <= ROUTING_CAPACITY);
        for index in 0..BUCKET_COUNT {
            assert!(forward.bucket_len(index) <= K);
            assert!(reverse.bucket_len(index) <= K);
        }
        assert_eq!(
            forward.closest([0xff; 32], ROUTING_CAPACITY),
            reverse.closest([0xff; 32], ROUTING_CAPACITY)
        );
        assert_eq!(
            forward.closest_verified([0xff; 32], ROUTING_CAPACITY),
            reverse.closest_verified([0xff; 32], ROUTING_CAPACITY)
        );

        // Candidate insertion alone is likewise independent of observation order.
        let mut forward_candidates = RoutingTable::new(local, []);
        let mut reverse_candidates = RoutingTable::new(local, []);
        for peer in &peers {
            forward_candidates.note_candidate(*peer);
        }
        for peer in peers.iter().rev() {
            reverse_candidates.note_candidate(*peer);
        }
        assert_eq!(
            forward_candidates.closest([0xff; 32], ROUTING_CAPACITY),
            reverse_candidates.closest([0xff; 32], ROUTING_CAPACITY)
        );

        let removed = forward.closest([0xff; 32], 1)[0];
        assert!(forward.remove(removed));
        assert_eq!(forward.state(removed), None);
        assert!(!forward.remove(removed));
    }

    #[test]
    fn closest_is_deterministic_xor_order() {
        let table = RoutingTable::new(id(0), [id(7), id(2), id(5), id(1)]);
        assert_eq!(table.closest(id(4), 3), vec![id(5), id(7), id(1)]);
        assert_eq!(table.closest(id(4), 3), table.closest(id(4), 3));
    }

    #[test]
    fn oversized_duplicate_reply_is_bounded_and_order_independent() {
        let local = id(0);
        let seed = id(1);
        let target = id(600);
        let reply: Vec<_> = (2..=2_000).flat_map(|n| [id(n), id(n)]).collect();

        let mut forward_routes = RoutingTable::new(local, [seed]);
        let mut forward = IterativeLookup::new(local, target, [seed]);
        assert_eq!(forward.next_batch(), vec![seed]);
        assert!(forward.record_authenticated_response(
            seed,
            reply.iter().copied(),
            &mut forward_routes
        ));

        let mut reverse_routes = RoutingTable::new(local, [seed]);
        let mut reverse = IterativeLookup::new(local, target, [seed]);
        assert_eq!(reverse.next_batch(), vec![seed]);
        assert!(reverse.record_authenticated_response(
            seed,
            reply.iter().rev().copied(),
            &mut reverse_routes
        ));

        assert!(forward.shortlist_len() <= K);
        assert!(reverse.shortlist_len() <= K);
        assert_eq!(forward.next_batch(), reverse.next_batch());
    }

    #[test]
    fn sparse_line_discovers_the_target_progressively() {
        let mut network = BTreeMap::new();
        for n in 1..8 {
            network.insert(id(n), vec![id(n + 1)]);
        }
        network.insert(id(8), Vec::new());

        let (routes, contacted) = drive_lookup(id(0), id(8), vec![id(1)], &network);
        assert_eq!(contacted, (1..=8).map(id).collect::<Vec<_>>());
        assert_eq!(routes.state(id(8)), Some(RouteState::Verified));
    }

    #[test]
    fn sparse_ring_discovers_without_requerying() {
        let mut network = BTreeMap::new();
        for n in 1..=9 {
            let previous = if n == 1 { 9 } else { n - 1 };
            let next = if n == 9 { 1 } else { n + 1 };
            network.insert(id(n), vec![id(previous), id(next)]);
        }

        let (_, contacted) = drive_lookup(id(0), id(6), vec![id(1)], &network);
        assert!(contacted.contains(&id(6)));
        assert_eq!(
            contacted.len(),
            contacted.iter().copied().collect::<BTreeSet<_>>().len()
        );
        assert!(contacted.len() <= network.len());
    }

    #[test]
    fn batches_respect_alpha_and_failures_terminate() {
        let local = id(0);
        let seeds: Vec<_> = (1..=K as u16).map(id).collect();
        let mut routes = RoutingTable::new(local, seeds.iter().copied());
        let mut lookup = IterativeLookup::new(local, id(100), seeds);
        let mut contacted = 0;

        while !lookup.is_finished() {
            let batch = lookup.next_batch();
            assert!(!batch.is_empty());
            assert!(batch.len() <= ALPHA);
            contacted += batch.len();
            for peer in batch {
                assert!(lookup.record_failure(peer, &mut routes));
            }
        }
        assert_eq!(contacted, K);
        assert_eq!(routes.learned_len(), 0);
        assert_eq!(routes.configured_len(), K);
        assert_eq!(routes.len(), K);
        assert!((1..=K as u16).all(|n| routes.state(id(n)) == Some(RouteState::Candidate)));
    }

    #[test]
    fn lookup_zero_capacity_leaves_candidates_unissued() {
        let local = id(0);
        let mut routes = RoutingTable::new(local, []);
        for n in 1..=4 {
            routes.promote_authenticated(id(n));
        }
        let mut lookup = IterativeLookup::new(local, local, routes.closest(local, K));

        assert!(lookup.next_batch_up_to(0).is_empty());
        assert!(lookup.queried.is_empty());
        assert!(!lookup.is_finished());
        assert_eq!(lookup.record_timeouts(&mut routes), 0);
        assert!((1..=4).all(|n| routes.state(id(n)) == Some(RouteState::Verified)));
        assert_eq!(lookup.next_batch(), vec![id(1), id(2), id(3)]);
    }

    #[test]
    fn lookup_partial_capacity_never_times_out_unissued_peers() {
        let local = id(0);
        let mut routes = RoutingTable::new(local, []);
        for n in 1..=5 {
            routes.promote_authenticated(id(n));
        }
        let mut lookup = IterativeLookup::new(local, local, routes.closest(local, K));

        assert_eq!(lookup.next_batch_up_to(1), vec![id(1)]);
        assert!(lookup.next_batch_up_to(0).is_empty());
        assert_eq!(lookup.queried, BTreeSet::from([id(1)]));
        assert_eq!(lookup.record_timeouts(&mut routes), 1);
        assert_eq!(routes.state(id(1)), None);
        assert!((2..=5).all(|n| routes.state(id(n)) == Some(RouteState::Verified)));

        assert_eq!(lookup.next_batch_up_to(2), vec![id(2), id(3)]);
        assert!(lookup.record_authenticated_response(id(2), [], &mut routes));
        assert_eq!(lookup.next_batch_up_to(1), vec![id(4)]);
        assert!(!lookup.queried.contains(&id(5)));
        assert!(!lookup.record_authenticated_response(id(5), [], &mut routes));
        assert_eq!(lookup.record_timeouts(&mut routes), 2);
        assert_eq!(routes.state(id(5)), Some(RouteState::Verified));
        assert_eq!(lookup.next_batch_up_to(ALPHA), vec![id(5)]);
    }

    #[test]
    fn lookup_shared_capacity_preserves_alpha_across_refills() {
        let local = id(0);
        let seeds = (1..=6).map(id).collect::<Vec<_>>();
        let mut routes = RoutingTable::new(local, seeds.iter().copied());
        let mut lookup = IterativeLookup::new(local, local, seeds);

        assert_eq!(lookup.next_batch_up_to(2), vec![id(1), id(2)]);
        assert_eq!(lookup.next_batch_up_to(usize::MAX), vec![id(3)]);
        assert!(lookup.next_batch_up_to(1).is_empty());
        assert!(lookup.record_authenticated_response(id(1), [], &mut routes));
        assert_eq!(lookup.next_batch_up_to(1), vec![id(4)]);
        assert!(lookup.next_batch_up_to(usize::MAX).is_empty());
        assert!(lookup.record_authenticated_response(id(2), [], &mut routes));
        assert_eq!(lookup.next_batch(), vec![id(5)]);
        assert_eq!(lookup.record_timeouts(&mut routes), ALPHA);
        assert_eq!(lookup.queried, (1..=5).map(id).collect::<BTreeSet<_>>());
        assert_eq!(lookup.next_batch_up_to(usize::MAX), vec![id(6)]);
    }

    #[test]
    fn lookup_shared_capacity_respects_remaining_query_budget() {
        let local = id(0);
        let seeds = [id(1), id(2), id(3)];
        let mut routes = RoutingTable::new(local, seeds);
        let mut lookup = IterativeLookup::new(local, local, seeds);
        // Place the lookup at its hard budget boundary without thousands of
        // preliminary request/completion pairs unrelated to this regression.
        lookup
            .queried
            .extend((100..).map(id).take(MAX_LOOKUP_QUERIES - 1));

        assert_eq!(lookup.next_batch_up_to(usize::MAX), vec![id(1)]);
        assert_eq!(lookup.queried.len(), MAX_LOOKUP_QUERIES);
        assert!(lookup.next_batch_up_to(usize::MAX).is_empty());
        assert!(!lookup.is_finished());
        assert!(!lookup.queried.contains(&id(2)));
        assert!(!lookup.queried.contains(&id(3)));
        assert_eq!(lookup.record_timeouts(&mut routes), 1);
        assert!(lookup.is_finished());
    }

    #[test]
    fn routing_timeout_fails_only_issued_unanswered_requests() {
        let local = id(0);
        let mut routes = RoutingTable::new(local, [id(2)]);
        for n in 1..=4 {
            routes.promote_authenticated(id(n));
        }
        let mut lookup = IterativeLookup::new(local, local, routes.closest(local, K));
        assert_eq!(lookup.next_batch(), vec![id(1), id(2), id(3)]);
        assert!(lookup.record_authenticated_response(id(1), [], &mut routes));

        assert_eq!(lookup.record_timeouts(&mut routes), 2);
        assert_eq!(routes.state(id(1)), Some(RouteState::Verified));
        assert_eq!(routes.state(id(2)), Some(RouteState::Candidate));
        assert_eq!(routes.state(id(3)), None);
        assert_eq!(routes.state(id(4)), Some(RouteState::Verified));
        assert_eq!(lookup.closest_authenticated_responders(), &[id(1)]);
        assert_eq!(lookup.record_timeouts(&mut routes), 0);
        assert_eq!(lookup.next_batch(), vec![id(4)]);
    }

    #[test]
    fn configured_seed_survives_learned_eviction_and_failure() {
        let local = id(0);
        let configured = id(0xffff);
        let mut routes = RoutingTable::new(local, [configured]);

        routes.promote_authenticated(configured);
        assert_eq!(routes.state(configured), Some(RouteState::Verified));
        for n in 0x8000..0x8000 + K as u16 {
            routes.promote_authenticated(id(n));
        }
        assert!(
            !routes
                .closest_verified(configured, ROUTING_CAPACITY)
                .contains(&configured)
        );
        assert_eq!(routes.state(configured), Some(RouteState::Candidate));
        assert!(routes.closest(configured, K).contains(&configured));

        // A later failed retry can remove learned liveness evidence, but not
        // the explicit local instruction to use this peer as a bootstrap.
        assert!(routes.remove(id(0x8000)));
        assert!(routes.promote_authenticated(configured));
        assert_eq!(routes.state(configured), Some(RouteState::Verified));
        assert!(routes.remove(configured));
        assert_eq!(routes.state(configured), Some(RouteState::Candidate));
        assert!(routes.closest(configured, K).contains(&configured));
    }

    #[test]
    fn lookup_retains_target_near_authenticated_responders_after_route_eviction() {
        let local = id(0);
        let responder = id(0xffff);
        let target: RoutingKey = responder;
        let mut routes = RoutingTable::new(local, [responder]);
        let mut lookup = IterativeLookup::new(local, target, [responder]);

        assert_eq!(lookup.next_batch(), vec![responder]);
        assert!(lookup.record_authenticated_response(responder, [], &mut routes));
        assert_eq!(lookup.closest_authenticated_responders(), &[responder]);

        // All peers occupy the same local-distance bucket. The long-lived
        // table prefers the K routes nearer `local`, but lookup results remain
        // ranked by the arbitrary lookup target.
        for n in 0x8000..0x8000 + K as u16 {
            routes.promote_authenticated(id(n));
        }
        assert!(
            !routes
                .closest_verified(target, ROUTING_CAPACITY)
                .contains(&responder)
        );
        assert_eq!(lookup.closest_authenticated_responders(), &[responder]);
    }

    #[test]
    fn lookup_responder_result_is_bounded_and_target_ordered() {
        let local = id(0);
        let target = id(25);
        let mut routes = RoutingTable::new(local, [id(1)]);
        let mut lookup = IterativeLookup::new(local, target, [id(1)]);

        for n in 1..=25 {
            assert_eq!(lookup.next_batch(), vec![id(n)]);
            let next = (n < 25).then(|| id(n + 1));
            assert!(lookup.record_authenticated_response(id(n), next.into_iter(), &mut routes));
        }

        let responders = lookup.closest_authenticated_responders();
        assert_eq!(responders.len(), K);
        assert_eq!(responders[0], target);
        assert!(!responders.contains(&id(2)));
        assert!(
            responders
                .windows(2)
                .all(|pair| distance_cmp(target, pair[0], pair[1]).is_le())
        );
    }

    #[test]
    fn unsolicited_or_duplicate_completion_cannot_promote() {
        let local = id(0);
        let seed = id(1);
        let stranger = id(2);
        let mut routes = RoutingTable::new(local, [seed]);
        let mut lookup = IterativeLookup::new(local, stranger, [seed]);

        assert!(!lookup.record_authenticated_response(stranger, [], &mut routes));
        assert_eq!(routes.state(stranger), None);
        assert_eq!(lookup.next_batch(), vec![seed]);
        assert!(lookup.record_authenticated_response(seed, [stranger], &mut routes));
        assert!(!lookup.record_authenticated_response(seed, [], &mut routes));
    }

    #[test]
    fn lookup_probe_topologies_terminate_with_bounded_unique_requests() {
        let peers = (0..64)
            .map(|index| probe_bytes("triblespace.net/lookup-probe-peer/v1", index))
            .collect::<Vec<_>>();
        let local = peers[0];
        let target = probe_targets(1, 0)[0];
        for topology in [
            ProbeTopology::Full,
            ProbeTopology::Ring,
            ProbeTopology::XorBuckets,
        ] {
            let network = ProbeNetwork::new(topology, &peers);
            let observed = probe_lookup(&network, local, target);
            assert_eq!(observed.requests, observed.contacted.len());
            assert!(observed.requests <= peers.len() - 1);
            assert!(observed.rounds <= observed.requests);
            assert!(observed.first_batch.len() <= ALPHA);
        }
    }

    /// Deterministic, opt-in capacity probe for the private iterative XOR
    /// lookup. All work is in-process: elapsed time measures local lookup plus
    /// synthetic FIND_NODE reply selection, never transport latency.
    ///
    /// Run with `cargo test -p triblespace-net --release
    /// iterative_lookup_scale_probe -- --ignored --nocapture`.
    /// `TRIBLESPACE_LOOKUP_SCALE_NODES` and `TRIBLESPACE_LOOKUP_SCALE_KEYS`
    /// default to 1,024 and 64. The overlap metrics are observational upper
    /// bounds only; this probe deliberately defines no batching protocol.
    #[test]
    #[ignore = "manual deterministic iterative-lookup scale measurement"]
    fn iterative_lookup_scale_probe() {
        let node_count = scale_parameter("TRIBLESPACE_LOOKUP_SCALE_NODES", 1_024);
        let key_count = scale_parameter("TRIBLESPACE_LOOKUP_SCALE_KEYS", 64);
        assert!(node_count > K);
        assert!(key_count > 0 && key_count <= u16::MAX as usize);
        let peers = (0..node_count)
            .map(|index| probe_bytes("triblespace.net/lookup-probe-peer/v1", index))
            .collect::<Vec<_>>();
        let local = peers[0];

        for topology in [
            ProbeTopology::Full,
            ProbeTopology::Ring,
            ProbeTopology::XorBuckets,
        ] {
            let build_started = Instant::now();
            let network = ProbeNetwork::new(topology, &peers);
            let build_elapsed = build_started.elapsed();
            for shared_prefix_bits in [0, 8, 16, 32, 240] {
                let targets = probe_targets(key_count, shared_prefix_bits);
                let started = Instant::now();
                let observations = targets
                    .into_iter()
                    .map(|target| (target, probe_lookup(&network, local, target)))
                    .collect::<Vec<_>>();
                let elapsed = started.elapsed();
                let requests = observations
                    .iter()
                    .map(|(_, observation)| observation.requests)
                    .sum::<usize>();
                let rounds = observations
                    .iter()
                    .map(|(_, observation)| observation.rounds)
                    .sum::<usize>();
                let contacted = observations
                    .iter()
                    .map(|(_, observation)| observation.contacted.clone())
                    .collect::<Vec<_>>();
                let first_batches = observations
                    .iter()
                    .map(|(_, observation)| observation.first_batch.clone())
                    .collect::<Vec<_>>();
                let mut prefix_sorted = observations.iter().collect::<Vec<_>>();
                prefix_sorted.sort_unstable_by_key(|(target, _)| *target);
                let prefix_sorted_contacted = prefix_sorted
                    .iter()
                    .map(|(_, observation)| observation.contacted.clone())
                    .collect::<Vec<_>>();
                let prefix_sorted_first_batches = prefix_sorted
                    .iter()
                    .map(|(_, observation)| observation.first_batch.clone())
                    .collect::<Vec<_>>();
                let mut contact_union = BTreeSet::new();
                for set in &contacted {
                    contact_union.extend(set.iter().copied());
                }
                let peer_contact_reuse_upper_bound =
                    1.0 - contact_union.len() as f64 / requests as f64;
                println!(
                    "iterative_lookup topology={} nodes={node_count} keys={key_count} shared_prefix_bits={shared_prefix_bits} topology_build_seconds={:.6} local_seconds={:.6} lookups_per_second={:.2} find_node_requests={} find_node_requests_per_second={:.2} requests_per_lookup={:.3} rounds={} rounds_per_lookup={:.3} contacted_peer_union={} peer_contact_reuse_upper_bound={peer_contact_reuse_upper_bound:.6} adjacent_contact_jaccard={:.6} adjacent_first_batch_jaccard={:.6} prefix_sorted_adjacent_contact_jaccard={:.6} prefix_sorted_adjacent_first_batch_jaccard={:.6}",
                    topology.name(),
                    build_elapsed.as_secs_f64(),
                    elapsed.as_secs_f64(),
                    key_count as f64 / elapsed.as_secs_f64(),
                    requests,
                    requests as f64 / elapsed.as_secs_f64(),
                    requests as f64 / key_count as f64,
                    rounds,
                    rounds as f64 / key_count as f64,
                    contact_union.len(),
                    adjacent_jaccard(&contacted),
                    adjacent_jaccard(&first_batches),
                    adjacent_jaccard(&prefix_sorted_contacted),
                    adjacent_jaccard(&prefix_sorted_first_batches),
                );
            }
        }
    }
}
