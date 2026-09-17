//! Disposable restart experiment, not a host feature or published file format.
//!
//! This runs the real routing/lookup machine against synthetic FIND_NODE peers.
//! The only saved relation is a bounded set of authenticated endpoint identities;
//! restoration supplies Candidates, never liveness, leases or authorization.
//! No provider GET, blob H, collection record, or publication cursor is involved.

use std::io::{Read, Write};

use anybytes::Bytes;
use anyhow::{Result, ensure};
use triblespace_core::blob::{Blob, encodings::rawbytes::RawBytes};
use triblespace_core::patch::{Entry, PATCH};

use super::*;

#[path = "warm_start/exact_h_counts.rs"]
mod exact_h_counts;

const MAX_CACHE_BYTES: usize = ROUTING_CAPACITY * 32;

/// Existing PATCH algebra supplies the canonical unary endpoint relation.
/// Plain ordered keys suffice at this bound; no parallel index or JSON shadow.
fn freeze(routes: &RoutingTable) -> Blob<RawBytes> {
    let mut endpoints = PATCH::<32>::new();
    for peer in routes.closest_verified(routes.local, ROUTING_CAPACITY) {
        endpoints.insert(&Entry::new(&peer));
    }
    let bytes: Vec<u8> = endpoints.iter_ordered().flatten().copied().collect();
    assert!(bytes.len() <= MAX_CACHE_BYTES);
    Blob::new(Bytes::from_source(bytes))
}

/// Bound the read before allocation, then validate the entire packed relation
/// before touching live state. Rejecting this disposable cache loses no facts.
fn restore(routes: &mut RoutingTable, reader: impl Read) -> Result<()> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CACHE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_CACHE_BYTES, "oversized route cache");
    ensure!(bytes.len().is_multiple_of(32), "partial endpoint identity");
    let mut previous: Option<PeerId> = None;
    for key in bytes.chunks_exact(32) {
        let peer: PeerId = key.try_into().unwrap();
        iroh_base::EndpointId::from_bytes(&peer)?;
        ensure!(
            previous.is_none_or(|last| last < peer),
            "noncanonical endpoint set"
        );
        previous = Some(peer);
    }
    for key in bytes.chunks_exact(32) {
        routes.note_candidate(key.try_into().unwrap());
    }
    Ok(())
}

fn endpoint(index: u64) -> PeerId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    *iroh_base::SecretKey::from(bytes).public().as_bytes()
}

fn restart(local: PeerId, configured: &[PeerId], cache: &Blob<RawBytes>) -> RoutingTable {
    let mut routes = RoutingTable::new(local, configured.iter().copied());
    restore(&mut routes, cache.bytes.as_ref()).unwrap();
    assert!(routes.closest_verified(local, ROUTING_CAPACITY).is_empty());
    routes
}

#[derive(Clone, Copy, Debug)]
enum Seeds {
    Closest,
    /// Experimental first wave: one configured DHT seed and ALPHA-1 nearest
    /// candidates. Admit the deferred closest-K set after that wave completes.
    /// The fixture has one configured seed; this is not a general multi-seed
    /// scheduling policy or a claim about async deadline fairness.
    BootstrapWave,
}

#[derive(Default)]
struct Observation {
    requests: usize,
    failed: usize,
    rounds: usize,
    winner_round: Option<usize>,
    first_batch: Vec<PeerId>,
    contacted: BTreeSet<PeerId>,
    responders: Vec<PeerId>,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lookup")
            .field("requests", &self.requests)
            .field("failures", &self.failed)
            .field("rounds", &self.rounds)
            .field("winner_round", &self.winner_round)
            .field("distinct_contacts", &self.contacted.len())
            .field("responders", &self.responders.len())
            .finish()
    }
}

/// A synthetic peer only returns identities. Failure is an absent endpoint;
/// a poisoned but authenticated endpoint is present with an empty/closed view.
struct Network {
    links: BTreeMap<PeerId, Vec<PeerId>>,
    winner: PeerId,
}

fn lookup(
    routes: &mut RoutingTable,
    target: RoutingKey,
    network: &Network,
    policy: Seeds,
) -> Observation {
    let mut deferred = routes.closest(target, K);
    let initial = match policy {
        Seeds::Closest => std::mem::take(&mut deferred),
        Seeds::BootstrapWave => {
            assert!(
                routes.configured.len() <= 1,
                "fixture policy supports one bootstrap"
            );
            if let Some(bootstrap) = routes.configured.iter_ordered().next().copied() {
                let mut initial = vec![bootstrap];
                initial.extend(
                    deferred
                        .iter()
                        .copied()
                        .filter(|peer| *peer != bootstrap)
                        .take(ALPHA - 1),
                );
                initial
            } else {
                std::mem::take(&mut deferred)
            }
        }
    };
    let mut machine = IterativeLookup::new(routes.local, target, initial);
    let mut observed = Observation::default();
    while !machine.is_finished() {
        let batch = machine.next_batch();
        assert!(!batch.is_empty());
        assert!(batch.len() <= ALPHA);
        observed.rounds += 1;
        observed.requests += batch.len();
        if observed.rounds == 1 {
            observed.first_batch = batch.clone();
        }
        for peer in batch {
            assert!(
                observed.contacted.insert(peer),
                "one request per peer per lookup"
            );
            if let Some(referrals) = network.links.get(&peer) {
                if peer == network.winner && observed.winner_round.is_none() {
                    observed.winner_round = Some(observed.rounds);
                }
                assert!(machine.record_authenticated_response(
                    peer,
                    referrals.iter().copied(),
                    routes
                ));
            } else {
                observed.failed += 1;
                assert!(machine.record_failure(peer, routes));
            }
        }
        // Admission remains subject to the same lookup bounds and local
        // failure cooldown. No second route table or responder authority.
        if !deferred.is_empty() {
            machine.add_candidates(
                deferred
                    .drain(..)
                    .filter(|peer| routes.query_eligible(*peer, crate::clock::mono_now())),
            );
            machine.trim_shortlist();
        }
    }
    observed.responders = machine.closest_authenticated_responders().to_vec();
    assert!(observed.requests <= MAX_LOOKUP_QUERIES);
    observed
}

fn line(count: usize) -> (PeerId, PeerId, Network) {
    let local = endpoint(0);
    let mut peers: Vec<_> = (1..=count as u64).map(endpoint).collect();
    peers.sort_unstable_by(|a, b| distance_cmp(local, *b, *a));
    let links = peers
        .iter()
        .enumerate()
        .map(|(index, peer)| (*peer, peers.get(index + 1).copied().into_iter().collect()))
        .collect();
    (
        local,
        peers[0],
        Network {
            links,
            winner: *peers.last().unwrap(),
        },
    )
}

#[test]
fn warm_start_roundtrip_is_bounded_candidate_only_and_not_a_lease() {
    let local = endpoint(0);
    let configured = endpoint(1);
    let live = endpoint(2);
    let referral = endpoint(3);
    let failed = endpoint(4);
    let mut before = RoutingTable::new(local, [configured]);
    before.promote_authenticated(live);
    before.note_candidate(referral);
    before.promote_authenticated(failed);
    before.note_failure(failed, crate::clock::mono_now());
    let cache = freeze(&before);
    assert_eq!(cache.bytes.as_ref(), live);

    // Exercise real byte persistence/reopen while dropping all old route state.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&cache.bytes).unwrap();
    file.as_file().sync_all().unwrap();
    drop(before);
    let mut after = RoutingTable::new(local, [configured]);
    restore(&mut after, file.reopen().unwrap()).unwrap();
    assert_eq!(after.state(live), Some(RouteState::Candidate));
    assert_eq!(after.state(referral), None);
    assert_eq!(after.state(failed), None);
    assert_eq!(after.configured_len(), 1);
    assert!(
        freeze(&after).bytes.is_empty(),
        "disk hints are not self-refreshing liveness"
    );

    after.note_failure(live, crate::clock::mono_now());
    restore(&mut after, cache.bytes.as_ref()).unwrap();
    assert_eq!(
        after.state(live),
        None,
        "reload cannot erase in-process failure evidence"
    );
    after.promote_authenticated(live);
    assert_eq!(freeze(&after), cache);

    // Changing the local endpoint does not import its predecessor's bucket
    // ownership or accidentally turn the new self identity into a peer.
    let changed_identity = restart(live, &[], &cache);
    assert_eq!(changed_identity.learned_len(), 0);
}

#[test]
fn warm_start_invalid_cache_is_rejected_before_admission() {
    let peer = endpoint(1);
    let mut routes = RoutingTable::new(endpoint(0), []);
    for bytes in [
        peer[..31].to_vec(),
        [peer, peer].concat(),
        vec![0; MAX_CACHE_BYTES + 1],
    ] {
        assert!(restore(&mut routes, bytes.as_slice()).is_err());
        assert_eq!(routes.learned_len(), 0);
    }
    let mut pair = [endpoint(2), peer];
    pair.sort_unstable();
    pair.reverse();
    assert!(restore(&mut routes, pair.concat().as_slice()).is_err());
    assert_eq!(routes.learned_len(), 0);
    let invalid = (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|peer| iroh_base::EndpointId::from_bytes(peer).is_err())
        .unwrap();
    let mut pair = [peer, invalid];
    pair.sort_unstable();
    assert!(restore(&mut routes, pair.concat().as_slice()).is_err());
    assert_eq!(routes.learned_len(), 0);
    assert_eq!(MAX_CACHE_BYTES, 163_840);

    let interrupted = std::io::Cursor::new(peer).chain(std::io::repeat(0).take(1));
    assert!(restore(&mut routes, interrupted).is_err());
    assert_eq!(routes.learned_len(), 0);
}

#[test]
fn warm_start_shortens_sparse_discovery_and_survives_dead_bootstrap() {
    let (local, bootstrap, mut network) = line(64);
    let mut routes = RoutingTable::new(local, [bootstrap]);
    let cold = lookup(&mut routes, local, &network, Seeds::Closest);
    assert_eq!(cold.requests, 64);
    assert_eq!(cold.winner_round, Some(64));
    let cache = freeze(&routes);
    drop(routes);
    let warm = lookup(
        &mut restart(local, &[bootstrap], &cache),
        local,
        &network,
        Seeds::Closest,
    );
    assert_eq!(warm.winner_round, Some(1));
    assert!(warm.requests < cold.requests);

    network.links.remove(&bootstrap);
    let dead_cold = lookup(
        &mut RoutingTable::new(local, [bootstrap]),
        local,
        &network,
        Seeds::Closest,
    );
    let dead_warm = lookup(
        &mut restart(local, &[bootstrap], &cache),
        local,
        &network,
        Seeds::BootstrapWave,
    );
    assert_eq!(dead_cold.winner_round, None);
    assert_eq!(dead_warm.winner_round, Some(1));
    assert!(dead_warm.requests <= K + 1);
    println!(
        "warm_start sparse_line nodes=64 cache_bytes={} cold={cold:?} warm={warm:?} dead_cold={dead_cold:?} dead_warm={dead_warm:?}",
        cache.bytes.len()
    );
}

fn hostile_fixture() -> (PeerId, PeerId, RoutingKey, Blob<RawBytes>, Network) {
    let local = endpoint(0);
    let mut peers: Vec<_> = (1..=512).map(endpoint).collect();
    peers.sort_unstable_by(|a, b| distance_cmp(local, *a, *b));
    let winner = peers[0];
    let stale = &peers[1..=K];
    let bootstrap = *peers.last().unwrap();
    let mut old_routes = RoutingTable::new(local, [bootstrap]);
    for peer in stale {
        old_routes.promote_authenticated(*peer);
    }
    let cache = freeze(&old_routes);
    assert_eq!(cache.bytes.len(), K * 32);
    let links = BTreeMap::from([(bootstrap, vec![winner]), (winner, Vec::new())]);
    (local, bootstrap, local, cache, Network { links, winner })
}

#[test]
fn warm_start_stale_cache_cannot_replace_configured_bootstrap_priority() {
    let (local, bootstrap, target, cache, network) = hostile_fixture();
    let cold = lookup(
        &mut RoutingTable::new(local, [bootstrap]),
        target,
        &network,
        Seeds::Closest,
    );
    let mut routes = restart(local, &[bootstrap], &cache);
    let stale = lookup(&mut routes, target, &network, Seeds::Closest);
    assert_eq!(cold.winner_round, Some(2));
    assert_eq!(stale.winner_round, None);
    assert_eq!(stale.requests, K);
    assert!(!stale.first_batch.contains(&bootstrap));
    // The existing cooldown recovers a later lookup in this fixture; repeatedly
    // restarting and reloading stale bytes would throw that failure memory away.
    let retry = lookup(&mut routes, target, &network, Seeds::Closest);
    assert_eq!(retry.winner_round, Some(2));
    let fair = lookup(
        &mut restart(local, &[bootstrap], &cache),
        target,
        &network,
        Seeds::BootstrapWave,
    );
    assert!(fair.first_batch.contains(&bootstrap));
    assert!(fair.winner_round.is_some());
    assert!(fair.requests <= K + 2);
    println!(
        "warm_start stale cache_bytes={} cold={cold:?} closest={stale:?} cooldown_retry={retry:?} bootstrap_wave={fair:?}",
        cache.bytes.len()
    );
}

#[test]
fn warm_start_authenticated_poison_is_still_not_an_independent_bootstrap() {
    let (local, bootstrap, target, cache, mut network) = hostile_fixture();
    for peer in cache.bytes.chunks_exact(32) {
        network.links.insert(peer.try_into().unwrap(), Vec::new());
    }
    let poisoned = lookup(
        &mut restart(local, &[bootstrap], &cache),
        target,
        &network,
        Seeds::Closest,
    );
    assert_eq!(poisoned.responders.len(), K);
    assert_eq!(poisoned.winner_round, None);
    assert_eq!(
        poisoned.failed, 0,
        "authentication is not an honest topology promise"
    );
    let fair = lookup(
        &mut restart(local, &[bootstrap], &cache),
        target,
        &network,
        Seeds::BootstrapWave,
    );
    assert!(fair.first_batch.contains(&bootstrap));
    assert!(fair.winner_round.is_some());
    println!("warm_start poisoned closest={poisoned:?} bootstrap_wave={fair:?}");
}

/// Measurement, not a live-network latency benchmark. Deterministic XOR-bucket
/// peers, one distant bootstrap, 32 earlier discovery targets and 64 independent
/// post-restart targets; each target starts with the same frozen contact set.
#[test]
#[ignore = "manual synthetic restart lookup measurement"]
fn warm_start_lookup_probe() {
    let peers: Vec<_> = (0..1_024).map(endpoint).collect();
    let local = peers[0];
    let bootstrap = peers[1];
    let mut network = Network {
        links: BTreeMap::new(),
        winner: peers[2],
    };
    for peer in &peers[1..] {
        let mut routes = RoutingTable::new(*peer, []);
        for candidate in &peers[1..] {
            routes.note_candidate(*candidate);
        }
        network.links.insert(*peer, routes.all());
    }
    let mut prior = RoutingTable::new(local, [bootstrap]);
    for target in &peers[2..34] {
        lookup(&mut prior, *target, &network, Seeds::Closest);
    }
    let started = std::time::Instant::now();
    let cache = freeze(&prior);
    let freeze_micros = started.elapsed().as_micros();
    drop(prior);
    let started = std::time::Instant::now();
    for _ in 0..100 {
        std::hint::black_box(restart(local, &[bootstrap], &cache));
    }
    println!(
        "warm_start_cache bytes={} endpoints={} freeze_micros={freeze_micros} restore_count=100 restore_total_micros={}",
        cache.bytes.len(),
        cache.bytes.len() / 32,
        started.elapsed().as_micros(),
    );
    for (name, warm, policy, dead_bootstrap) in [
        ("cold", false, Seeds::Closest, false),
        ("warm", true, Seeds::Closest, false),
        ("warm_bootstrap_wave", true, Seeds::BootstrapWave, false),
        ("cold_dead_bootstrap", false, Seeds::Closest, true),
        ("warm_dead_bootstrap", true, Seeds::BootstrapWave, true),
    ] {
        let saved = if dead_bootstrap {
            network.links.remove(&bootstrap)
        } else {
            None
        };
        let mut requests = 0;
        let mut rounds = 0;
        let mut failures = 0;
        let mut successes = 0;
        let mut winner_rounds = 0;
        for target in &peers[100..164] {
            network.winner = *target;
            let mut routes = if warm {
                restart(local, &[bootstrap], &cache)
            } else {
                RoutingTable::new(local, [bootstrap])
            };
            let result = lookup(&mut routes, *target, &network, policy);
            requests += result.requests;
            rounds += result.rounds;
            failures += result.failed;
            if let Some(round) = result.winner_round {
                successes += 1;
                winner_rounds += round;
            }
        }
        if let Some(saved) = saved {
            network.links.insert(bootstrap, saved);
        }
        println!(
            "warm_start_probe mode={name} nodes=1024 targets=64 cache_bytes={} successes={successes} requests={requests} rounds={rounds} failures={failures} winner_rounds={winner_rounds}",
            cache.bytes.len()
        );
    }
}
