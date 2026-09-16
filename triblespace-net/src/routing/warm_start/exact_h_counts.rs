//! Bounded operation counts through the real routing machine, with synthetic
//! authenticated FIND_NODE replies. Keys are already in rendezvous space:
//! adjacency here makes no claim about adjacency between raw blob handles.
//! Logical rounds drain one batch at a time; they are not elapsed time or the
//! host's asynchronous completion order. No connection, provider PUT, directory
//! GET, or blob GET is executed. Q is observed; Q + R is a publication projection.

use super::*;

const PEER_COUNT: usize = 64;
const TARGET_COUNT: usize = 16;

#[derive(Debug, Eq, PartialEq)]
struct Counts {
    requests: usize,
    rounds: usize,
    contacted: BTreeSet<PeerId>,
    replicas: Vec<PeerId>,
}

fn sequences() -> [(&'static str, Vec<RoutingKey>); 3] {
    let key = |index: usize| {
        let mut hasher =
            blake3::Hasher::new_derive_key("triblespace.net/exact-h-routing-counts/target/v1");
        hasher.update(&(index as u64).to_be_bytes());
        *hasher.finalize().as_bytes()
    };
    let mut base = key(0);
    base[0] &= 0x0f;
    base[31] &= 0xf0;
    let same = vec![base; TARGET_COUNT];
    let adjacent = (0..TARGET_COUNT)
        .map(|index| {
            let mut target = base;
            target[31] |= index as u8;
            target
        })
        .collect::<Vec<_>>();
    let dispersed = (0..TARGET_COUNT)
        .map(|index| {
            let mut target = if index == 0 { base } else { key(index) };
            target[0] = (target[0] & 0x0f) | ((index as u8) << 4);
            target
        })
        .collect::<Vec<_>>();
    assert_eq!(adjacent.iter().collect::<BTreeSet<_>>().len(), TARGET_COUNT);
    assert_eq!(
        dispersed
            .iter()
            .map(|target| target[0] >> 4)
            .collect::<BTreeSet<_>>()
            .len(),
        TARGET_COUNT
    );
    [
        ("same", same),
        ("adjacent", adjacent),
        ("dispersed", dispersed),
    ]
}

fn count_sequence(
    peers: &[PeerId],
    server_routes: &BTreeMap<PeerId, RoutingTable>,
    targets: &[RoutingKey],
    retain_routes: bool,
) -> Vec<Counts> {
    let local = peers[0];
    let bootstrap = peers[1];
    let mut retained = RoutingTable::new(local, [bootstrap]);
    targets
        .iter()
        .map(|&target| {
            let network = Network {
                links: server_routes
                    .iter()
                    .map(|(&peer, routes)| {
                        // Match the host's FIND_NODE reply: verified nearest K,
                        // then remove the requesting client's own identity.
                        let mut referrals = routes.closest_verified(target, K);
                        referrals.retain(|candidate| *candidate != local);
                        (peer, referrals)
                    })
                    .collect(),
                // This fixture counts all routing work, not a winner's arrival.
                winner: local,
            };
            let mut fresh = RoutingTable::new(local, [bootstrap]);
            let routes = if retain_routes {
                &mut retained
            } else {
                &mut fresh
            };
            let observed = lookup(routes, target, &network, Seeds::Closest);
            assert_eq!(observed.failed, 0);
            assert_eq!(observed.requests, observed.contacted.len());
            assert!((1..PEER_COUNT).contains(&observed.requests));
            assert!(observed.rounds <= observed.requests);
            assert!(observed.requests <= ALPHA * observed.rounds);
            assert!(
                observed
                    .contacted
                    .iter()
                    .all(|peer| network.links.contains_key(peer))
            );

            // Exact host lookup_replicas selection rule. The local directory
            // placement is not a remote PUT and must not contribute to R.
            let mut replicas = observed.responders;
            replicas.push(local);
            replicas.sort_unstable_by(|a, b| distance_cmp(target, *a, *b));
            replicas.dedup();
            replicas.truncate(K);
            assert!(replicas.len() <= K);
            Counts {
                requests: observed.requests,
                rounds: observed.rounds,
                contacted: observed.contacted,
                replicas,
            }
        })
        .collect()
}

#[test]
fn exact_h_routing_counts_fresh_and_retained_sequences() {
    let peers = (0..PEER_COUNT as u64).map(endpoint).collect::<Vec<_>>();
    assert_eq!(peers.iter().collect::<BTreeSet<_>>().len(), PEER_COUNT);
    let server_routes = peers[1..]
        .iter()
        .map(|&peer| {
            let mut routes = RoutingTable::new(peer, []);
            for candidate in &peers {
                routes.promote_authenticated(*candidate);
            }
            (peer, routes)
        })
        .collect::<BTreeMap<_, _>>();

    for (sequence, targets) in sequences() {
        assert_eq!(targets.len(), TARGET_COUNT);
        let fresh = count_sequence(&peers, &server_routes, &targets, false);
        let retained = count_sequence(&peers, &server_routes, &targets, true);
        assert_eq!(fresh[0], retained[0], "both modes start with one bootstrap");
        assert_eq!(
            fresh,
            count_sequence(&peers, &server_routes, &targets, false)
        );
        assert_eq!(
            retained,
            count_sequence(&peers, &server_routes, &targets, true)
        );
        if sequence == "same" {
            assert!(fresh.windows(2).all(|pair| pair[0] == pair[1]));
            assert!(
                retained.iter().all(|count| count.requests > 0),
                "retaining routes must not turn a repeated lookup into a cached final answer"
            );
        }
        for (mode, counts) in [("fresh", fresh), ("retained", retained)] {
            let mut contact_union = BTreeSet::new();
            for (ordinal, count) in counts.iter().enumerate() {
                let remote_replicas = count
                    .replicas
                    .iter()
                    .filter(|peer| **peer != peers[0])
                    .count();
                let previously_contacted = count.contacted.intersection(&contact_union).count();
                contact_union.extend(count.contacted.iter().copied());
                println!(
                    "exact_h_routing_counts peers={PEER_COUNT} sequence={sequence} route_state={mode} target={ordinal} observed_find_node_q={} logical_rounds={} distinct_contacts={} previously_contacted_peers={previously_contacted} sequence_distinct_contacts={} selected_replicas={} local_selected={} projected_remote_put_r={remote_replicas} predicted_advertisement_ops_q_plus_r={}",
                    count.requests,
                    count.rounds,
                    count.contacted.len(),
                    contact_union.len(),
                    count.replicas.len(),
                    count.replicas.contains(&peers[0]),
                    count.requests + remote_replicas,
                );
            }
        }
    }
}
