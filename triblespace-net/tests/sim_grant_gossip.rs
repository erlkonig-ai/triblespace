//! Grant gossip by participation, through whole hosts over the deterministic
//! transport. A grant over a resource R reaches every node that takes part in
//! R: R's roots, the keys named on delegation-valid prefixes of grants over
//! R, and the nodes admitted to sync R's content. Nobody dials on a grant's
//! behalf, and no resource kind is special.
//!
//! The scenarios observe what each store holds, how often each node dialled
//! another, what each host reports in its health, and which frames crossed a
//! tapped host: the GRANT_ROOTS listings it sent and heard, the resource each
//! walk OPEN names, and, for the retry scenario, walk streams the tap
//! silenced. Every scenario carries a positive control, so an assertion that
//! something did not travel is never satisfied by nothing travelling at all.
//!
//! Each scenario runs over a seed sweep, which shakes the arrival orders the
//! simulation's determinism contract makes reproducible.
#![cfg(feature = "sim")]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use iroh_base::EndpointId;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::capability::policy::resource_policy;
use triblespace_core::capability::{
    CapabilityHandle, CapabilityProof, CapabilityResource, capability_action,
};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionCommit, CollectionData, CollectionHandle,
    CollectionPolicy, CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt,
    empty_metadata_handle, private_policy, read_capability, write_capability,
};
use triblespace_core::id::Id;
use triblespace_core::macros::id_hex;
use triblespace_core::metadata;
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_core::trible::TribleSet;
use triblespace_net::connection::RESET_WALK_REFUSED;
use triblespace_net::health::{GrantHealth, GrantPeerHealth, PairState};
use triblespace_net::health_record::{self, Component, DEFAULT_MAX_AGE, State};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::patch_repair::PatchSummary;
use triblespace_net::peer::Peer;
use triblespace_net::protocol::{PILE_SYNC_ALPN, TAG_RECON, TAG_WALK};
use triblespace_net::recon::{self, grant_roots_frames};
use triblespace_net::transport::sim::{Crossed, SimConfig, SimNet, SimRecvStream, SimSendStream, Taps};
use triblespace_net::transport::{Conn, Harness, PeerId, SendStream, Transport, reset_code};
use triblespace_net::walk_stream::{
    FRAME_DONE, FRAME_LANDED, FRAME_OPEN, FRAME_SUBTREE, FRAME_VALUE,
};

/// The retired routing backlink, declared here so old-shape resource
/// descriptors can be written once core no longer exports it. It is an
/// anchored attribute: the anchor and the encoding are its identity, so this
/// declaration has the published attribute's id (pinned by
/// `the_local_retired_backlink_has_the_published_identity` in core).
mod retired {
    use triblespace_core::macros::attributes;
    use triblespace_core::prelude::*;

    attributes! {
        "62E951EC3ABB7F9B7F123BB7DE2F9F99" as pub resource_collection: inlineencodings::Handle<blobencodings::SimpleArchive>;
    }
}

/// Tag of the test's non-collection resource descriptors, standing in for a
/// Secrets version. Minted with `trible genid` on 2026-10-19 for this file.
const KIND_TEST_RESOURCE: Id = id_hex!("6F0A88AB3F0B3C732CB85805DA09D148");
/// The action the test's delivery definition grants. Minted with
/// `trible genid` on 2026-10-19 for this file.
const ACTION_TEST_DELIVER: Id = id_hex!("5766257B997431DDEC2AC40CC3E3B682");

/// Seeds each scenario sweeps.
const SEEDS: u64 = 8;

/// Walk OPEN component bytes, as the tap classifies them.
const WALK_COMMIT: u8 = 0;
const WALK_AUTHORIZATION: u8 = 1;
const WALK_DERIVE: u8 = 3;

/// Grant walks one host runs with one peer at once (walk.rs
/// `MAX_GRANT_WALKS_PER_PEER`).
const GRANT_WALKS_PER_PEER: usize = 8;
/// Resources a host takes from one connection's listings that it takes no
/// part in (grants.rs `MAX_UNKNOWN_RESOURCES_PER_LINK`).
const UNKNOWN_RESOURCES_PER_LINK: usize = 256;
/// How long a walk waits for a frame it is owed (walk.rs `WALK_DEADLINE`).
const WALK_DEADLINE: Duration = Duration::from_secs(60);

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn id(key: &SigningKey) -> PeerId {
    key.verifying_key().to_bytes()
}

fn virtual_clock() -> Arc<VirtualClock> {
    static CLOCK: OnceLock<Arc<VirtualClock>> = OnceLock::new();
    CLOCK
        .get_or_init(|| {
            let clock =
                VirtualClock::new(hifitime::Epoch::from_gregorian_utc_at_midnight(2026, 1, 1));
            clock::install_virtual(clock.clone()).expect("first virtual-clock install");
            clock
        })
        .clone()
}

fn run(test: impl AsyncFnOnce(Arc<VirtualClock>)) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(test(clock)));
}

/// A host on `harness`. It publishes no provider records and starts with no
/// route, so it reaches only the keys its pile names.
fn bring_up<T: Transport>(
    harness: Harness<T>,
    key: &SigningKey,
    store: MemoryRepo,
) -> Peer<MemoryRepo> {
    let (sender, receiver, wiring) = host::wire(EndpointId::from_bytes(&id(key)).unwrap());
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            daemon: None,
            provider_publication_budget: Some(0),
            bind: None,
        },
        wiring,
    ));
    Peer::with_wiring(store, sender, receiver)
}

async fn advance(clock: &Arc<VirtualClock>, peers: &mut [&mut Peer<MemoryRepo>], seconds: u64) {
    for _ in 0..seconds * 10 {
        SimNet::step(clock, Duration::from_millis(100)).await;
        for peer in peers.iter_mut() {
            peer.refresh();
        }
    }
}

/// Step until `done`, for at most `seconds`; how long it took.
async fn until(
    clock: &Arc<VirtualClock>,
    peers: &mut [&mut Peer<MemoryRepo>],
    seconds: u64,
    what: &str,
    done: impl FnMut(&mut [&mut Peer<MemoryRepo>]) -> bool,
) -> Duration {
    until_every(clock, peers, Duration::from_millis(100), seconds, what, done).await
}

/// Step by `step` until `done`, for at most `seconds`; how long it took. A
/// step shorter than a link's latency sees each arrival on its own.
async fn until_every(
    clock: &Arc<VirtualClock>,
    peers: &mut [&mut Peer<MemoryRepo>],
    step: Duration,
    seconds: u64,
    what: &str,
    mut done: impl FnMut(&mut [&mut Peer<MemoryRepo>]) -> bool,
) -> Duration {
    let started = clock::mono_now();
    let steps = Duration::from_secs(seconds).as_nanos() / step.as_nanos();
    for _ in 0..steps {
        if done(peers) {
            return clock::mono_now().duration_since(started);
        }
        SimNet::step(clock, step).await;
        for peer in peers.iter_mut() {
            peer.refresh();
        }
    }
    panic!("no {what} within {seconds} s");
}

/// One node's pile: its store and its configuration collection.
struct Pile {
    key: SigningKey,
    store: MemoryRepo,
    config: Collection<SimpleArchive>,
}

impl Pile {
    fn new(key: &SigningKey) -> Self {
        let mut store = MemoryRepo::default();
        let config = store
            .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
            .unwrap();
        Self {
            key: key.clone(),
            store,
            config,
        }
    }

    /// Hold the collection `name` under `policy` (descriptor and definitions).
    fn hold(&mut self, name: &str, policy: &CollectionPolicy) -> CollectionHandle {
        self.store
            .collection(name, policy.clone())
            .unwrap()
            .handle()
    }

    fn select(&mut self, collection: CollectionHandle) {
        write_sync_selection(&mut self.store, self.config, &self.key, collection, true).unwrap();
    }

    fn insert(&mut self, proofs: &[&CapabilityProof]) {
        for proof in proofs {
            self.store.insert_proof((*proof).clone()).unwrap();
        }
    }
}

/// `root` grants `subject` the capability `definition` over `resource`.
fn grant(
    root: &SigningKey,
    definition: CapabilityHandle,
    subject: &SigningKey,
    resource: CollectionHandle,
) -> CapabilityProof {
    CapabilityProof::new(
        CapabilityResource::from(resource),
        root,
        definition,
        subject.verifying_key(),
    )
}

fn holds_proof(peer: &mut Peer<MemoryRepo>, proof: &CapabilityProof) -> bool {
    peer.snapshot()
        .unwrap()
        .proofs()
        .unwrap()
        .any(|held| held.unwrap().id() == proof.id())
}

fn proofs(peer: &mut Peer<MemoryRepo>) -> Vec<CapabilityProof> {
    peer.snapshot()
        .unwrap()
        .proofs()
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn holds_blob(peer: &mut Peer<MemoryRepo>, handle: CollectionHandle) -> bool {
    peer.snapshot().unwrap().contains_blob(handle).unwrap()
}

fn holds_record(peer: &mut Peer<MemoryRepo>, record: CollectionRecord) -> bool {
    peer.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .any(|held| held.unwrap() == record)
}

/// A record of `collection` that `key` signs over fresh data, kept in `store`.
fn commit(
    store: &mut MemoryRepo,
    key: &SigningKey,
    collection: CollectionHandle,
    body: &[u8],
) -> CollectionRecord {
    let data = store
        .put::<UnknownBlob, _>(Bytes::from_source(body.to_vec()))
        .unwrap();
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        key,
        collection,
        CollectionData::new(data.raw),
        empty_metadata_handle(),
    ));
    store.insert(record).unwrap();
    record
}

/// Whether `peer` is peered with `other` for `collection` and receives it.
fn receives_from(peer: &Peer<MemoryRepo>, other: PeerId, collection: CollectionHandle) -> bool {
    peer.health().peerings.iter().any(|peering| {
        peering.peer == other
            && peering.collection == collection
            && peering.peered
            && peering.receives
    })
}

/// Walk OPENs the tapped host sent to `peer` since the `from`-th frame, by
/// the component its OPEN names.
fn opens_sent(taps: &Taps, from: usize, peer: PeerId, component: u8) -> usize {
    taps.since(from, peer, TAG_WALK)
        .iter()
        .filter(|crossed| {
            crossed.sent && crossed.kind == FRAME_OPEN && crossed.walk_kind == Some(component)
        })
        .count()
}

/// Walk OPENs between the tapped host and `peer`, either way, since the
/// `from`-th frame, by the component its OPEN names.
fn opens(taps: &Taps, from: usize, peer: PeerId, component: u8) -> usize {
    taps.since(from, peer, TAG_WALK)
        .iter()
        .filter(|crossed| crossed.kind == FRAME_OPEN && crossed.walk_kind == Some(component))
        .count()
}

/// Grant walk OPENs over `resource` between the tapped host and `peer`,
/// either way, since the `from`-th frame.
fn grant_opens(taps: &Taps, from: usize, peer: PeerId, resource: CollectionHandle) -> usize {
    taps.since(from, peer, TAG_WALK)
        .iter()
        .filter(|crossed| {
            crossed.kind == FRAME_OPEN
                && crossed.walk_kind == Some(WALK_AUTHORIZATION)
                && crossed.walk_resource == Some(resource.raw)
        })
        .count()
}

/// Record walk OPENs (Commit or Derive) that crossed the tap, to any peer,
/// between its `from`-th and `to`-th frames.
fn record_opens_between(taps: &Taps, from: usize, to: usize) -> usize {
    taps.crossed()[from..to]
        .iter()
        .filter(|crossed: &&Crossed| {
            crossed.tag == TAG_WALK
                && crossed.kind == FRAME_OPEN
                && matches!(crossed.walk_kind, Some(WALK_COMMIT | WALK_DERIVE))
        })
        .count()
}

/// The resources GRANT_ROOTS frames between the tapped host and `peer`
/// named since the `from`-th frame: those the tapped host `sent`, or heard.
fn listed(taps: &Taps, from: usize, peer: PeerId, sent: bool) -> BTreeSet<CollectionHandle> {
    taps.listed(from, peer)
        .into_iter()
        .filter(|listed| listed.sent == sent)
        .flat_map(|listed| listed.roots)
        .map(|(resource, _)| resource)
        .collect()
}

/// What `peer` reports of its grant agreement over `resource`.
fn grant_health(peer: &Peer<MemoryRepo>, resource: CollectionHandle) -> Option<GrantHealth> {
    peer.health()
        .grants
        .iter()
        .find(|grants| grants.resource == resource)
        .cloned()
}

/// What `peer` reports of `other`'s grant walks and listing over `resource`.
fn grant_peer(
    peer: &Peer<MemoryRepo>,
    resource: CollectionHandle,
    other: PeerId,
) -> Option<GrantPeerHealth> {
    grant_health(peer, resource)?
        .peers
        .into_iter()
        .find(|listing| listing.peer == other)
}

/// The test's delivery definition, as Secrets binds one: an action and a
/// name, nothing that makes it a collection's.
fn delivery_definition() -> Blob<SimpleArchive> {
    entity! {
        capability_action: ACTION_TEST_DELIVER,
        metadata::name: "test delivery",
    }
    .facts()
    .clone()
    .to_blob()
}

/// A Secrets-shaped resource descriptor rooted at `root`: a non-collection
/// tag and one `resource_policy` binding of `definition`, with or without
/// the retired backlink to `backlink`.
fn resource_descriptor(
    root: &SigningKey,
    definition: CapabilityHandle,
    backlink: Option<CollectionHandle>,
) -> TribleSet {
    entity! {
        metadata::tag: KIND_TEST_RESOURCE,
        retired::resource_collection?: backlink,
        resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(definition),
    }
    .facts()
    .clone()
}

// ---------------------------------------------------------------------------
// Scenario 1: a late WRITE grant reaches the collection's readers.
// ---------------------------------------------------------------------------

/// Variants of the late-WRITE scenario.
#[derive(Clone, Copy, Default)]
struct Late {
    base_seed: u64,
    /// C's READ is Open: the readers hold no grant at all.
    open_read: bool,
    /// R1 already holds a record X signed before X was granted anything.
    parked: bool,
    /// An outsider U shares another collection D with S, holds C's
    /// descriptor and is not peered for C.
    outsider: bool,
    /// After convergence the four stay quiet for ten minutes.
    quiet: bool,
}

/// W roots C; S is a server holding READ and WRITE; R1 and R2 read C and
/// reach W only through S (W–R1, W–R2 and R1–R2 are partitioned). The four
/// stay quiet long enough for every push timer to reach its cap, then W
/// signs a WRITE grant to X, who is never online. R1 and R2 hold it within
/// five virtual seconds: two hops over established connections, whose
/// simulated streams carry frames in no virtual time (the simulation's 1–30
/// ms latency applies to connection setup only), so what is measured is the
/// protocol's own waiting, in 100 ms steps. Every
/// hop carries exactly one grant walk over C, either way, and no record
/// walk opens anywhere on S until both readers hold the grant. Afterwards
/// all four hold the same grants over C and every neighbour's standing
/// listing of C is that root.
///
/// With `open_read` the collection's READ is Open and the readers hold no
/// grant at all: they take part in C by being admitted to sync it, and still
/// receive every grant over C. With `outsider`, a node U that shares another
/// collection D with S and holds C's descriptor, but is not peered for C,
/// is listed nothing about C and never holds the grant; that it was listed
/// D is its positive control.
///
/// With `parked`, R1 already holds a record X signed before X was granted
/// anything: it is not admitted at R1 until the late grant lands there, and
/// then it is, without the record travelling again.
///
/// With `quiet`, the four then stay quiet for ten virtual minutes, more than
/// three times the default health age: every pair of neighbours still reads
/// Current, and the recorded health conditions for C are Current too. Grant
/// agreement is a standing statement, not one a fresh walk renews.
fn late_write_grant_reaches_the_readers(case: Late) {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(case.base_seed ^ seed, SimConfig::default());
            let [w, s, r1, r2, x, u] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x3A].map(key);
            let read_policy = if case.open_read {
                AdmissionPolicy::Open
            } else {
                AdmissionPolicy::direct(w.verifying_key())
            };
            let policy =
                CollectionPolicy::new(read_policy, AdmissionPolicy::direct(w.verifying_key()));
            let mut piles = [&w, &s, &r1, &r2].map(Pile::new);
            let typed = piles[0].store.collection("late", policy.clone()).unwrap();
            let collection = typed.handle();
            for pile in &mut piles[1..] {
                assert_eq!(pile.hold("late", &policy), collection);
            }
            let parked_data = case.parked.then(|| {
                let record = commit(
                    &mut piles[2].store,
                    &x,
                    collection,
                    b"signed before X's grant",
                );
                let CollectionRecord::Commit(commit) = record else {
                    unreachable!()
                };
                commit.data().raw
            });
            let admitted_at = |peer: &mut Peer<MemoryRepo>, data: [u8; 32]| {
                typed
                    .admitted(&peer.snapshot().unwrap())
                    .unwrap()
                    .members()
                    .any(|member| member.raw == data)
            };
            let mut initial = vec![
                grant(&w, write_capability(), &s, collection),
                grant(&w, read_capability(), &s, collection),
            ];
            if !case.open_read {
                initial.push(grant(&w, read_capability(), &r1, collection));
                initial.push(grant(&w, read_capability(), &r2, collection));
            }
            for pile in &mut piles {
                pile.insert(&initial.iter().collect::<Vec<_>>());
                pile.select(collection);
            }
            let outsider = case.outsider.then(|| {
                let beside_policy = private_policy(s.verifying_key());
                let mut pile = Pile::new(&u);
                assert_eq!(pile.hold("late", &policy), collection);
                let beside = pile.hold("beside", &beside_policy);
                assert_eq!(piles[1].hold("beside", &beside_policy), beside);
                let reads = grant(&s, read_capability(), &u, beside);
                pile.insert(&[&reads]);
                piles[1].insert(&[&reads]);
                pile.select(beside);
                piles[1].select(beside);
                (pile, beside)
            });
            for (a, b) in [(&w, &r1), (&w, &r2), (&r1, &r2)] {
                net.partition(id(a), id(b));
            }
            let [w_pile, s_pile, r1_pile, r2_pile] = piles;
            let (s_harness, taps) = net.tap(&s);
            let mut wh = bring_up(net.join(&w), &w, w_pile.store);
            let mut sh = bring_up(s_harness, &s, s_pile.store);
            let mut r1h = bring_up(net.join(&r1), &r1, r1_pile.store);
            let mut r2h = bring_up(net.join(&r2), &r2, r2_pile.store);
            for host in [&mut wh, &mut sh, &mut r1h, &mut r2h] {
                host.activate_collection(collection);
            }
            let (w_id, s_id, r1_id, r2_id, u_id) = (id(&w), id(&s), id(&r1), id(&r2), id(&u));
            let mut uh = outsider.map(|(pile, beside)| {
                let mut host = bring_up(net.join(&u), &u, pile.store);
                host.activate_collection(beside);
                sh.activate_collections([collection, beside]);
                (host, beside)
            });
            // Positive control: the path exists before the late grant.
            until(
                &clock,
                &mut [&mut wh, &mut sh, &mut r1h, &mut r2h],
                60,
                "the readers peered through S",
                |hosts| {
                    receives_from(hosts[1], w_id, collection)
                        && receives_from(hosts[2], s_id, collection)
                        && receives_from(hosts[3], s_id, collection)
                },
            )
            .await;
            // Quiet long enough for every push timer to reach its cap.
            advance(&clock, &mut [&mut wh, &mut sh, &mut r1h, &mut r2h], 200).await;
            if let Some((host, beside)) = &mut uh {
                host.refresh();
                assert!(
                    receives_from(host, s_id, *beside),
                    "the outsider is connected to S"
                );
            }
            if let Some(data) = parked_data {
                assert!(
                    !admitted_at(&mut r1h, data),
                    "X's record admitted before X's grant"
                );
            }

            let from = taps.len();
            let late = grant(&w, write_capability(), &x, collection);
            wh.store().insert_proof(late.clone()).unwrap();
            wh.refresh();
            let reached = until(
                &clock,
                &mut [&mut wh, &mut sh, &mut r1h, &mut r2h],
                20,
                "the late WRITE grant at both readers",
                |hosts| holds_proof(hosts[2], &late) && holds_proof(hosts[3], &late),
            )
            .await;
            let to = taps.len();
            assert!(holds_proof(&mut sh, &late));
            assert_eq!(
                record_opens_between(&taps, from, to),
                0,
                "seed {seed}: the grant opened a record walk at S"
            );
            if let Some(data) = parked_data {
                until(
                    &clock,
                    &mut [&mut wh, &mut sh, &mut r1h, &mut r2h],
                    10,
                    "X's parked record admitted at R1",
                    |hosts| admitted_at(hosts[2], data),
                )
                .await;
            }
            println!(
                "late WRITE grant (open_read={}, seed {seed}): at both readers after \
                 {reached:?} virtual time, measured in 100 ms steps, two hops W->S->R over \
                 established connections (sim streams take no virtual time; its 1-30 ms \
                 latency is per connection setup)",
                case.open_read
            );
            assert!(reached <= Duration::from_secs(5), "{reached:?}");

            advance(&clock, &mut [&mut wh, &mut sh, &mut r1h, &mut r2h], 5).await;
            for hop in [w_id, r1_id, r2_id] {
                assert_eq!(
                    grant_opens(&taps, from, hop, collection),
                    1,
                    "seed {seed}: grant walks over C on one hop"
                );
            }
            // All four hold the same grants over C, and every neighbour's
            // standing listing of C is that root.
            let local = grant_health(&wh, collection).expect("W's grants over C").local;
            assert_eq!(local.leaf_count(), initial.len() as u64 + 1);
            for (host, neighbours) in [(&wh, 1), (&sh, 3), (&r1h, 1), (&r2h, 1)] {
                let grants = grant_health(host, collection).expect("grants over C");
                assert_eq!(grants.local, local, "seed {seed}");
                let listed = grants
                    .peers
                    .iter()
                    .filter_map(|listing| listing.listed)
                    .collect::<Vec<_>>();
                assert_eq!(listed, vec![local; neighbours], "seed {seed}: {grants:?}");
            }

            if let Some((mut host, beside)) = uh {
                host.refresh();
                assert!(!holds_proof(&mut host, &late), "the outsider holds the grant");
                let told = listed(&taps, 0, u_id, true);
                assert!(told.contains(&beside), "the outsider was listed D: {told:?}");
                assert!(!told.contains(&collection), "the outsider was listed C");
                assert!(grant_health(&host, collection).is_none());
            }

            if case.quiet {
                advance(&clock, &mut [&mut wh, &mut sh, &mut r1h, &mut r2h], 600).await;
                let now = clock::mono_now();
                for (host, neighbours) in [(&wh, 1), (&sh, 3), (&r1h, 1), (&r2h, 1)] {
                    let health = host.health();
                    let pairs = health
                        .collections
                        .iter()
                        .find(|entry| entry.collection == collection)
                        .expect("C is active")
                        .peers
                        .iter()
                        .map(|pair| pair.peer)
                        .collect::<Vec<_>>();
                    assert_eq!(pairs.len(), neighbours, "seed {seed}");
                    for peer in pairs {
                        assert_eq!(
                            health.pair(collection, peer, now, DEFAULT_MAX_AGE),
                            PairState::Current,
                            "seed {seed}: a quiet pair"
                        );
                    }
                    let conditions = health_record::conditions(&health, now)
                        .into_iter()
                        .filter(|condition| {
                            condition.component == Component::Collection
                                && condition.collection == Some(collection)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(conditions.len(), neighbours);
                    assert!(
                        conditions
                            .iter()
                            .all(|condition| condition.state == State::Current),
                        "seed {seed}: {conditions:?}"
                    );
                }
            }
        });
    }
}

#[test]
fn a_late_write_grant_reaches_the_readers_of_a_closed_collection() {
    late_write_grant_reaches_the_readers(Late {
        base_seed: 0x6A47_0100,
        ..Late::default()
    });
}

/// The Open-READ variant: a reader that holds no grant still takes part in
/// C by being admitted to sync it, so it receives the late grant (critique:
/// the receiver must not skip grants it is not named on). A node that is
/// connected but not peered for C is told nothing about C.
#[test]
fn a_late_write_grant_reaches_the_readers_of_an_open_read_collection() {
    late_write_grant_reaches_the_readers(Late {
        base_seed: 0x6A47_0200,
        open_read: true,
        outsider: true,
        ..Late::default()
    });
}

/// A reader holding a record X signed before X was granted WRITE admits it
/// once the late grant lands, without the record travelling again.
#[test]
fn a_late_write_grant_admits_a_record_the_reader_already_holds() {
    late_write_grant_reaches_the_readers(Late {
        base_seed: 0x6A47_0280,
        parked: true,
        ..Late::default()
    });
}

/// Health stays Current once grants agree: ten quiet minutes after the late
/// grant converged, every pair still reads Current.
#[test]
fn agreeing_grants_keep_every_pair_current_while_quiet() {
    late_write_grant_reaches_the_readers(Late {
        base_seed: 0x6A47_0A00,
        quiet: true,
        ..Late::default()
    });
}

/// A grant is not a record: a new grant over C moves no Commit or Derive
/// walk. W and S have been quiet long enough for the push timer to reach its
/// cap; W signs a WRITE grant, and every walk W opens to S until S holds it
/// is counted. The grant travels by an Authorization walk, which either side
/// may open: the one that hears the other list a different root for C
/// (positive control one). A record appended afterwards does open a Commit
/// walk (positive control two, so the counter is not blind).
///
/// Before the redesign the authorization summary was part of the
/// collection's wake root, so a new grant reset the push timer and the push
/// that carried it opened Commit and Derive walks as well.
#[test]
fn a_late_grant_opens_no_record_walk() {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0300 ^ seed, SimConfig::default());
            let [w, s, x] = [0x36, 0x37, 0x38].map(key);
            let policy = private_policy(w.verifying_key());
            let mut w_pile = Pile::new(&w);
            let mut s_pile = Pile::new(&s);
            let collection = w_pile.hold("quiet", &policy);
            s_pile.hold("quiet", &policy);
            let initial = [
                grant(&w, write_capability(), &s, collection),
                grant(&w, read_capability(), &s, collection),
            ];
            for pile in [&mut w_pile, &mut s_pile] {
                pile.insert(&initial.iter().collect::<Vec<_>>());
                pile.select(collection);
            }
            let (harness, taps) = net.tap(&w);
            let mut wh = bring_up(harness, &w, w_pile.store);
            let mut sh = bring_up(net.join(&s), &s, s_pile.store);
            wh.activate_collection(collection);
            sh.activate_collection(collection);
            let s_id = id(&s);
            // Quiet long enough for the push timer to reach its cap.
            advance(&clock, &mut [&mut wh, &mut sh], 200).await;
            assert!(receives_from(&sh, id(&w), collection));

            let from = taps.len();
            let late = grant(&w, write_capability(), &x, collection);
            wh.store().insert_proof(late.clone()).unwrap();
            wh.refresh();
            until(
                &clock,
                &mut [&mut wh, &mut sh],
                20,
                "the grant at S",
                |hosts| holds_proof(hosts[1], &late),
            )
            .await;
            let auth = opens(&taps, from, s_id, WALK_AUTHORIZATION);
            let records = opens_sent(&taps, from, s_id, WALK_COMMIT)
                + opens_sent(&taps, from, s_id, WALK_DERIVE);
            assert!(
                auth >= 1,
                "the grant travelled without an Authorization walk"
            );
            assert_eq!(
                records, 0,
                "seed {seed}: a grant opened {records} record walks"
            );

            let from = taps.len();
            let appended = commit(&mut *wh.store(), &w, collection, b"appended");
            wh.refresh();
            until(
                &clock,
                &mut [&mut wh, &mut sh],
                20,
                "the record at S",
                |hosts| holds_record(hosts[1], appended),
            )
            .await;
            assert!(
                opens_sent(&taps, from, s_id, WALK_COMMIT) >= 1,
                "a record travelled without a Commit walk: the counter is blind"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: a delivery grant reaches a non-syncing grantee through a third
// participant.
// ---------------------------------------------------------------------------

/// R is a Secrets-shaped resource whose descriptor still names C1 through
/// the retired backlink. Alice, Carol and Bob all read C1; Alice and Bob are
/// partitioned. Alice's delivery grant to Bob reaches Bob through Carol,
/// with R's descriptor, because Bob and Carol take part in R; the backlink
/// plays no part.
#[test]
fn a_routed_delivery_grant_relays_through_a_third_participant() {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0400 ^ seed, SimConfig::default());
            let [alice, carol, bob] = [0x41, 0x42, 0x43].map(key);
            let policy = private_policy(alice.verifying_key());
            let mut piles = [&alice, &carol, &bob].map(Pile::new);
            let c1 = piles[0].hold("shared", &policy);
            for pile in &mut piles[1..] {
                pile.hold("shared", &policy);
            }
            let reads = [
                grant(&alice, read_capability(), &carol, c1),
                grant(&alice, read_capability(), &bob, c1),
            ];
            let definition = delivery_definition();
            let delivery = definition.get_handle();
            piles[0].store.put::<SimpleArchive, _>(definition).unwrap();
            let resource = piles[0]
                .store
                .put::<SimpleArchive, _>(resource_descriptor(&alice, delivery, Some(c1)))
                .unwrap();
            let to_carol = grant(&alice, delivery, &carol, resource);
            let to_bob = grant(&alice, delivery, &bob, resource);
            piles[0].insert(&[&to_carol, &to_bob]);
            for pile in &mut piles {
                pile.insert(&reads.iter().collect::<Vec<_>>());
                pile.select(c1);
            }
            net.partition(id(&alice), id(&bob));
            let [a, c, b] = piles;
            let mut ah = bring_up(net.join(&alice), &alice, a.store);
            let mut ch = bring_up(net.join(&carol), &carol, c.store);
            let mut bh = bring_up(net.join(&bob), &bob, b.store);
            for host in [&mut ah, &mut ch, &mut bh] {
                host.activate_collection(c1);
            }
            let reached = until(
                &clock,
                &mut [&mut ah, &mut ch, &mut bh],
                60,
                "Alice's delivery grant at Bob",
                |hosts| holds_proof(hosts[2], &to_bob),
            )
            .await;
            assert!(holds_proof(&mut ch, &to_bob) && holds_proof(&mut ch, &to_carol));
            assert!(holds_blob(&mut bh, resource), "R's descriptor came with it");
            println!("routed delivery grant (seed {seed}): at Bob after {reached:?}");
        });
    }
}

/// R is a Secrets-shaped resource with no backlink, rooted at Alice. Alice
/// and Carol share C1; Carol and Bob share C2, which Carol roots and anyone
/// may read; Alice and Bob are partitioned, and Bob never selects C1. Alice
/// grants delivery over R to Bob, and, in the participating arm, to Carol.
///
/// - Participating: Bob, cold to R, holds Alice's grant, R's descriptor and
///   the delivery definition, which his completion fetch brought; he never
///   held the grant before R's descriptor, and his grant health shows the
///   grant waited for it unlanded. Carol holds Bob's grant, and her listing
///   to Bob named R.
/// - Control: when Carol takes no part in R, neither she nor Bob ever holds
///   it, and no listing to Bob names R; one names C2 (the positive control).
///
/// Alice never dialled Bob. Bob reads C2 by being admitted, not by a grant,
/// so Carol never dials him and he is no route of hers: a dial from Alice
/// to Bob could only be one on a grant's behalf, which nobody makes. Both
/// arms first check that Bob is peered with Carol for C2 and Carol with
/// Alice for C1, so the path exists.
#[test]
fn a_delivery_grant_reaches_a_non_syncing_grantee_through_a_third_participant() {
    for seed in 0..SEEDS {
        for carol_participates in [true, false] {
            run(async |clock| {
                let net = SimNet::new(0x6A47_0500 ^ seed, SimConfig::default());
                let [alice, carol, bob] = [0x44, 0x45, 0x46].map(key);
                let carol_id = id(&carol);
                let (mut ah, mut ch, mut bh, taps, to_bob, resource, definition, c2, mut arrivals) =
                    third_participant(&net, &clock, &alice, &carol, &bob, carol_participates).await;
                if carol_participates {
                    let reached = until_every(
                        &clock,
                        &mut [&mut ah, &mut ch, &mut bh],
                        Duration::from_millis(1),
                        60,
                        "Alice's delivery grant, R's descriptor and its definition at Bob",
                        |hosts| {
                            arrivals.note(hosts[2], &to_bob, resource);
                            holds_proof(hosts[2], &to_bob)
                                && holds_blob(hosts[2], resource)
                                && holds_blob(hosts[2], definition)
                        },
                    )
                    .await;
                    let (Some(grant_at), Some(descriptor_at)) = (arrivals.grant, arrivals.descriptor)
                    else {
                        unreachable!("both arrived")
                    };
                    println!(
                        "Bob's arrivals (seed {seed}): R's descriptor {descriptor_at:?}, the grant \
                         {grant_at:?} after the hosts came up"
                    );
                    assert!(
                        descriptor_at <= grant_at,
                        "seed {seed}: the grant landed before its descriptor"
                    );
                    // The simulated streams carry frames in no virtual time,
                    // so a descriptor fetched from Carol arrives within the
                    // millisecond its grant came: the order alone cannot tell
                    // a grant that waited from one that landed at once. Bob's
                    // grant health tells: the grant waited for R.
                    let from_carol = grant_peer(&bh, resource, carol_id).expect("Carol listed R");
                    assert!(from_carol.pending >= 1, "seed {seed}: {from_carol:?}");
                    assert!(holds_proof(&mut ch, &to_bob));
                    let heard = listed(&taps, 0, carol_id, false);
                    assert!(heard.contains(&resource), "seed {seed}: {heard:?}");
                    println!("delivery grant via Carol (seed {seed}): at Bob after {reached:?}");
                } else {
                    advance(&clock, &mut [&mut ah, &mut ch, &mut bh], 60).await;
                    assert!(!holds_proof(&mut ch, &to_bob));
                    assert!(!holds_proof(&mut bh, &to_bob));
                    let heard = listed(&taps, 0, carol_id, false);
                    assert!(heard.contains(&c2), "seed {seed}: {heard:?}");
                    assert!(!heard.contains(&resource), "a listing to Bob named R");
                }
                assert_eq!(net.dial_count(id(&alice), id(&bob)), 0, "seed {seed}");
            });
        }
    }
}

/// When a host first held a grant and the descriptor of its resource, since
/// the hosts came up.
struct Arrivals {
    started: clock::Mono,
    grant: Option<Duration>,
    descriptor: Option<Duration>,
}

impl Arrivals {
    fn new() -> Self {
        Self {
            started: clock::mono_now(),
            grant: None,
            descriptor: None,
        }
    }

    fn note(&mut self, host: &mut Peer<MemoryRepo>, grant: &CapabilityProof, resource: CollectionHandle) {
        let now = clock::mono_now().duration_since(self.started);
        if self.grant.is_none() && holds_proof(host, grant) {
            self.grant = Some(now);
        }
        if self.descriptor.is_none() && holds_blob(host, resource) {
            self.descriptor = Some(now);
        }
    }
}

/// Hosts for the third-participant scenario, converged on their collections:
/// Alice's, Carol's and Bob's (Bob tapped), Alice's grant to Bob, R, the
/// delivery definition, C2, and when Bob first held the grant and R's
/// descriptor, looked at every millisecond: a grant that landed before its
/// descriptor would be seen, since the descriptor's fetch takes a round
/// trip of at least two.
#[allow(clippy::type_complexity)]
async fn third_participant(
    net: &SimNet,
    clock: &Arc<VirtualClock>,
    alice: &SigningKey,
    carol: &SigningKey,
    bob: &SigningKey,
    carol_participates: bool,
) -> (
    Peer<MemoryRepo>,
    Peer<MemoryRepo>,
    Peer<MemoryRepo>,
    Taps,
    CapabilityProof,
    CollectionHandle,
    CapabilityHandle,
    CollectionHandle,
    Arrivals,
) {
    let mut a = Pile::new(alice);
    let mut c = Pile::new(carol);
    let mut b = Pile::new(bob);
    let c1_policy = private_policy(alice.verifying_key());
    let c2_policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(carol.verifying_key()),
    );
    let c1 = a.hold("alice and carol", &c1_policy);
    c.hold("alice and carol", &c1_policy);
    let c2 = c.hold("carol and bob", &c2_policy);
    b.hold("carol and bob", &c2_policy);
    let carol_reads = grant(alice, read_capability(), carol, c1);
    a.insert(&[&carol_reads]);
    c.insert(&[&carol_reads]);
    let definition = delivery_definition();
    let delivery = definition.get_handle();
    a.store.put::<SimpleArchive, _>(definition).unwrap();
    let resource = a
        .store
        .put::<SimpleArchive, _>(resource_descriptor(alice, delivery, None))
        .unwrap();
    let to_bob = grant(alice, delivery, bob, resource);
    a.insert(&[&to_bob]);
    if carol_participates {
        a.insert(&[&grant(alice, delivery, carol, resource)]);
    }
    a.select(c1);
    c.select(c1);
    c.select(c2);
    b.select(c2);
    net.partition(id(alice), id(bob));
    let (b_harness, taps) = net.tap(bob);
    let mut ah = bring_up(net.join(alice), alice, a.store);
    let mut ch = bring_up(net.join(carol), carol, c.store);
    let mut bh = bring_up(b_harness, bob, b.store);
    ah.activate_collection(c1);
    ch.activate_collections([c1, c2]);
    bh.activate_collection(c2);
    assert!(!holds_blob(&mut bh, resource) && !holds_blob(&mut bh, delivery), "Bob is cold");
    let (alice_id, carol_id) = (id(alice), id(carol));
    let mut arrivals = Arrivals::new();
    until_every(
        clock,
        &mut [&mut ah, &mut ch, &mut bh],
        Duration::from_millis(1),
        60,
        "Carol peered with Alice for C1 and Bob with Carol for C2",
        |hosts| {
            arrivals.note(hosts[2], &to_bob, resource);
            receives_from(hosts[1], alice_id, c1) && receives_from(hosts[2], carol_id, c2)
        },
    )
    .await;
    (ah, ch, bh, taps, to_bob, resource, delivery, c2, arrivals)
}

// ---------------------------------------------------------------------------
// Scenario 6: mixed descriptors.
// ---------------------------------------------------------------------------

/// Two Secrets-shaped resources rooted at Alice: R_old still carries the
/// retired backlink (to C1), R_new carries none. Both are granted to Carol
/// and to Bob, in the third-participant topology. Both grants and both
/// descriptors reach Bob through Carol alike: the same number of grant
/// walks over each crossed between Carol and Bob, and R_old arrives under
/// the handle Alice holds it by. Their handles differ (the backlink is part
/// of R_old's descriptor bytes).
#[test]
fn old_and_new_resource_descriptors_travel_alike() {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0600 ^ seed, SimConfig::default());
            let [alice, carol, bob] = [0x47, 0x48, 0x49].map(key);
            let mut a = Pile::new(&alice);
            let mut c = Pile::new(&carol);
            let mut b = Pile::new(&bob);
            let c1_policy = private_policy(alice.verifying_key());
            let c2_policy = private_policy(carol.verifying_key());
            let c1 = a.hold("alice and carol", &c1_policy);
            c.hold("alice and carol", &c1_policy);
            let c2 = c.hold("carol and bob", &c2_policy);
            b.hold("carol and bob", &c2_policy);
            let carol_reads = grant(&alice, read_capability(), &carol, c1);
            let bob_reads = grant(&carol, read_capability(), &bob, c2);
            a.insert(&[&carol_reads]);
            c.insert(&[&carol_reads, &bob_reads]);
            b.insert(&[&bob_reads]);
            let definition = delivery_definition();
            let delivery = definition.get_handle();
            a.store.put::<SimpleArchive, _>(definition).unwrap();
            let old = a
                .store
                .put::<SimpleArchive, _>(resource_descriptor(&alice, delivery, Some(c1)))
                .unwrap();
            let new = a
                .store
                .put::<SimpleArchive, _>(resource_descriptor(&alice, delivery, None))
                .unwrap();
            assert_ne!(old, new);
            let to_bob = [old, new].map(|resource| grant(&alice, delivery, &bob, resource));
            for resource in [old, new] {
                a.insert(&[&grant(&alice, delivery, &carol, resource)]);
            }
            a.insert(&to_bob.iter().collect::<Vec<_>>());
            a.select(c1);
            c.select(c1);
            c.select(c2);
            b.select(c2);
            net.partition(id(&alice), id(&bob));
            let (b_harness, taps) = net.tap(&bob);
            let mut ah = bring_up(net.join(&alice), &alice, a.store);
            let mut ch = bring_up(net.join(&carol), &carol, c.store);
            let mut bh = bring_up(b_harness, &bob, b.store);
            ah.activate_collection(c1);
            ch.activate_collections([c1, c2]);
            bh.activate_collection(c2);
            until(
                &clock,
                &mut [&mut ah, &mut ch, &mut bh],
                90,
                "both delivery grants and both descriptors at Bob",
                |hosts| {
                    to_bob.iter().all(|proof| holds_proof(hosts[2], proof))
                        && holds_blob(hosts[2], old)
                        && holds_blob(hosts[2], new)
                },
            )
            .await;
            advance(&clock, &mut [&mut ah, &mut ch, &mut bh], 10).await;
            let carol_id = id(&carol);
            let walks = [old, new].map(|resource| grant_opens(&taps, 0, carol_id, resource));
            assert!(walks[0] >= 1, "seed {seed}: no grant walk over R_old");
            assert_eq!(walks[0], walks[1], "seed {seed}: R_old and R_new walked unalike");
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 3: two teams on one pile stay isolated.
// ---------------------------------------------------------------------------

/// One host H holds two teams' collections, CA (rooted at A) and CB (rooted
/// at B), and every grant over each. A member of each team reads only its
/// own. Positive control: a grant over each that only H held at the start
/// reaches its team's member, and H's listings to each member named its own
/// team's collection. Then neither member holds any proof over the other
/// team's collection, nor its descriptor, nor any agreement over it, and no
/// listing H sent it ever named the other team's collection.
#[test]
fn two_teams_on_one_host_see_only_their_own_grants() {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0700 ^ seed, SimConfig::default());
            let [h, ka, a1, a2, kb, b1, b2] = [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57].map(key);
            let policy_a = private_policy(ka.verifying_key());
            let policy_b = private_policy(kb.verifying_key());
            let mut hp = Pile::new(&h);
            let mut ap = Pile::new(&a1);
            let mut bp = Pile::new(&b1);
            let ca = hp.hold("team a", &policy_a);
            let cb = hp.hold("team b", &policy_b);
            ap.hold("team a", &policy_a);
            bp.hold("team b", &policy_b);
            let host_a = [
                grant(&ka, read_capability(), &h, ca),
                grant(&ka, write_capability(), &h, ca),
            ];
            let host_b = [
                grant(&kb, read_capability(), &h, cb),
                grant(&kb, write_capability(), &h, cb),
            ];
            let a1_reads = grant(&ka, read_capability(), &a1, ca);
            let b1_reads = grant(&kb, read_capability(), &b1, cb);
            let a2_reads = grant(&ka, read_capability(), &a2, ca);
            let b2_writes = grant(&kb, write_capability(), &b2, cb);
            hp.insert(&[
                &host_a[0], &host_a[1], &host_b[0], &host_b[1], &a1_reads, &b1_reads, &a2_reads,
                &b2_writes,
            ]);
            ap.insert(&[&host_a[0], &host_a[1], &a1_reads]);
            bp.insert(&[&host_b[0], &host_b[1], &b1_reads]);
            hp.select(ca);
            hp.select(cb);
            ap.select(ca);
            bp.select(cb);
            let (a_harness, a_taps) = net.tap(&a1);
            let (b_harness, b_taps) = net.tap(&b1);
            let mut hh = bring_up(net.join(&h), &h, hp.store);
            let mut ah = bring_up(a_harness, &a1, ap.store);
            let mut bh = bring_up(b_harness, &b1, bp.store);
            hh.activate_collections([ca, cb]);
            ah.activate_collection(ca);
            bh.activate_collection(cb);
            until(
                &clock,
                &mut [&mut hh, &mut ah, &mut bh],
                60,
                "each team's grant held only at H, at its member",
                |hosts| holds_proof(hosts[1], &a2_reads) && holds_proof(hosts[2], &b2_writes),
            )
            .await;
            advance(&clock, &mut [&mut hh, &mut ah, &mut bh], 60).await;
            let h_id = id(&h);
            for (host, taps, own, other) in [(&mut ah, &a_taps, ca, cb), (&mut bh, &b_taps, cb, ca)] {
                let heard = listed(taps, 0, h_id, false);
                assert!(heard.contains(&own), "seed {seed}: {heard:?}");
                assert!(
                    !heard.contains(&other),
                    "seed {seed}: H listed the other team's collection"
                );
                let held = proofs(host);
                assert!(
                    held.iter()
                        .all(|proof| proof.resource() == CapabilityResource::from(own)),
                    "seed {seed}: a member holds a proof over the other team's collection"
                );
                assert!(!holds_blob(host, other), "the other team's descriptor");
                assert!(grant_health(host, own).is_some());
                assert!(
                    grant_health(host, other).is_none(),
                    "an agreement over the other team's collection"
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 4: junk delegation does not spread.
// ---------------------------------------------------------------------------

/// S roots C. G holds READ and WRITE over C, neither with a right to
/// delegate, and signs an extension G→Z to a stranger Z, who is never
/// online. G and S are peered for C, R1 reads C through S (G–R1 is
/// partitioned). Positive control: a grant over C that only G held at the
/// start (S→Y) reaches S and R1, so G's grants do travel. The G→Z chain
/// reaches neither S nor R1, and neither dials Z.
///
/// `empty_definition` names a definition with no actions at all in the G→Z
/// step: `validate_delegation` only checks that the child's actions are a
/// subset of the parent's delegated ones, so an empty child passes it
/// vacuously (critique: delegation validity for participation must not).
fn junk_delegation_does_not_spread(empty_definition: bool, base_seed: u64) {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(base_seed ^ seed, SimConfig::default());
            let [s, g, r1, z, y] = [0x61, 0x62, 0x63, 0x64, 0x65].map(key);
            let policy = private_policy(s.verifying_key());
            let mut piles = [&s, &g, &r1].map(Pile::new);
            let collection = piles[0].hold("junk", &policy);
            for pile in &mut piles[1..] {
                pile.hold("junk", &policy);
            }
            let g_reads = grant(&s, read_capability(), &g, collection);
            let initial = [
                g_reads.clone(),
                grant(&s, write_capability(), &g, collection),
                grant(&s, read_capability(), &r1, collection),
            ];
            for pile in &mut piles {
                pile.insert(&initial.iter().collect::<Vec<_>>());
                pile.select(collection);
            }
            let only_at_g = grant(&s, read_capability(), &y, collection);
            let child = if empty_definition {
                piles[1]
                    .store
                    .put::<SimpleArchive, _>(
                        entity! { metadata::name: "no actions at all" }
                            .facts()
                            .clone(),
                    )
                    .unwrap()
            } else {
                read_capability()
            };
            let junk = g_reads.delegate(&g, child, z.verifying_key()).unwrap();
            piles[1].insert(&[&only_at_g, &junk]);
            net.partition(id(&g), id(&r1));
            let [sp, gp, rp] = piles;
            let mut sh = bring_up(net.join(&s), &s, sp.store);
            let mut gh = bring_up(net.join(&g), &g, gp.store);
            let mut rh = bring_up(net.join(&r1), &r1, rp.store);
            for host in [&mut sh, &mut gh, &mut rh] {
                host.activate_collection(collection);
            }
            until(
                &clock,
                &mut [&mut sh, &mut gh, &mut rh],
                60,
                "G's grant S->Y at S and R1",
                |hosts| holds_proof(hosts[0], &only_at_g) && holds_proof(hosts[2], &only_at_g),
            )
            .await;
            advance(&clock, &mut [&mut sh, &mut gh, &mut rh], 60).await;
            assert!(
                !holds_proof(&mut sh, &junk),
                "seed {seed}: the junk chain reached S"
            );
            assert!(
                !holds_proof(&mut rh, &junk),
                "seed {seed}: the junk chain reached R1"
            );
            assert_eq!(net.dial_count(id(&s), id(&z)), 0, "S dialled the stranger");
            assert_eq!(
                net.dial_count(id(&r1), id(&z)),
                0,
                "R1 dialled the stranger"
            );
        });
    }
}

#[test]
fn an_undelegated_extension_to_a_stranger_does_not_spread() {
    junk_delegation_does_not_spread(false, 0x6A47_0800);
}

#[test]
fn an_extension_through_an_empty_definition_does_not_spread() {
    junk_delegation_does_not_spread(true, 0x6A47_0900);
}

// ---------------------------------------------------------------------------
// Scenario 5: the unknown-resource budget, and junk that never lands.
// ---------------------------------------------------------------------------

/// The root and the leaf a sender announces of a grant walk over `proof`'s
/// resource whose only grant is `proof`.
fn one_grant(resource: CollectionHandle, proof: &CapabilityProof) -> (PatchSummary, PatchSummary) {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&resource.raw);
    key[32..].copy_from_slice(&proof.id().raw);
    let mut patch = PATCH::<64, IdentitySchema, (), Blake3Merkle>::new();
    patch.insert(&Entry::new(&key));
    let node = |prefix: &[u8]| {
        let node = patch.merkle_node(prefix).unwrap();
        PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap()
    };
    (node(&resource.raw), node(&key))
}

/// A frame as it crosses a stream: kind, big-endian length, payload.
fn framed(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![kind];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn subtree(prefix: &[u8], summary: PatchSummary) -> Vec<u8> {
    let mut payload = vec![u8::try_from(prefix.len()).unwrap()];
    let mut padded = [0; 32];
    padded[..prefix.len()].copy_from_slice(prefix);
    payload.extend_from_slice(&padded);
    payload.extend_from_slice(&summary.root().unwrap_or_default());
    payload.extend_from_slice(&summary.leaf_count().to_be_bytes());
    framed(FRAME_SUBTREE, &payload)
}

/// The next frame on a stream, or `None` at its end or reset.
async fn next_frame(recv: &mut SimRecvStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    recv.read_exact(&mut header).await.ok()?;
    let mut payload = vec![0; u32::from_be_bytes(header[1..].try_into().unwrap()) as usize];
    recv.read_exact(&mut payload).await.ok()?;
    Some((header[0], payload))
}

/// What a hand-driven grant sender saw of the walks opened to it.
#[derive(Default)]
struct Served {
    /// Walks it holds open now, and the most it ever held at once.
    live: usize,
    peak: usize,
    /// The resources walks were opened over.
    opened: BTreeSet<CollectionHandle>,
    /// Walks both sides confirmed.
    confirmed: usize,
}

/// Serve one walk stream as a sender of `proofs`' single grant over the
/// resource its OPEN names: held a second before the first frame, so walks
/// overlap, then root, leaf, the proof's bytes and DONE, LANDED once the
/// opener's DONE arrives, and the end once its LANDED does. Any other stream
/// is dropped unanswered, as a blob request is.
async fn serve_walk(
    mut send: SimSendStream,
    mut recv: SimRecvStream,
    proofs: Rc<BTreeMap<CollectionHandle, CapabilityProof>>,
    served: Rc<RefCell<Served>>,
) {
    if recv.read_u8().await.ok() != Some(TAG_WALK) {
        return;
    }
    let Some((FRAME_OPEN, open)) = next_frame(&mut recv).await else {
        return;
    };
    let resource = CollectionHandle::new(open[..32].try_into().unwrap());
    let Some(proof) = proofs.get(&resource).cloned() else {
        send.reset(0);
        return;
    };
    {
        let mut served = served.borrow_mut();
        served.live += 1;
        served.peak = served.peak.max(served.live);
        served.opened.insert(resource);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (root, leaf) = one_grant(resource, &proof);
    let id = proof.id().raw;
    let mut value = id.to_vec();
    value.extend_from_slice(proof.as_bytes());
    let mut written = subtree(&[], root);
    written.extend(subtree(&id, leaf));
    written.extend(framed(FRAME_VALUE, &value));
    written.extend(framed(FRAME_DONE, &[]));
    let mut landed = send.write_all(&written).await.is_ok();
    let mut confirmed = false;
    while landed {
        match next_frame(&mut recv).await {
            // Our LANDED goes out before the opener can end the walk, so a
            // walk counts as live here no longer than it runs there.
            Some((FRAME_DONE, _)) => {
                served.borrow_mut().live -= 1;
                landed = send.write_all(&framed(FRAME_LANDED, &[])).await.is_ok();
                if !landed {
                    return;
                }
                loop {
                    match next_frame(&mut recv).await {
                        Some((FRAME_LANDED, _)) => {
                            confirmed = true;
                            break;
                        }
                        Some(_) => continue,
                        None => break,
                    }
                }
                break;
            }
            Some(_) => continue,
            None => landed = false,
        }
    }
    if !landed {
        served.borrow_mut().live -= 1;
        return;
    }
    if confirmed {
        served.borrow_mut().confirmed += 1;
        let _ = send.shutdown().await;
        while recv.read_u8().await.is_ok() {}
    }
}

/// V reads C, which H roots; they stay peered for C. A stranger Z, driven by
/// hand, dials V and lists 300 resources V takes no part in, each with one
/// grant Z signed to V: 150 whose descriptor no node holds or serves, and
/// 150 whose descriptor V already holds but which K, not Z, roots. Z
/// answers every grant walk V opens with that grant.
///
/// - V opens grant walks over exactly 256 of the 300 (the unknown-resource
///   budget per connection), not fewer, and never over the rest, however
///   long Z waits.
/// - Exactly 8 of those walks run at once, never more.
/// - None of the 300 grants lands at V: V's store gains no proof over any of
///   them. Positive control: every walk delivered its grant, which V skipped
///   (mismatched root) or held pending (no descriptor) and reported.
/// - Meanwhile a late grant H signs over C reaches V, and the honest pair's
///   grant walks over C end with no failure.
///
/// Z's descriptors with a mismatched root are resident at V rather than
/// served by Z: a hand-driven peer cannot answer the bearer key confirmation
/// of `blob/1`. A served descriptor is judged the same way once it lands.
#[test]
fn a_stranger_s_listing_is_bounded_and_its_junk_never_lands() {
    const SPAM: usize = 300;
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0B00 ^ seed, SimConfig::default());
            let [v, h, z, k, x] = [0x71, 0x72, 0x73, 0x74, 0x75].map(key);
            let (v_id, h_id) = (id(&v), id(&h));
            let policy = private_policy(h.verifying_key());
            let mut vp = Pile::new(&v);
            let mut hp = Pile::new(&h);
            let collection = hp.hold("honest", &policy);
            vp.hold("honest", &policy);
            let reads = grant(&h, read_capability(), &v, collection);
            for pile in [&mut vp, &mut hp] {
                pile.insert(&[&reads]);
                pile.select(collection);
            }
            let delivery = delivery_definition().get_handle();
            let mut junk = BTreeMap::new();
            let mut listing = Vec::new();
            let mut mismatched = BTreeSet::new();
            for i in 0..SPAM {
                let resident = i % 2 == 1;
                let root = if resident { &k } else { &z };
                let descriptor = entity! {
                    metadata::tag: KIND_TEST_RESOURCE,
                    metadata::name: format!("spam {i}"),
                    resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(delivery),
                }
                .facts()
                .clone();
                let resource = if resident {
                    vp.store.put::<SimpleArchive, _>(descriptor).unwrap()
                } else {
                    descriptor.to_blob().get_handle()
                };
                if resident {
                    mismatched.insert(resource);
                }
                let proof = grant(&z, delivery, &v, resource);
                listing.push((resource, one_grant(resource, &proof).0));
                junk.insert(resource, proof);
            }
            assert_eq!(mismatched.len(), SPAM / 2);
            let (v_harness, taps) = net.tap(&v);
            let mut vh = bring_up(v_harness, &v, vp.store);
            let mut hh = bring_up(net.join(&h), &h, hp.store);
            vh.activate_collection(collection);
            hh.activate_collection(collection);
            until(
                &clock,
                &mut [&mut vh, &mut hh],
                60,
                "V peered with H",
                |hosts| receives_from(hosts[0], h_id, collection),
            )
            .await;
            let before = proofs(&mut vh).len();

            // Z, by hand: dial, list, and answer the walks V opens.
            let served = Rc::new(RefCell::new(Served::default()));
            let mut harness = net.join(&z);
            let conn = harness.transport.dial(v_id, PILE_SYNC_ALPN).await.unwrap();
            let (mut recon_send, mut recon_recv) = conn.open_bi().await.unwrap();
            recon_send.write_all(&[TAG_RECON]).await.unwrap();
            recon_send
                .write_all(&framed(recon::FRAME_OPEN, &1u64.to_be_bytes()))
                .await
                .unwrap();
            for frame in grant_roots_frames(&listing) {
                let (kind, payload) = frame.encode();
                recon_send.write_all(&framed(kind, &payload)).await.unwrap();
            }
            tokio::task::spawn_local(async move {
                while recon_recv.read_u8().await.is_ok() {}
            });
            let proofs_by_resource = Rc::new(junk.clone());
            let serving = served.clone();
            tokio::task::spawn_local(async move {
                // The recon stream lives as long as this task: its end
                // would close the connection.
                let _recon = recon_send;
                while let Some((send, recv)) = conn.accept_bi().await {
                    tokio::task::spawn_local(serve_walk(
                        send,
                        recv,
                        proofs_by_resource.clone(),
                        serving.clone(),
                    ));
                }
            });
            tokio::task::spawn_local(async move {
                while harness.incoming.recv().await.is_some() {}
            });

            let late = grant(&h, read_capability(), &x, collection);
            hh.store().insert_proof(late.clone()).unwrap();
            hh.refresh();
            let z_id = id(&z);
            let opened_over = |taps: &Taps| {
                taps.since(0, z_id, TAG_WALK)
                    .iter()
                    .filter(|crossed| {
                        crossed.sent
                            && crossed.kind == FRAME_OPEN
                            && crossed.walk_kind == Some(WALK_AUTHORIZATION)
                    })
                    .map(|crossed| CollectionHandle::new(crossed.walk_resource.unwrap()))
                    .collect::<BTreeSet<_>>()
            };
            let took = until(
                &clock,
                &mut [&mut vh, &mut hh],
                300,
                "grant walks over 256 unknown resources",
                |_| opened_over(&taps).len() >= UNKNOWN_RESOURCES_PER_LINK,
            )
            .await;
            advance(&clock, &mut [&mut vh, &mut hh], 120).await;
            let opened = opened_over(&taps);
            assert_eq!(opened.len(), UNKNOWN_RESOURCES_PER_LINK, "seed {seed}");
            assert!(opened.iter().all(|resource| junk.contains_key(resource)));
            assert_eq!(served.borrow().opened, opened);
            assert_eq!(
                served.borrow().peak,
                GRANT_WALKS_PER_PEER,
                "seed {seed}: grant walks at once with one peer"
            );
            assert!(served.borrow().confirmed >= UNKNOWN_RESOURCES_PER_LINK);
            println!(
                "unknown-resource listing (seed {seed}): 256 walked within {took:?}, \
                 peak {} at once, {} confirmed",
                served.borrow().peak,
                served.borrow().confirmed
            );

            // Every grant crossed and was judged; none landed.
            for resource in &opened {
                let listing = grant_peer(&vh, *resource, z_id).expect("Z's listing of R");
                if mismatched.contains(resource) {
                    assert!(listing.skipped >= 1, "seed {seed}: {listing:?}");
                } else {
                    assert!(listing.pending >= 1, "seed {seed}: {listing:?}");
                }
            }
            let held = proofs(&mut vh);
            assert!(
                held.iter().all(|proof| !junk.values().any(|spam| spam.id() == proof.id())),
                "seed {seed}: a stranger's junk grant landed"
            );
            assert_eq!(held.len(), before + 1, "seed {seed}");
            assert!(holds_proof(&mut vh, &late), "the honest late grant");
            for (host, other) in [(&vh, h_id), (&hh, v_id)] {
                let honest = grant_peer(host, collection, other).expect("the honest pair");
                assert!(honest.ends.ok >= 1, "seed {seed}: {honest:?}");
                assert_eq!(honest.ends.failed, 0, "seed {seed}: {honest:?}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 7: onboarding with a full neighbour set.
// ---------------------------------------------------------------------------

/// G roots C and six readers read it; G's five asked-for neighbour slots
/// for C are full and every reader is peered with G (the positive control:
/// the asked-for set counts the reserved slot's holder too, so it holds at
/// least five). A
/// new grantee N comes online with an empty pile: it selects nothing and
/// knows no peer, so only a participant can reach it. G grants N READ over
/// C. The grant reaches every reader too, so N is a participant of C that
/// no connection reaches at G and at each reader: a reserved slot for such
/// participants dials N, whichever participant's comes first, and the grant
/// exchange lists C to N on that connection. N holds its grant, sees that it
/// was granted C, which it does not sync, and dialled nobody. G's asked-for
/// neighbours stay at least five. A reserved slot held already is handed on
/// once its holder has been peered for a reshuffle interval, so N waits at
/// most about that long.
#[test]
fn a_new_grantee_behind_a_full_neighbour_set_receives_its_grant() {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0C00 ^ seed, SimConfig::default());
            let g = key(0x81);
            let readers = (0x82..0x88).map(key).collect::<Vec<_>>();
            let n = key(0x89);
            let (g_id, n_id) = (id(&g), id(&n));
            let policy = private_policy(g.verifying_key());
            let mut gp = Pile::new(&g);
            let collection = gp.hold("busy", &policy);
            let reads = readers
                .iter()
                .map(|reader| grant(&g, read_capability(), reader, collection))
                .collect::<Vec<_>>();
            gp.insert(&reads.iter().collect::<Vec<_>>());
            gp.select(collection);
            let mut gh = bring_up(net.join(&g), &g, gp.store);
            gh.activate_collection(collection);
            let mut hosts = vec![gh];
            for (reader, read) in readers.iter().zip(&reads) {
                let mut pile = Pile::new(reader);
                pile.hold("busy", &policy);
                pile.insert(&[read]);
                pile.select(collection);
                let mut host = bring_up(net.join(reader), reader, pile.store);
                host.activate_collection(collection);
                hosts.push(host);
            }
            hosts.push(bring_up(net.join(&n), &n, Pile::new(&n).store));
            let asked = |g: &Peer<MemoryRepo>| {
                g.health()
                    .peerings
                    .iter()
                    .filter(|peering| {
                        peering.collection == collection && peering.asked && peering.peered
                    })
                    .count()
            };
            let reader_ids = readers.iter().map(id).collect::<Vec<_>>();
            until(
                &clock,
                &mut hosts.iter_mut().collect::<Vec<_>>(),
                120,
                "G's neighbour set for C full, every reader peered",
                |hosts| {
                    let health = hosts[0].health();
                    asked(hosts[0]) >= 5
                        && reader_ids.iter().all(|reader| {
                            health.peerings.iter().any(|peering| {
                                peering.peer == *reader
                                    && peering.collection == collection
                                    && peering.peered
                            })
                        })
                },
            )
            .await;
            advance(&clock, &mut hosts.iter_mut().collect::<Vec<_>>(), 10).await;
            assert!(asked(&hosts[0]) >= 5, "seed {seed}: the set is full");
            assert_eq!(net.dial_count(g_id, n_id), 0);

            let to_n = grant(&g, read_capability(), &n, collection);
            hosts[0].store().insert_proof(to_n.clone()).unwrap();
            hosts[0].refresh();
            let reached = until(
                &clock,
                &mut hosts.iter_mut().collect::<Vec<_>>(),
                120,
                "N's grant at N",
                |hosts| holds_proof(hosts.last_mut().unwrap(), &to_n),
            )
            .await;
            let mut participants = std::iter::once(g_id).chain(reader_ids.iter().copied());
            let dialled_n = participants
                .clone()
                .map(|participant| net.dial_count(participant, n_id))
                .collect::<Vec<_>>();
            println!(
                "onboarding behind a full neighbour set (seed {seed}): N holds its grant \
                 after {reached:?}; dials to N from G and the six readers: {dialled_n:?}"
            );
            assert!(dialled_n.iter().sum::<usize>() >= 1, "seed {seed}");
            assert!(
                participants.all(|participant| net.dial_count(n_id, participant) == 0),
                "N knew no peer"
            );
            until(
                &clock,
                &mut hosts.iter_mut().collect::<Vec<_>>(),
                30,
                "N sees it was granted C",
                |hosts| hosts.last().unwrap().health().named_unselected == [collection],
            )
            .await;
            assert!(asked(&hosts[0]) >= 5, "seed {seed}: the regular neighbours stay");
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 8: a failed grant walk is retried on the same connection.
// ---------------------------------------------------------------------------

/// W roots C and S reads and writes it; they are peered. W signs a late
/// grant. With `fault`, the tap at S silences every grant walk that opens in
/// the next two seconds, as a path that loses its packets would: both sides
/// wait out the walk deadline, the walk fails, and the side that opened it
/// opens it again after the backoff on the same connection, which delivers
/// the grant. No node dials again and the peering stands. Without the fault
/// (the control) the grant arrives at once and nothing is retried.
fn a_failed_grant_walk_is_retried(fault: bool, base_seed: u64) {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(base_seed ^ seed, SimConfig::default());
            let [w, s, x] = [0x91, 0x92, 0x93].map(key);
            let (w_id, s_id) = (id(&w), id(&s));
            let policy = private_policy(w.verifying_key());
            let mut wp = Pile::new(&w);
            let mut sp = Pile::new(&s);
            let collection = wp.hold("lossy", &policy);
            sp.hold("lossy", &policy);
            let initial = [
                grant(&w, read_capability(), &s, collection),
                grant(&w, write_capability(), &s, collection),
            ];
            for pile in [&mut wp, &mut sp] {
                pile.insert(&initial.iter().collect::<Vec<_>>());
                pile.select(collection);
            }
            let (s_harness, taps) = net.tap(&s);
            let mut wh = bring_up(net.join(&w), &w, wp.store);
            let mut sh = bring_up(s_harness, &s, sp.store);
            wh.activate_collection(collection);
            sh.activate_collection(collection);
            until(
                &clock,
                &mut [&mut wh, &mut sh],
                60,
                "S peered with W",
                |hosts| receives_from(hosts[1], w_id, collection),
            )
            .await;
            advance(&clock, &mut [&mut wh, &mut sh], 10).await;
            let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));

            if fault {
                taps.silence_walks(Some(WALK_AUTHORIZATION));
            }
            let late = grant(&w, write_capability(), &x, collection);
            wh.store().insert_proof(late.clone()).unwrap();
            wh.refresh();
            advance(&clock, &mut [&mut wh, &mut sh], 2).await;
            taps.silence_walks(None);
            if fault {
                assert!(taps.silenced() >= 1, "seed {seed}: the fault never fired");
                assert!(!holds_proof(&mut sh, &late), "a silenced walk delivered");
            } else {
                assert_eq!(taps.silenced(), 0);
            }
            let reached = until(
                &clock,
                &mut [&mut wh, &mut sh],
                WALK_DEADLINE.as_secs() + 20,
                "the late grant at S",
                |hosts| holds_proof(hosts[1], &late),
            )
            .await;
            println!(
                "late grant over a lossy path (fault={fault}, seed {seed}): at S \
                 {reached:?} after the fault ended"
            );
            assert_eq!(
                (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)),
                dials,
                "seed {seed}: a node dialled again"
            );
            assert!(receives_from(&sh, w_id, collection), "the peering ended");
            let walks = [(&wh, s_id), (&sh, w_id)]
                .map(|(host, other)| grant_peer(host, collection, other).expect("listing"));
            let retries = walks.iter().map(|walks| walks.retries).sum::<u64>();
            let failed = walks.iter().map(|walks| walks.ends.failed).sum::<u64>();
            if fault {
                assert!(
                    reached + Duration::from_secs(2) >= WALK_DEADLINE - Duration::from_secs(5),
                    "seed {seed}: arrived before the silenced walk could fail"
                );
                assert!(retries >= 1 && failed >= 1, "seed {seed}: {walks:?}");
            } else {
                assert!(reached <= Duration::from_secs(5), "{reached:?}");
                assert_eq!((retries, failed), (0, 0), "seed {seed}: {walks:?}");
            }
        });
    }
}

#[test]
fn a_failed_grant_walk_is_retried_on_the_same_connection() {
    a_failed_grant_walk_is_retried(true, 0x6A47_0D00);
}

#[test]
fn a_grant_walk_that_does_not_fail_is_not_retried() {
    a_failed_grant_walk_is_retried(false, 0x6A47_0D80);
}

// ---------------------------------------------------------------------------
// Scenario 10: a delegated grant that lands through a peering is completed.
// ---------------------------------------------------------------------------

/// W roots C, whose READ is Open and whose WRITE W holds; C's descriptor
/// also binds a delegable WRITE definition P rooted at W. W holds the chain
/// W -> X (P) -> Y (Q), where Q is an attenuated WRITE definition C does not
/// bind; X and Y are never online. B holds C's descriptor and P, which
/// travel together, but not Q, and is admitted to sync C by the Open READ
/// alone: it is no root of C and no key on the chain, so the chain reaches
/// it only because the connection is peered for C. The chain lands at B
/// (positive control); B then fetches Q from W, indexes the chain, so its
/// grants over C agree with W's, and admits Y as a writer of C, as W does.
#[test]
fn a_delegated_grant_landed_through_a_peering_is_completed_and_indexed() {
    use triblespace_core::capability::capability_delegate_action;
    use triblespace_core::collection::ACTION_WRITE;
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0E00 ^ seed, SimConfig::default());
            let [w, b, x, y] = [0xA1, 0xA2, 0xA3, 0xA4].map(key);
            let delegable = entity! {
                capability_action: ACTION_WRITE,
                capability_delegate_action: ACTION_WRITE,
                metadata::name: "delegable write",
            };
            let p: CapabilityHandle =
                IntoBlob::<SimpleArchive>::to_blob(delegable.facts().clone()).get_handle();
            let attenuated = entity! {
                capability_action: ACTION_WRITE,
                metadata::name: "attenuated write",
            }
            .facts()
            .clone();
            let policy = CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(w.verifying_key()),
            )
            .with_capability(delegable, AdmissionPolicy::direct(w.verifying_key()));
            let mut piles = [&w, &b].map(Pile::new);
            let typed = piles[0].store.collection("delegated", policy.clone()).unwrap();
            let collection = typed.handle();
            assert_eq!(piles[1].hold("delegated", &policy), collection);
            let q: CapabilityHandle = piles[0]
                .store
                .put::<SimpleArchive, _>(attenuated)
                .unwrap();
            let chain = grant(&w, p, &x, collection)
                .delegate(&x, q, y.verifying_key())
                .unwrap();
            piles[0].insert(&[&chain]);
            for pile in &mut piles {
                pile.select(collection);
            }
            let [w_pile, b_pile] = piles;
            let mut wh = bring_up(net.join(&w), &w, w_pile.store);
            let mut bh = bring_up(net.join(&b), &b, b_pile.store);
            for host in [&mut wh, &mut bh] {
                host.activate_collection(collection);
            }
            let (w_id, p, q) = (
                id(&w),
                CollectionHandle::new(p.raw),
                CollectionHandle::new(q.raw),
            );
            assert!(holds_blob(&mut bh, p), "B holds P with C's descriptor");
            assert!(!holds_blob(&mut bh, q), "B does not hold Q");
            let writes = |peer: &mut Peer<MemoryRepo>| {
                matches!(
                    typed.writer_is_admitted(&peer.snapshot().unwrap(), y.verifying_key()),
                    Ok(true)
                )
            };
            assert!(writes(&mut wh), "positive control: W admits Y");

            until(
                &clock,
                &mut [&mut wh, &mut bh],
                60,
                "B peered with W for C",
                |hosts| receives_from(hosts[1], w_id, collection),
            )
            .await;
            until(
                &clock,
                &mut [&mut wh, &mut bh],
                30,
                "the chain landed at B through the peering",
                |hosts| holds_proof(hosts[1], &chain),
            )
            .await;
            let local = grant_health(&wh, collection).expect("W's grants over C").local;
            assert_eq!(local.leaf_count(), 1);
            let reached = until(
                &clock,
                &mut [&mut wh, &mut bh],
                30,
                "Q fetched and the chain indexed at B",
                |hosts| {
                    holds_blob(hosts[1], q)
                        && grant_health(hosts[1], collection)
                            .is_some_and(|grants| grants.local == local)
                },
            )
            .await;
            println!(
                "delegated grant (seed {seed}): Q resident and the chain indexed at B \
                 {reached:?} virtual time after it landed, in 100 ms steps"
            );
            assert!(writes(&mut bh), "seed {seed}: B admits Y");
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 11: listings that arrive before the first store observation.
// ---------------------------------------------------------------------------

/// The keys of W and S, S's id the lower or the higher of the two.
fn w_and_s(s_lower: bool) -> [SigningKey; 2] {
    let mut keys = [0x97, 0x98].map(key);
    keys.sort_unstable_by_key(id);
    if s_lower {
        keys.reverse();
    }
    keys
}

/// The connections whose `recon/1` opened between the tapped host and `peer`
/// since the `from`-th frame.
fn connections(taps: &Taps, from: usize, peer: PeerId) -> usize {
    taps.since(from, peer, TAG_RECON)
        .iter()
        .filter(|crossed| crossed.kind == recon::FRAME_OPEN)
        .count()
}

/// How many of `collections` `host` heard `peer` list on their connection.
fn heard(host: &Peer<MemoryRepo>, collections: &[CollectionHandle], peer: PeerId) -> usize {
    let wanted = collections.iter().map(|collection| collection.raw).collect::<BTreeSet<_>>();
    host.health()
        .grants
        .iter()
        .filter(|grants| wanted.contains(&grants.resource.raw))
        .filter(|grants| {
            grants.peers.iter().any(|listing| listing.peer == peer && listing.listed.is_some())
        })
        .count()
}

/// How `host` counts its pairs with `peer` over `collections`: unknown,
/// behind, current.
fn pairs(host: &Peer<MemoryRepo>, collections: &[CollectionHandle], peer: PeerId) -> [usize; 3] {
    let health = host.health();
    let now = clock::mono_now();
    let mut counts = [0; 3];
    for collection in collections {
        counts[match health.pair(*collection, peer, now, DEFAULT_MAX_AGE) {
            PairState::Unknown => 0,
            PairState::Behind { .. } => 1,
            PairState::Current => 2,
        }] += 1;
    }
    counts
}

type Wired = (
    host::NetSender<<MemoryRepo as SnapshotSource>::Snapshot>,
    host::NetReceiver,
);

/// A host on `harness` that accepts connections and has observed no store.
fn bring_up_cold<T: Transport>(harness: Harness<T>, key: &SigningKey, daemon: Option<VerifyingKey>) -> Wired {
    let (sender, receiver, wiring) = host::wire(EndpointId::from_bytes(&id(key)).unwrap());
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            daemon,
            provider_publication_budget: Some(0),
            bind: None,
        },
        wiring,
    ));
    (sender, receiver)
}

/// The piles of W and S, which share `shared` collections W roots, each with
/// S's READ grant at both. W also holds a grant over the last of them, in
/// handle order, that S never saw.
struct Shared {
    w: SigningKey,
    s: SigningKey,
    wp: Pile,
    sp: Pile,
    collections: Vec<CollectionHandle>,
    missed: CapabilityProof,
}

impl Shared {
    fn new([w, s]: [SigningKey; 2], shared: usize) -> Self {
        let policy = private_policy(w.verifying_key());
        let mut wp = Pile::new(&w);
        let mut sp = Pile::new(&s);
        let mut collections = Vec::new();
        for index in 0..shared {
            let name = format!("shared {index}");
            let collection = wp.hold(&name, &policy);
            assert_eq!(sp.hold(&name, &policy), collection);
            for pile in [&mut wp, &mut sp] {
                pile.insert(&[&grant(&w, read_capability(), &s, collection)]);
                pile.select(collection);
            }
            collections.push(collection);
        }
        collections.sort_unstable_by_key(|collection| collection.raw);
        let missed = grant(&w, write_capability(), &key(0x99), *collections.last().unwrap());
        wp.insert(&[&missed]);
        Self { w, s, wp, sp, collections, missed }
    }

    fn last(&self) -> CollectionHandle {
        *self.collections.last().unwrap()
    }
}

/// S restarted alone: its host accepts connections and has observed no store
/// yet, and W, which keeps running, has listed everything the two share to
/// it on the connection W dialled.
struct Cold {
    net: SimNet,
    shared: Shared,
    w_id: PeerId,
    s_id: PeerId,
    wh: Peer<MemoryRepo>,
    wired: Wired,
    taps: Taps,
}

impl Cold {
    async fn new(clock: &Arc<VirtualClock>, seed: u64, s_lower: bool, shared: usize) -> Self {
        let net = SimNet::new(0x6A47_0E00 ^ seed, SimConfig::default());
        let mut shared = Shared::new(w_and_s(s_lower), shared);
        let (w_id, s_id) = (id(&shared.w), id(&shared.s));
        let (s_harness, taps) = net.tap(&shared.s);
        let wp = std::mem::take(&mut shared.wp.store);
        let mut wh = bring_up(net.join(&shared.w), &shared.w, wp);
        let wired = bring_up_cold(s_harness, &shared.s, None);
        wh.activate_collections(shared.collections.iter().copied());
        until(clock, &mut [&mut wh], 60, "W's listing at S", |_| {
            listed(&taps, 0, w_id, false).len() >= shared.collections.len()
        })
        .await;
        advance(clock, &mut [&mut wh], 2).await;
        assert!(listed(&taps, 0, w_id, true).is_empty(), "S has observed nothing yet");
        assert_eq!(opens(&taps, 0, w_id, WALK_AUTHORIZATION), 0, "no walk can be in flight");
        assert_eq!(opens(&taps, 0, w_id, WALK_COMMIT), 0, "no walk can be in flight");
        assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), (1, 0));
        assert_eq!(connections(&taps, 0, w_id), 1);
        Self { net, shared, w_id, s_id, wh, wired, taps }
    }

    fn dials(&self) -> (usize, usize) {
        (
            self.net.dial_count(self.w_id, self.s_id),
            self.net.dial_count(self.s_id, self.w_id),
        )
    }

    /// S's first store observation, which a peer over a running host takes
    /// as it is made, and S's activation `gap` seconds later.
    async fn observe(
        self,
        clock: &Arc<VirtualClock>,
        gap: u64,
    ) -> (Restarted, Peer<MemoryRepo>, Peer<MemoryRepo>) {
        let dials = self.dials();
        let Self { net, mut shared, w_id, s_id, mut wh, wired, taps } = self;
        let store = std::mem::take(&mut shared.sp.store);
        assert_eq!(listed(&taps, 0, w_id, true).len(), 0);
        let from = taps.len();
        let mut sh = Peer::with_wiring(store, wired.0, wired.1);
        assert_eq!(pairs(&sh, &shared.collections, w_id), [shared.collections.len(), 0, 0]);
        advance(clock, &mut [&mut wh, &mut sh], gap).await;
        sh.activate_collections(shared.collections.iter().copied());
        (Restarted { net, shared, w_id, s_id, taps, from, dials }, wh, sh)
    }
}

/// S after its first observation; `from` and `dials` are from just before it.
struct Restarted {
    net: SimNet,
    shared: Shared,
    w_id: PeerId,
    s_id: PeerId,
    taps: Taps,
    from: usize,
    dials: (usize, usize),
}

impl Restarted {
    /// Connections opened and dials made by W and by S since.
    fn since(&self) -> (usize, usize, usize) {
        (
            connections(&self.taps, self.from, self.w_id),
            self.net.dial_count(self.w_id, self.s_id) - self.dials.0,
            self.net.dial_count(self.s_id, self.w_id) - self.dials.1,
        )
    }

    fn unheard(&self, sh: &Peer<MemoryRepo>) -> usize {
        self.shared.collections.len() - heard(sh, &self.shared.collections, self.w_id)
    }
}

/// S restarts alone while W keeps running: W's listing of every collection
/// the two share reaches S before S's first store observation, when S cannot
/// yet tell what it takes part in. They share more collections than a
/// connection may list unknown ones, so S skips some, until W lists all of
/// them again on the same connection. W also holds a grant over the last
/// collection listed that S never saw.
#[test]
fn a_listing_heard_before_the_first_observation_is_not_lost() {
    for s_lower in [true, false] {
        for seed in 0..SEEDS {
            run(async |clock| {
                let cold =
                    Cold::new(&clock, seed, s_lower, UNKNOWN_RESOURCES_PER_LINK + 44).await;
                // Every other seed, S activates a while after it observed.
                let gap = 4 * (seed % 2);
                let (restarted, mut wh, mut sh) = cold.observe(&clock, gap).await;
                let total = restarted.shared.collections.len();
                let collections = restarted.shared.collections.clone();
                let w_id = restarted.w_id;
                let mut states = Vec::new();
                let started = clock::mono_now();
                let mut relisted = None;
                for _ in 0..REPEATED * 10 {
                    SimNet::step(&clock, Duration::from_millis(100)).await;
                    wh.refresh();
                    sh.refresh();
                    let after = clock::mono_now().duration_since(started);
                    if relisted.is_none() && restarted.unheard(&sh) == 0 {
                        relisted = Some(after);
                    }
                    let state = pairs(&sh, &collections, w_id);
                    if states.last().is_none_or(|(_, last)| *last != state) {
                        states.push((after, state));
                    }
                }
                let (opened, by_w, by_s) = restarted.since();
                let again = listed(&restarted.taps, restarted.from, w_id, false);
                let last = restarted.shared.last();
                let walks = |sent: bool| {
                    restarted
                        .taps
                        .since(restarted.from, w_id, TAG_WALK)
                        .iter()
                        .filter(|crossed| {
                            crossed.sent == sent
                                && crossed.kind == FRAME_OPEN
                                && crossed.walk_kind == Some(WALK_AUTHORIZATION)
                                && crossed.walk_resource == Some(last.raw)
                        })
                        .count()
                };
                let arrived = holds_proof(&mut sh, &restarted.shared.missed);
                println!(
                    "S lower {s_lower}, seed {seed}, activated after {gap} s: unheard {} of {total}, listed again {}, all \
                     heard after {relisted:?}; connections since {opened}, dials by W {by_w} and \
                     by S {by_s}; grant walks over the last opened by S {} and by W {}, the \
                     missed grant arrived: {arrived}",
                    restarted.unheard(&sh),
                    again.len(),
                    walks(true),
                    walks(false),
                );
                if seed == 0 {
                    println!("  S's pairs with W (unknown, behind, current): {states:?}");
                }
                assert_eq!(restarted.unheard(&sh), 0, "lost for good");
                assert!(arrived, "the missed grant");
                assert_eq!((opened, by_w, by_s), (0, 0, 0), "on the same connection");
                assert!(receives_from(&sh, w_id, last), "S is peered with W");
            });
        }
    }
}

/// The control: a listing the budget covers leaves the connection alone.
#[test]
fn a_listing_within_the_budget_before_the_first_observation_keeps_its_connection() {
    for shared in [200, UNKNOWN_RESOURCES_PER_LINK] {
        for s_lower in [true, false] {
            run(async |clock| {
                let cold = Cold::new(&clock, 0, s_lower, shared).await;
                let (restarted, mut wh, mut sh) = cold.observe(&clock, 0).await;
                advance(&clock, &mut [&mut wh, &mut sh], 90).await;
                assert_eq!(restarted.unheard(&sh), 0);
                assert!(holds_proof(&mut sh, &restarted.shared.missed));
                assert_eq!(restarted.since(), (0, 0, 0), "{shared} shared: reconnected");
            });
        }
    }
}

/// The other control: S observes its store before W lists anything, so it
/// knows what it takes part in and nothing is cut short.
#[test]
fn a_listing_heard_after_the_first_observation_keeps_its_connection() {
    for s_lower in [true, false] {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0E40, SimConfig::default());
            let mut shared = Shared::new(w_and_s(s_lower), UNKNOWN_RESOURCES_PER_LINK + 44);
            let (w_id, s_id) = (id(&shared.w), id(&shared.s));
            let (s_harness, taps) = net.tap(&shared.s);
            let mut sh = bring_up(s_harness, &shared.s, std::mem::take(&mut shared.sp.store));
            sh.activate_collections(shared.collections.iter().copied());
            advance(&clock, &mut [&mut sh], 3).await;
            let mut wh =
                bring_up(net.join(&shared.w), &shared.w, std::mem::take(&mut shared.wp.store));
            wh.activate_collections(shared.collections.iter().copied());
            let dials = net.dial_count(s_id, w_id);
            advance(&clock, &mut [&mut wh, &mut sh], 90).await;
            assert_eq!(heard(&sh, &shared.collections, w_id), shared.collections.len());
            assert!(holds_proof(&mut sh, &shared.missed));
            let dialled = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id) - dials);
            assert!(dialled.0 <= 1 && dialled.1 <= 1, "{dialled:?}");
            assert_eq!(connections(&taps, 0, w_id), dialled.0 + dialled.1);
        });
    }
}

/// Both hosts restart. S observes its store first, dials W and lists to it
/// while W has observed nothing: W hears all of it at S's next repeat.
#[test]
fn of_two_restarted_hosts_the_later_one_hears_the_next_repeat() {
    for s_lower in [true, false] {
        for seed in 0..SEEDS / 2 {
            run(async |clock| {
                let net = SimNet::new(0x6A47_0E80 ^ seed, SimConfig::default());
                let mut shared = Shared::new(w_and_s(s_lower), UNKNOWN_RESOURCES_PER_LINK + 44);
                let (w_id, s_id) = (id(&shared.w), id(&shared.s));
                let (s_harness, taps) = net.tap(&shared.s);
                let mut sh = bring_up(s_harness, &shared.s, std::mem::take(&mut shared.sp.store));
                let wired = bring_up_cold(net.join(&shared.w), &shared.w, None);
                sh.activate_collections(shared.collections.iter().copied());
                until(&clock, &mut [&mut sh], 60, "S's listing to W", |_| {
                    listed(&taps, 0, w_id, true).len() >= shared.collections.len()
                })
                .await;
                advance(&clock, &mut [&mut sh], 2).await;
                let from = taps.len();
                let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));
                let mut wh =
                    Peer::with_wiring(std::mem::take(&mut shared.wp.store), wired.0, wired.1);
                wh.activate_collections(shared.collections.iter().copied());
                let total = shared.collections.len();
                let took = until(
                    &clock,
                    &mut [&mut wh, &mut sh],
                    REPEATED,
                    "each side's listing at the other",
                    |hosts| {
                        heard(hosts[0], &shared.collections, s_id) == total
                            && heard(hosts[1], &shared.collections, w_id) == total
                    },
                )
                .await;
                advance(&clock, &mut [&mut wh, &mut sh], 60).await;
                assert_eq!(heard(&wh, &shared.collections, s_id), total);
                assert_eq!(heard(&sh, &shared.collections, w_id), total);
                assert!(holds_proof(&mut sh, &shared.missed));
                let opened = connections(&taps, from, w_id);
                let by_w = net.dial_count(w_id, s_id) - dials.0;
                let by_s = net.dial_count(s_id, w_id) - dials.1;
                println!(
                    "both restarted (S lower {s_lower}, seed {seed}): all heard after {took:?}; \
                     connections since {opened}, dials by W {by_w} and by S {by_s}"
                );
                assert_eq!((opened, by_w, by_s), (0, 0, 0));
            });
        }
    }
}

/// A stranger driven by hand lists 300 junk resources before S has observed
/// anything: a walk it opens is refused, and the listing is cut short. S's
/// first observation gives none of those slots back, drops nothing and dials
/// nobody, and the same listing on another connection meets the same budget.
#[test]
fn a_stranger_cut_short_early_keeps_its_budget_and_is_never_dialled() {
    run(async |clock| {
        let net = SimNet::new(0x6A47_0EC0, SimConfig::default());
        let [s, z] = [0x98, 0x9A].map(key);
        let (s_id, z_id) = (id(&s), id(&z));
        let mut sp = Pile::new(&s);
        let own = sp.hold("own", &private_policy(s.verifying_key()));
        sp.select(own);
        let delivery = delivery_definition().get_handle();
        let listing = (0..UNKNOWN_RESOURCES_PER_LINK + 44)
            .map(|index| {
                let mut raw = delivery.raw;
                raw[..8].copy_from_slice(&(index as u64).to_be_bytes());
                let resource = CollectionHandle::new(raw);
                (resource, one_grant(resource, &grant(&z, delivery, &s, resource)).0)
            })
            .collect::<Vec<_>>();
        let (sender, receiver) = bring_up_cold(net.join(&s), &s, None);
        let Harness { transport: z_transport, mut incoming } = net.join(&z);
        tokio::task::spawn_local(async move { while incoming.recv().await.is_some() {} });
        let connect = async |sequence: u64| {
            let conn = z_transport.dial(s_id, PILE_SYNC_ALPN).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&[TAG_RECON]).await.unwrap();
            send.write_all(&framed(recon::FRAME_OPEN, &sequence.to_be_bytes()))
                .await
                .unwrap();
            for frame in grant_roots_frames(&listing) {
                let (kind, payload) = frame.encode();
                send.write_all(&framed(kind, &payload)).await.unwrap();
            }
            // Whether the connection has ended, and the walks S opened on it.
            let ended = Rc::new(RefCell::new((false, 0)));
            let (reader, acceptor) = (ended.clone(), ended.clone());
            let accepting = conn.clone();
            tokio::task::spawn_local(async move {
                let _recon = send;
                while recv.read_u8().await.is_ok() {}
                reader.borrow_mut().0 = true;
            });
            tokio::task::spawn_local(async move {
                let mut streams = Vec::new();
                while let Some(stream) = accepting.accept_bi().await {
                    acceptor.borrow_mut().1 += 1;
                    streams.push(stream);
                }
            });
            (conn, ended)
        };
        let (conn, first) = connect(1).await;
        advance(&clock, &mut [], 2).await;
        // A grant walk over a junk resource, opened before S observed.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[TAG_WALK]).await.unwrap();
        let mut open = listing[0].0.raw.to_vec();
        open.extend([WALK_AUTHORIZATION, 0]);
        send.write_all(&framed(FRAME_OPEN, &open)).await.unwrap();
        advance(&clock, &mut [], 2).await;
        let refused = recv.read_u8().await.unwrap_err();
        assert_eq!(reset_code(&refused), Some(RESET_WALK_REFUSED), "{refused}");
        assert_eq!(*first.borrow(), (false, 0), "S neither ended it nor walked");

        let mut sh = Peer::with_wiring(sp.store, sender, receiver);
        sh.activate_collection(own);
        advance(&clock, &mut [&mut sh], 5).await;
        assert!(!first.borrow().0, "not dropped");
        assert!(first.borrow().1 >= GRANT_WALKS_PER_PEER, "walked now that S can tell");
        conn.close(0, b"the next one");
        advance(&clock, &mut [&mut sh], 1).await;
        let (_conn, second) = connect(2).await;
        until(&clock, &mut [&mut sh], 30, "walks over the second listing", |_| {
            second.borrow().1 >= GRANT_WALKS_PER_PEER
        })
        .await;
        // A later observation that changes something is no first one.
        let late = grant(&s, read_capability(), &key(0x9B), own);
        sh.store().insert_proof(late).unwrap();
        advance(&clock, &mut [&mut sh], 60).await;
        assert!(!second.borrow().0, "not dropped");
        let kept = sh
            .health()
            .grants
            .iter()
            .filter(|grants| grants.peers.iter().any(|listing| listing.listed.is_some()))
            .count();
        assert_eq!(kept, UNKNOWN_RESOURCES_PER_LINK, "the same budget");
        assert_eq!(net.dial_count(s_id, z_id), 0, "S dials no stranger");
    });
}

/// A host that never observes a store, as a leech's does: a dial it makes
/// completes, its fetches work, W's listing is cut short, and nothing
/// reconnects, since nothing is ever observed.
#[test]
fn a_host_that_never_observes_keeps_its_connection() {
    for s_lower in [true, false] {
        run(async |clock| {
            let net = SimNet::new(0x6A47_0F00, SimConfig::default());
            let mut shared = Shared::new(w_and_s(s_lower), UNKNOWN_RESOURCES_PER_LINK + 44);
            let (w_id, s_id) = (id(&shared.w), id(&shared.s));
            let (s_harness, taps) = net.tap(&shared.s);
            let mut wh =
                bring_up(net.join(&shared.w), &shared.w, std::mem::take(&mut shared.wp.store));
            let (sender, _receiver) = bring_up_cold(s_harness, &shared.s, Some(shared.w.verifying_key()));
            wh.refresh();
            let fetch = async |wh: &mut Peer<MemoryRepo>, handle: CollectionHandle| {
                let mut fetch =
                    std::pin::pin!(sender.fetch_blob(handle.raw, Duration::from_secs(20)));
                for _ in 0..200 {
                    tokio::select! {
                        biased;
                        fetched = &mut fetch => return fetched.is_some(),
                        () = SimNet::step(&clock, Duration::from_millis(100)) => wh.refresh(),
                    }
                }
                false
            };
            assert!(fetch(&mut wh, shared.collections[0]).await, "before any listing");
            assert!(net.dial_count(s_id, w_id) >= 1, "S's own dial completed");
            wh.activate_collections(shared.collections.iter().copied());
            until(&clock, &mut [&mut wh], 60, "W's listing at S", |_| {
                listed(&taps, 0, w_id, false).len() >= shared.collections.len()
            })
            .await;
            let from = taps.len();
            let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));
            assert!(fetch(&mut wh, shared.collections[1]).await, "after W's listing");
            advance(&clock, &mut [&mut wh], 100).await;
            assert_eq!(connections(&taps, from, w_id), 0, "reconnected");
            assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), dials);
            assert!(sender.health().grants.is_empty(), "S observed nothing");
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 12: everything is listed again on a connection that stays open.
// ---------------------------------------------------------------------------

/// The longest time between two listings of everything on a connection
/// (grants.rs `MIN_REPEAT` and `REPEAT_JITTER`), and some seconds' slack.
const REPEATED: u64 = 305;
/// The shortest (grants.rs `MIN_REPEAT`).
const REPEATS_AFTER: u64 = 270;
/// When a connection nothing crosses closes (connection.rs
/// `CONNECTION_IDLE_DEADLINE`).
const IDLE: u64 = 120;

/// Two hosts start together and sync five collections. The first listing
/// each sent the other, or only W's, is lost as it arrives, so the hearer's
/// pairs never turn current although every record and grant is there. The
/// next repeat heals them, on the connection as it stands.
#[test]
fn a_lost_listing_is_heard_at_the_next_repeat() {
    for both in [false, true] {
        for s_lower in [true, false] {
            for seed in 0..SEEDS {
                run(async |clock| {
                    let net = SimNet::new(0x6A47_1000 ^ seed, SimConfig::default());
                    let mut shared = Shared::new(w_and_s(s_lower), 5);
                    let (w_id, s_id) = (id(&shared.w), id(&shared.s));
                    let (s_harness, at_s) = net.tap(&shared.s);
                    let (w_harness, at_w) = net.tap(&shared.w);
                    // Crossed dials make two connections; what each lists is lost.
                    at_s.lose_listings(usize::MAX);
                    at_w.lose_listings(if both { usize::MAX } else { 0 });
                    let mut wh =
                        bring_up(w_harness, &shared.w, std::mem::take(&mut shared.wp.store));
                    let mut sh =
                        bring_up(s_harness, &shared.s, std::mem::take(&mut shared.sp.store));
                    wh.activate_collections(shared.collections.iter().copied());
                    sh.activate_collections(shared.collections.iter().copied());
                    let started = clock::mono_now();
                    advance(&clock, &mut [&mut wh, &mut sh], 100).await;
                    assert!(at_s.lost() >= 1 && (at_w.lost() >= 1) == both);
                    at_s.lose_listings(0);
                    at_w.lose_listings(0);
                    advance(&clock, &mut [&mut wh, &mut sh], 100).await;
                    assert_eq!(heard(&sh, &shared.collections, w_id), 0, "lost, and not repeated yet");
                    assert_eq!(pairs(&sh, &shared.collections, w_id)[2], 0, "never current");
                    for collection in &shared.collections {
                        assert!(receives_from(&sh, w_id, *collection), "control: they sync");
                    }
                    let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));
                    let from = at_s.len();
                    until(
                        &clock,
                        &mut [&mut wh, &mut sh],
                        REPEATED,
                        "every listing at both",
                        |hosts| {
                            heard(hosts[1], &shared.collections, w_id) == 5
                                && heard(hosts[0], &shared.collections, s_id) == 5
                        },
                    )
                    .await;
                    let took = clock::mono_now().duration_since(started);
                    assert!(took >= Duration::from_secs(REPEATS_AFTER - 5), "{took:?}");
                    println!("lost at S (and at W: {both}), S lower {s_lower}, seed {seed}: heard after {took:?}");
                    until(&clock, &mut [&mut wh, &mut sh], 10, "current pairs", |hosts| {
                        pairs(hosts[1], &shared.collections, w_id)[2] == 5
                            && pairs(hosts[0], &shared.collections, s_id)[2] == 5
                    })
                    .await;
                    assert!(holds_proof(&mut sh, &shared.missed));
                    assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), dials);
                    assert_eq!(connections(&at_s, from, w_id), 0, "the same connection");
                });
            }
        }
    }
}

/// A changed root whose listing is lost: S thinks it agrees with W and no
/// walk opens, so the grant W made does not reach S until the next repeat.
#[test]
fn a_grant_whose_listing_was_lost_arrives_at_the_next_repeat() {
    for s_lower in [true, false] {
        for seed in 0..SEEDS {
            run(async |clock| {
                let net = SimNet::new(0x6A47_1040 ^ seed, SimConfig::default());
                let mut shared = Shared::new(w_and_s(s_lower), 2);
                let w_id = id(&shared.w);
                let (s_harness, taps) = net.tap(&shared.s);
                let mut wh =
                    bring_up(net.join(&shared.w), &shared.w, std::mem::take(&mut shared.wp.store));
                let mut sh = bring_up(s_harness, &shared.s, std::mem::take(&mut shared.sp.store));
                wh.activate_collections(shared.collections.iter().copied());
                sh.activate_collections(shared.collections.iter().copied());
                until(&clock, &mut [&mut wh, &mut sh], 60, "agreement", |hosts| {
                    pairs(hosts[1], &shared.collections, w_id)[2] == 2
                })
                .await;
                // A retry left from the first walks would walk the change.
                advance(&clock, &mut [&mut wh, &mut sh], 10 + seed * 10).await;
                taps.lose_listings(usize::MAX);
                let late = grant(&shared.w, read_capability(), &key(0x9C), shared.collections[0]);
                wh.store().insert_proof(late.clone()).unwrap();
                wh.refresh();
                advance(&clock, &mut [&mut wh, &mut sh], 5).await;
                assert!(taps.lost() >= 1);
                taps.lose_listings(0);
                advance(&clock, &mut [&mut wh, &mut sh], 95).await;
                assert!(!holds_proof(&mut sh, &late), "S was not told");
                let took = until(
                    &clock,
                    &mut [&mut wh, &mut sh],
                    REPEATED,
                    "the late grant at S",
                    |hosts| holds_proof(hosts[1], &late),
                )
                .await;
                println!("S lower {s_lower}, seed {seed}: {took:?} after the first 100 s");
            });
        }
    }
}

/// W and S root 300 collections together, over which nobody holds a grant.
/// S has observed its store but has nothing active, so it can tell nothing
/// it takes part in: the budget keeps 256 of W's entries and skips 44, and
/// no first observation is ahead that would drop the connection. S activates
/// them all later. The next repeat heals the 44 on the same connection.
#[test]
fn collections_activated_after_their_listing_was_skipped_are_heard_at_the_next_repeat() {
    for s_lower in [true, false] {
        for seed in 0..SEEDS / 2 {
            run(async |clock| {
                let net = SimNet::new(0x6A47_1080 ^ seed, SimConfig::default());
                let [w, s] = w_and_s(s_lower);
                let (w_id, s_id) = (id(&w), id(&s));
                let both = || {
                    AdmissionPolicy::quorum([w.verifying_key(), s.verifying_key()], 1, None).unwrap()
                };
                let policy = CollectionPolicy::new(both(), both());
                let (mut wp, mut sp) = (Pile::new(&w), Pile::new(&s));
                let collections = (0..UNKNOWN_RESOURCES_PER_LINK + 44)
                    .map(|index| {
                        let name = format!("grantless {index}");
                        let collection = wp.hold(&name, &policy);
                        assert_eq!(sp.hold(&name, &policy), collection);
                        wp.select(collection);
                        sp.select(collection);
                        collection
                    })
                    .collect::<Vec<_>>();
                let (s_harness, taps) = net.tap(&s);
                let mut sh = bring_up(s_harness, &s, sp.store);
                advance(&clock, &mut [&mut sh], 3).await;
                let mut wh = bring_up(net.join(&w), &w, wp.store);
                wh.activate_collections(collections.iter().copied());
                until(&clock, &mut [&mut wh, &mut sh], 60, "W's listing at S", |_| {
                    listed(&taps, 0, w_id, false).len() == collections.len()
                })
                .await;
                advance(&clock, &mut [&mut wh, &mut sh], 2 + seed).await;
                let started = clock::mono_now();
                sh.activate_collections(collections.iter().copied());
                advance(&clock, &mut [&mut wh, &mut sh], 100).await;
                assert_eq!(heard(&sh, &collections, w_id), UNKNOWN_RESOURCES_PER_LINK);
                let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));
                until(&clock, &mut [&mut wh, &mut sh], REPEATED, "all heard", |hosts| {
                    heard(hosts[1], &collections, w_id) == collections.len()
                })
                .await;
                let took = clock::mono_now().duration_since(started);
                until(&clock, &mut [&mut wh, &mut sh], 10, "all current", |hosts| {
                    pairs(hosts[1], &collections, w_id)[2] == collections.len()
                })
                .await;
                println!("S lower {s_lower}, seed {seed}: heard {took:?} after activation");
                assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), dials);
                assert_eq!(connections(&taps, 0, w_id), 1, "one connection throughout");
            });
        }
    }
}

/// A peer driven by hand over a connection it dialled: it sends what a test
/// tells it to, reads what arrives unless told not to, and refuses every walk
/// at once.
struct ByHand {
    conn: triblespace_net::transport::sim::SimConn,
    recon: SimSendStream,
    /// Walk streams the host opened, and whether the connection ended.
    seen: Rc<RefCell<(usize, bool)>>,
    /// It reads nothing while this is set.
    deaf: Rc<RefCell<bool>>,
}

impl ByHand {
    async fn dial(
        transport: &triblespace_net::transport::sim::SimTransport,
        host: PeerId,
        sequence: u64,
    ) -> Self {
        let conn = transport.dial(host, PILE_SYNC_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[TAG_RECON]).await.unwrap();
        send.write_all(&framed(recon::FRAME_OPEN, &sequence.to_be_bytes()))
            .await
            .unwrap();
        let seen = Rc::new(RefCell::new((0, false)));
        let deaf = Rc::new(RefCell::new(false));
        let (reader, acceptor, ears) = (seen.clone(), seen.clone(), deaf.clone());
        tokio::task::spawn_local(async move {
            let mut arrived = [0; 4096];
            loop {
                while *ears.borrow() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                if !matches!(recv.read(&mut arrived).await, Ok(1..)) {
                    break;
                }
            }
            reader.borrow_mut().1 = true;
        });
        let accepting = conn.clone();
        tokio::task::spawn_local(async move {
            while let Some((mut send, _recv)) = accepting.accept_bi().await {
                acceptor.borrow_mut().0 += 1;
                send.reset(RESET_WALK_REFUSED);
            }
        });
        Self { conn, recon: send, seen, deaf }
    }

    async fn frame(&mut self, kind: u8, payload: &[u8]) {
        // A connection that has ended takes nothing more.
        let _ = self.recon.write_all(&framed(kind, payload)).await;
    }

    async fn list(&mut self, roots: &[(CollectionHandle, PatchSummary)]) {
        for frame in grant_roots_frames(roots) {
            let (kind, payload) = frame.encode();
            self.frame(kind, &payload).await;
        }
    }
}

/// 300 resources a key nobody knows lists, each with a grant to `subject`.
fn junk_listing(root: &SigningKey, subject: &SigningKey) -> Vec<(CollectionHandle, PatchSummary)> {
    let delivery = delivery_definition().get_handle();
    (0..UNKNOWN_RESOURCES_PER_LINK + 44)
        .map(|index| {
            let mut raw = delivery.raw;
            raw[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let resource = CollectionHandle::new(raw);
            (resource, one_grant(resource, &grant(root, delivery, subject, resource)).0)
        })
        .collect()
}

/// A stranger that lists 300 unknown resources every five seconds for ten
/// minutes gains nothing over one that listed them once: the same 256 kept
/// and, over the same time, no more walks, each of which it refuses. Nobody
/// dials it.
#[test]
fn a_stranger_gains_nothing_by_repeating_its_listing() {
    for seed in 0..SEEDS / 2 {
        let walks = [false, true].map(|repeats| {
            let opened = Rc::new(RefCell::new(0));
            let out = opened.clone();
            run(async |clock| {
                let net = SimNet::new(0x6A47_10C0 ^ seed, SimConfig::default());
                let [s, z] = [0x98, 0x9A].map(key);
                let mut sp = Pile::new(&s);
                let own = sp.hold("own", &private_policy(s.verifying_key()));
                sp.select(own);
                let mut sh = bring_up(net.join(&s), &s, sp.store);
                sh.activate_collection(own);
                advance(&clock, &mut [&mut sh], 2).await;
                let Harness { transport, mut incoming } = net.join(&z);
                tokio::task::spawn_local(async move { while incoming.recv().await.is_some() {} });
                let listing = junk_listing(&z, &s);
                let mut stranger = ByHand::dial(&transport, id(&s), 1).await;
                stranger.list(&listing).await;
                for _ in 0..120 {
                    advance(&clock, &mut [&mut sh], 5).await;
                    if repeats {
                        stranger.list(&listing).await;
                    }
                }
                let kept = sh
                    .health()
                    .grants
                    .iter()
                    .filter(|grants| grants.peers.iter().any(|peer| peer.listed.is_some()))
                    .count();
                assert_eq!(kept, UNKNOWN_RESOURCES_PER_LINK);
                assert!(!stranger.seen.borrow().1, "control: the connection stood throughout");
                assert_eq!(net.dial_count(id(&s), id(&z)), 0);
                *out.borrow_mut() = stranger.seen.borrow().0;
            });
            *opened.borrow()
        });
        println!("seed {seed}: walks opened to one that listed once {}, every 5 s {}", walks[0], walks[1]);
        // Each is opened again at 1, 3, 7, 15, 31 and 63 s, then every minute.
        assert!(walks[0] >= 14 * UNKNOWN_RESOURCES_PER_LINK, "control: {walks:?}");
        assert!(walks[1] <= walks[0] + UNKNOWN_RESOURCES_PER_LINK, "{walks:?}");
    }
}

/// W rooted `resources` of which S holds a grant, as of secret versions, and
/// which nobody selects; with `peered`, also a collection they sync.
struct Granted {
    w: SigningKey,
    s: SigningKey,
    wp: Pile,
    sp: Pile,
    synced: CollectionHandle,
    resources: Vec<CollectionHandle>,
}

impl Granted {
    fn new([w, s]: [SigningKey; 2], resources: usize) -> Self {
        let mut wp = Pile::new(&w);
        let mut sp = Pile::new(&s);
        let policy = private_policy(w.verifying_key());
        let synced = wp.hold("synced", &policy);
        sp.hold("synced", &policy);
        let reads = grant(&w, read_capability(), &s, synced);
        let definition = delivery_definition();
        let delivery = definition.get_handle();
        for pile in [&mut wp, &mut sp] {
            pile.insert(&[&reads]);
            pile.store.put::<SimpleArchive, _>(definition.clone()).unwrap();
        }
        let resources = (0..resources)
            .map(|index| {
                let descriptor = entity! {
                    metadata::tag: KIND_TEST_RESOURCE,
                    metadata::name: format!("version {index}"),
                    resource_policy*: AdmissionPolicy::direct(w.verifying_key()).binding(delivery),
                }
                .facts()
                .clone();
                let resource = wp.store.put::<SimpleArchive, _>(descriptor.clone()).unwrap();
                sp.store.put::<SimpleArchive, _>(descriptor).unwrap();
                let proof = grant(&w, delivery, &s, resource);
                wp.insert(&[&proof]);
                sp.insert(&[&proof]);
                resource
            })
            .collect();
        Self { w, s, wp, sp, synced, resources }
    }
}

/// GRANT_ROOTS frames and their bytes that crossed since the `from`-th frame,
/// either way.
fn listings(taps: &Taps, from: usize, peer: PeerId) -> (usize, usize) {
    taps.since(from, peer, TAG_RECON)
        .iter()
        .filter(|crossed| crossed.kind == recon::FRAME_GRANT_ROOTS)
        .fold((0, 0), |(frames, bytes), crossed| (frames + 1, bytes + crossed.wire_bytes))
}

/// CPU time this thread used.
fn cpu() -> Duration {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
    Duration::from_nanos(stat.split(' ').next().and_then(|ns| ns.parse().ok()).unwrap_or(0))
}

/// Two hosts that share 2,000 resources and one collection, agreed, idle for
/// ten minutes: the listings repeat, and nothing else that has to do with
/// grants happens. Printed, so that two builds can be compared: what crossed,
/// and the thread's CPU time, which is both hosts' and the simulation's.
#[test]
fn two_thousand_agreed_resources_idle_for_ten_minutes() {
    run(async |clock| {
        let net = SimNet::new(0x6A47_1100, SimConfig::default());
        let mut granted = Granted::new(w_and_s(true), 2000);
        let (w_id, s_id) = (id(&granted.w), id(&granted.s));
        granted.wp.select(granted.synced);
        granted.sp.select(granted.synced);
        let (s_harness, taps) = net.tap(&granted.s);
        let mut wh =
            bring_up(net.join(&granted.w), &granted.w, std::mem::take(&mut granted.wp.store));
        let mut sh = bring_up(s_harness, &granted.s, std::mem::take(&mut granted.sp.store));
        wh.activate_collection(granted.synced);
        sh.activate_collection(granted.synced);
        until(&clock, &mut [&mut wh, &mut sh], 120, "every resource heard", |hosts| {
            heard(hosts[1], &granted.resources, w_id) == granted.resources.len()
                && heard(hosts[0], &granted.resources, s_id) == granted.resources.len()
        })
        .await;
        advance(&clock, &mut [&mut wh, &mut sh], 30).await;
        let (from, before) = (taps.len(), cpu());
        let dials = (net.dial_count(w_id, s_id), net.dial_count(s_id, w_id));
        let totals = |host: &Peer<MemoryRepo>| {
            host.health()
                .grants
                .iter()
                .flat_map(|grants| &grants.peers)
                .map(|peer| peer.ends.failed + peer.skipped + peer.pending + peer.retries)
                .sum::<u64>()
        };
        advance(&clock, &mut [&mut wh, &mut sh], 600).await;
        let used = cpu() - before;
        let (frames, bytes) = listings(&taps, from, w_id);
        let other = taps.since(from, w_id, TAG_RECON).len() - frames;
        println!(
            "2,000 resources idle 600 s: GRANT_ROOTS {frames} frames, {bytes} B both ways; other \
             recon frames {other}; grant walk opens {}; record walk opens {}; CPU {used:?}",
            opens(&taps, from, w_id, WALK_AUTHORIZATION),
            opens(&taps, from, w_id, WALK_COMMIT) + opens(&taps, from, w_id, WALK_DERIVE),
        );
        assert_eq!(opens(&taps, from, w_id, WALK_AUTHORIZATION), 0, "equal roots walk nothing");
        assert_eq!((totals(&wh), totals(&sh)), (0, 0));
        assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), dials);
        // Two rounds each way fall in ten minutes: 2,001 entries of 72 B in
        // three frames with 5 B of framing.
        let round = 2001 * 72 + 3 * 5;
        assert_eq!((frames, bytes), (2 * 2 * 3, 2 * 2 * round));
    });
}

/// Two hosts with nothing active, of which S has W as its first contact and
/// W holds `blobs` S can fetch from it: so they connect, and each lists
/// everything to the other, as [`Granted`] makes them hold it.
struct Contacts {
    w_id: PeerId,
    s_id: PeerId,
    wh: Peer<MemoryRepo>,
    sh: Peer<MemoryRepo>,
    taps: Taps,
    blobs: Vec<[u8; 32]>,
}

impl Contacts {
    async fn new(clock: &Arc<VirtualClock>, seed: u64, s_lower: bool, blobs: usize) -> Self {
        let net = SimNet::new(seed, SimConfig::default());
        let mut granted = Granted::new(w_and_s(s_lower), 3);
        let (s_harness, taps) = net.tap(&granted.s);
        let blobs = (0..blobs)
            .map(|index| {
                let bytes = Bytes::from_source(format!("fetched {index}").into_bytes());
                granted.wp.store.put::<UnknownBlob, _>(bytes).unwrap().raw
            })
            .collect();
        let mut wh =
            bring_up(net.join(&granted.w), &granted.w, std::mem::take(&mut granted.wp.store));
        let daemon = Some(granted.w.verifying_key());
        let (sender, receiver) = bring_up_cold(s_harness, &granted.s, daemon);
        let store = std::mem::take(&mut granted.sp.store);
        let mut sh = Peer::with_wiring(store, sender, receiver);
        advance(clock, &mut [&mut wh, &mut sh], 2).await;
        let (w_id, s_id) = (id(&granted.w), id(&granted.s));
        Self { w_id, s_id, wh, sh, taps, blobs }
    }

    /// S fetches the next blob, over their connection or a new one.
    async fn fetch(&mut self, clock: &Arc<VirtualClock>) {
        let hash = self.blobs.pop().unwrap();
        let fetch = self.sh.fetch_blob_with_deadline(hash, Duration::from_secs(20));
        let mut fetch = std::pin::pin!(fetch);
        for _ in 0..200 {
            tokio::select! {
                biased;
                fetched = &mut fetch => {
                    assert!(fetched.is_some(), "control: W serves S");
                    return;
                }
                () = SimNet::step(clock, Duration::from_millis(100)) => {
                    self.wh.refresh();
                    self.sh.refresh();
                }
            }
        }
        panic!("control: the fetch never ended");
    }

    async fn advance(&mut self, clock: &Arc<VirtualClock>, seconds: u64) {
        advance(clock, &mut [&mut self.wh, &mut self.sh], seconds).await;
    }

    /// Whether each side reports the other as connected.
    fn connected(&self) -> [bool; 2] {
        [(&self.wh, self.s_id), (&self.sh, self.w_id)].map(|(host, other)| {
            host.health()
                .grants
                .iter()
                .any(|grants| grants.peers.iter().any(|peer| peer.peer == other))
        })
    }

    /// How long until neither side reports the other as connected.
    async fn closed(&mut self, clock: &Arc<VirtualClock>, what: &str) -> Duration {
        let started = clock::mono_now();
        for _ in 0..2400 {
            if self.connected() == [false, false] {
                return clock::mono_now().duration_since(started);
            }
            self.advance(clock, 1).await;
        }
        panic!("{what}: never closed");
    }
}

/// A connection nothing but listings cross closes at its idle deadline, as
/// it would without repeats: the first repeat falls after it. (A host that
/// still looks for neighbours sends the connection DHT lookups, which keep it
/// open with or without repeats.)
#[test]
fn a_connection_only_listings_crossed_closes_when_idle() {
    for s_lower in [true, false] {
        for seed in 0..SEEDS {
            run(async |clock| {
                let mut hosts = Contacts::new(&clock, 0x6A47_1140 ^ seed, s_lower, 1).await;
                hosts.fetch(&clock).await;
                let quiet = clock::mono_now();
                hosts.advance(&clock, 2).await;
                assert_eq!(listings(&hosts.taps, 0, hosts.w_id).0, 2, "control: each listed");
                assert_eq!(hosts.connected(), [true, true]);
                hosts.closed(&clock, "idle").await;
                let silent = clock::mono_now().duration_since(quiet);
                println!("S lower {s_lower}, seed {seed}: closed {silent:?} after the fetch");
                assert!(silent.abs_diff(Duration::from_secs(IDLE)) < Duration::from_secs(3), "{silent:?}");
                assert_eq!(listings(&hosts.taps, 0, hosts.w_id).0, 2, "nothing was repeated");
            });
        }
    }
}

/// Two hosts a fetch every 50 s kept connected long enough for both to have
/// repeated several times, at whatever phase their moments came to: once the
/// fetches end, the connection closes within three idle deadlines, one for
/// each side's last repeat and one of silence.
#[test]
fn two_hosts_repeats_alone_do_not_hold_their_connection_open() {
    let mut taken = Vec::new();
    for seed in 0..3 * SEEDS {
        let closed = Rc::new(RefCell::new(Duration::ZERO));
        let out = closed.clone();
        run(async |clock| {
            let mut hosts = Contacts::new(&clock, 0x6A47_1160 ^ seed, seed % 2 == 0, 40).await;
            // The last fetch falls at every phase of the time between repeats.
            for _ in 0..30 + seed * 12 / 50 {
                hosts.fetch(&clock).await;
                hosts.advance(&clock, 50).await;
                assert_eq!(hosts.connected(), [true, true], "control");
            }
            hosts.advance(&clock, seed * 12 % 50).await;
            hosts.fetch(&clock).await;
            assert_eq!(connections(&hosts.taps, 0, hosts.w_id), 1, "control: one throughout");
            for sent in [true, false] {
                let listed = hosts.taps.listed(0, hosts.w_id);
                let times = listed.iter().filter(|listed| listed.sent == sent).count();
                assert!(times >= 5, "control: {times}");
            }
            *out.borrow_mut() = hosts.closed(&clock, "two hosts").await;
        });
        taken.push(closed.borrow().as_secs());
    }
    println!("closed after the last fetch, in seconds: {taken:?}");
    assert!(taken.iter().all(|closed| *closed <= 3 * IDLE), "{taken:?}");
}

/// Repeats alone never keep a connection open, whatever the phase between
/// the two sides'. A frame of a kind nobody knows every 50 s holds one open
/// for ten minutes and more while S repeats to a peer driven by hand, which
/// lists to S at the shortest spacing. Once the other frames stop, at a
/// moment of every phase of that spacing, the connection closes within three
/// idle deadlines: one for each side's last repeat and one of silence.
#[test]
fn both_sides_repeats_alone_do_not_hold_a_connection_open() {
    let mut longest = Duration::ZERO;
    for phase in 0..27 {
        let closed = Rc::new(RefCell::new(Duration::ZERO));
        let out = closed.clone();
        run(async |clock| {
            let net = SimNet::new(0x6A47_1180 ^ phase, SimConfig::default());
            let mut granted = Granted::new(w_and_s(phase % 2 == 0), 3);
            let (w_id, s_id) = (id(&granted.w), id(&granted.s));
            let (s_harness, taps) = net.tap(&granted.s);
            let mut sh = bring_up(s_harness, &granted.s, std::mem::take(&mut granted.sp.store));
            advance(&clock, &mut [&mut sh], 2).await;
            let Harness { transport, mut incoming } = net.join(&granted.w);
            tokio::task::spawn_local(async move { while incoming.recv().await.is_some() {} });
            let listing = granted
                .resources
                .iter()
                .map(|resource| {
                    let proof = grant(
                        &granted.w,
                        delivery_definition().get_handle(),
                        &granted.s,
                        *resource,
                    );
                    (*resource, one_grant(*resource, &proof).0)
                })
                .collect::<Vec<_>>();
            let mut by_hand = ByHand::dial(&transport, s_id, 1).await;
            let quiet_at = 600 + phase * 10;
            for second in 0..2400 {
                if by_hand.seen.borrow().1 {
                    break;
                }
                if second % REPEATS_AFTER == 0 {
                    by_hand.list(&listing).await;
                }
                if second % 50 == 0 && second < quiet_at {
                    by_hand.frame(0x7E, &[]).await;
                }
                advance(&clock, &mut [&mut sh], 1).await;
                if second < quiet_at {
                    assert!(!by_hand.seen.borrow().1, "control: held open meanwhile");
                } else {
                    *out.borrow_mut() += Duration::from_secs(1);
                }
            }
            assert!(by_hand.seen.borrow().1, "phase {phase}: repeats held it open");
            let repeated = taps
                .listed(0, w_id)
                .iter()
                .filter(|listed| listed.sent)
                .count();
            assert!(repeated >= 3, "control: S listed {repeated} times");
            assert_eq!(opens(&taps, 0, w_id, WALK_AUTHORIZATION), 0, "control: they agree");
        });
        longest = longest.max(*closed.borrow());
    }
    println!("closed at the latest {longest:?} after the last other frame's 50 s");
    assert!(longest <= Duration::from_secs(3 * IDLE), "{longest:?}");
}

/// A connection closes amid a repeat, both ways. The peer, driven by hand,
/// has sent one of the three frames of its own when it closes; and it has
/// stopped reading, so that S's repeat is written and never arrives. On the next
/// connection it dials each side lists everything afresh, and S repeats there
/// in that connection's own time, once.
#[test]
fn a_connection_that_closes_amid_a_repeat_is_listed_afresh() {
    for s_lower in [true, false] {
        run(async |clock| {
            let net = SimNet::new(0x6A47_11C0, SimConfig::default());
            let mut granted = Granted::new(w_and_s(s_lower), 2000);
            let (w_id, s_id) = (id(&granted.w), id(&granted.s));
            let (s_harness, taps) = net.tap(&granted.s);
            let mut sh = bring_up(s_harness, &granted.s, std::mem::take(&mut granted.sp.store));
            advance(&clock, &mut [&mut sh], 2).await;
            let Harness { transport, mut incoming } = net.join(&granted.w);
            tokio::task::spawn_local(async move { while incoming.recv().await.is_some() {} });
            let delivery = delivery_definition().get_handle();
            let listing = granted
                .resources
                .iter()
                .map(|resource| {
                    let proof = grant(&granted.w, delivery, &granted.s, *resource);
                    (*resource, one_grant(*resource, &proof).0)
                })
                .collect::<Vec<_>>();
            let sent = |from: usize| {
                taps.listed(from, w_id).iter().filter(|listed| listed.sent).count()
            };
            let mut first = ByHand::dial(&transport, s_id, 1).await;
            first.list(&listing).await;
            for _ in 0..9 {
                first.frame(0x7E, &[]).await;
                advance(&clock, &mut [&mut sh], 25).await;
            }
            assert_eq!(heard(&sh, &granted.resources, w_id), 2000, "control");
            assert_eq!(sent(0), 3, "control: S listed everything once");
            *first.deaf.borrow_mut() = true;
            let from = taps.len();
            first.frame(0x7E, &[]).await;
            advance(&clock, &mut [&mut sh], 25).await;
            // S repeats 270 to 300 s after the connection opened.
            first.frame(0x7E, &[]).await;
            until(&clock, &mut [&mut sh], 60, "S's repeat", |_| sent(from) > 0).await;
            assert!(!first.seen.borrow().1, "the connection stands");
            let (kind, payload) = grant_roots_frames(&listing)[0].encode();
            first.frame(kind, &payload).await;
            advance(&clock, &mut [&mut sh], 1).await;
            first.conn.close(0, b"amid");
            advance(&clock, &mut [&mut sh], 2).await;
            assert!(sh.health().grants.iter().all(|grants| grants.peers.is_empty()));

            let again = taps.len();
            let mut second = ByHand::dial(&transport, s_id, 2).await;
            second.list(&listing).await;
            for _ in 0..10 {
                second.frame(0x7E, &[]).await;
                advance(&clock, &mut [&mut sh], 26).await;
            }
            assert_eq!(heard(&sh, &granted.resources, w_id), 2000);
            assert_eq!(sent(again), 3, "afresh, and nothing left over");
            second.frame(0x7E, &[]).await;
            advance(&clock, &mut [&mut sh], 50).await;
            assert_eq!(sent(again), 6, "then one repeat");
        });
    }
}

/// A host that never observes a store hears W's repeats for as long as their
/// connection lives, which W's own lookups keep open: it keeps what it kept,
/// lists nothing, walks nothing, and neither drops nor reconnects anything.
#[test]
fn a_host_that_never_observes_hears_repeats_and_does_nothing() {
    for s_lower in [true, false] {
        run(async |clock| {
            let cold = Cold::new(&clock, 0, s_lower, UNKNOWN_RESOURCES_PER_LINK + 44).await;
            let Cold { net, w_id, s_id, mut wh, wired, taps, .. } = cold;
            advance(&clock, &mut [&mut wh], 900).await;
            assert!(listed(&taps, 0, w_id, true).is_empty(), "it has nothing to list");
            assert_eq!(opens(&taps, 0, w_id, WALK_AUTHORIZATION), 0);
            assert!(wired.0.health().grants.is_empty(), "S observed nothing");
            assert_eq!((net.dial_count(w_id, s_id), net.dial_count(s_id, w_id)), (1, 0));
            assert_eq!(connections(&taps, 0, w_id), 1);
            let (frames, _) = listings(&taps, 0, w_id);
            assert!(frames >= 3, "control: W repeated, {frames} frames in all");
        });
    }
}
