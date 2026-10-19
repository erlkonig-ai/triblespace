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
use ed25519_dalek::SigningKey;
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
use triblespace_net::health::{GrantHealth, GrantPeerHealth, PairState};
use triblespace_net::health_record::{self, Component, DEFAULT_MAX_AGE, State};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::patch_repair::PatchSummary;
use triblespace_net::peer::Peer;
use triblespace_net::protocol::{PILE_SYNC_ALPN, TAG_RECON, TAG_WALK};
use triblespace_net::recon::{self, grant_roots_frames};
use triblespace_net::transport::sim::{Crossed, SimConfig, SimNet, SimRecvStream, SimSendStream, Taps};
use triblespace_net::transport::{Conn, Harness, PeerId, SendStream, Transport};
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
            walk_algorithm: Default::default(),
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
