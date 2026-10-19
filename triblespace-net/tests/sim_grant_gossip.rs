//! Grant gossip by participation, through whole hosts over the deterministic
//! transport. A grant over a resource R reaches every node that takes part in
//! R: R's roots, the keys named on delegation-valid prefixes of grants over
//! R, and the nodes admitted to sync R's content. Nobody dials on a grant's
//! behalf, and no resource kind is special.
//!
//! Written before the redesign, with base APIs only: what each store holds,
//! how often each node dialled another, and which frames crossed a tapped
//! host. A scenario the base contradicts is `#[ignore = "grant gossip
//! redesign"]` and names the base behaviour it contradicts; the others pass
//! on the base and guard behaviour the redesign must keep. Every scenario
//! carries a positive control, so an assertion that something did not travel
//! is never satisfied by nothing travelling at all.
//!
//! Each scenario runs over a seed sweep, which shakes the arrival orders the
//! simulation's determinism contract makes reproducible.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
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
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_core::trible::TribleSet;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::peer::Peer;
use triblespace_net::protocol::TAG_WALK;
use triblespace_net::transport::sim::{SimConfig, SimNet, Taps};
use triblespace_net::transport::{Harness, PeerId, Transport};
use triblespace_net::walk_stream::FRAME_OPEN;

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
    mut done: impl FnMut(&mut [&mut Peer<MemoryRepo>]) -> bool,
) -> Duration {
    let started = clock::mono_now();
    for _ in 0..seconds * 10 {
        if done(peers) {
            return clock::mono_now().duration_since(started);
        }
        SimNet::step(clock, Duration::from_millis(100)).await;
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

/// W roots C; S is a server holding READ and WRITE; R1 and R2 read C and
/// reach W only through S (W–R1, W–R2 and R1–R2 are partitioned). Once all
/// have converged, W signs a WRITE grant to X, who is never online. R1 and
/// R2 hold it within five virtual seconds: two hops at the default 1–30 ms
/// link latency. With `open_read` the collection's READ is Open and the
/// readers hold no grant at all: they take part in C by being admitted to
/// sync it, and still receive every grant over C.
///
/// With `parked`, R1 already holds a record X signed before X was granted
/// anything: it is not admitted at R1 until the late grant lands there, and
/// then it is, without the record travelling again.
fn late_write_grant_reaches_the_readers(open_read: bool, parked: bool, base_seed: u64) {
    for seed in 0..SEEDS {
        run(async |clock| {
            let net = SimNet::new(base_seed ^ seed, SimConfig::default());
            let [w, s, r1, r2, x] = [0x31, 0x32, 0x33, 0x34, 0x35].map(key);
            let read_policy = if open_read {
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
            let parked_data = parked.then(|| {
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
            if !open_read {
                initial.push(grant(&w, read_capability(), &r1, collection));
                initial.push(grant(&w, read_capability(), &r2, collection));
            }
            for pile in &mut piles {
                pile.insert(&initial.iter().collect::<Vec<_>>());
                pile.select(collection);
            }
            for (a, b) in [(&w, &r1), (&w, &r2), (&r1, &r2)] {
                net.partition(id(a), id(b));
            }
            let [w_pile, s_pile, r1_pile, r2_pile] = piles;
            let mut wh = bring_up(net.join(&w), &w, w_pile.store);
            let mut sh = bring_up(net.join(&s), &s, s_pile.store);
            let mut r1h = bring_up(net.join(&r1), &r1, r1_pile.store);
            let mut r2h = bring_up(net.join(&r2), &r2, r2_pile.store);
            for host in [&mut wh, &mut sh, &mut r1h, &mut r2h] {
                host.activate_collection(collection);
            }
            let (w_id, s_id) = (id(&w), id(&s));
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
            advance(&clock, &mut [&mut wh, &mut sh, &mut r1h, &mut r2h], 10).await;
            if let Some(data) = parked_data {
                assert!(
                    !admitted_at(&mut r1h, data),
                    "X's record admitted before X's grant"
                );
            }

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
            assert!(holds_proof(&mut sh, &late));
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
                "late WRITE grant (open_read={open_read}, seed {seed}): at both readers after \
                 {reached:?} virtual time, two hops W->S->R, sim link latency 1-30 ms"
            );
            assert!(reached <= Duration::from_secs(5), "{reached:?}");
        });
    }
}

#[test]
fn a_late_write_grant_reaches_the_readers_of_a_closed_collection() {
    late_write_grant_reaches_the_readers(false, false, 0x6A47_0100);
}

/// The Open-READ variant: a reader that holds no grant still takes part in
/// C by being admitted to sync it, so it receives the late grant (critique:
/// the receiver must not skip grants it is not named on).
#[test]
fn a_late_write_grant_reaches_the_readers_of_an_open_read_collection() {
    late_write_grant_reaches_the_readers(true, false, 0x6A47_0200);
}

/// A reader holding a record X signed before X was granted WRITE admits it
/// once the late grant lands, without the record travelling again.
#[test]
fn a_late_write_grant_admits_a_record_the_reader_already_holds() {
    late_write_grant_reaches_the_readers(false, true, 0x6A47_0280);
}

/// A grant is not a record: a new grant over C moves no Commit or Derive
/// walk. W and S have been quiet long enough for the push timer to reach its
/// cap; W signs a WRITE grant, and every walk W opens to S until S holds it
/// is counted. The grant travels by an Authorization walk (positive control
/// one), and a record appended afterwards does open a Commit walk (positive
/// control two, so the counter is not blind).
///
/// Base: the authorization summary is part of the collection's wake root
/// (schedule.rs `roots`, collection_activation `record_root`), so a new
/// grant resets the push timer and the push that carries it opens Commit and
/// Derive walks as well.
#[test]
#[ignore = "grant gossip redesign"]
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
            let auth = opens_sent(&taps, from, s_id, WALK_AUTHORIZATION);
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

/// Base regression guard and the positive control of the scenario below. R
/// is a Secrets-shaped resource whose descriptor still names C1 through the
/// retired backlink. Alice, Carol and Bob all read C1; Alice and Bob are
/// partitioned. Alice's delivery grant to Bob reaches Bob through Carol,
/// with R's descriptor. The base routes it as C1's evidence; the redesign
/// delivers it because Bob and Carol take part in R.
///
/// Ignored between the removal of the backlink routing and the grant walk
/// by participation, which delivers it again.
#[test]
#[ignore = "grant gossip redesign: backlink routing removed, participation delivery not yet in place"]
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
/// and Carol share C1; Carol and Bob share C2, which Carol roots; Alice and
/// Bob are partitioned, and Bob never selects C1. Alice grants delivery over
/// R to Bob, and, in the participating arm, to Carol.
///
/// - Participating: Bob holds Alice's grant, R's descriptor and the delivery
///   definition; Carol holds Bob's grant; Alice never dialled Bob.
/// - Control: when Carol takes no part in R, neither she nor Bob ever holds
///   it. Nobody dials on a grant's behalf.
///
/// Both arms first check that Bob is peered with Carol for C2 and Carol with
/// Alice for C1, so the path exists.
///
/// Base: a grant over a resource that is not a collection travels only as
/// the evidence of the collection its descriptor's backlink names, so with
/// no backlink it never leaves Alice.
#[test]
#[ignore = "grant gossip redesign"]
fn a_delivery_grant_reaches_a_non_syncing_grantee_through_a_third_participant() {
    for seed in 0..SEEDS {
        for carol_participates in [true, false] {
            run(async |clock| {
                let net = SimNet::new(0x6A47_0500 ^ seed, SimConfig::default());
                let [alice, carol, bob] = [0x44, 0x45, 0x46].map(key);
                let (mut ah, mut ch, mut bh, to_bob, resource, definition) =
                    third_participant(&net, &clock, &alice, &carol, &bob, carol_participates).await;
                if carol_participates {
                    let reached = until(
                        &clock,
                        &mut [&mut ah, &mut ch, &mut bh],
                        60,
                        "Alice's delivery grant at Bob",
                        |hosts| holds_proof(hosts[2], &to_bob),
                    )
                    .await;
                    assert!(holds_proof(&mut ch, &to_bob));
                    until(
                        &clock,
                        &mut [&mut ah, &mut ch, &mut bh],
                        30,
                        "R's descriptor and definition at Bob",
                        |hosts| holds_blob(hosts[2], resource) && holds_blob(hosts[2], definition),
                    )
                    .await;
                    println!("delivery grant via Carol (seed {seed}): at Bob after {reached:?}");
                } else {
                    advance(&clock, &mut [&mut ah, &mut ch, &mut bh], 60).await;
                    assert!(!holds_proof(&mut ch, &to_bob));
                    assert!(!holds_proof(&mut bh, &to_bob));
                }
                assert_eq!(net.dial_count(id(&alice), id(&bob)), 0);
            });
        }
    }
}

/// Hosts for the third-participant scenario, converged on their collections:
/// Alice's, Carol's and Bob's, Alice's grant to Bob, R, and the delivery
/// definition.
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
    CapabilityProof,
    CollectionHandle,
    CapabilityHandle,
) {
    let mut a = Pile::new(alice);
    let mut c = Pile::new(carol);
    let mut b = Pile::new(bob);
    let c1_policy = private_policy(alice.verifying_key());
    let c2_policy = private_policy(carol.verifying_key());
    let c1 = a.hold("alice and carol", &c1_policy);
    c.hold("alice and carol", &c1_policy);
    let c2 = c.hold("carol and bob", &c2_policy);
    b.hold("carol and bob", &c2_policy);
    let carol_reads = grant(alice, read_capability(), carol, c1);
    let bob_reads = grant(carol, read_capability(), bob, c2);
    a.insert(&[&carol_reads]);
    c.insert(&[&carol_reads, &bob_reads]);
    b.insert(&[&bob_reads]);
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
    let mut ah = bring_up(net.join(alice), alice, a.store);
    let mut ch = bring_up(net.join(carol), carol, c.store);
    let mut bh = bring_up(net.join(bob), bob, b.store);
    ah.activate_collection(c1);
    ch.activate_collections([c1, c2]);
    bh.activate_collection(c2);
    let (alice_id, carol_id) = (id(alice), id(carol));
    until(
        clock,
        &mut [&mut ah, &mut ch, &mut bh],
        60,
        "Carol peered with Alice for C1 and Bob with Carol for C2",
        |hosts| receives_from(hosts[1], alice_id, c1) && receives_from(hosts[2], carol_id, c2),
    )
    .await;
    (ah, ch, bh, to_bob, resource, delivery)
}

// ---------------------------------------------------------------------------
// Scenario 6: mixed descriptors.
// ---------------------------------------------------------------------------

/// Two Secrets-shaped resources rooted at Alice: R_old still carries the
/// retired backlink (to C1), R_new carries none. Both are granted to Carol
/// and to Bob, in the third-participant topology. Both grants and both
/// descriptors reach Bob through Carol alike, and their handles differ
/// (the backlink is part of R_old's descriptor bytes).
///
/// Base: R_new's grant never travels (no backlink); R_old's travels only as
/// C1's evidence, which Bob does not select.
#[test]
#[ignore = "grant gossip redesign"]
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
            let mut ah = bring_up(net.join(&alice), &alice, a.store);
            let mut ch = bring_up(net.join(&carol), &carol, c.store);
            let mut bh = bring_up(net.join(&bob), &bob, b.store);
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
        });
    }
}

// ---------------------------------------------------------------------------
// Scenario 3: two teams on one pile stay isolated.
// ---------------------------------------------------------------------------

/// One host H holds two teams' collections, CA (rooted at A) and CB (rooted
/// at B), and every grant over each. A member of each team reads only its
/// own. Positive control: a grant over each that only H held at the start
/// reaches its team's member. Then neither member holds any proof over the
/// other team's collection, nor its descriptor.
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
            let mut hh = bring_up(net.join(&h), &h, hp.store);
            let mut ah = bring_up(net.join(&a1), &a1, ap.store);
            let mut bh = bring_up(net.join(&b1), &b1, bp.store);
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
            for (host, own, other) in [(&mut ah, ca, cb), (&mut bh, cb, ca)] {
                let held = proofs(host);
                assert!(
                    held.iter()
                        .all(|proof| proof.resource() == CapabilityResource::from(own)),
                    "seed {seed}: a member holds a proof over the other team's collection"
                );
                assert!(!holds_blob(host, other), "the other team's descriptor");
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
///
/// Base: authorization evidence is decided by root and signatures only, so
/// the chain is C's evidence and spreads, and its keys become discovery
/// candidates.
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
#[ignore = "grant gossip redesign"]
fn an_undelegated_extension_to_a_stranger_does_not_spread() {
    junk_delegation_does_not_spread(false, 0x6A47_0800);
}

#[test]
#[ignore = "grant gossip redesign"]
fn an_extension_through_an_empty_definition_does_not_spread() {
    junk_delegation_does_not_spread(true, 0x6A47_0900);
}
