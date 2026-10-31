//! Two ordinary hosts, actual walk drivers, actual Lander/Serving publication.
//! Unlike the focused scripted-driver tests, no landing receipt is synthesized.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
    private_policy, write_capability,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::peer::Peer;
use triblespace_net::protocol::TAG_WALK;
use triblespace_net::reconcile::ReplicationMode;
use triblespace_net::transport::sim::{Crossed, SimConfig, SimNet, Taps};
use triblespace_net::transport::{Harness, Transport};
use triblespace_net::walk_stream::{
    FRAME_DONE, FRAME_LANDED, FRAME_OPEN, FRAME_RIBLT_CELL, FRAME_RIBLT_ROOT, FRAME_SUBTREE,
    FRAME_VALUE, FRAME_VALUE_REQUEST,
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn run(test: impl AsyncFnOnce(Arc<VirtualClock>)) {
    static SERIAL: Mutex<()> = Mutex::new(());
    static CLOCK: OnceLock<Arc<VirtualClock>> = OnceLock::new();
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = CLOCK
        .get_or_init(|| {
            let clock =
                VirtualClock::new(hifitime::Epoch::from_gregorian_utc_at_midnight(2026, 1, 1));
            clock::install_virtual(clock.clone()).unwrap();
            clock
        })
        .clone();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(test(clock)));
}

fn selected(
    store: &mut MemoryRepo,
    signer: &SigningKey,
    writers: &[&SigningKey],
) -> CollectionHandle {
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::quorum(writers.iter().map(|key| key.verifying_key()), 1, None).unwrap(),
    );
    let collection = store
        .collection("cached-riblt-two-hosts", policy)
        .unwrap()
        .handle();
    let config = store
        .collection(
            CONFIG_COLLECTION_NAME,
            private_policy(signer.verifying_key()),
        )
        .unwrap();
    write_sync_selection(store, config, signer, collection, true).unwrap();
    collection
}

fn commit(
    store: &mut MemoryRepo,
    signer: &SigningKey,
    collection: CollectionHandle,
    number: u64,
) -> [u8; 32] {
    let mut bytes = signer.verifying_key().to_bytes().to_vec();
    bytes.extend_from_slice(&number.to_be_bytes());
    let data = store
        .put::<UnknownBlob, _>(Bytes::from_source(bytes))
        .unwrap();
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            signer,
            collection,
            CollectionData::new(data.raw),
            empty_metadata_handle(),
        )))
        .unwrap();
    data.raw
}

fn grant(store: &mut MemoryRepo, signer: &SigningKey, collection: CollectionHandle, delegate: u8) {
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection),
            signer,
            write_capability(),
            key(delegate).verifying_key(),
        ))
        .unwrap();
}

fn host<T: Transport>(
    harness: Harness<T>,
    signer: &SigningKey,
    store: MemoryRepo,
) -> Peer<MemoryRepo> {
    let (sender, receiver, wiring) =
        host::wire(EndpointId::from_bytes(&signer.verifying_key().to_bytes()).unwrap());
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

fn records(peer: &mut Peer<MemoryRepo>, collection: CollectionHandle) -> usize {
    peer.store()
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .filter(|record| record.as_ref().unwrap().collection() == collection)
        .count()
}

fn proofs(peer: &mut Peer<MemoryRepo>) -> usize {
    peer.store().snapshot().unwrap().proofs().unwrap().count()
}

fn holds(peer: &mut Peer<MemoryRepo>, handles: &[[u8; 32]]) -> bool {
    let snapshot = peer.store().snapshot().unwrap();
    handles.iter().all(|handle| {
        snapshot
            .contains_blob(Inline::<
                triblespace_core::inline::encodings::hash::Handle<UnknownBlob>,
            >::new(*handle))
            .unwrap()
    })
}

async fn until(clock: &VirtualClock, seconds: u64, mut ready: impl FnMut() -> bool) {
    for _ in 0..seconds * 10 {
        if ready() {
            return;
        }
        // No Peer::refresh here: remote insertion/publication belongs to the
        // production landing task, and external appends to its reobserver.
        SimNet::step(clock, Duration::from_millis(100)).await;
    }
    panic!("two actual hosts did not converge within {seconds} virtual seconds");
}

/// The peer confirmed `record_count` records of C, and listed this side's
/// root of C's grants, holding `proof_count` of them.
fn confirmed(
    peer: &Peer<MemoryRepo>,
    other: [u8; 32],
    collection: CollectionHandle,
    record_count: u64,
    proof_count: u64,
) -> bool {
    let health = peer.health();
    let grants_agree = health
        .grants
        .iter()
        .find(|item| item.resource == collection)
        .is_some_and(|item| {
            item.local.leaf_count() == proof_count
                && item
                    .peers
                    .iter()
                    .any(|listing| listing.peer == other && listing.listed == Some(item.local))
        });
    grants_agree
        && health
            .collections
            .iter()
            .find(|item| item.collection == collection)
            .and_then(|item| item.peers.iter().find(|item| item.peer == other))
            .is_some_and(|item| {
                item.confirmed
                    .commits
                    .zip(item.confirmed.derives)
                    .is_some_and(|(commits, derives)| {
                        commits.leaf_count() + derives.leaf_count() == record_count
                    })
                    && item.pushes.last_ok
                    && item.receives.last_ok
            })
}

/// Walk frames outside grant walks: those are Prefix only, whatever the
/// host's preference (grants gossip by participation).
fn component_frames(taps: &Taps, from: usize, other: [u8; 32]) -> Vec<Crossed> {
    let frames = taps.since(from, other, TAG_WALK);
    let grant_streams: Vec<u64> = frames
        .iter()
        .filter(|frame| frame.walk_kind == Some(1))
        .map(|frame| frame.stream)
        .collect();
    frames
        .into_iter()
        .filter(|frame| !grant_streams.contains(&frame.stream))
        .collect()
}

/// Whether a grant walk crossed, as Prefix.
fn grant_walk_crossed(taps: &Taps, from: usize, other: [u8; 32]) -> bool {
    let frames = taps.since(from, other, TAG_WALK);
    frames
        .iter()
        .filter(|frame| frame.walk_kind == Some(1))
        .any(|opened| {
            frames
                .iter()
                .any(|frame| frame.stream == opened.stream && frame.kind == FRAME_SUBTREE)
        })
}

fn walk_counts(taps: &Taps, from: usize, other: [u8; 32]) -> (usize, usize, usize, usize) {
    let frames = component_frames(taps, from, other);
    let count = |kind| frames.iter().filter(|frame| frame.kind == kind).count();
    (
        count(FRAME_RIBLT_ROOT),
        count(FRAME_RIBLT_CELL),
        count(FRAME_VALUE),
        count(FRAME_VALUE_REQUEST),
    )
}

// The tap observes framed discovery, not FIN. Actual landing and directional
// completion are checked separately by `holds` and `confirmed` above.
fn cached_references_crossed(taps: &Taps, from: usize, other: [u8; 32]) -> bool {
    let frames = taps.since(from, other, TAG_WALK);
    frames
        .iter()
        .filter(|frame| frame.walk_kind == Some(2))
        .any(|opened| {
            let stream: Vec<_> = frames
                .iter()
                .filter(|frame| frame.stream == opened.stream)
                .collect();
            stream.iter().any(|frame| frame.kind == FRAME_RIBLT_CELL)
                && [true, false].into_iter().all(|sent| {
                    stream.iter().any(|frame| {
                        frame.sent == sent && frame.kind == FRAME_RIBLT_ROOT
                    })
                })
        })
}

#[test]
fn cached_riblt_two_hosts_land_records_auth_and_held_blobs_then_reconnect() {
    run(async |clock| {
        let net = SimNet::new(0xCACE_0031, SimConfig::default());
        let (a_key, b_key) = (key(171), key(172));
        let (a_id, b_id) = (
            a_key.verifying_key().to_bytes(),
            b_key.verifying_key().to_bytes(),
        );
        let mut a_store = MemoryRepo::default();
        let mut b_store = MemoryRepo::default();
        let collection = selected(&mut a_store, &a_key, &[&a_key, &b_key]);
        assert_eq!(
            selected(&mut b_store, &b_key, &[&a_key, &b_key]),
            collection
        );
        let mut handles = Vec::new();
        for number in 0..130 {
            handles.push(commit(&mut a_store, &a_key, collection, number));
            handles.push(commit(&mut b_store, &b_key, collection, number));
        }
        grant(&mut a_store, &a_key, collection, 173);
        grant(&mut b_store, &b_key, collection, 174);
        let (a_harness, taps) = net.tap(&a_key);
        let mut a = host(a_harness, &a_key, a_store);
        let mut b = host(net.join(&b_key), &b_key, b_store);
        a.activate_collection(collection);
        b.activate_collection(collection);
        a.set_replication(ReplicationMode::Full, [collection]);
        b.set_replication(ReplicationMode::Full, [collection]);
        until(&clock, 300, || {
            records(&mut a, collection) == 260
                && records(&mut b, collection) == 260
                && proofs(&mut a) == 2
                && proofs(&mut b) == 2
                && holds(&mut a, &handles)
                && holds(&mut b, &handles)
                && confirmed(&a, b_id, collection, 260, 2)
                && confirmed(&b, a_id, collection, 260, 2)
                && cached_references_crossed(&taps, 0, b_id)
        })
        .await;
        let (roots, cells, bodies, requests) = walk_counts(&taps, 0, b_id);
        assert!(
            roots >= 6 && cells > 0,
            "nonempty cached discovery in both directions"
        );
        assert!(bodies >= 260, "actual record bodies must cross");
        assert_eq!(
            requests, 0,
            "honest CachedRiblt must not request eager bodies"
        );
        assert!(
            component_frames(&taps, 0, b_id)
                .iter()
                .all(|frame| !matches!(frame.kind, FRAME_SUBTREE | FRAME_DONE | FRAME_LANDED))
        );
        assert!(grant_walk_crossed(&taps, 0, b_id), "grants cross as Prefix");
        assert!(taps.since(0, b_id, TAG_WALK).iter()
            .filter(|frame| frame.kind == FRAME_RIBLT_ROOT)
            .all(|frame| frame.wire_bytes == 46));

        let initial_dials = net.dial_count(a_id, b_id) + net.dial_count(b_id, a_id);
        net.partition(a_id, b_id);
        SimNet::step(&clock, Duration::from_secs(10)).await;
        handles.push(commit(&mut *a.store(), &a_key, collection, 1000));
        handles.push(commit(&mut *b.store(), &b_key, collection, 2000));
        grant(&mut *a.store(), &a_key, collection, 175);
        // No explicit refresh: the actual lander's reobserver must replace the
        // latest cache from these appended PATCH deltas before the healed walk.
        SimNet::step(&clock, Duration::from_secs(5)).await;
        assert_eq!(records(&mut a, collection), 261);
        assert_eq!(records(&mut b, collection), 261);
        let from = taps.len();
        net.heal(a_id, b_id);
        until(&clock, 300, || {
            records(&mut a, collection) == 262
                && records(&mut b, collection) == 262
                && proofs(&mut a) == 3
                && proofs(&mut b) == 3
                && holds(&mut a, &handles)
                && holds(&mut b, &handles)
                && confirmed(&a, b_id, collection, 262, 3)
                && confirmed(&b, a_id, collection, 262, 3)
                && cached_references_crossed(&taps, from, b_id)
        })
        .await;
        assert!(net.dial_count(a_id, b_id) + net.dial_count(b_id, a_id) > initial_dials);
        let (roots, cells, bodies, requests) = walk_counts(&taps, from, b_id);
        assert!(roots >= 6 && cells > 0 && bodies >= 2);
        assert_eq!(requests, 0);
    });
}

/// Two hosts that each read and write the collection, with no configuration
/// at all: every data walk either of them opens is cached RIBLT, and no
/// Prefix frame crosses outside grant walks.
#[test]
fn two_way_hosts_without_configuration_walk_data_only_as_cached_riblt() {
    run(async |clock| {
        let net = SimNet::new(0xCACE_0032, SimConfig::default());
        let (a_key, b_key) = (key(181), key(182));
        let (a_id, b_id) = (
            a_key.verifying_key().to_bytes(),
            b_key.verifying_key().to_bytes(),
        );
        let mut a_store = MemoryRepo::default();
        let mut b_store = MemoryRepo::default();
        let collection = selected(&mut a_store, &a_key, &[&a_key, &b_key]);
        assert_eq!(
            selected(&mut b_store, &b_key, &[&a_key, &b_key]),
            collection
        );
        commit(&mut a_store, &a_key, collection, 1);
        commit(&mut b_store, &b_key, collection, 2);
        let (harness, taps) = net.tap(&a_key);
        let mut a = host(harness, &a_key, a_store);
        let mut b = host(net.join(&b_key), &b_key, b_store);
        a.activate_collection(collection);
        b.activate_collection(collection);
        until(&clock, 240, || {
            records(&mut a, collection) == 2
                && records(&mut b, collection) == 2
                && confirmed(&a, b_id, collection, 2, 0)
                && confirmed(&b, a_id, collection, 2, 0)
        })
        .await;
        // Periodic walks originate on both hosts: wait until each side has
        // opened data walks, then check every data walk stream.
        until(&clock, 240, || {
            let frames = component_frames(&taps, 0, b_id);
            [true, false].into_iter().all(|sent| {
                frames
                    .iter()
                    .any(|frame| frame.kind == FRAME_OPEN && frame.sent == sent)
            })
        })
        .await;
        let frames = component_frames(&taps, 0, b_id);
        let mut streams: Vec<u64> = frames
            .iter()
            .filter(|frame| frame.kind == FRAME_OPEN)
            .map(|frame| frame.stream)
            .collect();
        streams.sort_unstable();
        streams.dedup();
        assert!(streams.len() >= 2);
        for stream in streams {
            let frames: Vec<_> = frames.iter().filter(|frame| frame.stream == stream).collect();
            assert!(
                frames.iter().all(|frame| !matches!(
                    frame.kind,
                    FRAME_SUBTREE | FRAME_DONE | FRAME_LANDED | FRAME_VALUE_REQUEST
                )),
                "a two-way data walk carries no Prefix frame: {frames:?}"
            );
        }
        let (roots, _, _, requests) = walk_counts(&taps, 0, b_id);
        assert!(roots > 0, "cached discovery ran");
        assert_eq!(requests, 0);
    });
}
