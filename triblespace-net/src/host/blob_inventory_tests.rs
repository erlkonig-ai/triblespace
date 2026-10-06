//! Held sets at the real immutable store/host boundary, and the reference
//! pull that compares them (design 2.9).
//!
//! The host publishes the store's held set of each active collection; it
//! scans nothing itself. These tests pin what that means for the serving
//! overlay: scan-once (a late child is not found by an arrival), rule-3
//! reports and the walk backstop, and reset on removal. A reference pull
//! brings a peer's held set here: what is resident joins as it is, what is
//! not is fetched by hash first.

use anybytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionHandle, CollectionPolicy, CollectionRecord,
    CollectionStore, CollectionStoreExt, HeldStore,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource, StoreChanges,
    StoreSnapshot as CoreStoreSnapshot,
};
use triblespace_core::trible::TribleSet;

use super::{ActiveCollections, PatchEntry, StoreSnapshot};

struct Fixture {
    store: MemoryRepo,
    local: VerifyingKey,
    collection: CollectionHandle,
}

impl Fixture {
    fn new(body: Bytes) -> Self {
        let signing = SigningKey::from_bytes(&[109; 32]);
        let local = signing.verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "host-positive-resident-inventory",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(local),
                    AdmissionPolicy::direct(local),
                ),
            )
            .unwrap()
            .handle();
        let data = store.put::<UnknownBlob, _>(body).unwrap();
        let metadata = store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        // Synchronization retains structurally valid signed records and their
        // exact direct blob references independently of payload decoding or
        // semantic WRITE admission. The bytes intentionally expose a simple
        // reference chain rather than imposing a SimpleArchive reader here.
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &signing,
                collection,
                Handle::<UnknownBlob>::to_hash(data),
                metadata,
            )))
            .unwrap();
        store.track_held([collection]);
        Self {
            store,
            local,
            collection,
        }
    }

    fn active(&self) -> ActiveCollections {
        let mut active = ActiveCollections::new();
        active.insert(&PatchEntry::new(&self.collection.raw));
        active
    }
}

fn observe(
    snapshot: &MemoryRepoSnapshot,
    active: &ActiveCollections,
    local: VerifyingKey,
    prior: Option<(&MemoryRepoSnapshot, &StoreSnapshot)>,
) -> StoreSnapshot {
    StoreSnapshot::from_store_changes(
        snapshot.clone(),
        active,
        local,
        prior.map(|(store, _)| store),
        prior.map(|(_, host)| host),
        prior.map_or(StoreChanges::ALL, |(before, _)| {
            snapshot.changes_since(before)
        }),
    )
    .unwrap()
}

/// The held digest a Full neighbour would compare.
fn digest(serving: &StoreSnapshot, collection: CollectionHandle) -> [u8; 32] {
    crate::collection_activation::held_digest(crate::patch_repair::PatchSummary::from_patch(
        serving
            .collection(collection)
            .unwrap()
            .repair
            .blob_inventory(),
    ))
}

fn held(serving: &StoreSnapshot, collection: CollectionHandle, handle: &[u8; 32]) -> bool {
    serving
        .collection(collection)
        .unwrap()
        .repair
        .blob_inventory()
        .has_prefix(handle)
}

/// A child put after its parent was scanned is not found by the arrival:
/// each blob is scanned once. A peer's report of it in C makes it held, and
/// only the held digest changes: the root leaves held blobs out.
#[test]
fn a_blob_only_child_is_held_after_a_report_not_by_its_arrival() {
    let child =
        Blob::<UnknownBlob>::new(Bytes::from_source(b"nested child arrives later".to_vec()));
    let child_handle = child.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(child_handle.raw.to_vec()));
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = observe(&before, &active, fixture.local, None);
    assert!(!held(&old, fixture.collection, &child_handle.raw));

    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let arrived = fixture.store.snapshot().unwrap();
    assert_eq!(arrived.changes_since(&before), StoreChanges::BLOBS);
    let unreported = observe(&arrived, &active, fixture.local, Some((&before, &old)));
    assert!(!held(&unreported, fixture.collection, &child_handle.raw));
    assert_eq!(
        digest(&old, fixture.collection),
        digest(&unreported, fixture.collection),
        "an arrival nobody reported changes nothing that is served"
    );

    fixture.store.note_held(fixture.collection, child_handle);
    let reported = fixture.store.snapshot().unwrap();
    let new = observe(
        &reported,
        &active,
        fixture.local,
        Some((&arrived, &unreported)),
    );
    let old_collection = old.collection(fixture.collection).unwrap();
    let new_collection = new.collection(fixture.collection).unwrap();
    let old_manifest = crate::collection_wire::manifest(&old_collection.repair);
    let new_manifest = crate::collection_wire::manifest(&new_collection.repair);
    assert_eq!(old_manifest.records, new_manifest.records);
    assert_eq!(
        old_manifest.authorization_evidence,
        new_manifest.authorization_evidence
    );
    assert_eq!(old_manifest.wake_root, new_manifest.wake_root);
    assert_ne!(
        digest(&old, fixture.collection),
        digest(&new, fixture.collection)
    );
    assert!(held(&new, fixture.collection, &child_handle.raw));
    // The retained immutable observation does not learn a future arrival.
    assert!(!held(&old, fixture.collection, &child_handle.raw));
}

/// The walk backstop finds the same late child with no report at all.
#[test]
fn a_walk_finds_a_blob_only_child_nobody_reported() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(b"found by the walk".to_vec()));
    let child_handle = child.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(child_handle.raw.to_vec()));
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = observe(&before, &active, fixture.local, None);
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    fixture.store.walk_held(1).unwrap();
    let after = fixture.store.snapshot().unwrap();
    let new = observe(&after, &active, fixture.local, Some((&before, &old)));
    assert!(held(&new, fixture.collection, &child_handle.raw));
    assert_ne!(
        digest(&old, fixture.collection),
        digest(&new, fixture.collection)
    );
}

/// No budget: a body of any size is held with its children in the first
/// observation, and an unchanged refresh changes nothing.
#[test]
fn a_large_body_is_held_whole_in_the_first_observation() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(b"after the large body".to_vec()));
    let child_handle = child.get_handle();
    let mut body = vec![0; 4096 * 32];
    body.extend_from_slice(&child_handle.raw);
    let mut fixture = Fixture::new(Bytes::from_source(body));
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let snapshot = fixture.store.snapshot().unwrap();
    let serving = observe(&snapshot, &active, fixture.local, None);
    assert!(held(&serving, fixture.collection, &child_handle.raw));
    let again = fixture.store.snapshot().unwrap();
    assert_eq!(again.changes_since(&snapshot), StoreChanges::NONE);
    let unchanged = observe(&again, &active, fixture.local, Some((&snapshot, &serving)));
    assert_eq!(
        digest(&serving, fixture.collection),
        digest(&unchanged, fixture.collection)
    );
}

#[test]
fn deselection_discards_inventory_and_reactivation_observes_current_residency() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(b"selected child".to_vec()));
    let child_handle = child.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(child_handle.raw.to_vec()));
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let snapshot = fixture.store.snapshot().unwrap();
    let old = observe(&snapshot, &active, fixture.local, None);
    assert!(held(&old, fixture.collection, &child_handle.raw));
    let off = observe(
        &snapshot,
        &ActiveCollections::new(),
        fixture.local,
        Some((&snapshot, &old)),
    );
    assert!(off.collection(fixture.collection).is_none());
    assert_eq!(off.collections().count(), 0);
    let reactivated = observe(&snapshot, &active, fixture.local, Some((&snapshot, &off)));
    assert!(held(&reactivated, fixture.collection, &child_handle.raw));
}

#[test]
fn removed_parent_with_resident_child_invalidates_disconnected_inventory() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(
        b"resident but disconnected child".to_vec(),
    ));
    let child_handle = child.get_handle();
    let parent = Blob::<UnknownBlob>::new(Bytes::from_source(child_handle.raw.to_vec()));
    let parent_handle = parent.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(parent_handle.raw.to_vec()));
    fixture.store.put::<UnknownBlob, _>(parent).unwrap();
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = observe(&before, &active, fixture.local, None);
    assert!(held(&old, fixture.collection, &child_handle.raw));
    // Deliberately bypass root-preserving repository GC to model a backing
    // store removal. All other bytes, including the disconnected child, stay.
    let kept: Vec<Inline<Handle<UnknownBlob>>> = before
        .blobs()
        .map(|entry| entry.unwrap().handle)
        .filter(|handle| *handle != parent_handle)
        .collect();
    fixture.store.blobs.keep(kept);
    let after = fixture.store.snapshot().unwrap();
    assert!(after.get::<Bytes, UnknownBlob>(child_handle).is_ok());
    assert!(after.get::<Bytes, UnknownBlob>(parent_handle).is_err());
    let new = observe(&after, &active, fixture.local, Some((&before, &old)));
    assert!(!held(&new, fixture.collection, &parent_handle.raw));
    assert!(!held(&new, fixture.collection, &child_handle.raw));
    assert_eq!(
        new.collection(fixture.collection)
            .unwrap()
            .repair
            .records()
            .summary(),
        old.collection(fixture.collection)
            .unwrap()
            .repair
            .records()
            .summary()
    );
}

/// The publication barrier: the observation that first serves a new record
/// already serves its whole closure. No walk runs here; none is needed.
#[test]
fn a_new_records_closure_is_served_by_the_observation_that_carries_it() {
    let mut fixture = Fixture::new(Bytes::from_source(b"first payload".to_vec()));
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = observe(&before, &active, fixture.local, None);
    let grandchild = fixture
        .store
        .put::<UnknownBlob, _>(Bytes::from_source(b"deep under the new record".to_vec()))
        .unwrap();
    let child = fixture
        .store
        .put::<UnknownBlob, _>(Bytes::from_source(grandchild.raw.to_vec()))
        .unwrap();
    let data = fixture
        .store
        .put::<UnknownBlob, _>(Bytes::from_source(child.raw.to_vec()))
        .unwrap();
    let metadata = fixture
        .store
        .put::<SimpleArchive, _>(TribleSet::new())
        .unwrap();
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[109; 32]),
        fixture.collection,
        Handle::<UnknownBlob>::to_hash(data),
        metadata,
    ));
    fixture.store.insert(record).unwrap();
    let after = fixture.store.snapshot().unwrap();
    let new = observe(&after, &active, fixture.local, Some((&before, &old)));
    let served = new.collection(fixture.collection).unwrap();
    assert!(served.repair.records().get(record.fingerprint()).is_some());
    for handle in [data, child, grandchild] {
        assert!(held(&new, fixture.collection, &handle.raw));
    }
}

mod reference_pull {
    use tokio::sync::mpsc::UnboundedReceiver;
    use triblespace_core::collection::{CollectionData, empty_metadata_handle};
    use triblespace_core::repo::SnapshotSource;

    use super::*;
    use crate::announce::{Announcements, State};
    use crate::collection_activation::{held_digest, record_root};
    use crate::connection::Link;
    use crate::patch_repair::PatchSummary;
    use crate::recon::Frame;
    use crate::walk::tests::walking::{Node, carry, connect, open};
    use crate::walk::{PullDone, PullKind};

    /// The held set the node's walks observe for C.
    fn held_set(node: &Node, collection: CollectionHandle) -> PatchSummary {
        PatchSummary::from_patch(
            node.serving()
                .collection(collection)
                .unwrap()
                .repair()
                .blob_inventory(),
        )
    }

    fn holds(node: &Node, collection: CollectionHandle, handle: &[u8; 32]) -> bool {
        let collection = node.serving().collection(collection).unwrap();
        collection.repair().blob_inventory().has_prefix(handle)
    }

    /// Two nodes holding one collection with the responder's record, whose
    /// data D names two blob-only children. The responder holds all three.
    /// The puller holds D, scanned before either child was resident, so no
    /// later arrival of a child makes it held there.
    struct Pair {
        puller: Node,
        responder: Node,
        collection: CollectionHandle,
        children: [Blob<UnknownBlob>; 2],
    }

    fn pair(first: u8) -> Pair {
        let mut puller = Node::new(first);
        let mut responder = Node::new(first + 1);
        let collection = puller.hold("references", open());
        assert_eq!(responder.hold("references", open()), collection);
        let children = [b"first child".as_slice(), b"second child".as_slice()]
            .map(|bytes| Blob::<UnknownBlob>::new(Bytes::from_source(bytes.to_vec())));
        let data = Blob::<UnknownBlob>::new(Bytes::from_source(
            children
                .iter()
                .flat_map(|child| child.get_handle().raw)
                .collect::<Vec<_>>(),
        ));
        for child in &children {
            responder
                .store
                .put::<UnknownBlob, _>(child.clone())
                .unwrap();
        }
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &responder.key,
            collection,
            CollectionData::new(data.get_handle().raw),
            empty_metadata_handle(),
        ));
        for node in [&mut puller, &mut responder] {
            node.store.put::<UnknownBlob, _>(data.clone()).unwrap();
            node.store.insert(record).unwrap();
            node.store.track_held([collection]);
            node.observe();
            assert!(holds(node, collection, &data.get_handle().raw));
        }
        for child in &children {
            assert!(holds(&responder, collection, &child.get_handle().raw));
            assert!(!holds(&puller, collection, &child.get_handle().raw));
        }
        Pair {
            puller,
            responder,
            collection,
            children,
        }
    }

    impl Pair {
        /// Answer the puller's fetches from the responder's store, failing
        /// those `fail` names. Returns the handles fetched.
        fn answer(&mut self, fail: &[[u8; 32]]) -> Vec<[u8; 32]> {
            let now = crate::clock::mono_now();
            let store = self.responder.store.snapshot().unwrap();
            let mut handles = Vec::new();
            for (walk, handle, proof) in std::mem::take(&mut self.puller.fetches) {
                assert!(proof.is_none());
                let blob = (!fail.contains(&handle)).then(|| {
                    BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(&store, Inline::new(handle))
                        .unwrap()
                });
                self.puller.walks.fetched(walk, handle, None, blob, now);
                handles.push(handle);
            }
            handles.sort_unstable();
            handles
        }
    }

    /// The puller lacks both children. It fetches them by hash from the
    /// responder and holds them in C only because the responder holds them
    /// there: D, which names them, was scanned before they arrived.
    #[test]
    fn a_reference_pull_fetches_what_the_peer_holds_and_holds_it_in_c() {
        let now = crate::clock::mono_now();
        let mut pair = pair(41);
        let collection = pair.collection;
        let mut wire = connect(&pair.puller, &pair.responder, 1);
        pair.puller
            .walks
            .start_reference_pull(&wire.to_right, collection, now);
        carry(&mut pair.puller, &mut pair.responder, &mut wire, now);
        let mut children = pair.children.clone().map(|child| child.get_handle().raw);
        children.sort_unstable();
        assert_eq!(pair.answer(&[]), children);
        carry(&mut pair.puller, &mut pair.responder, &mut wire, now);

        let walked = held_set(&pair.responder, collection);
        assert_eq!(
            pair.puller.done,
            [PullDone {
                peer: pair.responder.id(),
                collection,
                kind: PullKind::References,
                root: held_digest(walked),
                completed: true,
            }]
        );
        for child in &children {
            assert!(holds(&pair.puller, collection, child));
        }
        assert_eq!(held_set(&pair.puller, collection), walked);
    }

    /// The first child is resident at the puller without being held there,
    /// and joins without a fetch. The fetch of the second fails, so the pull
    /// does not complete and the next one fetches it again.
    #[test]
    fn a_resident_blob_joins_without_a_fetch_and_a_failed_fetch_is_retried() {
        let now = crate::clock::mono_now();
        let mut pair = pair(43);
        let collection = pair.collection;
        let [resident, fetched] = pair.children.clone().map(|child| child.get_handle().raw);
        pair.puller
            .store
            .put::<UnknownBlob, _>(pair.children[0].clone())
            .unwrap();
        pair.puller.observe();
        assert!(!holds(&pair.puller, collection, &resident));
        let mut wire = connect(&pair.puller, &pair.responder, 1);
        for attempt in 0..2 {
            pair.puller
                .walks
                .start_reference_pull(&wire.to_right, collection, now);
            carry(&mut pair.puller, &mut pair.responder, &mut wire, now);
            let fail = if attempt == 0 {
                vec![fetched]
            } else {
                Vec::new()
            };
            assert_eq!(pair.answer(&fail), [fetched]);
            carry(&mut pair.puller, &mut pair.responder, &mut wire, now);
            assert!(holds(&pair.puller, collection, &resident));
            assert_eq!(holds(&pair.puller, collection, &fetched), attempt == 1);
            assert_eq!(pair.puller.done[attempt].completed, attempt == 1);
        }
        assert_eq!(
            held_set(&pair.puller, collection),
            held_set(&pair.responder, collection)
        );
    }

    /// Answer `node`'s fetches from `holder`'s store.
    fn serve_fetches(node: &mut Node, holder: &mut Node) {
        let now = crate::clock::mono_now();
        let store = holder.store.snapshot().unwrap();
        for (walk, handle, _) in std::mem::take(&mut node.fetches) {
            let blob =
                BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(&store, Inline::new(handle))
                    .ok();
            node.walks.fetched(walk, handle, None, blob, now);
        }
    }

    /// What `node` announces for C as a Full neighbour.
    fn state(node: &Node, collection: CollectionHandle) -> State {
        let repair = node.serving().collection(collection).unwrap();
        let repair = repair.repair();
        State {
            root: record_root(
                collection,
                repair.records().summary(),
                repair.authorization_evidence().summary(),
            ),
            held: Some(held_digest(PatchSummary::from_patch(
                repair.blob_inventory(),
            ))),
        }
    }

    /// The announcements sent on a link: state and reply flag.
    fn announced(frames: &mut UnboundedReceiver<Frame>) -> Vec<(State, bool)> {
        std::iter::from_fn(|| frames.try_recv().ok())
            .map(|frame| match frame {
                Frame::Announce {
                    root,
                    held_digest,
                    reply,
                    ..
                } => (
                    State {
                        root,
                        held: held_digest,
                    },
                    reply,
                ),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    /// Astra's R1: two quiet Full neighbours with equal records hold
    /// different blobs in C. One announcement and its reply start a
    /// reference pull each way, and both end with the union: the next
    /// announcement is equal and starts nothing.
    #[test]
    fn quiet_full_neighbours_converge_after_one_announcement_and_reply() {
        let mut now = crate::clock::mono_now();
        let mut x = Node::new(51);
        let mut y = Node::new(52);
        let collection = x.hold("held apart", open());
        assert_eq!(y.hold("held apart", open()), collection);
        let children = [b"x holds this".as_slice(), b"y holds this".as_slice()]
            .map(|bytes| Blob::<UnknownBlob>::new(Bytes::from_source(bytes.to_vec())));
        let data = Blob::<UnknownBlob>::new(Bytes::from_source(
            children
                .iter()
                .flat_map(|child| child.get_handle().raw)
                .collect::<Vec<_>>(),
        ));
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &x.key,
            collection,
            CollectionData::new(data.get_handle().raw),
            empty_metadata_handle(),
        ));
        for (node, child) in [(&mut x, &children[0]), (&mut y, &children[1])] {
            node.store.put::<UnknownBlob, _>(child.clone()).unwrap();
            node.store.put::<UnknownBlob, _>(data.clone()).unwrap();
            node.store.insert(record).unwrap();
            node.store.track_held([collection]);
            node.observe();
        }
        let (x_state, y_state) = (state(&x, collection), state(&y, collection));
        assert_eq!(x_state.root, y_state.root);
        assert_ne!(x_state.held, y_state.held);

        // Announcements and walks ride separate fake links here.
        let (x_to_y, mut from_x) = Link::detached(2, y.id());
        let (y_to_x, mut from_y) = Link::detached(2, x.id());
        let (mut x_says, mut y_says) = (Announcements::default(), Announcements::default());
        x_says.observe([(collection, x_state)], now);
        y_says.observe([(collection, y_state)], now);
        x_says.neighbours([(collection, &x_to_y, true, true)], now);
        y_says.neighbours([(collection, &y_to_x, true, true)], now);
        // X's first opportunity comes first.
        while from_x.is_empty() {
            now = now + std::time::Duration::from_millis(100);
            x_says.poll(now);
        }
        let mut wire = connect(&x, &y, 1);
        let [(announcement, false)] = announced(&mut from_x)[..] else {
            panic!("one periodic announcement");
        };
        assert_eq!(announcement, x_state);
        let pulls = y_says.heard(x.id(), collection, announcement, false, now);
        assert_eq!(pulls, [(x.id(), collection, PullKind::References)]);
        y.walks.start_reference_pull(&wire.to_left, collection, now);
        let [(reply, true)] = announced(&mut from_y)[..] else {
            panic!("one reply");
        };
        assert_eq!(reply, y_state);
        let pulls = x_says.heard(y.id(), collection, reply, true, now);
        assert_eq!(pulls, [(y.id(), collection, PullKind::References)]);
        x.walks
            .start_reference_pull(&wire.to_right, collection, now);

        carry(&mut x, &mut y, &mut wire, now);
        serve_fetches(&mut x, &mut y);
        serve_fetches(&mut y, &mut x);
        carry(&mut x, &mut y, &mut wire, now);
        for (node, says) in [(&x, &mut x_says), (&y, &mut y_says)] {
            assert_eq!(node.done.len(), 1);
            assert!(node.done[0].completed);
            assert!(says.ended(node.done[0], now).is_empty());
        }
        let union = state(&x, collection);
        assert_eq!(union, state(&y, collection));
        for child in &children {
            assert!(holds(&x, collection, &child.get_handle().raw));
        }
        assert!(announced(&mut from_x).is_empty() && announced(&mut from_y).is_empty());

        x_says.observe([(collection, union)], now);
        y_says.observe([(collection, union)], now);
        assert!(
            y_says
                .heard(x.id(), collection, union, false, now)
                .is_empty()
        );
        assert!(announced(&mut from_y).is_empty());
    }
}
