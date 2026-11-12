use super::*;
use ed25519_dalek::SigningKey;
use triblespace_core::blob::IntoBlob;
use triblespace_core::collection::{CollectionPolicy, CollectionStore, CollectionStoreExt};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreList, BlobStorePut};

#[test]
fn maintenance_catches_arrivals_during_a_pass_without_self_sustaining_work() {
    let mut store = MemoryRepo::default();
    let before = store.snapshot().unwrap();
    let observed = ObservedStore::new(before.clone());
    let requested: Blob<UTF8String> = "arrived while maintenance ran".to_blob();
    assert!(observed
        .get::<Blob<UTF8String>, _>(requested.get_handle())
        .is_err());
    store.put::<UTF8String, _>(requested).unwrap();
    let interests = observed.dependencies();
    let after = store.snapshot().unwrap();
    let catch_up = maintenance_changed(&before, &after, &interests);
    assert!(
        catch_up,
        "post-work baseline must not swallow an in-flight append"
    );

    // The next poll has the post-work baseline, so only the retained dirty
    // bit requests its bounded catch-up pass. With no further arrivals or
    // writes that pass clears the bit instead of becoming an idle loop.
    let poll = store.snapshot().unwrap();
    assert!(!maintenance_changed(&after, &poll, &interests));
    assert!(catch_up || maintenance_changed(&after, &poll, &interests));
    let after_catch_up = store.snapshot().unwrap();
    assert!(!maintenance_changed(&poll, &after_catch_up, &interests));
}

#[test]
fn maintenance_ignores_repeated_observations_without_content_changes() {
    let mut store = MemoryRepo::default();
    let previous = store.snapshot().unwrap();
    let interests = StoreDependencies {
        all_blobs: true,
        all_records: true,
        capability_proofs: true,
        ..StoreDependencies::default()
    };

    for _ in 0..3 {
        let sampled = store.snapshot().unwrap();
        assert!(!maintenance_changed(&previous, &sampled, &interests));
    }
}

fn observed_maintenance_pass(
    pile: &mut Pile,
    targets: &[CollectionHandle],
    signer: &SigningKey,
    calls: &mut usize,
) -> (usize, StoreDependencies) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let references = targets
        .iter()
        .map(|handle| format!("blake3:{}", handle_hex(*handle)))
        .collect::<Vec<_>>();
    let mut observed = ObservedStore::new(pile);
    *calls += 1;
    let failures = runtime
        .block_on(maintenance_pass(
            &mut observed,
            &references,
            signer,
            true,
            SuccinctBackend::Cpu,
            &mut MaintenanceState::default(),
        ))
        .unwrap();
    (failures, observed.dependencies())
}

#[test]
fn maintenance_read_set_ignores_unrelated_arrivals_but_tracks_source_and_cold_blobs() {
    use triblespace_core::capability::{CapabilityProof, CapabilityResource};
    use triblespace_core::collection::{
        empty_metadata_handle, read_capability, CollectionCommit, CollectionSnapshotExt,
    };
    use triblespace_core::macros::entity;
    use triblespace_core::repo::{CapabilityProofStore, WantRead, WantRequest, WantStore};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("scoped-maintenance.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[61; 32]);
    // The maintainer is the pile's host: its MAPs are the ones believed.
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let mut writer = Pile::open(&path).unwrap();
    let policy = direct_policy(signer.verifying_key());
    let source = pile.collection("scoped source", policy.clone()).unwrap();
    let succinct = pile.attach::<SuccinctArchiveBlob>(source, ()).unwrap();
    let target = pile
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(source, succinct)
        .unwrap();
    let other = pile.collection("unrelated source", policy).unwrap();
    for text in ["first scoped member", "second scoped member"] {
        pile.commit(source, &signer, entity! { metadata::description: text })
            .unwrap();
    }
    let selected = [target.handle()];
    let mut calls = 0;
    let before = pile.snapshot().unwrap();
    let (failures, first_interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(failures, 0);
    let after = pile.snapshot().unwrap();
    assert!(
        maintenance_changed(&before, &after, &first_interests),
        "own publication requests one catch-up"
    );
    let (failures, interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(failures, 0);
    let settled = pile.snapshot().unwrap();
    assert!(!maintenance_changed(&after, &settled, &interests));
    assert_eq!(calls, 2);
    assert!(
        !interests.all_records && !interests.all_blobs,
        "exact selection and census stay scoped"
    );
    for handle in [source.handle(), succinct.handle(), target.handle()] {
        assert!(interests
            .records
            .contains(&CollectionRecordSelector::Collection(handle)));
        assert!(interests
            .blobs
            .contains(&Handle::<SimpleArchive>::to_hash(handle)));
    }

    writer.put::<UTF8String, _>("unrelated payload").unwrap();
    let requested: Blob<UTF8String> = "unrelated request".to_blob();
    writer
        .want(WantRequest::blob(requested.get_handle()))
        .unwrap();
    writer
        .commit(
            other,
            &signer,
            entity! { metadata::description: "unrelated record" },
        )
        .unwrap();
    let unrelated = pile.snapshot().unwrap();
    assert!(!unrelated.changes_since(&settled).is_empty());
    if maintenance_changed(&settled, &unrelated, &interests) {
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    }
    assert_eq!(
        calls, 2,
        "no maintenance call for unrelated blob, WANT or record"
    );

    // Proof lookup is still component-wide, deliberately. A proof-only
    // arrival retries once even when it concerns a different resource.
    assert!(interests.capability_proofs);
    writer
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(other.handle()),
            &signer,
            read_capability(),
            SigningKey::from_bytes(&[65; 32]).verifying_key(),
        ))
        .unwrap();
    let proof_arrived = pile.snapshot().unwrap();
    assert!(maintenance_changed(&unrelated, &proof_arrived, &interests));
    let (failures, interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(failures, 0);
    assert_eq!(calls, 3);
    assert!(!maintenance_changed(
        &proof_arrived,
        &pile.snapshot().unwrap(),
        &interests
    ));

    let cold: Blob<SimpleArchive> = entity! { metadata::description: "new cold source member" }
        .facts()
        .clone()
        .to_blob();
    writer
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &signer,
            source.handle(),
            Handle::<SimpleArchive>::to_hash(cold.get_handle()),
            empty_metadata_handle(),
        )))
        .unwrap();
    let source_arrived = pile.snapshot().unwrap();
    assert!(maintenance_changed(
        &proof_arrived,
        &source_arrived,
        &interests
    ));
    let (failures, cold_interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(
        failures, 0,
        "a node whose bytes are not here is left to the residual, not an error"
    );
    assert_eq!(calls, 4);
    assert!(cold_interests
        .blobs
        .contains(&Handle::<SimpleArchive>::to_hash(cold.get_handle())));
    let absent = pile.snapshot().unwrap();
    assert!(!absent.contains_blob(cold.get_handle()).unwrap());
    let read = absent.attached(target).unwrap();
    assert_eq!(read.support().len(), 2);
    assert_eq!(read.residual().len(), 1);
    drop(read);
    let wants_before = absent.wants().unwrap().count();
    assert_eq!(wants_before, 1, "maintenance did not manufacture a WANT");
    assert!(!maintenance_changed(
        &absent,
        &pile.snapshot().unwrap(),
        &cold_interests
    ));

    writer.put::<SimpleArchive, _>(cold).unwrap();
    let resident = pile.snapshot().unwrap();
    assert!(
        maintenance_changed(&absent, &resident, &cold_interests),
        "blob-only arrival retries the failed input"
    );
    let (failures, complete_interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(failures, 0);
    let complete = pile.snapshot().unwrap();
    assert_eq!(complete.attached(target).unwrap().support().len(), 3);
    assert!(maintenance_changed(
        &resident,
        &complete,
        &complete_interests
    ));
    let (failures, settled_interests) =
        observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
    assert_eq!(failures, 0);
    assert!(!maintenance_changed(
        &complete,
        &pile.snapshot().unwrap(),
        &settled_interests
    ));
    assert_eq!(calls, 6, "one retry and one bounded self-write catch-up");
    writer.close().unwrap();
    pile.close().unwrap();
}

#[test]
fn maintenance_errors_keep_missing_descriptors_and_grant_definitions_as_interests() {
    use triblespace_core::capability::{capability_action, CapabilityProof, CapabilityResource};
    use triblespace_core::collection::{CollectionSnapshotExt, ACTION_WRITE};
    use triblespace_core::macros::entity;
    use triblespace_core::repo::CapabilityProofStore;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("scoped-authority.pile");
    std::fs::File::create(&path).unwrap();
    let root = SigningKey::from_bytes(&[62; 32]);
    let signer = SigningKey::from_bytes(&[63; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let policy = direct_policy(root.verifying_key());
    // The signer writes the source through a delegated grant whose
    // definition is not here yet, so its member is not admitted, and the
    // attached target has nothing to attach until the definition arrives.
    let source = pile.collection("delegated source", policy.clone()).unwrap();
    let target = pile.attach::<SuccinctArchiveBlob>(source, ()).unwrap();
    pile.commit(
        source,
        &signer,
        entity! { metadata::description: "delegated member" },
    )
    .unwrap();
    let definition: Blob<SimpleArchive> = entity! {
        capability_action: ACTION_WRITE,
        metadata::description: "scoped maintenance test grant",
    }
    .facts()
    .clone()
    .to_blob();
    pile.insert_proof(CapabilityProof::new(
        CapabilityResource::from(source.handle()),
        &root,
        definition.get_handle(),
        signer.verifying_key(),
    ))
    .unwrap();

    let mut elsewhere = MemoryRepo::default();
    let late = elsewhere
        .collection("late selected descriptor", policy)
        .unwrap();
    let late_blob: Blob<SimpleArchive> = elsewhere.snapshot().unwrap().get(late.handle()).unwrap();
    let targets = [target.handle(), late.handle()];
    let mut calls = 0;
    let (failures, interests) = observed_maintenance_pass(&mut pile, &targets, &signer, &mut calls);
    assert_eq!(
        failures, 1,
        "the missing descriptor fails; the target has nothing to do"
    );
    assert!(interests.capability_proofs);
    for handle in [late.handle(), definition.get_handle()] {
        assert!(interests
            .blobs
            .contains(&Handle::<SimpleArchive>::to_hash(handle)));
    }
    assert!(!interests.all_records && !interests.all_blobs);
    let failed = pile.snapshot().unwrap();
    assert!(failed.attached(target).unwrap().cover().is_empty());
    pile.put::<UTF8String, _>("unrelated between failures")
        .unwrap();
    let unrelated = pile.snapshot().unwrap();
    assert!(!maintenance_changed(&failed, &unrelated, &interests));
    pile.put::<SimpleArchive, _>(definition).unwrap();
    pile.put::<SimpleArchive, _>(late_blob).unwrap();
    let available = pile.snapshot().unwrap();
    assert!(maintenance_changed(&unrelated, &available, &interests));
    let (failures, settled_interests) =
        observed_maintenance_pass(&mut pile, &targets, &signer, &mut calls);
    assert_eq!(failures, 0);
    let complete = pile.snapshot().unwrap();
    assert_eq!(complete.attached(target).unwrap().support().len(), 1);
    assert_eq!(calls, 2);
    assert!(maintenance_changed(
        &available,
        &complete,
        &settled_interests
    ));
    pile.close().unwrap();
}

#[test]
fn maintenance_name_lookup_remains_a_real_global_record_interest() {
    use triblespace_core::macros::entity;

    let mut pile = MemoryRepo::default();
    let signer = SigningKey::from_bytes(&[64; 32]);
    let source = pile
        .collection(
            "named maintenance target",
            direct_policy(signer.verifying_key()),
        )
        .unwrap();
    pile.commit(
        source,
        &signer,
        entity! { metadata::description: "named member" },
    )
    .unwrap();
    let snapshot = pile.snapshot().unwrap();
    let exact = ObservedStore::new(snapshot.clone());
    assert_eq!(
        resolve_maintenance_target(&exact, &format!("blake3:{}", handle_hex(source.handle())))
            .unwrap(),
        source.handle()
    );
    assert!(
        exact.dependencies().is_empty(),
        "an explicit handle needs no name inventory"
    );
    let named = ObservedStore::new(snapshot);
    assert_eq!(
        resolve_maintenance_target(&named, "name:named maintenance target").unwrap(),
        source.handle()
    );
    assert!(named.dependencies().all_records);
    assert!(!named.dependencies().all_blobs);
}

fn direct_policy(root: ed25519_dalek::VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
}

fn driver_fixture() -> (
    tempfile::TempDir,
    Pile,
    SigningKey,
    Collection<EntityIdSetBlob>,
) {
    use triblespace_core::macros::entity;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-maintenance.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[91; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let source = pile
        .collection("native maintenance", direct_policy(signer.verifying_key()))
        .unwrap();
    let target = pile
        .attach::<EntityIdSetBlob>(source, metadata::supersedes.id())
        .unwrap();
    let value = triblespace_core::id::genid();
    for description in ["first", "second"] {
        pile.commit(
            source,
            &signer,
            entity! { metadata::supersedes: &value, metadata::description: description },
        )
        .unwrap();
    }
    (directory, pile, signer, target)
}

#[tokio::test]
async fn native_driver_reports_real_work_then_becomes_quiet_and_closes() {
    let (directory, mut pile, signer, target) = driver_fixture();
    let mut driver = Driver::new(
        [Target::Handle(target.handle())],
        true,
        SuccinctBackend::Cpu,
    )
    .unwrap();
    let mut events = Vec::new();
    let first = driver
        .tick(&mut pile, &signer, &mut |event| events.push(event))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.failures, 0);
    assert!(first.published > 0);
    let starts = events
        .iter()
        .filter(|event| matches!(event, Event::HopStarted { .. }))
        .count();
    let finishes = events
        .iter()
        .filter(|event| matches!(event, Event::HopFinished { error: None, .. }))
        .count();
    assert_eq!(starts, finishes);
    assert_eq!(finishes, first.maintained);
    assert!(events.iter().any(
        |event| matches!(event, Event::HopFinished { publications, .. } if publications.maps > 0)
    ));
    for _ in 0..3 {
        driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap();
    }
    events.clear();
    assert!(driver
        .tick(&mut pile, &signer, &mut |event| events.push(event))
        .await
        .unwrap()
        .is_none());
    assert!(events.is_empty(), "idle polls must not claim activity");
    drop(driver);
    pile.close().unwrap();
    Pile::open_as(
        &directory.path().join("native-maintenance.pile"),
        signer.verifying_key(),
    )
    .unwrap()
    .close()
    .unwrap();
}

#[tokio::test]
async fn cancelling_between_hops_stops_work_and_next_tick_resumes() {
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use triblespace_core::collection::CollectionSnapshotExt;

    let (_directory, mut pile, signer, target) = driver_fixture();
    let mut driver = Driver::new(
        [Target::Handle(target.handle())],
        true,
        SuccinctBackend::Cpu,
    )
    .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let mut observer = move |event| observed.lock().unwrap().push(event);
    {
        let mut tick = Box::pin(driver.tick(&mut pile, &signer, &mut observer));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(tick.as_mut().poll(&mut context), Poll::Pending));
        assert!(
            events.lock().unwrap().is_empty(),
            "first boundary precedes any hop"
        );
        drop(tick);
    }
    {
        let mut tick = Box::pin(driver.tick(&mut pile, &signer, &mut observer));
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            assert!(matches!(tick.as_mut().poll(&mut context), Poll::Pending));
            if events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, Event::HopFinished { .. }))
            {
                break;
            }
        }
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::HopFinished { .. })));
        drop(tick);
    }
    let stopped = events.lock().unwrap().len();
    tokio::task::yield_now().await;
    assert_eq!(
        events.lock().unwrap().len(),
        stopped,
        "no detached maintenance worker"
    );
    let resumed = driver
        .tick(&mut pile, &signer, &mut observer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.failures, 0);
    assert!(!pile
        .snapshot()
        .unwrap()
        .attached(target)
        .unwrap()
        .support()
        .is_empty());
    drop(driver);
    pile.close().unwrap();
}

#[test]
fn interrupted_hop_observation_is_balanced_without_claiming_completion() {
    let mut events = Vec::new();
    let collection = Inline::new([92; 32]);
    let mut observer = |event| events.push(event);
    drop(HopObservation::start(&mut observer, collection));
    assert!(matches!(
        events.as_slice(),
        [Event::HopStarted { .. }, Event::HopCancelled { .. }]
    ));
}

/// A deterministic transport boundary over a real temporary pile. No sockets,
/// background tasks or timer race are needed to hold one acquisition in flight.
struct SuspendedStore {
    pile: Pile,
    acquiring: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SnapshotSource for SuspendedStore {
    type Snapshot = <Pile as SnapshotSource>::Snapshot;
    type SnapshotError = <Pile as SnapshotSource>::SnapshotError;
    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.pile.snapshot()
    }
}

impl BlobStorePut for SuspendedStore {
    type PutError = <Pile as BlobStorePut>::PutError;
    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: triblespace_core::blob::BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: triblespace_core::inline::InlineEncoding,
    {
        self.pile.put(item)
    }
}

impl CollectionStore for SuspendedStore {
    type InsertError = <Pile as CollectionStore>::InsertError;
    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.pile.insert(record)
    }
}

impl triblespace_core::repo::CapabilityProofStore for SuspendedStore {
    type InsertError = <Pile as triblespace_core::repo::CapabilityProofStore>::InsertError;
    fn insert_proof(
        &mut self,
        proof: triblespace_core::capability::CapabilityProof,
    ) -> Result<(), Self::InsertError> {
        self.pile.insert_proof(proof)
    }
}

impl AsyncBlobStoreAcquire for SuspendedStore {
    type AcquireError = <Pile as AsyncBlobStoreAcquire>::AcquireError;
    async fn acquire(
        &mut self,
        _handle: Inline<Handle<triblespace_core::blob::encodings::UnknownBlob>>,
    ) -> Result<Option<anybytes::Bytes>, Self::AcquireError> {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Active<'a>(&'a AtomicBool);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        self.acquiring.store(true, Ordering::SeqCst);
        let _active = Active(&self.acquiring);
        std::future::pending().await
    }
    fn acquires_remotely(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn cancelling_an_active_acquisition_drops_it_and_closes_the_pile() {
    use std::future::Future;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::task::{Context, Poll, Waker};
    use triblespace_core::macros::entity;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("suspended-acquisition.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[93; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let mut elsewhere = MemoryRepo::for_host(signer.verifying_key());
    let source = elsewhere
        .collection("cold source", direct_policy(signer.verifying_key()))
        .unwrap();
    let target = elsewhere
        .attach::<EntityIdSetBlob>(source, metadata::supersedes.id())
        .unwrap();
    let snapshot = elsewhere.snapshot().unwrap();
    let target_blob: Blob<SimpleArchive> = snapshot.get(target.handle()).unwrap();
    let parent_blob: Blob<SimpleArchive> = snapshot.get(source.handle()).unwrap();
    pile.put::<SimpleArchive, _>(target_blob).unwrap();
    let acquiring = Arc::new(AtomicBool::new(false));
    let mut store = SuspendedStore {
        pile,
        acquiring: Arc::clone(&acquiring),
    };
    let mut driver = Driver::new(
        [Target::Handle(target.handle())],
        false,
        SuccinctBackend::Cpu,
    )
    .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let mut observer = move |event| observed.lock().unwrap().push(event);
    {
        let mut tick = Box::pin(driver.tick(&mut store, &signer, &mut observer));
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            assert!(matches!(tick.as_mut().poll(&mut context), Poll::Pending));
            if acquiring.load(Ordering::SeqCst) {
                break;
            }
        }
        assert!(
            acquiring.load(Ordering::SeqCst),
            "real maintenance reached acquisition"
        );
        drop(tick);
    }
    assert!(
        !acquiring.load(Ordering::SeqCst),
        "dropping the tick dropped the acquisition"
    );
    assert!(events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::HopCancelled { .. })));
    let stopped = events.lock().unwrap().len();
    tokio::task::yield_now().await;
    assert_eq!(events.lock().unwrap().len(), stopped);
    // No detached work keeps a mutable borrow: the same native driver/store can
    // resume directly after the formerly absent bytes arrive.
    store.pile.put::<SimpleArchive, _>(parent_blob).unwrap();
    store
        .pile
        .commit(
            source,
            &signer,
            entity! { metadata::description: "available after cancellation" },
        )
        .unwrap();
    let pass = driver
        .tick(&mut store.pile, &signer, &mut observer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pass.failures, 0);
    drop(driver);
    store.pile.close().unwrap();
    Pile::open_as(&path, signer.verifying_key())
        .unwrap()
        .close()
        .unwrap();
}

#[tokio::test]
async fn native_name_selection_preserves_literal_whitespace() {
    use triblespace_core::macros::entity;
    let signer = SigningKey::from_bytes(&[94; 32]);
    let mut store = MemoryRepo::for_host(signer.verifying_key());
    let source = store
        .collection(
            "name ending in space ",
            direct_policy(signer.verifying_key()),
        )
        .unwrap();
    store
        .commit(
            source,
            &signer,
            entity! { metadata::description: "named member" },
        )
        .unwrap();
    let mut driver = Driver::new(
        [Target::Name("name ending in space ".into())],
        true,
        SuccinctBackend::Cpu,
    )
    .unwrap();
    let pass = driver
        .tick(&mut store, &signer, &mut |_| {})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pass.targets, 1);
    assert_eq!(pass.failures, 0);
}

use triblespace_core::collection::{registered_targets, AttachedMapping, MapMapping};

/// An attached mapping this crate does not define, onto a representation it
/// knows: the supersedes id set under its own algorithm id. Minted with
/// `trible genid` on 2026-11-12 for this test: 05A39DCCB574AE6BE0AF228D4F515AA8.
const RENAMED_ID_SET: Id = triblespace_core::id::id_hex!("05A39DCCB574AE6BE0AF228D4F515AA8");

struct RenamedIdSetAlgorithm;

impl MetaDescribe for RenamedIdSetAlgorithm {
    fn describe() -> Fragment {
        use triblespace_core::macros::entity;
        let id = RENAMED_ID_SET;
        entity! {
            triblespace_core::id::ExclusiveId::force_ref(&id) @
                metadata::name: "test-renamed-supersedes-id-set",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

struct RenamedIdSet;

impl MapMapping for RenamedIdSet {
    type Target = EntityIdSetBlob;

    fn fragment(&self) -> Fragment {
        use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
        use triblespace_core::macros::entity;
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <RenamedIdSetAlgorithm as MetaDescribe>::describe(),
        }
    }

    fn bind(
        _parent: &Fragment,
        attached: &Fragment,
    ) -> Result<Self, triblespace_core::collection::CollectionOperationError> {
        match descriptor::mapping_algorithm(attached.facts()) {
            Ok(Some(algorithm)) if algorithm == RENAMED_ID_SET => Ok(Self),
            other => Err(triblespace_core::collection::CollectionOperationError::Fatal(
                format!("not the renamed id set: {other:?}"),
            )),
        }
    }

    fn map<R: StoreRead>(
        &self,
        node: &triblespace_core::blob::Blob<SimpleArchive>,
        siblings: &[triblespace_core::collection::CollectionData],
        reader: &R,
    ) -> Result<
        triblespace_core::blob::Blob<EntityIdSetBlob>,
        triblespace_core::collection::CollectionOperationError,
    > {
        <EntityIdSetBlob as triblespace_core::collection::CollectionAttachment>::map(
            &metadata::supersedes.id(),
            node,
            siblings,
            reader,
        )
    }
}

/// A Driver runs a registered attached mapping by its algorithm, where the
/// representation's canonical mapping refuses it; without the registration
/// the hop fails as before. `registered_targets` finds the index once a MAP
/// names it.
#[tokio::test]
async fn a_registered_attached_mapping_runs_by_its_algorithm() {
    use triblespace_core::collection::CollectionSnapshotExt;
    use triblespace_core::macros::entity;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registered.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[91; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let source = pile
        .collection("registered", direct_policy(signer.verifying_key()))
        .unwrap();
    let target = pile.attach_with(source, RenamedIdSet).unwrap();
    let value = triblespace_core::id::genid();
    pile.commit(source, &signer, entity! { metadata::supersedes: &value })
        .unwrap();
    let registration = AttachedMapping::<RenamedIdSet>::new(RENAMED_ID_SET);
    assert!(registered_targets(&pile.snapshot().unwrap(), &registration)
        .unwrap()
        .is_empty());

    let mut plain = Driver::new([Target::Handle(target.handle())], false, SuccinctBackend::Cpu)
        .unwrap();
    let pass = plain.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!((pass.maintained, pass.failures), (0, 1));
    drop(plain);

    let mut driver = Driver::new([Target::Handle(target.handle())], false, SuccinctBackend::Cpu)
        .unwrap()
        .with_registered(registration);
    let mut events = Vec::new();
    let pass = driver
        .tick(&mut pile, &signer, &mut |event| events.push(event))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((pass.maintained, pass.failures), (1, 0));
    assert!(events.iter().any(
        |event| matches!(event, Event::HopFinished { publications, .. } if publications.maps > 0)
    ));
    let snapshot = pile.snapshot().unwrap();
    assert_eq!(
        registered_targets(&snapshot, driver.registered()).unwrap(),
        vec![(target.handle(), RENAMED_ID_SET)]
    );
    let attached = snapshot.attached(target).unwrap();
    assert!(attached.residual().is_empty());
    drop((attached, snapshot));

    // A new commit: the next tick attaches it.
    pile.commit(source, &signer, entity! { metadata::supersedes: &triblespace_core::id::genid() })
        .unwrap();
    let pass = driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!((pass.maintained, pass.failures), (1, 0));
    assert!(pile.snapshot().unwrap().attached(target).unwrap().residual().is_empty());
    drop(driver);
    pile.close().unwrap();
}

/// A derived mapping this crate does not define: the copy of each node,
/// under its own algorithm id, minted with `trible genid` on 2026-11-12 for
/// this test: 3ACEFFEACFE5C6AB0E24C22530189721.
const COPY_NODES: Id = triblespace_core::id::id_hex!("3ACEFFEACFE5C6AB0E24C22530189721");

struct CopyNodesAlgorithm;

impl MetaDescribe for CopyNodesAlgorithm {
    fn describe() -> Fragment {
        use triblespace_core::macros::entity;
        let id = COPY_NODES;
        entity! {
            triblespace_core::id::ExclusiveId::force_ref(&id) @
                metadata::name: "test-copy-nodes",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

struct CopyNodes;

impl triblespace_core::collection::DeriveMapping for CopyNodes {
    type Source = SimpleArchive;
    type Target = SimpleArchive;

    fn fragment(&self) -> Fragment {
        use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
        use triblespace_core::macros::entity;
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <CopyNodesAlgorithm as MetaDescribe>::describe(),
        }
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self, triblespace_core::collection::CollectionOperationError> {
        match descriptor::mapping_algorithm(target.facts()) {
            Ok(Some(algorithm)) if algorithm == COPY_NODES => Ok(Self),
            other => Err(triblespace_core::collection::CollectionOperationError::Fatal(
                format!("not the copy: {other:?}"),
            )),
        }
    }

    fn map<R: StoreRead>(
        &self,
        source: &triblespace_core::blob::Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<
        triblespace_core::blob::Blob<SimpleArchive>,
        triblespace_core::collection::CollectionOperationError,
    > {
        Ok(source.clone())
    }
}

/// The copy registration, counting the passes it is told about and saying
/// once that deferred work is due now.
struct Counted {
    inner: triblespace_core::collection::DerivedMapping<CopyNodes>,
    passes: std::sync::atomic::AtomicUsize,
    due: std::sync::Mutex<Option<Instant>>,
}

impl Mappings for Counted {
    fn runs(&self, algorithm: Id) -> bool {
        self.inner.runs(algorithm)
    }

    fn begin_pass<R: StoreRead>(&self, _snapshot: &R) {
        self.passes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.due.lock().unwrap() = None;
    }

    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, triblespace_core::collection::CollectionRealizationError> {
        self.inner.pending(snapshot, handle, algorithm)
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> triblespace_core::collection::Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        self.inner.maintain(pile, snapshot, handle, algorithm, signer)
    }

    fn due(&self) -> Option<Instant> {
        *self.due.lock().unwrap()
    }
}

/// One Driver maintains an attached and a derived collection, each through
/// its registration; without the derived registration the derived hop fails
/// as before. A registration's due work makes a tick pass with no input
/// changed.
#[tokio::test]
async fn attached_and_derived_registrations_run_in_one_driver() {
    use std::sync::atomic::Ordering;
    use triblespace_core::collection::{CollectionSnapshotExt, DerivedMapping};
    use triblespace_core::macros::entity;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("both.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[91; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let policy = direct_policy(signer.verifying_key());
    let source = pile.collection("both", policy.clone()).unwrap();
    let attached = pile.attach_with(source, RenamedIdSet).unwrap();
    let copy = pile.derive_with(source, CopyNodes, policy).unwrap();
    pile.commit(source, &signer, entity! { metadata::supersedes: &triblespace_core::id::genid() })
        .unwrap();
    let targets = || {
        [
            Target::Handle(attached.handle()),
            Target::Handle(copy.handle()),
        ]
    };

    let mut plain = Driver::new(targets(), false, SuccinctBackend::Cpu)
        .unwrap()
        .with_registered(AttachedMapping::<RenamedIdSet>::new(RENAMED_ID_SET));
    let pass = plain.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!((pass.maintained, pass.failures), (1, 1), "the copy is not registered");
    drop(plain);
    // New input for both: a registered hop runs when its registration says
    // it has work, and the plain Driver already attached the first commit.
    pile.commit(source, &signer, entity! { metadata::supersedes: &triblespace_core::id::genid() })
        .unwrap();

    let mut driver = Driver::new(targets(), false, SuccinctBackend::Cpu)
        .unwrap()
        .with_registered(AttachedMapping::<RenamedIdSet>::new(RENAMED_ID_SET))
        .with_registered(Counted {
            inner: DerivedMapping::new(COPY_NODES),
            passes: Default::default(),
            due: Default::default(),
        });
    let pass = driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!((pass.maintained, pass.failures), (2, 0));
    let snapshot = pile.snapshot().unwrap();
    assert!(snapshot.attached(attached).unwrap().residual().is_empty());
    assert_eq!(
        driver
            .registered()
            .pending(&snapshot, copy.handle(), COPY_NODES)
            .unwrap(),
        0
    );
    assert_eq!(
        registered_targets(&snapshot, &driver.registered().1).unwrap(),
        vec![(copy.handle(), COPY_NODES)]
    );
    drop(snapshot);

    // Quiet: no input changed, nothing due.
    for _ in 0..3 {
        driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap();
    }
    assert!(driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().is_none());
    let passes = driver.registered().1.passes.load(Ordering::SeqCst);
    // Deferred work due now: the next tick passes although nothing changed.
    *driver.registered().1.due.lock().unwrap() = Some(Instant::now());
    assert!(driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().is_some());
    assert_eq!(driver.registered().1.passes.load(Ordering::SeqCst), passes + 1);
    drop(driver);
    pile.close().unwrap();
}

/// The copy registration whose first maintain defers its work, as a failed
/// bind does: it publishes nothing, says the work is due now, and leaves the
/// store unchanged.
struct Deferring {
    inner: triblespace_core::collection::DerivedMapping<CopyNodes>,
    attempts: std::sync::atomic::AtomicUsize,
    due: std::sync::Mutex<Option<Instant>>,
}

impl Mappings for Deferring {
    fn runs(&self, algorithm: Id) -> bool {
        self.inner.runs(algorithm)
    }

    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, triblespace_core::collection::CollectionRealizationError> {
        self.inner.pending(snapshot, handle, algorithm)
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> triblespace_core::collection::Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        let attempt = self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt == 0 {
            *self.due.lock().unwrap() = Some(Instant::now());
            return Box::pin(async move {
                pile.snapshot().map_err(|error| {
                    triblespace_core::collection::CollectionRealizationError::Resolution(format!(
                        "{error:?}"
                    ))
                })
            });
        }
        *self.due.lock().unwrap() = None;
        self.inner.maintain(pile, snapshot, handle, algorithm, signer)
    }

    fn due(&self) -> Option<Instant> {
        *self.due.lock().unwrap()
    }
}

/// Work a registration deferred is done on its due pass although the store
/// has not changed: the Driver asks the registration whether a registered
/// hop has work instead of skipping it as unchanged.
#[tokio::test]
async fn a_due_registration_is_maintained_on_an_unchanged_store() {
    use std::sync::atomic::Ordering;
    use triblespace_core::collection::DerivedMapping;
    use triblespace_core::macros::entity;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deferred.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[91; 32]);
    let mut pile = Pile::open_as(&path, signer.verifying_key()).unwrap();
    let policy = direct_policy(signer.verifying_key());
    let source = pile.collection("deferred", policy.clone()).unwrap();
    let copy = pile.derive_with(source, CopyNodes, policy).unwrap();
    pile.commit(source, &signer, entity! { metadata::supersedes: &triblespace_core::id::genid() })
        .unwrap();
    let mut driver = Driver::new([Target::Handle(copy.handle())], false, SuccinctBackend::Cpu)
        .unwrap()
        .with_registered(Deferring {
            inner: DerivedMapping::new(COPY_NODES),
            attempts: Default::default(),
            due: Default::default(),
        });
    let pending = |pile: &mut Pile| {
        DerivedMapping::<CopyNodes>::new(COPY_NODES)
            .pending(&pile.snapshot().unwrap(), copy.handle(), COPY_NODES)
            .unwrap()
    };
    // The first pass defers: nothing derived, the work due now.
    driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!(driver.registered().1.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(pending(&mut pile), 1);
    // Nothing has changed in the store; the due pass maintains it anyway.
    let pass = driver.tick(&mut pile, &signer, &mut |_| {}).await.unwrap().unwrap();
    assert_eq!(driver.registered().1.attempts.load(Ordering::SeqCst), 2);
    assert_eq!((pass.maintained, pass.failures), (1, 0));
    assert_eq!(pending(&mut pile), 0);
    drop(driver);
    pile.close().unwrap();
}
