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
