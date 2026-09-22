use super::*;
use triblespace_core::collection::{CollectionCommit, CollectionDerive, CollectionMerge};
use triblespace_core::prelude::*;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::CapabilityProofRead;

struct Fixture<S = MemoryRepo> {
    store: S,
    signer: SigningKey,
    source: Collection<SimpleArchive>,
    target: Collection<EntityIdSetBlob>,
    reports: Collection<SimpleArchive>,
}

impl Fixture<MemoryRepo> {
    fn new() -> Self {
        Self::with_store(MemoryRepo::default())
    }
}

impl<S: Store> Fixture<S> {
    fn with_store(mut store: S) -> Self {
        let signer = SigningKey::from_bytes(&[73; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(signer.verifying_key()),
            AdmissionPolicy::direct(signer.verifying_key()),
        );
        let source = store.collection("observed source", policy.clone()).unwrap();
        let target = store
            .derive::<EntityIdSetBlob>(source, metadata::supersedes.id(), policy.clone())
            .unwrap();
        let reports = store
            .collection("maintenance observations", policy)
            .unwrap();
        let value = genid();
        store
            .commit(
                source,
                &signer,
                entity! {
                    metadata::supersedes: &value,
                },
            )
            .unwrap();
        Self {
            store,
            signer,
            source,
            target,
            reports,
        }
    }

    fn options(&self) -> Options {
        Options {
            telemetry_collection: Some(hex::encode(self.reports.handle().raw)),
            telemetry_node: Some(hex::encode(self.signer.verifying_key().to_bytes())),
            telemetry_worker: Some("test-maintainer".into()),
            telemetry_key: None,
            telemetry_interval_secs: Some(60),
        }
    }

    fn telemetry(&mut self) -> Telemetry {
        let config = self.options().config().unwrap().unwrap();
        Telemetry::open(&mut self.store, config, &self.signer).unwrap()
    }

    fn reports(&mut self) -> Vec<telemetry::WorkerReport> {
        let snapshot = self.store.snapshot().unwrap();
        let facts = snapshot
            .collection(self.reports)
            .unwrap()
            .view::<TribleSet>()
            .unwrap();
        telemetry::observe(
            &facts,
            triblespace_core::clock::epoch_now()
                .to_tai_duration()
                .total_nanoseconds(),
            Duration::from_secs(180),
        )
    }
}

fn pile_fixture() -> (tempfile::TempDir, Fixture<Pile>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("maintenance-telemetry.pile");
    std::fs::File::create(&path).unwrap();
    let store = Pile::open(&path).unwrap();
    (directory, Fixture::with_store(store))
}

fn equations() -> [CollectionRecord; 3] {
    let signer = SigningKey::from_bytes(&[74; 32]);
    let mut store = MemoryRepo::default();
    let collection: Collection<SimpleArchive> = store
        .collection(
            "counter fixture",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap();
    let low: Blob<SimpleArchive> = entity! { metadata::name: "low" }.facts().clone().to_blob();
    let high: Blob<SimpleArchive> = entity! { metadata::name: "high" }.facts().clone().to_blob();
    let low_handle = low.get_handle();
    let high_handle = high.get_handle();
    let low = Handle::<SimpleArchive>::to_hash(low_handle);
    let high = Handle::<SimpleArchive>::to_hash(high_handle);
    let a = CollectionCommit::sign(&signer, collection.handle(), low, low_handle);
    [
        CollectionRecord::Commit(a),
        CollectionRecord::Merge(CollectionMerge::sign(
            &signer,
            collection.handle(),
            low,
            high,
            high,
        )),
        CollectionRecord::Derive(CollectionDerive::sign(
            &signer,
            collection.handle(),
            low,
            high,
        )),
    ]
}

#[test]
fn publication_counter_counts_successful_calls_including_idempotent_insertions() {
    let records = equations();
    let mut store = MemoryRepo::default();
    let mut counts = Publications::default();
    {
        let mut counted = CountedStore {
            inner: &mut store,
            counts: &mut counts,
        };
        counted.insert(records[0]).unwrap();
        counted.insert(records[1]).unwrap();
        counted.insert(records[1]).unwrap();
        counted.insert(records[2]).unwrap();
    }
    assert_eq!(
        counts,
        Publications {
            merges: 2,
            derives: 1
        }
    );
    assert_eq!(store.snapshot().unwrap().records().unwrap().count(), 3);
}

#[test]
fn failed_insert_does_not_count_or_erase_a_prior_success() {
    struct Sink {
        calls: usize,
    }
    impl CollectionStore for Sink {
        type InsertError = std::io::Error;
        fn insert(&mut self, _: CollectionRecord) -> std::io::Result<()> {
            self.calls += 1;
            if self.calls == 2 {
                Err(std::io::Error::other("controlled rejection"))
            } else {
                Ok(())
            }
        }
    }
    let records = equations();
    let mut store = Sink { calls: 0 };
    let mut counts = Publications::default();
    let mut counted = CountedStore {
        inner: &mut store,
        counts: &mut counts,
    };
    counted.insert(records[1]).unwrap();
    assert!(counted.insert(records[2]).is_err());
    assert_eq!(
        counts,
        Publications {
            merges: 1,
            derives: 0
        }
    );
}

#[tokio::test]
async fn counter_preserves_snapshot_acquisition_and_proof_seams() {
    let mut fixture = Fixture::new();
    let proof = grant_collection_read(
        &mut fixture.store,
        fixture.source.handle(),
        &fixture.signer,
        SigningKey::from_bytes(&[75; 32]).verifying_key(),
    )
    .unwrap();
    let before = fixture.store.snapshot().unwrap();
    let blob: Blob<UTF8String> = "payload".to_blob();
    let expected = blob.bytes.clone();
    let mut counts = Publications::default();
    {
        let mut counted = CountedStore {
            inner: &mut fixture.store,
            counts: &mut counts,
        };
        let same_type: triblespace_core::repo::memoryrepo::MemoryRepoSnapshot =
            counted.snapshot().unwrap();
        assert!(same_type == before);
        let handle: Inline<Handle<UTF8String>> = counted.put(blob).unwrap();
        let acquired = counted.acquire(handle.transmute()).await.unwrap().unwrap();
        assert_eq!(acquired.as_ref(), expected.as_ref());
        // Proof insertion is delegated; it cannot become a maintenance output.
        let proof = same_type.proof(proof.id()).unwrap().unwrap();
        counted.insert_proof(proof).unwrap();
    }
    assert_eq!(counts, Publications::default());
}

#[test]
fn options_are_opt_in_and_require_valid_explicit_scope() {
    assert!(Options::default().config().unwrap().is_none());
    let fixture = Fixture::new();
    let valid = fixture.options();
    for invalid in [
        Options {
            telemetry_node: None,
            ..valid.clone()
        },
        Options {
            telemetry_worker: None,
            ..valid.clone()
        },
        Options {
            telemetry_worker: Some("x".repeat(33)),
            ..valid.clone()
        },
        Options {
            telemetry_worker: Some("nul\0label".into()),
            ..valid.clone()
        },
        Options {
            telemetry_node: Some("not an endpoint".into()),
            ..valid.clone()
        },
        Options {
            telemetry_interval_secs: Some(0),
            ..valid.clone()
        },
        Options {
            telemetry_collection: None,
            ..valid.clone()
        },
    ] {
        assert!(matches!(invalid.config(), Err(Failure::Parameters)));
    }
    assert_eq!(
        valid.config().unwrap().unwrap().interval,
        Duration::from_secs(60)
    );
}

#[test]
fn telemetry_preflight_does_not_create_authority_or_accept_the_wrong_writer() {
    let mut fixture = Fixture::new();
    let before = fixture.store.snapshot().unwrap();
    let config = fixture.options().config().unwrap().unwrap();
    let wrong = SigningKey::from_bytes(&[76; 32]);
    assert!(matches!(
        Telemetry::open(&mut fixture.store, config, &wrong),
        Err(Failure::Authority)
    ));
    assert!(fixture.store.snapshot().unwrap() == before);
    let directory = tempfile::tempdir().unwrap();
    let missing_key = directory.path().join("missing.key");
    let config = Options {
        telemetry_key: Some(missing_key.clone()),
        ..fixture.options()
    }
    .config()
    .unwrap()
    .unwrap();
    assert!(matches!(
        Telemetry::open(&mut fixture.store, config, &fixture.signer),
        Err(Failure::Key)
    ));
    assert!(!missing_key.exists());
    assert!(fixture.store.snapshot().unwrap() == before);
}

#[test]
fn telemetry_rejects_derived_simple_archive_even_when_writer_is_admitted() {
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::collection::{
        collection_mapping, collection_representation, collection_source, mapping_algorithm,
        KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING,
    };
    use triblespace_core::metadata::MetaDescribe;

    let mut fixture = Fixture::new();
    let algorithm = genid();
    let mapping = entity! { metadata::tag: KIND_COLLECTION_MAPPING, mapping_algorithm: &algorithm };
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(fixture.signer.verifying_key()),
        AdmissionPolicy::direct(fixture.signer.verifying_key()),
    );
    let derived: Collection<SimpleArchive> = fixture
        .store
        .register_collection(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: fixture.source.handle(),
            resource_policy*: policy.fragment(),
            collection_representation*: SimpleArchive::describe(),
            collection_mapping*: mapping,
        })
        .unwrap();
    let before = fixture.store.snapshot().unwrap();
    assert!(Collection::<SimpleArchive>::open(&before, derived.handle()).is_ok());
    assert!(derived
        .writer_is_admitted(&before, fixture.signer.verifying_key())
        .unwrap());
    let config = Options {
        telemetry_collection: Some(hex::encode(derived.handle().raw)),
        ..fixture.options()
    }
    .config()
    .unwrap()
    .unwrap();
    assert!(matches!(
        Telemetry::open(&mut fixture.store, config, &fixture.signer),
        Err(Failure::DerivedDestination)
    ));
    assert!(fixture.store.snapshot().unwrap() == before);
    // Control: the allowed append would be invisible through this derived
    // collection, unlike the ordinary source destination used by our fixture.
    fixture
        .store
        .commit(
            derived,
            &fixture.signer,
            entity! { metadata::name: "invisible" },
        )
        .unwrap();
    assert!(fixture
        .store
        .snapshot()
        .unwrap()
        .collection(derived)
        .unwrap()
        .view::<TribleSet>()
        .unwrap()
        .is_empty());
    fixture.telemetry().emit_due(&mut fixture.store);
    assert_eq!(fixture.reports().len(), 4);
}

#[test]
fn process_cpu_is_not_duplicated_into_stage_samples_and_unknowns_stay_absent() {
    let mut fixture = Fixture::new();
    let mut producer = fixture.telemetry();
    producer.emit_due(&mut fixture.store);
    let reports = fixture.reports();
    assert_eq!(reports.len(), 4);
    let cpu = |report: &telemetry::WorkerReport| {
        report
            .metrics
            .iter()
            .find(|metric| metric.metric == telemetry::Metric::CpuNs)
            .unwrap()
            .value
            .clone()
    };
    let process = reports
        .iter()
        .find(|report| report.role == "process")
        .unwrap();
    assert!(process.stages.is_empty());
    for stage in reports.iter().filter(|report| report.role == "maintenance") {
        assert_eq!(cpu(stage), triblespace_net::dashboard::CountMetric::Absent);
        for metric in [
            telemetry::Metric::PendingMerges,
            telemetry::Metric::PendingDerives,
            telemetry::Metric::Queued,
            telemetry::Metric::ReceivedBytes,
        ] {
            assert_eq!(
                stage
                    .metrics
                    .iter()
                    .find(|entry| entry.metric == metric)
                    .unwrap()
                    .value,
                triblespace_net::dashboard::CountMetric::Absent
            );
        }
        assert!(stage.backends.is_empty());
    }
}

#[test]
fn restart_reuses_opaque_scope_ids_but_never_cross_subtracts_sessions() {
    let mut fixture = Fixture::new();
    let mut first = fixture.telemetry();
    first.publications.merges = 17;
    first.emit_due(&mut fixture.store);
    let mut next = fixture.telemetry();
    assert_eq!(first.process, next.process);
    assert_eq!(first.hop, next.hop);
    assert_eq!(first.pass, next.pass);
    assert_eq!(first.no_publication_pass, next.no_publication_pass);
    assert_ne!(first.session, next.session);
    next.emit_due(&mut fixture.store);
    let reports = fixture.reports();
    assert_eq!(
        reports.len(),
        4,
        "a restart must not leave four stale workers"
    );
    assert!(reports.iter().all(|report| {
        report
            .metrics
            .iter()
            .all(|metric| metric.per_second.is_none())
    }));
}

#[test]
fn no_publication_pass_requires_success_but_not_zero_computation() {
    let mut fixture = Fixture::new();
    let mut producer = fixture.telemetry();
    let started = producer.begin_pass();
    producer.finish_pass(started, true);
    assert_eq!(producer.no_publication_passes, 1);
    let started = producer.begin_pass();
    producer.publications.merges += 1;
    producer.finish_pass(started, false);
    assert_eq!(producer.publications.merges, 1);
    assert_eq!(producer.no_publication_passes, 1);
    assert_eq!(producer.passes.failed, 1);
    let started = producer.begin_pass();
    producer.finish_pass(started, false);
    assert_eq!(producer.no_publication_passes, 1);
}

#[test]
fn cadence_throttles_successes_and_errors_across_many_boundaries() {
    let mut fixture = Fixture::new();
    let mut producer = fixture.telemetry();
    producer.emit_due(&mut fixture.store);
    let after = fixture.store.snapshot().unwrap();
    for _ in 0..100 {
        producer.emit_due(&mut fixture.store);
    }
    assert!(fixture.store.snapshot().unwrap() == after);
    let mut empty = MemoryRepo::default();
    producer.last_attempt = None;
    producer.emit_due(&mut empty); // No descriptor; error is finite and nonfatal.
    let attempt = producer.last_attempt;
    producer.emit_due(&mut fixture.store); // Must not immediately retry elsewhere.
    assert_eq!(producer.last_attempt, attempt);
    assert!(fixture.store.snapshot().unwrap() == after);
    producer.finish(&mut fixture.store);
    assert!(!producer.running && !producer.hops.active && !producer.passes.active);
}

#[tokio::test]
async fn disjoint_telemetry_does_not_wake_exact_handle_maintenance_interests() {
    // Real Pile supports exact read-set invalidation. MemoryRepo deliberately
    // has conservative changes_for and cannot prove this scheduler property.
    let (_directory, mut fixture) = pile_fixture();
    let references = vec![hex::encode(fixture.target.handle().raw)];
    let mut state = MaintenanceState::default();
    for _ in 0..2 {
        assert_eq!(
            maintenance_pass(
                &mut fixture.store,
                &references,
                &fixture.signer,
                true,
                SuccinctBackend::Cpu,
                &mut state
            )
            .await
            .unwrap(),
            0
        );
    }
    let baseline = fixture.store.snapshot().unwrap();
    let interests = state.interests();
    assert!(!interests.all_records);
    let mut producer = fixture.telemetry();
    producer.emit_due(&mut fixture.store);
    let after = fixture.store.snapshot().unwrap();
    assert!(!after.changes_since(&baseline).is_empty());
    assert!(!maintenance_changed(&baseline, &after, &interests));
    assert_eq!(
        producer.publications,
        Publications::default(),
        "external and telemetry records are not local counted maintenance"
    );
    fixture.store.close().unwrap();
}

#[tokio::test]
async fn name_selection_wakes_once_per_emission_without_observer_feedback() {
    let (_directory, mut fixture) = pile_fixture();
    let references = vec!["observed source".into()];
    let mut state = MaintenanceState::default();
    assert_eq!(
        maintenance_pass(
            &mut fixture.store,
            &references,
            &fixture.signer,
            false,
            SuccinctBackend::Cpu,
            &mut state
        )
        .await
        .unwrap(),
        0
    );
    let baseline = fixture.store.snapshot().unwrap();
    let interests = state.interests();
    assert!(interests.all_records);
    let mut producer = fixture.telemetry();
    producer.emit_due(&mut fixture.store);
    let after = fixture.store.snapshot().unwrap();
    assert!(maintenance_changed(&baseline, &after, &interests));
    assert_eq!(
        maintenance_pass_observed(
            &mut fixture.store,
            &references,
            &fixture.signer,
            false,
            SuccinctBackend::Cpu,
            &mut state,
            Some(&mut producer)
        )
        .await
        .unwrap(),
        0
    );
    let settled = fixture.store.snapshot().unwrap();
    assert!(!maintenance_changed(&after, &settled, &state.interests()));
    assert_eq!(producer.no_publication_passes, 1);
    assert_eq!(producer.publications, Publications::default());
    fixture.store.close().unwrap();
}

#[tokio::test]
async fn real_pass_counts_publications_then_successful_settled_no_publication_pass() {
    let mut fixture = Fixture::new();
    let references = vec![hex::encode(fixture.target.handle().raw)];
    let mut state = MaintenanceState::default();
    let mut producer = fixture.telemetry();
    assert_eq!(
        maintenance_pass_observed(
            &mut fixture.store,
            &references,
            &fixture.signer,
            true,
            SuccinctBackend::Cpu,
            &mut state,
            Some(&mut producer)
        )
        .await
        .unwrap(),
        0
    );
    assert!(producer.publications.derives > 0);
    let published = producer.publications;
    assert_eq!(
        maintenance_pass_observed(
            &mut fixture.store,
            &references,
            &fixture.signer,
            true,
            SuccinctBackend::Cpu,
            &mut state,
            Some(&mut producer)
        )
        .await
        .unwrap(),
        0
    );
    assert_eq!(producer.publications, published);
    assert_eq!(producer.no_publication_passes, 1);
    assert!(!producer.hops.active && !producer.passes.active);
}
