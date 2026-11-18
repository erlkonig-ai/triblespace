//! Moved with the producer from the trible CLI's custody wiring, whose
//! flag and destination tests stay there.

use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::collection::covered::Covered;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::prelude::*;
use triblespace_core::repo::pile::PileFile;

use super::Publisher;
use crate::dashboard::CountMetric;
use crate::health::HealthSnapshot;
use crate::peer::Repairing;
use crate::reconcile::ReconcileStats;
use crate::telemetry as t;

/// Custody's store type, opened as `trible pile net sync` opens it.
type Custody = Covered<Repairing<PileFile>>;

fn fixture() -> (
    tempfile::TempDir,
    Custody,
    Collection<blobencodings::SimpleArchive>,
    SigningKey,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("telemetry.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[8; 32]);
    let mut pile = Covered::new(Repairing::new(PileFile::open(&path).unwrap()));
    let collection = pile
        .collection(
            "test telemetry",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(signer.verifying_key()),
            ),
        )
        .unwrap();
    (directory, pile, collection, signer)
}

fn health(node: VerifyingKey) -> HealthSnapshot {
    HealthSnapshot {
        node: iroh_base::EndpointId::from_bytes(node.as_bytes()).unwrap(),
        started_at: None,
        observed_at: None,
        store: Default::default(),
        collections: Vec::new(),
        publication: Default::default(),
        blob_serving: Default::default(),
        peerings: Vec::new(),
        grants: Vec::new(),
        named_unselected: Vec::new(),
    }
}

#[test]
fn samples_keep_unknowns_sessions_and_successful_landing_counters_distinct() {
    let (_directory, mut pile, collection, signer) = fixture();
    let mut publisher =
        Publisher::open(&mut pile, &signer, collection.handle(), "test-sync").unwrap();
    let mut health = health(signer.verifying_key());
    let now = triblespace_core::clock::epoch_now();
    let first = publisher
        .sample(&health, now, Duration::from_secs(1), None)
        .unwrap();
    let before = t::observe(
        first.facts(),
        &triblespace_core::repo::SnapshotSource::snapshot(&mut first.blobs().clone()).unwrap(),
        now.to_tai_duration().total_nanoseconds(),
        Duration::from_secs(180),
    );
    let hydration = before
        .iter()
        .find(|report| report.role == "hydration")
        .unwrap();
    assert_eq!(
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Queued)
            .unwrap()
            .value,
        CountMetric::Absent
    );
    let serve = before.iter().find(|report| report.role == "serve").unwrap();
    assert_eq!(
        serve
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Active)
            .unwrap()
            .value,
        CountMetric::Absent
    );
    assert!(before.iter().all(|report| {
        report
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::CpuNs)
            .unwrap()
            .value
            == CountMetric::Absent
    }));

    publisher.reconciled(
        &ReconcileStats {
            landed: 2,
            received_bytes: 223,
            pending_blobs: Some(0),
            ..Default::default()
        },
        Duration::from_millis(20),
    );
    health.observed_at = Some(triblespace_core::clock::mono_now());
    health.blob_serving.completed = 1;
    health.blob_serving.sent_bytes = 223;
    health.blob_serving.in_flight = 2;
    let later = now + hifitime::Duration::from_seconds(1.0);
    let second = publisher
        .sample(&health, later, Duration::from_secs(2), Some(500_000_000))
        .unwrap();
    let mut joined = first;
    joined += second;
    let reports = t::observe(
        joined.facts(),
        &triblespace_core::repo::SnapshotSource::snapshot(&mut joined.blobs().clone()).unwrap(),
        later.to_tai_duration().total_nanoseconds(),
        Duration::from_secs(180),
    );
    let hydration = reports
        .iter()
        .find(|report| report.role == "hydration")
        .unwrap();
    assert_eq!(
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Queued)
            .unwrap()
            .value,
        CountMetric::Value(0)
    );
    let received = hydration
        .metrics
        .iter()
        .find(|value| value.metric == t::Metric::ReceivedBytes)
        .unwrap();
    assert_eq!(received.value, CountMetric::Value(223));
    assert_eq!(received.per_second, Some(223.0));
    let serve = reports
        .iter()
        .find(|report| report.role == "serve")
        .unwrap();
    assert_eq!(
        serve
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Active)
            .unwrap()
            .value,
        CountMetric::Value(2)
    );
    assert_eq!(
        reports
            .iter()
            .filter(|report| report
                .metrics
                .iter()
                .any(|value| value.metric == t::Metric::CpuNs
                    && value.value == CountMetric::Value(500_000_000)))
            .map(|report| report.role.as_str())
            .collect::<Vec<_>>(),
        ["process"]
    );

    publisher.reconciled(&ReconcileStats::default(), Duration::from_millis(5));
    let failed = publisher
        .sample(&health, later, Duration::from_secs(3), None)
        .unwrap();
    let reports = t::observe(
        failed.facts(),
        &triblespace_core::repo::SnapshotSource::snapshot(&mut failed.blobs().clone()).unwrap(),
        later.to_tai_duration().total_nanoseconds(),
        Duration::from_secs(180),
    );
    let hydration = reports
        .iter()
        .find(|report| report.role == "hydration")
        .unwrap();
    assert_eq!(
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Queued)
            .unwrap()
            .value,
        CountMetric::Absent
    );
    assert_eq!(
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::Completed)
            .unwrap()
            .value,
        CountMetric::Value(2)
    );
    assert_eq!(
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::ReceivedBytes)
            .unwrap()
            .value,
        CountMetric::Value(223)
    );
    publisher.session = ufoid();
    let restarted = later + hifitime::Duration::from_seconds(1.0);
    let fresh_session = publisher
        .sample(&health, restarted, Duration::from_secs(1), None)
        .unwrap();
    let mut joined = joined;
    joined += fresh_session;
    assert!(
        t::observe(
            joined.facts(),
            &triblespace_core::repo::SnapshotSource::snapshot(&mut joined.blobs().clone()).unwrap(),
            restarted.to_tai_duration().total_nanoseconds(),
            Duration::from_secs(180)
        )
        .iter()
        .all(|report| report
            .metrics
            .iter()
            .all(|value| value.per_second.is_none()))
    );
    pile.close().unwrap();
}
