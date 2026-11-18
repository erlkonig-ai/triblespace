//! A caller outside triblespace-net constructs and drives the sync producer,
//! as the trible CLI's custody and native applications do.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use triblespace_core::collection::covered::Covered;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::prelude::*;
use triblespace_core::repo::SnapshotSource;
use triblespace_core::repo::pile::PileFile;
use triblespace_net::dashboard::CountMetric;
use triblespace_net::health::HealthSnapshot;
use triblespace_net::reconcile::ReconcileStats;
use triblespace_net::telemetry::{self as t, sync};

#[test]
fn an_outside_caller_opens_reconciles_and_publishes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("app.pile");
    std::fs::File::create(&path).unwrap();
    let signer = SigningKey::from_bytes(&[3; 32]);
    let node = signer.verifying_key();
    // Not custody's Repairing wrapper: the producer needs only a Store.
    let mut store = Covered::new(PileFile::open(&path).unwrap());
    let collection = store
        .collection(
            "app telemetry",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::direct(node)),
        )
        .unwrap();

    assert_eq!(
        sync::Publisher::open(&mut store, &signer, collection.handle(), "")
            .err()
            .unwrap(),
        sync::Error::WorkerLabel
    );
    assert_eq!(
        sync::Publisher::open(
            &mut store,
            &SigningKey::from_bytes(&[4; 32]),
            collection.handle(),
            "app-sync"
        )
        .err()
        .unwrap(),
        sync::Error::NotAdmitted
    );

    let mut publisher =
        sync::Publisher::open(&mut store, &signer, collection.handle(), "app-sync").unwrap();
    publisher.reconciled(
        &ReconcileStats {
            landed: 3,
            received_bytes: 96,
            pending_blobs: Some(1),
            ..Default::default()
        },
        Duration::from_millis(7),
    );
    let health = HealthSnapshot {
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
    };
    publisher.publish(&mut store, &health).unwrap();

    let snapshot = store.snapshot().unwrap();
    let facts = snapshot
        .collection(collection)
        .unwrap()
        .view::<TribleSet>()
        .unwrap();
    let now = triblespace_core::clock::epoch_now()
        .to_tai_duration()
        .total_nanoseconds();
    let reports = t::observe(&facts, &snapshot, now, Duration::from_secs(180));
    let mut roles = reports
        .iter()
        .map(|report| report.role.as_str())
        .collect::<Vec<_>>();
    roles.sort_unstable();
    assert_eq!(
        roles,
        ["hydration", "process", "publication", "repair", "serve"]
    );
    assert!(
        reports
            .iter()
            .all(|report| report.node == node.to_bytes() && report.worker == "app-sync")
    );
    let hydration = reports
        .iter()
        .find(|report| report.role == "hydration")
        .unwrap();
    let value = |metric| {
        hydration
            .metrics
            .iter()
            .find(|value| value.metric == metric)
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(value(t::Metric::Completed), CountMetric::Value(3));
    assert_eq!(value(t::Metric::ReceivedBytes), CountMetric::Value(96));
    assert_eq!(value(t::Metric::Queued), CountMetric::Value(1));
    drop(snapshot);
    store.close().unwrap();
}
