//! Optional aggregate publication at the existing sync-loop boundary.
//! No inventory, acquisition, new subscription or implicit flush lives here.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::collection::{descriptor, Collection, CollectionStoreExt};
use triblespace_core::metadata;
use triblespace_core::prelude::*;
use triblespace_core::repo::pile::Pile;
use triblespace_net::health::{HealthSnapshot, LinkHealth};
use triblespace_net::transport::LinkPath;
use triblespace_net::health_record as h;
use triblespace_net::reconcile::ReconcileStats;
use triblespace_net::telemetry as t;

#[derive(clap::Args)]
pub(crate) struct Options {
    /// Existing source collection receiving signed aggregate work samples.
    /// Does not create a descriptor or activate collection replication.
    #[arg(long, value_name = "HANDLE", requires = "telemetry_key")]
    telemetry_collection: Option<String>,
    /// Existing reporting key, independently admitted by the destination WRITE policy.
    #[arg(long, value_name = "PATH", requires = "telemetry_collection")]
    telemetry_key: Option<PathBuf>,
    /// Distinguish simultaneous workers on the same endpoint (at most 32 UTF-8 bytes).
    #[arg(long, value_name = "NAME", default_value = "sync")]
    telemetry_worker: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt};
    use triblespace_net::dashboard::CountMetric;

    fn fixture() -> (
        tempfile::TempDir,
        Pile,
        Collection<blobencodings::SimpleArchive>,
        PathBuf,
        SigningKey,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("telemetry.pile");
        std::fs::File::create(&path).unwrap();
        let key_path = directory.path().join("reporting.key");
        let signer = triblespace_core::signing_key_file::init(&key_path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let collection = pile
            .collection(
                "test telemetry",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(signer.verifying_key()),
                ),
            )
            .unwrap();
        (directory, pile, collection, key_path, signer)
    }

    fn options(collection: Collection<blobencodings::SimpleArchive>, key: PathBuf) -> Options {
        Options {
            telemetry_collection: Some(hex::encode(collection.handle().raw)),
            telemetry_key: Some(key),
            telemetry_worker: "test-sync".to_owned(),
        }
    }

    fn health(node: VerifyingKey) -> HealthSnapshot {
        HealthSnapshot {
            node: iroh_base::EndpointId::from_bytes(node.as_bytes()).unwrap(),
            direction: None,
            started_at: None,
            observed_at: None,
            store: Default::default(),
            collections: Vec::new(),
            publication: Default::default(),
            blob_serving: Default::default(),
            links: Vec::new(),
        }
    }

    #[test]
    fn telemetry_is_opt_in_and_requires_both_destination_and_writer() {
        let handle = hex::encode([0xAC; 32]);
        let args = ["net", "sync", "test.pile", "--collection", handle.as_str()];
        let super::super::Command::Sync { telemetry, .. } =
            super::super::Command::try_parse_from(args).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(telemetry.telemetry_collection.is_none());
        assert!(telemetry.telemetry_key.is_none());
        assert_eq!(telemetry.telemetry_worker, "sync");
        for incomplete in [
            ["--telemetry-collection", handle.as_str()],
            ["--telemetry-key", "writer.key"],
        ] {
            assert!(
                super::super::Command::try_parse_from(args.into_iter().chain(incomplete)).is_err()
            );
        }
        assert!(
            super::super::Command::try_parse_from(args.into_iter().chain([
                "--telemetry-collection",
                handle.as_str(),
                "--telemetry-key",
                "writer.key",
                "--telemetry-worker",
                "custody",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn fresh_link_observations_are_published_as_transport_metrics() {
        let (_directory, mut pile, collection, key_path, signer) = fixture();
        let mut publisher = Publisher::open(
            &mut pile,
            signer.verifying_key(),
            options(collection, key_path),
        )
        .unwrap()
        .unwrap();
        let peer = ed25519_dalek::SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes();
        let mut health = health(signer.verifying_key());
        health.links.push(LinkHealth {
            peer,
            path: LinkPath::Direct,
            observed_at: triblespace_core::clock::mono_now(),
            rtt_ns: Some(1_000),
            sent_bytes: Some(2_000),
            received_bytes: Some(3_000),
        });
        let at = triblespace_core::clock::epoch_now();
        let facts = publisher
            .sample(&health, at, Duration::from_secs(1), None)
            .unwrap();
        let report = t::observe(
            facts.facts(),
            at.to_tai_duration().total_nanoseconds(),
            Duration::from_secs(180),
        )
        .into_iter()
        .find(|report| report.role == "link")
        .expect("fresh link report");
        assert_eq!(report.peers, vec![peer]);
        assert_eq!(report.paths, vec!["direct"]);
        assert_eq!(
            report
                .metrics
                .iter()
                .find(|metric| metric.metric == t::Metric::RttNs)
                .unwrap()
                .value,
            triblespace_net::dashboard::CountMetric::Value(1_000)
        );
        assert_eq!(
            report
                .metrics
                .iter()
                .find(|metric| metric.metric == t::Metric::TransportSentBytes)
                .unwrap()
                .value,
            triblespace_net::dashboard::CountMetric::Value(2_000)
        );
        assert_eq!(
            report
                .metrics
                .iter()
                .find(|metric| metric.metric == t::Metric::TransportReceivedBytes)
                .unwrap()
                .value,
            triblespace_net::dashboard::CountMetric::Value(3_000)
        );
        pile.close().unwrap();
    }

    #[test]
    fn opening_disabled_or_rejected_reporting_never_appends_or_creates_authority() {
        let (directory, pile, collection, key_path, signer) = fixture();
        pile.close().unwrap();
        let path = directory.path().join("telemetry.pile");
        let before = std::fs::read(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        assert!(Publisher::open(
            &mut pile,
            signer.verifying_key(),
            Options {
                telemetry_collection: None,
                telemetry_key: None,
                telemetry_worker: "sync".into(),
            }
        )
        .unwrap()
        .is_none());
        let absent_key = directory.path().join("private-reporting-key-is-absent");
        let error = Publisher::open(
            &mut pile,
            signer.verifying_key(),
            options(collection, absent_key.clone()),
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "telemetry reporting key is unavailable");
        assert!(!absent_key.exists());
        let other_path = directory.path().join("not-admitted.key");
        triblespace_core::signing_key_file::init(&other_path).unwrap();
        let error = Publisher::open(
            &mut pile,
            signer.verifying_key(),
            options(collection, other_path),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "telemetry reporting key is not admitted by the destination"
        );
        let missing = Blob::<blobencodings::UnknownBlob>::new(anybytes::Bytes::from(
            b"unpublished telemetry descriptor".to_vec(),
        ))
        .get_handle();
        let mut unknown = options(collection, key_path);
        unknown.telemetry_collection = Some(hex::encode(missing.raw));
        let error = Publisher::open(&mut pile, signer.verifying_key(), unknown)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "telemetry destination is not a readable source collection"
        );
        assert!(!format!("{error:#}").contains(&hex::encode_upper(missing.raw)));
        pile.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn reporting_commits_only_to_the_selected_existing_collection() {
        let (_directory, mut pile, collection, key_path, signer) = fixture();
        let other: Collection<blobencodings::SimpleArchive> = pile
            .collection(
                "unselected",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let before = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let node = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let publisher = Publisher::open(&mut pile, node, options(collection, key_path))
            .unwrap()
            .unwrap();
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            before
        );
        let previous = pile.snapshot().unwrap();
        let other_observation = triblespace_core::repo::ObservedStore::new(previous.clone());
        assert!(other_observation
            .collection(other)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .is_empty());
        let unrelated_interests = other_observation.dependencies();
        assert!(!unrelated_interests.all_records && !unrelated_interests.all_blobs);
        let own_observation = triblespace_core::repo::ObservedStore::new(previous.clone());
        assert!(own_observation
            .collection(collection)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .is_empty());
        publisher.publish(&mut pile, &health(node)).unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert!(!snapshot.changes_since(&previous).is_empty());
        assert!(
            snapshot
                .changes_for(&previous, &unrelated_interests)
                .is_empty(),
            "telemetry does not invalidate a disjoint exact collection read"
        );
        assert!(
            !snapshot
                .changes_for(&previous, &own_observation.dependencies())
                .is_empty(),
            "the destination's real change is not hidden behind a moved baseline"
        );
        assert!(snapshot
            .collection(other)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .is_empty());
        let facts = snapshot
            .collection(collection)
            .unwrap()
            .view::<TribleSet>()
            .unwrap();
        let now = triblespace_core::clock::epoch_now()
            .to_tai_duration()
            .total_nanoseconds();
        let reports = t::observe(&facts, now, Duration::from_secs(180));
        assert_eq!(reports.len(), 5);
        assert!(reports
            .iter()
            .all(|report| report.node == node.to_bytes() && report.worker == "test-sync"));
        assert!(collection
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .unwrap());
        assert!(!collection.writer_is_admitted(&snapshot, node).unwrap());
        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn reporting_rejects_derived_simple_archives_whose_commits_are_not_visible() {
        use triblespace_core::capability::policy::resource_policy;
        use triblespace_core::collection::{
            collection_mapping, collection_representation, collection_source, mapping_algorithm,
            KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING,
        };
        use triblespace_core::metadata::MetaDescribe;

        let (_directory, mut pile, source, key_path, signer) = fixture();
        let algorithm = ufoid();
        let mapping =
            entity! { metadata::tag: KIND_COLLECTION_MAPPING, mapping_algorithm: &algorithm };
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(signer.verifying_key()),
            AdmissionPolicy::Open,
        );
        let derived: Collection<blobencodings::SimpleArchive> = pile
            .register_collection(entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_source: source.handle(),
                resource_policy*: policy.fragment(),
                collection_representation*: blobencodings::SimpleArchive::describe(),
                collection_mapping*: mapping,
            })
            .unwrap();
        let snapshot = pile.snapshot().unwrap();
        assert!(
            Collection::<blobencodings::SimpleArchive>::open(&snapshot, derived.handle()).is_ok()
        );
        assert!(derived
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .unwrap());
        let before = snapshot.records().unwrap().count();
        let error = Publisher::open(
            &mut pile,
            signer.verifying_key(),
            options(derived, key_path),
        )
        .err()
        .unwrap();
        assert_eq!(
            error.to_string(),
            "telemetry destination must be a source collection"
        );
        assert_eq!(pile.snapshot().unwrap().records().unwrap().count(), before);
        // Positive control: ordinary commit succeeds here, but the derived
        // collection's passive observation cannot consume a root COMMIT.
        pile.commit(
            derived,
            &signer,
            entity! { metadata::description: "invisible root commit" },
        )
        .unwrap();
        assert!(pile
            .snapshot()
            .unwrap()
            .collection(derived)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .is_empty());
        pile.close().unwrap();
    }

    #[test]
    fn samples_keep_unknowns_sessions_and_successful_landing_counters_distinct() {
        let (_directory, mut pile, collection, key_path, signer) = fixture();
        let mut publisher = Publisher::open(
            &mut pile,
            signer.verifying_key(),
            options(collection, key_path),
        )
        .unwrap()
        .unwrap();
        let mut health = health(signer.verifying_key());
        let now = triblespace_core::clock::epoch_now();
        let first = publisher
            .sample(&health, now, Duration::from_secs(1), None)
            .unwrap();
        let before = t::observe(
            first.facts(),
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
        assert!(before.iter().all(|report| report
            .metrics
            .iter()
            .find(|value| value.metric == t::Metric::CpuNs)
            .unwrap()
            .value
            == CountMetric::Absent));

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
        assert!(t::observe(
            joined.facts(),
            restarted.to_tai_duration().total_nanoseconds(),
            Duration::from_secs(180)
        )
        .iter()
        .all(|report| report
            .metrics
            .iter()
            .all(|value| value.per_second.is_none())));
        pile.close().unwrap();
    }
}

pub(super) struct Publisher {
    collection: Collection<blobencodings::SimpleArchive>,
    signer: SigningKey,
    session: ExclusiveId,
    node: VerifyingKey,
    worker: Inline<inlineencodings::ShortString>,
    started: Instant,
    subjects: [Fragment; 5],
    landed: u128,
    received_bytes: u128,
    reconcile_work_ns: u128,
    pending_blobs: Option<u64>,
}

impl Publisher {
    pub(super) fn open(
        pile: &mut Pile,
        node: VerifyingKey,
        options: Options,
    ) -> Result<Option<Self>> {
        let Some(handle) = options.telemetry_collection else {
            return Ok(None);
        };
        let path = options
            .telemetry_key
            .ok_or_else(|| anyhow!("telemetry requires an explicit reporting key"))?;
        let signer = triblespace_core::signing_key_file::load_existing(&path)
            .map_err(|_| anyhow!("telemetry reporting key is unavailable"))?;
        let handle = super::parse_collection(&handle)
            .map_err(|_| anyhow!("telemetry destination is not a collection handle"))?;
        let worker: Inline<inlineencodings::ShortString> = options
            .telemetry_worker
            .as_str()
            .try_to_inline()
            .map_err(|_| anyhow!("telemetry worker label is too long"))?;
        if options.telemetry_worker.is_empty()
            || options.telemetry_worker.chars().any(char::is_control)
        {
            return Err(anyhow!(
                "telemetry worker label must be nonempty printable text"
            ));
        }
        // Opening and checking the selected destination is a read. There is
        // deliberately no collection(), derive(), grant or maintain fallback.
        let snapshot = pile
            .snapshot()
            .map_err(|_| anyhow!("telemetry destination observation failed"))?;
        let collection = Collection::<blobencodings::SimpleArchive>::open(&snapshot, handle)
            .map_err(|_| anyhow!("telemetry destination is not a readable source collection"))?;
        let facts: TribleSet = snapshot
            .get(handle)
            .map_err(|_| anyhow!("telemetry destination descriptor is unavailable"))?;
        if descriptor::source(&facts)
            .map_err(|_| anyhow!("telemetry destination lineage is not readable"))?
            .is_some()
        {
            return Err(anyhow!("telemetry destination must be a source collection"));
        }
        if !collection
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .map_err(|_| anyhow!("telemetry writer admission could not be observed"))?
        {
            return Err(anyhow!(
                "telemetry reporting key is not admitted by the destination"
            ));
        }
        Ok(Some(Self {
            collection,
            signer,
            session: ufoid(),
            node: node.clone(),
            worker: worker.clone(),
            started: Instant::now(),
            subjects: ["hydration", "serve", "repair", "publication", "process"].map(|role| {
                entity! {
                    h::attrs::endpoint: node.clone(),
                    t::attrs::worker: worker.clone(),
                    t::attrs::role: role,
                }
            }),
            landed: 0,
            received_bytes: 0,
            reconcile_work_ns: 0,
            pending_blobs: None,
        }))
    }

    pub(super) fn reconciled(&mut self, stats: &ReconcileStats, elapsed: Duration) {
        self.landed += stats.landed as u128;
        self.received_bytes += u128::from(stats.received_bytes);
        self.reconcile_work_ns += elapsed.as_nanos();
        self.pending_blobs = stats.pending_blobs.map(|count| count as u64);
    }

    fn sample(
        &self,
        health: &HealthSnapshot,
        now: hifitime::Epoch,
        elapsed: Duration,
        cpu_ns: Option<u128>,
    ) -> Result<Fragment> {
        let created: Inline<inlineencodings::NsTAIInterval> = (now, now)
            .try_to_inline()
            .map_err(|_| anyhow!("telemetry sample timestamp cannot be encoded"))?;
        let elapsed_ns = elapsed.as_nanos();
        let live = health.is_fresh(triblespace_core::clock::mono_now(), h::HOST_MAX_AGE);
        let serving = &health.blob_serving;
        let publication = &health.publication;
        let repair_active = health
            .collections
            .iter()
            .flat_map(|collection| &collection.peers)
            .filter(|peer| peer.in_flight)
            .count() as u64;
        let mut facts = entity! {
            metadata::tag: &t::KIND_SAMPLE,
            t::attrs::subject*: self.subjects[0].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            t::attrs::elapsed_ns: elapsed_ns,
            t::attrs::completed: self.landed,
            t::attrs::received_bytes: self.received_bytes,
            t::attrs::work_ns: self.reconcile_work_ns,
            t::attrs::queued?: self.pending_blobs,
        };
        // No hydration active/failed estimate: sampling does not run inside an
        // awaited tick, and an unavailable speculative word is not a known
        // failed blob. Capacity and attempts are not those measurements.
        facts += entity! {
            metadata::tag: &t::KIND_SAMPLE,
            t::attrs::subject*: self.subjects[1].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            t::attrs::elapsed_ns: elapsed_ns,
            t::attrs::active?: live.then_some(serving.in_flight),
            t::attrs::completed?: live.then_some(serving.completed),
            t::attrs::failed?: live.then_some(serving.failed),
            t::attrs::sent_bytes?: live.then_some(serving.sent_bytes),
            t::attrs::work_ns?: live.then_some(serving.work_ns),
        };
        facts += entity! {
            metadata::tag: &t::KIND_SAMPLE,
            t::attrs::subject*: self.subjects[2].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            t::attrs::elapsed_ns: elapsed_ns,
            t::attrs::active?: live.then_some(repair_active),
        };
        facts += entity! {
            metadata::tag: &t::KIND_SAMPLE,
            t::attrs::subject*: self.subjects[3].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            t::attrs::elapsed_ns: elapsed_ns,
            t::attrs::active?: live.then_some(publication.in_flight as u64),
            t::attrs::completed?: live.then_some(publication.acknowledged),
            t::attrs::failed?: live.then_some(publication.rejected.saturating_add(publication.unavailable)),
        };
        facts += entity! {
            metadata::tag: &t::KIND_SAMPLE,
            t::attrs::subject*: self.subjects[4].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            t::attrs::elapsed_ns: elapsed_ns,
            t::attrs::cpu_ns?: cpu_ns,
            t::attrs::parallel_compiled: triblespace_core::PARALLEL_COMPILED,
        };
        // Link subjects are emitted only from fresh adapter observations.
        // A missing/aged observation remains absent; it is never converted
        // into a zero-byte or zero-RTT claim.  Transport counters include
        // protocol overhead and therefore use their own attributes.
        let observed_at = triblespace_core::clock::mono_now();
        for link in &health.links {
            if observed_at < link.observed_at
                || observed_at.duration_since(link.observed_at) > h::HOST_MAX_AGE
            {
                continue;
            }
            let Ok(peer) = VerifyingKey::from_bytes(&link.peer) else {
                continue;
            };
            let subject = entity! {
                h::attrs::endpoint: self.node.clone(),
                t::attrs::worker: self.worker.clone(),
                t::attrs::role: "link",
                h::attrs::peer: peer,
            };
            facts += entity! {
                metadata::tag: &t::KIND_SAMPLE,
                t::attrs::subject*: subject,
                h::attrs::session: &self.session,
                metadata::created_at: created,
                t::attrs::elapsed_ns: elapsed_ns,
                t::attrs::path: link.path.label(),
                t::attrs::rtt_ns?: link.rtt_ns,
                t::attrs::transport_sent_bytes?: link.sent_bytes,
                t::attrs::transport_received_bytes?: link.received_bytes,
            };
        }
        Ok(facts)
    }

    pub(super) fn publish(&self, pile: &mut Pile, health: &HealthSnapshot) -> Result<()> {
        let facts = self.sample(
            health,
            triblespace_core::clock::epoch_now(),
            self.started.elapsed(),
            crate::cli::util::process_cpu_ns(),
        )?;
        // Discard backend cause chains at this reporting boundary. An error
        // may include a read capability or a private path, never telemetry.
        pile.commit(self.collection, &self.signer, facts)
            .map_err(|_| anyhow!("telemetry append failed"))?;
        Ok(())
    }
}
