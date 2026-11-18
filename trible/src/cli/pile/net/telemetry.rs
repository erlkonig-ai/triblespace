//! Custody's wiring of the sync producer, [`Publisher`]: the flags and the
//! destination handle. The producer itself lives in
//! `triblespace_net::telemetry::sync`, shared with native applications.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;

use triblespace_net::telemetry::sync::Publisher;

use super::Custody;

#[derive(clap::Args)]
pub(crate) struct Options {
    /// Existing source collection receiving signed aggregate work samples.
    /// Uses the node key; does not create a descriptor or activate replication.
    #[arg(long, value_name = "HANDLE")]
    telemetry_collection: Option<String>,
    /// Distinguish simultaneous workers on the same endpoint.
    #[arg(long, value_name = "NAME", default_value = "sync")]
    telemetry_worker: String,
}

/// Open custody's producer when `--telemetry-collection` is given.
pub(super) fn open(
    pile: &mut Custody,
    signer: &SigningKey,
    options: Options,
) -> Result<Option<Publisher>> {
    let Some(handle) = options.telemetry_collection else {
        return Ok(None);
    };
    let handle = super::parse_collection(&handle)
        .map_err(|_| anyhow!("telemetry destination is not a collection handle"))?;
    Ok(Some(Publisher::open(
        pile,
        signer,
        handle,
        &options.telemetry_worker,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ed25519_dalek::VerifyingKey;
    use std::time::Duration;
    use triblespace_core::collection::{
        AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
    };
    use triblespace_core::metadata;
    use triblespace_core::prelude::*;
    use triblespace_net::health::HealthSnapshot;
    use triblespace_net::telemetry as t;

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
        let mut pile = super::super::open_custody(&path).unwrap();
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

    fn options(collection: Collection<blobencodings::SimpleArchive>) -> Options {
        Options {
            telemetry_collection: Some(hex::encode(collection.handle().raw)),
            telemetry_worker: "test-sync".to_owned(),
        }
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
    fn telemetry_is_opt_in_and_has_no_independent_writer() {
        let handle = hex::encode([0xAC; 32]);
        let args = ["net", "sync", "test.pile"];
        let super::super::Command::Sync { telemetry, .. } =
            super::super::Command::try_parse_from(args).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(telemetry.telemetry_collection.is_none());
        assert_eq!(telemetry.telemetry_worker, "sync");
        assert!(super::super::Command::try_parse_from(
            args.into_iter().chain(["--telemetry-key", "writer.key"])
        )
        .is_err());
        assert!(
            super::super::Command::try_parse_from(args.into_iter().chain([
                "--telemetry-collection",
                handle.as_str(),
                "--telemetry-worker",
                "custody",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn opening_disabled_or_rejected_reporting_never_appends_or_creates_authority() {
        let (directory, pile, collection, signer) = fixture();
        pile.close().unwrap();
        let path = directory.path().join("telemetry.pile");
        let before = std::fs::read(&path).unwrap();
        let mut pile = super::super::open_custody(&path).unwrap();
        assert!(open(
            &mut pile,
            &signer,
            Options {
                telemetry_collection: None,
                telemetry_worker: "sync".into(),
            }
        )
        .unwrap()
        .is_none());
        let other = SigningKey::from_bytes(&[9; 32]);
        let error = open(&mut pile, &other, options(collection)).err().unwrap();
        assert_eq!(
            error.to_string(),
            "telemetry reporting key is not admitted by the destination"
        );
        let missing = Blob::<blobencodings::UnknownBlob>::new(anybytes::Bytes::from(
            b"unpublished telemetry descriptor".to_vec(),
        ))
        .get_handle();
        let mut unknown = options(collection);
        unknown.telemetry_collection = Some(hex::encode(missing.raw));
        let error = open(&mut pile, &signer, unknown).err().unwrap();
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
        let (_directory, mut pile, collection, signer) = fixture();
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
        let node = signer.verifying_key();
        let publisher = open(&mut pile, &signer, options(collection))
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
        let reports = t::observe(&facts, &snapshot, now, Duration::from_secs(180));
        assert_eq!(reports.len(), 5);
        assert!(reports
            .iter()
            .all(|report| report.node == node.to_bytes() && report.worker == "test-sync"));
        assert!(collection
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .unwrap());
        assert!(collection.writer_is_admitted(&snapshot, node).unwrap());
        for record in snapshot.records().unwrap().map(Result::unwrap) {
            if record.collection() == collection.handle() {
                assert_eq!(record.public_key().raw, node.to_bytes());
                record.verify_strict().unwrap();
            }
        }
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

        let (_directory, mut pile, source, signer) = fixture();
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
        let error = open(&mut pile, &signer, options(derived)).err().unwrap();
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
}
