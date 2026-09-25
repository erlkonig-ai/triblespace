use assert_cmd::Command;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::locator::blob_locator;
use triblespace_core::blob::IntoBlob;
use triblespace_core::collection::reference_summary::{
    ReferenceSummaryBlob, ReferenceSummaryLayout, ReferenceSummaryView,
};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionRead, CollectionSnapshotExt,
    CollectionStoreExt,
};
use triblespace_core::inline::Inline;
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;

#[test]
fn reference_summary_cli_registers_maintains_and_reuses_ordinary_derived_records() {
    for arguments in [vec![], vec!["--log2-bits", "18", "--probes", "3"]] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("producer.pile");
        let key = directory.path().join("producer.key");
        std::fs::File::create(&path).unwrap();
        let signer = triblespace_core::signing_key_file::init(&key).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let source = pile
            .collection(
                "attachments",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(signer.verifying_key()),
                    AdmissionPolicy::direct(signer.verifying_key()),
                ),
            )
            .unwrap();
        let text = "attachment stored by the producer before its COMMIT";
        let attachment = IntoBlob::<UTF8String>::to_blob(text).get_handle();
        let commit = pile
            .commit(source, &signer, entity! { metadata::description: text })
            .unwrap();
        pile.close().unwrap();

        let derive = || {
            let output = Command::cargo_bin("trible")
                .unwrap()
                .args(["pile", "collection", "derive"])
                .arg(&path)
                .args(["attachments", "reference-summary", "--key"])
                .arg(&key)
                .args(&arguments)
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            String::from_utf8(output).unwrap().trim().to_owned()
        };
        let handle = derive();
        assert_eq!(derive(), handle, "descriptor registration is idempotent");
        let raw: [u8; 32] = hex::decode(handle.strip_prefix("blake3:").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut first_records = None;
        for _ in 0..2 {
            Command::cargo_bin("trible")
                .unwrap()
                .args(["pile", "collection", "maintain"])
                .arg(&path)
                .arg(&handle)
                .arg("--key")
                .arg(&key)
                .assert()
                .success();
            let mut pile = Pile::open(&path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            let target =
                Collection::<ReferenceSummaryBlob>::open(&snapshot, Inline::new(raw)).unwrap();
            let observed = snapshot.collection(target).unwrap();
            // The view stands on its one leaf, and the leaf is the commit's:
            // freshness against the source finds nothing missing.
            assert_eq!(observed.support().unwrap().len(), 1);
            let source_snapshot = snapshot.collection(source).unwrap();
            assert!(source_snapshot
                .support()
                .unwrap()
                .contains(Inline::new(commit.data().raw)));
            assert!(observed.missing_from(&source_snapshot).unwrap().is_empty());
            let view = observed.view::<ReferenceSummaryView>().unwrap();
            assert_eq!(
                view.layout(),
                if arguments.is_empty() {
                    ReferenceSummaryLayout::default()
                } else {
                    ReferenceSummaryLayout::new(18, 3).unwrap()
                }
            );
            assert!(view
                .query()
                .unwrap()
                .contains_locator(blob_locator(attachment.raw)));
            let records = snapshot
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>();
            assert!(records.iter().any(|record| matches!(
                record,
                triblespace_core::collection::CollectionRecord::Derive(_)
            )));
            for record in &records {
                record.verify_strict().unwrap();
                assert_eq!(record.public_key().raw, signer.verifying_key().to_bytes());
            }
            if let Some(previous) = &first_records {
                assert_eq!(&records, previous, "warm maintenance adds no new equations");
            } else {
                first_records = Some(records);
            }
            drop(source_snapshot);
            drop(observed);
            drop(snapshot);
            pile.close().unwrap();
        }
    }
}
