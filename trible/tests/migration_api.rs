//! Native preparation over the released fixture, without CLI argv/stdout.
use std::path::Path;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;
use trible::migration::{
    inspect, legacy_branch_names, prepare, prepare_with_progress, BranchDecision, Outcome,
    Requirement, Stage,
};
use triblespace_core::blob::{
    encodings::{simplearchive::SimpleArchive, UnknownBlob},
    Blob,
};
use triblespace_core::collection::Collection;
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::metadata;
use triblespace_core::repo::pile::{Pile, PileFile, PileRecords};
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_core::trible::TribleSet;

fn legacy(path: &Path) -> Vec<u8> {
    let bytes = include_bytes!("fixtures/legacy_v0464_branch.pile").to_vec();
    std::fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn released_pile_requires_an_explicit_branch_choice_before_any_output() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    let original = legacy(&source);
    let inspection = inspect(&source).unwrap();
    assert!(!inspection.current_framing);
    assert_eq!(inspection.legacy_branches.len(), 1);
    assert_eq!(
        legacy_branch_names(&source)
            .unwrap()
            .values()
            .next()
            .unwrap(),
        "legacy"
    );
    assert_eq!(
        prepare(&source, &destination, &[]).unwrap(),
        Outcome::ChoiceRequired {
            requirements: vec![Requirement::Branch {
                branch: inspection.legacy_branches[0]
            }],
        }
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read(source).unwrap(), original);
}

#[test]
fn native_conversion_retains_source_and_reports_retained_pins_honestly() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    let original = legacy(&source);
    let branch = inspect(&source).unwrap().legacy_branches[0];
    let signer = SigningKey::from_bytes(&[3; 32]);
    let decision = BranchDecision {
        branch,
        collection_name: "events",
        signer: &signer,
        authority: signer.verifying_key(),
    };
    let Outcome::Converted {
        destination: actual,
        branches,
        ..
    } = prepare(&source, &destination, &[decision]).unwrap()
    else {
        panic!("expected a prepared candidate");
    };
    assert_eq!(actual, destination);
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0].branch, branch);
    let mut reader = Pile::with_host(PileFile::open_read_only(&destination).unwrap(), None);
    reader.refresh().unwrap();
    let snapshot = reader.snapshot().unwrap();
    let collection = Collection::<SimpleArchive>::open(&snapshot, branches[0].collection).unwrap();
    let actual: TribleSet = collection.read(&snapshot).unwrap();
    // Frozen fixture A/B/C are exactly these three tag facts. The orphan and
    // repository metadata must not enter the returned collection's content.
    let mut expected = TribleSet::new();
    for byte in [1, 2, 3] {
        let id = Id::new([byte; 16]).unwrap();
        expected += triblespace_core::macros::entity! {
            ExclusiveId::force_ref(&id) @ metadata::tag: metadata::KIND_MULTI,
        }
        .into_facts();
    }
    assert_eq!(actual, expected);
    reader.close().unwrap();
    let mut records = PileRecords::open(&destination).unwrap();
    while let Some(record) = records.next() {
        assert!(records.has_current_framing(&record.unwrap()));
    }
    let candidate = std::fs::read(&destination).unwrap();
    let unused = dir.path().join("unused.pile");
    assert_eq!(
        prepare(&destination, &unused, &[]).unwrap(),
        Outcome::Current {
            legacy_branches: vec![branch],
        }
    );
    assert!(!unused.exists());
    assert_eq!(std::fs::read(&destination).unwrap(), candidate);
    assert_eq!(std::fs::read(&source).unwrap(), original);
}

#[test]
fn existing_inode_aliases_and_dangling_links_never_become_output() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let original = legacy(&source);
    let branch = inspect(&source).unwrap().legacy_branches[0];
    let signer = SigningKey::from_bytes(&[3; 32]);
    let choices = [BranchDecision {
        branch,
        collection_name: "events",
        signer: &signer,
        authority: signer.verifying_key(),
    }];
    let alias = dir.path().join("alias.pile");
    std::fs::hard_link(&source, &alias).unwrap();
    assert!(prepare(&source, &alias, &choices).is_err());
    assert!(prepare(&source, &source, &choices).is_err());
    #[cfg(unix)]
    {
        let link = dir.path().join("link.pile");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(prepare(&source, &link, &choices).is_err());
        let dangling = dir.path().join("dangling.pile");
        let absent = dir.path().join("absent.pile");
        std::os::unix::fs::symlink(&absent, &dangling).unwrap();
        assert!(prepare(&source, &dangling, &choices).is_err());
        assert!(!absent.exists());
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
}

fn envelope(kind: &[u8; 32]) -> Vec<u8> {
    // Existing published frame marker, also used by migrate_upgrade.rs.
    let mut bytes = vec![0; 256];
    bytes[..28].copy_from_slice(
        &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B").unwrap(),
    );
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..64].copy_from_slice(kind);
    bytes
}

#[test]
fn unsupported_frames_and_deployed_32_are_structured_nonwriting_outcomes() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    let unknown = envelope(&[0xa5; 32]);
    std::fs::write(&source, &unknown).unwrap();
    assert!(matches!(
        prepare(&source, &destination, &[]).unwrap(),
        Outcome::Unsupported { .. }
    ));
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&source).unwrap(), unknown);
    // Existing deployed /32 COMMIT kind; no signature claim is made by inspection.
    let kind: [u8; 32] =
        hex::decode("A1322BB3F5214287C314D42AFCC1A97CB264FACD9A22B4938838BE78DB31AA59")
            .unwrap()
            .try_into()
            .unwrap();
    let deployed = envelope(&kind);
    std::fs::write(&source, &deployed).unwrap();
    assert_eq!(
        prepare(&source, &destination, &[]).unwrap(),
        Outcome::ChoiceRequired {
            requirements: vec![Requirement::Canonical { records: 1 }],
        }
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&source).unwrap(), deployed);
}

#[test]
fn unknown_branch_decisions_do_not_override_the_source() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    std::fs::write(&source, []).unwrap();
    let signer = SigningKey::from_bytes(&[3; 32]);
    // The real fixture's branch, deliberately absent from this empty source.
    let fixture = dir.path().join("fixture.pile");
    legacy(&fixture);
    let branch = inspect(&fixture).unwrap().legacy_branches[0];
    let choices = [BranchDecision {
        branch,
        collection_name: "events",
        signer: &signer,
        authority: signer.verifying_key(),
    }];
    assert!(prepare(&source, &destination, &choices).is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::metadata(source).unwrap().len(), 0);
}

#[test]
fn current_storage_does_not_require_interpreting_blob_payloads() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("unused.pile");
    std::fs::write(&source, []).unwrap();
    let mut pile = Pile::open(&source).unwrap();
    pile.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(
        b"application data this storage migration does not understand".to_vec(),
    )))
    .unwrap();
    pile.close().unwrap();
    let original = std::fs::read(&source).unwrap();
    assert_eq!(
        prepare(&source, &destination, &[]).unwrap(),
        Outcome::Current {
            legacy_branches: vec![],
        }
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&source).unwrap(), original);
}

#[test]
fn a_tombstone_before_a_later_head_does_not_hide_the_live_branch_choice() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    let original = legacy(&source);
    let branch = inspect(&source).unwrap().legacy_branches[0];
    // Existing physical kind from core repo/pile/record_kind.rs; this module
    // is deliberately private, so the integration fixture pins its bytes.
    let mut bytes = envelope(&hex_literal::hex!(
        "8D9F27E76D3620EEC29B781F841E9EF77F2607B40DC702FE3DAED007E9228CA5"
    ));
    let raw: [u8; 16] = branch.into();
    bytes[64..80].copy_from_slice(&raw);
    bytes.extend_from_slice(&original);
    std::fs::write(&source, &bytes).unwrap();
    assert_eq!(inspect(&source).unwrap().legacy_branches, vec![branch]);
    assert_eq!(
        prepare(&source, &destination, &[]).unwrap(),
        Outcome::ChoiceRequired {
            requirements: vec![Requirement::Branch { branch }],
        }
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
}

#[test]
fn cancellation_during_copy_or_at_acceptance_never_returns_a_candidate() {
    for cancel_stage in [Stage::Reframe, Stage::Ready] {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.pile");
        let destination = dir.path().join("candidate.pile");
        let original = legacy(&source);
        let branch = inspect(&source).unwrap().legacy_branches[0];
        let signer = SigningKey::from_bytes(&[3; 32]);
        let decisions = [BranchDecision {
            branch,
            collection_name: "events",
            signer: &signer,
            authority: signer.verifying_key(),
        }];
        let mut cancelled = false;
        let result = prepare_with_progress(&source, &destination, &decisions, &mut |progress| {
            if progress.stage == cancel_stage
                && (cancel_stage == Stage::Ready || progress.completed_bytes > 0)
            {
                cancelled = true;
                return false;
            }
            true
        });
        assert!(cancelled);
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert!(destination.exists());
        // A partial or even complete unaccepted candidate is not a resume flag.
        assert!(prepare(&source, &destination, &decisions).is_err());
    }
}

#[test]
fn a_source_append_during_conversion_prevents_acceptance() {
    use std::io::Write;
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    let destination = dir.path().join("candidate.pile");
    let mut original = legacy(&source);
    let branch = inspect(&source).unwrap().legacy_branches[0];
    let signer = SigningKey::from_bytes(&[3; 32]);
    let decisions = [BranchDecision {
        branch,
        collection_name: "events",
        signer: &signer,
        authority: signer.verifying_key(),
    }];
    let mut appended = false;
    let result = prepare_with_progress(&source, &destination, &decisions, &mut |progress| {
        if progress.stage == Stage::Branch && !appended {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .unwrap()
                .write_all(b"external append")
                .unwrap();
            appended = true;
        }
        true
    });
    assert!(appended);
    assert!(result.unwrap_err().to_string().contains("source changed"));
    original.extend_from_slice(b"external append");
    assert_eq!(std::fs::read(&source).unwrap(), original);
}
