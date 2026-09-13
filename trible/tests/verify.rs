use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};
use hifitime::Epoch;
use predicates::prelude::*;
use std::path::Path;
use tempfile::tempdir;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::capability::{
    Capability, CapabilityMode, CapabilityProof, CapabilityResource, CapabilityValidity,
    CAPABILITY_PROOF_HEADER_LEN,
};
use triblespace_core::collection::{
    CollectionCommit, CollectionDerive, CollectionMerge, CollectionRecord, CollectionStore,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{BlobStorePut, CapabilityProofStore};

fn signed_records() -> [CollectionRecord; 3] {
    let key = SigningKey::from_bytes(&[1; 32]);
    // These are opaque fixture handles, deliberately without any resident
    // descriptor, metadata, input or output blob. Verification needs none.
    [
        CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        )),
        CollectionRecord::Merge(CollectionMerge::sign(
            &key,
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
            Inline::new([4; 32]),
        )),
        CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            Inline::new([1; 32]),
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        )),
    ]
}

fn write_records(path: &Path) {
    std::fs::File::create(path).unwrap();
    let mut pile = Pile::open(path).unwrap();
    for record in signed_records() {
        pile.insert(record).unwrap();
    }
    pile.close().unwrap();
}

#[test]
fn verify_checks_physical_duplicates_without_blobs_keys_policy_or_clock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("records.pile");
    write_records(&path);
    let root = SigningKey::from_bytes(&[2; 32]);
    let delegate = SigningKey::from_bytes(&[3; 32]);
    let proof = CapabilityProof::issue_root(
        &root,
        CapabilityResource::new([4; 32]),
        Capability::new(Inline::new([5; 32]), CapabilityMode::Invoke),
        Some(
            CapabilityValidity::new(Epoch::from_tai_seconds(1.0), Epoch::from_tai_seconds(2.0))
                .unwrap(),
        ),
        delegate.verifying_key(),
    );
    let mut pile = Pile::open(&path).unwrap();
    pile.insert_proof(proof).unwrap();
    pile.close().unwrap();
    let mut before = std::fs::read(&path).unwrap();
    before.extend_from_within(..);
    std::fs::write(&path, &before).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "verify"])
        .arg(&path)
        .env("TRIBLESPACE_KEY", dir.path().join("missing.key"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("COMMIT=2, MERGE=2, DERIVE=2, AUTH=2")
                .and(predicate::str::contains("Invalid native records: 0")),
        );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!dir.path().join("missing.key").exists());
}

#[test]
fn verify_reports_every_bad_collection_signature_without_mutating_the_pile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad-records.pile");
    write_records(&path);
    let offsets: Vec<_> = PileRecords::open(&path)
        .unwrap()
        .map(|raw| raw.unwrap().offset)
        .collect();
    assert_eq!(offsets.len(), 3);
    let mut before = std::fs::read(&path).unwrap();
    // Alter the first signed field, not the framing or operand ordering.
    // Trusted structural replay still decodes all three; the explicit audit
    // must reject each signature rather than stop after the first failure.
    for offset in offsets {
        before[offset + 64] ^= 0x80;
    }
    std::fs::write(&path, &before).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "verify"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Invalid native records: 3"))
        .stderr(
            predicate::str::contains("Invalid COMMIT at byte")
                .and(predicate::str::contains("Invalid MERGE at byte"))
                .and(predicate::str::contains("Invalid DERIVE at byte")),
        );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn verify_checks_auth_signatures_and_path_local_attenuation() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad-auth.pile");
    std::fs::File::create(&path).unwrap();
    let root = SigningKey::from_bytes(&[2; 32]);
    let delegate = SigningKey::from_bytes(&[3; 32]);
    let leaf = SigningKey::from_bytes(&[4; 32]);
    let resource = CapabilityResource::new([5; 32]);
    let capability = Capability::new(Inline::new([6; 32]), CapabilityMode::Invoke);
    let first =
        CapabilityProof::issue_root(&root, resource, capability, None, delegate.verifying_key());
    let child =
        CapabilityProof::issue_root(&delegate, resource, capability, None, leaf.verifying_key());
    let mut bad_path = first.as_bytes().to_vec();
    bad_path.extend_from_slice(
        &child.as_bytes()[CAPABILITY_PROOF_HEADER_LEN..child.as_bytes().len() - 64],
    );
    let signature = delegate.sign(&bad_path);
    bad_path.extend_from_slice(&signature.to_bytes());
    let bad_path = CapabilityProof::from_bytes(&bad_path).unwrap();
    bad_path.verify_signatures().unwrap();
    assert!(bad_path.validate_structure().is_err());

    let mut bad_signature = first.into_bytes();
    *bad_signature.last_mut().unwrap() ^= 0x80;
    let bad_signature = CapabilityProof::from_bytes(&bad_signature).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    pile.insert_proof(bad_path).unwrap();
    pile.insert_proof(bad_signature).unwrap();
    pile.close().unwrap();
    let before = std::fs::read(&path).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "verify"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("AUTH=2")
                .and(predicate::str::contains("Invalid native records: 2")),
        )
        .stderr(
            predicate::str::contains("cannot delegate")
                .and(predicate::str::contains("invalid signature")),
        );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn verify_reports_unsigned_and_opaque_records_without_hashing_blob_payloads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unaudited.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    pile.put::<UTF8String, _>("blob hashes are a separate audit")
        .unwrap();
    pile.close().unwrap();
    let payload_offset = PileRecords::open(&path)
        .unwrap()
        .find_map(|raw| match raw.unwrap().content {
            PileRecordContent::Blob { data_offset, .. } => Some(data_offset),
            _ => None,
        })
        .unwrap();
    let mut before = std::fs::read(&path).unwrap();
    before[payload_offset] ^= 0x80;
    // Historical unsigned V4 MERGE framing, retained only as inert evidence.
    let mut legacy = vec![0u8; 256];
    legacy[..28].copy_from_slice(
        &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B").unwrap(),
    );
    legacy[28..32].copy_from_slice(&1u32.to_le_bytes());
    legacy[32..64].copy_from_slice(
        &hex::decode("0CEE320DE0BDA40A6A6F52221C5E4E4D2CE3B165B69C858673FD13D98F655379").unwrap(),
    );
    for (index, value) in [1u8, 2, 3, 4].into_iter().enumerate() {
        legacy[64 + index * 32..96 + index * 32].fill(value);
    }
    before.extend_from_slice(&legacy);
    // Deliberately unrecognized kind under known bounded framing.
    legacy[32..64].fill(0xA5);
    before.extend_from_slice(&legacy);
    std::fs::write(&path, &before).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "verify"])
        .arg(&path)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("COMMIT=0, MERGE=0, DERIVE=0, AUTH=0").and(
                predicate::str::contains(
                    "Not checked: unsigned legacy equations=1, opaque records=1, other records=1",
                ),
            ),
        );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
