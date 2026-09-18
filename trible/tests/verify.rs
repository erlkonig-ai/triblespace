use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use std::path::Path;
use tempfile::tempdir;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
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
    let proof = CapabilityProof::new(
        CapabilityResource::new([4; 32]),
        &root,
        Inline::new([5; 32]),
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
fn verify_checks_auth_signatures_without_interpreting_definition_blobs() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad-auth.pile");
    std::fs::File::create(&path).unwrap();
    let root = SigningKey::from_bytes(&[2; 32]);
    let delegate = SigningKey::from_bytes(&[3; 32]);
    let leaf = SigningKey::from_bytes(&[4; 32]);
    let resource = CapabilityResource::new([5; 32]);
    let capability = Inline::new([6; 32]);
    let first = CapabilityProof::new(resource, &root, capability, delegate.verifying_key());
    let child = first
        .delegate(&delegate, Inline::new([7; 32]), leaf.verifying_key())
        .unwrap();
    // Neither referenced definition exists. Byte audit must still accept the
    // valid signed chain, regardless of its later interpretation as authority.
    child.verify_signatures().unwrap();
    let mut pile = Pile::open(&path).unwrap();
    pile.insert_proof(first).unwrap();
    pile.insert_proof(child).unwrap();
    pile.close().unwrap();
    let offset = PileRecords::open(&path)
        .unwrap()
        .find_map(|raw| match raw.unwrap().content {
            PileRecordContent::CapabilityProof {
                data_offset,
                data_len,
                ..
            } => Some(data_offset + data_len - 1),
            _ => None,
        })
        .unwrap();
    let mut before = std::fs::read(&path).unwrap();
    before[offset] ^= 0x80;
    std::fs::write(&path, &before).unwrap();
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "verify"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("AUTH=2")
                .and(predicate::str::contains("Invalid native records: 1")),
        )
        .stderr(predicate::str::contains("invalid signature"));
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

// Canonical but deliberately uninserted COMMIT witnesses keep these
// physical-storage fixtures independent of ancestor arrival order.
