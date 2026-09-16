use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStoreGet;
use triblespace::prelude::BlobStoreList;
use triblespace::prelude::BlobStorePut;
use triblespace::prelude::SnapshotSource;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::blob::TryFromBlob;
use triblespace_core::collection::{
    descriptor, AdmissionPolicy, Collection, CollectionMerge, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionStore, CollectionStoreExt,
};
use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{CapabilityProofRead, WantRead, WantRequest, WantStore};
use triblespace_core::trible::TribleSet;

fn opaque_envelope(needle: Option<[u8; 32]>) -> Vec<u8> {
    let mut record = vec![0u8; 256];
    record[..16].copy_from_slice(
        &hex::decode("E5A95E5D8A0BBA8782E46B9C9E73B313").expect("envelope marker"),
    );
    record[16..32].fill(0xA5);
    record[32..36].copy_from_slice(&1u32.to_le_bytes());
    if let Some(needle) = needle {
        record[80..112].copy_from_slice(&needle);
    }
    record
}

fn legacy_v3_definition_followed_by_blob() -> Vec<u8> {
    const HEADER_LEN: usize = 256;
    let payload = b"prioritize";
    let mut bytes = vec![0u8; 3 * HEADER_LEN];

    bytes[..16].copy_from_slice(
        &hex::decode("3BE108504E4F5242FB24AA72D6D94CE1").expect("definition marker"),
    );
    bytes[16..32].copy_from_slice(&hex::decode("B9566CF892C55CCB0E58411E1B18CD7F").expect("scope"));
    bytes[32..48]
        .copy_from_slice(&hex::decode("8F4A27C8581DADCBA1ADA8BA228069B6").expect("representation"));
    bytes[48..64]
        .copy_from_slice(&hex::decode("6D64C5F4B9E9B73F57C5F8702AB7FE45").expect("recipe"));

    let blob = &mut bytes[HEADER_LEN..];
    blob[..16]
        .copy_from_slice(&hex::decode("9C33EEB525065A62EAEC4BE43DCC355A").expect("V3 blob marker"));
    blob[16..24].copy_from_slice(&1_786_400_694_176u64.to_ne_bytes());
    blob[24..32].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
    blob[32..64].copy_from_slice(blake3::hash(payload).as_bytes());
    blob[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

    bytes
}

fn retired_team_record(kind: &str, seeds: &[u8]) -> Vec<u8> {
    let mut record = vec![0u8; 256];
    record[..28].copy_from_slice(
        &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B")
            .expect("envelope marker"),
    );
    record[28..32].copy_from_slice(&1u32.to_le_bytes());
    record[32..64].copy_from_slice(&hex::decode(kind).expect("record kind"));
    for (slot, seed) in seeds.iter().enumerate() {
        let key = SigningKey::from_bytes(&[*seed; 32]).verifying_key();
        record[64 + slot * 32..96 + slot * 32].copy_from_slice(&key.to_bytes());
    }
    record
}

fn retired_blob_want_record(handle: Inline<Handle<UnknownBlob>>, asserted: bool) -> Vec<u8> {
    let mut record = vec![0u8; 256];
    record[..28].copy_from_slice(
        &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B")
            .expect("envelope marker"),
    );
    record[28..32].copy_from_slice(&1u32.to_le_bytes());
    let kind = if asserted {
        "EC1C024C04AF08243DB3AE318C93FA500355C74395C0F553CFFC0AF0A4BA0346"
    } else {
        "ACCB531FC7489357C40FCEF0DDE8BD9088F2AC1924A652EA211ADD5C30B95B46"
    };
    record[32..64].copy_from_slice(&hex::decode(kind).expect("retired WANT kind"));
    record[64..96].copy_from_slice(&handle.raw);
    record
}

#[test]
fn create_initializes_empty_pile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("create_test.pile");
    std::fs::File::create(&path).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "create", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    let pile: Pile = Pile::open(&path).unwrap();
    pile.close().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

#[test]
fn create_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("nested")
        .join("dirs")
        .join("create_test.pile");

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "create", path.to_str().unwrap()])
        .assert()
        .success();

    assert!(path.exists());
    assert!(path.parent().unwrap().exists());
}

#[test]
fn compact_uses_valid_blob_occurrence_without_collecting_blobs_or_equations() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().unwrap();
    let source_path = dir.path().join("duplicate-source.pile");
    let destination_path = dir.path().join("compacted.pile");
    std::fs::File::create(&source_path).unwrap();

    let mut source = Pile::open(&source_path).unwrap();
    let blob = source
        .put::<UTF8String, _>("keep every resident blob")
        .unwrap();
    let equation = CollectionRecord::Merge(CollectionMerge::sign(
        &SigningKey::from_bytes(&[1; 32]),
        Inline::new([1; 32]),
        witnessed(
            &SigningKey::from_bytes(&[1; 32]),
            Inline::new([1; 32]),
            Inline::new([2; 32]),
        ),
        witnessed(
            &SigningKey::from_bytes(&[1; 32]),
            Inline::new([1; 32]),
            Inline::new([3; 32]),
        ),
        Inline::new([4; 32]),
    ));
    source.insert(equation).unwrap();
    source.close().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let payload_offset = PileRecords::open(&source_path)
        .unwrap()
        .find_map(|record| match record.unwrap().content {
            PileRecordContent::Blob { data_offset, .. } => Some(data_offset),
            _ => None,
        })
        .unwrap();

    // Pile concatenation is the ordinary way physical duplicates arise. The
    // semantic indexes already collapse them on replay; compaction must also
    // remove the repeated bytes from the new file.
    let one_copy = std::fs::read(&source_path).unwrap();
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&source_path)
        .unwrap()
        .write_all(&one_copy)
        .unwrap();
    // Leave the duplicate valid but corrupt the first occurrence's payload.
    // The segmented occurrence index projects one semantic handle while blob
    // transfer must still walk its physical offsets until validation succeeds.
    let mut source_before = std::fs::read(&source_path).unwrap();
    source_before[payload_offset] ^= 0xFF;
    std::fs::write(&source_path, &source_before).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("blob records: 2 -> 1")
                .and(predicate::str::contains("collection records: 2 -> 1"))
                .and(predicate::str::contains(
                    "retired team records: 0 -> 0 (dropped)",
                )),
        );

    assert_eq!(std::fs::read(&source_path).unwrap(), source_before);
    assert!(std::fs::metadata(&destination_path).unwrap().len() < source_before.len() as u64);
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&destination_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let records = PileRecords::open(&destination_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record.content, PileRecordContent::Blob { .. }))
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(record.content, PileRecordContent::Collection { .. }))
            .count(),
        1
    );

    let mut compacted = Pile::open(&destination_path).unwrap();
    let snapshot = compacted.snapshot().unwrap();
    let fetched: Blob<UTF8String> = snapshot.get(blob).unwrap();
    assert_eq!(fetched.bytes.as_ref(), b"keep every resident blob");
    assert_eq!(
        snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![equation]
    );
    drop(snapshot);
    compacted.close().unwrap();
}

#[test]
fn compact_preserves_current_delegated_capability_proof_and_admission() {
    use std::io::Write as _;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::capability::{
        capability_action, capability_delegate_action, CapabilityProof, CapabilityResource,
    };
    use triblespace_core::collection::{ACTION_READ, ACTION_WRITE};
    use triblespace_core::macros::entity;
    use triblespace_core::repo::CapabilityProofStore;

    let dir = tempdir().unwrap();
    let source_path = dir.path().join("delegated-auth-source.pile");
    let destination_path = dir.path().join("compacted.pile");
    std::fs::File::create(&source_path).unwrap();
    let [root, intermediary, recipient, stranger]: [SigningKey; 4] = std::array::from_fn(|_| {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    });
    let subjects = [&root, &intermediary, &recipient, &stranger].map(SigningKey::verifying_key);

    let mut source = Pile::open(&source_path).unwrap();
    let collection = source
        .collection(
            "compact-current-auth",
            CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    let parent_blob: Blob<SimpleArchive> = entity! {
        capability_action: ACTION_WRITE,
        capability_delegate_action: ACTION_READ,
    }
    .facts()
    .to_blob();
    let child_blob: Blob<SimpleArchive> = entity! {
        capability_action: ACTION_READ,
    }
    .facts()
    .to_blob();
    let parent_capability = source.put(parent_blob.clone()).unwrap();
    let child_capability = source.put(child_blob.clone()).unwrap();
    assert_ne!(parent_capability, child_capability);
    let proof = CapabilityProof::new(
        CapabilityResource::new(collection.handle().raw),
        &root,
        parent_capability,
        intermediary.verifying_key(),
    )
    .delegate(&intermediary, child_capability, recipient.verifying_key())
    .unwrap();
    assert_eq!(
        proof.capabilities().collect::<Vec<_>>(),
        vec![parent_capability, child_capability]
    );
    proof.verify_signatures().unwrap();
    // Store only the full chain: the intermediary's WRITE must still be
    // authorized by its prefix, even though the final grant invokes only READ.
    source.insert_proof(proof.clone()).unwrap();
    let snapshot = source.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, collection.handle()).unwrap();
    let before_admission = subjects.map(|subject| {
        (
            opened.reader_is_admitted(&snapshot, subject).unwrap(),
            opened.writer_is_admitted(&snapshot, subject).unwrap(),
        )
    });
    assert_eq!(
        before_admission,
        [(true, true), (false, true), (true, false), (false, false)]
    );
    drop(snapshot);
    source.close().unwrap();

    // Concatenation repeats the physical AUTH frame, not the semantic proof.
    let one_copy = std::fs::read(&source_path).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&source_path)
        .unwrap()
        .write_all(&one_copy)
        .unwrap();
    let source_before = std::fs::read(&source_path).unwrap();
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("capability proofs: 2 -> 1"));
    assert_eq!(std::fs::read(&source_path).unwrap(), source_before);

    let mut records = PileRecords::open(&destination_path).unwrap();
    let proof_frames: Vec<_> = records
        .by_ref()
        .filter_map(|record| match record.unwrap().content {
            PileRecordContent::CapabilityProof {
                id,
                data_offset,
                data_len,
            } => Some((id, data_offset, data_len)),
            _ => None,
        })
        .collect();
    assert_eq!(proof_frames.len(), 1);
    let (id, offset, len) = proof_frames[0];
    assert_eq!(id, proof.id());
    assert_eq!(&records.bytes()[offset..offset + len], proof.as_bytes());
    drop(records);

    let mut compacted = Pile::open(&destination_path).unwrap();
    let snapshot = compacted.snapshot().unwrap();
    assert_eq!(
        snapshot
            .proofs()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![proof.clone()]
    );
    let retained = snapshot.proof(proof.id()).unwrap().unwrap();
    assert_eq!(retained.id(), proof.id());
    assert_eq!(retained.as_bytes(), proof.as_bytes());
    retained.verify_signatures().unwrap();
    for (handle, expected) in [
        (parent_capability, parent_blob),
        (child_capability, child_blob),
    ] {
        let actual: Blob<SimpleArchive> = snapshot.get(handle).unwrap();
        assert_eq!(actual.bytes.as_ref(), expected.bytes.as_ref());
    }
    let opened = Collection::<SimpleArchive>::open(&snapshot, collection.handle()).unwrap();
    let after_admission = subjects.map(|subject| {
        (
            opened.reader_is_admitted(&snapshot, subject).unwrap(),
            opened.writer_is_admitted(&snapshot, subject).unwrap(),
        )
    });
    assert_eq!(after_admission, before_admission);
    drop(snapshot);
    compacted.close().unwrap();
}

#[test]
fn compact_drops_retired_team_records() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("retired-team-source.pile");
    let destination_path = dir.path().join("compacted.pile");

    let mut bytes = retired_team_record(
        "327FFCAAA3F5A10424DC2059E3A7A3517F837E7E56A3C850979EFA9F5E3A1ED7",
        &[1, 2],
    );
    bytes.extend_from_slice(&retired_team_record(
        "97C69C746D01741C8012A56F08D2C424E0291B5424EB9CD7637FD4A655C93DFB",
        &[3],
    ));
    std::fs::write(&source_path, &bytes).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "retired team records: 2 -> 0 (dropped)",
        ));

    assert_eq!(std::fs::read(&source_path).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&destination_path).unwrap().len(), 0);
}

#[test]
fn monotone_want_migration_is_explicit_additive_and_idempotent() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("retired-wants.pile");
    let destination_path = dir.path().join("compacted.pile");
    let active = Inline::<Handle<UnknownBlob>>::new([0x81; 32]);
    let inactive = Inline::<Handle<UnknownBlob>>::new([0x82; 32]);

    let mut bytes = retired_blob_want_record(active, true);
    bytes.extend_from_slice(&retired_blob_want_record(inactive, true));
    bytes.extend_from_slice(&retired_blob_want_record(inactive, false));
    std::fs::write(&source_path, &bytes).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "diagnose", "check"])
        .arg(&source_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Recognized 3 retired WANT log record(s)",
        ));

    let mut before = Pile::open(&source_path).unwrap();
    let before_snapshot = before.snapshot().unwrap();
    assert!(before_snapshot.wants().unwrap().next().is_none());
    drop(before_snapshot);
    before.close().unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "migrate"])
        .arg(&source_path)
        .args(["run", "monotone-wants", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Would append 1 monotone WANT marker(s)",
        ));
    assert_eq!(std::fs::read(&source_path).unwrap(), bytes);

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "migrate"])
        .arg(&source_path)
        .args(["run", "monotone-wants"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Appended 1 monotone WANT marker(s)",
        ));
    let migrated_len = std::fs::metadata(&source_path).unwrap().len();
    assert_eq!(migrated_len, bytes.len() as u64 + 256);

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "migrate"])
        .arg(&source_path)
        .args(["run", "monotone-wants"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to do"));
    assert_eq!(std::fs::metadata(&source_path).unwrap().len(), migrated_len);

    // Retired history concatenated after cutover stays inert in ordinary
    // replay and compaction; only another explicit migration could promote it.
    let stale = Inline::<Handle<UnknownBlob>>::new([0x83; 32]);
    let mut appended = std::fs::OpenOptions::new()
        .append(true)
        .open(&source_path)
        .unwrap();
    use std::io::Write as _;
    appended
        .write_all(&retired_blob_want_record(stale, true))
        .unwrap();
    appended.sync_all().unwrap();
    drop(appended);

    let mut reopened = Pile::open(&source_path).unwrap();
    let reopened_snapshot = reopened.snapshot().unwrap();
    assert_eq!(
        reopened_snapshot
            .wants()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![WantRequest::blob(active)]
    );
    drop(reopened_snapshot);
    reopened.close().unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "retired WANT log records: 4 -> 0 (dropped)",
        ));
    let mut compacted = Pile::open(&destination_path).unwrap();
    let compacted_snapshot = compacted.snapshot().unwrap();
    assert_eq!(
        compacted_snapshot
            .wants()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![WantRequest::blob(active)]
    );
    drop(compacted_snapshot);
    compacted.close().unwrap();
}

#[cfg(unix)]
#[test]
fn compact_copies_source_permissions_after_rewrite() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().unwrap();
    let source_path = dir.path().join("permission-source.pile");
    let destination_path = dir.path().join("permission-destination.pile");
    std::fs::File::create(&source_path).unwrap();
    std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o640)).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success();

    assert_eq!(
        std::fs::metadata(&destination_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
}

#[test]
fn compact_carries_opaque_records_exactly_and_says_so() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("opaque-source.pile");
    let destination_path = dir.path().join("carried.pile");
    let source_bytes = opaque_envelope(None);
    std::fs::write(&source_path, &source_bytes).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "frames of unknown kind: 1 (256 bytes) -> 1 (256 bytes) (carried exactly)",
        ));

    assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
    assert_eq!(std::fs::read(&destination_path).unwrap(), source_bytes);
}

#[test]
fn compact_removes_destination_after_post_create_failure() {
    let dir = tempdir().unwrap();
    let source_path = dir.path().join("corrupt-source.pile");
    let destination_path = dir.path().join("must-not-survive.pile");
    std::fs::File::create(&source_path).unwrap();

    let mut source = Pile::open(&source_path).unwrap();
    source.put::<UTF8String, _>("only occurrence").unwrap();
    source.close().unwrap();
    let payload_offset = PileRecords::open(&source_path)
        .unwrap()
        .find_map(|record| match record.unwrap().content {
            PileRecordContent::Blob { data_offset, .. } => Some(data_offset),
            _ => None,
        })
        .unwrap();
    let mut source_bytes = std::fs::read(&source_path).unwrap();
    source_bytes[payload_offset] ^= 0xFF;
    std::fs::write(&source_path, &source_bytes).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "compact"])
        .arg(&source_path)
        .arg("--into")
        .arg(&destination_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("compact pile"));

    assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
    assert!(!destination_path.exists());
}

#[test]
fn collection_init_registers_direct_root_without_a_commit_and_is_idempotent() {
    use triblespace::prelude::TryToInline;

    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("init.pile");
    let key_path = dir.path().join("operator.key");
    std::fs::File::create(&pile_path).unwrap();
    let root = triblespace_core::signing_key_file::init(&key_path).unwrap();

    let invoke = || {
        Command::cargo_bin("trible")
            .unwrap()
            .args(["pile", "collection", "init"])
            .arg(&pile_path)
            .arg("shared-relations")
            .arg("--key")
            .arg(&key_path)
            .output()
            .unwrap()
    };

    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let output = std::str::from_utf8(&first.stdout).unwrap();
    assert!(predicate::str::is_match(r"^blake3:[0-9a-f]{64}\n$")
        .unwrap()
        .eval(output));
    let encoded: Inline<Hash<Blake3>> = output.trim().try_to_inline().unwrap();
    let handle = encoded.into();
    let first_len = std::fs::metadata(&pile_path).unwrap().len();

    let second = invoke();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), first_len);

    let mut pile = Pile::open(&pile_path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    Collection::<SimpleArchive>::open(&snapshot, handle).unwrap();
    let descriptor_blob: Blob<SimpleArchive> = snapshot.get(handle).unwrap();
    let facts = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(descriptor_blob).unwrap();
    let name: Blob<UTF8String> = snapshot
        .get(descriptor::name(&facts).unwrap().unwrap())
        .unwrap();
    assert_eq!(name.bytes.as_ref(), b"shared-relations");
    let direct = AdmissionPolicy::direct(root.verifying_key());
    assert_eq!(
        descriptor::policy(&facts).unwrap(),
        CollectionPolicy::new(direct.clone(), direct)
    );
    assert_eq!(snapshot.records().unwrap().count(), 0);
    drop(snapshot);
    pile.close().unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "collection", "list"])
        .arg(&pile_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("no collections referenced"));
}

#[test]
fn collection_init_requires_an_existing_signing_key() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("init-missing-key.pile");
    let key_path = dir.path().join("missing.key");
    std::fs::File::create(&pile_path).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "collection", "init"])
        .arg(&pile_path)
        .arg("shared-relations")
        .arg("--key")
        .arg(&key_path)
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("load collection-root signing key"));

    assert!(!key_path.exists());
    assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), 0);
}

#[test]
fn collection_grant_read_is_replay_idempotent_and_admits_the_endpoint() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("grant-read.pile");
    let key_path = dir.path().join("self.key");
    std::fs::File::create(&pile_path).unwrap();
    let root = triblespace_core::signing_key_file::init(&key_path).unwrap();
    let reader = SigningKey::from_bytes(&[77; 32]);
    let endpoint = iroh_base::PublicKey::from_bytes(&reader.verifying_key().to_bytes())
        .unwrap()
        .to_string();

    let mut pile = Pile::open(&pile_path).unwrap();
    let collection = pile
        .collection(
            "cli-read-grant",
            CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    pile.close().unwrap();

    let handle = format!("blake3:{}", hex::encode(collection.handle().raw));
    let invoke = || {
        Command::cargo_bin("trible")
            .unwrap()
            .args(["pile", "collection", "grant-read"])
            .arg(&pile_path)
            .arg(&handle)
            .arg(&endpoint)
            .output()
            .unwrap()
    };

    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_len = std::fs::metadata(&pile_path).unwrap().len();
    let second = invoke();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), first_len);

    let mut pile = Pile::open(&pile_path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, collection.handle()).unwrap();
    assert!(opened
        .reader_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    let proofs = snapshot
        .proofs()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].root_key(), root.verifying_key());
    assert_eq!(proofs[0].leaf_key(), reader.verifying_key());
    assert_eq!(proofs[0].resource().as_bytes(), &collection.handle().raw);
    proofs[0].verify_signatures().unwrap();
    drop(snapshot);
    pile.close().unwrap();
}

#[test]
fn collection_grant_write_is_replay_idempotent_and_admits_the_author() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("grant-write.pile");
    let key_path = dir.path().join("self.key");
    std::fs::File::create(&pile_path).unwrap();
    let root = triblespace_core::signing_key_file::init(&key_path).unwrap();
    let writer = SigningKey::from_bytes(&[78; 32]);
    let recipient = iroh_base::PublicKey::from_bytes(&writer.verifying_key().to_bytes())
        .unwrap()
        .to_string();

    let mut pile = Pile::open(&pile_path).unwrap();
    let collection = pile
        .collection(
            "cli-write-grant",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    pile.close().unwrap();

    let handle = format!("blake3:{}", hex::encode(collection.handle().raw));
    let invoke = || {
        Command::cargo_bin("trible")
            .unwrap()
            .args(["pile", "collection", "grant-write"])
            .arg(&pile_path)
            .arg(&handle)
            .arg(&recipient)
            .output()
            .unwrap()
    };

    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_len = std::fs::metadata(&pile_path).unwrap().len();
    let second = invoke();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(second.stdout, first.stdout);
    assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), first_len);

    let mut pile = Pile::open(&pile_path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, collection.handle()).unwrap();
    assert!(opened
        .writer_is_admitted(&snapshot, writer.verifying_key())
        .unwrap());
    let proofs = snapshot
        .proofs()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].root_key(), root.verifying_key());
    assert_eq!(proofs[0].leaf_key(), writer.verifying_key());
    assert_eq!(proofs[0].resource().as_bytes(), &collection.handle().raw);
    proofs[0].verify_signatures().unwrap();
    drop(snapshot);
    pile.close().unwrap();
}

#[test]
fn put_ingests_file() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("put_test.pile");
    std::fs::File::create(&pile_path).unwrap();
    let input_path = dir.path().join("input.bin");
    std::fs::write(&input_path, b"hello world").unwrap();

    let digest = blake3::hash(b"hello world").to_hex().to_string();
    let handle = format!("blake3:{digest}");
    let pattern = format!("^{handle}\\n$");

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_match(pattern).unwrap());

    let mut pile: Pile = Pile::open(&pile_path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert!(snapshot.blobs().next().is_some());
    drop(snapshot);
    pile.close().unwrap();
}

#[test]
fn get_restores_blob() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("get_test.pile");
    std::fs::File::create(&pile_path).unwrap();
    let input_path = dir.path().join("input.bin");
    let output_path = dir.path().join("output.bin");
    let contents = b"fetch me";
    std::fs::write(&input_path, contents).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let digest = blake3::hash(contents).to_hex().to_string();
    let handle = format!("blake3:{digest}");

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "get",
            pile_path.to_str().unwrap(),
            &handle,
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    let out = std::fs::read(&output_path).unwrap();
    assert_eq!(contents, &out[..]);
}

#[test]
fn list_blobs_outputs_expected_handle() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("list_blobs.pile");
    std::fs::File::create(&pile_path).unwrap();
    let input_path = dir.path().join("input.bin");
    let contents = b"hello";
    std::fs::write(&input_path, contents).unwrap();

    let digest = blake3::hash(contents).to_hex().to_string();
    let handle = format!("blake3:{digest}");
    let pattern = format!("^{handle}\\n$");

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "blob", "list", pile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_match(&pattern).unwrap());
}

#[test]
fn list_blobs_with_metadata_outputs_details() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("list_blobs_meta.pile");
    std::fs::File::create(&pile_path).unwrap();
    let input_path = dir.path().join("input.bin");
    let contents = b"hello";
    std::fs::write(&input_path, contents).unwrap();

    let digest = blake3::hash(contents).to_hex().to_string();
    let handle = format!("blake3:{digest}");
    let pattern = format!(r"^{}\t\S+\t{}\n$", handle, contents.len());

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "list",
            "--metadata",
            pile_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_match(&pattern).unwrap());
}

#[test]
fn diagnose_reports_healthy() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("diag.pile");
    std::fs::File::create(&pile_path).unwrap();

    // create an empty pile file
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "create", pile_path.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "diagnose", "check", pile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("healthy"));
}

#[test]
fn diagnose_decodes_and_locates_bearer_blob_wants() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("blob-want.pile");
    std::fs::File::create(&pile_path).unwrap();

    let handle = Inline::<Handle<UnknownBlob>>::new([0x42; 32]);
    let mut pile = Pile::open(&pile_path).unwrap();
    pile.want(WantRequest::blob(handle)).unwrap();
    pile.close().unwrap();

    let handle_hex = hex::encode_upper(handle.raw);
    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "record-at",
            pile_path.to_str().unwrap(),
            "0",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "classification: want (current grow-only set)",
        ))
        .stdout(predicate::str::contains("request_kind: blob"))
        .stdout(predicate::str::contains(format!("handle: {handle_hex}")));

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "locate-hash",
            pile_path.to_str().unwrap(),
            &handle_hex,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "typed want reference at byte 0 (request field handle)",
        ))
        .stdout(predicate::str::contains("want markers:   1"));
}

#[test]
fn diagnose_decodes_legacy_v3_definition_and_continues_into_blob() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("legacy-definition-then-blob.pile");
    std::fs::write(&pile_path, legacy_v3_definition_followed_by_blob()).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "record-at",
            pile_path.to_str().unwrap(),
            "0",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "marker: 3BE108504E4F5242FB24AA72D6D94CE1",
        ))
        .stdout(predicate::str::contains(
            "classification: legacy-v3-collection-definition (inert)",
        ))
        .stdout(predicate::str::contains(
            "scope: B9566CF892C55CCB0E58411E1B18CD7F",
        ))
        .stdout(predicate::str::contains(
            "representation: 8F4A27C8581DADCBA1ADA8BA228069B6",
        ))
        .stdout(predicate::str::contains(
            "recipe: 6D64C5F4B9E9B73F57C5F8702AB7FE45",
        ))
        .stdout(predicate::str::contains("known_span_bytes: 256"))
        .stdout(predicate::str::contains("next_offset: 256"));

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "record-at",
            pile_path.to_str().unwrap(),
            "256",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("classification: blob"))
        .stdout(predicate::str::contains("known_span_bytes: 512"))
        .stdout(predicate::str::contains("next_offset: 768"))
        .stdout(predicate::str::contains("payload_offset: 512"))
        .stdout(predicate::str::contains("payload_length: 10"))
        .stdout(predicate::str::contains(
            "payload_hash: 15FC745FC8162C584C12017295E065808B04FA51D72EAE20283A2415A4D5B1B0",
        ));

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "diagnose", "check", pile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pile appears healthy"))
        .stdout(predicate::str::contains(
            "Recognized 1 inert legacy V3 collection record(s) (first byte 0, last byte 0)",
        ));
}

#[test]
fn diagnose_record_at_distinguishes_version_skew_from_a_torn_record() {
    let dir = tempdir().unwrap();
    let unsupported_path = dir.path().join("unsupported.pile");
    let torn_path = dir.path().join("torn.pile");

    let mut unsupported = vec![0u8; 256];
    unsupported[..16].fill(0xA5);
    std::fs::write(&unsupported_path, unsupported).unwrap();
    std::fs::write(
        &torn_path,
        hex::decode("9C33EEB525065A62EAEC4BE43DCC355A").expect("V3 blob marker"),
    )
    .unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "record-at",
            unsupported_path.to_str().unwrap(),
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "record format unsupported by this binary",
        ))
        .stderr(predicate::str::contains("Upgrade trible"))
        .stderr(predicate::str::contains("amputate").not());

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "record-at",
            torn_path.to_str().unwrap(),
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("malformed or incomplete"))
        .stderr(predicate::str::contains("cannot prove"))
        .stderr(predicate::str::contains("--truncate-to <BYTE_OFFSET>"));
}

#[test]
fn diagnose_qualifies_health_when_opaque_bodies_are_skipped() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("opaque-diag.pile");
    std::fs::write(&pile_path, opaque_envelope(None)).unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "diagnose", "check", pile_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Known record projection appears healthy",
        ))
        .stdout(predicate::str::contains(
            "bodies were not semantically validated",
        ));
}

#[test]
fn diagnose_locate_hash_scans_the_complete_opaque_record() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("opaque-locate.pile");
    let needle = [0x4D; 32];
    std::fs::write(&pile_path, opaque_envelope(Some(needle))).unwrap();
    let handle = format!("blake3:{}", hex::encode_upper(needle));

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "locate-hash",
            pile_path.to_str().unwrap(),
            &handle,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("opaque-record byte match"))
        .stdout(predicate::str::contains("opaque records: 1"));
}

#[test]
fn diagnose_reports_invalid_hash() {
    use std::io::Seek;
    use std::io::Write;

    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("bad.pile");
    std::fs::File::create(&pile_path).unwrap();
    let blob_path = dir.path().join("blob.bin");
    std::fs::write(&blob_path, b"good data").unwrap();

    // put a blob into the pile
    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            blob_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // corrupt the blob bytes directly
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&pile_path)
        .unwrap();
    // first blob payload starts after the fixed 256-byte envelope header
    file.seek(std::io::SeekFrom::Start(256)).unwrap();
    file.write_all(b"X").unwrap();

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "diagnose", "check", pile_path.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("incorrect hashes"));
}

#[test]
fn inspect_outputs_tribles() {
    use triblespace::prelude::*;
    use triblespace_core::examples;
    use triblespace_core::inline::encodings::hash::Handle;

    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("inspect.pile");
    std::fs::File::create(&pile_path).unwrap();

    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::blob::{Blob, IntoBlob};
    let dataset = examples::dataset();
    let blob: Blob<SimpleArchive> = dataset.to_blob();

    let handle_str = {
        let mut pile: Pile = Pile::open(&pile_path).unwrap();
        let handle = pile.put::<SimpleArchive, _>(blob).unwrap();
        pile.close().unwrap();

        let hash = Handle::to_hash(handle);
        hash.from_inline::<String>()
    };

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "inspect",
            pile_path.to_str().unwrap(),
            &handle_str,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Length:"));
}

#[test]
fn diagnose_locate_hash_reports_header_and_payload_refs() {
    let dir = tempdir().unwrap();
    let pile_path = dir.path().join("locate_hash.pile");
    std::fs::File::create(&pile_path).unwrap();

    // Put blob1 and capture its handle string.
    let blob1_path = dir.path().join("blob1.bin");
    std::fs::write(&blob1_path, b"blob1").unwrap();
    let out1 = Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            blob1_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let handle1 = String::from_utf8(out1).unwrap();
    let handle1 = handle1.trim().to_string();

    // Put blob2 containing the raw digest bytes of blob1 in its payload, so the
    // locator can find a payload reference.
    let digest_hex = handle1.strip_prefix("blake3:").expect("handle prefix");
    let digest_bytes = hex::decode(digest_hex).expect("decode digest hex");
    let mut payload = b"prefix".to_vec();
    payload.extend_from_slice(&digest_bytes);
    payload.extend_from_slice(b"suffix");

    let blob2_path = dir.path().join("blob2.bin");
    std::fs::write(&blob2_path, payload).unwrap();
    let out2 = Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "blob",
            "put",
            pile_path.to_str().unwrap(),
            blob2_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let handle2 = String::from_utf8(out2).unwrap();
    let handle2 = handle2.trim().to_string();

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "diagnose",
            "locate-hash",
            pile_path.to_str().unwrap(),
            &handle1,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("blob header match"))
        .stdout(predicate::str::contains(&format!(
            "payload reference in {handle2}"
        )))
        .stdout(predicate::str::contains("Summary"));
}

/// A malformed or incomplete source pile must make `migrate` fail loud with a
/// boundary-confirmed repair path, without truncating the source file.
#[test]
fn corrupt_source_fails_loud_without_truncation() {
    use std::io::Write;

    let dir = tempdir().unwrap();
    let src_path = dir.path().join("corrupt_src.pile");
    std::fs::File::create(&src_path).unwrap();

    // Tear the tail before even a complete record marker has landed.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&src_path)
            .unwrap();
        file.write_all(&[0xFFu8; 8]).unwrap();
        file.sync_all().unwrap();
    }
    let len_before = std::fs::metadata(&src_path).unwrap().len();

    let fail_loud = || {
        predicate::str::contains("cannot prove")
            .and(predicate::str::contains("--truncate-to <BYTE_OFFSET>"))
    };

    // migrate (in-place rewrite): still refuses to open a corrupt pile.
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "migrate", src_path.to_str().unwrap(), "list"])
        .assert()
        .failure()
        .stderr(fail_loud());

    let len_after = std::fs::metadata(&src_path).unwrap().len();
    assert_eq!(
        len_before, len_after,
        "source pile must not be truncated by a failed open"
    );
}

/// A complete unknown marker is format/version skew, not evidence that the
/// tail is disposable. Normal commands and the explicit repair command both
/// fail without suggesting or performing truncation.
#[test]
fn unsupported_record_marker_never_recommends_or_performs_amputation() {
    use std::io::Write;

    let dir = tempdir().unwrap();
    let path = dir.path().join("unsupported.pile");
    let unknown_marker = [0xA5u8; 16];
    let mut unknown_record = [0u8; 256];
    unknown_record[..16].copy_from_slice(&unknown_marker);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&unknown_record)
        .unwrap();
    let len_before = std::fs::metadata(&path).unwrap().len();

    let unsupported_without_repair_hint = || {
        predicate::str::contains("unsupported")
            .and(predicate::str::contains("version skew"))
            .and(predicate::str::contains("trible pile amputate").not())
    };

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "migrate", path.to_str().unwrap(), "list"])
        .assert()
        .failure()
        .stderr(unsupported_without_repair_hint());

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "amputate",
            path.to_str().unwrap(),
            "--truncate-to",
            "0",
        ])
        .assert()
        .failure()
        .stderr(unsupported_without_repair_hint());

    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        len_before,
        "an unknown marker must survive even an explicit amputation attempt"
    );
}

#[test]
fn amputate_requires_and_matches_the_current_reader_boundary() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("torn.pile");
    std::fs::write(&path, [0xFFu8; 8]).unwrap();

    // The old copy-pasteable command is deliberately incomplete now.
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "amputate", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--truncate-to"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);

    // A guessed boundary cannot destroy anything.
    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "amputate",
            path.to_str().unwrap(),
            "--truncate-to",
            "1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match the current reader's boundary 0",
        ));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 8);

    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "amputate",
            path.to_str().unwrap(),
            "--truncate-to",
            "0",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("at confirmed boundary"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

// Canonical but deliberately uninserted COMMIT witnesses keep these
// physical-storage fixtures independent of ancestor arrival order.
fn witnessed(
    signer: &ed25519_dalek::SigningKey,
    collection: triblespace_core::collection::CollectionHandle,
    data: triblespace_core::collection::CollectionData,
) -> (
    triblespace_core::collection::CollectionData,
    triblespace_core::collection::CollectionRecordFingerprint,
) {
    let record = triblespace_core::collection::CollectionCommit::sign(
        signer,
        collection,
        data,
        triblespace_core::collection::empty_metadata_handle(),
    );
    (data, record.fingerprint())
}
