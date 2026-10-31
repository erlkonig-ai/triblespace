//! CLI-private tests. Manual cases require the independently built /32 writer.
#[path = "native_tests.rs"]
mod native_tests;
#[path = "retired_tests.rs"]
mod retired_tests;

use super::*;
use clap::Parser;
use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use triblespace_core::blob::{encodings::UnknownBlob, Blob};
use triblespace_core::collection::records::CollectionCommit;
use triblespace_core::repo::{BlobStorePut, WantRequest, WantStore};

fn seed(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn fresh(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
pub(super) fn key(dir: &Path, n: u8) -> PathBuf {
    let path = dir.join(format!("synthetic-{n}.key"));
    fresh(&path, hex::encode([n; 32]).as_bytes());
    path
}
pub(super) fn hash(path: &Path) -> String {
    blake3::hash(&std::fs::read(path).unwrap())
        .to_hex()
        .to_string()
}
pub(super) fn args(source: &Path, dir: &Path, name: &str, key: &Path) -> Args {
    Args {
        into: dir.join(name),
        key: key.to_owned(),
        source_hash: hash(source),
        refreshes: vec![],
        retain_unconverted_caches: false,
        report: Some(dir.join(format!("{name}.jsonl"))),
        dry_run: false,
    }
}
fn current_source(dir: &Path) -> PathBuf {
    let path = dir.join("current.pile");
    fresh(&path, &[]);
    let mut pile = PileFile::open(&path).unwrap();
    let blob = Blob::<UnknownBlob>::new(Bytes::from_source(b"synthetic current payload".to_vec()));
    let payload = pile.put::<UnknownBlob, _>(blob).unwrap();
    for n in [7, 8, 9] {
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &seed(n),
            Inline::new([11; 32]),
            Inline::new(payload.raw),
            Inline::new([12; 32]),
        )))
        .unwrap();
    }
    pile.want(WantRequest::blob(payload)).unwrap();
    pile.close().unwrap();
    path
}
pub(super) fn ids(path: &Path) -> Ids {
    let mut result = Ids::default();
    for framed in PileRecords::open(path).unwrap() {
        match framed.unwrap().content {
            PileRecordContent::Collection { record } => {
                record.verify_strict().unwrap();
                add(&mut result.records, record.fingerprint().raw());
            }
            PileRecordContent::Blob { hash, .. } => add(&mut result.blobs, hash.raw),
            PileRecordContent::CapabilityProof { id, .. } => add(&mut result.proofs, id.raw),
            _ => {}
        }
    }
    result
}
fn events(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn current_assertions_keep_all_authors_and_exact_frames() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let before = hash(&source);
    let key = key(dir.path(), 7);
    let run_args = args(&source, dir.path(), "rewritten.pile", &key);
    let into = run_args.into.clone();
    run(source.clone(), run_args).unwrap();
    assert_eq!(hash(&source), before);
    assert_eq!(ids(&into).records, ids(&source).records);
    assert_eq!(ids(&into).records.len(), 3);
    assert!(!partial_path(&into).exists());
    assert_eq!(
        std::fs::metadata(&into).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn source_identity_length_and_hash_checks_remain_independent_of_opener_observation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.pile");
    fresh(&path, b"source bytes");
    let mut source = Source::open(&path, None).unwrap();
    source.check().unwrap();
    // Model a mismatched retained byte view without violating mmap's immutable
    // backing-file contract by overwriting or truncating a mapped file.
    source.bytes = Bytes::from_source(b"changed view".to_vec());
    assert!(format!("{:#}", source.check().unwrap_err()).contains("source bytes changed"));
    drop(source);

    let source = Source::open(&path, None).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"appended")
        .unwrap();
    assert!(format!("{:#}", source.check().unwrap_err()).contains("identity/length/time changed"));
    drop(source);

    let source = Source::open(&path, None).unwrap();
    let replacement = dir.path().join("replacement.pile");
    fresh(&replacement, b"source bytesappended");
    std::fs::rename(&replacement, &path).unwrap();
    assert!(format!("{:#}", source.check().unwrap_err()).contains("identity/length/time changed"));
}

#[test]
fn missing_key_and_refresh_never_create_them_or_a_destination() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let missing = dir.path().join("nonexistent.key");
    let a = args(&source, dir.path(), "missing-key.pile", &missing);
    let output = a.into.clone();
    assert!(run(source.clone(), a).is_err());
    assert!(!missing.exists() && !output.exists() && !partial_path(&output).exists());
    let key = key(dir.path(), 7);
    let mut a = args(&source, dir.path(), "missing-refresh.pile", &key);
    let missing = dir.path().join("nonexistent-refresh.pile");
    a.refreshes.push(missing.clone());
    let output = a.into.clone();
    assert!(run(source, a).is_err());
    assert!(!missing.exists() && !output.exists() && !partial_path(&output).exists());
}

#[test]
fn every_existing_output_and_input_alias_is_refused_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let before = hash(&source);
    let key = key(dir.path(), 7);
    for variant in 0..8 {
        let mut a = args(&source, dir.path(), &format!("alias-{variant}.pile"), &key);
        match variant {
            0 => a.into = source.clone(),
            1 => a.report = Some(source.clone()),
            2 => a.report = Some(a.into.clone()),
            3 => {
                std::fs::hard_link(&source, &a.into).unwrap();
            }
            4 => {
                std::os::unix::fs::symlink(&source, &a.into).unwrap();
            }
            5 => fresh(&a.into, b"do not overwrite"),
            6 => fresh(&partial_path(&a.into), b"do not resume"),
            7 => fresh(a.report.as_ref().unwrap(), b"do not overwrite report"),
            _ => unreachable!(),
        }
        assert!(run(source.clone(), a).is_err(), "variant {variant}");
        assert_eq!(hash(&source), before);
    }
}

#[test]
fn dry_run_is_stdout_only_and_hash_mismatch_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let key = key(dir.path(), 7);
    let mut a = args(&source, dir.path(), "dry.pile", &key);
    a.dry_run = true;
    assert!(
        run(source.clone(), a).is_err(),
        "explicit report conflicts with dry-run"
    );
    let mut a = args(&source, dir.path(), "dry.pile", &key);
    a.dry_run = true;
    a.report = None;
    let count = std::fs::read_dir(dir.path()).unwrap().count();
    run(source.clone(), a).unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), count);
    let mut a = args(&source, dir.path(), "wrong-hash.pile", &key);
    a.source_hash = "00".repeat(32);
    assert!(run(source, a).is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), count);
}

#[test]
fn controlled_failures_leave_incomplete_partials_and_fresh_retry_matches_ids() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let before = hash(&source);
    let key = key(dir.path(), 7);
    for (i, stop) in [Stop::AfterCopy, Stop::AfterAssertion, Stop::BeforePublish]
        .into_iter()
        .enumerate()
    {
        let a = args(&source, dir.path(), &format!("stopped-{i}.pile"), &key);
        let into = a.into.clone();
        let report = a.report.clone().unwrap();
        assert!(execute(source.clone(), a, Mode::Refresh, stop).is_err());
        assert!(!into.exists() && partial_path(&into).exists());
        assert_eq!(events(&report).last().unwrap()["event"], "unsuccessful");
    }
    let mut results = Vec::new();
    for n in 0..2 {
        let a = args(&source, dir.path(), &format!("retry-{n}.pile"), &key);
        let into = a.into.clone();
        execute(source.clone(), a, Mode::Refresh, Stop::Never).unwrap();
        results.push(ids(&into));
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0].records.len(), 1);
    assert_eq!(hash(&source), before);
}

// Exact published framing constants, not new record kinds. This tiny test-only
// raw writer covers the current Branch/Tombstone passthrough allowlist.
fn raw_frame(kind: [u8; 32]) -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[..28].copy_from_slice(&hex_literal::hex!(
        "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B"
    ));
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..64].copy_from_slice(&kind);
    bytes
}
#[test]
fn named_current_allowlist_keeps_raw_frames_and_retired_or_unknown_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), 7);
    let mut branch = raw_frame(frame::BRANCH);
    branch[64..80].fill(1);
    branch[96..128].fill(2);
    let mut tombstone = raw_frame(frame::TOMBSTONE);
    tombstone[64..80].fill(1);
    let mut want = raw_frame(frame::WANT);
    want[64] = 0; // Replaced below by the actual public writer's WANT frame.
    let current = current_source(dir.path());
    let frames = PileRecords::open(&current).unwrap();
    let bytes = frames.bytes().clone();
    for framed in frames {
        let f = framed.unwrap();
        if matches!(f.content, PileRecordContent::Want { .. }) {
            want.copy_from_slice(&bytes[f.offset..f.offset + f.len]);
        }
    }
    let source = dir.path().join("allowlist.pile");
    fresh(
        &source,
        &[
            branch.as_slice(),
            tombstone.as_slice(),
            want.as_slice(),
            want.as_slice(),
        ]
        .concat(),
    );
    let a = args(&source, dir.path(), "allowlist-out.pile", &key);
    let into = a.into.clone();
    run(source, a).unwrap();
    let output = std::fs::read(into).unwrap();
    assert_eq!(
        &output[..1024],
        &[
            branch.as_slice(),
            tombstone.as_slice(),
            want.as_slice(),
            want.as_slice()
        ]
        .concat()
    );
    let retired =
        hex_literal::hex!("EC1C024C04AF08243DB3AE318C93FA500355C74395C0F553CFFC0AF0A4BA0346");
    for (n, kind) in [retired, [0xa5; 32]].into_iter().enumerate() {
        let source = dir.path().join(format!("unsupported-{n}.pile"));
        let mut old = raw_frame(kind);
        old[64..96].copy_from_slice(&want[96..128]);
        fresh(&source, &old);
        let a = args(&source, dir.path(), &format!("refused-{n}.pile"), &key);
        let output = a.into.clone();
        assert!(run(source.clone(), a).is_err());
        assert!(!output.exists());
        // Export reports evidence outside its scope; it is not full migration.
        let a = args(&source, dir.path(), &format!("export-{n}.pile"), &key);
        let report = a.report.clone().unwrap();
        execute(source, a, Mode::Refresh, Stop::Never).unwrap();
        assert!(events(&report)
            .iter()
            .any(|e| e["event"] == "outside-refresh-export"));
        assert_eq!(
            events(&report).last().unwrap()["full_rewrite_obligations_satisfied"],
            false
        );
    }
}

#[test]
fn parser_requires_one_existing_key_contract_and_disallows_report_dryrun() {
    let base = [
        "migrate",
        "canonical",
        "--into",
        "out",
        "--key",
        "key",
        "--source-hash",
        "00",
    ];
    assert!(super::super::Command::try_parse_from(base).is_ok());
    assert!(
        super::super::Command::try_parse_from(base.into_iter().chain(["--key", "other"])).is_err()
    );
    assert!(
        super::super::Command::try_parse_from(base.into_iter().chain([
            "--dry-run",
            "--report",
            "report"
        ]))
        .is_err()
    );
}

#[test]
fn invalid_current_signature_and_truncated_framing_refuse_publication() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let key = key(dir.path(), 7);
    let bytes = std::fs::read(&source).unwrap();
    let offset = PileRecords::open(&source)
        .unwrap()
        .map(Result::unwrap)
        .find(|f| matches!(f.content, PileRecordContent::Collection { .. }))
        .unwrap()
        .offset;
    for variant in 0..2 {
        let mut damaged = bytes.clone();
        if variant == 0 {
            damaged[offset + 255] ^= 1;
        } else {
            damaged.pop();
        }
        let source = dir.path().join(format!("invalid-{variant}.pile"));
        fresh(&source, &damaged);
        let a = args(
            &source,
            dir.path(),
            &format!("invalid-out-{variant}.pile"),
            &key,
        );
        let into = a.into.clone();
        assert!(run(source.clone(), a).is_err());
        assert!(!into.exists());
        assert_eq!(std::fs::read(source).unwrap(), damaged);
    }
}

fn old_fixture(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var_os("LEGACY32_NATIVE_FIXTURES").expect("actual /32 writer fixtures required"),
    )
    .join(name)
}
pub(super) fn exports(source: &Path, dir: &Path) -> Vec<PathBuf> {
    [8, 9]
        .into_iter()
        .map(|n| {
            let key = key(dir, n);
            let a = args(source, dir, &format!("refresh-{n}.pile"), &key);
            let output = a.into.clone();
            execute(source.to_owned(), a, Mode::Refresh, Stop::Never).unwrap();
            output
        })
        .collect()
}

#[test]
#[ignore = "manual: requires independently generated actual /32 native fixtures"]
fn actual_old_writer_requires_exact_foreign_refresh_and_accounts_caches() {
    for name in ["complete.pile", "non-eight.pile", "foreign-cache.pile"] {
        let dir = tempfile::tempdir().unwrap();
        let source = old_fixture(name);
        let before = hash(&source);
        let key = key(dir.path(), 7);
        let missing = args(&source, dir.path(), "missing.pile", &key);
        let output = missing.into.clone();
        assert!(run(source.clone(), missing).is_err());
        assert!(!output.exists());
        let refreshes = exports(&source, dir.path());
        let mut a = args(&source, dir.path(), "converted.pile", &key);
        a.refreshes = refreshes.clone();
        let output = a.into.clone();
        if name == "complete.pile" {
            run(source.clone(), a).unwrap();
        } else {
            assert!(run(source.clone(), a).is_err());
            assert!(!output.exists());
            let mut a = args(&source, dir.path(), "accounted.pile", &key);
            a.refreshes = refreshes;
            a.retain_unconverted_caches = true;
            let report = a.report.clone().unwrap();
            let output = a.into.clone();
            run(source.clone(), a).unwrap();
            assert_eq!(ids(&output).records.len(), 9);
            assert!(events(&report)
                .iter()
                .any(|e| e["disposition"] == "cache-original-only"));
        }
        assert_eq!(hash(&source), before);
    }
}

#[test]
#[ignore = "manual: requires independently generated actual /32 native fixtures"]
fn refresh_does_not_import_grants_blobs_or_unrelated_assertions() {
    use triblespace_core::capability::{CapabilityProof, CapabilityResource};
    use triblespace_core::repo::proof::CapabilityProofStore;
    let dir = tempfile::tempdir().unwrap();
    let source = old_fixture("complete.pile");
    let refreshes = exports(&source, dir.path());
    let mut extra = PileFile::open(&refreshes[0]).unwrap();
    let blob = Blob::<UnknownBlob>::new(Bytes::from_source(b"unrelated refresh blob".to_vec()));
    let handle = extra.put::<UnknownBlob, _>(blob).unwrap();
    let proof = CapabilityProof::new(
        CapabilityResource::new([99; 32]),
        &seed(7),
        Inline::new([98; 32]),
        seed(9).verifying_key(),
    );
    let proof_id = proof.id().raw;
    extra.insert_proof(proof).unwrap();
    let unrelated = CollectionRecord::Commit(CollectionCommit::sign(
        &seed(8),
        Inline::new([97; 32]),
        Inline::new(handle.raw),
        Inline::new([96; 32]),
    ));
    extra.insert(unrelated).unwrap();
    extra.close().unwrap();
    let key = key(dir.path(), 7);
    let mut a = args(&source, dir.path(), "isolated-refresh.pile", &key);
    a.refreshes = refreshes;
    let into = a.into.clone();
    run(source, a).unwrap();
    let result = ids(&into);
    assert_eq!(result.records.len(), 9);
    assert!(result.records.get(&unrelated.fingerprint().raw()).is_none());
    assert!(result.blobs.get(&handle.raw).is_none());
    assert!(result.proofs.get(&proof_id).is_none());
}

#[test]
#[ignore = "manual: requires independently generated actual /32 native fixtures"]
fn local_substitution_and_wrong_metadata_in_native_refresh_cannot_satisfy_foreign_foundation() {
    let dir = tempfile::tempdir().unwrap();
    let source = old_fixture("complete.pile");
    let refreshes = exports(&source, dir.path());
    let key = key(dir.path(), 7);
    for variant in 0..2 {
        let bad_path = dir.path().join(format!("wrong-refresh-{variant}.pile"));
        fresh(&bad_path, &[]);
        let mut pile = PileFile::open(&bad_path).unwrap();
        for f in PileRecords::open(&refreshes[0]).unwrap() {
            if let PileRecordContent::Collection { record } = f.unwrap().content {
                let record = match record {
                    CollectionRecord::Commit(c) => {
                        CollectionRecord::Commit(CollectionCommit::sign(
                            &seed(if variant == 0 { 7 } else { 8 }),
                            c.collection(),
                            c.data(),
                            if variant == 0 {
                                c.metadata()
                            } else {
                                Inline::new([99; 32])
                            },
                        ))
                    }
                    other => other,
                };
                pile.insert(record).unwrap();
            }
        }
        pile.close().unwrap();
        let mut a = args(
            &source,
            dir.path(),
            &format!("wrong-refresh-out-{variant}.pile"),
            &key,
        );
        a.refreshes = vec![bad_path, refreshes[1].clone()];
        let into = a.into.clone();
        assert!(run(source.clone(), a).is_err());
        assert!(!into.exists());
    }
}
