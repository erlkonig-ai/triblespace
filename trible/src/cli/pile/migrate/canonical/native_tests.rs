//! Native API controls; manual interoperability uses the preserved unmodified
//! deployed3ca writer packet, never this converter's mirrored test codec.
use super::*;
use crate::migration::{
    inspect, prepare_canonical, prepare_canonical_with_progress, CanonicalOutcome, Stage,
};

#[test]
fn native_preserves_current_authors_and_rejects_every_existing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let before = hash(&source);
    let destination = dir.path().join("native.pile");
    let outcome = prepare_canonical(&source, &destination, &seed(7), &[]).unwrap();
    assert!(matches!(
        outcome,
        CanonicalOutcome::Converted {
            emitted_assertions: 0,
            retained_original_caches: 0,
            ..
        }
    ));
    assert_eq!(ids(&destination).records, ids(&source).records);
    assert_eq!(hash(&source), before);
    assert!(!partial_path(&destination).exists());
    let hard = dir.path().join("hard.pile");
    std::fs::hard_link(&source, &hard).unwrap();
    let link = dir.path().join("link.pile");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    let dangling = dir.path().join("dangling.pile");
    std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
    for target in [&source, &destination, &hard, &link, &dangling] {
        assert!(prepare_canonical(&source, target, &seed(7), &[]).is_err());
    }
    assert_eq!(hash(&source), before);
}

#[test]
fn native_cancellation_and_source_change_never_publish() {
    for stage in [Stage::Canonical, Stage::Audit, Stage::Ready] {
        let dir = tempfile::tempdir().unwrap();
        let source = current_source(dir.path());
        let before = hash(&source);
        let destination = dir.path().join("cancelled.pile");
        let mut reached = false;
        let result =
            prepare_canonical_with_progress(&source, &destination, &seed(7), &[], &mut |p| {
                if p.stage == stage {
                    reached = true;
                    false
                } else {
                    true
                }
            });
        assert!(reached && result.is_err());
        assert!(!destination.exists());
        assert_eq!(hash(&source), before);
        assert!(prepare_canonical(&source, &destination, &seed(7), &[]).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let source = current_source(dir.path());
    let destination = dir.path().join("changed.pile");
    let mut changed = false;
    let result = prepare_canonical_with_progress(&source, &destination, &seed(7), &[], &mut |p| {
        if p.stage == Stage::Ready {
            OpenOptions::new()
                .append(true)
                .open(&source)
                .unwrap()
                .write_all(b"appended after audit")
                .unwrap();
            changed = true;
        }
        true
    });
    assert!(changed && result.is_err());
    assert!(!destination.exists());
}

// Exact retained actual-writer packet: deployed3ca5c1cb5504d8ff60730edfe5bf641b01f44913,
// producer tree2d9a7816e42dc4ba2962e6a61060a6913f699872 (only example added).
// Runtime signing/framing code was unmodified. These payloads are opaque,
// therefore these tests establish storage interoperability, not app readiness.
fn actual_fixture(name: &str) -> PathBuf {
    let path = old_fixture(name);
    let expected = match name {
        "complete.pile" => "53d9bc487d92574f702a9d30c47de4823ad84b3cb9a0a97b90481de4aed108f3",
        "non-eight.pile" => "dbd3851c70fef4814c48e78566bb350b78a1f1555cd78ae26b3cbcb10b0ef1ca",
        "foreign-cache.pile" => "2436bc7946283455f65ff1d1a3ce9d324b3b669c85d629a3f4f963340d0a3c41",
        _ => unreachable!(),
    };
    assert_eq!(
        hash(&path),
        expected,
        "requires the exact retained actual-writer fixture"
    );
    path
}

#[test]
#[ignore = "requires preserved actual deployed /32 writer fixtures"]
fn actual_writer_owned_assertions_convert_without_a_key_file_or_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let packet = actual_fixture("complete.pile");
    let frames = PileRecords::open(&packet).unwrap();
    let bytes = frames.bytes().clone();
    let signer = seed(7);
    let source = dir.path().join("owned.pile");
    let mut own = Vec::new();
    let mut assertions = 0;
    // Select an author's intact assertions from the real writer packet. All
    // blobs/proofs stay intact; no old framing or signature is generated here.
    for framed in frames {
        let framed = framed.unwrap();
        let raw = &bytes[framed.offset..framed.offset + framed.len];
        if let PileRecordContent::Opaque {
            kind: OpaqueKind::Described(kind),
        } = framed.content
        {
            if frame::supported(kind) {
                let tagged = frame::tagged(kind, raw).unwrap();
                let old = legacy32::verified(&tagged).unwrap();
                if old.author != signer.verifying_key().to_bytes() {
                    continue;
                }
                assertions += 1;
            }
        }
        own.extend_from_slice(raw);
    }
    assert_eq!(assertions, 5);
    fresh(&source, &own);
    let destination = dir.path().join("converted.pile");
    let outcome = prepare_canonical(&source, &destination, &signer, &[]).unwrap();
    assert_eq!(
        outcome,
        CanonicalOutcome::Converted {
            destination: destination.clone(),
            source_hash: *blake3::hash(&own).as_bytes(),
            emitted_assertions: 5,
            retained_original_caches: 0,
        }
    );
    assert_eq!(ids(&destination).records.len(), 5);
    for blob in ids(&source).blobs.iter() {
        assert!(ids(&destination).blobs.get(&blob).is_some());
    }
    assert_eq!(ids(&destination).proofs, ids(&source).proofs);
    assert!(inspect(&destination).unwrap().requirements.is_empty());
    assert_eq!(std::fs::read(&source).unwrap(), own);
}

#[test]
#[ignore = "requires preserved actual deployed /32 writer fixtures"]
fn actual_writer_foreign_refreshes_and_retained_caches_are_typed() {
    for name in ["complete.pile", "non-eight.pile", "foreign-cache.pile"] {
        let dir = tempfile::tempdir().unwrap();
        let source = actual_fixture(name);
        let before = hash(&source);
        let destination = dir.path().join("missing.pile");
        let mut authors = vec![
            seed(8).verifying_key().to_bytes(),
            seed(9).verifying_key().to_bytes(),
        ];
        authors.sort();
        assert_eq!(
            prepare_canonical(&source, &destination, &seed(7), &[]).unwrap(),
            CanonicalOutcome::ForeignRefreshRequired { authors }
        );
        assert!(!destination.exists());
        let refreshes = exports(&source, dir.path());
        let destination = dir.path().join("converted.pile");
        let outcome = prepare_canonical(&source, &destination, &seed(7), &refreshes).unwrap();
        assert_eq!(
            outcome,
            CanonicalOutcome::Converted {
                destination: destination.clone(),
                source_hash: hex::decode(&before).unwrap().try_into().unwrap(),
                emitted_assertions: 9,
                retained_original_caches: if name == "complete.pile" { 0 } else { 1 },
            }
        );
        assert_eq!(ids(&destination).records.len(), 9);
        for blob in ids(&source).blobs.iter() {
            assert!(ids(&destination).blobs.get(&blob).is_some());
        }
        assert_eq!(hash(&source), before);
    }
}
