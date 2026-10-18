//! Synthetic offline conversion only. No Pile, filesystem, credentials or admission.
use super::legacy32;

use ed25519_dalek::{Signer, SigningKey};
use hex_literal::hex;
use legacy32::{convert, Input, Invalid, Kind, Outcome, Unresolved};
use triblespace_core::capability::{CapabilityHandle, CapabilityProof, CapabilityResource};
use triblespace_core::collection::records::{
    CollectionCommit, CollectionDerive, CollectionRecord, SourceLocator, KIND_COLLECTION_COMMIT,
    KIND_COLLECTION_DERIVE,
};
use triblespace_core::inline::Inline;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn converted(result: &legacy32::Conversion<'_>) -> CollectionRecord {
    match result.outcome {
        Outcome::Converted {
            record,
            new_fingerprint,
        } => {
            record.verify_strict().unwrap();
            assert_eq!(record.fingerprint().raw(), new_fingerprint);
            assert_eq!(
                *blake3::hash(&record.to_bytes()).as_bytes(),
                new_fingerprint
            );
            assert_ne!(result.old_fingerprint, Some(new_fingerprint));
            record
        }
        ref other => panic!("expected conversion, got {other:?}"),
    }
}

// Independent old-codec vectors copied from deployed3ca5c1cb records.rs:2774-2871,
// Git blob5783570aa228ff80213131b3acb5b5f8634d8cbb. Literal old signatures and
// fingerprints, not values recomputed by the converter's transcript helper.
fn golden(tag: u8) -> (Vec<u8>, [u8; 32]) {
    let author = hex!("EA4A6C63E29C520ABEF5507B132EC5F9954776AEBEBE7B92421EEA691446D22C");
    let (fields, signature, fingerprint) = match tag {
        1 => (
            vec![[1; 32], [2; 32], [3; 32], author],
            hex!("F89FCF5C72BC7EC3E376C6AB6BDEFC6ECEA3ADBBCA7A36DBF1729413A7820564F684108AF3E8E3898904D20EA458DCAE68F0F97F4E5C06DAFA0FAE0691F68D0B"),
            hex!("B1740DE9C272B4552B97EDDF77C796D72688A2B9325D815C302236882657E608"),
        ),
        9 => (
            vec![[2; 32], SourceLocator::of([3; 32]).raw(), [4; 32], author],
            hex!("BD0AB9CD39C01F21FF7C81657DF0B9B478962047052CB49E2E557B9966510F27FAD9550769E6A31891CF5A0E8B0F175B12FD5CFBA731775476553141644ABC06"),
            hex!("2CA5233360BA208B1EE09C0B79CA064578BC79D1EB84E449282500A070A422BF"),
        ),
        8 => (
            vec![[1; 32], [4; 32], author],
            hex!("D55D87F954FE0387950F87A83854023A7523AFEF609DAEFC459FD07132DCBDD2C8A9FF024376020A24E4E00394C82E71B33F34B4552D51953D49EDDB51869308"),
            hex!("2B3A051CFECDCDA75BCEE8CE25157B38632FEC992902D95082DCA1710C2068A9"),
        ),
        _ => unreachable!(),
    };
    let mut bytes = vec![tag];
    for field in fields {
        bytes.extend_from_slice(&field)
    }
    bytes.extend_from_slice(&signature);
    if tag == 8 {
        bytes.extend_from_slice(&[0; 28]);
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&[3; 32]);
    }
    (bytes, fingerprint)
}

// Mirrored old grammar for adversarial synthetic controls only. Interoperability
// is established separately by the literal deployed-codec vectors above.
fn synthetic(tag: u8, signer: &SigningKey, third: [u8; 32], count: u32) -> Vec<u8> {
    let (domain, semantic): (&[u8], [u8; 16]) = match tag {
        1 => (
            b"triblespace.collection.commit.transcript",
            hex!("B34817308188C4515A3C51967A91A603"),
        ),
        9 => (
            &hex!("3F33151333CCDE3566D792C723DF70A74ACCF357CD0B9A7E7E1C61913020D22F"),
            hex!("630BF5B294A3A1D85C0A7B185C9BC899"),
        ),
        10 => (
            &hex!("4A5191C36898D0B453FEFF99ED0E38524AADD87ED8EB8620BD39623B5221B5BE"),
            hex!("329669AA662709605053C123671DF1D2"),
        ),
        8 => (
            &hex!("B75F4382781F565972D759D69C72703B2A2E525B9D3B13A249590235C7BE8C40"),
            hex!("D0D98881093C0A6F318E1E1525521F80"),
        ),
        _ => unreachable!(),
    };
    let author = signer.verifying_key().to_bytes();
    let mut transcript = domain.to_vec();
    transcript.extend_from_slice(&semantic);
    if tag == 1 {
        transcript.extend_from_slice(&2u32.to_be_bytes())
    }
    transcript.extend_from_slice(&author);
    transcript.extend_from_slice(&[1; 32]);
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&[1; 32]);
    if tag == 8 {
        transcript.extend_from_slice(&count.to_be_bytes());
        for n in 1..=count {
            transcript.extend_from_slice(&[n as u8; 32]);
        }
        transcript.extend_from_slice(&third);
        bytes.extend_from_slice(&third);
        bytes.extend_from_slice(&author);
    } else {
        transcript.extend_from_slice(&[2; 32]);
        transcript.extend_from_slice(&third);
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&third);
        bytes.extend_from_slice(&author);
    }
    bytes.extend_from_slice(&signer.sign(&transcript).to_bytes());
    if tag == 8 {
        bytes.extend_from_slice(&[0; 28]);
        bytes.extend_from_slice(&count.to_be_bytes());
        for n in 1..=count {
            bytes.extend_from_slice(&[n as u8; 32]);
        }
    }
    bytes
}

#[test]
fn deployed_vectors_verify_and_convert_to_current_literal_prefix() {
    let signer = key(7);
    for tag in [1, 9, 8] {
        let (bytes, fingerprint) = golden(tag);
        let result = convert(Input::TaggedCollection(&bytes), Some(&signer));
        assert_eq!(result.original, bytes);
        assert_eq!(result.old_fingerprint, Some(fingerprint));
        println!(
            "deployed3ca tag={tag} fingerprint={} bytes={}",
            hex::encode(fingerprint),
            hex::encode(&bytes)
        );
        if tag == 8 {
            assert!(matches!(
                result.outcome,
                Outcome::Unresolved(Unresolved::CacheDispositionRequired {
                    kind: Kind::Merge,
                    ..
                })
            ));
            continue;
        }
        let record = converted(&result);
        let expected = if tag == 1 {
            CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                Inline::new([1; 32]),
                Inline::new([2; 32]),
                Inline::new([3; 32]),
            ))
        } else {
            CollectionRecord::Derive(CollectionDerive::sign(
                &signer,
                Inline::new([2; 32]),
                SourceLocator::of([3; 32]),
                Inline::new([4; 32]),
            ))
        };
        assert_eq!(record, expected);
        let canonical = record.to_bytes();
        assert_eq!(canonical.len(), 224);
        assert_eq!(
            canonical[..32],
            if tag == 1 {
                KIND_COLLECTION_COMMIT
            } else {
                KIND_COLLECTION_DERIVE
            }
        );
        assert_eq!(&canonical[128..160], signer.verifying_key().as_bytes());
        let signature = ed25519_dalek::Signature::from_slice(&canonical[160..]).unwrap();
        signer
            .verifying_key()
            .verify_strict(&canonical[..160], &signature)
            .unwrap();
        if tag == 9 {
            assert_eq!(&canonical[32..64], &bytes[1..33]);
            assert_eq!(&canonical[64..96], &bytes[65..97]);
            assert_eq!(&canonical[96..128], &bytes[33..65]);
        }
        assert!(CollectionRecord::from_bytes(&bytes).is_err());
        println!(
            "canonical tag={tag} fingerprint={} bytes={}",
            hex::encode(record.fingerprint().raw()),
            hex::encode(canonical)
        );
    }
}

#[test]
fn three_signers_same_payload_never_substitute_authorship_or_metadata() {
    let a = key(7);
    let b = key(8);
    let c = key(9);
    for tag in [1, 9] {
        let original_a = synthetic(tag, &a, [3; 32], 0);
        let different_metadata_or_output = synthetic(tag, &a, [4; 32], 0);
        let first = converted(&convert(Input::TaggedCollection(&original_a), Some(&a)));
        let different = converted(&convert(
            Input::TaggedCollection(&different_metadata_or_output),
            Some(&a),
        ));
        assert_ne!(first.fingerprint(), different.fingerprint());
        for foreign in [&b, &c] {
            let bytes = synthetic(tag, foreign, [3; 32], 0);
            let missing = convert(Input::TaggedCollection(&bytes), None);
            assert!(matches!(
                missing.outcome,
                Outcome::Unresolved(Unresolved::SignerUnavailable { .. })
            ));
            let wrong = convert(Input::TaggedCollection(&bytes), Some(&a));
            assert_eq!(wrong.original, bytes);
            assert!(matches!(
                wrong.outcome,
                Outcome::Unresolved(Unresolved::SignerMismatch { .. })
            ));
            // Supplying that actual signer explicitly changes key availability,
            // not author identity. No admission inference is made either way.
            let own = converted(&convert(Input::TaggedCollection(&bytes), Some(foreign)));
            assert_eq!(own.public_key().raw, foreign.verifying_key().to_bytes());
            assert_ne!(first.fingerprint(), own.fingerprint());
        }
    }
}

#[test]
fn verification_precedes_key_selection_and_preserves_invalid_originals() {
    for tag in [1, 9] {
        let (original, _) = golden(tag);
        for offset in [1, 33, 65, 129, 161] {
            let mut bad = original.clone();
            bad[offset] ^= 1;
            let result = convert(Input::TaggedCollection(&bad), None);
            assert!(matches!(
                result.outcome,
                Outcome::Invalid(Invalid::Signature)
            ));
            assert_eq!(result.original.as_ptr(), bad.as_ptr());
            assert!(result.old_fingerprint.is_some());
        }
        let mut bad_key = original.clone();
        bad_key[97..129].fill(0);
        assert!(matches!(
            convert(Input::TaggedCollection(&bad_key), Some(&key(7))).outcome,
            Outcome::Invalid(Invalid::PublicKey)
        ));
    }
}

#[test]
fn valid_caches_require_disposition_for_every_signer_and_arity() {
    for author in [7, 8, 9] {
        for count in [2, 8, 16] {
            let bytes = synthetic(8, &key(author), [20; 32], count);
            let result = convert(Input::TaggedCollection(&bytes), Some(&key(7)));
            assert!(matches!(
                result.outcome,
                Outcome::Unresolved(Unresolved::CacheDispositionRequired {
                    kind: Kind::Merge,
                    ..
                })
            ));
            assert_eq!(result.original, bytes);
        }
        let mut bytes = synthetic(10, &key(author), [3; 32], 0);
        assert!(matches!(
            convert(Input::TaggedCollection(&bytes), Some(&key(7))).outcome,
            Outcome::Unresolved(Unresolved::CacheDispositionRequired {
                kind: Kind::Map,
                ..
            })
        ));
        bytes[161] ^= 1;
        assert!(matches!(
            convert(Input::TaggedCollection(&bytes), None).outcome,
            Outcome::Invalid(Invalid::Signature)
        ));
    }
}

#[test]
fn malformed_and_unsupported_inputs_are_preserved_without_guessing_formats() {
    assert!(matches!(
        convert(Input::TaggedCollection(&[]), None).outcome,
        Outcome::Invalid(Invalid::Length)
    ));
    for tag in [2, 3, 4, 5, 6, 7, 11, 12, 255] {
        let bytes = vec![tag, 99, 88];
        let result = convert(Input::TaggedCollection(&bytes), Some(&key(7)));
        assert!(
            matches!(result.outcome, Outcome::Unresolved(Unresolved::UnsupportedHistoricalKind(n)) if n == tag)
        );
        assert_eq!(result.original, bytes);
        assert_eq!(result.old_fingerprint, None);
    }
    for count in [1, 17] {
        let bytes = synthetic(8, &key(7), [20; 32], count);
        assert!(matches!(
            convert(Input::TaggedCollection(&bytes), None).outcome,
            Outcome::Invalid(Invalid::MergeCount)
        ));
    }
    let (good, _) = golden(8);
    let mut padding = good.clone();
    padding[161] = 1;
    assert!(matches!(
        convert(Input::TaggedCollection(&padding), None).outcome,
        Outcome::Invalid(Invalid::MergePadding)
    ));
    let mut order = good.clone();
    order[193..225].fill(3);
    assert!(matches!(
        convert(Input::TaggedCollection(&order), None).outcome,
        Outcome::Invalid(Invalid::MergeInputOrder)
    ));
    assert!(matches!(
        convert(Input::TaggedCollection(&good[..good.len() - 1]), None).outcome,
        Outcome::Invalid(Invalid::Length)
    ));
}

#[test]
fn auth_uses_existing_verifier_and_returns_exact_original_bytes() {
    let a = key(7);
    let b = key(8);
    let c = key(9);
    let proof = CapabilityProof::new(
        CapabilityResource::new([1; 32]),
        &a,
        CapabilityHandle::new([2; 32]),
        b.verifying_key(),
    )
    .delegate(&b, CapabilityHandle::new([3; 32]), c.verifying_key())
    .unwrap();
    let result = convert(Input::Auth(proof.as_bytes()), None);
    assert_eq!(result.original.as_ptr(), proof.as_bytes().as_ptr());
    assert!(matches!(result.outcome, Outcome::UnchangedAuth { id } if id == proof.id().raw));
    assert_eq!(result.old_fingerprint, None);
    let mut tampered = proof.as_bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        convert(Input::Auth(&tampered), Some(&a)).outcome,
        Outcome::Invalid(Invalid::AuthSignature)
    ));
    assert!(matches!(
        convert(Input::Auth(&[0; 224]), None).outcome,
        Outcome::Invalid(Invalid::AuthStructure)
    ));
}

#[test]
fn repeatability_and_partial_batch_are_not_completion_or_foreign_refresh() {
    let a = key(7);
    let originals = [golden(1).0, golden(9).0, synthetic(1, &key(8), [3; 32], 0)];
    let first = converted(&convert(Input::TaggedCollection(&originals[0]), Some(&a)));
    // Simulated interruption: caller has consumed only the first result. There
    // is no batch completion/durability API or receipt to accidentally publish.
    let resumed: Vec<_> = originals
        .iter()
        .map(|bytes| convert(Input::TaggedCollection(bytes), Some(&a)))
        .collect();
    assert_eq!(converted(&resumed[0]), first);
    converted(&resumed[1]);
    assert!(matches!(
        resumed[2].outcome,
        Outcome::Unresolved(Unresolved::SignerMismatch { .. })
    ));
    for (bytes, outcome) in originals.iter().zip(&resumed) {
        assert_eq!(outcome.original, bytes);
    }
    let retry = convert(Input::TaggedCollection(&originals[1]), Some(&a));
    assert_eq!(converted(&resumed[1]), converted(&retry));
}
