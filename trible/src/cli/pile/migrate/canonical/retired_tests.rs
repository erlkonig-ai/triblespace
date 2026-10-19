//! Closed synthetic sources and existing golden signatures only. No live pile,
//! environment-selected fixture, network, private key discovery or runtime edit.
use super::*;
use hex_literal::hex;

// Literal signatures/fields from core records.rs's existing
// retired_live_equations_keep_their_fields_and_golden_bytes test. This is only
// a native-envelope fixture writer, not a new retired signer or decoder.
fn retired_frame(merge: bool) -> Vec<u8> {
    let author = hex!("EA4A6C63E29C520ABEF5507B132EC5F9954776AEBEBE7B92421EEA691446D22C");
    let (kind, fields, signature, blocks) = if merge {
        (
            hex!("424E7CF62C69A76E6829DF9F71CDFCB42B2B4795143AC6CC5CFF57F410E287CA"),
            vec![[1; 32], [2; 32], [3; 32], [4; 32], author],
            hex!("39D1BE8DC91EE25298CD4B03D4CDD9D1D021994A0B5999EFCD86F1BB4D87EE08A64EE5C40BBBAA21F01C6963BCF2F259CD76D93CBBB4D4351879CB7167ADB00B"),
            2u32,
        )
    } else {
        (
            hex!("5839C091F53DFDDCC32BB1909471989E3C40F934A64E4A2F7729E610ACF0494F"),
            vec![[2; 32], [3; 32], [4; 32], author],
            hex!("10325E15C286E263AFE7D7219F4F637F852F1EB61ECA68916DA4793C6BE9BAB5287380B741FF9D1AE6AD5FA36329785AAA36C6FAABFEB759A7E5387F1F2D140B"),
            1u32,
        )
    };
    let mut raw = raw_frame(kind).to_vec();
    raw.resize(blocks as usize * 256, 0);
    raw[28..32].copy_from_slice(&blocks.to_le_bytes());
    let mut dense: Vec<_> = fields.into_iter().flatten().collect();
    dense.extend_from_slice(&signature);
    raw[64..64 + dense.len()].copy_from_slice(&dense);
    raw
}

fn old_commit_frame() -> Vec<u8> {
    let (tagged, _) = super::super::conversion_tests::golden(1);
    let mut raw = raw_frame(frame::COMMIT).to_vec();
    raw[64..].copy_from_slice(&tagged[1..]);
    raw
}

fn assert_inert_projection(path: &Path, expected_records: &PATCH<32>) {
    let mut pile = PileFile::open_read_only(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let mut actual = PATCH::new();
    for record in snapshot.records().unwrap() {
        add(&mut actual, record.unwrap().fingerprint().raw());
    }
    assert_eq!(&actual, expected_records);
    // No current membership assertion for either retired equation's output.
    // These selectors do not claim descriptor/admission or computation checks.
    for collection in [1, 2] {
        assert!(snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
                Inline::new([collection; 32]),
                Inline::new([4; 32]),
            )]))
            .unwrap()
            .is_empty());
    }
    assert_eq!(snapshot.retired_collection_equations().count(), 2);
    drop(snapshot);
    pile.close().unwrap();
}

#[test]
fn golden_v8_v9_copy_exact_occurrences_without_reseal_or_current_membership() {
    let dir = tempfile::tempdir().unwrap();
    let merge = retired_frame(true);
    let derive = retired_frame(false);
    let bytes = [merge.as_slice(), derive.as_slice(), merge.as_slice(), derive.as_slice()].concat();
    let source = dir.path().join("retired.pile");
    fresh(&source, &bytes);
    let fingerprints = [
        hex!("BF31C64514D9721278866D2AD87819D0C4282D5AC59A7AEBC37729D078038BDC"),
        hex!("2CEC0E4B0A78362E7EC93F5951B4FE6B1BB8233A1A6377C51ECF455A5B945672"),
    ];
    for (n, framed) in PileRecords::open(&source).unwrap().enumerate() {
        let framed = framed.unwrap();
        let PileRecordContent::RetiredCollectionEquation { equation } = framed.content else {
            panic!("not a native retired equation");
        };
        equation.verify_strict().unwrap();
        assert_eq!(equation.fingerprint().raw(), fingerprints[n % 2]);
        assert!(!supported(framed.content));
    }
    assert_inert_projection(&source, &PATCH::new());
    // Deliberately NOT the golden author: preservation cannot require its key.
    let key = key(dir.path(), 8);
    let a = args(&source, dir.path(), "retained.pile", &key);
    let into = a.into.clone();
    let report = a.report.clone().unwrap();
    run(source.clone(), a).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
    assert_eq!(&std::fs::read(&into).unwrap()[..bytes.len()], &bytes);
    assert_inert_projection(&into, &PATCH::new());
    assert_eq!(PileRecords::open(&into).unwrap().filter(|f| matches!(
        f.as_ref().unwrap().content, PileRecordContent::RetiredCollectionEquation { .. }
    )).count(), 4);
    assert!(ids(&into).records.is_empty());
    let report = events(&report);
    assert_eq!(report.iter().filter(|e| e["retained_inert_evidence"] == true).count(), 4);
    let end = report.last().unwrap();
    assert_eq!(end["event"], "published");
    assert_eq!(end["retained_inert_occurrences"], 4);
    assert_eq!(end["retained_inert_bytes"], bytes.len());
    assert_eq!(end["source_evidence_fully_replaced"], false);
    assert_eq!(end["source_retention_required"], true);
    assert_eq!(report.iter().find(|e| e["event"] == "verified").unwrap()["emitted_occurrences"], 0);
    assert!(!partial_path(&into).exists());
}

#[test]
fn mixed_current_old32_and_retired_preserve_the_exact_filtered_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let current_path = current_source(dir.path());
    let current = std::fs::read(&current_path).unwrap();
    let merge = retired_frame(true);
    let derive = retired_frame(false);
    let old = old_commit_frame();
    let source_bytes = [merge.as_slice(), &current, &old, &derive, &merge, &derive].concat();
    let prefix = [merge.as_slice(), &current, &derive, &merge, &derive].concat();
    let source = dir.path().join("mixed.pile");
    fresh(&source, &source_bytes);
    assert_inert_projection(&source, &ids(&current_path).records);
    let key = key(dir.path(), 7);
    let a = args(&source, dir.path(), "mixed-out.pile", &key);
    let into = a.into.clone();
    run(source.clone(), a).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), source_bytes);
    assert_eq!(&std::fs::read(&into).unwrap()[..prefix.len()], &prefix);
    let mut expected = ids(&current_path).records;
    let converted = CollectionCommit::sign(
        &seed(7), Inline::new([1; 32]), Inline::new([2; 32]), Inline::new([3; 32]),
    );
    add(&mut expected, converted.fingerprint().raw());
    assert_eq!(expected.len(), 4);
    assert_inert_projection(&into, &expected);
    assert!(PileRecords::open(&into).unwrap().all(|f| !matches!(
        f.unwrap().content,
        PileRecordContent::Collection { record: CollectionRecord::Derive(_) }
    )));
}

#[test]
fn refresh_excludes_both_retired_kinds_even_for_the_original_author() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = [retired_frame(true), retired_frame(false)].concat();
    let source = dir.path().join("retired-refresh-source.pile");
    fresh(&source, &bytes);
    let key = key(dir.path(), 7);
    let a = args(&source, dir.path(), "retired-refresh.pile", &key);
    let into = a.into.clone();
    let report = a.report.clone().unwrap();
    execute(source.clone(), a, Mode::Refresh, Stop::Never).unwrap();
    assert_eq!(std::fs::read(source).unwrap(), bytes);
    assert!(ids(&into).records.is_empty());
    assert!(PileRecords::open(&into).unwrap().all(|f| !matches!(
        f.unwrap().content, PileRecordContent::RetiredCollectionEquation { .. }
    )));
    let report = events(&report);
    assert_eq!(report.iter().filter(|e| e["event"] == "outside-refresh-export").count(), 2);
    assert_eq!(report.last().unwrap()["retained_inert_occurrences"], 0);
    assert_eq!(report.last().unwrap()["full_rewrite_obligations_satisfied"], false);
}

#[test]
fn forged_retired_fields_author_and_signature_refuse_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), 7);
    for merge in [false, true] {
        // Every semantic field, author, R and S; merge padding tested separately.
        for field in 0..if merge { 7 } else { 6 } {
            let mut damaged = retired_frame(merge);
            damaged[64 + field * 32 + 31] ^= 1;
            let source = dir.path().join(format!("forged-{merge}-{field}.pile"));
            fresh(&source, &damaged);
            let a = args(&source, dir.path(), &format!("forged-out-{merge}-{field}.pile"), &key);
            let into = a.into.clone();
            let report = a.report.clone().unwrap();
            assert!(run(source.clone(), a).is_err());
            assert!(!into.exists());
            assert_eq!(std::fs::read(&source).unwrap(), damaged);
            assert_eq!(events(&report).last().unwrap()["event"], "unsuccessful");
            // Audit still verifies signatures even with a matching prefix hash.
            assert!(audit(&source, &Ids::default(), damaged.len(), blake3::hash(&damaged)).is_err());
        }
    }
}

#[test]
fn malformed_retired_envelopes_padding_and_tails_refuse_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), 7);
    for merge in [false, true] {
        for variant in 0..6 {
            let mut damaged = retired_frame(merge);
            match variant {
                0 => damaged[0] ^= 1,
                1 => damaged[32..64].fill(0xa5), // Unknown kind, not an allowlist extension.
                2 => damaged[28..32].fill(0),
                3 => {
                    let blocks = if merge { 1u32 } else { 2u32 };
                    damaged[28..32].copy_from_slice(&blocks.to_le_bytes());
                    damaged.resize(blocks as usize * 256, 0);
                }
                4 => { damaged.pop(); }
                5 if merge => damaged[511] = 1,
                5 => damaged.extend_from_slice(&[0; 31]),
                _ => unreachable!(),
            }
            let source = dir.path().join(format!("envelope-{merge}-{variant}.pile"));
            fresh(&source, &damaged);
            let a = args(&source, dir.path(), &format!("envelope-out-{merge}-{variant}.pile"), &key);
            let into = a.into.clone();
            let report = a.report.clone().unwrap();
            assert!(run(source.clone(), a).is_err());
            assert!(!into.exists());
            assert_eq!(std::fs::read(source).unwrap(), damaged);
            assert_eq!(events(&report).last().unwrap()["event"], "unsuccessful");
        }
    }
}

#[test]
fn audit_rejects_retired_prefix_tamper_removal_and_reordering() {
    let dir = tempfile::tempdir().unwrap();
    let merge = retired_frame(true);
    let derive = retired_frame(false);
    let prefix = [merge.as_slice(), derive.as_slice(), merge.as_slice()].concat();
    let good = dir.path().join("prefix-good.pile");
    fresh(&good, &prefix);
    audit(&good, &Ids::default(), prefix.len(), blake3::hash(&prefix)).unwrap();
    for variant in 0..3 {
        let mut damaged = prefix.clone();
        match variant {
            0 => damaged[100] ^= 1,
            1 => { damaged.drain(..merge.len()); }
            2 => damaged = [derive.as_slice(), merge.as_slice(), merge.as_slice()].concat(),
            _ => unreachable!(),
        }
        let path = dir.path().join(format!("prefix-bad-{variant}.pile"));
        fresh(&path, &damaged);
        assert!(audit(&path, &Ids::default(), prefix.len(), blake3::hash(&prefix)).is_err());
    }
}

#[test]
fn audit_rejects_extra_retired_tail_and_a_frame_crossing_the_prefix_end() {
    let dir = tempfile::tempdir().unwrap();
    for merge in [false, true] {
        let frame = retired_frame(merge);
        let bytes = [frame.as_slice(), frame.as_slice()].concat();
        let path = dir.path().join(format!("tail-{merge}.pile"));
        fresh(&path, &bytes);
        audit(&path, &Ids::default(), bytes.len(), blake3::hash(&bytes)).unwrap();
        // First: a whole extra frame. Second: a valid frame starting before,
        // but ending after, the claimed copied prefix. Both hashes match.
        for copied in [frame.len(), frame.len() + 128] {
            let error = audit(&path, &Ids::default(), copied, blake3::hash(&bytes[..copied]))
                .unwrap_err();
            assert!(format!("{error:#}").contains("not wholly within the copied frame prefix"));
        }
    }
}

#[test]
fn retired_copy_interruptions_keep_source_and_never_publish_completion() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = [retired_frame(true), retired_frame(false), old_commit_frame()].concat();
    let source = dir.path().join("interrupt-source.pile");
    fresh(&source, &bytes);
    let key = key(dir.path(), 7);
    for (n, stop) in [Stop::AfterCopy, Stop::AfterAssertion, Stop::BeforePublish].into_iter().enumerate() {
        let a = args(&source, dir.path(), &format!("interrupt-{n}.pile"), &key);
        let into = a.into.clone();
        let report = a.report.clone().unwrap();
        assert!(execute(source.clone(), a, Mode::Rewrite, stop).is_err());
        assert!(!into.exists() && partial_path(&into).exists());
        assert_eq!(std::fs::read(&source).unwrap(), bytes);
        let report = events(&report);
        assert_eq!(report.last().unwrap()["event"], "unsuccessful");
        assert!(!report.iter().any(|e| e["event"] == "published"));
    }
}
