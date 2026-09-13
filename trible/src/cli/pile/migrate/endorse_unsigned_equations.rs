//! Add current writer endorsements without altering historical unsigned evidence.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace_core::collection::{
    collection_capability_audience, write_capability, CollectionDerive, CollectionHandle,
    CollectionMerge, CollectionRead, CollectionReadAudience, CollectionRecord, CollectionStore,
    LegacyUnsignedCollectionEquation,
};
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStoreList, SnapshotSource};

#[derive(Debug, Default, Eq, PartialEq)]
struct Report {
    endorsed: usize,
    already_present: usize,
    missing_references: usize,
}

pub(super) fn run(
    path: PathBuf,
    collection: String,
    signing_key: PathBuf,
    dry_run: bool,
) -> Result<()> {
    let text = collection.trim();
    let raw = text.strip_prefix("blake3:").unwrap_or(text);
    let mut bytes = [0; 32];
    hex::decode_to_slice(raw, &mut bytes)
        .context("collection must be blake3:<64 hex digits> or exactly 64 hex digits")?;
    let collection = CollectionHandle::new(bytes);
    let signer = triblespace_core::signing_key_file::load_existing(&signing_key)
        .with_context(|| format!("load existing signing key {}", signing_key.display()))?;
    let mut pile = super::super::open_refreshed(&path)?;
    let result = endorse(&mut pile, collection, &signer, dry_run);
    let close = pile.close().map_err(|error| anyhow!("close pile: {error}"));
    let report = result?;
    close?;
    println!("collection: blake3:{}", hex::encode(collection.raw));
    println!(
        "endorser: {}",
        hex::encode_upper(signer.verifying_key().to_bytes())
    );
    println!(
        "{}: {}; already present: {}; skipped missing references: {}",
        if dry_run { "would endorse" } else { "endorsed" },
        report.endorsed,
        report.already_present,
        report.missing_references,
    );
    println!("Equations were not recomputed; original authorship is not recovered.");
    Ok(())
}

fn endorse(
    pile: &mut Pile,
    collection: CollectionHandle,
    signer: &SigningKey,
    dry_run: bool,
) -> Result<Report> {
    // One immutable observation supplies the descriptor, proofs, authorization
    // instant, old equations, and direct-reference residency for this run.
    let snapshot = pile.snapshot().context("freeze endorsement snapshot")?;
    let admitted = match collection_capability_audience(&snapshot, collection, write_capability())
        .context("inspect target WRITE audience")?
    {
        CollectionReadAudience::Open => true,
        CollectionReadAudience::Restricted(subjects) => subjects.contains(&signer.verifying_key()),
    };
    if !admitted {
        bail!(
            "signer lacks WRITE authority for blake3:{}",
            hex::encode(collection.raw)
        );
    }

    let mut report = Report::default();
    // Distinct historical frames can carry the same equation. This set tracks
    // only this run's receipts, so dry-run and publication count them alike.
    let mut seen = BTreeSet::new();
    for equation in snapshot.legacy_unsigned_collection_equations() {
        if equation.collection() != collection {
            continue;
        }
        let mut resident = true;
        for reference in equation.blob_references() {
            if !snapshot
                .contains_blob(reference)
                .context("inspect direct reference residency")?
            {
                resident = false;
                break;
            }
        }
        if !resident {
            report.missing_references += 1;
            continue;
        }
        let record = match equation {
            LegacyUnsignedCollectionEquation::Merge {
                collection,
                low,
                high,
                result,
            } => CollectionRecord::Merge(CollectionMerge::sign(
                signer, collection, low, high, result,
            )),
            LegacyUnsignedCollectionEquation::Derive {
                collection,
                input,
                output,
            } => {
                CollectionRecord::Derive(CollectionDerive::sign(signer, collection, input, output))
            }
        };
        if !seen.insert(record) {
            continue;
        }
        match snapshot
            .record(record.fingerprint())
            .context("inspect existing endorsement")?
        {
            Some(existing) if existing == record => {
                report.already_present += 1;
                continue;
            }
            Some(_) => bail!(
                "conflicting record at endorsement fingerprint {:X}",
                record.fingerprint()
            ),
            None => {}
        }
        if !dry_run {
            pile.insert(record).context("append writer endorsement")?;
        }
        report.endorsed += 1;
    }
    if !dry_run {
        pile.flush().context("flush writer endorsements")?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use anybytes::Bytes;
    use clap::Parser;
    use tempfile::NamedTempFile;
    use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::BlobStorePut;

    use super::*;

    fn frame(equation: LegacyUnsignedCollectionEquation) -> [u8; 256] {
        let mut bytes = [0; 256];
        // Existing generic pile-frame magic, copied from repo/pile.rs.
        bytes[..28].copy_from_slice(
            &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B").unwrap(),
        );
        bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
        bytes[64..96].copy_from_slice(&equation.collection().raw);
        match equation {
            LegacyUnsignedCollectionEquation::Merge {
                low, high, result, ..
            } => {
                bytes[32..64].copy_from_slice(
                    &hex::decode(
                        "0CEE320DE0BDA40A6A6F52221C5E4E4D2CE3B165B69C858673FD13D98F655379",
                    )
                    .unwrap(),
                );
                bytes[96..128].copy_from_slice(&low.raw);
                bytes[128..160].copy_from_slice(&high.raw);
                bytes[160..192].copy_from_slice(&result.raw);
            }
            LegacyUnsignedCollectionEquation::Derive { input, output, .. } => {
                bytes[32..64].copy_from_slice(
                    &hex::decode(
                        "7ACE1ED10F3EBC632627058CC461DC1CC171CD2E56C52E5DCE60EA4C8DC23C36",
                    )
                    .unwrap(),
                );
                bytes[96..128].copy_from_slice(&input.raw);
                bytes[128..160].copy_from_slice(&output.raw);
            }
        }
        bytes
    }

    fn fixture(
        missing: bool,
    ) -> Result<(
        NamedTempFile,
        SigningKey,
        CollectionHandle,
        Vec<LegacyUnsignedCollectionEquation>,
    )> {
        let file = NamedTempFile::new()?;
        let signer = SigningKey::from_bytes(&[42; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(signer.verifying_key()),
        );
        let mut pile = Pile::open(file.path())?;
        let source = pile.collection("endorsement-source", policy.clone())?;
        let target = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())?
            .handle();
        let unselected = pile
            .collection("unselected-endorsement-target", policy)?
            .handle();
        // Deliberately not encoded lattice members: endorsement never decodes
        // or recomputes historical inputs/results, it asserts these endpoints.
        let mut inputs = Vec::new();
        for payload in [b"left".as_slice(), b"right", b"result"] {
            let handle = pile.put::<UnknownBlob, _>(Bytes::from_source(payload.to_vec()))?;
            inputs.push(Handle::<UnknownBlob>::to_hash(handle));
        }
        inputs[..2].sort_unstable();
        let equations = vec![
            LegacyUnsignedCollectionEquation::Merge {
                collection: target,
                low: inputs[0],
                high: inputs[1],
                result: inputs[2],
            },
            LegacyUnsignedCollectionEquation::Derive {
                collection: target,
                input: inputs[0],
                output: if missing {
                    Inline::new([0xff; 32])
                } else {
                    inputs[2]
                },
            },
            // Same admitted signer and resident endpoints; only the exact
            // collection selection keeps this equation out of the run.
            LegacyUnsignedCollectionEquation::Merge {
                collection: unselected,
                low: inputs[0],
                high: inputs[1],
                result: inputs[2],
            },
        ];
        pile.close()?;
        let mut append = OpenOptions::new().append(true).open(file.path())?;
        for equation in &equations {
            append.write_all(&frame(*equation))?;
        }
        append.sync_all()?;
        Ok((file, signer, target, equations))
    }

    #[test]
    fn authorized_endorsements_preserve_frames_endpoints_and_repeat_without_append() -> Result<()> {
        let (file, signer, target, equations) = fixture(false)?;
        let original = fs::read(file.path())?;
        let mut pile = super::super::super::open_refreshed(file.path())?;
        assert_eq!(
            endorse(&mut pile, target, &signer, false)?,
            Report {
                endorsed: 2,
                ..Report::default()
            }
        );
        let after = fs::read(file.path())?;
        assert_eq!(&after[..original.len()], original);
        let snapshot = pile.snapshot()?;
        assert_eq!(
            snapshot
                .legacy_unsigned_collection_equations()
                .collect::<BTreeSet<_>>(),
            equations.iter().copied().collect()
        );
        let records = snapshot.records()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(records.len(), 2);
        for record in records {
            record.verify_strict()?;
            assert_eq!(record.public_key().raw, signer.verifying_key().to_bytes());
            assert_eq!(record.collection(), target);
            let original_equation = match record {
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    LegacyUnsignedCollectionEquation::Merge {
                        collection: merge.collection(),
                        low,
                        high,
                        result: merge.result(),
                    }
                }
                CollectionRecord::Derive(derive) => LegacyUnsignedCollectionEquation::Derive {
                    collection: derive.collection(),
                    input: derive.input(),
                    output: derive.output(),
                },
                CollectionRecord::Commit(_) => panic!("endorsement must not create COMMITs"),
            };
            assert!(equations.contains(&original_equation));
        }
        drop(snapshot);
        assert_eq!(
            endorse(&mut pile, target, &signer, false)?,
            Report {
                already_present: 2,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(file.path())?, after);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn unauthorized_writer_and_dry_run_leave_the_entire_pile_unchanged() -> Result<()> {
        let (file, signer, target, _) = fixture(false)?;
        let original = fs::read(file.path())?;
        let mut pile = super::super::super::open_refreshed(file.path())?;
        let outsider = SigningKey::from_bytes(&[43; 32]);
        assert!(endorse(&mut pile, target, &outsider, false)
            .unwrap_err()
            .to_string()
            .contains("lacks WRITE authority"));
        assert_eq!(fs::read(file.path())?, original);
        assert_eq!(
            endorse(&mut pile, target, &signer, true)?,
            Report {
                endorsed: 2,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(file.path())?, original);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn missing_direct_references_are_skipped_without_losing_legacy_evidence() -> Result<()> {
        let (file, signer, target, equations) = fixture(true)?;
        let original = fs::read(file.path())?;
        let mut pile = super::super::super::open_refreshed(file.path())?;
        assert_eq!(
            endorse(&mut pile, target, &signer, false)?,
            Report {
                endorsed: 1,
                missing_references: 1,
                already_present: 0
            }
        );
        let snapshot = pile.snapshot()?;
        assert_eq!(
            snapshot.legacy_unsigned_collection_equations().count(),
            equations.len()
        );
        assert_eq!(snapshot.records()?.count(), 1);
        assert_eq!(&fs::read(file.path())?[..original.len()], original);
        drop(snapshot);
        pile.close()?;
        Ok(())
    }

    #[test]
    fn missing_existing_key_never_creates_a_key_or_modifies_the_pile() -> Result<()> {
        let (file, _, target, _) = fixture(false)?;
        let original = fs::read(file.path())?;
        let directory = tempfile::tempdir()?;
        let key = directory.path().join("absent.key");
        assert!(run(
            file.path().to_path_buf(),
            hex::encode(target.raw),
            key.clone(),
            false
        )
        .is_err());
        assert!(!key.exists());
        assert_eq!(fs::read(file.path())?, original);
        Ok(())
    }

    #[test]
    fn command_uses_the_explicit_existing_key_and_preserves_it() -> Result<()> {
        let (file, signer, target, _) = fixture(false)?;
        let key = NamedTempFile::new()?;
        let key_bytes = hex::encode(signer.to_bytes());
        fs::write(key.path(), key_bytes.as_bytes())?;
        let original = fs::read(file.path())?;
        let collection = format!("blake3:{}", hex::encode(target.raw));
        run(
            file.path().to_path_buf(),
            collection.clone(),
            key.path().to_path_buf(),
            true,
        )?;
        assert_eq!(fs::read(file.path())?, original);
        run(
            file.path().to_path_buf(),
            collection.clone(),
            key.path().to_path_buf(),
            false,
        )?;
        let endorsed = fs::read(file.path())?;
        assert!(endorsed.len() > original.len());
        run(
            file.path().to_path_buf(),
            collection,
            key.path().to_path_buf(),
            false,
        )?;
        assert_eq!(fs::read(file.path())?, endorsed);
        assert_eq!(fs::read(key.path())?, key_bytes.as_bytes());
        Ok(())
    }

    #[test]
    fn command_requires_collection_and_signing_key() {
        let prefix = [
            "trible",
            "pile",
            "migrate",
            "unused.pile",
            "endorse-unsigned-equations",
        ];
        for incomplete in [
            vec![],
            vec!["--collection", "unused"],
            vec!["--signing-key", "unused.key"],
        ] {
            assert!(
                crate::TribleCli::try_parse_from(prefix.into_iter().chain(incomplete)).is_err()
            );
        }
        assert!(crate::TribleCli::try_parse_from(prefix.into_iter().chain([
            "--collection",
            "unused",
            "--signing-key",
            "unused.key",
            "--dry-run",
        ]))
        .is_ok());
    }
}
