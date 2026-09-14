//! Explicit audit of native evidence, separate from ordinary trusted reads.

use std::path::Path;

use anyhow::{anyhow, Result};
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::CollectionRecord;
use triblespace_core::repo::pile::{LegacyCollectionRecordKindV3, PileRecordContent, PileRecords};

pub(super) fn run(path: &Path) -> Result<()> {
    // The canonical raw iterator opens read-only, captures one file prefix,
    // and neither builds semantic indexes nor hashes blob payloads. Physical
    // duplicates must each be audited, even if ordinary replay collapses them.
    let mut records =
        PileRecords::open(path).map_err(|error| super::pile_read_error(path, error))?;
    let mut checked = [0usize; 4];
    let mut invalid = 0usize;
    let mut unsigned = 0usize;
    let mut opaque = 0usize;
    let mut other = 0usize;
    while let Some(raw) = records.next() {
        let raw = raw.map_err(|error| super::pile_read_error(path, error))?;
        let (kind, result) = match raw.content {
            PileRecordContent::Collection { record } => {
                let (kind, index) = match &record {
                    CollectionRecord::Commit(_) => ("COMMIT", 0),
                    CollectionRecord::Merge(_) => ("MERGE", 1),
                    CollectionRecord::Derive(_) => ("DERIVE", 2),
                };
                checked[index] += 1;
                (kind, record.verify_strict().map_err(anyhow::Error::from))
            }
            PileRecordContent::CapabilityProof {
                data_offset,
                data_len,
                ..
            } => {
                checked[3] += 1;
                // PileRecords established this exact body range. Validation
                // checks only the self-contained signature chain, never a
                // chosen policy root or the referenced definition blobs.
                let bytes = records.bytes().slice(data_offset..data_offset + data_len);
                let result = CapabilityProof::from_owned_bytes(bytes)
                    .map_err(anyhow::Error::from)
                    .and_then(|proof| proof.verify_signatures().map_err(anyhow::Error::from));
                ("AUTH", result)
            }
            PileRecordContent::LegacyUnsignedCollectionEquation { .. }
            | PileRecordContent::LegacyCollectionV3 {
                kind: LegacyCollectionRecordKindV3::Merge | LegacyCollectionRecordKindV3::Derive,
            }
            | PileRecordContent::RetiredCollectionDeriveV4 => {
                unsigned += 1;
                continue;
            }
            PileRecordContent::Opaque { .. } => {
                opaque += 1;
                continue;
            }
            _ => {
                other += 1;
                continue;
            }
        };
        if let Err(error) = result {
            invalid += 1;
            eprintln!("Invalid {kind} at byte {}: {error}", raw.offset);
        }
    }
    println!(
        "Native record audit: COMMIT={}, MERGE={}, DERIVE={}, AUTH={}",
        checked[0], checked[1], checked[2], checked[3]
    );
    println!("Invalid native records: {invalid}");
    println!(
        "Not checked: unsigned legacy equations={unsigned}, opaque records={opaque}, other records={other}"
    );
    println!("Scope: signatures only; no blob hashes or capability-definition interpretation");
    if invalid != 0 {
        return Err(anyhow!("{invalid} native record(s) failed verification"));
    }
    Ok(())
}
