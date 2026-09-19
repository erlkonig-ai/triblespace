//! Explicit writer endorsement of historical payload-only equations.
//!
//! A historical equation states a payload relation that nobody signed. This
//! reissues it as a current signed record under the caller's key. It never
//! reads an ancestor payload and never authors a COMMIT: the statement is
//! exactly the old one, now with an author.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::{
    admitted_record_witnesses, collection_action_audience, descriptor, preview_record_witnesses,
    CollectionData, CollectionDerive, CollectionFunctionalConflict, CollectionHandle,
    CollectionMerge, CollectionRead, CollectionReadAudience, CollectionRecord,
    CollectionRecordSelector, CollectionStore, ConflictingCollectionOutput,
    LegacyUnsignedCollectionEquation, RecordDecodeError, Support, ACTION_WRITE,
    COLLECTION_DERIVE_SIGNED_V2_BYTES_LEN, COLLECTION_MERGE_SIGNED_V2_BYTES_LEN,
    COLLECTION_RECORD_KIND_DERIVE_V2, COLLECTION_RECORD_KIND_MERGE_V2,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::pile::{
    OpaqueKind, Pile, PileRecordContent, PileRecords, PileSnapshot,
};
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, SnapshotSource};
use triblespace_core::trible::TribleSet;

// Published payload-only signed framing handles, preserved verbatim from
// repo/pile/record_kind.rs. Ordinary replay deliberately treats these as opaque;
// only this explicit migration interprets their bodies through the old codec.
const MERGE_SIGNED_V2_FRAME: &str =
    "9D9B962D46FA42168AB3A11FB367AC14692D4F51B5190196F2BDB08D5BC2BA07";
const DERIVE_SIGNED_V2_FRAME: &str =
    "B2EE8382C70161379E387D692B822946A60B602A909EED66B7D6DA2A62F36232";

#[derive(Debug, Default, Eq, PartialEq)]
struct Report {
    endorsed: usize,
    already_present: usize,
    missing_outputs: usize,
    unmapped_targets: usize,
    unauthorized: usize,
    invalid_signatures: usize,
    malformed_signed_frames: usize,
}

impl Report {
    fn skipped(&self) -> usize {
        self.missing_outputs
            + self.unmapped_targets
            + self.unauthorized
            + self.invalid_signatures
            + self.malformed_signed_frames
    }
}

#[derive(Default)]
struct Inventory {
    equations: BTreeSet<LegacyUnsignedCollectionEquation>,
    report: Report,
}

/// Native framing supplies every boundary. No BLOB payload is read or hashed,
/// and no retired record becomes part of the pile's permanent indexes.
fn inventory(path: &Path, collection: CollectionHandle) -> Result<Inventory> {
    let mut result = Inventory::default();
    let merge_kind = hex::decode(MERGE_SIGNED_V2_FRAME)?;
    let derive_kind = hex::decode(DERIVE_SIGNED_V2_FRAME)?;
    let mut records = PileRecords::open(path).context("open historical record framing")?;
    while let Some(record) = records.next() {
        let record = record.context("read historical record framing")?;
        let (tag, payload_len, frame_len) = match record.content {
            PileRecordContent::LegacyUnsignedCollectionEquation { equation }
                if equation.collection() == collection =>
            {
                result.equations.insert(equation);
                continue;
            }
            PileRecordContent::Opaque {
                kind: OpaqueKind::Described(kind),
            } if kind.as_slice() == merge_kind => (
                COLLECTION_RECORD_KIND_MERGE_V2,
                COLLECTION_MERGE_SIGNED_V2_BYTES_LEN,
                512,
            ),
            PileRecordContent::Opaque {
                kind: OpaqueKind::Described(kind),
            } if kind.as_slice() == derive_kind => (
                COLLECTION_RECORD_KIND_DERIVE_V2,
                COLLECTION_DERIVE_SIGNED_V2_BYTES_LEN,
                256,
            ),
            _ => continue,
        };
        let frame = &records.bytes()[record.offset..record.offset + record.len];
        if frame.get(64..96) != Some(collection.raw.as_slice()) {
            continue;
        }
        let malformed = || {
            eprintln!(
                "skipped retired signed equation at byte {}: malformed body",
                record.offset
            );
        };
        if frame.len() != frame_len
            || frame
                .get(64 + payload_len..)
                .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        {
            malformed();
            result.report.malformed_signed_frames += 1;
            continue;
        }
        let mut bytes = Vec::with_capacity(payload_len + 1);
        bytes.push(tag);
        bytes.extend_from_slice(&frame[64..64 + payload_len]);
        // These bytes are exactly what the live decoder reads: restoring the
        // witness-free record brought the live dense form back to the retired
        // one, so the retired frame is the only thing still historical here.
        let decoded = match CollectionRecord::from_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(RecordDecodeError::Verification(_)) => {
                eprintln!(
                    "skipped retired signed equation at byte {}: invalid old signature",
                    record.offset
                );
                result.report.invalid_signatures += 1;
                continue;
            }
            Err(_) => {
                malformed();
                result.report.malformed_signed_frames += 1;
                continue;
            }
        };
        let Some(equation) = payload_equation(decoded) else {
            malformed();
            result.report.malformed_signed_frames += 1;
            continue;
        };
        result.equations.insert(equation);
    }
    Ok(result)
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
    // Scan first: the later refreshed snapshot contains this complete prefix.
    // Concurrent appends after it are deliberately a subsequent explicit run.
    let historical = inventory(&path, collection)?;
    let mut pile = super::super::open_refreshed(&path)?;
    let result = endorse(&mut pile, historical, collection, &signer, dry_run);
    let close = pile.close().map_err(|error| anyhow!("close pile: {error}"));
    let report = result?;
    close?;
    println!("collection: blake3:{}", hex::encode(collection.raw));
    println!(
        "endorser: {}",
        hex::encode_upper(signer.verifying_key().to_bytes())
    );
    println!(
        "{}: {}; already-endorsed equations: {}; skipped missing outputs: {}; \
         unmapped targets: {}; unauthorized: {}; \
         invalid old signatures: {}; malformed old signed frames: {}",
        if dry_run { "would endorse" } else { "endorsed" },
        report.endorsed,
        report.already_present,
        report.missing_outputs,
        report.unmapped_targets,
        report.unauthorized,
        report.invalid_signatures,
        report.malformed_signed_frames,
    );
    println!("Payloads and historical frames are unchanged; results were not recomputed. These are fresh owner endorsements of the exact historical statements, not recovered historical provenance: the old author is not preserved and is not claimed.");
    if report.skipped() != 0 {
        bail!(
            "{} historical equation(s)/frame(s) remain unresolved",
            report.skipped()
        );
    }
    Ok(())
}

fn endorse(
    pile: &mut Pile,
    historical: Inventory,
    collection: CollectionHandle,
    signer: &SigningKey,
    dry_run: bool,
) -> Result<Report> {
    let snapshot = pile.snapshot().context("freeze endorsement snapshot")?;
    let (records, report) = plan(&snapshot, historical, collection, signer)?;
    // Reject functional conflicts before publishing anything. Records may be
    // appended in any order: an endorsement names payloads, so it does not
    // depend on another record having arrived first.
    if !dry_run {
        for record in records {
            pile.insert(record).context("append endorsement")?;
        }
        pile.flush().context("flush writer endorsements")?;
    }
    Ok(report)
}

fn output(record: CollectionRecord) -> CollectionData {
    match record {
        CollectionRecord::Commit(commit) => commit.data(),
        CollectionRecord::Merge(merge) => merge.result(),
        CollectionRecord::Derive(derive) => derive.output(),
    }
}

fn payload_equation(record: CollectionRecord) -> Option<LegacyUnsignedCollectionEquation> {
    match record {
        CollectionRecord::Commit(_) => None,
        CollectionRecord::Merge(merge) => {
            let (low, high) = merge.inputs();
            Some(LegacyUnsignedCollectionEquation::Merge {
                collection: merge.collection(),
                low,
                high,
                result: merge.result(),
            })
        }
        CollectionRecord::Derive(derive) => Some(LegacyUnsignedCollectionEquation::Derive {
            collection: derive.collection(),
            input: derive.input(),
            output: derive.output(),
        }),
    }
}

/// Check the direct functional law over admitted and planned records before
/// publishing any of the latter. The optional second input distinguishes
/// DERIVE from MERGE; merge inputs are canonical in the record itself.
fn check_functionality(records: impl IntoIterator<Item = CollectionRecord>) -> Result<()> {
    let mut outputs: BTreeMap<_, ConflictingCollectionOutput> = BTreeMap::new();
    for record in records {
        let (key, data) = match record {
            CollectionRecord::Commit(_) => continue,
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                ((merge.collection(), low, Some(high)), merge.result())
            }
            CollectionRecord::Derive(derive) => {
                ((derive.collection(), derive.input(), None), derive.output())
            }
        };
        let incoming = ConflictingCollectionOutput {
            record: Some(record),
            data,
        };
        if let Some(known) = outputs.get(&key) {
            if known.data != data {
                let (first, second) = if known.data < data {
                    (*known, incoming)
                } else {
                    (incoming, *known)
                };
                return Err(match key {
                    (collection, low, Some(high)) => CollectionFunctionalConflict::Merge {
                        collection,
                        low,
                        high,
                        first,
                        second,
                    },
                    (target, input, None) => CollectionFunctionalConflict::Derive {
                        target,
                        input,
                        first,
                        second,
                    },
                }
                .into());
            }
        } else {
            outputs.insert(key, incoming);
        }
    }
    Ok(())
}

fn plan(
    snapshot: &PileSnapshot,
    historical: Inventory,
    collection: CollectionHandle,
    signer: &SigningKey,
) -> Result<(Vec<CollectionRecord>, Report)> {
    let Inventory {
        equations: old_equations,
        mut report,
    } = historical;
    let admitted = match collection_action_audience(snapshot, collection, ACTION_WRITE)
        .context("inspect target WRITE audience")?
    {
        CollectionReadAudience::Open => true,
        CollectionReadAudience::Restricted(subjects) => subjects.contains(&signer.verifying_key()),
    };
    if !admitted {
        report.unauthorized = old_equations.len();
        eprintln!(
            "skipped {} equation(s): signer lacks WRITE authority for blake3:{}",
            report.unauthorized,
            hex::encode(collection.raw)
        );
        return Ok((Vec::new(), report));
    }

    let facts = snapshot
        .get::<TribleSet, SimpleArchive>(collection)
        .context("read target descriptor")?;
    let source = descriptor::source(&facts).context("read immediate source")?;

    // Records the pile already admits are the conflict baseline: a plan may
    // not contradict what this collection (or its immediate source) already
    // says. They are not inputs to the endorsement itself.
    let mut seeds = admitted_record_witnesses(snapshot, collection)
        .context("resolve admitted target records")?;
    if let Some(source) = source {
        seeds.extend(
            admitted_record_witnesses(snapshot, source)
                .context("resolve admitted immediate-source records")?,
        );
    }
    seeds.sort_unstable_by_key(|(record, _)| record.fingerprint());

    let mut records = Vec::new();
    let mut proposed = Vec::new();
    for old in old_equations {
        let result = match old {
            LegacyUnsignedCollectionEquation::Merge { result, .. } => result,
            LegacyUnsignedCollectionEquation::Derive { output, .. } => output,
        };
        // Only the result must be resident. Historical input payloads may have
        // been evicted, and that is fine: the equation states a relation
        // between digests, so endorsing it needs no ancestor bytes and no
        // ancestor record. This is the whole reason the plan is a single pass
        // now -- there is no support to accumulate and no fixed point to
        // reach, because a record no longer cites the records before it.
        if !snapshot
            .contains_blob(Handle::<UnknownBlob>::from_hash(result))
            .context("inspect historical output residency")?
        {
            report.missing_outputs += 1;
            eprintln!(
                "skipped equation {:X}: missing output blob",
                old.fingerprint()
            );
            continue;
        }
        let record = match old {
            LegacyUnsignedCollectionEquation::Merge {
                low, high, result, ..
            } => CollectionRecord::Merge(CollectionMerge::sign(
                signer, collection, low, high, result,
            )),
            LegacyUnsignedCollectionEquation::Derive { input, output, .. } => {
                // A DERIVE asserts the mapping this descriptor names. Without
                // a source there is no mapping and the statement means nothing.
                if source.is_none() {
                    report.unmapped_targets += 1;
                    eprintln!(
                        "skipped equation {:X}: target descriptor has no source",
                        old.fingerprint()
                    );
                    continue;
                }
                CollectionRecord::Derive(CollectionDerive::sign(
                    signer, collection, input, output,
                ))
            }
        };
        proposed.push(record);
        // The producers of the same member are the only records this could
        // already be.
        let member = match record {
            CollectionRecord::Commit(commit) => commit.data(),
            CollectionRecord::Merge(merge) => merge.result(),
            CollectionRecord::Derive(derive) => derive.output(),
        };
        if snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
                collection, member,
            )]))
            .context("inspect exact existing endorsement")?
            .contains(&record)
        {
            report.already_present += 1;
        } else {
            records.push(record);
            report.endorsed += 1;
        }
    }

    check_functionality(
        seeds
            .iter()
            .map(|(record, _)| *record)
            .chain(proposed.iter().copied()),
    )
    .context("conflicting historical endorsement plan; nothing was appended")?;
    // `check_functionality` compares the plan against itself and the records
    // already admitted. That misses a conflict that only exists once the plan
    // CLOSES -- a commuting square, where two routes agree on every record in
    // isolation and disagree about an output only when both are present. Let
    // the ordinary admission machinery resolve the complete overlay and report
    // it. The plan no longer needs what this returns, but it still needs this
    // to fail.
    preview_record_witnesses(snapshot, collection, proposed.iter().copied())
        .context("preflight complete endorsement overlay; nothing was appended")?;
    Ok((records, report))
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    use anybytes::Bytes;
    use clap::Parser;
    use ed25519_dalek::Signer;
    use tempfile::NamedTempFile;
    use triblespace_core::blob::encodings::succinctarchive::{
        Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    };
    use triblespace_core::collection::{
        AdmissionPolicy, Collection, CollectionCommit, CollectionPolicy, CollectionStoreExt,
    };
    use triblespace_core::id::Id;
    use triblespace_core::inline::Inline;
    use triblespace_core::macros::entity;
    use triblespace_core::metadata;
    use triblespace_core::repo::BlobStorePut;

    use super::*;

    fn frame(equation: LegacyUnsignedCollectionEquation) -> Vec<u8> {
        let mut bytes = vec![0; 256];
        // Existing generic framing magic, copied verbatim from repo/pile.rs.
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

    fn signed_frame(equation: LegacyUnsignedCollectionEquation, signer: &SigningKey) -> Vec<u8> {
        let mut frame = frame(equation);
        let (tag, payload_len, physical_len, kind) = match equation {
            LegacyUnsignedCollectionEquation::Merge { .. } => (
                COLLECTION_RECORD_KIND_MERGE_V2,
                COLLECTION_MERGE_SIGNED_V2_BYTES_LEN,
                512,
                MERGE_SIGNED_V2_FRAME,
            ),
            LegacyUnsignedCollectionEquation::Derive { .. } => (
                COLLECTION_RECORD_KIND_DERIVE_V2,
                COLLECTION_DERIVE_SIGNED_V2_BYTES_LEN,
                256,
                DERIVE_SIGNED_V2_FRAME,
            ),
        };
        frame.resize(physical_len, 0);
        frame[28..32].copy_from_slice(&((physical_len / 256) as u32).to_le_bytes());
        frame[32..64].copy_from_slice(&hex::decode(kind).unwrap());
        // The live record IS the retired dense body now, so sign it with the
        // ordinary constructor instead of splicing a key and signature in.
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
            } => CollectionRecord::Derive(CollectionDerive::sign(
                signer, collection, input, output,
            )),
        };
        let dense = record.to_bytes();
        debug_assert_eq!(dense[0], tag);
        frame[64..64 + payload_len].copy_from_slice(&dense[1..]);
        frame
    }

    fn merge(
        collection: CollectionHandle,
        a: CollectionData,
        b: CollectionData,
        result: CollectionData,
    ) -> LegacyUnsignedCollectionEquation {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        LegacyUnsignedCollectionEquation::Merge {
            collection,
            low,
            high,
            result,
        }
    }

    fn derive(
        collection: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
    ) -> LegacyUnsignedCollectionEquation {
        LegacyUnsignedCollectionEquation::Derive {
            collection,
            input,
            output,
        }
    }

    fn append(path: &Path, frames: impl IntoIterator<Item = Vec<u8>>) -> Result<()> {
        let mut file = OpenOptions::new().append(true).open(path)?;
        for frame in frames {
            file.write_all(&frame)?;
        }
        file.sync_all()?;
        Ok(())
    }

    fn blob(pile: &mut Pile, text: &str) -> Result<CollectionData> {
        let handle = pile.put::<UnknownBlob, _>(Bytes::from_source(text.as_bytes().to_vec()))?;
        Ok(Handle::<UnknownBlob>::to_hash(handle))
    }

    /// A new test pile with the same authoritative records but selected cache
    /// payloads absent. Native framing preserves all other bytes exactly.
    fn without_blobs(path: &Path, excluded: &BTreeSet<CollectionData>) -> Result<NamedTempFile> {
        let mut result = NamedTempFile::new()?;
        let mut records = PileRecords::open(path)?;
        while let Some(record) = records.next() {
            let record = record?;
            if matches!(record.content, PileRecordContent::Blob { hash, .. } if excluded.contains(&hash))
            {
                continue;
            }
            result.write_all(&records.bytes()[record.offset..record.offset + record.len])?;
        }
        result.flush()?;
        Ok(result)
    }

    struct Fixture {
        file: NamedTempFile,
        signer: SigningKey,
        source: Collection<SimpleArchive>,
        target: CollectionHandle,
        commits: [CollectionCommit; 2],
        images: [CollectionData; 3],
        equations: [LegacyUnsignedCollectionEquation; 3],
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let file = NamedTempFile::new()?;
            let signer = SigningKey::from_bytes(&[42; 32]);
            let policy = CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(signer.verifying_key()),
            );
            let mut pile = Pile::open(file.path())?;
            let source = pile.collection("endorsement-source", policy.clone())?;
            let target = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy)?
                .handle();
            let a = pile.commit(
                source,
                &signer,
                entity! { metadata::tag: Id::new([1; 16]).unwrap() },
            )?;
            let b = pile.commit(
                source,
                &signer,
                entity! { metadata::tag: Id::new([2; 16]).unwrap() },
            )?;
            // Deliberately not encoded target values: migration never decodes
            // or rederives payloads. It binds real COMMIT/equation witnesses.
            let images = [
                blob(&mut pile, "image-a")?,
                blob(&mut pile, "image-b")?,
                blob(&mut pile, "image-union")?,
            ];
            pile.close()?;
            let equations = [
                derive(target, a.data(), images[0]),
                derive(target, b.data(), images[1]),
                merge(target, images[0], images[1], images[2]),
            ];
            Ok(Self {
                file,
                signer,
                source,
                target,
                commits: [a, b],
                images,
                equations,
            })
        }

        fn endorse(&self, dry_run: bool) -> Result<Report> {
            let historical = inventory(self.file.path(), self.target)?;
            let mut pile = super::super::super::open_refreshed(self.file.path())?;
            let result = endorse(&mut pile, historical, self.target, &self.signer, dry_run);
            pile.close()?;
            result
        }

        fn records(&self) -> Result<Vec<CollectionRecord>> {
            let mut pile = super::super::super::open_refreshed(self.file.path())?;
            let snapshot = pile.snapshot()?;
            let result = snapshot
                .records()?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            pile.close()?;
            Ok(result)
        }

        fn support_for(
            &self,
            collection: CollectionHandle,
            member: CollectionData,
        ) -> Result<Support> {
            let mut pile = super::super::super::open_refreshed(self.file.path())?;
            let mut support = self.source.cover([]);
            for (record, represented) in admitted_record_witnesses(&pile.snapshot()?, collection)? {
                if output(record) == member {
                    support = support.union(&represented)?;
                }
            }
            pile.close()?;
            Ok(support)
        }
    }

    #[test]
    fn both_epochs_plan_topologically_preserve_frames_and_repeat_without_append() -> Result<()> {
        let fixture = Fixture::new()?;
        // Physical order is intentionally the reverse dependency order.
        append(
            fixture.file.path(),
            [
                signed_frame(fixture.equations[2], &fixture.signer),
                frame(fixture.equations[1]),
                frame(fixture.equations[0]),
                signed_frame(fixture.equations[0], &fixture.signer),
            ],
        )?;
        let original = fs::read(fixture.file.path())?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 3,
                ..Report::default()
            }
        );
        let after = fs::read(fixture.file.path())?;
        assert_eq!(&after[..original.len()], original);
        let records = fixture.records()?;
        assert_eq!(records.len(), 5);
        let by_fingerprint: BTreeMap<_, _> = records
            .iter()
            .map(|record| (record.fingerprint(), *record))
            .collect();
        for record in records {
            record.verify_strict()?;
            if record.collection() != fixture.target {
                continue;
            }
            assert!(fixture
                .equations
                .contains(&payload_equation(record).unwrap()));
            // Each endorsement's input payloads are ones the pile actually
            // produces. The witness-era version of this looked up a cited
            // fingerprint; production is the same relation without the field.
            let produces = |payload| {
                by_fingerprint.values().any(|producer: &CollectionRecord| {
                    producer.collection() == fixture.target && output(*producer) == payload
                })
            };
            match record {
                CollectionRecord::Derive(derive) => {
                    assert!(fixture
                        .commits
                        .iter()
                        .any(|commit| commit.data() == derive.input()));
                }
                CollectionRecord::Merge(merge) => {
                    assert!(produces(merge.inputs().0));
                    assert!(produces(merge.inputs().1));
                }
                CollectionRecord::Commit(_) => panic!("migration must not create COMMITs"),
            }
        }
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                already_present: 3,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, after);
        Ok(())
    }

    #[test]
    fn dry_run_is_a_complete_plan_but_never_publishes_its_witnesses() -> Result<()> {
        let fixture = Fixture::new()?;
        append(fixture.file.path(), fixture.equations.map(frame))?;
        let before = fs::read(fixture.file.path())?;
        assert_eq!(
            fixture.endorse(true)?,
            Report {
                endorsed: 3,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, before);
        assert_eq!(fixture.records()?.len(), 2);
        Ok(())
    }

    #[test]
    fn a_valid_old_signature_is_not_carried_into_the_new_endorsement() -> Result<()> {
        let fixture = Fixture::new()?;
        // Under witnesses this equation was unendorsable: its inputs named no
        // admitted target record, and a valid historical signature could not
        // fill that in. There is no such gap now -- the equation states a
        // payload relation and can be restated -- so the property that
        // survives is the one the name was always about: the old authorship is
        // neither preserved nor claimed. The new record is the migrator's
        // statement, signed by the migrator.
        let historical = SigningKey::from_bytes(&[43; 32]);
        append(
            fixture.file.path(),
            [signed_frame(fixture.equations[2], &historical)],
        )?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 1,
                ..Report::default()
            }
        );
        let endorsement = fixture
            .records()?
            .into_iter()
            .find(|record| payload_equation(*record) == Some(fixture.equations[2]))
            .expect("the historical equation is endorsed");
        assert_eq!(
            endorsement.public_key().raw,
            fixture.signer.verifying_key().to_bytes()
        );
        assert_ne!(
            endorsement.public_key().raw,
            historical.verifying_key().to_bytes()
        );
        Ok(())
    }

    #[test]
    fn both_epochs_use_exact_records_without_evicted_input_payloads() -> Result<()> {
        for signed in [false, true] {
            for is_merge in [false, true] {
                let fixture = Fixture::new()?;
                let mut excluded: BTreeSet<_> =
                    fixture.commits.iter().map(|commit| commit.data()).collect();
                let old = if is_merge {
                    let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
                    for (commit, image) in fixture.commits.into_iter().zip(fixture.images) {
                        pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
                            &fixture.signer,
                            fixture.target,
                            commit.data(),
                            image,
                        )))?;
                        excluded.insert(image);
                    }
                    pile.close()?;
                    fixture.equations[2]
                } else {
                    fixture.equations[0]
                };
                let file = without_blobs(fixture.file.path(), &excluded)?;
                append(
                    file.path(),
                    [if signed {
                        signed_frame(old, &fixture.signer)
                    } else {
                        frame(old)
                    }],
                )?;
                let historical = inventory(file.path(), fixture.target)?;
                let mut pile = super::super::super::open_refreshed(file.path())?;
                let snapshot = pile.snapshot()?;
                for input in &excluded {
                    assert!(!snapshot.contains_blob(Handle::<UnknownBlob>::from_hash(*input))?);
                }
                assert_eq!(
                    endorse(
                        &mut pile,
                        historical,
                        fixture.target,
                        &fixture.signer,
                        false
                    )?,
                    Report {
                        endorsed: 1,
                        ..Report::default()
                    }
                );
                let snapshot = pile.snapshot()?;
                for input in excluded {
                    assert!(
                        !snapshot.contains_blob(Handle::<UnknownBlob>::from_hash(input))?,
                        "migration fetched an input payload"
                    );
                }
                // The endorsement exists and says exactly the old equation.
                // What it does NOT do is name the records that produced its
                // inputs, which is why none of their payloads had to be here.
                assert!(snapshot
                    .records()?
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .into_iter()
                    .any(|record| payload_equation(record) == Some(old)));
                pile.close()?;
            }
        }
        Ok(())
    }

    #[test]
    fn migration_order_no_longer_matters_and_downstream_names_the_upstream_payload(
    ) -> Result<()> {
        let fixture = Fixture::new()?;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let policy = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(fixture.signer.verifying_key()),
        );
        let source = Collection::<SuccinctArchiveBlob>::open(&pile.snapshot()?, fixture.target)?;
        let downstream = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(source, (), policy)?
            .handle();
        let result = blob(&mut pile, "downstream-image")?;
        pile.close()?;
        append(fixture.file.path(), fixture.equations.map(frame))?;
        append(
            fixture.file.path(),
            [frame(derive(downstream, fixture.images[2], result))],
        )?;
        let run_downstream = || -> Result<Report> {
            let historical = inventory(fixture.file.path(), downstream)?;
            let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
            let report = endorse(&mut pile, historical, downstream, &fixture.signer, false)?;
            pile.close()?;
            Ok(report)
        };
        // Downstream first. Under witnesses this was refused: the downstream
        // DERIVE had to cite the upstream MERGE record, so upstream had to be
        // migrated first and the ordering was load-bearing. A DERIVE names an
        // input PAYLOAD now, so it can be stated before anything produces that
        // payload -- migration order stopped mattering when citation did.
        assert_eq!(
            run_downstream()?,
            Report {
                endorsed: 1,
                ..Report::default()
            }
        );
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 3,
                ..Report::default()
            }
        );
        // Running it again after upstream lands adds nothing: the record was
        // already exactly this statement.
        assert_eq!(
            run_downstream()?,
            Report {
                already_present: 1,
                ..Report::default()
            }
        );
        let records = fixture.records()?;
        let witness = records
            .iter()
            .find(|record| matches!(record, CollectionRecord::Merge(_)))
            .unwrap();
        let derived = records
            .iter()
            .find_map(|record| match record {
                CollectionRecord::Derive(derive) if derive.collection() == downstream => {
                    Some(derive)
                }
                _ => None,
            })
            .unwrap();
        // The downstream DERIVE names the upstream MERGE's result payload.
        // It does not name the merge record, and does not need to: the
        // upstream migration having run is what makes that payload exist.
        assert_eq!(derived.input(), output(*witness));
        Ok(())
    }

    #[test]
    fn an_unauthorized_record_is_not_part_of_the_functional_baseline() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let outsider = SigningKey::from_bytes(&[43; 32]);
        // The same input mapped to a DIFFERENT output, by a key this
        // collection does not admit. Under witnesses this test said such a
        // record cannot witness an input; the plan does not take inputs from
        // records at all now, so what remains to check is the other half:
        // an unadmitted record is not a statement the plan has to agree with,
        // and must not read as a functional conflict.
        pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
            &outsider,
            fixture.target,
            fixture.commits[0].data(),
            fixture.images[2],
        )))?;
        pile.close()?;
        append(fixture.file.path(), [frame(fixture.equations[0])])?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 1,
                ..Report::default()
            }
        );
        Ok(())
    }

    #[test]
    fn merge_support_aliases_need_no_fan_out_at_all() -> Result<()> {
        let fixture = Fixture::new()?;
        let [x, y, z] = fixture.images;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let mut commits = fixture.commits.to_vec();
        for tag in 3..=5 {
            commits.push(pile.commit(
                fixture.source,
                &fixture.signer,
                entity! { metadata::tag: Id::new([tag; 16]).unwrap() },
            )?);
        }
        pile.close()?;
        // x has two disjoint support routes, y has three. This used to cost
        // three MERGE records -- one per witness pair, chosen by a greedy
        // cover, and already an improvement on the six-pair Cartesian
        // product. A merge names PAYLOADS, and x is one payload however many
        // records produce it, so one record now carries what three did and
        // the fan-out disappears rather than shrinking.
        let equations = [
            merge(fixture.target, x, y, z),
            derive(fixture.target, commits[0].data(), x),
            derive(fixture.target, commits[1].data(), x),
            derive(fixture.target, commits[2].data(), y),
            derive(fixture.target, commits[3].data(), y),
            derive(fixture.target, commits[4].data(), y),
        ];
        append(fixture.file.path(), equations.map(frame))?;
        let before = fs::read(fixture.file.path())?;
        let dry_run = fixture.endorse(true)?;
        assert_eq!(
            dry_run,
            Report {
                endorsed: 6,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, before);
        assert_eq!(fixture.endorse(false)?, dry_run);
        let after = fs::read(fixture.file.path())?;
        assert_eq!(&after[..before.len()], before);
        assert_eq!(
            fixture
                .records()?
                .iter()
                .filter(|record| matches!(record, CollectionRecord::Merge(_)))
                .count(),
            1
        );
        // One record, and the support is still the whole union: what the
        // three-record cover was reconstructing is what content addressing
        // already relates.
        let expected = fixture
            .source
            .cover(commits.iter().map(|commit| Inline::new(commit.data().raw)));
        assert_eq!(fixture.support_for(fixture.target, z)?, expected);
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                already_present: 6,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, after);
        Ok(())
    }

    #[test]
    fn a_later_source_alias_grows_support_without_a_new_downstream_record() -> Result<()> {
        let fixture = Fixture::new()?;
        let [a, b] = fixture.commits;
        let x = fixture.images[0];
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let policy = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(fixture.signer.verifying_key()),
        );
        let source = Collection::<SuccinctArchiveBlob>::open(&pile.snapshot()?, fixture.target)?;
        let downstream = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(source, (), policy)?
            .handle();
        let result = blob(&mut pile, "aliased-downstream-image")?;
        pile.close()?;
        append(
            fixture.file.path(),
            [
                frame(derive(fixture.target, a.data(), x)),
                frame(derive(downstream, x, result)),
            ],
        )?;
        let run_downstream = |dry_run| -> Result<Report> {
            let historical = inventory(fixture.file.path(), downstream)?;
            let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
            let report = endorse(&mut pile, historical, downstream, &fixture.signer, dry_run);
            pile.close()?;
            report
        };
        assert_eq!(fixture.endorse(false)?.endorsed, 1);
        assert_eq!(run_downstream(false)?.endorsed, 1);
        let first = fs::read(fixture.file.path())?;
        assert_eq!(run_downstream(false)?.already_present, 1);
        assert_eq!(fs::read(fixture.file.path())?, first);

        // New support arrives for the same source payload. Under witnesses
        // the downstream DERIVE had to be reissued citing the new record, so
        // this added a second downstream certificate. The downstream record
        // says `x -> result`, which is unchanged by another record also
        // producing x -- so nothing downstream needs writing, and the support
        // underneath it widens on its own.
        append(
            fixture.file.path(),
            [signed_frame(
                derive(fixture.target, b.data(), x),
                &fixture.signer,
            )],
        )?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 1,
                already_present: 1,
                ..Report::default()
            }
        );
        let after = fs::read(fixture.file.path())?;
        assert_eq!(
            run_downstream(false)?,
            Report {
                already_present: 1,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, after);
        // Support now covers both source commits, under the one record that
        // was already there.
        let expected = fixture
            .source
            .cover([Inline::new(a.data().raw), Inline::new(b.data().raw)]);
        assert_eq!(fixture.support_for(downstream, result)?, expected);
        assert_eq!(
            fixture
                .records()?
                .iter()
                .filter(|record| record.collection() == downstream)
                .count(),
            1
        );

        // A later, different real record with the same support is not new
        // work, even if its fingerprint wins the canonical witness ordering.
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let metadata = pile.put::<SimpleArchive, _>(
            entity! { metadata::tag: Id::new([98; 16]).unwrap() }
                .facts()
                .clone(),
        )?;
        let duplicate =
            CollectionCommit::sign(&fixture.signer, fixture.source.handle(), a.data(), metadata);
        pile.insert(CollectionRecord::Commit(duplicate))?;
        pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
            &fixture.signer,
            fixture.target,
            a.data(),
            x,
        )))?;
        pile.close()?;
        let before = fs::read(fixture.file.path())?;
        assert_eq!(
            run_downstream(false)?,
            Report {
                already_present: 1,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, before);
        Ok(())
    }

    #[test]
    fn self_output_merge_certifies_support_once() -> Result<()> {
        let fixture = Fixture::new()?;
        let [x, y, _] = fixture.images;
        append(
            fixture.file.path(),
            [
                frame(fixture.equations[0]),
                frame(fixture.equations[1]),
                frame(merge(fixture.target, x, y, x)),
            ],
        )?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 3,
                ..Report::default()
            }
        );
        let expected = fixture.source.cover(
            fixture
                .commits
                .iter()
                .map(|commit| Inline::new(commit.data().raw)),
        );
        assert_eq!(fixture.support_for(fixture.target, x)?, expected);
        let after = fs::read(fixture.file.path())?;
        for _ in 0..3 {
            assert_eq!(
                fixture.endorse(false)?,
                Report {
                    already_present: 3,
                    ..Report::default()
                }
            );
            assert_eq!(fs::read(fixture.file.path())?, after);
        }
        Ok(())
    }

    #[test]
    fn a_payload_cycle_needs_no_acyclic_record_plan() -> Result<()> {
        let fixture = Fixture::new()?;
        let [x, y, z] = fixture.images;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let c = pile.commit(
            fixture.source,
            &fixture.signer,
            entity! { metadata::tag: Id::new([3; 16]).unwrap() },
        )?;
        let w = blob(&mut pile, "cycle-third-input")?;
        pile.close()?;
        // This historical payload graph cycles x -> z -> x. Migration does not
        // re-prove its mathematics. It used to have to build grounded, finite
        // record ancestry through that cycle, which cost an extra record where
        // the plan re-entered it; a record that names no other record cannot
        // form a cycle, so the plan is one record per equation and finite by
        // construction. The support each payload ends up with is unchanged.
        let equations = [
            fixture.equations[0],
            fixture.equations[1],
            derive(fixture.target, c.data(), w),
            merge(fixture.target, x, y, z),
            merge(fixture.target, z, w, x),
        ];
        append(fixture.file.path(), equations.map(frame))?;
        let before = fs::read(fixture.file.path())?;
        let planned = fixture.endorse(true)?;
        assert_eq!(
            planned,
            Report {
                endorsed: 5,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, before);
        assert_eq!(fixture.endorse(false)?, planned);
        let expected = fixture.source.cover(
            fixture
                .commits
                .iter()
                .copied()
                .chain([c])
                .map(|commit| Inline::new(commit.data().raw)),
        );
        assert_eq!(fixture.support_for(fixture.target, x)?, expected);
        assert_eq!(fixture.support_for(fixture.target, z)?, expected);
        let after = fs::read(fixture.file.path())?;
        for _ in 0..3 {
            assert_eq!(
                fixture.endorse(false)?,
                Report {
                    already_present: 5,
                    ..Report::default()
                }
            );
            assert_eq!(fs::read(fixture.file.path())?, after);
        }
        Ok(())
    }

    #[test]
    fn duplicate_commit_payloads_with_equal_support_choose_one_real_record() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let different_metadata = pile.put::<SimpleArchive, _>(
            entity! { metadata::tag: Id::new([99; 16]).unwrap() }
                .facts()
                .clone(),
        )?;
        let duplicate = CollectionCommit::sign(
            &fixture.signer,
            fixture.source.handle(),
            fixture.commits[0].data(),
            different_metadata,
        );
        pile.insert(CollectionRecord::Commit(duplicate))?;
        pile.close()?;
        append(fixture.file.path(), [frame(fixture.equations[0])])?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 1,
                ..Report::default()
            }
        );
        let records = fixture.records()?;
        let derived = records
            .iter()
            .find_map(|record| match record {
                CollectionRecord::Derive(derive) => Some(*derive),
                _ => None,
            })
            .unwrap();
        // Two COMMITs assert the same payload. The endorsement names that
        // payload once, so which of them a reader relates it to is not a
        // choice the migration has to make any more -- there is exactly one
        // record, not one per producer.
        assert_eq!(derived.input(), duplicate.data());
        assert_eq!(derived.input(), fixture.commits[0].data());
        Ok(())
    }

    #[test]
    fn equal_support_alternative_equations_are_all_idempotent_receipts() -> Result<()> {
        let fixture = Fixture::new()?;
        let a = fixture.commits[0].data();
        let b = fixture.commits[1].data();
        let [x, y, z] = fixture.images;
        // These are two lawful routes to the same {a, b} support: the
        // initial join and absorption of x into that already joined result.
        // Each source payload still has exactly one derived image.
        let equations = [
            derive(fixture.target, a, x),
            derive(fixture.target, b, y),
            merge(fixture.target, x, y, z),
            merge(fixture.target, z, x, z),
        ];
        append(fixture.file.path(), equations.map(frame))?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 4,
                ..Report::default()
            }
        );
        let after = fs::read(fixture.file.path())?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                already_present: 4,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, after);
        Ok(())
    }

    #[test]
    fn conflicting_planned_derive_outputs_abort_without_appending() -> Result<()> {
        for signed in [false, true] {
            let fixture = Fixture::new()?;
            let a = fixture.commits[0].data();
            let b = fixture.commits[1].data();
            let [x, y, z] = fixture.images;
            let equations = [
                derive(fixture.target, a, x),
                derive(fixture.target, a, y),
                derive(fixture.target, b, z),
            ];
            append(
                fixture.file.path(),
                equations.into_iter().map(|equation| {
                    if signed {
                        signed_frame(equation, &fixture.signer)
                    } else {
                        frame(equation)
                    }
                }),
            )?;
            let before = fs::read(fixture.file.path())?;
            for dry_run in [true, false] {
                let error = fixture.endorse(dry_run).unwrap_err();
                let conflict = error
                    .downcast_ref::<CollectionFunctionalConflict>()
                    .context("expected a functional conflict")?;
                match conflict {
                    CollectionFunctionalConflict::Derive {
                        target,
                        input,
                        first,
                        second,
                    } => {
                        assert_eq!(*target, fixture.target);
                        assert_eq!(*input, a);
                        assert_eq!(
                            BTreeSet::from([first.data, second.data]),
                            BTreeSet::from([x, y])
                        );
                    }
                    other => bail!("expected a DERIVE conflict, got {other}"),
                }
                // The independent b -> z endorsement must not leak out either.
                assert_eq!(fs::read(fixture.file.path())?, before);
            }
        }
        Ok(())
    }

    #[test]
    fn conflicting_planned_merge_outputs_abort_without_appending() -> Result<()> {
        for signed in [false, true] {
            let fixture = Fixture::new()?;
            let [x, y, z] = fixture.images;
            let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
            let other_result = blob(&mut pile, "conflicting-union")?;
            pile.close()?;
            let equations = [
                fixture.equations[0],
                fixture.equations[1],
                merge(fixture.target, x, y, z),
                merge(fixture.target, y, x, other_result),
            ];
            append(
                fixture.file.path(),
                equations.into_iter().map(|equation| {
                    if signed {
                        signed_frame(equation, &fixture.signer)
                    } else {
                        frame(equation)
                    }
                }),
            )?;
            let before = fs::read(fixture.file.path())?;
            for dry_run in [true, false] {
                let error = fixture.endorse(dry_run).unwrap_err();
                let conflict = error
                    .downcast_ref::<CollectionFunctionalConflict>()
                    .context("expected a functional conflict")?;
                match conflict {
                    CollectionFunctionalConflict::Merge {
                        collection,
                        low,
                        high,
                        first,
                        second,
                    } => {
                        assert_eq!(*collection, fixture.target);
                        assert_eq!((*low, *high), (x.min(y), x.max(y)));
                        assert_eq!(
                            BTreeSet::from([first.data, second.data]),
                            BTreeSet::from([z, other_result]),
                        );
                    }
                    other => bail!("expected a MERGE conflict, got {other}"),
                }
                // Even the otherwise valid prerequisite DERIVEs stay planned.
                assert_eq!(fs::read(fixture.file.path())?, before);
            }
        }
        Ok(())
    }

    #[test]
    fn planned_output_cannot_conflict_with_an_admitted_equation() -> Result<()> {
        let fixture = Fixture::new()?;
        let a = fixture.commits[0];
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
    &fixture.signer,
    fixture.target,
    a.data(),
    fixture.images[0],
)))?;
        pile.close()?;
        append(
            fixture.file.path(),
            [frame(derive(fixture.target, a.data(), fixture.images[1]))],
        )?;
        let before = fs::read(fixture.file.path())?;
        let error = fixture.endorse(false).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<CollectionFunctionalConflict>(),
            Some(CollectionFunctionalConflict::Derive { .. }),
        ));
        assert_eq!(fs::read(fixture.file.path())?, before);
        Ok(())
    }

    #[test]
    fn newly_closed_native_conflicts_are_checked_with_authority() -> Result<()> {
        for authorized in [false, true] {
            let fixture = Fixture::new()?;
            let [a, b] = fixture.commits;
            let [x, y, _] = fixture.images;
            let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
            // P is a real signed record, but not yet in the pile. Its exact
            // bytes are what the historical a -> x plan will later produce.
            let p = CollectionDerive::sign(
    &fixture.signer,
    fixture.target,
    a.data(),
    x,
);
            let q = CollectionDerive::sign(
    &fixture.signer,
    fixture.target,
    b.data(),
    y,
);
            pile.insert(CollectionRecord::Derive(q))?;
            let bad = blob(&mut pile, "dormant-conflicting-result")?;
            let outsider = SigningKey::from_bytes(&[43; 32]);
            pile.insert(CollectionRecord::Merge(CollectionMerge::sign(
    if authorized {
                    &fixture.signer
                } else {
                    &outsider
                },
    fixture.target,
    x,
    y,
    bad,
)))?;
            pile.close()?;
            append(
                fixture.file.path(),
                [frame(fixture.equations[0]), frame(fixture.equations[2])],
            )?;
            let before = fs::read(fixture.file.path())?;
            if authorized {
                for dry_run in [true, false] {
                    let error = fixture.endorse(dry_run).unwrap_err();
                    assert!(format!("{error:#}").contains("conflicting merge outputs"));
                    assert_eq!(fs::read(fixture.file.path())?, before);
                }
            } else {
                let expected = Report {
                    endorsed: 2,
                    ..Report::default()
                };
                assert_eq!(fixture.endorse(true)?, expected);
                assert_eq!(fs::read(fixture.file.path())?, before);
                assert_eq!(fixture.endorse(false)?, expected);
                let after = fs::read(fixture.file.path())?;
                assert_eq!(&after[..before.len()], before);
                assert_eq!(
                    fixture.endorse(false)?,
                    Report {
                        already_present: 2,
                        ..Report::default()
                    }
                );
                assert_eq!(fs::read(fixture.file.path())?, after);
            }
        }
        Ok(())
    }

    #[test]
    fn newly_closed_native_support_needs_no_second_round() -> Result<()> {
        let fixture = Fixture::new()?;
        let [a, b] = fixture.commits;
        let [x, z, y] = fixture.images;
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let c = pile.commit(
            fixture.source,
            &fixture.signer,
            entity! { metadata::tag: Id::new([3; 16]).unwrap() },
        )?;
        let dz = CollectionDerive::sign(&fixture.signer, fixture.target, b.data(), z);
        let dy = CollectionDerive::sign(&fixture.signer, fixture.target, c.data(), y);
        pile.insert(CollectionRecord::Derive(dz))?;
        pile.insert(CollectionRecord::Derive(dy))?;
        pile.insert(CollectionRecord::Merge(CollectionMerge::sign(
            &fixture.signer,
            fixture.target,
            x,
            z,
            z,
        )))?;
        let result = blob(&mut pile, "activated-support-result")?;
        pile.close()?;
        append(
            fixture.file.path(),
            [
                frame(derive(fixture.target, a.data(), x)),
                frame(merge(fixture.target, z, y, result)),
            ],
        )?;
        let before = fs::read(fixture.file.path())?;
        // K first certifies {b,c}; P then closes the already stored M, whose
        // {a,b} support has to reach K. That used to need a second planning
        // round and a third record -- K reissued once its support had widened.
        // A record states a payload relation and never states its support, so
        // K is written once and the widening happens underneath it, in the
        // coverage fold, with no second round to reach a fixed point in.
        let expected_report = Report {
            endorsed: 2,
            ..Report::default()
        };
        assert_eq!(fixture.endorse(true)?, expected_report);
        assert_eq!(fs::read(fixture.file.path())?, before);
        assert_eq!(fixture.endorse(false)?, expected_report);
        let expected_support = fixture
            .source
            .cover([a, b, c].map(|commit| Inline::new(commit.data().raw)));
        assert_eq!(
            fixture.support_for(fixture.target, result)?,
            expected_support
        );
        let after = fs::read(fixture.file.path())?;
        assert_eq!(&after[..before.len()], before);
        for _ in 0..3 {
            assert_eq!(
                fixture.endorse(false)?,
                Report {
                    already_present: 2,
                    ..Report::default()
                }
            );
            assert_eq!(fs::read(fixture.file.path())?, after);
        }
        Ok(())
    }

    #[test]
    fn commuting_square_conflicts_abort_before_appending() -> Result<()> {
        for agrees in [false, true] {
            let fixture = Fixture::new()?;
            let [a, b] = fixture.commits;
            let [x, y, z] = fixture.images;
            let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
            let c = blob(&mut pile, "merged-source-member")?;
            pile.insert(CollectionRecord::Merge(CollectionMerge::sign(
    &fixture.signer,
    fixture.source.handle(),
    a.data(),
    b.data(),
    c,
)))?;
            let joined = if agrees {
                z
            } else {
                blob(&mut pile, "noncommuting-target-result")?
            };
            pile.close()?;
            append(
                fixture.file.path(),
                [
                    frame(derive(fixture.target, a.data(), x)),
                    frame(derive(fixture.target, b.data(), y)),
                    frame(derive(fixture.target, c, z)),
                    frame(merge(fixture.target, x, y, joined)),
                ],
            )?;
            let before = fs::read(fixture.file.path())?;
            if agrees {
                assert_eq!(
                    fixture.endorse(true)?,
                    Report {
                        endorsed: 4,
                        ..Report::default()
                    }
                );
                assert_eq!(fs::read(fixture.file.path())?, before);
                assert_eq!(
                    fixture.endorse(false)?,
                    Report {
                        endorsed: 4,
                        ..Report::default()
                    }
                );
                let after = fs::read(fixture.file.path())?;
                assert_eq!(
                    fixture.endorse(false)?,
                    Report {
                        already_present: 4,
                        ..Report::default()
                    }
                );
                assert_eq!(fs::read(fixture.file.path())?, after);
            } else {
                for dry_run in [true, false] {
                    let error = fixture.endorse(dry_run).unwrap_err();
                    assert!(format!("{error:#}").contains("conflicting merge outputs"));
                    assert_eq!(fs::read(fixture.file.path())?, before);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn a_missing_output_is_refused_and_an_ungrounded_cycle_is_merely_unbelieved() -> Result<()> {
        let fixture = Fixture::new()?;
        let a = fixture.images[0];
        let b = fixture.images[1];
        let c = fixture.images[2];
        append(
            fixture.file.path(),
            [
                frame(merge(fixture.target, a, c, b)),
                frame(merge(fixture.target, b, c, a)),
                frame(derive(
                    fixture.target,
                    fixture.commits[0].data(),
                    Inline::new([0xff; 32]),
                )),
            ],
        )?;
        // The derive's output blob is absent, and that is still refused: you
        // cannot endorse a result you do not have.
        //
        // The two merges cycle a -> b -> a with nothing grounding either, and
        // they ARE endorsed now. Under witnesses the migration refused them,
        // because no witness record existed to cite. That gate moved rather
        // than vanished: an equation is a statement its author is entitled to
        // make, and whether anything reaches it from the foundation is settled
        // by the reader, in the coverage fold, at read time. So the records
        // exist and mean nothing -- their support is empty.
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 2,
                missing_outputs: 1,
                ..Report::default()
            }
        );
        let empty = fixture.source.cover([]);
        assert_eq!(fixture.support_for(fixture.target, a)?, empty);
        assert_eq!(fixture.support_for(fixture.target, b)?, empty);
        Ok(())
    }

    #[test]
    fn invalid_old_signatures_and_noncanonical_bodies_stay_opaque() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut invalid = signed_frame(fixture.equations[0], &fixture.signer);
        invalid[255] ^= 1;
        let mut malformed = signed_frame(fixture.equations[2], &fixture.signer);
        malformed[511] = 1;
        append(fixture.file.path(), [invalid, malformed])?;
        let before = fs::read(fixture.file.path())?;
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                invalid_signatures: 1,
                malformed_signed_frames: 1,
                ..Report::default()
            }
        );
        assert_eq!(fs::read(fixture.file.path())?, before);
        Ok(())
    }

    #[test]
    fn exact_target_selection_and_writer_authority_remain_explicit() -> Result<()> {
        let fixture = Fixture::new()?;
        let unrelated = derive(
            fixture.source.handle(),
            fixture.commits[0].data(),
            fixture.images[0],
        );
        append(
            fixture.file.path(),
            [frame(fixture.equations[0]), frame(unrelated)],
        )?;
        let before = fs::read(fixture.file.path())?;
        let historical = inventory(fixture.file.path(), fixture.target)?;
        assert_eq!(historical.equations.len(), 1);
        let mut pile = super::super::super::open_refreshed(fixture.file.path())?;
        let outsider = SigningKey::from_bytes(&[43; 32]);
        assert_eq!(
            endorse(&mut pile, historical, fixture.target, &outsider, false)?,
            Report {
                unauthorized: 1,
                ..Report::default()
            },
        );
        pile.close()?;
        assert_eq!(fs::read(fixture.file.path())?, before);
        assert_eq!(
            fixture.endorse(false)?,
            Report {
                endorsed: 1,
                ..Report::default()
            }
        );
        Ok(())
    }

    #[test]
    fn missing_existing_key_never_creates_a_key_or_modifies_the_pile() -> Result<()> {
        let fixture = Fixture::new()?;
        let before = fs::read(fixture.file.path())?;
        let directory = tempfile::tempdir()?;
        let key = directory.path().join("absent.key");
        assert!(run(
            fixture.file.path().to_path_buf(),
            hex::encode(fixture.target.raw),
            key.clone(),
            false
        )
        .is_err());
        assert!(!key.exists());
        assert_eq!(fs::read(fixture.file.path())?, before);
        Ok(())
    }

    #[test]
    fn command_uses_the_explicit_existing_key_and_preserves_it() -> Result<()> {
        let fixture = Fixture::new()?;
        append(fixture.file.path(), fixture.equations.map(frame))?;
        let key = NamedTempFile::new()?;
        let key_bytes = hex::encode(fixture.signer.to_bytes());
        fs::write(key.path(), key_bytes.as_bytes())?;
        let collection = format!("blake3:{}", hex::encode(fixture.target.raw));
        let before = fs::read(fixture.file.path())?;
        run(
            fixture.file.path().to_path_buf(),
            collection.clone(),
            key.path().to_path_buf(),
            true,
        )?;
        assert_eq!(fs::read(fixture.file.path())?, before);
        run(
            fixture.file.path().to_path_buf(),
            collection.clone(),
            key.path().to_path_buf(),
            false,
        )?;
        let after = fs::read(fixture.file.path())?;
        assert!(after.len() > before.len());
        run(
            fixture.file.path().to_path_buf(),
            collection,
            key.path().to_path_buf(),
            false,
        )?;
        assert_eq!(fs::read(fixture.file.path())?, after);
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
