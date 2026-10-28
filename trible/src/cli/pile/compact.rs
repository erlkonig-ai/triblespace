//! Whole-pile physical compaction, conservative by default.
//!
//! The default mode is not garbage collection. Every distinct resident blob
//! is an explicit direct root; the retained-rewrite machinery then projects
//! current native sets and legacy pin state through their own semantics. The
//! rewrite drops physical duplicates, superseded log entries, corrupt blob
//! occurrences when another occurrence validates, and known semantically inert
//! retired records such as `RetiredCollectionDeriveV4`, historical PEER
//! evidence, STORE_SCOPE assertions, and retired WANT logs. Repacked blob
//! records receive fresh insertion timestamps. Distinct collection equations
//! and commits are never inferred to be redundant. Retired capability proofs
//! are capability records and are carried exactly. A frame whose kind this
//! binary does not know is carried exactly, by its own length, and counted:
//! nothing it could name is dropped here, and a binary that knows the kind
//! reads it from the compacted pile unchanged (JP, 2026-09-13).
//!
//! Length checks reject ordinary concurrent appends observed during the work,
//! but callers requiring an exact whole-file result must still quiesce writers:
//! an append after the final check can remain outside the valid observed-prefix
//! result.
//!
//! `--source-prefix L` reads the source as exactly its first `L` bytes,
//! through a read-only handle bounded to that prefix: writers may keep
//! appending while it runs, nothing at or past `L` is mapped, parsed or
//! replayed, and every length check compares against `L`. Because the pile
//! is append-only, the result is the compaction of a copy of those `L`
//! bytes without making the copy. `L` must be a record boundary.
//!
//! The destination is written under a hidden name beside it and published
//! by hard link only when the run is complete, so a run that fails or is
//! killed leaves no file that looks like a finished compaction.
//!
//! `--dropped-into DROPPED` keeps what the compaction drops. After the
//! compaction is written and closed, every frame of the source it does not
//! hold is written to DROPPED by `pile subtract`'s own
//! [`super::subtract::write_difference`], with the source bounded to exactly
//! the bytes the compaction read. Difference files kept beside an older
//! mainline stay complete only while the mainline keeps what they left out;
//! a compaction can drop such a frame, so its dropped set is the next
//! difference generation, written as exhaust of the run that drops it. The
//! destination is published only after DROPPED is: a compacted pile without
//! its dropped frames is the one result that must not look finished.
//!
//! The record census is lock-free. On a source a writer is appending to it
//! can map an append still in flight; when the file grew while the census
//! read it and a second read finds the record whole, the failure says so
//! instead of advising repair.
//!
//! `--drop-collection` is deliberately different: it opts into reachability
//! garbage collection. Only bytes reached by carried records, proofs, WANTs,
//! pins and opaque-frame conservative references survive. Raw unrooted blobs
//! are not promised retention. Exclusion is physical copying policy, not
//! revocation, semantic retraction, or a promise that sync will not restore it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use triblespace_core::collection::records::CollectionHandle;
use triblespace_core::repo::pile::{
    CollectionFrame, CollectionFrameFilter, CorruptBlobPolicy, DrainedGeneration, Pile,
    PileRecordContent, PileRecords, PileRewriteStats, PreparedRetainedRewrite, WantRewritePolicy,
};
use triblespace_core::repo::{BlobStoreList, RetentionRoots, SnapshotSource};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RecordCensus {
    bytes: u64,
    blobs: usize,
    collection_records: usize,
    capability_proofs: usize,
    retired_capability_proofs: usize,
    current_wants: usize,
    retired_want_records: usize,
    retired_team_records: usize,
    opaque: usize,
    opaque_bytes: u64,
}

fn census(path: &Path, prefix: Option<u64>) -> Result<RecordCensus> {
    let records = match prefix {
        Some(prefix) => PileRecords::open_prefix(path, prefix),
        None => PileRecords::open(path),
    };
    let records = records.map_err(|error| super::pile_read_error(path, error))?;
    census_records(path, records)
}

/// Count the records `records`, a lock-free scan opened on `path`, holds.
fn census_records(path: &Path, mut records: PileRecords) -> Result<RecordCensus> {
    let bytes = u64::try_from(records.bytes().len()).context("pile length exceeds u64")?;
    let mut census = RecordCensus {
        bytes,
        ..RecordCensus::default()
    };
    while let Some(record) = records.next() {
        let record = record.map_err(|error| census_read_error(path, bytes, error))?;
        match record.content {
            PileRecordContent::Blob { .. } => census.blobs += 1,
            PileRecordContent::Collection { .. } => census.collection_records += 1,
            PileRecordContent::CapabilityProof { .. } => census.capability_proofs += 1,
            PileRecordContent::RetiredCapabilityProof => census.retired_capability_proofs += 1,
            PileRecordContent::Want { .. } => census.current_wants += 1,
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => census.retired_want_records += 1,
            PileRecordContent::RetiredPeerEvidenceV1
            | PileRecordContent::RetiredStoreScopeV1
            | PileRecordContent::RetiredArtifactOfferV1 => census.retired_team_records += 1,
            PileRecordContent::Opaque { .. } => {
                census.opaque += 1;
                census.opaque_bytes +=
                    u64::try_from(record.len).context("frame length exceeds u64")?;
            }
            _ => {}
        }
    }
    Ok(census)
}

/// A census read failure. The census takes no lock, so on a pile a writer
/// is appending to it can map a record still being written and stop there.
/// Growth alone does not show that: a live pile grows whatever stopped the
/// census, damage in the middle included. So when the file grew, it is read
/// again, and only a record that is now whole earns "a writer is
/// appending", with its boundary as a safe `--source-prefix`. Anything else
/// keeps the damage advice, saying what the second read saw.
fn census_read_error(
    path: &Path,
    observed: u64,
    error: triblespace_core::repo::pile::ReadError,
) -> anyhow::Error {
    use triblespace_core::repo::pile::ReadError;
    if let ReadError::CorruptPile { valid_length } = error {
        let damage = || super::pile_read_error(path, ReadError::CorruptPile { valid_length });
        let Ok(now) = std::fs::metadata(path).map(|metadata| metadata.len()) else {
            return damage();
        };
        if now <= observed {
            return damage();
        }
        if !reads_whole_at(path, valid_length) {
            return damage().context(format!(
                "the file grew from {observed} to {now} bytes while the census read it, but a \
                 second read of the grown file still stops at byte {valid_length}: that is \
                 damage, or an append still in progress there. Stop the writers and retry to \
                 tell them apart"
            ));
        }
        return anyhow!(
            "source pile {} changed while being read: the record census mapped {observed} bytes \
             and found the record at byte {valid_length} still incomplete, the file has since \
             grown to {now} bytes, and a second read finds that record whole, so a writer is \
             appending. This is not damage. Compaction needs a quiescent source: stop its \
             writers and retry, or compact a fixed prefix with --source-prefix {valid_length} \
             (a record boundary)",
            path.display()
        );
    }
    super::pile_read_error(path, error)
}

/// Whether a fresh scan of the file at `path` reads a whole record at
/// `offset`.
fn reads_whole_at(path: &Path, offset: usize) -> bool {
    let Ok(records) = PileRecords::open(path) else {
        return false;
    };
    for record in records {
        match record {
            Ok(record) if record.offset < offset => continue,
            Ok(record) => return record.offset == offset,
            Err(_) => return false,
        }
    }
    false
}

pub(super) fn create_fresh_destination(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

pub(super) fn cleanup_incomplete_destination(path: &Path, primary: anyhow::Error) -> anyhow::Error {
    match std::fs::remove_file(path) {
        Ok(()) => primary,
        Err(cleanup) => primary.context(format!(
            "additionally failed to remove incomplete destination {}: {cleanup}",
            path.display()
        )),
    }
}

/// Whether `a` and `b` name the same directory entry, through their
/// existing directories' canonical paths.
fn same_entry(a: &Path, b: &Path) -> Result<bool> {
    let entry = |path: &Path| -> Result<(PathBuf, Option<std::ffi::OsString>)> {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = std::fs::canonicalize(directory)
            .with_context(|| format!("resolve {}", directory.display()))?;
        Ok((directory, path.file_name().map(ToOwned::to_owned)))
    };
    Ok(entry(a)? == entry(b)?)
}

/// The source length every check compares: the file's length, or for a
/// `--source-prefix` handle the prefix itself (less only if the file shrank
/// below it).
fn observed_source_len(source: &Pile, when: &str) -> Result<u64> {
    source
        .observed_length()
        .map_err(|error| anyhow!("stat source pile {when}: {error}"))
}

fn compact_into(
    source: &mut Pile,
    destination: &mut Pile,
    stable_source_len: u64,
    drained: &[DrainedGeneration],
    prepared: Option<PreparedRetainedRewrite>,
) -> Result<PileRewriteStats> {
    let mut roots = RetentionRoots::new();
    if prepared.is_none() {
        let snapshot = source.snapshot().context("freeze source pile")?;
        for info in snapshot.blobs() {
            let info = info.map_err(|error| anyhow!("list source blobs: {error}"))?;
            // Default compact is conservative, not reachability GC.
            roots.retain_direct(info.handle);
        }
    }

    let after_inventory = observed_source_len(source, "after inventory")?;
    if after_inventory != stable_source_len {
        bail!(
            "source pile changed while its blob inventory was frozen ({} -> {} bytes); retry after quiescing writers",
            stable_source_len,
            after_inventory,
        );
    }

    let stats = if let Some(prepared) = prepared {
        prepared.write_into(destination, CorruptBlobPolicy::Refuse)
    } else {
        source.rewrite_retained_into_leaving(
            destination,
            &roots,
            WantRewritePolicy::Preserve,
            drained,
        )
    }
    .map_err(|error| anyhow!("compact pile: {error}"))?;

    let final_source_len = observed_source_len(source, "after compaction")?;
    if final_source_len != stable_source_len {
        bail!(
            "source pile changed during compaction ({} -> {} bytes); cleanup of the incomplete destination will be attempted and any cleanup failure reported; retry after quiescing writers",
            stable_source_len,
            final_source_len,
        );
    }
    Ok(stats)
}

struct ExcludeCollections<'a>(&'a BTreeSet<CollectionHandle>);

impl CollectionFrameFilter for ExcludeCollections<'_> {
    fn carries(&mut self, frame: &CollectionFrame) -> bool {
        !frame
            .collection
            .is_some_and(|collection| self.0.contains(&collection))
    }
}

/// What `pile compact` is asked to do.
pub(super) struct Request {
    pub source: PathBuf,
    pub into: PathBuf,
    pub drop_drained: Vec<String>,
    pub drop_collection: Vec<String>,
    pub source_prefix: Option<u64>,
    pub dropped_into: Option<PathBuf>,
}

pub(super) fn run(request: Request) -> Result<()> {
    let Request {
        source: source_path,
        into: destination_path,
        drop_drained,
        drop_collection,
        source_prefix,
        dropped_into,
    } = request;
    let drained = drop_drained
        .iter()
        .map(|pair| {
            let (retired, current) = pair.split_once('=').ok_or_else(|| {
                anyhow!("--drop-drained takes RETIRED=CURRENT, two collection handles: {pair:?}")
            })?;
            Ok(DrainedGeneration {
                retired: super::collection::parse_collection_handle(retired)?,
                current: super::collection::parse_collection_handle(current)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if destination_path.exists() {
        bail!(
            "destination {} already exists; compact writes a fresh pile",
            destination_path.display()
        );
    }
    if let Some(dropped) = &dropped_into {
        if *dropped == destination_path || *dropped == source_path {
            bail!(
                "--dropped-into {} names the same path as the {}; it must be a third file",
                dropped.display(),
                if *dropped == source_path {
                    "source"
                } else {
                    "destination"
                }
            );
        }
        super::subtract::refuse_existing(dropped).context("--dropped-into")?;
    }

    eprintln!("Compaction: scanning source record headers...");
    let source_census = census(&source_path, source_prefix)?;

    eprintln!(
        "Compaction: opening source indexes ({} bytes)...",
        source_census.bytes
    );
    let mut source = match source_prefix {
        // Read-only, bounded, and replayed to exactly the prefix by the open.
        Some(prefix) => Pile::open_prefix(&source_path, prefix)
            .map_err(|error| super::pile_read_error(&source_path, error))?,
        None => super::open_refreshed(&source_path)?,
    };
    let source_permissions = match source.backing_file_metadata() {
        Ok(metadata) => metadata.permissions(),
        Err(error) => {
            let _ = source.close();
            return Err(anyhow!(error).context("stat source pile"));
        }
    };
    let stable_source_len = match observed_source_len(&source, "after replay") {
        Ok(length) => length,
        Err(error) => {
            let _ = source.close();
            return Err(error);
        }
    };
    if source_prefix.is_some_and(|prefix| prefix != stable_source_len) {
        let _ = source.close();
        bail!(
            "source pile shrank below its fixed prefix ({} -> {} bytes)",
            source_prefix.unwrap_or_default(),
            stable_source_len,
        );
    }
    if stable_source_len != source_census.bytes {
        let _ = source.close();
        bail!(
            "source pile changed during compaction preflight ({} -> {} bytes); retry after quiescing writers",
            source_census.bytes,
            stable_source_len,
        );
    }

    // Resolve every selection and native rewrite refusal before even creating
    // the destination directory/file. Keep that exact frozen selection for
    // copying, so neither the filter nor the retention walk runs twice.
    let selection = (|| -> Result<_> {
        if drop_collection.is_empty() {
            return Ok((BTreeSet::new(), None));
        }
        eprintln!("Compaction: resolving collection exclusions...");
        let snapshot = source.snapshot().context("freeze exclusion selection")?;
        let excluded = super::collection::resolve_exclusions(&snapshot, &drop_collection)?;
        drop(snapshot);
        eprintln!("Compaction: selecting retained frames and walking blob references...");
        let prepared = source
            .prepare_retained_rewrite(
                &RetentionRoots::new(),
                WantRewritePolicy::Preserve,
                &drained,
                &mut ExcludeCollections(&excluded),
            )
            .map_err(|error| anyhow!("plan collection exclusion: {error}"))?;
        if !prepared.corrupt_blobs().is_empty() {
            bail!("collection exclusion reaches {} corrupt blobs; refusing before destination creation",
                prepared.corrupt_blobs().len());
        }
        let planned_len = observed_source_len(&source, "after exclusion plan")?;
        if planned_len != stable_source_len {
            bail!(
                "source pile changed during collection exclusion preflight ({} -> {} bytes)",
                stable_source_len,
                planned_len
            );
        }
        eprintln!(
            "Compaction: retained {} blobs ({} payload bytes); selection complete.",
            prepared.retained_blobs(),
            prepared.retained_bytes(),
        );
        Ok((excluded, Some(prepared)))
    })();
    let (excluded, prepared) = match selection {
        Ok(selection) => selection,
        Err(error) => {
            let _ = source.close();
            return Err(error);
        }
    };

    if let Some(parent) = destination_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create destination directory {}", parent.display()))?;
    }
    if let Some(parent) = dropped_into
        .as_deref()
        .and_then(Path::parent)
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create --dropped-into directory {}", parent.display()))?;
    }
    if let Some(dropped) = &dropped_into {
        // Both directories exist now, so a second spelling of one entry
        // shows: publishing DROPPED there would put the dropped frames
        // where the compaction is expected.
        let same = same_entry(dropped, &destination_path);
        if !matches!(same, Ok(false)) {
            let _ = source.close();
            let reason = match same {
                Ok(_) => "is the same file as the destination".to_owned(),
                Err(error) => format!("cannot be told apart from the destination: {error:#}"),
            };
            bail!(
                "--dropped-into {} {reason} {}; it must be a third file",
                dropped.display(),
                destination_path.display()
            );
        }
    }
    // The compaction is written under a hidden name and published as the
    // destination only when the run is complete, its dropped frames
    // included: a run that fails or is killed before then leaves no file
    // that looks like a finished compaction.
    let building = match super::subtract::temporary_sibling(&destination_path, "compact") {
        Ok(building) => building,
        Err(error) => {
            let _ = source.close();
            return Err(error);
        }
    };
    let destination_file = match create_fresh_destination(&building) {
        Ok(file) => file,
        Err(error) => {
            let _ = source.close();
            return Err(anyhow!(error).context(format!("create {}", building.display())));
        }
    };
    let mut destination = match Pile::open(&building) {
        Ok(pile) => pile,
        Err(error) => {
            drop(destination_file);
            let _ = source.close();
            return Err(cleanup_incomplete_destination(
                &building,
                anyhow!("open destination {}: {error}", building.display()),
            ));
        }
    };

    eprintln!("Compaction: copying retained state to fresh destination...");
    let operation = compact_into(
        &mut source,
        &mut destination,
        stable_source_len,
        &drained,
        prepared,
    )
    .and_then(|stats| Ok((stats, census(&building, None)?)));
    let destination_close = destination
        .close()
        .map_err(|error| anyhow!("close destination: {error}"));
    let source_close = source
        .close()
        .map_err(|error| anyhow!("close source: {error}"));

    let (stats, destination_census) = match (operation, destination_close, source_close) {
        (Ok(result), Ok(()), Ok(())) => result,
        (Err(error), _, _) | (Ok(_), Err(error), _) | (Ok(_), Ok(()), Err(error)) => {
            drop(destination_file);
            return Err(cleanup_incomplete_destination(&building, error));
        }
    };

    if let Err(error) = destination_file.set_permissions(source_permissions) {
        let error = anyhow!(error).context(format!(
            "copy source permissions to destination {}",
            building.display()
        ));
        drop(destination_file);
        return Err(cleanup_incomplete_destination(&building, error));
    }
    drop(destination_file);

    // The compaction is not finished until what it dropped is kept.
    let dropped = match &dropped_into {
        None => None,
        Some(dropped_path) => {
            eprintln!(
                "Compaction: writing the frames it dropped into {}...",
                dropped_path.display()
            );
            match super::subtract::write_difference(
                &source_path,
                &building,
                dropped_path,
                false,
                // Exactly the bytes the compaction read.
                Some(stable_source_len),
            ) {
                Ok(difference) => Some(difference.against(&destination_path)),
                Err(error) => {
                    let state = if std::fs::symlink_metadata(dropped_path).is_ok() {
                        "exists but the run failed after publishing it; inspect it"
                    } else {
                        "was not created"
                    };
                    let error = error.context(format!(
                        "could not keep the compaction's dropped frames in {} ({} {state}); \
                         the compaction is discarded and {} was not created, because a \
                         compacted pile without its dropped frames would lose what older \
                         difference files left out. The source is unchanged; fix the cause \
                         and rerun",
                        dropped_path.display(),
                        dropped_path.display(),
                        destination_path.display(),
                    ));
                    return Err(cleanup_incomplete_destination(&building, error));
                }
            }
        }
    };

    if let Err(error) = super::subtract::publish(&building, &destination_path) {
        let kept = dropped_into
            .as_deref()
            .map(|dropped| format!("; its dropped frames are kept in {}", dropped.display()))
            .unwrap_or_default();
        let error = error.context(format!(
            "finish the compaction into {}{kept}",
            destination_path.display()
        ));
        return Err(if building.exists() {
            cleanup_incomplete_destination(&building, error)
        } else {
            error
        });
    }

    println!(
        "Compacted {} into {}:\n  bytes: {} -> {}\n  blob records: {} -> {}\n  collection records: {} -> {}\n  capability proofs: {} -> {}\n  retired capability proofs: {} -> {} (carried exactly)\n  current WANT records: {} -> {}\n  retired WANT log records: {} -> {} (dropped)\n  retired team records: {} -> {} (dropped)\n  frames of unknown kind: {} ({} bytes) -> {} ({} bytes) (carried exactly)\n  active wants: {}\n  active legacy pins: {}",
        source_path.display(),
        destination_path.display(),
        source_census.bytes,
        destination_census.bytes,
        source_census.blobs,
        destination_census.blobs,
        source_census.collection_records,
        destination_census.collection_records,
        source_census.capability_proofs,
        destination_census.capability_proofs,
        source_census.retired_capability_proofs,
        destination_census.retired_capability_proofs,
        source_census.current_wants,
        destination_census.current_wants,
        source_census.retired_want_records,
        destination_census.retired_want_records,
        source_census.retired_team_records,
        destination_census.retired_team_records,
        source_census.opaque,
        source_census.opaque_bytes,
        destination_census.opaque,
        destination_census.opaque_bytes,
        stats.wants,
        stats.strong_pins,
    );
    println!(
        "  retired equations left behind, signed twin present: {}",
        stats.superseded_equations
    );
    if !drop_collection.is_empty() {
        println!("  excluded collections (including resident descriptor descendants): {}\n  collection frames excluded: {}\n  blob policy: reachability GC; raw unrooted blobs are not retained",
            excluded.len(), stats.filtered_frames);
    }
    println!(
        "  frames left behind with drained generations: {}",
        stats.drained_frames
    );
    println!(
        "  retired v8/v9 equations carried for the clean-pile migration: {}",
        stats.retired_equations
    );
    if let Some(difference) = dropped {
        println!("Dropped frames kept (source minus destination):");
        difference.print();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_compaction_refuses_source_append_before_copying() {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::repo::pile::CarryEveryFrame;
        use triblespace_core::repo::BlobStorePut;

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("source.pile");
        let destination_path = dir.path().join("destination.pile");
        create_fresh_destination(&source_path).unwrap();
        create_fresh_destination(&destination_path).unwrap();
        let mut source = Pile::open(&source_path).unwrap();
        let stable_len = source.backing_file_metadata().unwrap().len();
        let prepared = source
            .prepare_retained_rewrite(
                &RetentionRoots::new(),
                WantRewritePolicy::Preserve,
                &[],
                &mut CarryEveryFrame,
            )
            .unwrap();
        source
            .put::<UTF8String, _>("appended after preparation")
            .unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        let error = compact_into(
            &mut source,
            &mut destination,
            stable_len,
            &[],
            Some(prepared),
        )
        .unwrap_err();
        assert!(error.to_string().contains("source pile changed"));
        assert_eq!(destination.backing_file_metadata().unwrap().len(), 0);
        destination.close().unwrap();
        source.close().unwrap();
    }

    /// A pile of one complete blob frame followed by all but the last 8
    /// bytes of a second, as a writer leaves it mid-append. Returns the
    /// missing 8 bytes and the boundary before the torn frame.
    fn torn_pile(path: &Path) -> (Vec<u8>, u64) {
        use std::io::Write as _;
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::repo::BlobStorePut;

        let model = path.with_extension("model");
        create_fresh_destination(&model).unwrap();
        let mut pile = Pile::open(&model).unwrap();
        pile.put::<UTF8String, _>("the first, complete frame")
            .unwrap();
        pile.put::<UTF8String, _>("the second frame, still being appended")
            .unwrap();
        pile.close().unwrap();
        let bytes = std::fs::read(&model).unwrap();
        let first = PileRecords::open(&model)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .len;
        let cut = bytes.len() - 8;
        std::fs::File::create(path)
            .unwrap()
            .write_all(&bytes[..cut])
            .unwrap();
        (bytes[cut..].to_vec(), first as u64)
    }

    #[test]
    fn census_reports_a_source_that_grew_while_read_as_a_writer_not_damage() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.pile");
        let (rest, boundary) = torn_pile(&path);
        // The census maps the file, then the writer finishes its append.
        let records = PileRecords::open(&path).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&rest)
            .unwrap();

        let rendered = format!("{:#}", census_records(&path, records).unwrap_err());
        assert!(rendered.contains("changed while being read"), "{rendered}");
        assert!(rendered.contains("a writer is appending"), "{rendered}");
        assert!(
            rendered.contains(&format!("--source-prefix {boundary}")),
            "{rendered}"
        );
        assert!(!rendered.contains("amputate"), "{rendered}");
        // The finished pile reads whole.
        census(&path, None).unwrap();
    }

    /// A pile of three complete blob frames whose middle frame is damaged:
    /// its span is zeroed, which the reader calls a malformed record.
    /// Returns the damaged frame's offset.
    fn damaged_in_the_middle(path: &Path) -> u64 {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::repo::BlobStorePut;

        create_fresh_destination(path).unwrap();
        let mut pile = Pile::open(path).unwrap();
        for text in ["the first frame", "the damaged frame", "the frame after it"] {
            pile.put::<UTF8String, _>(text).unwrap();
        }
        pile.close().unwrap();
        let middle = PileRecords::open(path)
            .unwrap()
            .nth(1)
            .unwrap()
            .unwrap()
            .offset;
        let mut bytes = std::fs::read(path).unwrap();
        bytes[middle + 28..middle + 32].fill(0);
        std::fs::write(path, &bytes).unwrap();
        middle as u64
    }

    #[test]
    fn census_calls_damage_in_the_middle_damage_while_the_file_grows() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.pile");
        let damaged = damaged_in_the_middle(&path);
        // The census maps the file, then a writer appends after it.
        let records = PileRecords::open(&path).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0u8; 1024])
            .unwrap();

        let rendered = format!("{:#}", census_records(&path, records).unwrap_err());
        assert!(!rendered.contains("a writer is appending"), "{rendered}");
        assert!(!rendered.contains("--source-prefix"), "{rendered}");
        assert!(rendered.contains("amputate"), "{rendered}");
        assert!(
            rendered.contains(&format!("second read of the grown file still stops at byte {damaged}")),
            "{rendered}"
        );
    }

    #[test]
    fn census_calls_a_record_still_incomplete_on_a_second_read_unresolved() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.pile");
        let (rest, boundary) = torn_pile(&path);
        let records = PileRecords::open(&path).unwrap();
        // The file grows, but the torn frame is still not whole.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&rest[..4])
            .unwrap();

        let rendered = format!("{:#}", census_records(&path, records).unwrap_err());
        assert!(!rendered.contains("a writer is appending"), "{rendered}");
        assert!(!rendered.contains("--source-prefix"), "{rendered}");
        assert!(
            rendered.contains(&format!("second read of the grown file still stops at byte {boundary}")),
            "{rendered}"
        );
    }

    #[test]
    fn census_keeps_the_repair_advice_when_the_file_did_not_grow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.pile");
        torn_pile(&path);
        let rendered = format!("{:#}", census(&path, None).unwrap_err());
        assert!(rendered.contains("malformed or incomplete known record"));
        assert!(rendered.contains("amputate"), "{rendered}");
        assert!(!rendered.contains("changed while being read"));
    }

    #[test]
    fn cleanup_reports_removal_failure_without_losing_primary_error() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("still-a-directory");
        std::fs::create_dir(&destination).unwrap();

        let error = cleanup_incomplete_destination(&destination, anyhow!("primary failure"));
        let rendered = format!("{error:#}");
        assert!(rendered.contains("primary failure"));
        assert!(rendered.contains("additionally failed to remove incomplete destination"));
        assert!(rendered.contains(destination.to_str().unwrap()));
    }
}
