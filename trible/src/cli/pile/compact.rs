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

fn census(path: &Path) -> Result<RecordCensus> {
    let mut records =
        PileRecords::open(path).map_err(|error| super::pile_read_error(path, error))?;
    let bytes = u64::try_from(records.bytes().len()).context("pile length exceeds u64")?;
    let mut census = RecordCensus {
        bytes,
        ..RecordCensus::default()
    };
    while let Some(record) = records.next() {
        let record = record.map_err(|error| super::pile_read_error(path, error))?;
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

    let after_inventory = source
        .backing_file_metadata()
        .context("stat source pile after inventory")?
        .len();
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

    let final_source_len = source
        .backing_file_metadata()
        .context("stat source pile after compaction")?
        .len();
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

pub(super) fn run(
    source_path: PathBuf,
    destination_path: PathBuf,
    drop_drained: Vec<String>,
    drop_collection: Vec<String>,
) -> Result<()> {
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

    eprintln!("Compaction: scanning source record headers...");
    let source_census = census(&source_path)?;

    eprintln!(
        "Compaction: opening source indexes ({} bytes)...",
        source_census.bytes
    );
    let mut source = super::open_refreshed(&source_path)?;
    let source_metadata = source.backing_file_metadata().context("stat source pile")?;
    let stable_source_len = source_metadata.len();
    let source_permissions = source_metadata.permissions();
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
        let planned_len = source
            .backing_file_metadata()
            .context("stat source after exclusion plan")?
            .len();
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
    let destination_file = create_fresh_destination(&destination_path)
        .with_context(|| format!("create fresh destination {}", destination_path.display()))?;
    let mut destination = match Pile::open(&destination_path) {
        Ok(pile) => pile,
        Err(error) => {
            drop(destination_file);
            let _ = source.close();
            return Err(cleanup_incomplete_destination(
                &destination_path,
                anyhow!("open destination {}: {error}", destination_path.display()),
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
    .and_then(|stats| Ok((stats, census(&destination_path)?)));
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
            return Err(cleanup_incomplete_destination(&destination_path, error));
        }
    };

    if let Err(error) = destination_file.set_permissions(source_permissions) {
        let error = anyhow!(error).context(format!(
            "copy source permissions to destination {}",
            destination_path.display()
        ));
        drop(destination_file);
        return Err(cleanup_incomplete_destination(&destination_path, error));
    }
    drop(destination_file);

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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_compaction_refuses_source_append_before_copying() {
        use triblespace_core::repo::pile::CarryEveryFrame;
        use triblespace_core::repo::{BlobStorePut, StorageClose};

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
        source.put("appended after preparation").unwrap();
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
