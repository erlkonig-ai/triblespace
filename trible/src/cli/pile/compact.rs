//! Conservative whole-pile physical compaction.
//!
//! This is deliberately not garbage collection. Every distinct resident blob
//! is an explicit direct root; the retained-rewrite machinery then projects
//! current native sets and legacy pin state through their own semantics. The
//! rewrite drops physical duplicates, superseded log entries, corrupt blob
//! occurrences when another occurrence validates, and known semantically inert
//! retired records such as `RetiredCollectionDeriveV4`, historical PEER
//! evidence, STORE_SCOPE assertions, and retired WANT logs. Repacked blob
//! records receive fresh insertion timestamps. Distinct collection equations
//! and commits are never inferred to be redundant. A frame whose kind this
//! binary does not know is carried exactly, by its own length, and counted:
//! nothing it could name is dropped here, and a binary that knows the kind
//! reads it from the compacted pile unchanged (JP, 2026-09-13).
//!
//! Length checks reject ordinary concurrent appends observed during the work,
//! but callers requiring an exact whole-file result must still quiesce writers:
//! an append after the final check can remain outside the valid observed-prefix
//! result.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use triblespace_core::repo::pile::{
    Pile, PileRecordContent, PileRecords, PileRewriteStats, WantRewritePolicy,
};
use triblespace_core::repo::{BlobStoreList, RetentionRoots, SnapshotSource};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RecordCensus {
    bytes: u64,
    blobs: usize,
    collection_records: usize,
    capability_proofs: usize,
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
            PileRecordContent::Want { .. } => census.current_wants += 1,
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => census.retired_want_records += 1,
            PileRecordContent::RetiredPeerEvidenceV1
            | PileRecordContent::RetiredStoreScopeV1
            | PileRecordContent::RetiredArtifactOfferV1 => census.retired_team_records += 1,
            PileRecordContent::Opaque { .. } => {
                census.opaque += 1;
                census.opaque_bytes += u64::try_from(record.len).context("frame length exceeds u64")?;
            }
            _ => {}
        }
    }
    Ok(census)
}

fn create_fresh_destination(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn cleanup_incomplete_destination(path: &Path, primary: anyhow::Error) -> anyhow::Error {
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
) -> Result<PileRewriteStats> {
    let snapshot = source.snapshot().context("freeze source pile")?;
    let mut roots = RetentionRoots::new();
    for info in snapshot.blobs() {
        let info = info.map_err(|error| anyhow!("list source blobs: {error}"))?;
        // Direct is intentional: this command preserves every blob already in
        // the pile, so recursive discovery would add work without changing the
        // keep set.
        roots.retain_direct(info.handle);
    }
    drop(snapshot);

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

    let stats = source
        .rewrite_retained_into(destination, &roots, WantRewritePolicy::Preserve)
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

pub(super) fn run(source_path: PathBuf, destination_path: PathBuf) -> Result<()> {
    if destination_path.exists() {
        bail!(
            "destination {} already exists; compact writes a fresh pile",
            destination_path.display()
        );
    }

    let source_census = census(&source_path)?;

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

    let operation = compact_into(&mut source, &mut destination, stable_source_len)
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
        "Compacted {} into {}:\n  bytes: {} -> {}\n  blob records: {} -> {}\n  collection records: {} -> {}\n  capability proofs: {} -> {}\n  current WANT records: {} -> {}\n  retired WANT log records: {} -> {} (dropped)\n  retired team records: {} -> {} (dropped)\n  frames of unknown kind: {} ({} bytes) -> {} ({} bytes) (carried exactly)\n  active wants: {}\n  active legacy pins: {}",
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
