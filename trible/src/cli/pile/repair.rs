//! `trible pile repair`: copy every valid record of a damaged pile into a
//! fresh one, stepping over each torn or invalid region and naming it.

use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use triblespace_core::repo::pile::{
    PileRecordContent, PileRecords, RepairDefect, RepairStep, ResyncingRecords,
};

/// Exit status when the destination was written but ranges were skipped.
pub(super) const EXIT_SKIPPED: i32 = 3;

/// Write the repaired copy of `source` to `into` and report every skipped
/// range. Returns the process exit status: 0 when nothing was skipped,
/// [`EXIT_SKIPPED`] otherwise. Every failure is an error, and leaves no
/// destination behind.
pub(super) fn run(source: &Path, into: &Path) -> Result<i32> {
    if fs::symlink_metadata(into).is_ok() {
        bail!(
            "refusing: destination {} already exists; repair writes a fresh pile",
            into.display()
        );
    }
    let mut walk =
        ResyncingRecords::open(source).map_err(|error| super::pile_read_error(source, error))?;
    let source_bytes = walk.bytes().len();
    if source_bytes == 0 {
        bail!(
            "{} is empty; there is nothing to repair and nothing was written",
            source.display()
        );
    }

    let temporary = super::subtract::temporary_sibling(into, "repair")?;
    let file = super::compact::create_fresh_destination(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let mut out = BufWriter::new(file);
    let mut records = 0u64;
    let mut opaque = 0u64;
    let mut output_bytes = 0u64;
    let mut ranges = 0u64;
    let mut skipped_bytes = 0u64;
    let mut unsupported = false;

    let written = (|| -> Result<()> {
        while let Some(step) = walk.next() {
            match step {
                RepairStep::Record(record) => {
                    let frame = &walk.bytes()[record.offset..record.offset + record.len];
                    out.write_all(frame)
                        .with_context(|| format!("write {}", temporary.display()))?;
                    records += 1;
                    output_bytes += frame.len() as u64;
                    if matches!(record.content, PileRecordContent::Opaque { .. }) {
                        opaque += 1;
                    }
                }
                RepairStep::Skipped(range) => {
                    let defect = match range.defect {
                        RepairDefect::Corrupt => "corrupt".to_owned(),
                        RepairDefect::BlobHash => "blob-hash".to_owned(),
                        RepairDefect::Unsupported { marker } => {
                            unsupported = true;
                            format!("unsupported-marker:{}", hex::encode_upper(marker))
                        }
                    };
                    println!(
                        "skipped start={} end={} bytes={} defect={defect}",
                        range.start,
                        range.end,
                        range.len()
                    );
                    ranges += 1;
                    skipped_bytes += range.len() as u64;
                }
            }
        }
        if records == 0 {
            bail!(
                "no valid record found in {}; nothing was written",
                source.display()
            );
        }
        let file = out
            .into_inner()
            .map_err(|error| anyhow!("flush {}: {}", temporary.display(), error.error()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        drop(file);

        // The output is read back with the ordinary reader before it is
        // published: it must hold exactly the copied records and nothing
        // that fails to decode.
        let mut check = PileRecords::open(&temporary)
            .map_err(|error| anyhow!("reread {}: {error}", temporary.display()))?;
        let mut reread = 0u64;
        while let Some(record) = check.next() {
            record.map_err(|error| {
                anyhow!(
                    "the repaired copy {} does not read back cleanly ({error}); not published",
                    temporary.display()
                )
            })?;
            reread += 1;
        }
        if reread != records {
            bail!(
                "the repaired copy {} reads back {reread} records, not the {records} copied; \
                 not published",
                temporary.display()
            );
        }
        super::subtract::publish(&temporary, into)
    })();
    if let Err(error) = written {
        return Err(super::compact::cleanup_incomplete_destination(
            &temporary, error,
        ));
    }

    println!("repaired {} into {}", source.display(), into.display());
    println!("copied records={records} opaque={opaque} bytes={output_bytes}");
    println!("total ranges={ranges} skipped_bytes={skipped_bytes} source_bytes={source_bytes}");
    if ranges == 0 {
        return Ok(0);
    }
    eprintln!(
        "WARNING: {ranges} range(s), {skipped_bytes} bytes of {}, were not copied into {}. \
         Keep the source: it is unchanged. A skipped blob can be fetched again by sync from \
         any peer that holds it, since blobs are content-addressed.",
        source.display(),
        into.display()
    );
    if unsupported {
        eprintln!(
            "NOTE: some ranges begin with a record marker this reader does not know; that is \
             usually garbage, but it can be a newer format. A newer trible may read them."
        );
    }
    Ok(EXIT_SKIPPED)
}
