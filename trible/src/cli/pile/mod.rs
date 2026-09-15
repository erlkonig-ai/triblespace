use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

use triblespace_core::repo::pile::{Pile, ReadError};

pub mod blob;
pub mod collection;
mod compact;
mod diagnose;
mod migrate;
pub mod net;
mod path_text;
mod signing;
mod verify;

#[derive(Parser)]
pub enum PileCommand {
    /// Operations on blobs stored in a pile file.
    Blob {
        #[command(subcommand)]
        cmd: blob::Command,
    },
    /// Collection-aware views of a pile.
    ///
    /// A collection is a grow-only set of signed records identified by the
    /// blake3 handle of its descriptor blob. These subcommands decode that
    /// descriptor — including its independent READ and WRITE policies — so a
    /// root collection lists under the name it was given, rather than as the
    /// opaque bytes `pile blob inspect` would report. Every one of them takes
    /// either the name or the handle.
    Collection {
        #[command(subcommand)]
        cmd: collection::Command,
    },
    /// Provision durable signing identities for pile-backed writers.
    SigningKey {
        #[command(subcommand)]
        cmd: signing::Command,
    },
    /// Create a new empty pile file.
    ///
    /// This is mainly a cross-platform convenience; a plain `touch` on
    /// Unix-like systems achieves the same result.
    Create {
        /// Path to the pile file to create
        path: PathBuf,
    },
    /// Repack one pile into a fresh file without garbage-collecting blobs.
    ///
    /// Every distinct valid blob is retained. Exact duplicate blob,
    /// collection, and proof records collapse through their native set
    /// identities; active WANTs and legacy pin state are projected once. All
    /// distinct current native COMMIT/MERGE/DERIVE records remain. Retired
    /// PEER and STORE_SCOPE records are recognized and dropped.
    /// The source is never modified, the destination must not exist, and
    /// opaque framed records are carried byte-for-byte without interpreting
    /// them. Quiesce writers when the output must cover the exact whole
    /// file: a sufficiently late append may remain outside the valid observed
    /// prefix. On Unix the fresh destination starts no broader than mode 0600;
    /// source permissions are applied through its open file handle only after
    /// the rewrite closes. Post-create failures trigger a destination-removal
    /// attempt, and cleanup failures are reported.
    Compact {
        /// Source pile to read without modifying.
        source: PathBuf,
        /// Fresh destination pile to create.
        #[arg(long = "into")]
        into: PathBuf,
    },
    /// Diagnostic helpers for inspecting and repairing piles.
    Diagnose {
        #[command(subcommand)]
        cmd: diagnose::Command,
    },
    /// Recheck native record and AUTH proof signatures, read-only.
    ///
    /// Audits every physical COMMIT, MERGE, DERIVE and current AUTH proof in
    /// the observed file prefix, including duplicate occurrences. Referenced
    /// blobs need not be resident. This does not check blob hashes, legacy
    /// branch chains, clock validity, WRITE admission or collection policy;
    /// use `pile diagnose check` for the separate blob/legacy-chain audit.
    /// Unsigned legacy equations and opaque records are reported as unchecked.
    Verify {
        /// Path to the pile file to inspect.
        pile: PathBuf,
    },
    /// DESTRUCTIVE: truncate a pile at its first malformed or torn record,
    /// deleting everything after it.
    ///
    /// This explicit repair entry point loads every structurally complete
    /// record and cuts the file back to the last valid boundary—everything
    /// past that point is permanently destroyed. Complete opaque envelopes
    /// are crossed, and a torn opaque envelope can be cut at its known start;
    /// unknown unenveloped markers are refused because their length is
    /// unknowable and may indicate a newer pile format. This is last-resort
    /// surgery for a torn append left by a crashed write: back the file up
    /// first, inspect the reported boundary with `trible pile diagnose
    /// record-at`, confirm the tail is genuinely torn, and only then run this
    /// by hand with that exact boundary.
    Amputate {
        /// Path to the pile file to amputate (TRUNCATED in place)
        path: PathBuf,
        /// Exact byte offset to truncate to.
        ///
        /// This must equal the boundary reported by the current reader. The
        /// explicit value prevents an old tool's generic repair suggestion
        /// from becoming an unexamined destructive command.
        #[arg(long, value_name = "BYTE_OFFSET")]
        truncate_to: usize,
    },
    /// Migrate legacy pile metadata to the current schemas.
    Migrate {
        /// Path to the pile file to modify
        pile: PathBuf,
        #[command(subcommand)]
        cmd: migrate::Command,
    },
    /// Distributed pile sync over iroh (p2p QUIC connections).
    Net {
        #[command(subcommand)]
        cmd: net::Command,
    },
}

/// Turn a pile read failure into an operator-facing diagnostic without
/// suggesting destructive repair for an unsupported record marker.
pub(crate) fn pile_read_error(path: &Path, err: ReadError) -> anyhow::Error {
    match err {
        err @ ReadError::UnsupportedRecord { .. } => anyhow!(
            "pile {} contains a record format unsupported by this binary ({err}); this is likely \
             version skew. Upgrade trible to a reader that recognizes the marker. The pile was \
             left unchanged",
            path.display()
        ),
        err @ ReadError::CorruptPile { .. } => anyhow!(
            "pile {} has a malformed or incomplete known record ({err}); this reader cannot \
             prove that the remaining bytes are a disposable torn write. The pile was left \
             unchanged. Inspect the reported boundary with `trible pile diagnose record-at {} \
             <BYTE_OFFSET>`. Only after making a backup and independently confirming that every \
             byte from that boundary onward may be destroyed, run `trible pile amputate {} \
             --truncate-to <BYTE_OFFSET>`",
            path.display(),
            path.display(),
            path.display()
        ),
        err => anyhow!("read pile {}: {err}", path.display()),
    }
}

/// Open a pile and load its records via `refresh`, failing loud on a corrupt,
/// torn, or unsupported tail without modifying it. Deliberate repair of
/// genuine corruption stays a separate, boundary-confirmed
/// `trible pile amputate <path> --truncate-to <byte-offset>` step.
pub(crate) fn open_refreshed(path: &Path) -> Result<Pile> {
    let mut pile = Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(pile_read_error(path, err));
    }
    Ok(pile)
}

pub fn run(cmd: PileCommand) -> Result<()> {
    match cmd {
        PileCommand::Blob { cmd } => blob::run(cmd),
        PileCommand::Collection { cmd } => collection::run(cmd),
        PileCommand::SigningKey { cmd } => signing::run(cmd),
        PileCommand::Create { path } => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Pile::open no longer auto-creates files (v0.32.1), so we
            // explicitly touch the path first. Fine if the file already
            // exists — fs::File::create truncates empty-or-not, and
            // piles are append-only so an empty file is the initial
            // state.
            fs::File::create(&path)?;

            let pile: Pile = Pile::open(&path)?;
            // Explicit close makes the empty pile durable and avoids Drop warnings.
            pile.close().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            Ok(())
        }
        PileCommand::Compact { source, into } => compact::run(source, into),
        PileCommand::Net { cmd } => net::run(cmd),
        PileCommand::Diagnose { cmd } => diagnose::run(cmd),
        PileCommand::Verify { pile } => verify::run(&pile),
        PileCommand::Amputate { path, truncate_to } => {
            let mut pile = Pile::open(&path)?;
            // Boundary comparison and truncation happen under the same
            // exclusive file lock. A preflight `refresh` here would leave a
            // check-then-act race with another repair process.
            let amputated = match pile.amputate_at(truncate_to) {
                Ok(amputated) => amputated,
                Err(ReadError::CorruptPile { valid_length }) => {
                    let _ = pile.close();
                    return Err(anyhow!(
                        "refusing destructive repair: --truncate-to {truncate_to} does not match \
                         the current reader's boundary {valid_length}; the pile was left unchanged"
                    ));
                }
                Err(err) => {
                    let _ = pile.close();
                    return Err(pile_read_error(&path, err));
                }
            };
            pile.close()
                .map_err(|e| anyhow::anyhow!("close pile: {e:?}"))?;
            if amputated {
                println!(
                    "{}: amputated tail at confirmed boundary {truncate_to}",
                    path.display()
                );
            } else {
                println!("{}: already valid", path.display());
            }
            Ok(())
        }
        PileCommand::Migrate { pile, cmd } => migrate::run(pile, cmd),
    }
}
