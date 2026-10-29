use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use triblespace_core::repo::pile::{Pile, ReadError};

pub mod blob;
pub mod collection;
mod compact;
mod diagnose;
pub mod migrate;
pub mod net;
mod path_text;
mod signing;
mod subtract;
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
    /// Repack one pile into a fresh file; preserve all blobs by default.
    ///
    /// By default every distinct valid blob is retained. Exact duplicate blob,
    /// collection, and proof records collapse through their native set
    /// identities; active WANTs and legacy pin state are projected once. All
    /// distinct current native COMMIT/MERGE/DERIVE/MAP records remain unless
    /// explicitly excluded. --drop-collection opts into reachability garbage
    /// collection, dropping selected collection frames and unrooted blobs. Retired
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
        /// Leave a drained generation behind: `RETIRED=CURRENT`, two
        /// collection handles. Every frame naming RETIRED or a collection
        /// derived from it is not carried, after checking that every commit
        /// of RETIRED is present in CURRENT, admitted under CURRENT's WRITE
        /// policy. Repeat for several generations; a generation may be
        /// retired once, and never while it is another pair's CURRENT.
        #[arg(long = "drop-drained", value_name = "RETIRED=CURRENT")]
        drop_drained: Vec<String>,
        /// Explicitly leave collections and their resident descriptor
        /// descendants behind. Repeat names or full handles. Unlike default
        /// compact, this opts into reachability GC: unrooted blobs are dropped.
        /// Proofs, WANTs, pins and unknown frames retain their ordinary roots.
        /// Absent handles and missing or ambiguous names are refused. This
        /// does not revoke grants or prevent sync from restoring the data.
        #[arg(long = "drop-collection", value_name = "NAME_OR_FULL_HANDLE")]
        drop_collection: Vec<String>,
        /// Read SOURCE as exactly its first BYTES bytes, read-only, while
        /// writers may keep appending. BYTES must be a record boundary, such
        /// as the file's length at some earlier moment. Bytes at or past it
        /// are never parsed, and the output equals the compaction of a copy
        /// of that prefix.
        #[arg(long = "source-prefix", value_name = "BYTES")]
        source_prefix: Option<u64>,
        /// Keep what the compaction drops: after writing the destination,
        /// write every frame of the source (or of its --source-prefix) that
        /// the destination does not hold into this fresh file, exactly as
        /// `pile subtract SOURCE --minus DESTINATION [--source-prefix BYTES]`
        /// would. `cat DESTINATION DROPPED` then holds everything in the
        /// source bytes the compaction read. It must not exist and must not
        /// be the destination; it is written to a hidden sibling, synced, and
        /// published by hard link. The destination is published only after
        /// it, so a run that fails or is killed earlier leaves no
        /// destination: a compaction without its dropped frames never looks
        /// like a finished one.
        #[arg(long = "dropped-into", value_name = "DROPPED")]
        dropped_into: Option<PathBuf>,
        /// With --dropped-into: omit from DROPPED the source blob frames that
        /// fail hash validation and have no valid copy, instead of refusing,
        /// and count them, as `pile subtract --allow-corrupt` does. Under
        /// --drop-collection such a blob is not carried when nothing reaches
        /// it, so without this flag the run refuses after the compaction.
        /// Check the result with `pile subtract --check --allow-corrupt`.
        #[arg(long, requires = "dropped_into")]
        allow_corrupt: bool,
    },
    /// Write SOURCE minus MINUS as a fresh difference pile, read-only on both.
    ///
    /// Concatenation is the merge, so a backup can be kept as its difference
    /// to a mainline pile: `cat MINUS DESTINATION` then holds everything SOURCE
    /// holds. Every frame of SOURCE's observed prefix whose content MINUS does
    /// not already hold is copied byte-for-byte, in SOURCE order; a frame
    /// repeated inside SOURCE is written once. Identity per kind:
    ///
    /// - blob: its handle (BLAKE3 of the payload), present only when MINUS
    ///   holds an occurrence whose payload validates, read as ordinary blob
    ///   reads are; a blob is copied only after its own payload matches its
    ///   header.
    ///
    /// - COMMIT, MERGE, DERIVE, MAP: the record fingerprint, BLAKE3 of the
    ///   canonical signed assertion.
    ///
    /// - AUTH proof: its proof id, BLAKE3 of the canonical body.
    ///
    /// - WANT: the exact canonical request.
    ///
    /// - legacy pin head or tombstone: pin id plus head (log order across
    ///   files is not kept).
    ///
    /// - every retired, legacy, opaque or unknown kind: BLAKE3 of the exact
    ///   frame bytes. Such frames are never dropped unless MINUS holds the
    ///   identical bytes; opaque and unknown ones are counted.
    ///
    /// A malformed frame in SOURCE, or a blob frame failing its hash with no
    /// valid copy elsewhere, refuses (naming the byte offset) unless
    /// --allow-corrupt is given. DESTINATION must not exist; it is written to
    /// a hidden sibling, synced, and published without replacing anything.
    /// SOURCE, MINUS (and DIFF) must be distinct files by device and inode.
    ///
    /// With --check, nothing is written: every blob and record of SOURCE is
    /// looked up in MINUS or DIFF by the same identities, anything missing
    /// is listed, and the command exits 1 if any is.
    ///
    /// --source-prefix bounds SOURCE to its first BYTES bytes, for both the
    /// difference and --check, as `pile compact --source-prefix` does.
    Subtract {
        /// Pile to subtract from; opened read-only.
        source: PathBuf,
        /// Mainline pile whose content is left out; opened read-only.
        #[arg(long, value_name = "MINUS")]
        minus: PathBuf,
        /// Fresh difference pile to create; must not exist.
        #[arg(
            long,
            value_name = "DESTINATION",
            required_unless_present = "check",
            conflicts_with = "check"
        )]
        into: Option<PathBuf>,
        /// Verify instead of writing: SOURCE is contained in MINUS plus DIFF.
        #[arg(long, requires = "diff")]
        check: bool,
        /// With --check: the difference pile written earlier.
        #[arg(long, value_name = "DIFF", requires = "check")]
        diff: Option<PathBuf>,
        /// Omit SOURCE blob frames that fail hash validation and have no valid
        /// copy, and stop at a malformed frame, instead of refusing; both are
        /// reported.
        #[arg(long)]
        allow_corrupt: bool,
        /// Read SOURCE as exactly its first BYTES bytes, read-only, while
        /// writers may keep appending. BYTES must be a record boundary; bytes
        /// at or past it are never read.
        #[arg(long = "source-prefix", value_name = "BYTES")]
        source_prefix: Option<u64>,
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
///
/// The fold has no host, so it believes no MERGE or MAP and every believed
/// foundation is its own frontier node.
///
/// The rule for every command: open as a host, the key it signs with,
/// through [`open_refreshed_as`] or [`open_refreshed_with`], exactly when
/// what the command does depends on which MERGEs and MAPs the fold believes,
/// because it publishes them (a carry, a derived view's upkeep, or attaching)
/// or reads through them (an attached read such as `collection search`, or
/// the dashboard's member lattice). Every other command opens here, with no
/// host, including one that signs records: a COMMIT, DERIVE, grant or
/// descriptor is admitted by WRITE, never by the host, and a record scan or
/// copy never asks the fold.
pub(crate) fn open_refreshed(path: &Path) -> Result<Pile> {
    open_refreshed_with(path, None)
}

/// [`open_refreshed`] as `host`: the fold believes the MERGEs `host` signed
/// and no other key's. Maintenance signing with a key needs the pile opened
/// as that key, or the merges it publishes are never believed and the carry
/// refuses to publish them.
pub(crate) fn open_refreshed_as(path: &Path, host: VerifyingKey) -> Result<Pile> {
    open_refreshed_with(path, Some(host))
}

/// The host a command that reads through merges folds as: the key it would
/// sign with.
///
/// An explicit key must load, so a mistyped `--key` is an error rather than
/// a quietly keyless read. Without one, the default (`TRIBLESPACE_KEY`, else
/// `self.key` beside the pile) is used when it loads, and with no loadable
/// key the read believes no MERGE and no MAP: every believed foundation is
/// its own frontier node and nothing is attached.
pub(crate) fn reading_host(explicit: Option<&Path>, pile: &Path) -> Result<Option<VerifyingKey>> {
    let path = triblespace_core::signing_key_file::resolve_path(explicit, pile);
    match triblespace_core::signing_key_file::load_existing(&path) {
        Ok(key) => Ok(Some(key.verifying_key())),
        Err(error) if explicit.is_some() => {
            Err(anyhow!("load signing key {}: {error}", path.display()))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod reading_host_tests {
    use super::{open_refreshed_with, reading_host};
    use std::collections::BTreeSet;
    use triblespace_core::collection::CoverageRead;
    use triblespace_core::repo::SnapshotSource;

    #[test]
    fn an_explicit_key_is_the_host_the_pile_opens_as_and_must_load() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("read.pile");
        std::fs::File::create(&pile).unwrap();
        let key = directory.path().join("reader.key");
        let signer = triblespace_core::signing_key_file::init(&key).unwrap();
        let host = reading_host(Some(&key), &pile).unwrap();
        assert_eq!(host, Some(signer.verifying_key()));
        // The opened store folds as that key, which is what makes its reads
        // attach the key's own merges.
        let mut opened = open_refreshed_with(&pile, host).unwrap();
        let folded_as = opened
            .snapshot()
            .unwrap()
            .index(&BTreeSet::new())
            .unwrap()
            .host();
        assert_eq!(
            folded_as.map(|key| key.raw),
            Some(signer.verifying_key().to_bytes())
        );
        opened.close().unwrap();

        let missing = directory.path().join("missing.key");
        assert!(
            reading_host(Some(&missing), &pile).is_err(),
            "a key named on the command line that does not load is an error, not a keyless read"
        );
        assert!(!missing.exists(), "resolving a key never creates one");
    }
}

/// [`open_refreshed`] with or without a host.
pub(crate) fn open_refreshed_with(path: &Path, host: Option<VerifyingKey>) -> Result<Pile> {
    let opened = match host {
        Some(host) => Pile::open_as(path, host),
        None => Pile::open(path),
    };
    let mut pile = opened.map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
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

            // Pile::open no longer auto-creates files (v0.32.1), so the
            // path is created here, but never truncated: `File::create`
            // used to empty an existing pile, destroying its append-only
            // history. An existing empty file is already the initial state
            // and is accepted; an existing nonempty one is refused.
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let len = fs::metadata(&path)?.len();
                    if len != 0 {
                        return Err(anyhow!(
                            "{} already exists and holds {len} bytes; `pile create` never \
                             truncates a pile. Open it as it is, or choose a new path",
                            path.display()
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }

            let pile: Pile = Pile::open(&path)?;
            // Explicit close makes the empty pile durable and avoids Drop warnings.
            pile.close().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            Ok(())
        }
        PileCommand::Compact {
            source,
            into,
            drop_drained,
            drop_collection,
            source_prefix,
            dropped_into,
            allow_corrupt,
        } => compact::run(compact::Request {
            source,
            into,
            drop_drained,
            drop_collection,
            source_prefix,
            dropped_into,
            allow_corrupt,
        }),
        PileCommand::Subtract {
            source,
            minus,
            into,
            check,
            diff,
            allow_corrupt,
            source_prefix,
        } => subtract::run(subtract::Request {
            source,
            minus,
            into,
            check,
            diff,
            allow_corrupt,
            source_prefix,
        }),
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
    }
}
