//! `trible pile subtract`: one pile minus another, as a fresh difference file.
//!
//! Concatenation is the merge, so a backup can be kept as its difference to
//! the mainline pile: `cat MINUS DIFF` then holds everything SOURCE held. The
//! difference is every frame of SOURCE whose content MINUS does not already
//! hold, copied byte-for-byte in SOURCE order; a frame repeated inside SOURCE
//! is written once. Legacy pin heads and tombstones and retired WANT logs are
//! the exception: their meaning is their file order, so every occurrence is
//! kept, and `--check` compares their sequence. Neither input is opened for
//! writing.
//!
//! Each frame kind is compared by the identity the core gives it. A blob is
//! present only when MINUS holds a hash-valid occurrence, checked through the
//! same snapshot read that serves ordinary blob reads; a blob is copied only
//! after its own payload is checked against its header. Frames this reader
//! cannot interpret are never dropped: they are compared by their exact bytes.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use anybytes::Bytes;
use anyhow::{anyhow, bail, Context, Result};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::CollectionRecord;
use triblespace_core::id::RawId;
use triblespace_core::inline::encodings::hash::{Blake3, Handle};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{
    GetBlobError, PileFile, PileFileSnapshot, PileRecord, PileRecordContent, PileRecords,
};
use triblespace_core::repo::{BlobStoreGet, SnapshotSource, WantRequest};

/// What the subtraction is asked to do.
pub(super) struct Request {
    pub source: PathBuf,
    pub minus: PathBuf,
    pub into: Option<PathBuf>,
    pub check: bool,
    pub diff: Option<PathBuf>,
    pub allow_corrupt: bool,
}

/// The identity a non-blob frame is compared by.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Identity {
    /// BLAKE3 of the canonical signed COMMIT/MERGE/DERIVE/MAP bytes.
    Collection([u8; 32]),
    /// BLAKE3 of the canonical capability-proof body.
    Proof([u8; 32]),
    /// The exact canonical WANT request.
    Want(WantRequest),
    /// A legacy pin head: pin id and the head it names.
    PinHead(RawId, [u8; 32]),
    /// A legacy pin tombstone: pin id.
    PinTombstone(RawId),
    /// BLAKE3 of the exact frame bytes, for every retired, legacy or unknown
    /// kind the core carries but does not project into current state.
    Frame([u8; 32]),
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = |bytes: &[u8]| hex::encode_upper(bytes);
        match self {
            Self::Collection(fingerprint) => write!(f, "record fingerprint {}", hex(fingerprint)),
            Self::Proof(id) => write!(f, "proof id {}", hex(id)),
            Self::Want(request) => write!(f, "want request {}", hex(&request.to_bytes())),
            Self::PinHead(pin, head) => write!(f, "pin {} head {}", hex(pin), hex(head)),
            Self::PinTombstone(pin) => write!(f, "pin {} tombstone", hex(pin)),
            Self::Frame(digest) => write!(f, "frame digest {}", hex(digest)),
        }
    }
}

enum Item {
    Blob {
        hash: [u8; 32],
        data_offset: usize,
        data_len: usize,
    },
    Record {
        identity: Identity,
        opaque: bool,
        /// A log whose meaning is its file order: every occurrence is kept.
        ordered: bool,
    },
}

/// The kind label and comparison identity of one decoded frame.
fn classify(record: &PileRecord, frame: &[u8]) -> (&'static str, Item) {
    let exact = || Identity::Frame(Blake3::digest(frame));
    let known = |identity| Item::Record {
        identity,
        opaque: false,
        ordered: false,
    };
    let logged = |identity| Item::Record {
        identity,
        opaque: false,
        ordered: true,
    };
    match record.content {
        PileRecordContent::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } => (
            "blob",
            Item::Blob {
                hash: hash.raw,
                data_offset,
                data_len,
            },
        ),
        PileRecordContent::Collection { record } => {
            let label = match record {
                CollectionRecord::Commit(_) => "COMMIT",
                CollectionRecord::Merge(_) => "MERGE",
                CollectionRecord::Derive(_) => "DERIVE",
                CollectionRecord::Map(_) => "MAP",
            };
            (
                label,
                known(Identity::Collection(record.fingerprint().raw())),
            )
        }
        PileRecordContent::CapabilityProof { id, .. } => {
            ("AUTH proof", known(Identity::Proof(id.raw)))
        }
        PileRecordContent::Want { request } => ("WANT", known(Identity::Want(request))),
        PileRecordContent::Branch { branch_id, head } => (
            "legacy pin head",
            logged(Identity::PinHead(branch_id.into(), head.raw)),
        ),
        PileRecordContent::BranchTombstone { branch_id } => (
            "legacy pin tombstone",
            logged(Identity::PinTombstone(branch_id.into())),
        ),
        PileRecordContent::RetiredWantAssert { .. }
        | PileRecordContent::RetiredWantRetract { .. } => ("retired WANT log", logged(exact())),
        PileRecordContent::LegacyUnsignedCollectionEquation { .. } => {
            ("legacy unsigned equation", known(exact()))
        }
        PileRecordContent::RetiredCollectionEquation { .. } => {
            ("retired v8/v9 equation", known(exact()))
        }
        PileRecordContent::RetiredCapabilityProof => ("retired AUTH proof", known(exact())),
        PileRecordContent::RetiredPeerEvidenceV1 | PileRecordContent::RetiredStoreScopeV1 => {
            ("retired team record", known(exact()))
        }
        PileRecordContent::RetiredArtifactOfferV1 => ("retired artifact offer", known(exact())),
        PileRecordContent::LegacyCollectionV3 { .. } => ("legacy V3 collection", known(exact())),
        PileRecordContent::RetiredCollectionDeriveV4 => ("retired V4 derive", known(exact())),
        PileRecordContent::Opaque { .. } => (
            "opaque/unknown",
            Item::Record {
                identity: exact(),
                opaque: true,
                ordered: false,
            },
        ),
        // A variant newer than this command: carried by its exact bytes.
        _ => (
            "unclassified",
            Item::Record {
                identity: exact(),
                opaque: true,
                ordered: false,
            },
        ),
    }
}

/// A pile the source is compared against: its record identities and one
/// snapshot answering hash-verified blob presence.
struct Side {
    path: PathBuf,
    len: usize,
    records: HashSet<Identity>,
    /// Order-sensitive log frames, in file order.
    logged: Vec<Identity>,
    snapshot: PileFileSnapshot,
    file: PileFile,
}

impl Side {
    fn open(path: &Path) -> Result<Self> {
        // Record identities come from one raw scan of a fixed prefix; the
        // blob snapshot below is taken afterwards and covers at least it.
        let mut scan =
            PileRecords::open(path).map_err(|error| super::pile_read_error(path, error))?;
        let bytes = scan.bytes().clone();
        let mut records = HashSet::new();
        let mut logged = Vec::new();
        while let Some(record) = scan.next() {
            let record = record.map_err(|error| super::pile_read_error(path, error))?;
            if !matches!(record.content, PileRecordContent::Blob { .. }) {
                let frame = &bytes[record.offset..record.offset + record.len];
                if let (_, Item::Record { identity, ordered, .. }) = classify(&record, frame) {
                    if ordered {
                        logged.push(identity);
                    }
                    records.insert(identity);
                }
            }
        }
        drop(scan);
        drop(bytes);

        let mut file =
            PileFile::open_read_only(path).map_err(|error| super::pile_read_error(path, error))?;
        let snapshot = match file.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = file.close();
                return Err(super::pile_read_error(path, error));
            }
        };
        let len = file
            .backing_file_metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len() as usize;
        Ok(Self {
            path: path.to_path_buf(),
            len,
            records,
            logged,
            snapshot,
            file,
        })
    }

    /// Whether this pile holds an occurrence of `hash` whose payload
    /// validates, read exactly as an ordinary blob read is.
    fn has_valid_blob(&self, hash: [u8; 32]) -> bool {
        match self
            .snapshot
            .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(hash))
        {
            Ok(_) => true,
            Err(GetBlobError::BlobNotFound(_) | GetBlobError::ValidationError(_)) => false,
            Err(GetBlobError::ConversionError(never)) => match never {},
        }
    }

    fn close(self) -> Result<()> {
        drop(self.snapshot);
        self.file
            .close()
            .map_err(|error| anyhow!("close {}: {error:?}", self.path.display()))
    }
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))
}

/// Refuse unless every path names a different existing file.
fn require_distinct(paths: &[&Path]) -> Result<()> {
    let mut seen: Vec<(&Path, _)> = Vec::new();
    for path in paths {
        let identity = file_identity(path)?;
        if let Some((other, _)) = seen.iter().find(|(_, earlier)| *earlier == identity) {
            bail!(
                "refusing: {} and {} are the same file ({identity:?}); subtract needs distinct piles",
                other.display(),
                path.display()
            );
        }
        seen.push((*path, identity));
    }
    Ok(())
}

#[derive(Default)]
struct KindCounts {
    read: u64,
    kept: u64,
    present: u64,
    repeated: u64,
}

#[derive(Default)]
struct CheckCounts {
    read: u64,
    in_minus: u64,
    in_diff: u64,
    missing: u64,
}

fn row(kind: &str, columns: [String; 4]) {
    let [a, b, c, d] = columns;
    println!("  {kind:<26} {a:>12} {b:>12} {c:>12} {d:>12}");
}

pub(super) fn run(request: Request) -> Result<()> {
    if request.check {
        let diff = request
            .diff
            .as_deref()
            .ok_or_else(|| anyhow!("--check needs --diff <DIFF>"))?;
        check(&request.source, &request.minus, diff, request.allow_corrupt)
    } else {
        let into = request
            .into
            .as_deref()
            .ok_or_else(|| anyhow!("subtract needs --into <DESTINATION>"))?;
        subtract(&request.source, &request.minus, into, request.allow_corrupt)
    }
}

fn temporary_sibling(into: &Path) -> Result<PathBuf> {
    let name = into
        .file_name()
        .ok_or_else(|| anyhow!("destination {} names no file", into.display()))?;
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".subtract-{}.tmp", std::process::id()));
    Ok(into.with_file_name(temporary))
}

fn subtract(source: &Path, minus: &Path, into: &Path, allow_corrupt: bool) -> Result<()> {
    if fs::symlink_metadata(into).is_ok() {
        bail!(
            "refusing: destination {} already exists; subtract never overwrites",
            into.display()
        );
    }
    require_distinct(&[source, minus])?;

    let minus_side = Side::open(minus)?;
    let mut scan =
        PileRecords::open(source).map_err(|error| super::pile_read_error(source, error))?;
    let bytes = scan.bytes().clone();

    let temporary = temporary_sibling(into)?;
    let file = super::compact::create_fresh_destination(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let mut out = BufWriter::with_capacity(8 << 20, file);

    let mut counts: BTreeMap<&'static str, KindCounts> = BTreeMap::new();
    let mut kept_blobs: HashSet<[u8; 32]> = HashSet::new();
    let mut kept_records: HashSet<Identity> = HashSet::new();
    let mut corrupt: Vec<(usize, [u8; 32])> = Vec::new();
    let mut opaque_kept = (0u64, 0u64);
    let mut written = 0u64;
    let mut frames = 0u64;
    let mut stopped = None;

    let result = (|| -> Result<()> {
        while let Some(record) = scan.next() {
            let record = match record {
                Ok(record) => record,
                Err(error) if allow_corrupt => {
                    stopped = Some(error.to_string());
                    break;
                }
                Err(error) => {
                    return Err(super::pile_read_error(source, error).context(format!(
                        "refusing: {} is not fully readable",
                        source.display()
                    )))
                }
            };
            frames += 1;
            let frame = &bytes[record.offset..record.offset + record.len];
            let (kind, item) = classify(&record, frame);
            let count = counts.entry(kind).or_default();
            count.read += 1;
            let keep = match item {
                Item::Blob {
                    hash,
                    data_offset,
                    data_len,
                } => {
                    if kept_blobs.contains(&hash) {
                        count.repeated += 1;
                        false
                    } else if minus_side.has_valid_blob(hash) {
                        count.present += 1;
                        false
                    } else if Blake3::digest(&bytes[data_offset..data_offset + data_len]) == hash {
                        kept_blobs.insert(hash);
                        true
                    } else {
                        corrupt.push((record.offset, hash));
                        false
                    }
                }
                Item::Record {
                    ordered: true,
                    opaque,
                    ..
                } => {
                    if opaque {
                        opaque_kept.0 += 1;
                        opaque_kept.1 += frame.len() as u64;
                    }
                    true
                }
                Item::Record {
                    identity, opaque, ..
                } => {
                    if kept_records.contains(&identity) {
                        count.repeated += 1;
                        false
                    } else if minus_side.records.contains(&identity) {
                        count.present += 1;
                        false
                    } else {
                        kept_records.insert(identity);
                        if opaque {
                            opaque_kept.0 += 1;
                            opaque_kept.1 += frame.len() as u64;
                        }
                        true
                    }
                }
            };
            if keep {
                count.kept += 1;
                out.write_all(frame)
                    .with_context(|| format!("write {}", temporary.display()))?;
                written += frame.len() as u64;
            }
        }

        // A corrupt occurrence is harmless when a valid copy of the same blob
        // reached the difference from a later frame.
        corrupt.retain(|(_, hash)| !kept_blobs.contains(hash));
        if !corrupt.is_empty() && !allow_corrupt {
            let listed: Vec<String> = corrupt
                .iter()
                .take(20)
                .map(|(offset, hash)| {
                    format!("byte {offset} (header names {})", hex::encode_upper(hash))
                })
                .collect();
            bail!(
                "refusing: {} blob frame(s) of {} fail hash validation and neither {} nor \
                 another frame holds a valid copy: {}{}; rerun with --allow-corrupt to omit them",
                corrupt.len(),
                source.display(),
                minus.display(),
                listed.join(", "),
                if corrupt.len() > 20 { ", ..." } else { "" }
            );
        }

        let file = out
            .into_inner()
            .map_err(|error| anyhow!("flush {}: {}", temporary.display(), error.error()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        drop(file);
        // A hard link publishes without replacing: it fails if the
        // destination appeared meanwhile.
        fs::hard_link(&temporary, into).with_context(|| {
            format!(
                "publish {} as {} (refusing to replace an existing file)",
                temporary.display(),
                into.display()
            )
        })?;
        fs::remove_file(&temporary).with_context(|| format!("remove {}", temporary.display()))?;
        if let Some(parent) = into
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("sync directory {}", parent.display()))?;
        }
        Ok(())
    })();
    drop(scan);
    if let Err(error) = result {
        let _ = minus_side.close();
        return Err(if temporary.exists() {
            super::compact::cleanup_incomplete_destination(&temporary, error)
        } else {
            error
        });
    }

    println!(
        "subtract {} minus {} -> {}",
        source.display(),
        minus.display(),
        into.display()
    );
    println!(
        "scope: {frames} frames of {}'s {} observed bytes, against {}'s {} bytes \
         (blob presence hash-verified there; records by identity, see --help)",
        source.display(),
        bytes.len(),
        minus.display(),
        minus_side.len,
    );
    row(
        "kind",
        ["read", "kept", "in MINUS", "repeated"].map(String::from),
    );
    for (kind, count) in &counts {
        row(
            kind,
            [count.read, count.kept, count.present, count.repeated].map(|n| n.to_string()),
        );
    }
    println!(
        "opaque/unknown frames kept: {} ({} bytes)",
        opaque_kept.0, opaque_kept.1
    );
    println!("corrupt blob frames skipped: {}", corrupt.len());
    println!("bytes written: {written}");
    if let Some(error) = stopped {
        let warning = format!(
            "WARNING: the scan of {} stopped early ({error}); everything after that byte is \
             NOT represented in {}",
            source.display(),
            into.display()
        );
        println!("{warning}");
        eprintln!("{warning}");
    }
    minus_side.close()
}

fn check(source: &Path, minus: &Path, diff: &Path, allow_corrupt: bool) -> Result<()> {
    require_distinct(&[source, minus, diff])?;
    let minus_side = Side::open(minus)?;
    let diff_side = match Side::open(diff) {
        Ok(side) => side,
        Err(error) => {
            let _ = minus_side.close();
            return Err(error);
        }
    };
    let result = check_against(source, &minus_side, &diff_side, allow_corrupt);
    let closed = minus_side.close().and(diff_side.close());
    result.and(closed)
}

fn check_against(source: &Path, minus: &Side, diff: &Side, allow_corrupt: bool) -> Result<()> {
    let mut scan =
        PileRecords::open(source).map_err(|error| super::pile_read_error(source, error))?;
    let bytes = scan.bytes().clone();
    let mut counts: BTreeMap<&'static str, CheckCounts> = BTreeMap::new();
    let mut missing = 0u64;
    let mut corrupt = 0u64;
    let mut frames = 0u64;
    let mut stopped = None;
    let mut logged = Vec::new();
    const LISTED: u64 = 100;

    while let Some(record) = scan.next() {
        let record = match record {
            Ok(record) => record,
            Err(error) if allow_corrupt => {
                stopped = Some(error.to_string());
                break;
            }
            Err(error) => {
                return Err(super::pile_read_error(source, error).context(format!(
                    "refusing: {} is not fully readable",
                    source.display()
                )))
            }
        };
        frames += 1;
        let frame = &bytes[record.offset..record.offset + record.len];
        let (kind, item) = classify(&record, frame);
        let count = counts.entry(kind).or_default();
        count.read += 1;
        let (in_minus, in_diff, identity) = match item {
            Item::Blob {
                hash,
                data_offset,
                data_len,
            } => {
                let in_minus = minus.has_valid_blob(hash);
                let in_diff = !in_minus && diff.has_valid_blob(hash);
                if !in_minus
                    && !in_diff
                    && Blake3::digest(&bytes[data_offset..data_offset + data_len]) != hash
                {
                    corrupt += 1;
                    println!(
                        "corrupt in SOURCE, no valid copy elsewhere: blob frame at byte {} names {}",
                        record.offset,
                        hex::encode_upper(hash)
                    );
                    continue;
                }
                (
                    in_minus,
                    in_diff,
                    format!("blob {}", hex::encode_upper(hash)),
                )
            }
            Item::Record {
                identity, ordered, ..
            } => {
                if ordered {
                    logged.push(identity);
                }
                let in_minus = minus.records.contains(&identity);
                let in_diff = !in_minus && diff.records.contains(&identity);
                (in_minus, in_diff, identity.to_string())
            }
        };
        if in_minus {
            count.in_minus += 1;
        } else if in_diff {
            count.in_diff += 1;
        } else {
            count.missing += 1;
            missing += 1;
            if missing <= LISTED {
                println!(
                    "MISSING {kind} at byte {} of SOURCE: {identity}",
                    record.offset
                );
            }
        }
    }

    println!(
        "check {} = {} + {}",
        source.display(),
        minus.path.display(),
        diff.path.display()
    );
    println!(
        "scope: {frames} frames of {}'s {} observed bytes; {} observed as {} bytes, {} as {} bytes",
        source.display(),
        bytes.len(),
        minus.path.display(),
        minus.len,
        diff.path.display(),
        diff.len
    );
    row(
        "kind",
        ["read", "in MINUS", "in DIFF", "missing"].map(String::from),
    );
    for (kind, count) in &counts {
        let columns = [count.read, count.in_minus, count.in_diff, count.missing];
        row(kind, columns.map(|n| n.to_string()));
    }
    println!("corrupt blob frames without a valid copy: {corrupt}");
    println!("missing: {missing}");
    if let Some(error) = &stopped {
        println!(
            "WARNING: the scan of {} stopped early ({error}); later bytes were not checked",
            source.display()
        );
    }
    let log_matches = logged == diff.logged;
    println!(
        "order-sensitive log frames: {} in SOURCE, {} in DIFF, sequence {}",
        logged.len(),
        diff.logged.len(),
        if log_matches { "identical" } else { "DIFFERS" }
    );
    if !log_matches {
        bail!(
            "the order-sensitive log (legacy pins, retired WANTs) of {} is not reproduced \
             in order by {}: replaying the difference would end in a different state",
            source.display(),
            diff.path.display()
        );
    }
    if missing > 0 {
        bail!(
            "{missing} item(s) of {} are in neither {} nor {}",
            source.display(),
            minus.path.display(),
            diff.path.display()
        );
    }
    if corrupt > 0 && !allow_corrupt {
        bail!("{corrupt} corrupt blob frame(s) of {} have no valid copy anywhere; pass --allow-corrupt to accept", source.display());
    }
    Ok(())
}
