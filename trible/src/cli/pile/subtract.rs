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
//!
//! `--source-prefix L` bounds SOURCE to its first `L` bytes, read-only, the
//! way `pile compact --source-prefix` does: writers may keep appending and
//! nothing at or past `L` is read. `pile compact --dropped-into` writes its
//! dropped frames through [`write_difference`] with the compaction's source
//! bounded the same way, so a compaction's exhaust is exactly this command's
//! output for SOURCE minus the compacted pile.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anybytes::Bytes;
use anyhow::{anyhow, bail, Context, Result};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::CollectionRecord;
use triblespace_core::id::RawId;
use triblespace_core::inline::encodings::hash::{Blake3, Handle};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{
    blob_record_bytes, GetBlobError, PileFile, PileFileSnapshot, PileRecord, PileRecordContent,
    PileRecords,
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
    pub source_prefix: Option<u64>,
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
        /// A blob in a legacy framing that a normalized pack re-encodes as a
        /// current BLOB record: same payload, same hash.
        reframe: bool,
    },
    /// A historical record a normalized pack keeps as an ordinary blob whose
    /// payload is the record's exact frame bytes, named by their BLAKE3
    /// digest: recoverable by handle, never replayed.
    Wrapped { digest: [u8; 32] },
    Record {
        identity: Identity,
        opaque: bool,
        /// A log whose meaning is its file order: every occurrence is kept.
        ordered: bool,
    },
}

/// Whether a normalized pack wraps this record as a blob of its exact
/// frame bytes: every legacy pin head and tombstone and every retired WANT
/// assert or retract in any framing, whose meaning was their replay order,
/// and every other record not in the current framing (V1, unenveloped V3,
/// the 36-byte legacy envelope) unless its content is native. Blobs,
/// COMMIT/MERGE/DERIVE/MAP, AUTH proofs and current WANTs keep their native
/// contracts; current-framed retired and unknown kinds stay as they are.
fn wraps(record: &PileRecord, current: bool) -> bool {
    match record.content {
        PileRecordContent::Branch { .. }
        | PileRecordContent::BranchTombstone { .. }
        | PileRecordContent::RetiredWantAssert { .. }
        | PileRecordContent::RetiredWantRetract { .. } => true,
        PileRecordContent::Blob { .. }
        | PileRecordContent::Collection { .. }
        | PileRecordContent::CapabilityProof { .. }
        | PileRecordContent::Want { .. } => false,
        _ => !current,
    }
}

/// The kind label and comparison identity of one decoded frame; `current`
/// says whether the frame is in the current framing. Under
/// [`KeepEvery::Normalized`] the records [`wraps`] names become
/// [`Item::Wrapped`] and legacy-framed blobs are marked for re-encoding.
fn classify(
    record: &PileRecord,
    frame: &[u8],
    current: bool,
    keep: KeepEvery,
) -> (&'static str, Item) {
    let normalized = keep == KeepEvery::Normalized;
    let (label, item) = classify_native(record, frame);
    match item {
        Item::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } => (
            label,
            Item::Blob {
                hash,
                data_offset,
                data_len,
                reframe: normalized && !current,
            },
        ),
        _ if normalized && wraps(record, current) => (
            label,
            Item::Wrapped {
                digest: Blake3::digest(frame),
            },
        ),
        item => (label, item),
    }
}

/// The kind label and native comparison identity of one decoded frame.
fn classify_native(record: &PileRecord, frame: &[u8]) -> (&'static str, Item) {
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
                reframe: false,
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

/// One pile read through one frozen, read-only snapshot: the identities of
/// its records and hash-verified blob presence both come from the same
/// mapping, bounded to the prefix the snapshot accepted. Bytes a writer
/// appends afterwards are never read, and a path re-pointed meanwhile does
/// not change what this side holds.
pub(super) struct Side {
    pub(super) path: PathBuf,
    /// Length of the accepted prefix every lookup is answered from.
    pub(super) len: usize,
    /// The opened file as its handle reported it when the snapshot was taken.
    pub(super) stamp: Stamp,
    records: HashSet<Identity>,
    /// Order-sensitive log frames and opaque/unknown frames, in file order,
    /// each marked whether it is opaque and whether a normalized pack wraps it.
    logged: Vec<(Identity, bool, bool)>,
    /// BLAKE3 digests of the exact frames a normalized pack wraps as blobs.
    wrapped: HashSet<[u8; 32]>,
    /// How many frames a normalized pack never contains (records it wraps,
    /// blobs in a legacy framing), and the first [`LISTED`] as (offset, kind).
    unnormalized: (u64, Vec<(usize, &'static str)>),
    snapshot: Option<PileFileSnapshot>,
    file: Option<PileFile>,
}

impl Side {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let file =
            PileFile::open_read_only(path).map_err(|error| super::pile_read_error(path, error))?;
        let mut side = Self {
            path: path.to_path_buf(),
            len: 0,
            stamp: Stamp::default_for(path),
            records: HashSet::new(),
            logged: Vec::new(),
            wrapped: HashSet::new(),
            unnormalized: (0, Vec::new()),
            snapshot: None,
            file: Some(file),
        };
        // On any error below, dropping `side` closes the file.
        let file = side.file.as_mut().expect("just opened");
        let snapshot = file
            .snapshot()
            .map_err(|error| super::pile_read_error(path, error))?;
        let metadata = file
            .backing_file_metadata()
            .with_context(|| format!("stat {}", path.display()))?;
        side.stamp = Stamp::of(&metadata, path)?;
        side.len = snapshot.prefix_len();
        let mut scan = snapshot.raw_records();
        side.snapshot = Some(snapshot);
        let bytes = scan.bytes().clone();
        while let Some(record) = scan.next() {
            let record = record.map_err(|error| super::pile_read_error(path, error))?;
            let current = scan.has_current_framing(&record);
            let frame = &bytes[record.offset..record.offset + record.len];
            match classify(&record, frame, current, KeepEvery::Log) {
                (kind, Item::Blob { .. }) => {
                    if !current {
                        side.note_unnormalized(record.offset, kind);
                    }
                }
                (
                    kind,
                    Item::Record {
                        identity,
                        ordered,
                        opaque,
                    },
                ) => {
                    let wrappable = wraps(&record, current);
                    if wrappable {
                        side.wrapped.insert(Blake3::digest(frame));
                        side.note_unnormalized(record.offset, kind);
                    }
                    if ordered || opaque {
                        side.logged.push((identity, opaque, wrappable));
                    }
                    side.records.insert(identity);
                }
                (_, Item::Wrapped { .. }) => unreachable!("only a normalized pack wraps"),
            }
        }
        Ok(side)
    }

    fn note_unnormalized(&mut self, offset: usize, kind: &'static str) {
        self.unnormalized.0 += 1;
        if self.unnormalized.1.len() < LISTED as usize {
            self.unnormalized.1.push((offset, kind));
        }
    }

    fn snapshot(&self) -> &PileFileSnapshot {
        self.snapshot.as_ref().expect("side snapshot taken at open")
    }

    /// The raw records of exactly the accepted prefix, from the same mapping.
    pub(super) fn scan(&self) -> PileRecords {
        self.snapshot().raw_records()
    }

    /// Bytes of the file past the accepted prefix when the snapshot was taken:
    /// a torn tail, or an append still in flight.
    pub(super) fn unaccepted(&self) -> u64 {
        self.stamp.len.saturating_sub(self.len as u64)
    }

    /// The frames `keep` copies at every occurrence, in file order.
    fn log(&self, keep: KeepEvery) -> Vec<Identity> {
        self.logged
            .iter()
            // An entry is opaque or else an order-sensitive log frame; a
            // normalized pack keeps what it wraps as a blob instead.
            .filter(|(_, opaque, wrappable)| {
                keep.every(!opaque, *opaque) && !(keep == KeepEvery::Normalized && *wrappable)
            })
            .map(|(identity, _, _)| *identity)
            .collect()
    }

    /// Whether this pile holds an occurrence of `hash` whose payload
    /// validates, read exactly as an ordinary blob read is.
    fn has_valid_blob(&self, hash: [u8; 32]) -> bool {
        match self
            .snapshot()
            .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(hash))
        {
            Ok(_) => true,
            Err(GetBlobError::BlobNotFound(_) | GetBlobError::ValidationError(_)) => false,
            Err(GetBlobError::ConversionError(never)) => match never {},
        }
    }

    pub(super) fn close(mut self) -> Result<()> {
        drop(self.snapshot.take());
        match self.file.take() {
            Some(file) => file
                .close()
                .map_err(|error| anyhow!("close {}: {error:?}", self.path.display())),
            None => Ok(()),
        }
    }
}

impl Drop for Side {
    fn drop(&mut self) {
        drop(self.snapshot.take());
        if let Some(file) = self.file.take() {
            // Read-only: nothing to persist, only the handle to release.
            let _ = file.close();
        }
    }
}

/// The first side of `sides` holding the bytes named by `hash` under
/// `keep`: a hash-valid blob, or, for a normalized pack, also a frame it
/// wraps whose exact bytes hash to `hash`.
fn content_holder(sides: &[&Side], hash: [u8; 32], keep: KeepEvery) -> Option<usize> {
    sides.iter().position(|side| {
        side.has_valid_blob(hash) || (keep == KeepEvery::Normalized && side.wrapped.contains(&hash))
    })
}

/// The first side of `sides` holding a record of `identity`.
fn record_holder(sides: &[&Side], identity: &Identity) -> Option<usize> {
    sides
        .iter()
        .position(|side| side.records.contains(identity))
}

/// What a file looked like when it was opened: which file, how long, and
/// when it last changed. A static input whose stamp differs later was
/// replaced, rewritten or truncated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Stamp {
    pub(super) identity: FileIdentity,
    pub(super) len: u64,
    modified: Option<std::time::SystemTime>,
    /// Inode change time (seconds, nanoseconds) where there is one.
    changed: Option<(i64, i64)>,
}

impl Stamp {
    pub(super) fn of(metadata: &fs::Metadata, path: &Path) -> Result<Self> {
        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt as _;
            Some((metadata.ctime(), metadata.ctime_nsec()))
        };
        #[cfg(not(unix))]
        let changed = None;
        Ok(Self {
            identity: opened_identity(metadata, path)?,
            len: metadata.len(),
            modified: metadata.modified().ok(),
            changed,
        })
    }

    /// The stamp of whatever `path` names now.
    pub(super) fn now(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        Self::of(&metadata, path)
    }

    #[cfg(unix)]
    fn default_for(_path: &Path) -> Self {
        Self {
            identity: (0, 0),
            len: 0,
            modified: None,
            changed: None,
        }
    }

    #[cfg(not(unix))]
    fn default_for(path: &Path) -> Self {
        Self {
            identity: path.to_path_buf(),
            len: 0,
            modified: None,
            changed: None,
        }
    }
}

/// What tells two files apart: device and inode where there are such.
#[cfg(unix)]
pub(super) type FileIdentity = (u64, u64);
#[cfg(not(unix))]
pub(super) type FileIdentity = PathBuf;

#[cfg(unix)]
fn file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    opened_identity(&metadata, path)
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> Result<FileIdentity> {
    fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))
}

/// The identity of the file `metadata` describes, taken from a handle open
/// on `path`. Without inodes it falls back to `path`'s canonical form.
#[cfg(unix)]
pub(super) fn opened_identity(metadata: &fs::Metadata, _path: &Path) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
pub(super) fn opened_identity(_metadata: &fs::Metadata, path: &Path) -> Result<FileIdentity> {
    file_identity(path)
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
pub(super) struct KindCounts {
    read: u64,
    kept: u64,
    present: u64,
    repeated: u64,
}

#[derive(Default)]
pub(super) struct CheckCounts {
    read: u64,
    in_minus: u64,
    in_diff: u64,
    missing: u64,
}

pub(super) fn row(kind: &str, columns: [String; 4]) {
    let [a, b, c, d] = columns;
    println!("  {kind:<26} {a:>12} {b:>12} {c:>12} {d:>12}");
}

pub(super) fn run(request: Request) -> Result<()> {
    if request.check {
        let diff = request
            .diff
            .as_deref()
            .ok_or_else(|| anyhow!("--check needs --diff <DIFF>"))?;
        check(
            &request.source,
            &request.minus,
            diff,
            request.allow_corrupt,
            request.source_prefix,
        )
    } else {
        let into = request
            .into
            .as_deref()
            .ok_or_else(|| anyhow!("subtract needs --into <DESTINATION>"))?;
        write_difference(
            &request.source,
            &request.minus,
            into,
            request.allow_corrupt,
            request.source_prefix,
            None,
        )?
        .print();
        Ok(())
    }
}

/// A raw scan of SOURCE, or of exactly its first `prefix` bytes.
fn open_source(source: &Path, prefix: Option<u64>) -> Result<PileRecords> {
    match prefix {
        Some(prefix) => PileRecords::open_prefix(source, prefix),
        None => PileRecords::open(source),
    }
    .map_err(|error| super::pile_read_error(source, error))
}

/// How much of SOURCE a scan covered, for the reports.
fn extent(bytes: usize, prefix: Option<u64>) -> String {
    match prefix {
        Some(_) => format!("first {bytes} bytes (fixed prefix)"),
        None => format!("{bytes} observed bytes"),
    }
}

/// Refuse a difference destination that already exists, before any work.
pub(super) fn refuse_existing(into: &Path) -> Result<()> {
    if fs::symlink_metadata(into).is_ok() {
        bail!(
            "refusing: destination {} already exists; subtract never overwrites",
            into.display()
        );
    }
    Ok(())
}

/// The hidden name `verb` writes `into` under until it is published.
pub(super) fn temporary_sibling(into: &Path, verb: &str) -> Result<PathBuf> {
    let name = into
        .file_name()
        .ok_or_else(|| anyhow!("destination {} names no file", into.display()))?;
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".{verb}-{}.tmp", std::process::id()));
    Ok(into.with_file_name(temporary))
}

/// Publish the written and synced `temporary` as `into`. A hard link
/// publishes without replacing: it fails if `into` appeared meanwhile.
pub(super) fn publish(temporary: &Path, into: &Path) -> Result<()> {
    fs::hard_link(temporary, into).with_context(|| {
        format!(
            "publish {} as {} (refusing to replace an existing file)",
            temporary.display(),
            into.display()
        )
    })?;
    fs::remove_file(temporary).with_context(|| format!("remove {}", temporary.display()))?;
    if let Some(parent) = into
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync directory {}", parent.display()))?;
    }
    Ok(())
}

/// Which frames the shared writer copies at every occurrence, in input
/// order, instead of once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeepEvery {
    /// Legacy pins and retired WANT logs, whose meaning is their order
    /// (`pile subtract`, `pile compact --dropped-into`).
    Log,
    /// The log, and frames this reader cannot interpret, which it cannot
    /// assume idempotent (`yard diff`).
    LogAndUnknown,
    /// A normalized archival pack (`yard pack`): current-framed frames of
    /// unknown kind at every occurrence; every historical record [`wraps`]
    /// names becomes an ordinary blob of its exact frame bytes, kept once by
    /// their hash; legacy-framed blobs are re-encoded as current BLOB
    /// records. The output is then in the current framing throughout.
    Normalized,
}

impl KeepEvery {
    fn every(self, ordered: bool, opaque: bool) -> bool {
        match self {
            Self::Log => ordered,
            Self::LogAndUnknown => ordered || opaque,
            Self::Normalized => opaque,
        }
    }
}

/// One input of the shared writer and checker: a raw scan of a pile and the
/// path it is reported under.
pub(super) struct Input {
    pub(super) path: PathBuf,
    pub(super) scan: PileRecords,
}

/// What the shared writer copied, for the reports.
#[derive(Default)]
pub(super) struct Tally {
    pub(super) frames: u64,
    /// Bytes the input scans covered, summed.
    pub(super) bytes: usize,
    counts: BTreeMap<&'static str, KindCounts>,
    opaque_kept: (u64, u64),
    /// A normalized pack: historical records written as blobs of their
    /// exact bytes (count, record bytes), and legacy-framed blobs re-encoded.
    normalized: Option<((u64, u64), u64)>,
    pub(super) corrupt: usize,
    pub(super) written: u64,
    /// Inputs whose scan stopped early at a malformed frame (--allow-corrupt).
    pub(super) stopped: Vec<(PathBuf, String)>,
    /// How many items each baseline side supplied, by position.
    pub(super) covered: Vec<u64>,
}

impl Tally {
    /// The per-kind table and the trailing counts, as `pile subtract` prints
    /// them; `present` names the baseline column.
    pub(super) fn print_table(&self, present: &str) {
        row(
            "kind",
            ["read", "kept", present, "repeated"].map(String::from),
        );
        for (kind, count) in &self.counts {
            row(
                kind,
                [count.read, count.kept, count.present, count.repeated].map(|n| n.to_string()),
            );
        }
        println!(
            "opaque/unknown frames kept: {} ({} bytes)",
            self.opaque_kept.0, self.opaque_kept.1
        );
        if let Some(((wrapped, wrapped_bytes), reframed)) = self.normalized {
            println!(
                "historical records kept as blobs of their exact bytes: {wrapped} \
                 ({wrapped_bytes} record bytes)"
            );
            println!("legacy-framed blobs re-encoded in the current framing: {reframed}");
        }
        println!("corrupt blob frames skipped: {}", self.corrupt);
        println!("bytes written: {}", self.written);
    }

    pub(super) fn warn_stopped(&self, into: &Path) {
        for (source, error) in &self.stopped {
            let warning = format!(
                "WARNING: the scan of {} stopped early ({error}); everything after that byte is \
                 NOT represented in {}",
                source.display(),
                into.display()
            );
            println!("{warning}");
            eprintln!("{warning}");
        }
    }
}

/// Copy into `out`, in input order, every frame of `inputs` whose content
/// neither `baseline` nor an earlier copied frame already holds. This is the
/// one writer behind `pile subtract`, `pile compact --dropped-into`,
/// `yard diff` and `yard pack`.
///
/// A blob is held only by a hash-valid occurrence, and copied only after its
/// own payload matches its header; an occurrence failing its hash is
/// harmless when a valid copy is in the baseline or reaches `out` from
/// another frame of any input, and refuses otherwise unless `allow_corrupt`.
/// The frames `keep` names are copied at every occurrence, so `out` repeats
/// them in input order; every other frame is copied once. Opaque and unknown
/// frames are compared by their exact bytes and never dropped otherwise.
pub(super) fn copy_new(
    inputs: Vec<Input>,
    baseline: &[&Side],
    baseline_label: &str,
    out: &mut impl std::io::Write,
    out_path: &Path,
    allow_corrupt: bool,
    keep: KeepEvery,
) -> Result<Tally> {
    let normalized = keep == KeepEvery::Normalized;
    let mut tally = Tally {
        covered: vec![0; baseline.len()],
        normalized: normalized.then_some(((0, 0), 0)),
        ..Tally::default()
    };
    // One stamp for every record this run encodes rather than copies: an
    // insertion time is a local fact about the file written, as for `put`.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    let mut kept_blobs: HashSet<[u8; 32]> = HashSet::new();
    let mut kept_records: HashSet<Identity> = HashSet::new();
    let mut corrupt: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut paths = Vec::new();

    for Input { path, mut scan } in inputs {
        let input = paths.len();
        let bytes = scan.bytes().clone();
        tally.bytes += bytes.len();
        while let Some(record) = scan.next() {
            let record = match record {
                Ok(record) => record,
                Err(error) if allow_corrupt => {
                    tally.stopped.push((path.clone(), error.to_string()));
                    break;
                }
                Err(error) => {
                    return Err(super::pile_read_error(&path, error).context(format!(
                        "refusing: {} is not fully readable",
                        path.display()
                    )))
                }
            };
            tally.frames += 1;
            let frame = &bytes[record.offset..record.offset + record.len];
            let current = scan.has_current_framing(&record);
            let (kind, item) = classify(&record, frame, current, keep);
            let count = tally.counts.entry(kind).or_default();
            count.read += 1;
            // Bytes to write in place of the frame, for an encoded record.
            let mut encoded: Option<Vec<u8>> = None;
            let encode = |payload: &[u8]| {
                blob_record_bytes(stamp, payload).ok_or_else(|| {
                    anyhow!(
                        "record at byte {} of {} is too large for a blob record",
                        record.offset,
                        path.display()
                    )
                })
            };
            let write = match item {
                Item::Blob {
                    hash,
                    data_offset,
                    data_len,
                    reframe,
                } => {
                    let payload = &bytes[data_offset..data_offset + data_len];
                    if kept_blobs.contains(&hash) {
                        count.repeated += 1;
                        false
                    } else if let Some(holder) = content_holder(baseline, hash, keep) {
                        count.present += 1;
                        tally.covered[holder] += 1;
                        false
                    } else if Blake3::digest(payload) == hash {
                        kept_blobs.insert(hash);
                        if reframe {
                            encoded = Some(encode(payload)?);
                            if let Some((_, reframed)) = tally.normalized.as_mut() {
                                *reframed += 1;
                            }
                        }
                        true
                    } else {
                        corrupt.push((input, record.offset, hash));
                        false
                    }
                }
                Item::Wrapped { digest } => {
                    if kept_blobs.contains(&digest) {
                        count.repeated += 1;
                        false
                    } else if let Some(holder) = content_holder(baseline, digest, keep) {
                        count.present += 1;
                        tally.covered[holder] += 1;
                        false
                    } else {
                        kept_blobs.insert(digest);
                        encoded = Some(encode(frame)?);
                        if let Some(((wrapped, wrapped_bytes), _)) = tally.normalized.as_mut() {
                            *wrapped += 1;
                            *wrapped_bytes += frame.len() as u64;
                        }
                        true
                    }
                }
                Item::Record {
                    ordered, opaque, ..
                } if keep.every(ordered, opaque) => {
                    if opaque {
                        tally.opaque_kept.0 += 1;
                        tally.opaque_kept.1 += frame.len() as u64;
                    }
                    true
                }
                Item::Record {
                    identity, opaque, ..
                } => {
                    if kept_records.contains(&identity) {
                        count.repeated += 1;
                        false
                    } else if let Some(holder) = record_holder(baseline, &identity) {
                        count.present += 1;
                        tally.covered[holder] += 1;
                        false
                    } else {
                        kept_records.insert(identity);
                        if opaque {
                            tally.opaque_kept.0 += 1;
                            tally.opaque_kept.1 += frame.len() as u64;
                        }
                        true
                    }
                }
            };
            if write {
                let written = encoded.as_deref().unwrap_or(frame);
                count.kept += 1;
                out.write_all(written)
                    .with_context(|| format!("write {}", out_path.display()))?;
                tally.written += written.len() as u64;
            }
        }
        paths.push(path);
    }

    // A corrupt occurrence is harmless when a valid copy of the same blob
    // reached the output from a later frame, of this input or another.
    corrupt.retain(|(_, _, hash)| !kept_blobs.contains(hash));
    if !corrupt.is_empty() && !allow_corrupt {
        let listed: Vec<String> = corrupt
            .iter()
            .take(20)
            .map(|(input, offset, hash)| {
                format!(
                    "{} byte {offset} (header names {})",
                    paths[*input].display(),
                    hex::encode_upper(hash)
                )
            })
            .collect();
        bail!(
            "refusing: {} blob frame(s) fail hash validation and neither {baseline_label} nor \
             another frame holds a valid copy: {}{}; rerun with --allow-corrupt to omit them",
            corrupt.len(),
            listed.join(", "),
            if corrupt.len() > 20 { ", ..." } else { "" }
        );
    }
    tally.corrupt = corrupt.len();
    Ok(tally)
}

/// Flush and sync a written output, returning its file.
pub(super) fn finish(out: BufWriter<fs::File>, path: &Path) -> Result<fs::File> {
    let file = out
        .into_inner()
        .map_err(|error| anyhow!("flush {}: {}", path.display(), error.error()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    Ok(file)
}

/// What one written difference holds, for the report.
pub(super) struct Difference {
    source: PathBuf,
    minus: PathBuf,
    into: PathBuf,
    source_prefix: Option<u64>,
    minus_bytes: usize,
    tally: Tally,
}

/// Write SOURCE (or its first `source_prefix` bytes) minus MINUS into the
/// fresh file `into`: written to a hidden sibling, synced, and published by
/// hard link, so `into` either does not exist or holds the whole difference.
///
/// SOURCE is opened by path. With `expected_source`, the identity of a file
/// the caller already read there, a path that names another file once the
/// scan has opened it is refused: the caller's file was replaced, and the
/// replacement minus MINUS is not what the caller meant.
pub(super) fn write_difference(
    source: &Path,
    minus: &Path,
    into: &Path,
    allow_corrupt: bool,
    source_prefix: Option<u64>,
    expected_source: Option<&FileIdentity>,
) -> Result<Difference> {
    refuse_existing(into)?;
    require_distinct(&[source, minus])?;

    let minus_side = Side::open(minus)?;
    let scan = open_source(source, source_prefix).and_then(|scan| {
        let Some(expected) = expected_source else {
            return Ok(scan);
        };
        match file_identity(source) {
            Ok(found) if found == *expected => Ok(scan),
            found => bail!(
                "refusing: {} was replaced after it was read: the file read there was {:?}, \
                 but the path now names {}; its frames are not the ones that were read",
                source.display(),
                expected,
                match found {
                    Ok(found) => format!("{found:?}"),
                    Err(error) => format!("no readable file ({error:#})"),
                }
            ),
        }
    })?;

    let temporary = temporary_sibling(into, "subtract")?;
    let file = super::compact::create_fresh_destination(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let mut out = BufWriter::with_capacity(8 << 20, file);

    let result = (|| -> Result<Tally> {
        let input = Input {
            path: source.to_path_buf(),
            scan,
        };
        let label = minus.display().to_string();
        let tally = copy_new(
            vec![input],
            &[&minus_side],
            &label,
            &mut out,
            &temporary,
            allow_corrupt,
            KeepEvery::Log,
        )?;
        drop(finish(out, &temporary)?);
        publish(&temporary, into)?;
        Ok(tally)
    })();
    let tally = match result {
        Ok(tally) => tally,
        Err(error) => {
            return Err(if temporary.exists() {
                super::compact::cleanup_incomplete_destination(&temporary, error)
            } else {
                error
            })
        }
    };

    let minus_bytes = minus_side.len;
    minus_side.close()?;
    Ok(Difference {
        source: source.to_path_buf(),
        minus: minus.to_path_buf(),
        into: into.to_path_buf(),
        source_prefix,
        minus_bytes,
        tally,
    })
}

impl Difference {
    /// The same difference, reported against `minus`: compact computes it
    /// against its output's hidden name and reports the published one.
    pub(super) fn against(mut self, minus: &Path) -> Self {
        self.minus = minus.to_path_buf();
        self
    }

    pub(super) fn print(&self) {
        println!(
            "subtract {} minus {} -> {}",
            self.source.display(),
            self.minus.display(),
            self.into.display()
        );
        println!(
            "scope: {} frames of {}'s {}, against {}'s {} bytes \
             (blob presence hash-verified there; records by identity, see --help)",
            self.tally.frames,
            self.source.display(),
            extent(self.tally.bytes, self.source_prefix),
            self.minus.display(),
            self.minus_bytes,
        );
        self.tally.print_table("in MINUS");
        self.tally.warn_stopped(&self.into);
    }
}

fn check(
    source: &Path,
    minus: &Path,
    diff: &Path,
    allow_corrupt: bool,
    source_prefix: Option<u64>,
) -> Result<()> {
    require_distinct(&[source, minus, diff])?;
    let minus_side = Side::open(minus)?;
    let diff_side = Side::open(diff)?;
    let input = Input {
        path: source.to_path_buf(),
        scan: open_source(source, source_prefix)?,
    };
    let checked = check_union(
        vec![input],
        &[&minus_side],
        &diff_side,
        None,
        allow_corrupt,
        KeepEvery::Log,
    )?;
    println!(
        "check {} = {} + {}",
        source.display(),
        minus_side.path.display(),
        diff_side.path.display()
    );
    println!(
        "scope: {} frames of {}'s {}; {} observed as {} bytes, {} as {} bytes",
        checked.frames,
        source.display(),
        extent(checked.bytes, source_prefix),
        minus_side.path.display(),
        minus_side.len,
        diff_side.path.display(),
        diff_side.len
    );
    checked.print_table("in MINUS", "in DIFF");
    let source_label = source.display().to_string();
    let verdict = checked.verdict(
        &source_label,
        &minus_side.path.display().to_string(),
        &diff_side.path.display().to_string(),
        allow_corrupt,
    );
    let closed = minus_side.close().and(diff_side.close());
    verdict.and(closed)
}

/// How many missing, extra or unnormalized items a check lists by name.
const LISTED: u64 = 100;

/// What the shared checker found.
#[derive(Default)]
pub(super) struct Checked {
    pub(super) frames: u64,
    pub(super) bytes: usize,
    counts: BTreeMap<&'static str, CheckCounts>,
    pub(super) missing: u64,
    pub(super) corrupt: u64,
    pub(super) stopped: Vec<(PathBuf, String)>,
    /// The inputs' order-sensitive log frames, concatenated in input order.
    logged: Vec<Identity>,
    /// The output's order-sensitive log frames.
    out_logged: Vec<Identity>,
    /// Items each baseline side supplied, by position.
    pub(super) covered: Vec<u64>,
    /// With provenance: output items no input holds.
    pub(super) extra: Option<u64>,
    /// A normalized pack: output frames it must not contain (a raw record it
    /// wraps, or a blob in a legacy framing).
    pub(super) unnormalized: Option<u64>,
}

/// Confirm that every blob and record of `inputs` is in `baseline` or `out`,
/// by the identities `copy_new` compares, and that `out`'s order-sensitive
/// frames (those `keep` copies at every occurrence) are exactly the inputs'
/// concatenated in input order. With
/// `provenance`, also confirm the converse: every frame of `out` is held by
/// one of those piles (normally the inputs), so `out` holds nothing else.
pub(super) fn check_union(
    inputs: Vec<Input>,
    baseline: &[&Side],
    out: &Side,
    provenance: Option<&[&Side]>,
    allow_corrupt: bool,
    keep: KeepEvery,
) -> Result<Checked> {
    let mut checked = Checked {
        covered: vec![0; baseline.len()],
        out_logged: out.log(keep),
        ..Checked::default()
    };

    for Input { path, mut scan } in inputs {
        let bytes = scan.bytes().clone();
        checked.bytes += bytes.len();
        while let Some(record) = scan.next() {
            let record = match record {
                Ok(record) => record,
                Err(error) if allow_corrupt => {
                    checked.stopped.push((path.clone(), error.to_string()));
                    break;
                }
                Err(error) => {
                    return Err(super::pile_read_error(&path, error).context(format!(
                        "refusing: {} is not fully readable",
                        path.display()
                    )))
                }
            };
            checked.frames += 1;
            let frame = &bytes[record.offset..record.offset + record.len];
            let current = scan.has_current_framing(&record);
            let (kind, item) = classify(&record, frame, current, keep);
            let count = checked.counts.entry(kind).or_default();
            count.read += 1;
            let (holder, in_out, identity) = match item {
                Item::Wrapped { digest } => {
                    // Only a hash-valid blob in the output holds it; the raw
                    // frame there would not be a normalized pack.
                    let holder = content_holder(baseline, digest, keep);
                    let in_out = holder.is_none() && out.has_valid_blob(digest);
                    (
                        holder,
                        in_out,
                        format!("exact frame, as blob {}", hex::encode_upper(digest)),
                    )
                }
                Item::Blob {
                    hash,
                    data_offset,
                    data_len,
                    ..
                } => {
                    let holder = content_holder(baseline, hash, keep);
                    let in_out = holder.is_none() && out.has_valid_blob(hash);
                    if holder.is_none()
                        && !in_out
                        && Blake3::digest(&bytes[data_offset..data_offset + data_len]) != hash
                    {
                        checked.corrupt += 1;
                        println!(
                            "corrupt in {}, no valid copy elsewhere: blob frame at byte {} names {}",
                            path.display(),
                            record.offset,
                            hex::encode_upper(hash)
                        );
                        continue;
                    }
                    (holder, in_out, format!("blob {}", hex::encode_upper(hash)))
                }
                Item::Record {
                    identity,
                    ordered,
                    opaque,
                } => {
                    if keep.every(ordered, opaque) {
                        checked.logged.push(identity);
                    }
                    let holder = record_holder(baseline, &identity);
                    let in_out = holder.is_none() && out.records.contains(&identity);
                    (holder, in_out, identity.to_string())
                }
            };
            if let Some(holder) = holder {
                count.in_minus += 1;
                checked.covered[holder] += 1;
            } else if in_out {
                count.in_diff += 1;
            } else {
                count.missing += 1;
                checked.missing += 1;
                if checked.missing <= LISTED {
                    println!(
                        "MISSING {kind} at byte {} of {}: {identity}",
                        record.offset,
                        path.display()
                    );
                }
            }
        }
    }

    if keep == KeepEvery::Normalized {
        for (offset, kind) in &out.unnormalized.1 {
            println!(
                "UNNORMALIZED {kind} at byte {offset} of {}: a pack keeps it only as a \
                 current-framed blob",
                out.path.display()
            );
        }
        checked.unnormalized = Some(out.unnormalized.0);
    }

    if let Some(holders) = provenance {
        let mut extra = 0u64;
        let mut scan = out.scan();
        let bytes = scan.bytes().clone();
        while let Some(record) = scan.next() {
            let record = record.map_err(|error| super::pile_read_error(&out.path, error))?;
            let frame = &bytes[record.offset..record.offset + record.len];
            let current = scan.has_current_framing(&record);
            let (kind, item) = classify(&record, frame, current, keep);
            let (held, identity) = match item {
                Item::Blob { hash, .. } => (
                    content_holder(holders, hash, keep).is_some(),
                    format!("blob {}", hex::encode_upper(hash)),
                ),
                // Counted above as unnormalized; held when an input holds it.
                Item::Wrapped { digest } => (
                    content_holder(holders, digest, keep).is_some(),
                    format!("exact frame {}", hex::encode_upper(digest)),
                ),
                Item::Record { identity, .. } => (
                    record_holder(holders, &identity).is_some(),
                    identity.to_string(),
                ),
            };
            if !held {
                extra += 1;
                if extra <= LISTED {
                    println!(
                        "EXTRA {kind} at byte {} of {}: {identity} is held by no input",
                        record.offset,
                        out.path.display()
                    );
                }
            }
        }
        checked.extra = Some(extra);
    }
    Ok(checked)
}

impl Checked {
    pub(super) fn print_table(&self, present: &str, out: &str) {
        row("kind", ["read", present, out, "missing"].map(String::from));
        for (kind, count) in &self.counts {
            let columns = [count.read, count.in_minus, count.in_diff, count.missing];
            row(kind, columns.map(|n| n.to_string()));
        }
        println!("corrupt blob frames without a valid copy: {}", self.corrupt);
        println!("missing: {}", self.missing);
        if let Some(extra) = self.extra {
            println!("extra: {extra}");
        }
        if let Some(unnormalized) = self.unnormalized {
            println!("unnormalized: {unnormalized}");
        }
        for (source, error) in &self.stopped {
            println!(
                "WARNING: the scan of {} stopped early ({error}); later bytes were not checked",
                source.display()
            );
        }
        println!(
            "order-sensitive log frames: {} in SOURCE, {} in DIFF, sequence {}",
            self.logged.len(),
            self.out_logged.len(),
            if self.logged == self.out_logged {
                "identical"
            } else {
                "DIFFERS"
            }
        );
    }

    /// Refuse unless the check proved what it set out to.
    pub(super) fn verdict(
        &self,
        source: &str,
        minus: &str,
        diff: &str,
        allow_corrupt: bool,
    ) -> Result<()> {
        if self.logged != self.out_logged {
            bail!(
                "the order-sensitive frames (legacy pins and retired WANTs, and in yard \
                 commands uninterpreted frames) of {source} are not reproduced occurrence for \
                 occurrence by {diff}: replaying it would end in a different state"
            );
        }
        if self.missing > 0 && minus.is_empty() {
            bail!("{} item(s) of {source} are not in {diff}", self.missing);
        }
        if self.missing > 0 {
            bail!(
                "{} item(s) of {source} are in neither {minus} nor {diff}",
                self.missing
            );
        }
        if let Some(extra) = self.extra.filter(|extra| *extra > 0) {
            bail!("{extra} item(s) of {diff} are held by none of {source}");
        }
        if let Some(unnormalized) = self.unnormalized.filter(|count| *count > 0) {
            bail!(
                "{unnormalized} frame(s) of {diff} are historical records or legacy-framed \
                 blobs as written, not current-framed blobs: not a normalized pack"
            );
        }
        if self.corrupt > 0 && !allow_corrupt {
            bail!(
                "{} corrupt blob frame(s) of {source} have no valid copy anywhere; pass \
                 --allow-corrupt to accept",
                self.corrupt
            );
        }
        Ok(())
    }
}
