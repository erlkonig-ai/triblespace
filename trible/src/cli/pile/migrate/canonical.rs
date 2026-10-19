//! One-time offline /32 conversion. Historical codecs never enter core replay.
//! Original evidence remains in the operator-retained hash-bound source.
//! Native retired signed equations are copied exactly as inert evidence only.
use std::collections::BTreeSet; // One selector call's ephemeral scratch only.
use std::fs::{File, Metadata};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use triblespace_core::blob::Bytes;
use triblespace_core::collection::{
    CollectionRead, CollectionRecord, CollectionRecordSelector, CollectionStore,
};
use triblespace_core::inline::Inline;
use triblespace_core::patch::{Entry, PATCH};
use triblespace_core::repo::pile::{
    description_blobs, OpaqueKind, PileFile, PileFileSnapshot, PileRecordContent, PileRecords,
};
use triblespace_core::repo::SnapshotSource;

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod conversion_tests;
mod frame;
mod legacy32;
#[cfg(test)]
mod rehearsal_tests;
#[cfg(test)]
mod tests;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// New destination. Existing DST or DST.partial is never replaced/resumed.
    #[arg(long)]
    pub into: PathBuf,
    /// One existing signing-key file. Only assertions by its exact author reseal.
    #[arg(long)]
    pub key: PathBuf,
    /// BLAKE3 of the complete immutable source file (64 hex characters).
    #[arg(long)]
    pub source_hash: String,
    /// Canonical native refresh pile. Only exact matching foundations are used.
    #[arg(long = "refresh")]
    pub refreshes: Vec<PathBuf>,
    /// Explicitly retain valid foreign/non-eight cache evidence ONLY in source.
    /// The source must be kept. This does not migrate or rebuild those caches.
    #[arg(long)]
    pub retain_unconverted_caches: bool,
    /// Fresh JSON-lines report, including every old/new identity disposition.
    #[arg(long, conflicts_with = "dry_run")]
    pub report: Option<PathBuf>,
    /// Verify/classify without writing any output files; report goes to stdout.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(clap::Args, Debug)]
pub struct RefreshArgs {
    #[arg(long)]
    pub into: PathBuf,
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub source_hash: String,
    #[arg(long, conflicts_with = "dry_run")]
    pub report: Option<PathBuf>,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Rewrite,
    Refresh,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Never,
    AfterCopy,
    AfterAssertion,
    BeforePublish,
}

pub fn run(source: PathBuf, args: Args) -> Result<()> {
    execute(source, args, Mode::Rewrite, Stop::Never)
}
pub fn export(source: PathBuf, args: RefreshArgs) -> Result<()> {
    execute(
        source,
        Args {
            into: args.into,
            key: args.key,
            source_hash: args.source_hash,
            refreshes: vec![],
            retain_unconverted_caches: false,
            report: args.report,
            dry_run: args.dry_run,
        },
        Mode::Refresh,
        Stop::Never,
    )
}

struct Source {
    path: PathBuf,
    file: File,
    metadata: Metadata,
    bytes: Bytes,
    hash: [u8; 32],
}
impl Source {
    fn open(path: &Path, expected: Option<[u8; 32]>) -> Result<Self> {
        super::lattice_v3::refuse_if_open(path)?;
        let file = File::open(path).with_context(|| format!("open source {}", path.display()))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "source must be a regular frozen file");
        let records = PileRecords::open(path)
            .map_err(|e| anyhow!("open frames {}: {e:?}", path.display()))?;
        let bytes = records.bytes().clone();
        let hash = *blake3::hash(&bytes).as_bytes();
        if let Some(expected) = expected {
            ensure!(hash == expected, "source hash mismatch: {}", path.display());
        }
        let source = Self {
            path: path.to_owned(),
            file,
            metadata,
            bytes,
            hash,
        };
        source.check()?;
        Ok(source)
    }
    fn check(&self) -> Result<()> {
        for now in [self.file.metadata()?, std::fs::metadata(&self.path)?] {
            ensure!(
                same_file(&self.metadata, &now)
                    && now.len() == self.metadata.len()
                    && now.modified()? == self.metadata.modified()?,
                "source identity/length/time changed: {}",
                self.path.display()
            );
        }
        ensure!(
            *blake3::hash(&self.bytes).as_bytes() == self.hash,
            "source bytes changed: {}",
            self.path.display()
        );
        Ok(())
    }
    fn records(&self) -> Result<PileRecords> {
        self.check()?;
        PileRecords::open(&self.path).map_err(|e| anyhow!("read frames: {e:?}"))
    }
}

#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same_file(_: &Metadata, _: &Metadata) -> bool {
    false
} // Opener guard already refuses unsupported platforms.

fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}
fn normalized(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path.canonicalize().context("resolve existing path");
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?.join(
        path.file_name()
            .ok_or_else(|| anyhow!("path needs a filename"))?,
    ))
}
fn paths(args: &Args, source: &Path) -> Result<()> {
    ensure!(
        !(args.dry_run && args.report.is_some()),
        "dry-run writes no report file; use stdout"
    );
    let partial = partial_path(&args.into);
    let outputs: Vec<_> = [&args.into, &partial]
        .into_iter()
        .chain(args.report.iter())
        .collect();
    let inputs: Vec<_> = [source, args.key.as_path()]
        .into_iter()
        .chain(args.refreshes.iter().map(PathBuf::as_path))
        .collect();
    let mut seen: Vec<PathBuf> = Vec::new(); // Ephemeral path validation, not retained data.
    for output in outputs {
        let output_name = normalized(output)?;
        ensure!(
            !seen.contains(&output_name),
            "output/report paths alias each other"
        );
        for input in &inputs {
            ensure!(
                output_name != normalized(input)?,
                "output/report aliases input {}",
                input.display()
            );
            if let (Ok(a), Ok(b)) = (std::fs::metadata(output), std::fs::metadata(input)) {
                ensure!(!same_file(&a, &b), "output/report inode aliases input");
            }
        }
        match std::fs::symlink_metadata(output) {
            Ok(_) => bail!(
                "refusing existing output {} (including symlinks/partials)",
                output.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        seen.push(output_name);
    }
    Ok(())
}

struct Report(Option<File>);
impl Report {
    fn event(&mut self, value: Value) -> Result<()> {
        let mut line = serde_json::to_vec(&value)?;
        line.push(b'\n');
        match &mut self.0 {
            Some(file) => file.write_all(&line)?,
            None => std::io::stdout().lock().write_all(&line)?,
        }
        Ok(())
    }
    fn sync(&mut self) -> Result<()> {
        match &mut self.0 {
            Some(file) => file.sync_all()?,
            None => std::io::stdout().flush()?,
        }
        Ok(())
    }
}
struct Refresh {
    source: Source,
    snapshot: PileFileSnapshot,
}
#[derive(Default, Debug, PartialEq, Eq)]
struct Ids {
    records: PATCH<32>,
    blobs: PATCH<32>,
    proofs: PATCH<32>,
}
fn add(set: &mut PATCH<32>, key: [u8; 32]) {
    set.insert(&Entry::new(&key));
}

fn execute(source_path: PathBuf, args: Args, mode: Mode, stop: Stop) -> Result<()> {
    paths(&args, &source_path)?;
    let expected: [u8; 32] = hex::decode(&args.source_hash)
        .context("source hash hex")?
        .try_into()
        .map_err(|_| anyhow!("source hash must be32bytes"))?;
    let source = Source::open(&source_path, Some(expected))?;
    let key = triblespace_core::signing_key_file::load_existing(&args.key)
        .context("load explicit existing signer")?;
    let mut refreshes = Vec::new();
    for path in &args.refreshes {
        let frozen = Source::open(path, None)?;
        let mut pile =
            PileFile::open_read_only(path).map_err(|e| anyhow!("open refresh: {e:?}"))?;
        let snapshot = pile
            .snapshot()
            .map_err(|e| anyhow!("snapshot refresh: {e:?}"));
        pile.close().map_err(|e| anyhow!("close refresh: {e:?}"))?;
        refreshes.push(Refresh {
            source: frozen,
            snapshot: snapshot?,
        });
    }
    let mut report = Report(
        args.report
            .as_ref()
            .map(|p| super::super::compact::create_fresh_destination(p))
            .transpose()?,
    );
    report.event(json!({"event":"begin", "operation":format!("{mode:?}"), "source":source.path,
        "source_hash":hex::encode(source.hash), "source_bytes":source.bytes.len(),
        "author":hex::encode(key.verifying_key().to_bytes()), "retain_source":true,
        "refreshes":refreshes.iter().map(|r| json!({"path":r.source.path,"hash":hex::encode(r.source.hash)})).collect::<Vec<_>>() }))?;
    let result = rewrite(&source, &args, mode, stop, &key, &refreshes, &mut report);
    if let Err(error) = &result {
        report.event(json!({"event":"unsuccessful", "error":format!("{error:#}"),
            "destination_exists":args.into.exists(), "partial":partial_path(&args.into),
            "source_retention_required":true}))?;
        report.sync()?;
    }
    result
}

fn rewrite(
    source: &Source,
    args: &Args,
    mode: Mode,
    stop: Stop,
    key: &SigningKey,
    refreshes: &[Refresh],
    report: &mut Report,
) -> Result<()> {
    let partial = partial_path(&args.into);
    let mut raw = if args.dry_run {
        None
    } else {
        Some(super::super::compact::create_fresh_destination(&partial)?)
    };
    let mut expected = Ids::default();
    // A streaming prefix digest retains physical order and multiplicity without
    // a second frame catalogue. New canonical assertions append after this span.
    let mut copied = blake3::Hasher::new();
    let mut copied_bytes = 0usize;
    let mut retained_inert_occurrences = 0u64;
    let mut retained_inert_bytes = 0usize;
    let mut blocked = 0u64;
    // Pass one: validate every source frame. Copy only the exact allowlist.
    for framed in source.records()? {
        let framed = framed.map_err(|e| anyhow!("source framing: {e:?}"))?;
        let bytes = &source.bytes[framed.offset..framed.offset + framed.len];
        if mode == Mode::Refresh && !supported(framed.content) {
            report.event(
                json!({"event":"outside-refresh-export", "offset":framed.offset,
                "length":framed.len,"content":format!("{:?}",framed.content),
                "frame_hash":hex::encode(blake3::hash(bytes).as_bytes()),"original_only":true}),
            )?;
            continue;
        }
        let valid = validate_frame(framed.content, bytes, &source.bytes);
        if let Err(error) = valid {
            blocked += 1;
            report.event(json!({"event":"refused", "offset":framed.offset,"length":framed.len,"reason":format!("{error:#}")}))?;
            continue;
        }
        let copy =
            mode == Mode::Rewrite && !matches!(framed.content, PileRecordContent::Opaque { .. });
        if copy {
            if let Some(writer) = &mut raw {
                writer.write_all(bytes)?;
            }
            copied.update(bytes);
            copied_bytes += bytes.len();
            match framed.content {
                PileRecordContent::Blob { hash, .. } => add(&mut expected.blobs, hash.raw),
                PileRecordContent::CapabilityProof { id, .. } => add(&mut expected.proofs, id.raw),
                PileRecordContent::Collection { record } => {
                    add(&mut expected.records, record.fingerprint().raw())
                }
                PileRecordContent::RetiredCollectionEquation { .. } => {
                    retained_inert_occurrences += 1;
                    retained_inert_bytes += framed.len;
                }
                _ => {}
            }
            report.event(
                json!({"event":"raw-copy", "offset":framed.offset,"length":framed.len,
                "retained_inert_evidence":matches!(framed.content, PileRecordContent::RetiredCollectionEquation { .. }),
                "frame_hash":hex::encode(blake3::hash(bytes).as_bytes())}),
            )?;
        }
    }
    if let Some(writer) = raw {
        writer.sync_all()?;
        drop(writer);
    }
    ensure!(
        blocked == 0,
        "{blocked} invalid/unsupported required source frame(s); original preserved"
    );
    ensure!(
        stop != Stop::AfterCopy,
        "controlled interruption after raw copy"
    );
    let mut pile = if args.dry_run {
        None
    } else {
        Some(PileFile::open(&partial).map_err(|e| anyhow!("open partial: {e:?}"))?)
    };
    let converted = (|| -> Result<(u64, u64)> {
        if let Some(pile) = &mut pile {
            pile.publish_record_kind_descriptions()
                .map_err(|e| anyhow!("publish kinds: {e:?}"))?;
        }
        for blob in description_blobs() {
            add(&mut expected.blobs, blob.get_handle().raw);
        }
        let mut emitted = 0;
        let mut retained_caches = 0;
        for framed in source.records()? {
            let framed = framed.map_err(|e| anyhow!("source framing: {e:?}"))?;
            match framed.content {
                PileRecordContent::Opaque {
                    kind: OpaqueKind::Described(kind),
                } if frame::supported(kind) => {
                    let tagged = frame::tagged(
                        kind,
                        &source.bytes[framed.offset..framed.offset + framed.len],
                    )
                    .map_err(|e| anyhow!("old framing: {e:?}"))?;
                    let old = legacy32::verified(&tagged)
                        .map_err(|e| anyhow!("old verification: {e:?}"))?;
                    let owned = old.author == key.verifying_key().to_bytes();
                    let mut records = Vec::new(); // This assertion's matches only.
                    let disposition;
                    if mode == Mode::Refresh && (!owned || !old.foundation()) {
                        disposition = "outside-refresh-export";
                    } else {
                        match legacy32::reseal_or_refresh(
                            legacy32::Input::TaggedCollection(&tagged),
                            key,
                            None,
                        )
                        .outcome
                        {
                            legacy32::Outcome::Converted { record, .. } => {
                                records.push(record);
                                disposition = "same-author-reseal";
                            }
                            _ if !old.foundation() && args.retain_unconverted_caches => {
                                retained_caches += 1;
                                disposition = "cache-original-only";
                            }
                            _ if old.foundation() && !owned && mode == Mode::Rewrite => {
                                let selector = if old.kind == legacy32::Kind::Commit {
                                    CollectionRecordSelector::CommitMember(
                                        Inline::new(old.collection()),
                                        Inline::new(old.produced()),
                                    )
                                } else {
                                    CollectionRecordSelector::ProducedMember(
                                        Inline::new(old.collection()),
                                        Inline::new(old.produced()),
                                    )
                                };
                                let selectors = BTreeSet::from([selector]); // One query's scratch.
                                for refresh in refreshes {
                                    for record in refresh
                                        .snapshot
                                        .select_records(&selectors)
                                        .map_err(|e| anyhow!("select refresh: {e:?}"))?
                                    {
                                        if old.matches(&record) {
                                            records.push(record);
                                        }
                                    }
                                }
                                if records.is_empty() {
                                    blocked += 1;
                                    disposition = "missing-exact-foreign-refresh";
                                } else {
                                    disposition = "exact-foreign-refresh";
                                }
                            }
                            other => {
                                blocked += 1;
                                disposition = "cache-disposition-required";
                                report.event(json!({"event":"detail","offset":framed.offset,"reason":format!("{other:?}")}))?;
                            }
                        }
                    }
                    report.event(json!({"event":"assertion", "offset":framed.offset,"length":framed.len,
                        "kind":format!("{:?}",old.kind),"author":hex::encode(old.author),
                        "old_id":hex::encode(old.old_fingerprint),"disposition":disposition,
                        "new_ids":records.iter().map(|r| hex::encode(r.fingerprint().raw())).collect::<Vec<_>>() }))?;
                    for record in records {
                        add(&mut expected.records, record.fingerprint().raw());
                        if let Some(pile) = &mut pile {
                            pile.insert(record)
                                .map_err(|e| anyhow!("append canonical: {e:?}"))?;
                            pile.flush()
                                .map_err(|e| anyhow!("flush assertion: {e:?}"))?;
                        }
                        emitted += 1;
                        ensure!(
                            stop != Stop::AfterAssertion,
                            "controlled interruption after flushed assertion"
                        );
                    }
                }
                PileRecordContent::Collection { record } if mode == Mode::Refresh => {
                    let export = foundation(record)
                        && record.public_key().raw == key.verifying_key().to_bytes();
                    report.event(json!({"event":"current-assertion", "offset":framed.offset,"length":framed.len,
                        "id":hex::encode(record.fingerprint().raw()),
                        "disposition":if export {"unchanged-own-foundation"} else {"outside-refresh-export"}}))?;
                    if export {
                        add(&mut expected.records, record.fingerprint().raw());
                        if let Some(pile) = &mut pile {
                            pile.insert(record)
                                .map_err(|e| anyhow!("append current refresh: {e:?}"))?;
                            pile.flush()
                                .map_err(|e| anyhow!("flush current assertion: {e:?}"))?;
                        }
                        emitted += 1;
                        ensure!(
                            stop != Stop::AfterAssertion,
                            "controlled interruption after flushed assertion"
                        );
                    }
                }
                _ => {}
            }
        }
        Ok((emitted, retained_caches))
    })();
    let closed = pile
        .map(|p| p.close().map_err(|e| anyhow!("close partial: {e:?}")))
        .transpose();
    let (emitted, retained_caches) = converted?;
    closed?;
    ensure!(
        blocked == 0,
        "{blocked} required assertion(s) unresolved; partial is NOT completion"
    );
    source.check()?;
    for refresh in refreshes {
        refresh.source.check()?;
    }
    if !args.dry_run {
        audit(&partial, &expected, copied_bytes, copied.finalize())?;
    }
    report.event(json!({"event":"verified", "operation":format!("{mode:?}"),"emitted_occurrences":emitted,
        "distinct_current_assertions":expected.records.len(),"retained_original_caches":retained_caches,
        "retained_inert_occurrences":retained_inert_occurrences,"retained_inert_bytes":retained_inert_bytes,
        "source_retention_required":true,"dry_run":args.dry_run}))?;
    report.sync()?;
    ensure!(
        stop != Stop::BeforePublish,
        "controlled interruption before publication"
    );
    if !args.dry_run {
        source.check()?;
        for refresh in refreshes {
            refresh.source.check()?;
        }
        std::fs::hard_link(&partial, &args.into)
            .context("publish verified destination without replacement")?;
        let parent = args
            .into
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?
            .sync_all()
            .context("destination published but directory sync failed")?;
        std::fs::remove_file(&partial)
            .context("destination published but partial-link cleanup failed")?;
        File::open(parent)?
            .sync_all()
            .context("destination published but cleanup sync failed")?;
    }
    report
        .event(
            json!({"event":if args.dry_run { "dry-run-verified" } else { "published" },
        "operation":format!("{mode:?}"),"destination":args.into,
        "full_rewrite_obligations_satisfied":mode == Mode::Rewrite && !args.dry_run,
        "retained_original_only_caches":retained_caches,
        "retained_inert_occurrences":retained_inert_occurrences,"retained_inert_bytes":retained_inert_bytes,
        "source_evidence_fully_replaced":false,
        "source_retention_required":true}),
        )
        .context("output verified/published but final report failed")?;
    report
        .sync()
        .context("output verified/published but report sync failed")
}

fn foundation(record: CollectionRecord) -> bool {
    matches!(
        record,
        CollectionRecord::Commit(_) | CollectionRecord::Derive(_)
    )
}
fn supported(content: PileRecordContent) -> bool {
    match content {
        PileRecordContent::Blob { .. }
        | PileRecordContent::CapabilityProof { .. }
        | PileRecordContent::Collection { .. }
        | PileRecordContent::Want { .. }
        | PileRecordContent::Branch { .. }
        | PileRecordContent::BranchTombstone { .. } => true,
        PileRecordContent::Opaque {
            kind: OpaqueKind::Described(kind),
        } => frame::supported(kind),
        _ => false,
    }
}
fn validate_frame(content: PileRecordContent, raw: &[u8], all: &[u8]) -> Result<()> {
    match content {
        PileRecordContent::Blob {
            hash,
            data_offset,
            data_len,
            ..
        } => ensure!(
            *blake3::hash(&all[data_offset..data_offset + data_len]).as_bytes() == hash.raw,
            "BLOB hash mismatch"
        ),
        PileRecordContent::CapabilityProof {
            id,
            data_offset,
            data_len,
        } => {
            match legacy32::convert(
                legacy32::Input::Auth(&all[data_offset..data_offset + data_len]),
                None,
            )
            .outcome
            {
                legacy32::Outcome::UnchangedAuth { id: verified } => {
                    ensure!(verified == id.raw, "AUTH identity mismatch")
                }
                other => bail!("AUTH verification: {other}"),
            }
        }
        PileRecordContent::Collection { record } => record
            .verify_strict()
            .map_err(|e| anyhow!("canonical signature: {e:?}"))?,
        // Authorship of already-native v8/v9 evidence, not a current assertion.
        // Pass one copies the original frame; pass two never reseals/promotes it.
        PileRecordContent::RetiredCollectionEquation { equation } => equation
            .verify_strict()
            .map_err(|e| anyhow!("retired equation signature: {e:?}"))?,
        PileRecordContent::Want { .. } => ensure!(
            raw.get(32..64) == Some(frame::WANT.as_slice()),
            "not a current WANT frame"
        ),
        PileRecordContent::Branch { .. } => ensure!(
            raw.get(32..64) == Some(frame::BRANCH.as_slice()),
            "not a current Branch frame"
        ),
        PileRecordContent::BranchTombstone { .. } => ensure!(
            raw.get(32..64) == Some(frame::TOMBSTONE.as_slice()),
            "not a current BranchTombstone frame"
        ),
        PileRecordContent::Opaque {
            kind: OpaqueKind::Described(kind),
        } => {
            let tagged = frame::tagged(kind, raw)
                .map_err(|e| anyhow!("unsupported/invalid old frame: {e:?}"))?;
            legacy32::verified(&tagged).map_err(|e| anyhow!("old signature: {e:?}"))?;
        }
        _ => bail!("unsupported historical/unknown source frame: {content:?}"),
    }
    Ok(())
}

fn audit(
    path: &Path,
    expected: &Ids,
    copied_bytes: usize,
    copied_hash: blake3::Hash,
) -> Result<()> {
    let frames = PileRecords::open(path).map_err(|e| anyhow!("audit frames: {e:?}"))?;
    let bytes = frames.bytes().clone();
    let mut actual = Ids::default();
    let prefix = bytes
        .get(..copied_bytes)
        .ok_or_else(|| anyhow!("copied frame prefix shortened"))?;
    ensure!(
        blake3::hash(prefix) == copied_hash,
        "copied frame order/bytes/occurrence count changed"
    );
    for framed in frames {
        let framed = framed.map_err(|e| anyhow!("audit framing: {e:?}"))?;
        let raw = &bytes[framed.offset..framed.offset + framed.len];
        ensure!(
            !matches!(framed.content, PileRecordContent::Opaque { .. }),
            "unexpected old/opaque output frame"
        );
        if matches!(
            framed.content,
            PileRecordContent::RetiredCollectionEquation { .. }
        ) {
            ensure!(
                framed
                    .offset
                    .checked_add(framed.len)
                    .is_some_and(|end| end <= copied_bytes),
                "retired equation is not wholly within the copied frame prefix"
            );
        }
        validate_frame(framed.content, raw, &bytes)?;
        match framed.content {
            PileRecordContent::Blob { hash, .. } => add(&mut actual.blobs, hash.raw),
            PileRecordContent::CapabilityProof { id, .. } => add(&mut actual.proofs, id.raw),
            PileRecordContent::Collection { record } => {
                add(&mut actual.records, record.fingerprint().raw())
            }
            _ => {}
        }
    }
    ensure!(
        &actual == expected,
        "output identity sets differ from verified obligations"
    );
    let mut file = PileFile::open_read_only(path).map_err(|e| anyhow!("reopen output: {e:?}"))?;
    let checked = (|| -> Result<()> {
        let snapshot = file
            .snapshot()
            .map_err(|e| anyhow!("audit snapshot: {e:?}"))?;
        let mut indexed = PATCH::new();
        for record in snapshot
            .records()
            .map_err(|e| anyhow!("audit records: {e:?}"))?
        {
            add(
                &mut indexed,
                record
                    .map_err(|e| anyhow!("audit record: {e:?}"))?
                    .fingerprint()
                    .raw(),
            );
        }
        ensure!(
            indexed == expected.records,
            "native index lost assertion identity"
        );
        Ok(())
    })();
    let closed = file.close().map_err(|e| anyhow!("close audit: {e:?}"));
    checked.and(closed)
}
