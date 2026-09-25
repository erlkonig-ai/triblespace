//! `trible pile migrate SRC clean --into DST`: the lattice v2 clean-pile
//! migration (spec D8).
//!
//! It writes a NEW pile holding what the new lattice needs and nothing it
//! must not trust or replay: one owner's COMMITs per payload of every current
//! root, the payloads of retired generations re-signed into their current root,
//! leaf DERIVEs re-emitted in the locator form under the foundation owner's
//! key, every signature-valid capability proof, the descriptors of kept
//! collections, the record-kind descriptions, and the blobs all of those
//! reach. Every MERGE of any kind, every retired kind, WANTs, legacy pins,
//! COMMITs of retired collections and duplicate-owner COMMITs are dropped and
//! counted. Merges are rebuilt afterwards by each owner's maintenance.
//!
//! **Locking.** The source is opened with a read-only descriptor
//! ([`PileFile::open_read_only`]), so nothing this command does can write it.
//! Replay takes the same shared `flock` every indexed reader takes
//! (`collection list` and friends): held only while the index is built,
//! escalated to an exclusive lock only for a re-check when replay meets a
//! record torn by an in-flight append. Nothing is locked afterwards: every
//! later read comes from the immutable mapped prefix that replay validated,
//! and the raw census walks exactly that prefix through the snapshot's own
//! mapping ([`PileFileSnapshot::raw_records`]): no lock, no reopen by path,
//! and nothing appended after replay (an append still in flight included) is
//! ever decoded. Blob appends up to 1 GiB share the lock and are never
//! blocked; appends that take the exclusive lock (collection records, proofs,
//! larger blobs) wait at most for the replay.
//!
//! **Ownership.** Per `(current root, data)`, among COMMITs whose signature
//! verifies strictly and whose signer the root admits as a writer, the owner
//! is the signer of the earliest in source order. The record index is keyed
//! `collection || data || frame offset`, so one streaming walk meets each
//! payload's commits contiguously and in source order: nothing is buffered
//! beyond the payload in hand.
//!
//! **Retention.** Direct references of kept records, descriptors and proofs
//! are copied, and a copied blob is walked for further references only when
//! it is a canonical `SimpleArchive` (rows strictly increasing, no nil entity
//! or attribute): exactly its value column is probed, one residency lookup in
//! the in-memory blob index per row until a value is accepted, never a payload
//! read and never a buffered copy of the column. Every other blob is a leaf.
//! That is exact for this data model, where a handle lives in an archive's
//! value column; derived images (Succinct, Rank9, views) are
//! functions of source archives the pile keeps, so their references are
//! already retained through those. The one exception is a kept leaf whose
//! foundation is not in the destination (the source never held its payload):
//! its image is walked conservatively, every 32-byte-aligned stride probed
//! for residency, so the blobs it names still travel. A walk of every kept
//! blob that way would probe every stride of large non-archive payloads too,
//! and the default `BlobChildren` hashes every candidate it hits. Each kept
//! blob is read once, validated once and written once.
//!
//! **Streaming.** Nothing proportional to payload bytes is held in memory:
//! blobs are mmap-backed views of the source prefix, copied one at a time.
//! What is held is index-sized: the owner of every kept payload, the chosen
//! leaves per derived collection, the candidate v9/v11 DERIVEs of kept
//! derived collections, and the set of copied blob handles.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::records::{
    CollectionCommit, CollectionDerive, LegacyUnsignedCollectionEquation, SourceLocator,
};
use triblespace_core::collection::{
    collection_writer_is_admitted_by_policy, descriptor, AdmissionPolicy, CollectionRead,
    CollectionRecord, CollectionStore, RetiredCollectionEquation, ACTION_WRITE,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{
    description_blobs, GetBlobError, PileFile, PileFileSnapshot, PileRecord, PileRecordContent,
    ReadError,
};
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    SnapshotSource,
};
use triblespace_core::trible::TribleSet;

type Raw = [u8; 32];

/// Rewrite a pile into a clean lattice v2 pile (see the module docs).
#[derive(clap::Args, Debug)]
pub struct CleanArgs {
    /// Fresh destination pile, mode 0600. Must not exist. It is written as
    /// `DST.partial` and linked into place only once complete and audited.
    /// Nothing is created with `--dry-run`.
    #[arg(long = "into")]
    pub into: PathBuf,
    /// Current root collection handles, one per line (`blake3:` optional;
    /// `#` starts a comment; anything after the first word is ignored).
    #[arg(long)]
    pub roots: PathBuf,
    /// Adoption plan: `RETIRED_HANDLE CURRENT_HANDLE` per line. Payloads the
    /// retired collection admitted and the current root lacks are re-signed
    /// into the current root with the first `--key`.
    #[arg(long)]
    pub adopt: Option<PathBuf>,
    /// Also adopt from every retired root whose descriptor name equals the
    /// name of exactly one current root.
    #[arg(long)]
    pub adopt_by_name: bool,
    /// Payload adoption: `PAYLOAD_HANDLE CURRENT_HANDLE` per line. Exactly
    /// that payload is re-signed into that current root with the first
    /// `--key`, once per distinct metadata of its strictly verifying commits
    /// anywhere in the source, whether or not the collection it was committed
    /// to is admitted or even readable. For rescuing single payloads without
    /// adopting a whole retired collection.
    #[arg(long)]
    pub adopt_payloads: Option<PathBuf>,
    /// Collections that are not kept roots (retired roots, descriptor-less
    /// collections, derived collections carrying commits) whose payloads may
    /// be dropped although no kept root holds them: one handle per line, `#`
    /// starts the reason. Without it a real run refuses to drop any resident
    /// payload that exists nowhere else in the destination; a dry run
    /// reports them. The guard proves bytes survive somewhere, not that a
    /// faculty will see them where it looks: that is what --adopt and
    /// --adopt-payloads decide.
    #[arg(long)]
    pub discard: Option<PathBuf>,
    /// Signing key file (64 hex characters) this run may sign with; repeat
    /// for several. The first adopts; each re-signs the leaf DERIVEs of the
    /// foundations it owns. No key is used implicitly.
    #[arg(long = "key", value_name = "PATH")]
    pub keys: Vec<PathBuf>,
    /// Write the full JSON report to this NEW file. It must not exist, and
    /// must not name the source or the destination.
    #[arg(long)]
    pub report: Option<PathBuf>,
    /// Plan and count only; no destination is created.
    #[arg(long)]
    pub dry_run: bool,
    /// Drop frames of kinds this binary does not know instead of refusing.
    #[arg(long)]
    pub drop_unknown: bool,
}

const LOCK_DESCRIPTION: &str = "source opened read-only; one shared flock held only while replay \
    builds the index (escalated to an exclusive re-check only if replay meets a record torn by an \
    in-flight append), as `collection list` does; no lock afterwards; the raw census walks exactly \
    the replayed prefix through the snapshot's own mapping, never reopening the path or decoding \
    anything appended after replay";

const RETENTION_DESCRIPTION: &str = "direct references of kept records, descriptors and proofs \
    are copied; a copied blob is walked only when it is a canonical SimpleArchive, probing its \
    value column against the in-memory blob index, one lookup per row until a value is accepted; \
    every other blob is a leaf and is not scanned, except a kept leaf image whose foundation the \
    destination does not hold, whose every 32-byte-aligned stride is probed";

pub fn run(source: PathBuf, args: CleanArgs) -> Result<()> {
    let started = Instant::now();
    let roots = parse_roots(&read_text(&args.roots)?)?;
    let explicit_adoptions = match &args.adopt {
        Some(path) => parse_adoptions(&read_text(path)?)?,
        None => Vec::new(),
    };
    let payload_adoptions = match &args.adopt_payloads {
        Some(path) => parse_payload_adoptions(&read_text(path)?)?,
        None => Vec::new(),
    };
    let discard = match &args.discard {
        Some(path) => parse_discard(&read_text(path)?)?,
        None => BTreeSet::new(),
    };
    let keys = args
        .keys
        .iter()
        .map(|path| {
            triblespace_core::signing_key_file::load_existing(path)
                .map_err(|error| anyhow!("load signing key {}: {error}", path.display()))
        })
        .collect::<Result<Vec<SigningKey>>>()?;
    if !args.dry_run && args.into.exists() {
        bail!(
            "destination {} already exists; clean writes a fresh pile",
            args.into.display()
        );
    }
    if let Some(report) = &args.report {
        check_report_path(report, &source, &args.into)?;
    }

    let mut src = PileFile::open_read_only(&source)
        .map_err(|error| super::super::pile_read_error(&source, error))?;
    let outcome = (|| {
        let snapshot = src
            .snapshot()
            .map_err(|error| super::super::pile_read_error(&source, error))?;
        eprintln!(
            "clean: replayed {} ({} bytes) in {:.1}s; the source is no longer locked",
            source.display(),
            snapshot.prefix_len(),
            started.elapsed().as_secs_f64()
        );
        let run = Run::new(
            &snapshot,
            &args,
            keys,
            roots,
            explicit_adoptions,
            payload_adoptions,
            discard,
            started,
        )?;
        run.execute(&snapshot, &source, &args)
    })();
    let closed = src
        .close()
        .map_err(|error| anyhow!("close source: {error}"));
    let report = outcome?;
    closed?;

    print_summary(&report);
    if let Some(path) = &args.report {
        let text = serde_json::to_string_pretty(&report).context("render report")?;
        // A new file only: never truncate one that appeared meanwhile.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create report {}", path.display()))?;
        std::io::Write::write_all(&mut file, (text + "\n").as_bytes())
            .with_context(|| format!("write report {}", path.display()))?;
    }
    Ok(())
}

/// A path's identity for comparison before either file exists: absolute,
/// with its directory resolved through symlinks when that directory exists.
fn path_identity(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map(|parent| parent.join(name))
            .unwrap_or(absolute),
        _ => absolute,
    }
}

/// The report is written to a NEW file (created exclusively, so neither an
/// existing file nor a symlink is ever followed and truncated), and it must
/// not name the source, the destination or the destination's partial file.
/// Checked before any work, so a bad `--report` costs nothing.
fn check_report_path(report: &Path, source: &Path, into: &Path) -> Result<()> {
    let report_identity = path_identity(report);
    for (what, path) in [
        ("the source pile", source.to_path_buf()),
        ("the destination (--into)", into.to_path_buf()),
        ("the partial destination", partial_path(into)),
    ] {
        if report_identity == path_identity(&path) {
            bail!(
                "--report {} names {what}; the report must be a separate new file",
                report.display()
            );
        }
    }
    if std::fs::symlink_metadata(report).is_ok() {
        bail!(
            "--report {} already exists; the report is only ever written to a new file",
            report.display()
        );
    }
    Ok(())
}

/// Where the destination is written until it is complete: `DST.partial`.
fn partial_path(destination: &Path) -> PathBuf {
    let mut name = destination
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".partial");
    destination.with_file_name(name)
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn parse_handle(text: &str) -> Result<Raw> {
    Ok(super::super::collection::parse_collection_handle(text)?.raw)
}

/// Meaningful words of each line, comments and blank lines removed.
fn words(text: &str) -> impl Iterator<Item = (usize, Vec<&str>)> {
    text.lines().enumerate().filter_map(|(number, line)| {
        let words: Vec<&str> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        (!words.is_empty()).then_some((number + 1, words))
    })
}

fn parse_roots(text: &str) -> Result<Vec<Raw>> {
    let mut roots = Vec::new();
    for (number, words) in words(text) {
        let root = parse_handle(words[0]).with_context(|| format!("--roots line {number}"))?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.is_empty() {
        bail!("--roots names no collection");
    }
    Ok(roots)
}

fn parse_adoptions(text: &str) -> Result<Vec<(Raw, Raw)>> {
    let mut pairs = Vec::new();
    for (number, words) in words(text) {
        let [retired, current] = words[..] else {
            bail!("--adopt line {number}: expected `RETIRED_HANDLE CURRENT_HANDLE`");
        };
        pairs.push((
            parse_handle(retired).with_context(|| format!("--adopt line {number}"))?,
            parse_handle(current).with_context(|| format!("--adopt line {number}"))?,
        ));
    }
    Ok(pairs)
}

fn parse_payload_adoptions(text: &str) -> Result<Vec<(Raw, Raw)>> {
    let mut pairs = Vec::new();
    for (number, words) in words(text) {
        let [payload, current] = words[..] else {
            bail!("--adopt-payloads line {number}: expected `PAYLOAD_HANDLE CURRENT_HANDLE`");
        };
        let payload =
            parse_handle(payload).with_context(|| format!("--adopt-payloads line {number}"))?;
        let current =
            parse_handle(current).with_context(|| format!("--adopt-payloads line {number}"))?;
        if !pairs.contains(&(payload, current)) {
            pairs.push((payload, current));
        }
    }
    Ok(pairs)
}

fn parse_discard(text: &str) -> Result<BTreeSet<Raw>> {
    let mut handles = BTreeSet::new();
    for (number, words) in words(text) {
        handles.insert(parse_handle(words[0]).with_context(|| format!("--discard line {number}"))?);
    }
    Ok(handles)
}

fn hex(raw: &Raw) -> String {
    hex::encode(raw)
}

// ---------------------------------------------------------------------------
// Descriptors and admission

#[derive(Clone, Debug)]
enum Described {
    Root { name: Option<String> },
    Derived { source: Raw },
    Missing,
    Unreadable(String),
}

fn describe(snapshot: &PileFileSnapshot, handle: Raw) -> Described {
    let facts: TribleSet = match snapshot.get::<TribleSet, SimpleArchive>(Inline::new(handle)) {
        Ok(facts) => facts,
        Err(GetBlobError::BlobNotFound(_)) => return Described::Missing,
        Err(error) => return Described::Unreadable(error.to_string()),
    };
    if let Err(error) = descriptor::entity(&facts) {
        return Described::Unreadable(error.to_string());
    }
    match descriptor::source(&facts) {
        Ok(Some(source)) => Described::Derived { source: source.raw },
        Ok(None) => Described::Root {
            name: descriptor::name(&facts).ok().flatten().and_then(|name| {
                snapshot
                    .get::<Blob<UTF8String>, UTF8String>(name)
                    .ok()
                    .and_then(|blob| std::str::from_utf8(&blob.bytes).ok().map(str::to_owned))
            }),
        },
        Err(error) => Described::Unreadable(error.to_string()),
    }
}

/// Who may WRITE a collection, decided from its own descriptor policy and the
/// proofs the destination keeps, as the coverage fold decides it. Cached per
/// collection and per `(collection, signer)`.
struct WriteAdmission<'a> {
    reader: &'a PileFileSnapshot,
    /// Every source proof whose signatures all verify: exactly the proofs
    /// the destination keeps (a pile accepts no other). Admission is decided
    /// from these alone, so a record judged admitted here is admitted by the
    /// destination's own evidence, never by the valid prefix of a proof the
    /// destination cannot hold.
    proofs: Vec<CapabilityProof>,
    /// Source proofs dropped because some signature fails.
    invalid_proofs: u64,
    policies: HashMap<Raw, Option<Vec<AdmissionPolicy>>>,
    decided: HashMap<(Raw, Raw), bool>,
}

impl<'a> WriteAdmission<'a> {
    fn new(reader: &'a PileFileSnapshot) -> Result<Self> {
        let (mut proofs, mut invalid_proofs) = (Vec::new(), 0u64);
        for proof in reader
            .proofs()
            .map_err(|error| anyhow!("list proofs: {error}"))?
        {
            let proof = proof.map_err(|error| anyhow!("read proof: {error}"))?;
            if proof.verify_signatures().is_ok() {
                proofs.push(proof);
            } else {
                invalid_proofs += 1;
            }
        }
        Ok(Self {
            reader,
            proofs,
            invalid_proofs,
            policies: HashMap::new(),
            decided: HashMap::new(),
        })
    }

    fn policies(&mut self, collection: Raw) -> Option<Vec<AdmissionPolicy>> {
        let reader = self.reader;
        self.policies
            .entry(collection)
            .or_insert_with(|| {
                let facts: TribleSet = reader
                    .get::<TribleSet, SimpleArchive>(Inline::new(collection))
                    .ok()?;
                descriptor::entity(&facts).ok()?;
                Some(descriptor::admission_policies(reader, &facts, ACTION_WRITE, None).collect())
            })
            .clone()
    }

    fn admits(&mut self, collection: Raw, signer: Raw) -> bool {
        if let Some(decided) = self.decided.get(&(collection, signer)) {
            return *decided;
        }
        let decided = match (self.policies(collection), VerifyingKey::from_bytes(&signer)) {
            (Some(policies), Ok(subject)) => policies.iter().any(|policy| {
                collection_writer_is_admitted_by_policy(
                    self.reader,
                    Inline::new(collection),
                    policy,
                    subject,
                    &self.proofs,
                )
            }),
            _ => false,
        };
        self.decided.insert((collection, signer), decided);
        decided
    }
}

// ---------------------------------------------------------------------------
// The plan: which collections are kept, adopted from, or dropped

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceRef {
    Root(usize),
    Derived(usize),
}

struct DerivedPlan {
    handle: Raw,
    source: SourceRef,
    source_handle: Raw,
    root: usize,
    depth: usize,
}

#[derive(Default)]
struct CollectionCounts {
    commits: u64,
    merges_v10: u64,
    derives_v11: u64,
    merges_v8: u64,
    derives_v9: u64,
}

impl CollectionCounts {
    fn total(&self) -> u64 {
        self.commits + self.merges_v10 + self.derives_v11 + self.merges_v8 + self.derives_v9
    }

    fn json(&self) -> Value {
        json!({
            "commit_frames": self.commits,
            "merge_v10_frames": self.merges_v10,
            "derive_v11_frames": self.derives_v11,
            "merge_v8_frames": self.merges_v8,
            "derive_v9_frames": self.derives_v9,
        })
    }
}

#[derive(Default)]
struct RootStats {
    kept_commits: u64,
    kept_payloads: u64,
    duplicate_owner: u64,
    invalid_signature: u64,
    unadmitted: u64,
    adopted_commits: u64,
    adopted_payloads: u64,
    /// Kept payloads (foundations) per owner, adopted ones included.
    foundations: BTreeMap<u32, u64>,
}

#[derive(Default)]
struct RetiredStats {
    valid_admitted: u64,
    invalid_signature: u64,
    unadmitted: u64,
    /// Admitted commits of a payload by other than its earliest admitted
    /// signer there, whose metadata is not adopted.
    duplicate_owner: u64,
    adopted_payloads: u64,
    adopted_commits: u64,
    already_present: u64,
}

#[derive(Default)]
struct DerivedStats {
    /// Frame counts of the candidate DERIVEs by outcome.
    reemitted: u64,
    kept_current: u64,
    no_key: BTreeMap<u32, u64>,
    owner_not_admitted: BTreeMap<u32, u64>,
    upstream_pending: BTreeMap<u32, u64>,
    superseded: u64,
    conflicting: u64,
    /// Claims whose signer the target does not admit to WRITE.
    unadmitted_claim: u64,
    merged_input: u64,
    unmatched_input: u64,
    invalid_signature: u64,
    /// Leaves emitted per owner, one per source foundation.
    emitted: BTreeMap<u32, u64>,
    source_foundations: BTreeMap<u32, u64>,
}

struct Plan {
    roots: Vec<Raw>,
    root_names: Vec<Option<String>>,
    root_index: HashMap<Raw, usize>,
    derived: Vec<DerivedPlan>,
    derived_index: HashMap<Raw, usize>,
    /// Retired roots, mapped to the index of the current root they are
    /// adopted into when they are.
    retired: BTreeMap<Raw, (Option<String>, Option<usize>)>,
    /// Known collections that are neither kept nor retired roots, and why.
    dropped: BTreeMap<Raw, String>,
    /// Single payloads adopted into a current root: `(payload, root)`.
    adopted_payloads: Vec<(Raw, usize)>,
    adopt_payload_set: HashSet<Raw>,
    /// Retired roots whose payloads may be dropped although no kept root
    /// holds them.
    discard: BTreeSet<Raw>,
    /// `--discard` handles that are not retired roots of this source.
    unused_discards: Vec<Raw>,
}

impl Plan {
    fn kept(&self, collection: &Raw) -> bool {
        self.root_index.contains_key(collection) || self.derived_index.contains_key(collection)
    }

    fn known(&self, collection: &Raw) -> bool {
        self.kept(collection)
            || self.retired.contains_key(collection)
            || self.dropped.contains_key(collection)
    }
}

fn plan(
    snapshot: &PileFileSnapshot,
    roots: Vec<Raw>,
    explicit_adoptions: &[(Raw, Raw)],
    adopt_by_name: bool,
    payload_adoptions: &[(Raw, Raw)],
    discard: BTreeSet<Raw>,
) -> Result<Plan> {
    let mut known: BTreeSet<Raw> = snapshot
        .collections()
        .map_err(|error| anyhow!("list collections: {error}"))?
        .into_iter()
        .map(|handle| handle.raw)
        .collect();
    known.extend(
        snapshot
            .retired_collection_equations()
            .map(|equation| equation.collection().raw),
    );

    let mut root_names = Vec::new();
    for root in &roots {
        match describe(snapshot, *root) {
            Described::Root { name } => root_names.push(name),
            Described::Derived { .. } => {
                bail!("--roots names blake3:{}, a derived collection", hex(root))
            }
            Described::Missing => bail!(
                "--roots names blake3:{}, whose descriptor is not in the source; WRITE \
                 admission cannot be decided without it",
                hex(root)
            ),
            Described::Unreadable(error) => bail!(
                "--roots names blake3:{}, whose descriptor is unreadable: {error}",
                hex(root)
            ),
        }
    }
    let root_index: HashMap<Raw, usize> = roots
        .iter()
        .enumerate()
        .map(|(index, root)| (*root, index))
        .collect();

    let mut described: BTreeMap<Raw, Described> = BTreeMap::new();
    let mut lookup = |handle: Raw| -> Described {
        described
            .entry(handle)
            .or_insert_with(|| describe(snapshot, handle))
            .clone()
    };

    // Derived collections whose source chain ends in a kept root are kept,
    // together with every derived collection on the chain.
    let mut chains: BTreeMap<Raw, Vec<Raw>> = BTreeMap::new();
    let mut retired: BTreeMap<Raw, (Option<String>, Option<usize>)> = BTreeMap::new();
    let mut dropped: BTreeMap<Raw, String> = BTreeMap::new();
    for handle in known.iter().copied() {
        if root_index.contains_key(&handle) {
            continue;
        }
        match lookup(handle) {
            Described::Root { name } => {
                retired.insert(handle, (name, None));
            }
            Described::Missing => {
                dropped.insert(handle, "descriptor not in source".to_owned());
            }
            Described::Unreadable(error) => {
                dropped.insert(handle, format!("descriptor unreadable: {error}"));
            }
            Described::Derived { source } => {
                let mut chain = vec![handle];
                let mut cursor = source;
                let verdict = loop {
                    if root_index.contains_key(&cursor) {
                        break Ok(());
                    }
                    if chain.contains(&cursor) || chain.len() > 64 {
                        break Err("source chain does not end in a root".to_owned());
                    }
                    match lookup(cursor) {
                        Described::Derived { source } => {
                            chain.push(cursor);
                            cursor = source;
                        }
                        Described::Root { .. } => {
                            break Err(format!("derived from retired root blake3:{}", hex(&cursor)))
                        }
                        Described::Missing => {
                            break Err(format!(
                                "source chain reaches blake3:{}, whose descriptor is not in \
                                 the source",
                                hex(&cursor)
                            ))
                        }
                        Described::Unreadable(error) => {
                            break Err(format!(
                                "source chain reaches an unreadable descriptor: {error}"
                            ))
                        }
                    }
                };
                match verdict {
                    Ok(()) => {
                        chains.insert(handle, chain);
                    }
                    Err(reason) => {
                        dropped.insert(handle, reason);
                    }
                }
            }
        }
    }

    // Every derived collection on a kept chain, upstream first.
    let mut depth_of: BTreeMap<Raw, (usize, Raw)> = BTreeMap::new();
    for chain in chains.values() {
        for (position, handle) in chain.iter().enumerate() {
            let depth = chain.len() - position;
            let source = match lookup(*handle) {
                Described::Derived { source } => source,
                _ => unreachable!("chain members are derived descriptors"),
            };
            depth_of.insert(*handle, (depth, source));
        }
    }
    let mut ordered: Vec<(usize, Raw, Raw)> = depth_of
        .into_iter()
        .map(|(handle, (depth, source))| (depth, handle, source))
        .collect();
    ordered.sort();
    let mut derived: Vec<DerivedPlan> = Vec::new();
    let mut derived_index: HashMap<Raw, usize> = HashMap::new();
    for (depth, handle, source_handle) in ordered {
        let (source, root) = if let Some(&root) = root_index.get(&source_handle) {
            (SourceRef::Root(root), root)
        } else {
            let upstream = derived_index[&source_handle];
            (SourceRef::Derived(upstream), derived[upstream].root)
        };
        derived_index.insert(handle, derived.len());
        derived.push(DerivedPlan {
            handle,
            source,
            source_handle,
            root,
            depth,
        });
    }

    for (retired_handle, current) in explicit_adoptions {
        let Some(&root) = root_index.get(current) else {
            bail!(
                "--adopt maps into blake3:{}, which is not one of the --roots",
                hex(current)
            );
        };
        if root_index.contains_key(retired_handle) {
            bail!(
                "--adopt maps blake3:{}, a current root, as a retired collection",
                hex(retired_handle)
            );
        }
        match lookup(*retired_handle) {
            Described::Derived { .. } => bail!(
                "--adopt maps blake3:{}, a derived collection; only roots are adopted",
                hex(retired_handle)
            ),
            Described::Root { name } => {
                let entry = retired.entry(*retired_handle).or_insert((name, None));
                if entry.1.is_some_and(|mapped| mapped != root) {
                    bail!(
                        "--adopt maps blake3:{} into two different roots",
                        hex(retired_handle)
                    );
                }
                entry.1 = Some(root);
            }
            // Nothing it holds can be shown admitted; the mapping is recorded
            // so the report shows it, and adopts nothing.
            Described::Missing | Described::Unreadable(_) => {
                dropped.remove(retired_handle);
                retired.insert(*retired_handle, (None, Some(root)));
            }
        }
    }
    if adopt_by_name {
        for (_, (name, mapped)) in retired.iter_mut() {
            let Some(name) = name else { continue };
            if mapped.is_some() {
                continue;
            }
            let matches: Vec<usize> = root_names
                .iter()
                .enumerate()
                .filter(|(_, root_name)| root_name.as_deref() == Some(name.as_str()))
                .map(|(index, _)| index)
                .collect();
            match matches[..] {
                [] => {}
                [root] => *mapped = Some(root),
                _ => bail!(
                    "--adopt-by-name: {} current roots are named {name:?}; map its retired \
                     generations with --adopt instead",
                    matches.len()
                ),
            }
        }
    }

    let mut adopted_payloads = Vec::new();
    for (payload, current) in payload_adoptions {
        let Some(&root) = root_index.get(current) else {
            bail!(
                "--adopt-payloads adopts into blake3:{}, which is not one of the --roots",
                hex(current)
            );
        };
        adopted_payloads.push((*payload, root));
    }
    // Discarding a kept root contradicts --roots and is refused. A handle
    // that is not a retired root of this source discards nothing; it is
    // reported, so one list can serve several piles and a typo is visible.
    let mut unused_discards = Vec::new();
    for handle in &discard {
        if root_index.contains_key(handle) {
            bail!("--discard names blake3:{}, one of the --roots", hex(handle));
        }
        if !retired.contains_key(handle)
            && !dropped.contains_key(handle)
            && !chains.contains_key(handle)
            && !chains.values().any(|chain| chain.contains(handle))
        {
            eprintln!(
                "clean: --discard names blake3:{}, not a collection of this source; ignored",
                hex(handle)
            );
            unused_discards.push(*handle);
        }
    }

    Ok(Plan {
        roots,
        root_names,
        root_index,
        derived,
        derived_index,
        retired,
        dropped,
        adopt_payload_set: adopted_payloads.iter().map(|(payload, _)| *payload).collect(),
        adopted_payloads,
        discard,
        unused_discards,
    })
}

// ---------------------------------------------------------------------------
// Signature checks, a batch at a time on every core

const CHECK_BATCH: usize = 4096;

/// The items of `inner` in their order, each paired with the answer of
/// `check`. Answers are computed a batch at a time across the available
/// cores, so a stream of strict Ed25519 checks costs its CPU time divided by
/// the core count, and memory stays one batch.
struct Checked<I: Iterator, F> {
    inner: I,
    check: F,
    workers: usize,
    ready: std::collections::VecDeque<(I::Item, bool)>,
}

impl<I: Iterator, F> Checked<I, F> {
    fn new(inner: I, check: F) -> Self {
        let workers = std::thread::available_parallelism()
            .map_or(1, |cores| cores.get())
            .min(16);
        Self {
            inner,
            check,
            workers,
            ready: std::collections::VecDeque::new(),
        }
    }
}

impl<I, F> Iterator for Checked<I, F>
where
    I: Iterator,
    I::Item: Sync,
    F: Fn(&I::Item) -> bool + Sync,
{
    type Item = (I::Item, bool);

    fn next(&mut self) -> Option<Self::Item> {
        if self.ready.is_empty() {
            let batch: Vec<I::Item> = self.inner.by_ref().take(CHECK_BATCH).collect();
            if batch.is_empty() {
                return None;
            }
            let check = &self.check;
            let chunk = batch.len().div_ceil(self.workers);
            let answers: Vec<bool> = std::thread::scope(|scope| {
                let parts: Vec<_> = batch
                    .chunks(chunk)
                    .map(|part| scope.spawn(move || part.iter().map(check).collect::<Vec<_>>()))
                    .collect();
                parts
                    .into_iter()
                    .flat_map(|part| part.join().expect("a signature check does not panic"))
                    .collect()
            });
            self.ready.extend(batch.into_iter().zip(answers));
        }
        self.ready.pop_front()
    }
}

// ---------------------------------------------------------------------------
// The raw census: every frame of the frozen prefix, in source order

#[derive(Default)]
struct Census {
    frames: u64,
    blob_frames: u64,
    blob_bytes: u64,
    commits: u64,
    merges_v10: u64,
    derives_v11: u64,
    merges_v8: u64,
    derives_v9: u64,
    capability_proofs: u64,
    retired_capability_proofs: u64,
    wants: u64,
    retired_want_records: u64,
    pins: u64,
    pin_tombstones: u64,
    legacy_v3: u64,
    legacy_unsigned_equations: u64,
    retired_derive_v4: u64,
    retired_team_records: u64,
    retired_artifact_offers: u64,
    opaque: u64,
    opaque_bytes: u64,
}

impl Census {
    fn json(&self) -> Value {
        json!({
            "frames": self.frames,
            "blob_frames": self.blob_frames,
            "blob_frame_bytes": self.blob_bytes,
            "commit": self.commits,
            "merge_v10": self.merges_v10,
            "derive_v11": self.derives_v11,
            "merge_v8": self.merges_v8,
            "derive_v9": self.derives_v9,
            "capability_proof": self.capability_proofs,
            "retired_capability_proof": self.retired_capability_proofs,
            "want": self.wants,
            "retired_want_record": self.retired_want_records,
            "pin": self.pins,
            "pin_tombstone": self.pin_tombstones,
            "legacy_v3": self.legacy_v3,
            "legacy_unsigned_equation": self.legacy_unsigned_equations,
            "retired_derive_v4": self.retired_derive_v4,
            "retired_team_record": self.retired_team_records,
            "retired_artifact_offer": self.retired_artifact_offers,
            "unknown_kind": self.opaque,
            "unknown_kind_bytes": self.opaque_bytes,
        })
    }
}

/// A chosen leaf of a derived collection: its foundation's owner, and
/// whether the leaf is in the destination.
#[derive(Clone, Copy)]
struct Leaf {
    owner: u32,
    written: bool,
}

/// What becomes of the chosen claim for one source foundation.
enum Decision {
    Write(CollectionDerive, Outcome),
    /// The run holds no key of the foundation's owner.
    NoKey,
    /// The owner is not admitted to WRITE the target.
    NotAdmitted,
    /// The source leaf this one maps was not written.
    UpstreamPending,
}

/// How a leaf DERIVE reached the destination.
#[derive(Clone, Copy)]
enum Outcome {
    /// A current (v11) DERIVE signed by the foundation's owner, kept as is.
    KeptCurrent,
    /// Re-signed by the owner from a retired (v9) DERIVE's claim.
    Reemitted,
}

/// One DERIVE frame into a kept derived collection, in source order.
#[derive(Clone, Copy)]
struct Candidate {
    offset: u64,
    /// The source foundation's handle (v9), or its locator (v11).
    input: Raw,
    output: Raw,
    signer: u32,
    /// Index into `current` for a v11 record, kept as-is when chosen.
    current: Option<u32>,
}

/// Interned signer keys: per-foundation state stores a `u32`, not 32 bytes.
#[derive(Default)]
struct Signers {
    keys: Vec<Raw>,
    index: HashMap<Raw, u32>,
}

impl Signers {
    fn intern(&mut self, key: Raw) -> u32 {
        if let Some(index) = self.index.get(&key) {
            return *index;
        }
        let index = u32::try_from(self.keys.len()).expect("fewer than 2^32 signers");
        self.keys.push(key);
        self.index.insert(key, index);
        index
    }

    fn hex(&self, index: u32) -> String {
        hex(&self.keys[index as usize])
    }
}

struct RawPass {
    census: Census,
    per_collection: BTreeMap<Raw, CollectionCounts>,
    /// Candidate DERIVEs per kept derived collection, in source order.
    candidates: Vec<Vec<Candidate>>,
    current: Vec<CollectionDerive>,
    invalid_candidates: Vec<u64>,
    /// `(collection, result)` of every MERGE (v8 and v10) of a kept collection.
    merge_results: HashSet<(Raw, Raw)>,
    /// Every decodable equation whose output names a blob: `(kind, collection,
    /// output, inputs)`. The clean pile drops them all; an output whose inputs
    /// are not all valid here would be the only copy of those facts.
    equations: Vec<(&'static str, Raw, Raw, Vec<Raw>)>,
}

/// Every frame of the snapshot's replayed prefix, read from its own mapping:
/// frames appended after replay, a torn in-flight append among them, are
/// never decoded, and a re-pointed path cannot substitute another file.
fn raw_pass(snapshot: &PileFileSnapshot, plan: &Plan, signers: &mut Signers) -> Result<RawPass> {
    // Only a claim that could become a leaf of a kept derived collection
    // is worth a signature check.
    let checked = Checked::new(
        snapshot.raw_records(),
        |record: &Result<PileRecord, ReadError>| match record {
            Ok(PileRecord {
                content:
                    PileRecordContent::Collection {
                        record: CollectionRecord::Derive(derive),
                    },
                ..
            }) => {
                plan.derived_index.contains_key(&derive.collection().raw)
                    && derive.verify_strict().is_ok()
            }
            Ok(PileRecord {
                content:
                    PileRecordContent::RetiredCollectionEquation {
                        equation: equation @ RetiredCollectionEquation::DeriveV9 { .. },
                    },
                ..
            }) => {
                plan.derived_index.contains_key(&equation.collection().raw)
                    && equation.verify_strict().is_ok()
            }
            _ => false,
        },
    );
    let mut pass = RawPass {
        census: Census::default(),
        per_collection: BTreeMap::new(),
        candidates: vec![Vec::new(); plan.derived.len()],
        current: Vec::new(),
        invalid_candidates: vec![0; plan.derived.len()],
        merge_results: HashSet::new(),
        equations: Vec::new(),
    };
    for (record, verified) in checked {
        // Replay accepted every frame of this prefix; failing to decode one
        // now means bytes below it changed, never a torn tail.
        let record = record.map_err(|error| {
            anyhow!("census: a frame below the replayed prefix no longer decodes: {error}")
        })?;
        let census = &mut pass.census;
        census.frames += 1;
        let offset = record.offset as u64;
        match record.content {
            PileRecordContent::Blob { .. } => {
                census.blob_frames += 1;
                census.blob_bytes += record.len as u64;
            }
            PileRecordContent::Collection { record: current } => {
                let collection = current.collection().raw;
                let counts = pass.per_collection.entry(collection).or_default();
                match current {
                    CollectionRecord::Commit(_) => {
                        census.commits += 1;
                        counts.commits += 1;
                    }
                    CollectionRecord::Merge(merge) => {
                        census.merges_v10 += 1;
                        counts.merges_v10 += 1;
                        pass.equations.push((
                            "merge_v10",
                            collection,
                            merge.result().raw,
                            merge.inputs().iter().map(|input| input.raw).collect(),
                        ));
                        if plan.kept(&collection) {
                            pass.merge_results.insert((collection, merge.result().raw));
                        }
                    }
                    CollectionRecord::Derive(derive) => {
                        census.derives_v11 += 1;
                        counts.derives_v11 += 1;
                        if let Some(&target) = plan.derived_index.get(&collection) {
                            if !verified {
                                pass.invalid_candidates[target] += 1;
                            } else {
                                let current = u32::try_from(pass.current.len())
                                    .expect("fewer than 2^32 current DERIVEs");
                                pass.current.push(derive);
                                pass.candidates[target].push(Candidate {
                                    offset,
                                    input: derive.input().raw(),
                                    output: derive.output().raw,
                                    signer: signers.intern(derive.public_key().raw),
                                    current: Some(current),
                                });
                            }
                        }
                    }
                }
            }
            PileRecordContent::RetiredCollectionEquation { equation } => {
                let collection = equation.collection().raw;
                let counts = pass.per_collection.entry(collection).or_default();
                match equation {
                    RetiredCollectionEquation::MergeV8 {
                        low, high, result, ..
                    } => {
                        census.merges_v8 += 1;
                        counts.merges_v8 += 1;
                        pass.equations.push((
                            "merge_v8",
                            collection,
                            result.raw,
                            vec![low.raw, high.raw],
                        ));
                        if plan.kept(&collection) {
                            pass.merge_results.insert((collection, result.raw));
                        }
                    }
                    RetiredCollectionEquation::DeriveV9 {
                        input,
                        output,
                        public_key,
                        ..
                    } => {
                        census.derives_v9 += 1;
                        counts.derives_v9 += 1;
                        pass.equations.push(("derive_v9", collection, output.raw, vec![input.raw]));
                        if let Some(&target) = plan.derived_index.get(&collection) {
                            if !verified {
                                pass.invalid_candidates[target] += 1;
                            } else {
                                pass.candidates[target].push(Candidate {
                                    offset,
                                    input: input.raw,
                                    output: output.raw,
                                    signer: signers.intern(public_key.raw),
                                    current: None,
                                });
                            }
                        }
                    }
                }
            }
            PileRecordContent::CapabilityProof { .. } => census.capability_proofs += 1,
            PileRecordContent::RetiredCapabilityProof => census.retired_capability_proofs += 1,
            PileRecordContent::Want { .. } => census.wants += 1,
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => census.retired_want_records += 1,
            PileRecordContent::Branch { .. } => census.pins += 1,
            PileRecordContent::BranchTombstone { .. } => census.pin_tombstones += 1,
            PileRecordContent::LegacyCollectionV3 { .. } => census.legacy_v3 += 1,
            PileRecordContent::LegacyUnsignedCollectionEquation { equation } => {
                census.legacy_unsigned_equations += 1;
                match equation {
                    LegacyUnsignedCollectionEquation::Merge {
                        collection,
                        low,
                        high,
                        result,
                    } => pass.equations.push((
                        "legacy_merge",
                        collection.raw,
                        result.raw,
                        vec![low.raw, high.raw],
                    )),
                    LegacyUnsignedCollectionEquation::Derive {
                        collection,
                        input,
                        output,
                    } => pass.equations.push((
                        "legacy_derive",
                        collection.raw,
                        output.raw,
                        vec![input.raw],
                    )),
                }
            }
            PileRecordContent::RetiredCollectionDeriveV4 => census.retired_derive_v4 += 1,
            PileRecordContent::RetiredPeerEvidenceV1 | PileRecordContent::RetiredStoreScopeV1 => {
                census.retired_team_records += 1
            }
            PileRecordContent::RetiredArtifactOfferV1 => census.retired_artifact_offers += 1,
            // A kind this reader has no rule for is unknown to it, whether
            // or not the pile layer can name it: refused unless dropped.
            _ => {
                census.opaque += 1;
                census.opaque_bytes += record.len as u64;
            }
        }
    }
    Ok(pass)
}

/// Equations whose output has valid bytes here while one of their inputs does
/// not: the output is then the only copy of those facts. The clean pile drops
/// every equation record, so such an output is lost unless the destination
/// keeps its bytes anyway (a kept leaf image, for one).
#[derive(Default)]
struct SoleRepresentations {
    checked: u64,
    candidates: Vec<(&'static str, Raw, Raw)>,
}

fn sole_representations(snapshot: &PileFileSnapshot, pass: &RawPass) -> Result<SoleRepresentations> {
    // Valid means resident AND hashing to its handle: a corrupt occurrence
    // regenerates nothing. Each blob is read and hashed at most once.
    let mut valid: HashMap<Raw, bool> = HashMap::new();
    let mut is_valid = |handle: Raw| -> Result<bool> {
        if let Some(known) = valid.get(&handle) {
            return Ok(*known);
        }
        let answer = match snapshot.get::<Blob<UnknownBlob>, UnknownBlob>(Inline::new(handle)) {
            Ok(_) => true,
            Err(GetBlobError::BlobNotFound(_)) | Err(GetBlobError::ValidationError(_)) => false,
            Err(error) => bail!("inspect blob {}: {error}", hex(&handle)),
        };
        valid.insert(handle, answer);
        Ok(answer)
    };
    let mut sole = SoleRepresentations::default();
    for (kind, collection, output, inputs) in &pass.equations {
        sole.checked += 1;
        if !is_valid(*output)? {
            continue;
        }
        let mut regenerable = true;
        for input in inputs {
            if !is_valid(*input)? {
                regenerable = false;
                break;
            }
        }
        if !regenerable {
            sole.candidates.push((*kind, *collection, *output));
        }
    }
    Ok(sole)
}

/// The report, given which sole copies the destination did not keep.
fn sole_json(sole: &SoleRepresentations, lost: &[(&'static str, Raw, Raw)]) -> Value {
    let mut by: BTreeMap<(&'static str, Raw), u64> = BTreeMap::new();
    for (kind, collection, _) in lost {
        *by.entry((*kind, *collection)).or_default() += 1;
    }
    json!({
        "equations_checked": sole.checked,
        "sole_copies": sole.candidates.len(),
        "kept_in_destination": sole.candidates.len() - lost.len(),
        "found": lost.len(),
        "by_kind_and_collection": by.iter().map(|((kind, collection), count)| json!({
            "kind": kind, "collection": hex(collection), "count": count,
        })).collect::<Vec<_>>(),
        "examples": lost.iter().take(10).map(|(kind, collection, output)| json!({
            "kind": kind, "collection": hex(collection), "output": hex(output),
        })).collect::<Vec<_>>(),
        "not_decodable": "frames of unknown kinds (census unknown_kind) are dropped only with --drop-unknown",
    })
}

// ---------------------------------------------------------------------------
// Writing: the destination, or nothing at all in a dry run

enum Sink {
    Pile(PileFile),
    DryRun,
}

impl Sink {
    fn put(&mut self, blob: Blob<UnknownBlob>) -> Result<()> {
        if let Sink::Pile(pile) = self {
            pile.put::<UnknownBlob, _>(blob)
                .map_err(|error| anyhow!("write blob: {error}"))?;
        }
        Ok(())
    }

    fn insert(&mut self, record: CollectionRecord) -> Result<()> {
        if let Sink::Pile(pile) = self {
            pile.insert(record)
                .map_err(|error| anyhow!("write collection record: {error}"))?;
        }
        Ok(())
    }

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<()> {
        if let Sink::Pile(pile) = self {
            pile.insert_proof(proof)
                .map_err(|error| anyhow!("write capability proof: {error}"))?;
        }
        Ok(())
    }
}

const BLOCK: u64 = 256;

fn round_up(len: u64) -> u64 {
    len.div_ceil(BLOCK) * BLOCK
}

/// The frame a blob of this length occupies: one header block, then the
/// payload padded to whole blocks.
fn blob_frame_len(len: usize) -> u64 {
    BLOCK + round_up(len as u64)
}

/// The frame a proof occupies: magic and span, then the canonical proof bytes
/// (its kind first), padded to whole blocks.
fn proof_frame_len(len: usize) -> u64 {
    round_up(32 + len as u64)
}

#[derive(Default)]
struct BlobStats {
    kept: u64,
    kept_payload_bytes: u64,
    archives_walked: u64,
    values_probed: u64,
    /// Leaf images walked conservatively because their foundation is not
    /// in the destination, and the blobs that walk added.
    stride_walks: u64,
    stride_children: u64,
    corrupt_skipped: u64,
    references_not_resident: u64,
    /// Distinct resident source blobs, and those the destination does not
    /// hold (never reached, or no occurrence validates), with payload bytes
    /// as the source's record headers state them.
    source_distinct: u64,
    source_payload_bytes: u64,
    dropped: u64,
    dropped_payload_bytes: u64,
}

/// Copies blobs out of the frozen source prefix, each once.
struct Retainer<'a> {
    src: &'a PileFileSnapshot,
    /// Every handle decided: copied, or found with no valid occurrence.
    copied: HashSet<Raw>,
    /// Handles decided but not copied, because no occurrence validates.
    corrupt: HashSet<Raw>,
    stats: BlobStats,
    projected_bytes: u64,
}

impl<'a> Retainer<'a> {
    fn new(src: &'a PileFileSnapshot) -> Self {
        Self {
            src,
            copied: HashSet::new(),
            corrupt: HashSet::new(),
            stats: BlobStats::default(),
            projected_bytes: 0,
        }
    }

    /// Count the source's distinct blobs and those the destination will not
    /// hold. One pass over the in-memory blob index, reading record headers
    /// only (no payload is hashed).
    fn count_dropped(&mut self) -> Result<()> {
        let src = self.src;
        for info in src.blobs() {
            let info = info.map_err(|error| anyhow!("list source blobs: {error}"))?;
            let handle = info.handle.raw;
            self.stats.source_distinct += 1;
            self.stats.source_payload_bytes += info.length;
            if !self.copied.contains(&handle) || self.corrupt.contains(&handle) {
                self.stats.dropped += 1;
                self.stats.dropped_payload_bytes += info.length;
            }
        }
        Ok(())
    }

    fn resident(&self, handle: Raw) -> bool {
        self.src
            .contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
            .unwrap_or(false)
    }

    /// Keep `handle`, a direct reference of a kept record, and everything
    /// its archive closure reaches. An absent direct reference is counted.
    fn keep(&mut self, sink: &mut Sink, handle: Raw) -> Result<()> {
        if self.copied.contains(&handle) {
            return Ok(());
        }
        if !self.resident(handle) {
            self.stats.references_not_resident += 1;
            return Ok(());
        }
        let mut pending = vec![handle];
        while let Some(handle) = pending.pop() {
            if !self.copied.insert(handle) {
                continue;
            }
            let blob: Blob<UnknownBlob> = match self
                .src
                .get::<Blob<UnknownBlob>, UnknownBlob>(Inline::new(handle))
            {
                Ok(blob) => blob,
                Err(GetBlobError::ValidationError(_)) => {
                    // No resident occurrence hashes to its handle; nothing
                    // can be copied, and the reference stays dangling.
                    self.stats.corrupt_skipped += 1;
                    self.corrupt.insert(handle);
                    continue;
                }
                Err(error) => bail!("read blob {}: {error}", hex(&handle)),
            };
            let len = blob.bytes.len();
            let (src, copied) = (self.src, &self.copied);
            let mut probed = 0u64;
            let children = archive_children(&blob.bytes, |value| {
                probed += 1;
                !copied.contains(value)
                    && src
                        .contains_blob(Inline::<Handle<UnknownBlob>>::new(*value))
                        .unwrap_or(false)
            });
            if let Some(children) = children {
                self.stats.archives_walked += 1;
                self.stats.values_probed += probed;
                pending.extend(children);
            }
            self.stats.kept += 1;
            self.stats.kept_payload_bytes += len as u64;
            self.projected_bytes += blob_frame_len(len);
            sink.put(blob)?;
        }
        Ok(())
    }

    /// The conservative walk, for a kept leaf image whose foundation is not
    /// in the destination to carry its references: keep every resident blob
    /// a 32-byte-aligned stride of the image names, each with its archive
    /// closure. Probes are residency lookups; the image is not re-hashed.
    fn keep_strides(&mut self, sink: &mut Sink, handle: Raw) -> Result<()> {
        if !self.resident(handle) {
            return Ok(());
        }
        let blob: Blob<UnknownBlob> = match self
            .src
            .get::<Blob<UnknownBlob>, UnknownBlob>(Inline::new(handle))
        {
            Ok(blob) => blob,
            // Counted when the image itself was kept.
            Err(GetBlobError::ValidationError(_)) => return Ok(()),
            Err(error) => bail!("read blob {}: {error}", hex(&handle)),
        };
        self.stats.stride_walks += 1;
        for stride in blob.bytes.chunks_exact(32) {
            let value = <Raw>::try_from(stride).expect("a stride is 32 bytes");
            if !self.copied.contains(&value) && self.resident(value) {
                self.stats.stride_children += 1;
                self.keep(sink, value)?;
            }
        }
        Ok(())
    }
}

/// The values of a canonical `SimpleArchive` that `probe` accepts, each
/// once, or `None` for any blob that is not one: rows of 64 bytes, strictly
/// increasing, each with a non-nil entity and attribute. Every row's value is
/// probed as it is checked, so a blob that turns out not to be an archive
/// hands back nothing it probed.
fn archive_children(bytes: &[u8], mut probe: impl FnMut(&Raw) -> bool) -> Option<Vec<Raw>> {
    if bytes.is_empty() || bytes.len() % 64 != 0 {
        return None;
    }
    let mut children = HashSet::new();
    let mut previous: Option<&[u8]> = None;
    for row in bytes.chunks_exact(64) {
        if row[..16].iter().all(|byte| *byte == 0) || row[16..32].iter().all(|byte| *byte == 0) {
            return None;
        }
        if previous.is_some_and(|previous| previous >= row) {
            return None;
        }
        previous = Some(row);
        let value = <Raw>::try_from(&row[32..]).expect("a row ends in a 32-byte value");
        if !children.contains(&value) && probe(&value) {
            children.insert(value);
        }
    }
    let mut children: Vec<Raw> = children.into_iter().collect();
    children.sort_unstable();
    Some(children)
}

// ---------------------------------------------------------------------------
// The run

/// What the roots walk decided: per root and per adopted retired collection
/// counts, the owner of every kept payload, and the payloads adoption may
/// carry, each with the retired collection it came from.
struct Roots {
    stats: Vec<RootStats>,
    retired: BTreeMap<Raw, RetiredStats>,
    owners: HashMap<(u32, Raw), u32>,
    adoptable: BTreeMap<(usize, Raw, Raw), Raw>,
    /// Every payload any commit of a collection other than a kept root
    /// names (retired roots, descriptor-less or derived collections),
    /// whatever its signature or admission: what dropping it would drop.
    retired_payloads: BTreeMap<Raw, BTreeSet<Raw>>,
    /// Every distinct metadata of a strictly verifying commit of each
    /// payload listed for payload adoption, from any collection.
    payload_metadata: HashMap<Raw, BTreeSet<Raw>>,
    payload_adoption: PayloadAdoptionStats,
    /// `(root, payload, metadata)` of every commit the destination holds, kept
    /// or adopted, so payload rescue adds only variants it does not hold yet.
    written: HashSet<(usize, Raw, Raw)>,
}

/// What dropping one retired root would drop.
#[derive(Default, Clone, Copy)]
struct Unkept {
    payloads: u64,
    /// Resident in the source, held by no kept root.
    absent_resident: u64,
    /// Held by no kept root and not resident here either.
    absent_elsewhere: u64,
}

#[derive(Default)]
struct PayloadAdoptionStats {
    adopted: u64,
    already_present: u64,
    /// Metadata variants added to a payload the adopter already carried in
    /// this run through collection adoption.
    variants_added: u64,
}

impl Roots {
    /// Record the owner of the payload whose commits just ended, if any
    /// commit of it was kept.
    fn close_run(&mut self, run: Option<((usize, Raw), Option<u32>)>) {
        if let Some(((root, data), Some(owner))) = run {
            self.owners.insert((root as u32, data), owner);
            let stats = &mut self.stats[root];
            stats.kept_payloads += 1;
            *stats.foundations.entry(owner).or_default() += 1;
        }
    }
}

/// The destination side of a run: what is copied, what is written, and the
/// frame bytes that projects.
struct Writing<'a, 's> {
    retainer: Retainer<'a>,
    sink: &'s mut Sink,
    records_written: BTreeMap<&'static str, u64>,
}

impl Writing<'_, '_> {
    fn keep(&mut self, handle: Raw) -> Result<()> {
        self.retainer.keep(self.sink, handle)
    }

    /// Write one record after the blobs it names, and count it as `kind`.
    fn record(&mut self, record: CollectionRecord, kind: &'static str) -> Result<()> {
        for reference in record.blob_references() {
            self.keep(reference.raw)?;
        }
        self.retainer.projected_bytes += BLOCK;
        self.sink.insert(record)?;
        *self.records_written.entry(kind).or_default() += 1;
        Ok(())
    }

    fn written(&self, kind: &str) -> u64 {
        self.records_written.get(kind).copied().unwrap_or(0)
    }
}

struct Run {
    plan: Plan,
    dry_run: bool,
    keys: Vec<SigningKey>,
    key_index: HashMap<Raw, usize>,
    started: Instant,
    /// Seconds since the start at which each phase finished.
    phases: std::cell::RefCell<Map<String, Value>>,
}

impl Run {
    fn new(
        snapshot: &PileFileSnapshot,
        args: &CleanArgs,
        keys: Vec<SigningKey>,
        roots: Vec<Raw>,
        explicit_adoptions: Vec<(Raw, Raw)>,
        payload_adoptions: Vec<(Raw, Raw)>,
        discard: BTreeSet<Raw>,
        started: Instant,
    ) -> Result<Self> {
        let plan = plan(
            snapshot,
            roots,
            &explicit_adoptions,
            args.adopt_by_name,
            &payload_adoptions,
            discard,
        )?;
        let key_index = keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.verifying_key().to_bytes(), index))
            .collect();
        let phases = std::cell::RefCell::new(Map::new());
        phases.borrow_mut().insert(
            "replayed_and_planned".into(),
            json!(started.elapsed().as_secs_f64()),
        );
        Ok(Self {
            plan,
            dry_run: args.dry_run,
            keys,
            key_index,
            started,
            phases,
        })
    }

    fn execute(
        self,
        snapshot: &PileFileSnapshot,
        source: &Path,
        args: &CleanArgs,
    ) -> Result<Value> {
        let started = self.started;
        let plan = &self.plan;
        let mut signers = Signers::default();
        let mut admission = WriteAdmission::new(snapshot)?;

        // Adoption needs a key every mapped current root admits. Refuse
        // before anything is written rather than emit inadmissible records.
        let adoption_targets: BTreeSet<usize> = plan
            .retired
            .values()
            .filter_map(|(_, mapped)| *mapped)
            .chain(plan.adopted_payloads.iter().map(|(_, root)| *root))
            .collect();
        let adopter = if adoption_targets.is_empty() {
            None
        } else {
            let Some(adopter) = self.keys.first() else {
                bail!("adoption is planned but no --key was given; the first --key adopts");
            };
            let adopter_key = adopter.verifying_key().to_bytes();
            for root in &adoption_targets {
                if !admission.admits(plan.roots[*root], adopter_key) {
                    bail!(
                        "the first --key ({}) is not admitted to WRITE blake3:{}; adopted \
                         payloads re-signed with it would not be admissible there",
                        hex(&adopter_key),
                        hex(&plan.roots[*root])
                    );
                }
            }
            Some(adopter)
        };

        eprintln!(
            "clean: planned {} root(s), {} derived collection(s), {} retired root(s)",
            plan.roots.len(),
            plan.derived.len(),
            plan.retired.len(),
        );
        let pass = raw_pass(snapshot, plan, &mut signers)?;
        if pass.census.opaque > 0 && !args.drop_unknown {
            bail!(
                "the source holds {} frame(s) ({} bytes) of kinds this binary does not know; \
                 refusing to drop them silently. Use a binary that knows them, or pass \
                 --drop-unknown",
                pass.census.opaque,
                pass.census.opaque_bytes
            );
        }
        self.mark(
            "census",
            format_args!(
                "{} frame(s), {} candidate leaf claim(s) verified",
                pass.census.frames,
                pass.candidates.iter().map(Vec::len).sum::<usize>()
            ),
        );
        let sole = sole_representations(snapshot, &pass)?;
        self.mark(
            "sole_representations",
            format_args!(
                "{} equation(s) checked, {} output(s) are the only valid copy of their facts",
                sole.checked,
                sole.candidates.len()
            ),
        );

        // The destination is written under a `.partial` name, created only
        // now, after every refusal that needs no writing, and installed under
        // its own name without replacing anything once it is complete and
        // audited. A failure removes it; a killed run leaves a file whose name
        // says it is incomplete, never a plausible short pile.
        let partial = partial_path(&args.into);
        let created = !args.dry_run;
        let mut sink = if created {
            if let Some(parent) = partial
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("create destination directory {}", parent.display())
                })?;
            }
            drop(
                super::super::compact::create_fresh_destination(&partial).with_context(|| {
                    format!(
                        "create fresh destination {} (a leftover from an interrupted run is \
                         never reused; remove it)",
                        partial.display()
                    )
                })?,
            );
            match PileFile::open(&partial) {
                Ok(pile) => Sink::Pile(pile),
                Err(error) => {
                    return Err(super::super::compact::cleanup_incomplete_destination(
                        &partial,
                        anyhow!("open destination {}: {error}", partial.display()),
                    ))
                }
            }
        } else {
            Sink::DryRun
        };

        let written = self.write(
            snapshot,
            &pass,
            &sole,
            &mut signers,
            &mut admission,
            adopter,
            &mut sink,
        );
        let closed = match sink {
            Sink::Pile(pile) => pile
                .close()
                .map_err(|error| anyhow!("close destination: {error}")),
            Sink::DryRun => Ok(()),
        };
        let mut report = match (written, closed) {
            (Ok(report), Ok(())) => report,
            (Err(error), _) | (Ok(_), Err(error)) if created => {
                return Err(super::super::compact::cleanup_incomplete_destination(
                    &partial, error,
                ));
            }
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
        };

        let (destination_bytes, audit) = if args.dry_run {
            (Value::Null, Value::Null)
        } else {
            self.mark(
                "written",
                format_args!("{} closed and synced", partial.display()),
            );
            let installed = audit_destination(&partial).and_then(|(mut audit, unresolved)| {
                // An unresolved reference is expected when the source never
                // held valid bytes for it either. One the source holds intact
                // was lost by the copy, and the destination is refused.
                let (mut lost, mut absent, mut corrupt) = (Vec::new(), 0u64, 0u64);
                for handle in &unresolved {
                    match snapshot.get::<Blob<UnknownBlob>, UnknownBlob>(Inline::new(*handle)) {
                        Ok(_) => lost.push(*handle),
                        Err(GetBlobError::BlobNotFound(_)) => absent += 1,
                        Err(GetBlobError::ValidationError(_)) => corrupt += 1,
                        Err(error) => bail!("inspect source blob {}: {error}", hex(handle)),
                    }
                }
                if !lost.is_empty() {
                    bail!(
                        "the destination leaves {} reference(s) unresolved whose valid bytes \
                         the source holds, e.g. blake3:{}; refusing to install a lossy copy",
                        lost.len(),
                        hex(&lost[0])
                    );
                }
                let object = audit.as_object_mut().expect("the audit is an object");
                object.insert("unresolved_absent_in_source".into(), json!(absent));
                object.insert("unresolved_corrupt_in_source".into(), json!(corrupt));
                let bytes = std::fs::metadata(&partial)
                    .with_context(|| format!("stat {}", partial.display()))?
                    .len();
                // A hard link installs without replacing: it fails if the
                // destination appeared meanwhile.
                std::fs::hard_link(&partial, &args.into).with_context(|| {
                    format!("install {} as {}", partial.display(), args.into.display())
                })?;
                Ok((bytes, audit))
            });
            let (bytes, audit) = match installed {
                Ok(installed) => installed,
                Err(error) => {
                    return Err(super::super::compact::cleanup_incomplete_destination(
                        &partial, error,
                    ))
                }
            };
            std::fs::remove_file(&partial)
                .with_context(|| format!("remove the installed {}", partial.display()))?;
            self.mark(
                "installed",
                format_args!("{} audited and linked into place", args.into.display()),
            );
            (json!(bytes), audit)
        };
        let object = report.as_object_mut().expect("the report is an object");
        object.insert("source".into(), json!(source.display().to_string()));
        object.insert("destination".into(), json!(args.into.display().to_string()));
        object.insert("dry_run".into(), json!(args.dry_run));
        object.insert("source_bytes".into(), json!(snapshot.prefix_len()));
        object.insert("destination_bytes".into(), destination_bytes);
        object.insert("destination_audit".into(), audit);
        object.insert("source_lock".into(), json!(LOCK_DESCRIPTION));
        object.insert(
            "elapsed_seconds".into(),
            json!(started.elapsed().as_secs_f64()),
        );
        object.insert(
            "phase_finished_at_seconds".into(),
            Value::Object(self.phases.borrow().clone()),
        );
        Ok(report)
    }

    /// Record that a phase finished now, and say so on stderr.
    fn mark(&self, phase: &str, what: std::fmt::Arguments) {
        let at = self.started.elapsed().as_secs_f64();
        eprintln!("clean: {phase}: {what}, at {at:.1}s");
        self.phases.borrow_mut().insert(phase.into(), json!(at));
    }

    fn signer_key(&self, signers: &Signers, signer: u32) -> Option<&SigningKey> {
        self.key_index
            .get(&signers.keys[signer as usize])
            .map(|index| &self.keys[*index])
    }

    fn write(
        &self,
        snapshot: &PileFileSnapshot,
        pass: &RawPass,
        sole: &SoleRepresentations,
        signers: &mut Signers,
        admission: &mut WriteAdmission,
        adopter: Option<&SigningKey>,
        sink: &mut Sink,
    ) -> Result<Value> {
        let mut out = Writing {
            retainer: Retainer::new(snapshot),
            sink,
            records_written: BTreeMap::new(),
        };
        let proofs_kept = self.keep_descriptors_and_proofs(&mut out, admission)?;
        let proofs_invalid = admission.invalid_proofs;
        let mut roots = self.keep_roots(&mut out, snapshot, signers, admission)?;
        self.mark(
            "roots",
            format_args!(
                "{} commit(s) and {} blob(s) kept",
                out.written("commit"),
                out.retainer.stats.kept
            ),
        );
        if let Some(adopter) = adopter {
            self.adopt(&mut out, &mut roots, signers, adopter)?;
            self.adopt_payloads(&mut out, &mut roots, signers, adopter)?;
        }
        let unkept = self.unkept(snapshot, &roots)?;
        self.refuse_unkept(&unkept)?;
        let derived_stats = self.reemit_leaves(&mut out, pass, &roots, signers, admission)?;
        self.mark(
            "derived",
            format_args!(
                "{} leaf DERIVE(s) written, {} blob(s) kept",
                out.written("derive"),
                out.retainer.stats.kept
            ),
        );

        // Every kind this binary writes, resolvable from the file alone.
        let mut descriptions = 0u64;
        for blob in description_blobs() {
            let handle = blob.get_handle().raw;
            if out.retainer.copied.insert(handle) {
                out.retainer.projected_bytes += blob_frame_len(blob.bytes.len());
                out.sink.put(blob)?;
                descriptions += 1;
            }
        }
        out.retainer.count_dropped()?;

        // A sole copy the destination keeps anyway (a kept leaf image, say)
        // is preserved; one it does not keep is refused in a real run.
        let lost: Vec<(&'static str, Raw, Raw)> = sole
            .candidates
            .iter()
            .filter(|(_, _, output)| !out.retainer.copied.contains(output))
            .copied()
            .collect();
        if !lost.is_empty() && !self.dry_run {
            bail!(
                "refusing to drop {} equation output(s) that are the only valid copy of their \
                 facts (an input is missing or corrupt here), e.g. {} blake3:{}; see a dry run's \
                 sole_representations",
                lost.len(),
                lost[0].0,
                hex(&lost[0].2)
            );
        }

        let mut report = self.report(
            pass,
            signers,
            &out,
            &roots,
            &unkept,
            &derived_stats,
            proofs_kept,
            proofs_invalid,
            descriptions,
        );
        report
            .as_object_mut()
            .expect("the report is an object")
            .insert("sole_representations".into(), sole_json(sole, &lost));
        Ok(report)
    }

    /// Descriptors first, then the proofs that admit writers, so every
    /// record lands after what it needs to be decided. The proofs are the
    /// signature-valid ones admission was decided from.
    fn keep_descriptors_and_proofs(
        &self,
        out: &mut Writing,
        admission: &WriteAdmission,
    ) -> Result<u64> {
        let plan = &self.plan;
        for handle in plan
            .roots
            .iter()
            .chain(plan.derived.iter().map(|derived| &derived.handle))
        {
            out.keep(*handle)?;
        }
        let mut kept = 0u64;
        for proof in admission.proofs.iter().cloned() {
            for definition in proof.blob_references() {
                out.keep(definition.raw)?;
            }
            // The resource is not an ownership edge, but a resource
            // descriptor that names no dropped collection is what lets the
            // proof be interpreted, so it travels with it.
            let resource = proof.resource().into_bytes();
            if (!plan.known(&resource) || plan.kept(&resource)) && out.retainer.resident(resource) {
                out.keep(resource)?;
            }
            out.retainer.projected_bytes += proof_frame_len(proof.as_bytes().len());
            out.sink.insert_proof(proof)?;
            kept += 1;
        }
        Ok(kept)
    }

    /// Roots: one streaming walk of the record index. Each payload's commits
    /// arrive together and in source order, so its owner is the signer of the
    /// first that verifies and is admitted. Commits of adopted retired
    /// collections are collected for [`Self::adopt`] on the way.
    fn keep_roots(
        &self,
        out: &mut Writing,
        snapshot: &PileFileSnapshot,
        signers: &mut Signers,
        admission: &mut WriteAdmission,
    ) -> Result<Roots> {
        let plan = &self.plan;
        let mut roots = Roots {
            stats: plan.roots.iter().map(|_| RootStats::default()).collect(),
            retired: BTreeMap::new(),
            owners: HashMap::new(),
            adoptable: BTreeMap::new(),
            retired_payloads: BTreeMap::new(),
            payload_metadata: HashMap::new(),
            payload_adoption: PayloadAdoptionStats::default(),
            written: HashSet::new(),
        };
        let mut run: Option<((usize, Raw), Option<u32>)> = None;
        // The same owner rule per `(retired collection, data)`: only the
        // earliest admitted signer's metadata is carried into adoption.
        let mut retired_run: Option<((Raw, Raw), Option<Raw>)> = None;
        let records = snapshot
            .records()
            .map_err(|error| anyhow!("read collection records: {error}"))?;
        // Only commits of kept roots and of adopted retired collections are
        // decided by their signatures.
        let checked =
            Checked::new(
                records,
                |record: &Result<CollectionRecord, ReadError>| match record {
                    Ok(CollectionRecord::Commit(commit)) => {
                        let collection = commit.collection().raw;
                        (plan.root_index.contains_key(&collection)
                            || plan
                                .retired
                                .get(&collection)
                                .is_some_and(|(_, mapped)| mapped.is_some())
                            || plan.adopt_payload_set.contains(&commit.data().raw))
                            && commit.verify_strict().is_ok()
                    }
                    _ => false,
                },
            );
        for (record, verified) in checked {
            let record = record.map_err(|error| anyhow!("read collection record: {error}"))?;
            let CollectionRecord::Commit(commit) = record else {
                // MERGEs are dropped; current DERIVEs were taken in the census.
                continue;
            };
            let collection = commit.collection().raw;
            let data = commit.data().raw;
            let signer = commit.public_key().raw;
            if verified && plan.adopt_payload_set.contains(&data) {
                roots
                    .payload_metadata
                    .entry(data)
                    .or_default()
                    .insert(commit.metadata().raw);
            }
            if let Some(&root) = plan.root_index.get(&collection) {
                if run.map(|(key, _)| key) != Some((root, data)) {
                    roots.close_run(run.take());
                    run = Some(((root, data), None));
                }
                let stats = &mut roots.stats[root];
                if !verified {
                    stats.invalid_signature += 1;
                    continue;
                }
                if !admission.admits(collection, signer) {
                    stats.unadmitted += 1;
                    continue;
                }
                let signer = signers.intern(signer);
                let owner = &mut run.as_mut().expect("a run is open").1;
                if owner.is_none() {
                    *owner = Some(signer);
                }
                if *owner != Some(signer) {
                    stats.duplicate_owner += 1;
                    continue;
                }
                stats.kept_commits += 1;
                roots.written.insert((root, data, commit.metadata().raw));
                out.record(record, "commit")?;
            } else if let Some((_, mapped)) = plan.retired.get(&collection) {
                roots
                    .retired_payloads
                    .entry(collection)
                    .or_default()
                    .insert(data);
                let Some(root) = mapped else { continue };
                if retired_run.map(|(key, _)| key) != Some((collection, data)) {
                    retired_run = Some(((collection, data), None));
                }
                let stats = roots.retired.entry(collection).or_default();
                if !verified {
                    stats.invalid_signature += 1;
                    continue;
                }
                if !admission.admits(collection, signer) {
                    stats.unadmitted += 1;
                    continue;
                }
                stats.valid_admitted += 1;
                let owner = &mut retired_run.as_mut().expect("a run is open").1;
                if *owner.get_or_insert(signer) != signer {
                    stats.duplicate_owner += 1;
                    continue;
                }
                roots
                    .adoptable
                    .entry((*root, data, commit.metadata().raw))
                    .or_insert(collection);
            } else {
                // A commit into a collection that is neither a kept nor a
                // retired root: its descriptor is missing or unreadable, or
                // it names a derived collection. Its payload is counted all
                // the same, so the guard sees what dropping it would drop.
                roots
                    .retired_payloads
                    .entry(collection)
                    .or_default()
                    .insert(data);
            }
        }
        roots.close_run(run.take());
        Ok(roots)
    }

    /// Admitted payloads of a mapped retired collection that the current
    /// root lacks, re-signed into it by the first key, which then owns them.
    /// Only the metadata of the payload's owner in the retired collection
    /// (its earliest admitted signer) is carried, as for a current root.
    fn adopt(
        &self,
        out: &mut Writing,
        roots: &mut Roots,
        signers: &mut Signers,
        adopter: &SigningKey,
    ) -> Result<()> {
        let adopter_signer = signers.intern(adopter.verifying_key().to_bytes());
        let mut adopted: BTreeSet<(usize, Raw)> = BTreeSet::new();
        for ((root, data, metadata), retired) in &roots.adoptable {
            let stats = roots.retired.entry(*retired).or_default();
            if roots.owners.contains_key(&(*root as u32, *data)) {
                stats.already_present += 1;
                continue;
            }
            let commit = CollectionCommit::sign(
                adopter,
                Inline::new(self.plan.roots[*root]),
                Inline::new(*data),
                Inline::new(*metadata),
            );
            out.record(CollectionRecord::Commit(commit), "adopted_commit")?;
            roots.written.insert((*root, *data, *metadata));
            stats.adopted_commits += 1;
            roots.stats[*root].adopted_commits += 1;
            if adopted.insert((*root, *data)) {
                stats.adopted_payloads += 1;
            }
        }
        // Presence was decided against the pre-adoption owners, so a payload
        // adopted with two metadata archives is adopted with both.
        for (root, data) in adopted {
            roots.owners.insert((root as u32, data), adopter_signer);
            let stats = &mut roots.stats[root];
            stats.adopted_payloads += 1;
            *stats.foundations.entry(adopter_signer).or_default() += 1;
        }
        Ok(())
    }

    /// Exactly the listed payloads, re-signed into their current root by the
    /// first key, once per distinct metadata of their strictly verifying
    /// commits anywhere in the source. The new signature is a fresh
    /// endorsement, not the original authorship. A payload the root already
    /// holds is left as it is.
    fn adopt_payloads(
        &self,
        out: &mut Writing,
        roots: &mut Roots,
        signers: &mut Signers,
        adopter: &SigningKey,
    ) -> Result<()> {
        let adopter_signer = signers.intern(adopter.verifying_key().to_bytes());
        for (payload, root) in &self.plan.adopted_payloads {
            if let Some(owner) = roots.owners.get(&(*root as u32, *payload)).copied() {
                roots.payload_adoption.already_present += 1;
                // Carried by collection adoption, which takes one signer's
                // metadata: add the variants it left out. A payload another
                // key owns stays that key's alone (one owner per payload).
                if owner == adopter_signer {
                    let variants = roots.payload_metadata.get(payload).cloned().unwrap_or_default();
                    for metadata in variants {
                        if !roots.written.insert((*root, *payload, metadata)) {
                            continue;
                        }
                        let commit = CollectionCommit::sign(
                            adopter,
                            Inline::new(self.plan.roots[*root]),
                            Inline::new(*payload),
                            Inline::new(metadata),
                        );
                        out.record(CollectionRecord::Commit(commit), "adopted_payload_commit")?;
                        roots.stats[*root].adopted_commits += 1;
                        roots.payload_adoption.variants_added += 1;
                    }
                }
                continue;
            }
            let Some(variants) = roots.payload_metadata.get(payload).cloned() else {
                bail!(
                    "--adopt-payloads lists blake3:{}, but no commit of it in the source \
                     verifies strictly; there is no metadata to carry",
                    hex(payload)
                );
            };
            // One commit per distinct metadata: pile order is not authorship
            // order, so no single variant can claim to be the original.
            for metadata in &variants {
                let commit = CollectionCommit::sign(
                    adopter,
                    Inline::new(self.plan.roots[*root]),
                    Inline::new(*payload),
                    Inline::new(*metadata),
                );
                out.record(CollectionRecord::Commit(commit), "adopted_payload_commit")?;
                roots.written.insert((*root, *payload, *metadata));
            }
            roots.owners.insert((*root as u32, *payload), adopter_signer);
            let stats = &mut roots.stats[*root];
            stats.adopted_commits += variants.len() as u64;
            stats.adopted_payloads += 1;
            *stats.foundations.entry(adopter_signer).or_default() += 1;
            roots.payload_adoption.adopted += 1;
        }
        Ok(())
    }

    /// Per retired root: its payloads, and those of them resident in the
    /// source that no kept root of the destination holds. Those are what
    /// dropping the root would lose.
    fn unkept(&self, snapshot: &PileFileSnapshot, roots: &Roots) -> Result<BTreeMap<Raw, Unkept>> {
        let kept: HashSet<Raw> = roots.owners.keys().map(|(_, data)| *data).collect();
        let mut unkept = BTreeMap::new();
        for (collection, payloads) in &roots.retired_payloads {
            let mut entry = Unkept {
                payloads: payloads.len() as u64,
                ..Unkept::default()
            };
            for payload in payloads {
                if kept.contains(payload) {
                    continue;
                }
                let resident = snapshot
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(*payload))
                    .map_err(|error| anyhow!("inspect retired payload: {error}"))?;
                if resident {
                    entry.absent_resident += 1;
                } else {
                    entry.absent_elsewhere += 1;
                }
            }
            unkept.insert(*collection, entry);
        }
        Ok(unkept)
    }

    /// Refuse, in a real run, to drop a resident payload no kept root holds
    /// unless its retired root is listed in `--discard`. A dry run reports.
    fn refuse_unkept(&self, unkept: &BTreeMap<Raw, Unkept>) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let refused: Vec<String> = unkept
            .iter()
            .filter(|(collection, entry)| {
                entry.absent_resident > 0 && !self.plan.discard.contains(*collection)
            })
            .map(|(collection, entry)| {
                let name = match self.plan.retired.get(collection) {
                    Some((name, _)) => name.clone().unwrap_or_else(|| "(unnamed)".to_owned()),
                    None => self.plan.dropped.get(collection).map_or_else(
                        || "(commits into a derived collection)".to_owned(),
                        |reason| format!("(not a root: {reason})"),
                    ),
                };
                format!(
                    "  blake3:{} {name}: {} of {} payload(s) exist nowhere else",
                    hex(collection),
                    entry.absent_resident,
                    entry.payloads
                )
            })
            .collect();
        if !refused.is_empty() {
            bail!(
                "refusing to drop {} collection(s) holding resident payloads that no kept \
                 root holds:\n{}\nKeep them with --roots, carry payloads with --adopt or \
                 --adopt-payloads, or list the collection in --discard after deciding it may go",
                refused.len(),
                refused.join("\n")
            );
        }
        Ok(())
    }

    /// Derived collections, upstream first. A source foundation is a kept
    /// payload of the root, or a chosen leaf output of the derived source,
    /// whether or not that leaf could be written.
    fn reemit_leaves(
        &self,
        out: &mut Writing,
        pass: &RawPass,
        roots: &Roots,
        signers: &Signers,
        admission: &mut WriteAdmission,
    ) -> Result<Vec<DerivedStats>> {
        let plan = &self.plan;
        let owners = &roots.owners;
        let mut leaves: Vec<HashMap<Raw, Leaf>> =
            plan.derived.iter().map(|_| HashMap::new()).collect();
        let mut derived_stats: Vec<DerivedStats> = plan
            .derived
            .iter()
            .map(|_| DerivedStats::default())
            .collect();
        for (index, derived) in plan.derived.iter().enumerate() {
            // Upstream collections come first, so every source this one
            // reads is already settled below `index`.
            let (upstream_leaves, rest) = leaves.split_at_mut(index);
            let target_leaves = &mut rest[0];
            let stats = &mut derived_stats[index];
            stats.invalid_signature = pass.invalid_candidates[index];
            stats.source_foundations = match derived.source {
                SourceRef::Root(root) => roots.stats[root].foundations.clone(),
                SourceRef::Derived(upstream) => {
                    let mut counts = BTreeMap::new();
                    for leaf in upstream_leaves[upstream].values() {
                        *counts.entry(leaf.owner).or_default() += 1;
                    }
                    counts
                }
            };
            let foundation_of = |foundation: &Raw| -> Option<Leaf> {
                match derived.source {
                    SourceRef::Root(root) => {
                        owners.get(&(root as u32, *foundation)).map(|owner| Leaf {
                            owner: *owner,
                            written: true,
                        })
                    }
                    SourceRef::Derived(upstream) => {
                        upstream_leaves[upstream].get(foundation).copied()
                    }
                }
            };
            let candidates = &pass.candidates[index];
            // A v11 DERIVE names its foundation by locator; resolve it only
            // when some candidate needs it.
            let locators: HashMap<Raw, Raw> = if candidates.iter().any(|c| c.current.is_some()) {
                match derived.source {
                    SourceRef::Root(root) => owners
                        .keys()
                        .filter(|(owner_root, _)| *owner_root == root as u32)
                        .map(|(_, data)| (SourceLocator::of(*data).raw(), *data))
                        .collect(),
                    SourceRef::Derived(upstream) => upstream_leaves[upstream]
                        .keys()
                        .map(|output| (SourceLocator::of(*output).raw(), *output))
                        .collect(),
                }
            } else {
                HashMap::new()
            };
            let mut groups: BTreeMap<Raw, Vec<Candidate>> = BTreeMap::new();
            for candidate in candidates {
                let foundation = match candidate.current {
                    None => Some(candidate.input),
                    Some(_) => locators.get(&candidate.input).copied(),
                };
                let Some(foundation) =
                    foundation.filter(|foundation| foundation_of(foundation).is_some())
                else {
                    if candidate.current.is_none()
                        && pass
                            .merge_results
                            .contains(&(derived.source_handle, candidate.input))
                    {
                        stats.merged_input += 1;
                    } else {
                        stats.unmatched_input += 1;
                    }
                    continue;
                };
                // A claim whose signer the target's WRITE policy does not
                // admit was never believed in the source: it neither competes
                // for the leaf nor counts as a conflict.
                if !admission.admits(derived.handle, signers.keys[candidate.signer as usize]) {
                    stats.unadmitted_claim += 1;
                    continue;
                }
                groups.entry(foundation).or_default().push(*candidate);
            }
            for (foundation, mut group) in groups {
                group.sort_by_key(|candidate| candidate.offset);
                let source = foundation_of(&foundation).expect("grouped foundations are known");
                let owner = source.owner;
                // The owner's current record, kept as is without a key; else
                // the owner's earliest claim; else the earliest admitted one.
                let chosen = *group
                    .iter()
                    .find(|candidate| candidate.signer == owner && candidate.current.is_some())
                    .or_else(|| group.iter().find(|candidate| candidate.signer == owner))
                    .unwrap_or(&group[0]);
                for candidate in &group {
                    if candidate.offset == chosen.offset {
                        continue;
                    }
                    if candidate.output == chosen.output {
                        stats.superseded += 1;
                    } else {
                        stats.conflicting += 1;
                    }
                }
                let target = derived.handle;
                let decision = if !source.written {
                    // The leaf this one maps is not in the destination
                    // either; its owner derives both after the cutover.
                    Decision::UpstreamPending
                } else {
                    match chosen.current {
                        Some(current) if chosen.signer == owner => {
                            Decision::Write(pass.current[current as usize], Outcome::KeptCurrent)
                        }
                        _ => match self.signer_key(signers, owner) {
                            Some(key) => Decision::Write(
                                CollectionDerive::sign(
                                    key,
                                    Inline::new(target),
                                    SourceLocator::of(foundation),
                                    Inline::new(chosen.output),
                                ),
                                Outcome::Reemitted,
                            ),
                            None => Decision::NoKey,
                        },
                    }
                };
                let decision = match decision {
                    Decision::Write(..)
                        if !admission.admits(target, signers.keys[owner as usize]) =>
                    {
                        Decision::NotAdmitted
                    }
                    decision => decision,
                };
                let written = match decision {
                    Decision::Write(derive, outcome) => {
                        out.record(CollectionRecord::Derive(derive), "derive")?;
                        // The image's references normally travel with the
                        // foundation's archive. Without that foundation in
                        // the destination, the image is walked itself.
                        if !out.retainer.copied.contains(&foundation)
                            || out.retainer.corrupt.contains(&foundation)
                        {
                            out.retainer.keep_strides(out.sink, chosen.output)?;
                        }
                        match outcome {
                            Outcome::KeptCurrent => stats.kept_current += 1,
                            Outcome::Reemitted => stats.reemitted += 1,
                        }
                        *stats.emitted.entry(owner).or_default() += 1;
                        true
                    }
                    Decision::NoKey => {
                        *stats.no_key.entry(owner).or_default() += 1;
                        false
                    }
                    Decision::NotAdmitted => {
                        *stats.owner_not_admitted.entry(owner).or_default() += 1;
                        false
                    }
                    Decision::UpstreamPending => {
                        *stats.upstream_pending.entry(owner).or_default() += 1;
                        false
                    }
                };
                // Identical images of two foundations are one leaf output:
                // the first foundation's owner answers for it downstream,
                // unless only a later one's leaf was written.
                let leaf = Leaf { owner, written };
                target_leaves
                    .entry(chosen.output)
                    .and_modify(|existing| {
                        if written && !existing.written {
                            *existing = leaf;
                        }
                    })
                    .or_insert(leaf);
            }
        }
        Ok(derived_stats)
    }

    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        pass: &RawPass,
        signers: &Signers,
        out: &Writing,
        roots: &Roots,
        unkept: &BTreeMap<Raw, Unkept>,
        derived_stats: &[DerivedStats],
        proofs_kept: u64,
        proofs_invalid: u64,
        descriptions: u64,
    ) -> Value {
        let (root_stats, retired_stats) = (&roots.stats, &roots.retired);
        let payload_adoption = &roots.payload_adoption;
        let retainer = &out.retainer;
        let plan = &self.plan;
        let by_owner = |counts: &BTreeMap<u32, u64>| -> Value {
            Value::Object(
                counts
                    .iter()
                    .filter(|(_, count)| **count > 0)
                    .map(|(owner, count)| (signers.hex(*owner), json!(count)))
                    .collect::<Map<String, Value>>(),
            )
        };
        let frames = |handle: &Raw| -> Value {
            pass.per_collection
                .get(handle)
                .map(CollectionCounts::json)
                .unwrap_or_else(|| CollectionCounts::default().json())
        };

        let roots: Vec<Value> = plan
            .roots
            .iter()
            .zip(root_stats)
            .zip(&plan.root_names)
            .map(|((handle, stats), name)| {
                let merges = pass
                    .per_collection
                    .get(handle)
                    .map_or(0, |counts| counts.merges_v8 + counts.merges_v10);
                json!({
                    "handle": hex(handle),
                    "name": name,
                    "source_frames": frames(handle),
                    "kept_commits": stats.kept_commits,
                    "kept_payloads": stats.kept_payloads,
                    "adopted_commits": stats.adopted_commits,
                    "adopted_payloads": stats.adopted_payloads,
                    "dropped": {
                        "duplicate_owner": stats.duplicate_owner,
                        "invalid_signature": stats.invalid_signature,
                        "unadmitted": stats.unadmitted,
                        "merge_frames": merges,
                    },
                    "payloads_by_owner": by_owner(&stats.foundations),
                })
            })
            .collect();

        let retired: Vec<Value> = plan
            .retired
            .iter()
            .map(|(handle, (name, mapped))| {
                let stats = retired_stats.get(handle);
                json!({
                    "handle": hex(handle),
                    "name": name,
                    "adopted_into": mapped.map(|root| hex(&plan.roots[root])),
                    "records": pass.per_collection.get(handle).map_or(0, CollectionCounts::total),
                    "source_frames": frames(handle),
                    "admitted_commits": stats.map_or(0, |s| s.valid_admitted),
                    "invalid_signature": stats.map_or(0, |s| s.invalid_signature),
                    "unadmitted": stats.map_or(0, |s| s.unadmitted),
                    "duplicate_owner": stats.map_or(0, |s| s.duplicate_owner),
                    "adopted_payloads": stats.map_or(0, |s| s.adopted_payloads),
                    "adopted_commits": stats.map_or(0, |s| s.adopted_commits),
                    "already_present": stats.map_or(0, |s| s.already_present),
                    "payloads": unkept.get(handle).map_or(0, |u| u.payloads),
                    "absent_resident": unkept.get(handle).map_or(0, |u| u.absent_resident),
                    "absent_elsewhere": unkept.get(handle).map_or(0, |u| u.absent_elsewhere),
                    "discarded": plan.discard.contains(handle),
                })
            })
            .collect();

        let derived: Vec<Value> = plan
            .derived
            .iter()
            .zip(derived_stats)
            .map(|(derived, stats)| {
                let mut needs = BTreeMap::new();
                for (owner, count) in &stats.source_foundations {
                    let emitted = stats.emitted.get(owner).copied().unwrap_or(0);
                    needs.insert(*owner, count.saturating_sub(emitted));
                }
                json!({
                    "handle": hex(&derived.handle),
                    "source": hex(&derived.source_handle),
                    "root": hex(&plan.roots[derived.root]),
                    "depth": derived.depth,
                    "source_frames": frames(&derived.handle),
                    "source_foundations": stats.source_foundations.values().sum::<u64>(),
                    "foundations_with_leaf": stats.emitted.values().sum::<u64>(),
                    "needs_rederive_by_owner": by_owner(&needs),
                    "source_foundations_by_owner": by_owner(&stats.source_foundations),
                    "leaves_by_owner": by_owner(&stats.emitted),
                    "derive_frames": {
                        "reemitted": stats.reemitted,
                        "kept_current": stats.kept_current,
                        "no_key_by_owner": by_owner(&stats.no_key),
                        "owner_not_admitted_by_owner": by_owner(&stats.owner_not_admitted),
                        "source_leaf_not_written_by_owner": by_owner(&stats.upstream_pending),
                        "superseded": stats.superseded,
                        "conflicting_output": stats.conflicting,
                        "unadmitted_claim": stats.unadmitted_claim,
                        "merged_input": stats.merged_input,
                        "unmatched_input": stats.unmatched_input,
                        "invalid_signature": stats.invalid_signature,
                    },
                })
            })
            .collect();

        let dropped: Vec<Value> = plan
            .dropped
            .iter()
            .map(|(handle, reason)| {
                json!({
                    "handle": hex(handle),
                    "reason": reason,
                    "records": pass.per_collection.get(handle).map_or(0, CollectionCounts::total),
                    "source_frames": frames(handle),
                })
            })
            .collect();

        let census = &pass.census;
        let retired_commits: u64 = plan
            .retired
            .keys()
            .chain(plan.dropped.keys())
            .filter_map(|handle| pass.per_collection.get(handle))
            .map(|counts| counts.commits)
            .sum();
        let derived_commits: u64 = plan
            .derived
            .iter()
            .filter_map(|derived| pass.per_collection.get(&derived.handle))
            .map(|counts| counts.commits)
            .sum();
        let kept_current: u64 = derived_stats.iter().map(|stats| stats.kept_current).sum();
        let stats = &retainer.stats;
        let refused: Vec<Value> = unkept
            .iter()
            .filter(|(handle, entry)| entry.absent_resident > 0 && !plan.discard.contains(*handle))
            .map(|(handle, entry)| json!({"handle": hex(handle), "absent_resident": entry.absent_resident}))
            .collect();
        json!({
            "roots": roots,
            "retired": retired,
            "payload_adoption": {
                "listed": plan.adopted_payloads.len(),
                "adopted": payload_adoption.adopted,
                "already_present": payload_adoption.already_present,
                "variants_added": payload_adoption.variants_added,
            },
            "unkept_guard": {
                "not_retired": unkept
                    .iter()
                    .filter(|(handle, _)| !plan.retired.contains_key(*handle))
                    .map(|(handle, entry)| json!({
                        "handle": hex(handle),
                        "reason": plan.dropped.get(handle).cloned()
                            .unwrap_or_else(|| "commits into a derived collection".to_owned()),
                        "payloads": entry.payloads,
                        "absent_resident": entry.absent_resident,
                        "absent_elsewhere": entry.absent_elsewhere,
                        "discarded": plan.discard.contains(handle),
                    }))
                    .collect::<Vec<_>>(),
                "discarded_roots": plan.discard.len() - plan.unused_discards.len(),
                "unused_discards": plan.unused_discards.iter().map(hex).collect::<Vec<_>>(),
                "would_refuse": refused,
            },
            "derived": derived,
            "dropped_collections": dropped,
            "source_census": census.json(),
            "records_written": {
                "commit": out.written("commit"),
                "adopted_commit": out.written("adopted_commit"),
                "adopted_payload_commit": out.written("adopted_payload_commit"),
                "derive": out.written("derive"),
                "capability_proof": proofs_kept,
            },
            "dropped_frames": {
                "merge_v10": census.merges_v10,
                "merge_v8": census.merges_v8,
                "derive_v9": census.derives_v9,
                "commit_in_retired_or_dropped_collection": retired_commits,
                "commit_in_derived_collection": derived_commits,
                "derive_v11_not_kept": census.derives_v11.saturating_sub(kept_current),
                "want": census.wants,
                "retired_want_record": census.retired_want_records,
                "pin": census.pins,
                "pin_tombstone": census.pin_tombstones,
                "legacy_v3": census.legacy_v3,
                "legacy_unsigned_equation": census.legacy_unsigned_equations,
                "retired_derive_v4": census.retired_derive_v4,
                "retired_capability_proof": census.retired_capability_proofs,
                "retired_team_record": census.retired_team_records,
                "retired_artifact_offer": census.retired_artifact_offers,
                "unknown_kind": census.opaque,
            },
            "capability_proofs": {
                "kept": proofs_kept,
                "invalid_signature": proofs_invalid,
            },
            "blobs": {
                "kept": stats.kept,
                "kept_payload_bytes": stats.kept_payload_bytes,
                "record_kind_descriptions_added": descriptions,
                "archives_walked": stats.archives_walked,
                "archive_values_probed": stats.values_probed,
                "corrupt_skipped": stats.corrupt_skipped,
                "references_not_resident": stats.references_not_resident,
                "leaf_images_walked_conservatively": stats.stride_walks,
                "kept_by_conservative_walk": stats.stride_children,
                "source_distinct": stats.source_distinct,
                "source_payload_bytes": stats.source_payload_bytes,
                "dropped": stats.dropped,
                "dropped_payload_bytes": stats.dropped_payload_bytes,
                "retention": RETENTION_DESCRIPTION,
            },
            "destination_bytes_projected": retainer.projected_bytes,
            "signers": signers.keys.iter().map(hex).collect::<Vec<_>>(),
        })
    }
}

/// Re-read the written pile: every record verifies strictly, and every blob
/// a record or proof names directly is resident unless the source lacked it.
fn audit_destination(path: &Path) -> Result<(Value, BTreeSet<Raw>)> {
    let mut pile = PileFile::open_read_only(path)
        .map_err(|error| super::super::pile_read_error(path, error))?;
    let result = (|| {
        let snapshot = pile
            .snapshot()
            .map_err(|error| super::super::pile_read_error(path, error))?;
        let (mut records, mut invalid) = (0u64, 0u64);
        let mut unresolved: BTreeSet<Raw> = BTreeSet::new();
        let resident =
            |handle: Inline<Handle<UnknownBlob>>| snapshot.contains_blob(handle).unwrap_or(false);
        let all = snapshot
            .records()
            .map_err(|error| anyhow!("read records: {error}"))?;
        let checked = Checked::new(all, |record: &Result<CollectionRecord, ReadError>| {
            record
                .as_ref()
                .is_ok_and(|record| record.verify_strict().is_ok())
        });
        for (record, verified) in checked {
            let record = record.map_err(|error| anyhow!("read record: {error}"))?;
            records += 1;
            if !verified {
                invalid += 1;
            }
            unresolved.extend(
                record
                    .blob_references()
                    .filter(|handle| !resident(*handle))
                    .map(|handle| handle.raw),
            );
        }
        let mut proofs = 0u64;
        for proof in snapshot
            .proofs()
            .map_err(|error| anyhow!("read proofs: {error}"))?
        {
            let proof = proof.map_err(|error| anyhow!("read proof: {error}"))?;
            proofs += 1;
            unresolved.extend(
                proof
                    .blob_references()
                    .filter(|handle| !resident(*handle))
                    .map(|handle| handle.raw),
            );
        }
        if invalid > 0 {
            bail!("{invalid} written record(s) fail strict verification");
        }
        Ok((
            json!({
                "records": records,
                "proofs": proofs,
                "unresolved_references": unresolved.len(),
            }),
            unresolved,
        ))
    })();
    let closed = pile
        .close()
        .map_err(|error| anyhow!("close destination: {error}"));
    let audit = result?;
    closed?;
    Ok(audit)
}

/// The first 16 hex characters of a handle, for a one-line summary.
fn short(handle: &Value) -> &str {
    handle
        .as_str()
        .and_then(|handle| handle.get(..16))
        .unwrap_or("")
}

fn print_summary(report: &Value) {
    let get = |path: &[&str]| -> Value {
        let mut value = report;
        for key in path {
            value = &value[*key];
        }
        value.clone()
    };
    println!(
        "Clean pile {} -> {}{}",
        get(&["source"]).as_str().unwrap_or(""),
        get(&["destination"]).as_str().unwrap_or(""),
        if get(&["dry_run"]).as_bool() == Some(true) {
            " (dry run: nothing written)"
        } else {
            ""
        }
    );
    println!(
        "  bytes: {} -> {} (projected {})",
        get(&["source_bytes"]),
        get(&["destination_bytes"]),
        get(&["destination_bytes_projected"])
    );
    println!(
        "  written: {} commit(s), {} adopted commit(s), {} leaf DERIVE(s), {} proof(s), {} blob(s) \
         and {} record-kind description blob(s)",
        get(&["records_written", "commit"]),
        get(&["records_written", "adopted_commit"]),
        get(&["records_written", "derive"]),
        get(&["records_written", "capability_proof"]),
        get(&["blobs", "kept"]),
        get(&["blobs", "record_kind_descriptions_added"]),
    );
    println!(
        "  rescued: {} of {} listed payload(s) adopted ({} already present); guard: {} retired \
         root(s) discarded, {} holding payloads found nowhere else",
        get(&["payload_adoption", "adopted"]),
        get(&["payload_adoption", "listed"]),
        get(&["payload_adoption", "already_present"]),
        get(&["unkept_guard", "discarded_roots"]),
        get(&["unkept_guard", "would_refuse"])
            .as_array()
            .map_or(0, Vec::len),
    );
    println!(
        "  dropped: {} MERGE v10, {} MERGE v8, {} DERIVE v9 frame(s), {} WANT(s), {} pin record(s), \
         {} of {} distinct source blob(s) ({} payload bytes)",
        get(&["dropped_frames", "merge_v10"]),
        get(&["dropped_frames", "merge_v8"]),
        get(&["dropped_frames", "derive_v9"]),
        get(&["dropped_frames", "want"]),
        get(&["dropped_frames", "pin"]),
        get(&["blobs", "dropped"]),
        get(&["blobs", "source_distinct"]),
        get(&["blobs", "dropped_payload_bytes"]),
    );
    for root in get(&["roots"]).as_array().into_iter().flatten() {
        println!(
            "  root {} {}: kept {} commit(s) of {} payload(s), adopted {}, dropped {} \
             duplicate-owner, {} invalid, {} unadmitted",
            short(&root["handle"]),
            root["name"],
            root["kept_commits"],
            root["kept_payloads"],
            root["adopted_payloads"],
            root["dropped"]["duplicate_owner"],
            root["dropped"]["invalid_signature"],
            root["dropped"]["unadmitted"],
        );
    }
    for retired in get(&["retired"]).as_array().into_iter().flatten() {
        println!(
            "  retired {} {}: {} record(s), adopted {} payload(s){}",
            short(&retired["handle"]),
            retired["name"],
            retired["records"],
            retired["adopted_payloads"],
            if retired["adopted_into"].is_null() {
                " (unmapped)"
            } else {
                ""
            }
        );
    }
    for derived in get(&["derived"]).as_array().into_iter().flatten() {
        println!(
            "  derived {} (depth {}): {} of {} source foundation(s) have a leaf; needs \
             re-derive: {}",
            short(&derived["handle"]),
            derived["depth"],
            derived["foundations_with_leaf"],
            derived["source_foundations"],
            derived["needs_rederive_by_owner"],
        );
    }
    println!(
        "  elapsed: {:.1}s; source lock: {}",
        get(&["elapsed_seconds"]).as_f64().unwrap_or(0.0),
        "shared, during replay only"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_children_accepts_only_canonical_archives() {
        let row = |entity: u8, attribute: u8, value: u8| {
            let mut row = [0u8; 64];
            row[..16].fill(entity);
            row[16..32].fill(attribute);
            row[32..].fill(value);
            row
        };
        let everything = |_: &Raw| true;
        let archive: Vec<u8> = [row(1, 1, 9), row(1, 2, 9), row(2, 1, 7)].concat();
        assert_eq!(
            archive_children(&archive, everything),
            Some(vec![[7; 32], [9; 32]])
        );
        let mut probed = Vec::new();
        let children = archive_children(&archive, |value| {
            probed.push(*value);
            value == &[9; 32]
        });
        assert_eq!(children, Some(vec![[9; 32]]));
        assert_eq!(
            probed,
            vec![[9; 32], [7; 32]],
            "a value already accepted is not probed again"
        );

        let unordered: Vec<u8> = [row(2, 1, 7), row(1, 1, 9)].concat();
        assert_eq!(archive_children(&unordered, everything), None);
        let repeated: Vec<u8> = [row(1, 1, 9), row(1, 1, 9)].concat();
        assert_eq!(archive_children(&repeated, everything), None);
        let nil_entity: Vec<u8> = [row(0, 1, 9)].concat();
        assert_eq!(archive_children(&nil_entity, everything), None);
        assert_eq!(archive_children(b"not an archive", everything), None);
        assert_eq!(archive_children(&[], everything), None);
    }

    #[test]
    fn plan_files_parse_comments_and_prefixes() {
        let root = [0xAB; 32];
        let text = format!("# roots\n\nblake3:{}  wiki\n{}\n", hex(&root), hex(&root));
        assert_eq!(parse_roots(&text).unwrap(), vec![root]);
        let pairs =
            parse_adoptions(&format!("{} {} # old wiki\n", hex(&[1; 32]), hex(&root))).unwrap();
        assert_eq!(pairs, vec![([1; 32], root)]);
        assert!(parse_adoptions(&hex(&root)).is_err());
        assert!(parse_roots("# nothing\n").is_err());
        // Payload adoptions: pairs, repeats collapsed. Discards: the first
        // word of each line, the rest of the line is the reason.
        let payloads = parse_payload_adoptions(&format!(
            "{p} blake3:{r}\n{p} {r} # again\n",
            p = hex(&[2; 32]),
            r = hex(&root)
        ))
        .unwrap();
        assert_eq!(payloads, vec![([2; 32], root)]);
        assert!(parse_payload_adoptions(&hex(&[2; 32])).is_err());
        let discard =
            parse_discard(&format!("blake3:{} # secrets v1, superseded\n", hex(&[3; 32])))
                .unwrap();
        assert_eq!(discard, BTreeSet::from([[3; 32]]));
        assert!(parse_discard("# none\n").unwrap().is_empty());
    }

    #[test]
    fn checked_answers_every_item_in_order_across_batches() {
        let items: Vec<u32> = (0..(2 * CHECK_BATCH as u32 + 7)).collect();
        let checked: Vec<(u32, bool)> =
            Checked::new(items.clone().into_iter(), |item: &u32| item % 3 == 0).collect();
        assert_eq!(checked.len(), items.len());
        for (index, (item, answer)) in checked.into_iter().enumerate() {
            assert_eq!(item, index as u32);
            assert_eq!(answer, item % 3 == 0);
        }
    }

    #[test]
    fn census_walks_exactly_the_replayed_prefix() {
        use triblespace_core::repo::pile::PileRecords;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.pile");
        let other = dir.path().join("other.pile");
        for (file, payloads) in [(&path, vec!["first"]), (&other, vec!["first", "second"])] {
            std::fs::File::create(file).unwrap();
            let mut pile = PileFile::open(file).unwrap();
            for payload in payloads {
                pile.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(anybytes::Bytes::from_source(
                    payload.as_bytes().to_vec(),
                )))
                .unwrap();
            }
            pile.close().unwrap();
        }
        let plan = Plan {
            roots: Vec::new(),
            root_names: Vec::new(),
            root_index: HashMap::new(),
            derived: Vec::new(),
            derived_index: HashMap::new(),
            retired: BTreeMap::new(),
            dropped: BTreeMap::new(),
            adopted_payloads: Vec::new(),
            adopt_payload_set: HashSet::new(),
            discard: BTreeSet::new(),
            unused_discards: Vec::new(),
        };
        let census = |snapshot: &PileFileSnapshot| {
            let pass = raw_pass(snapshot, &plan, &mut Signers::default()).unwrap();
            (pass.census.frames, pass.census.blob_frames)
        };

        let mut source = PileFile::open_read_only(&path).unwrap();
        let snapshot = source.snapshot().unwrap();
        let replayed = census(&snapshot);
        assert_eq!(replayed.1, 1);

        // A peer's append still in flight at the replayed boundary: the
        // file now ends in a torn frame, which a walk of the path meets.
        let torn = &std::fs::read(&other).unwrap()[..300];
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, torn).unwrap();
        drop(file);
        assert!(
            PileRecords::open(&path)
                .unwrap()
                .any(|record| record.is_err()),
            "the file's tail is torn"
        );
        assert_eq!(
            census(&snapshot),
            replayed,
            "the torn tail is never decoded"
        );

        // Re-pointing the path at another pile changes nothing either.
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(
            census(&snapshot),
            replayed,
            "the census reads the replayed file"
        );
        drop(snapshot);
        source.close().unwrap();
    }

    #[test]
    fn report_path_must_be_a_separate_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pile");
        std::fs::write(&source, b"").unwrap();
        let into = dir.path().join("clean.pile");
        let report = dir.path().join("report.json");
        assert!(check_report_path(&report, &source, &into).is_ok());
        for named in [
            source.clone(),
            into.clone(),
            partial_path(&into),
            dir.path().join(".").join("clean.pile"),
        ] {
            let error = check_report_path(&named, &source, &into).unwrap_err();
            assert!(error.to_string().contains("names"), "{error}");
        }
        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&source, &link).unwrap();
            let error = check_report_path(&link, &source, &into).unwrap_err();
            assert!(error.to_string().contains("already exists"), "{error}");
        }
    }

    #[test]
    fn frame_lengths_follow_the_block_layout() {
        assert_eq!(blob_frame_len(0), 256);
        assert_eq!(blob_frame_len(1), 512);
        assert_eq!(blob_frame_len(256), 512);
        assert_eq!(proof_frame_len(224), 256);
        assert_eq!(proof_frame_len(225), 512);
    }
}
