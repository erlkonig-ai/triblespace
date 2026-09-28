//! `trible pile migrate SRC lattice-v3 --into DST`: the lattice v3 cutover
//! filter.
//!
//! A stop-the-world compaction writing a fresh copy of a pile that keeps
//! what lattice v3 replicates and folds and leaves behind what each host now
//! computes for itself:
//!
//! - every COMMIT of every generation, retired generations included, is kept;
//! - capability proofs, WANTs, legacy pins and frames of unknown kind travel
//!   exactly as `pile compact` carries them;
//! - every MERGE of every encoding and every signer (current v10, retired v8,
//!   retired v2 and v6, legacy unsigned, legacy V3) is left behind: a host
//!   folds only merges its own key signed, and rebuilds them;
//! - a DERIVE of any encoding is left behind when its target's resident
//!   descriptor names only mapping algorithms that become attached or are
//!   deleted ([`v3_mappings`](super::super::collection::v3_mappings)), and is
//!   kept when the mapping stays derived, when an algorithm is unrecognised,
//!   and when the descriptor is not resident or does not decode;
//! - a blob is kept only when the carried state reaches it: the conservative
//!   walk (every aligned 32-byte word naming a resident blob is a child) from
//!   what every kept record names (commit data and metadata, DERIVE outputs,
//!   descriptors), from proofs, WANTs and pins, from the aligned words of kept
//!   frames of unknown kind, and from the record-kind descriptions this binary
//!   writes. Merge results and the images of dropped DERIVEs no kept record
//!   reaches are left behind. Archive the source before replacing it.
//!
//! The source is read through a read-only descriptor, and the command refuses
//! a source another process holds open: this rewrites a frozen copy, never a
//! live pile. `--dry-run` runs the rewrite's own selection pass and retention
//! walk without writing, so it prints exactly the counts the real run prints.
//! Both then read the result through the lattice v3 fold opened without a
//! host key, which believes no merge: the frontier of every kept collection
//! is then its believed foundations, and each foundation's payload must be
//! resident. The dry run reads the source that way, the real run the
//! destination; the answers agree because every foundation of a kept
//! collection is a kept record, and a kept record's payload is kept whenever
//! it is resident.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::collection::records::{
    collection_mapping, collection_name, mapping_algorithm, CollectionHandle,
    KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::{find, pattern};
use triblespace_core::metadata;
use triblespace_core::repo::pile::{
    CollectionFrame, CollectionFrameFilter, CollectionFrameGeneration, CollectionFrameRole, Pile,
    PileFile, PileFileSnapshot, WantRewritePolicy,
};
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, RetentionRoots, SnapshotSource};
use triblespace_core::trible::TribleSet;

use super::super::collection::v3_mappings::{v3_mapping, V3Fate, V3_MAPPINGS};
use super::super::compact::{cleanup_incomplete_destination, create_fresh_destination};

/// Rewrite a pile copy for lattice v3 (see the module docs).
#[derive(clap::Args, Debug)]
pub struct LatticeV3Args {
    /// Fresh destination pile, mode 0600 until written. Must not exist.
    #[arg(long = "into", required_unless_present = "dry_run")]
    pub into: Option<PathBuf>,
    /// Decide and count every frame, and check readability against the
    /// source, without writing anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Accept believed foundations whose payload is not resident. Without
    /// it such a result is refused (a real run removes its destination).
    /// The filter never creates one: it keeps every resident payload a kept
    /// record names.
    #[arg(long)]
    pub allow_absent: bool,
    /// A mapping-algorithm id (32 hex characters) this binary does not know
    /// that becomes attached: DERIVEs into collections naming only attached
    /// or deleted algorithms are left behind. Repeat for several.
    #[arg(long = "attached-mapping", value_name = "ID")]
    pub attached_mappings: Vec<String>,
}

/// What a collection's resident descriptor says, as far as the filter cares.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Class {
    /// No descriptor blob is resident.
    Missing,
    /// The descriptor blob does not decode as a SimpleArchive.
    Undecodable,
    /// A descriptor naming no mapping algorithm, with the names it carries.
    Unmapped { names: BTreeSet<String> },
    /// A descriptor naming these mapping algorithms.
    Mapped { algorithms: BTreeSet<Id> },
}

fn classify(reader: &PileFileSnapshot, collection: [u8; 32]) -> Class {
    let handle: Inline<Handle<SimpleArchive>> = Inline::new(collection);
    if !reader.contains_blob(handle).unwrap_or(false) {
        return Class::Missing;
    }
    let Ok(facts) = reader.get::<TribleSet, SimpleArchive>(handle) else {
        return Class::Undecodable;
    };
    let algorithms: BTreeSet<Id> = find!(
        algorithm: Id,
        pattern!(&facts, [
            { _?descriptor @
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_mapping: _?mapping,
            },
            { _?mapping @
                metadata::tag: KIND_COLLECTION_MAPPING,
                mapping_algorithm: ?algorithm,
            },
        ])
    )
    .collect();
    if !algorithms.is_empty() {
        return Class::Mapped { algorithms };
    }
    let names = find!(
        name: Inline<Handle<UTF8String>>,
        pattern!(&facts, [{ _?descriptor @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_name: ?name,
        }])
    )
    .filter_map(|name| reader.get::<Blob<UTF8String>, UTF8String>(name).ok())
    .filter_map(|name| std::str::from_utf8(&name.bytes).ok().map(str::to_owned))
    .collect();
    Class::Unmapped { names }
}

/// The fate of one algorithm: the table's, else `--attached-mapping`.
fn fate(id: Id, attached: &BTreeSet<Id>) -> Option<V3Fate> {
    v3_mapping(id)
        .map(|mapping| mapping.fate)
        .or_else(|| attached.contains(&id).then_some(V3Fate::Attached))
}

impl Class {
    /// Whether DERIVEs into this collection are left behind: only when the
    /// descriptor names mapping algorithms and every one is attached or
    /// deleted.
    fn leaves_derives_behind(&self, attached: &BTreeSet<Id>) -> bool {
        match self {
            Class::Mapped { algorithms } => algorithms
                .iter()
                .all(|id| fate(*id, attached).is_some_and(V3Fate::leaves_derives_behind)),
            Class::Missing | Class::Undecodable | Class::Unmapped { .. } => false,
        }
    }

    fn label(&self, attached: &BTreeSet<Id>) -> String {
        match self {
            Class::Missing => "(no resident descriptor)".to_owned(),
            Class::Undecodable => "(undecodable descriptor)".to_owned(),
            Class::Unmapped { names } if names.is_empty() => "(no mapping)".to_owned(),
            Class::Unmapped { names } => format!(
                "root {}",
                names
                    .iter()
                    .map(|name| format!("{name:?}"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            Class::Mapped { algorithms } => algorithms
                .iter()
                .map(|id| match v3_mapping(*id) {
                    Some(mapping) => {
                        format!("{id:X} {} [{}]", mapping.name, mapping.fate.label())
                    }
                    None if attached.contains(id) => {
                        format!("{id:X} [attached: --attached-mapping]")
                    }
                    None => format!("{id:X} [unrecognised]"),
                })
                .collect::<Vec<_>>()
                .join(" + "),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Tally {
    carried: usize,
    left: usize,
}

impl Tally {
    fn add(&mut self, carried: bool) {
        if carried {
            self.carried += 1;
        } else {
            self.left += 1;
        }
    }
}

/// The tallies of the filter's answers, and the classes it read: owned, so
/// they outlive the source snapshot the filter reads descriptors from.
#[derive(Debug, Default)]
struct Census {
    attached: BTreeSet<Id>,
    classes: BTreeMap<[u8; 32], Class>,
    by_kind: BTreeMap<(CollectionFrameGeneration, CollectionFrameRole), Tally>,
    by_collection: BTreeMap<Option<[u8; 32]>, BTreeMap<CollectionFrameRole, Tally>>,
}

/// The filter the rewrite asks about every collection-algebra frame.
struct V3Filter<'a> {
    reader: &'a PileFileSnapshot,
    census: Census,
}

impl<'a> V3Filter<'a> {
    fn new(reader: &'a PileFileSnapshot, attached: &BTreeSet<Id>) -> Self {
        Self {
            reader,
            census: Census {
                attached: attached.clone(),
                ..Census::default()
            },
        }
    }

    fn class(&mut self, collection: [u8; 32]) -> &Class {
        let reader = self.reader;
        self.census
            .classes
            .entry(collection)
            .or_insert_with(|| classify(reader, collection))
    }
}

impl CollectionFrameFilter for V3Filter<'_> {
    fn carries(&mut self, frame: &CollectionFrame) -> bool {
        let collection = frame.collection.map(|handle| handle.raw);
        if let Some(collection) = collection {
            self.class(collection);
        }
        let census = &mut self.census;
        let carried = match (frame.role, collection) {
            (CollectionFrameRole::Merge, _) => false,
            (CollectionFrameRole::Derive, Some(collection)) => {
                !census.classes[&collection].leaves_derives_behind(&census.attached)
            }
            (CollectionFrameRole::Derive, None)
            | (CollectionFrameRole::Commit, _)
            | (CollectionFrameRole::Definition, _) => true,
        };
        census
            .by_kind
            .entry((frame.generation, frame.role))
            .or_default()
            .add(carried);
        census
            .by_collection
            .entry(collection)
            .or_default()
            .entry(frame.role)
            .or_default()
            .add(carried);
        carried
    }
}

fn role_label(role: CollectionFrameRole) -> &'static str {
    match role {
        CollectionFrameRole::Commit => "COMMIT",
        CollectionFrameRole::Merge => "MERGE",
        CollectionFrameRole::Derive => "DERIVE",
        CollectionFrameRole::Definition => "DEFINITION",
    }
}

fn generation_label(generation: CollectionFrameGeneration) -> &'static str {
    match generation {
        CollectionFrameGeneration::Current => "current",
        CollectionFrameGeneration::RetiredV8V9 => "retired v8/v9",
        CollectionFrameGeneration::RetiredOpaque => "retired v2/v6/v7",
        CollectionFrameGeneration::LegacyUnsigned => "legacy unsigned",
        CollectionFrameGeneration::LegacyV3 => "legacy V3",
    }
}

/// What the rewrite's own accounting says, identical for the plan and the
/// real run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameAccounting {
    filtered: usize,
    superseded: usize,
    drained: usize,
    opaque_carried: usize,
    retired_carried: usize,
}

/// Resident blobs in the source, and the ones the rewrite keeps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobAccounting {
    resident: usize,
    resident_bytes: u64,
    kept: usize,
    kept_bytes: u64,
}

fn blob_totals(reader: &impl BlobStoreList) -> Result<(usize, u64)> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for info in reader.blobs() {
        let info = info.map_err(|error| anyhow!("list blobs: {error:?}"))?;
        count += 1;
        bytes += info.length;
    }
    Ok((count, bytes))
}

/// Per kept collection with a believed foundation: the number of believed
/// foundations and the ones whose payload is not resident.
type Readability = BTreeMap<[u8; 32], (usize, Vec<[u8; 32]>)>;

/// Read `collections` through the fold of a store opened without a host
/// key, which believes no merge, so each frontier is exactly the believed
/// foundations; name every foundation whose payload is not resident.
fn readability(pile: &mut Pile, collections: &BTreeSet<[u8; 32]>) -> Result<Readability> {
    let snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("snapshot for the readability check: {error:?}"))?;
    let coverage = snapshot.coverage();
    let mut report = Readability::new();
    for collection in collections {
        let (support, _) = coverage.frontier_support(CollectionHandle::new(*collection));
        let mut foundations = 0usize;
        let mut absent = Vec::new();
        for member in support.iter_ordered() {
            foundations += 1;
            let handle: Inline<Handle<UnknownBlob>> = Inline::new(*member);
            if !snapshot
                .contains_blob(handle)
                .map_err(|error| anyhow!("residency lookup: {error:?}"))?
            {
                absent.push(*member);
            }
        }
        if foundations > 0 {
            report.insert(*collection, (foundations, absent));
        }
    }
    Ok(report)
}

impl Census {
    /// Collections the readability check reads: every collection a carried
    /// frame names, except those whose DERIVEs are left behind. Those keep
    /// only COMMITs, which attest nothing in a derived collection.
    fn kept_collections(&self) -> BTreeSet<[u8; 32]> {
        self.by_collection
            .iter()
            .filter_map(|(collection, roles)| {
                let collection = (*collection)?;
                let carried = roles.values().any(|tally| tally.carried > 0);
                let leaves = self
                    .classes
                    .get(&collection)
                    .is_some_and(|class| class.leaves_derives_behind(&self.attached));
                (carried && !leaves).then_some(collection)
            })
            .collect()
    }

    /// The report both modes print, in full.
    fn report(
        &self,
        accounting: FrameAccounting,
        blobs: BlobAccounting,
        readability: &Readability,
    ) -> String {
        let mut out = String::new();
        let attached = &self.attached;
        let _ = writeln!(out, "mapping classification:");
        for mapping in V3_MAPPINGS {
            let _ = writeln!(
                out,
                "  {:X} {}: {}, from {}",
                mapping.id,
                mapping.name,
                mapping.fate.label(),
                mapping.source
            );
        }
        for id in attached {
            let _ = writeln!(out, "  {id:X}: attached, from --attached-mapping");
        }
        let _ = writeln!(out, "frames (carried / left behind):");
        for ((generation, role), tally) in &self.by_kind {
            let _ = writeln!(
                out,
                "  {} ({}): {} / {}",
                role_label(*role),
                generation_label(*generation),
                tally.carried,
                tally.left
            );
        }
        let _ = writeln!(
            out,
            "rewrite: {} left behind by the filter, {} superseded, {} drained; carried {} frames of unknown kind and {} retired v8/v9 equations",
            accounting.filtered,
            accounting.superseded,
            accounting.drained,
            accounting.opaque_carried,
            accounting.retired_carried,
        );
        let _ = writeln!(
            out,
            "blobs: {} resident ({} bytes), {} kept ({} bytes), {} left behind ({} bytes)",
            blobs.resident,
            blobs.resident_bytes,
            blobs.kept,
            blobs.kept_bytes,
            blobs.resident - blobs.kept,
            blobs.resident_bytes - blobs.kept_bytes,
        );

        let mut by_mapping: BTreeMap<String, (Tally, usize)> = BTreeMap::new();
        for (collection, roles) in &self.by_collection {
            let Some(derive) = roles.get(&CollectionFrameRole::Derive) else {
                continue;
            };
            let label = match collection {
                Some(collection) => self
                    .classes
                    .get(collection)
                    .map(|class| class.label(attached))
                    .unwrap_or_default(),
                None => "(legacy V3 definition ids)".to_owned(),
            };
            let entry = by_mapping.entry(label).or_default();
            entry.0.carried += derive.carried;
            entry.0.left += derive.left;
            entry.1 += 1;
        }
        let _ = writeln!(
            out,
            "DERIVE frames by mapping (carried / left behind, collections):"
        );
        for (label, (tally, collections)) in &by_mapping {
            let _ = writeln!(
                out,
                "  {label}: {} / {} in {collections}",
                tally.carried, tally.left
            );
        }

        let _ = writeln!(out, "frames by collection (carried / left behind):");
        for (collection, roles) in &self.by_collection {
            let (name, label) = match collection {
                Some(collection) => (
                    format!("blake3:{}", hex::encode_upper(collection)),
                    self.classes
                        .get(collection)
                        .map(|class| class.label(attached))
                        .unwrap_or_default(),
                ),
                None => (
                    "(legacy V3)".to_owned(),
                    "(16-byte definition ids)".to_owned(),
                ),
            };
            let counts = roles
                .iter()
                .map(|(role, tally)| {
                    format!("{} {} / {}", role_label(*role), tally.carried, tally.left)
                })
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "  {name} {label}: {counts}");
        }

        let foundations: usize = readability.values().map(|(count, _)| count).sum();
        let absent: usize = readability.values().map(|(_, absent)| absent.len()).sum();
        let _ = writeln!(
            out,
            "readability (keyless fold): {} kept collections with believed foundations, {foundations} foundations, {absent} not resident",
            readability.len(),
        );
        for (collection, (count, missing)) in readability {
            if missing.is_empty() {
                continue;
            }
            let label = self
                .classes
                .get(collection)
                .map(|class| class.label(attached))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  blake3:{} {label}: {} of {count} not resident",
                hex::encode_upper(collection),
                missing.len(),
            );
            for handle in missing {
                let _ = writeln!(out, "    absent blake3:{}", hex::encode_upper(handle));
            }
        }
        out
    }
}

/// Processes other than this one holding `path` open, by pid.
///
/// Every `/proc/<pid>/fd` entry this user may read is compared with the
/// file's device and inode. A process whose descriptor table this user
/// cannot read (another user's, without privilege) is not seen.
#[cfg(target_os = "linux")]
fn other_openers(path: &Path) -> Result<Vec<u32>> {
    use std::os::unix::fs::MetadataExt as _;

    let target = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let own = std::process::id();
    let mut openers = Vec::new();
    let processes = std::fs::read_dir("/proc")
        .context("list /proc to find processes holding the source open")?;
    for process in processes.flatten() {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own {
            continue;
        }
        let Ok(descriptors) = std::fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            let Ok(metadata) = std::fs::metadata(descriptor.path()) else {
                continue;
            };
            if metadata.dev() == target.dev() && metadata.ino() == target.ino() {
                openers.push(pid);
                break;
            }
        }
    }
    Ok(openers)
}

#[cfg(not(target_os = "linux"))]
fn other_openers(path: &Path) -> Result<Vec<u32>> {
    bail!(
        "cannot tell on this system whether another process holds {} open; the lattice v3 filter \
         only runs where it can check (Linux /proc)",
        path.display()
    )
}

fn parse_attached(ids: &[String]) -> Result<BTreeSet<Id>> {
    let mut attached = BTreeSet::new();
    for text in ids {
        let id = Id::from_hex(text.trim()).ok_or_else(|| {
            anyhow!("--attached-mapping takes a 32-hex-digit non-nil id: {text:?}")
        })?;
        if let Some(mapping) = v3_mapping(id) {
            bail!(
                "--attached-mapping {id:X} is {} already, classified {}",
                mapping.name,
                mapping.fate.label()
            );
        }
        attached.insert(id);
    }
    Ok(attached)
}

fn refuse_if_open(path: &Path) -> Result<()> {
    let openers = other_openers(path)?;
    if !openers.is_empty() {
        bail!(
            "{} is open in {} other process(es) (pid {}); the lattice v3 filter rewrites a frozen \
             copy, never a live pile. Stop them or copy the pile first",
            path.display(),
            openers.len(),
            openers
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn open_source(path: &Path) -> Result<PileFile> {
    let mut source = PileFile::open_read_only(path)
        .map_err(|error| anyhow!("open source {}: {error:?}", path.display()))?;
    if let Err(error) = source.refresh() {
        let _ = source.close();
        return Err(super::super::pile_read_error(path, error));
    }
    Ok(source)
}

fn refuse_absent(readability: &Readability, allow_absent: bool) -> Result<()> {
    let absent: usize = readability.values().map(|(_, absent)| absent.len()).sum();
    if absent > 0 && !allow_absent {
        bail!(
            "{absent} believed foundation(s) of kept collections are not resident (listed \
             above). They are not resident in the source either: the filter keeps every \
             resident payload a kept record names. Pass --allow-absent to accept them"
        );
    }
    Ok(())
}

pub fn run(source_path: PathBuf, args: LatticeV3Args) -> Result<()> {
    let attached = parse_attached(&args.attached_mappings)?;
    if !source_path.is_file() {
        bail!("source {} is not a pile file", source_path.display());
    }
    if let Some(into) = &args.into {
        if into.exists() {
            bail!(
                "destination {} already exists; the filter writes a fresh pile",
                into.display()
            );
        }
    }
    refuse_if_open(&source_path)?;
    let stable_len = std::fs::metadata(&source_path)
        .with_context(|| format!("stat {}", source_path.display()))?
        .len();

    if args.dry_run {
        return dry_run(&source_path, &attached, args.allow_absent, stable_len);
    }
    let destination_path = args
        .into
        .ok_or_else(|| anyhow!("--into is required without --dry-run"))?;
    filter_into(
        &source_path,
        &destination_path,
        &attached,
        args.allow_absent,
        stable_len,
    )
}

fn check_source_len(path: &Path, stable_len: u64) -> Result<()> {
    let now = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if now != stable_len {
        bail!(
            "source {} changed while it was read ({stable_len} -> {now} bytes); the filter needs \
             a quiesced copy",
            path.display()
        );
    }
    Ok(())
}

fn dry_run(
    source_path: &Path,
    attached: &BTreeSet<Id>,
    allow_absent: bool,
    stable_len: u64,
) -> Result<()> {
    let mut source = open_source(source_path)?;
    let planned = (|| -> Result<(String, Readability)> {
        let reader = source
            .snapshot()
            .map_err(|error| anyhow!("snapshot source: {error:?}"))?;
        let (resident, resident_bytes) = blob_totals(&reader)?;
        let mut filter = V3Filter::new(&reader, attached);
        let plan = source
            .plan_retained_rewrite(
                &RetentionRoots::new(),
                WantRewritePolicy::Preserve,
                &[],
                &mut filter,
            )
            .map_err(|error| anyhow!("plan the lattice v3 filter: {error}"))?;
        let blobs = BlobAccounting {
            resident,
            resident_bytes,
            kept: plan.retained_blobs,
            kept_bytes: plan.retained_bytes,
        };
        check_source_len(source_path, stable_len)?;
        let accounting = FrameAccounting {
            filtered: plan.filtered_frames,
            superseded: plan.superseded_equations,
            drained: plan.drained_frames,
            opaque_carried: plan.opaque_frames,
            retired_carried: plan.retired_equations,
        };
        let mut keyless = Pile::new(
            PileFile::open_read_only(source_path)
                .map_err(|error| anyhow!("reopen source: {error:?}"))?,
        );
        let read = readability(&mut keyless, &filter.census.kept_collections());
        keyless
            .close()
            .map_err(|error| anyhow!("close source: {error:?}"))?;
        let read = read?;
        Ok((filter.census.report(accounting, blobs, &read), read))
    })();
    let closed = source
        .close()
        .map_err(|error| anyhow!("close source: {error:?}"));
    let (report, read) = planned?;
    closed?;
    println!(
        "lattice-v3 dry run of {} (nothing written)",
        source_path.display()
    );
    print!("{report}");
    refuse_absent(&read, allow_absent)
}

fn filter_into(
    source_path: &Path,
    destination_path: &Path,
    attached: &BTreeSet<Id>,
    allow_absent: bool,
    stable_len: u64,
) -> Result<()> {
    let mut source = open_source(source_path)?;
    let source_permissions = match std::fs::metadata(source_path) {
        Ok(metadata) => metadata.permissions(),
        Err(error) => {
            let _ = source.close();
            return Err(anyhow!(error).context("stat source"));
        }
    };
    if let Some(parent) = destination_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if let Err(error) = std::fs::create_dir_all(parent) {
            let _ = source.close();
            return Err(anyhow!(error)
                .context(format!("create destination directory {}", parent.display())));
        }
    }
    let destination_file = match create_fresh_destination(destination_path) {
        Ok(file) => file,
        Err(error) => {
            let _ = source.close();
            return Err(anyhow!(error).context(format!(
                "create fresh destination {}",
                destination_path.display()
            )));
        }
    };
    let mut destination = match PileFile::open(destination_path) {
        Ok(pile) => pile,
        Err(error) => {
            drop(destination_file);
            let _ = source.close();
            return Err(cleanup_incomplete_destination(
                destination_path,
                anyhow!("open destination {}: {error:?}", destination_path.display()),
            ));
        }
    };

    let operation = (|| -> Result<(Census, FrameAccounting, (usize, u64), usize)> {
        let reader = source
            .snapshot()
            .map_err(|error| anyhow!("snapshot source: {error:?}"))?;
        let resident = blob_totals(&reader)?;
        let mut filter = V3Filter::new(&reader, attached);
        // No explicit roots: a blob travels only when the carried state
        // reaches it.
        let stats = source
            .rewrite_retained_into_filtered(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Preserve,
                &[],
                &mut filter,
            )
            .map_err(|error| anyhow!("lattice v3 filter: {error}"))?;
        check_source_len(source_path, stable_len)?;
        let accounting = FrameAccounting {
            filtered: stats.filtered_frames,
            superseded: stats.superseded_equations,
            drained: stats.drained_frames,
            opaque_carried: stats.opaque_frames,
            retired_carried: stats.retired_equations,
        };
        Ok((filter.census, accounting, resident, stats.retained_blobs))
    })();
    let destination_close = destination
        .close()
        .map_err(|error| anyhow!("close destination: {error:?}"));
    let source_close = source
        .close()
        .map_err(|error| anyhow!("close source: {error:?}"));
    let (census, accounting, (resident, resident_bytes), retained) =
        match (operation, destination_close, source_close) {
            (Ok(result), Ok(()), Ok(())) => result,
            (Err(error), _, _) | (Ok(_), Err(error), _) | (Ok(_), Ok(()), Err(error)) => {
                drop(destination_file);
                return Err(cleanup_incomplete_destination(destination_path, error));
            }
        };

    // Read the written pile back: it holds exactly the blobs the rewrite
    // kept, and the keyless fold of every kept collection names resident
    // payloads.
    let checked = (|| -> Result<(Readability, BlobAccounting)> {
        let mut written = Pile::new(
            PileFile::open_read_only(destination_path)
                .map_err(|error| anyhow!("reopen destination: {error:?}"))?,
        );
        let result = (|| -> Result<(Readability, BlobAccounting)> {
            let snapshot = written
                .snapshot()
                .map_err(|error| anyhow!("snapshot destination: {error:?}"))?;
            let (kept, kept_bytes) = blob_totals(&snapshot)?;
            if kept != retained {
                bail!("the destination holds {kept} blobs, the rewrite kept {retained}");
            }
            drop(snapshot);
            let blobs = BlobAccounting {
                resident,
                resident_bytes,
                kept,
                kept_bytes,
            };
            Ok((
                readability(&mut written, &census.kept_collections())?,
                blobs,
            ))
        })();
        let closed = written
            .close()
            .map_err(|error| anyhow!("close destination: {error:?}"));
        let read = result?;
        closed?;
        Ok(read)
    })();
    let (read, blobs) = match checked {
        Ok(checked) => checked,
        Err(error) => {
            drop(destination_file);
            return Err(cleanup_incomplete_destination(destination_path, error));
        }
    };
    if let Err(error) = destination_file.set_permissions(source_permissions) {
        drop(destination_file);
        return Err(cleanup_incomplete_destination(
            destination_path,
            anyhow!(error).context("copy source permissions to the destination"),
        ));
    }
    drop(destination_file);

    let destination_len = std::fs::metadata(destination_path)
        .with_context(|| format!("stat {}", destination_path.display()))?
        .len();
    println!(
        "lattice-v3 filter of {} into {}",
        source_path.display(),
        destination_path.display()
    );
    print!("{}", census.report(accounting, blobs, &read));
    println!("destination: {stable_len} -> {destination_len} bytes");
    if let Err(error) = refuse_absent(&read, allow_absent) {
        return Err(cleanup_incomplete_destination(
            destination_path,
            error.context("the destination was removed"),
        ));
    }
    Ok(())
}
