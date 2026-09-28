//! `trible pile migrate SRC lattice-v3 --into DST`: the lattice v3 cutover
//! filter.
//!
//! A stop-the-world compaction writing a fresh copy of a pile that keeps
//! what lattice v3 replicates and folds and leaves behind what each host now
//! computes for itself:
//!
//! - every COMMIT of every generation, retired generations included, is kept;
//! - capability proofs (current and retired), WANTs, legacy pins and frames
//!   of unknown kind travel exactly as `pile compact` carries them;
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
//!   descriptors), from proofs, WANTs and pins, from every 32 bytes, at any
//!   offset, of kept frames of unknown kind and retired proofs, from the
//!   record-kind descriptions this binary writes, and from every `--root`.
//!   Merge results and the images of
//!   dropped DERIVEs no kept record reaches are left behind, and so is the
//!   descriptor of a collection no kept record names (one that never held a
//!   record, say): name such handles with `--root` or `--roots-from` when
//!   something outside the pile (a sync or maintenance list, an exact-handle
//!   override) still opens them. The report lists every resident descriptor
//!   of a collection some frame names that is left behind. Archive the
//!   source before replacing it;
//! - a resident blob the walk reaches of which no occurrence matches its
//!   hash, whether a kept record, a root or another blob names it, makes
//!   both runs refuse, naming it under `corrupt blobs`; the real run writes
//!   nothing. Corruption in a frozen copy may be a copy fault the live pile
//!   does not share, so a person decides: `--allow-corrupt` sets each such
//!   blob aside instead (not copied, still named). Its damaged bytes are
//!   read for what they name, but a valid blob named only by a damaged word
//!   of it cannot be reached and is left behind. The archived source keeps
//!   the damaged bytes; a peer may hold valid ones.
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
//! it is resident and not corrupt. A corrupt payload is counted as corrupt,
//! apart from those not resident.
//!
//! A real run ends with a digest of the destination's frames that leaves out
//! blob insertion timestamps, which every rewrite stamps afresh: two runs
//! over one source write the same digest, not the same bytes.

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
    CollectionFrame, CollectionFrameFilter, CollectionFrameGeneration, CollectionFrameRole,
    CorruptBlobPolicy, GetBlobError, Pile, PileFile, PileFileSnapshot, PileRecordContent,
    PileRecords, PileRewriteError, WantRewritePolicy,
};
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, RetentionRoots, SnapshotSource};
use triblespace_core::trible::TribleSet;

use super::super::collection::parse_collection_handle;
use super::super::collection::v3_mappings::{v3_mapping, V3Fate, V3_MAPPINGS};
use super::super::compact::{cleanup_incomplete_destination, create_fresh_destination};

/// Rewrite a pile copy for lattice v3 (see the module docs).
#[derive(clap::Args, Debug)]
pub struct LatticeV3Args {
    /// A blob to keep with everything it reaches, as `blake3:HEX` or bare
    /// hex: typically a collection handle something outside the pile opens,
    /// whose descriptor no kept record may name. Repeat for several; one
    /// that is not resident in the source is reported, not refused.
    #[arg(long = "root", value_name = "HANDLE")]
    pub roots: Vec<String>,
    /// A file of handles to keep as `--root` keeps them: one per line,
    /// `blake3:HEX` or bare hex; blank lines and lines starting with `#` are
    /// skipped, and a line `NAME=HANDLE` (optionally after `export `) is read
    /// as its HANDLE, so a collection environment file serves as it is.
    /// Repeat for several files.
    #[arg(long = "roots-from", value_name = "FILE")]
    pub roots_from: Vec<PathBuf>,
    /// Fresh destination pile, mode 0600 until written. Must not exist.
    #[arg(long = "into", required_unless_present = "dry_run")]
    pub into: Option<PathBuf>,
    /// Decide and count every frame, and check readability against the
    /// source, without writing anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Accept believed foundations whose payload is not resident. Without
    /// it such a result is refused (a real run removes its destination).
    /// The filter never creates one: it keeps every valid resident payload a
    /// kept record names. A corrupt payload is `--allow-corrupt`'s question.
    #[arg(long)]
    pub allow_absent: bool,
    /// Set aside, instead of refusing, every resident blob the kept state
    /// reaches of which no occurrence matches its hash: it is not copied,
    /// and both runs name it. Its damaged bytes are read for what they name,
    /// but a valid blob named only by a damaged word of it cannot be reached
    /// and is left behind. A frozen copy's corruption may be a copy fault the
    /// live pile does not share: check the live pile or copy it again first.
    #[arg(long)]
    pub allow_corrupt: bool,
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
    /// No occurrence of the descriptor blob matches its hash.
    Corrupt,
    /// The descriptor blob does not decode as a SimpleArchive.
    Undecodable,
    /// A descriptor naming no mapping, with the names it carries.
    Unmapped { names: BTreeSet<String> },
    /// A descriptor naming mappings: the algorithms of those tagged as
    /// mappings, and how many name no algorithm that way.
    Mapped {
        algorithms: BTreeSet<Id>,
        unresolved: usize,
    },
}

fn classify(reader: &PileFileSnapshot, collection: [u8; 32]) -> Class {
    let handle: Inline<Handle<SimpleArchive>> = Inline::new(collection);
    if !reader.contains_blob(handle).unwrap_or(false) {
        return Class::Missing;
    }
    let facts = match reader.get::<TribleSet, SimpleArchive>(handle) {
        Ok(facts) => facts,
        Err(GetBlobError::ValidationError(_)) => return Class::Corrupt,
        Err(_) => return Class::Undecodable,
    };
    let mappings: BTreeSet<Id> = find!(
        mapping: Id,
        pattern!(&facts, [{ _?descriptor @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_mapping: ?mapping,
        }])
    )
    .collect();
    if !mappings.is_empty() {
        let tagged: BTreeSet<(Id, Id)> = find!(
            (mapping: Id, algorithm: Id),
            pattern!(&facts, [
                { _?descriptor @
                    metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                    collection_mapping: ?mapping,
                },
                { ?mapping @
                    metadata::tag: KIND_COLLECTION_MAPPING,
                    mapping_algorithm: ?algorithm,
                },
            ])
        )
        .collect();
        let resolved: BTreeSet<Id> = tagged.iter().map(|(mapping, _)| *mapping).collect();
        return Class::Mapped {
            algorithms: tagged.into_iter().map(|(_, algorithm)| algorithm).collect(),
            unresolved: mappings.difference(&resolved).count(),
        };
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
    /// Whether DERIVEs into this collection are left behind: only when every
    /// mapping the descriptor names is tagged with an algorithm, and every
    /// such algorithm is attached or deleted. A mapping this reader cannot
    /// resolve keeps them, as an unrecognised algorithm does.
    fn leaves_derives_behind(&self, attached: &BTreeSet<Id>) -> bool {
        match self {
            Class::Mapped {
                algorithms,
                unresolved,
            } => {
                *unresolved == 0
                    && !algorithms.is_empty()
                    && algorithms
                        .iter()
                        .all(|id| fate(*id, attached).is_some_and(V3Fate::leaves_derives_behind))
            }
            Class::Missing | Class::Corrupt | Class::Undecodable | Class::Unmapped { .. } => false,
        }
    }

    fn label(&self, attached: &BTreeSet<Id>) -> String {
        match self {
            Class::Missing => "(no resident descriptor)".to_owned(),
            Class::Corrupt => "(corrupt descriptor)".to_owned(),
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
            Class::Mapped {
                algorithms,
                unresolved,
            } => algorithms
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
                .chain((*unresolved > 0).then(|| {
                    format!("{unresolved} mapping(s) without a tagged algorithm [unrecognised]")
                }))
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
#[derive(Clone, Debug, Eq, PartialEq)]
struct FrameAccounting {
    filtered: usize,
    superseded: usize,
    drained: usize,
    repeated: usize,
    opaque_carried: usize,
    retired_carried: usize,
    proofs_carried: usize,
    retired_proofs_carried: usize,
    corrupt: BTreeSet<Inline<Handle<UnknownBlob>>>,
}

/// The handles `--root` and `--roots-from` name, split by residency in the
/// source: the resident ones are kept with what they reach.
#[derive(Clone, Debug, Default)]
struct Roots {
    resident: BTreeSet<[u8; 32]>,
    absent: BTreeSet<[u8; 32]>,
}

impl Roots {
    fn retention(&self) -> RetentionRoots {
        let mut roots = RetentionRoots::new();
        for handle in &self.resident {
            roots.retain_recursive(Inline::<Handle<UnknownBlob>>::new(*handle));
        }
        roots
    }
}

/// Read the handles `--root` and `--roots-from` name (see
/// [`LatticeV3Args::roots_from`] for the file format).
fn parse_roots(roots: &[String], files: &[PathBuf]) -> Result<BTreeSet<[u8; 32]>> {
    let mut parsed = BTreeSet::new();
    for text in roots {
        parsed.insert(parse_collection_handle(text).context("--root")?.raw);
    }
    for file in files {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("read --roots-from {}", file.display()))?;
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let value = line
                .rsplit_once('=')
                .map_or(line, |(_, value)| value)
                .trim()
                .trim_matches(|quote| quote == '"' || quote == '\'');
            let handle = parse_collection_handle(value)
                .with_context(|| format!("{}:{}", file.display(), number + 1))?;
            parsed.insert(handle.raw);
        }
    }
    Ok(parsed)
}

/// Split the named roots by residency in `reader`.
fn resolve_roots(reader: &PileFileSnapshot, named: &BTreeSet<[u8; 32]>) -> Result<Roots> {
    let mut roots = Roots::default();
    for handle in named {
        let resident = reader
            .contains_blob(Inline::<Handle<UnknownBlob>>::new(*handle))
            .map_err(|error| anyhow!("residency lookup: {error:?}"))?;
        if resident {
            roots.resident.insert(*handle);
        } else {
            roots.absent.insert(*handle);
        }
    }
    Ok(roots)
}

/// Resident blobs in the source, the ones the rewrite keeps, and the
/// reached ones it finds corrupt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobAccounting {
    resident: usize,
    resident_bytes: u64,
    kept: usize,
    kept_bytes: u64,
    corrupt: usize,
    corrupt_bytes: u64,
}

/// Blobs a pile lists, and their bytes as the pile records them. For the
/// destination, which holds exactly the occurrence the rewrite copied.
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

/// Blobs the source lists, each counted by the occurrence a copy takes, its
/// first valid one, as the rewrite and the destination count it; a blob
/// with no valid occurrence by its first. This validates every resident
/// blob, which the rewrite's walk then finds already validated.
fn source_totals(reader: &PileFileSnapshot) -> Result<(usize, u64)> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for info in reader.blobs() {
        let info = info.map_err(|error| anyhow!("list blobs: {error:?}"))?;
        count += 1;
        bytes += match reader.get::<anybytes::Bytes, UnknownBlob>(info.handle) {
            Ok(valid) => valid.len() as u64,
            Err(_) => info.length,
        };
    }
    Ok((count, bytes))
}

/// The recorded bytes of the corrupt blobs, by their first occurrence.
fn corrupt_bytes(
    reader: &PileFileSnapshot,
    corrupt: &BTreeSet<Inline<Handle<UnknownBlob>>>,
) -> Result<u64> {
    let mut bytes = 0u64;
    for handle in corrupt {
        let info = reader
            .blob_info(*handle)
            .map_err(|error| anyhow!("blob info: {error:?}"))?;
        bytes += info.map_or(0, |info| info.length);
    }
    Ok(bytes)
}

/// Per kept collection with a believed foundation: the number of believed
/// foundations, the ones whose payload is not resident, and the ones whose
/// payload is resident only as corrupt bytes.
type Readability = BTreeMap<[u8; 32], (usize, Vec<[u8; 32]>, Vec<[u8; 32]>)>;

/// Read `collections` through the fold of a store opened without a host
/// key, which believes no merge, so each frontier is exactly the believed
/// foundations; name every foundation whose payload is resident only as
/// `corrupt` bytes, and apart from those every one whose payload is not
/// resident.
fn readability(
    pile: &mut Pile,
    collections: &BTreeSet<[u8; 32]>,
    corrupt: &BTreeSet<Inline<Handle<UnknownBlob>>>,
) -> Result<Readability> {
    let snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("snapshot for the readability check: {error:?}"))?;
    let coverage = snapshot.coverage();
    let mut report = Readability::new();
    for collection in collections {
        let (support, _) = coverage.frontier_support(CollectionHandle::new(*collection));
        let mut foundations = 0usize;
        let mut absent = Vec::new();
        let mut damaged = Vec::new();
        for member in support.iter_ordered() {
            foundations += 1;
            let handle: Inline<Handle<UnknownBlob>> = Inline::new(*member);
            if corrupt.contains(&handle) {
                damaged.push(*member);
            } else if !snapshot
                .contains_blob(handle)
                .map_err(|error| anyhow!("residency lookup: {error:?}"))?
            {
                absent.push(*member);
            }
        }
        if foundations > 0 {
            report.insert(*collection, (foundations, absent, damaged));
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

    /// Every resident descriptor of a collection some frame names that the
    /// rewrite leaves behind, with whether its DERIVEs are left behind too.
    /// `kept` answers for the destination (or the plan). Collections no
    /// frame names are not examined: nothing in the pile says they exist.
    fn left_descriptors(
        &self,
        mut kept: impl FnMut([u8; 32]) -> Result<bool>,
    ) -> Result<Vec<([u8; 32], bool)>> {
        let mut left = Vec::new();
        for (collection, class) in &self.classes {
            if *class == Class::Missing || kept(*collection)? {
                continue;
            }
            left.push((*collection, class.leaves_derives_behind(&self.attached)));
        }
        Ok(left)
    }

    /// The report both modes print, in full.
    fn report(
        &self,
        accounting: &FrameAccounting,
        blobs: BlobAccounting,
        roots: &Roots,
        left_descriptors: &[([u8; 32], bool)],
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
        let _ = writeln!(
            out,
            "records (carried / left behind; one held in several frames counts once):"
        );
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
            "rewrite: {} left behind by the filter, {} superseded, {} drained, {} repeated frames counted once; carried {} frames of unknown kind and {} retired v8/v9 equations",
            accounting.filtered,
            accounting.superseded,
            accounting.drained,
            accounting.repeated,
            accounting.opaque_carried,
            accounting.retired_carried,
        );
        let _ = writeln!(
            out,
            "capability proofs carried: {} current, {} retired",
            accounting.proofs_carried, accounting.retired_proofs_carried,
        );
        let corrupt_roots = roots
            .resident
            .iter()
            .filter(|handle| {
                accounting
                    .corrupt
                    .contains(&Inline::<Handle<UnknownBlob>>::new(**handle))
            })
            .count();
        let _ = writeln!(
            out,
            "roots: {} named, {} resident and kept with what they reach, {corrupt_roots} resident only as corrupt bytes, {} not resident in the source",
            roots.resident.len() + roots.absent.len(),
            roots.resident.len() - corrupt_roots,
            roots.absent.len(),
        );
        for handle in &roots.absent {
            let _ = writeln!(out, "  not resident blake3:{}", hex::encode_upper(handle));
        }
        let _ = writeln!(
            out,
            "blobs: {} resident ({} bytes), {} kept ({} bytes), {} corrupt ({} bytes), {} left behind ({} bytes)",
            blobs.resident,
            blobs.resident_bytes,
            blobs.kept,
            blobs.kept_bytes,
            blobs.corrupt,
            blobs.corrupt_bytes,
            blobs
                .resident
                .saturating_sub(blobs.kept)
                .saturating_sub(blobs.corrupt),
            blobs
                .resident_bytes
                .saturating_sub(blobs.kept_bytes)
                .saturating_sub(blobs.corrupt_bytes),
        );
        let _ = writeln!(
            out,
            "corrupt blobs: {} reached with no occurrence matching its hash, not copied",
            accounting.corrupt.len(),
        );
        for handle in &accounting.corrupt {
            let _ = writeln!(out, "  corrupt blake3:{}", hex::encode_upper(handle.raw));
        }

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
            "DERIVE records by mapping (carried / left behind, collections):"
        );
        for (label, (tally, collections)) in &by_mapping {
            let _ = writeln!(
                out,
                "  {label}: {} / {} in {collections}",
                tally.carried, tally.left
            );
        }

        let _ = writeln!(out, "records by collection (carried / left behind):");
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

        let _ = writeln!(
            out,
            "descriptors left behind: {} (resident; only collections a frame names are examined, keep others with --root)",
            left_descriptors.len()
        );
        for (collection, derives_left) in left_descriptors {
            let class = self.classes.get(collection);
            let label = class.map(|class| class.label(attached)).unwrap_or_default();
            let why = if class == Some(&Class::Corrupt) {
                "resident only as corrupt bytes (see corrupt blobs)"
            } else if *derives_left {
                "its DERIVEs are left behind"
            } else {
                "no kept record or root reaches it"
            };
            let _ = writeln!(
                out,
                "  blake3:{} {label}: {why}",
                hex::encode_upper(collection)
            );
        }

        let foundations: usize = readability.values().map(|(count, _, _)| count).sum();
        let absent: usize = readability
            .values()
            .map(|(_, absent, _)| absent.len())
            .sum();
        let damaged: usize = readability
            .values()
            .map(|(_, _, damaged)| damaged.len())
            .sum();
        let _ = writeln!(
            out,
            "readability (keyless fold): {} kept collections with believed foundations, {foundations} foundations, {absent} not resident, {damaged} corrupt",
            readability.len(),
        );
        for (collection, (count, missing, damaged)) in readability {
            if missing.is_empty() && damaged.is_empty() {
                continue;
            }
            let label = self
                .classes
                .get(collection)
                .map(|class| class.label(attached))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  blake3:{} {label}: {} not resident and {} corrupt of {count}",
                hex::encode_upper(collection),
                missing.len(),
                damaged.len(),
            );
            for handle in missing {
                let _ = writeln!(out, "    absent blake3:{}", hex::encode_upper(handle));
            }
            for handle in damaged {
                let _ = writeln!(out, "    corrupt blake3:{}", hex::encode_upper(handle));
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

/// A digest of a pile's frames, in file order, that leaves out the one field
/// every rewrite stamps afresh, a blob record's insertion timestamp: a blob
/// record counts by its content hash and length, every other frame by its
/// bytes. Two runs of the filter over one source write piles with the same
/// digest, though not the same bytes.
fn content_digest(path: &Path) -> Result<blake3::Hash> {
    let mut records =
        PileRecords::open(path).map_err(|error| anyhow!("walk {}: {error:?}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    while let Some(record) = records.next() {
        let record = record.map_err(|error| anyhow!("walk {}: {error:?}", path.display()))?;
        match record.content {
            PileRecordContent::Blob { hash, data_len, .. } => {
                hasher.update(b"blob");
                hasher.update(&hash.raw);
                hasher.update(&(data_len as u64).to_le_bytes());
            }
            _ => {
                hasher.update(b"frame");
                hasher.update(&(record.len as u64).to_le_bytes());
                hasher.update(&records.bytes()[record.offset..record.offset + record.len]);
            }
        }
    }
    Ok(hasher.finalize())
}

/// Why corrupt blobs stop a run, naming them when `list`.
fn corrupt_refusal(corrupt: &BTreeSet<Inline<Handle<UnknownBlob>>>, list: bool) -> String {
    let mut text = format!(
        "{} blob(s) the kept state reaches are resident only as corrupt bytes: no occurrence \
         matches its hash, so nothing valid can be copied, and a valid blob named only by a \
         damaged word of one cannot be reached and would be left behind. Corruption in a \
         frozen copy may be a copy fault the live pile does not share: check the live pile or \
         copy it again, or pass --allow-corrupt to set them aside",
        corrupt.len()
    );
    if list {
        for handle in corrupt {
            let _ = write!(text, "\n  corrupt blake3:{}", hex::encode_upper(handle.raw));
        }
    }
    text
}

/// Refuse a result with corrupt blobs unless `--allow-corrupt`, and one with
/// believed foundations whose payload is not resident unless
/// `--allow-absent`.
fn refuse(
    readability: &Readability,
    corrupt: &BTreeSet<Inline<Handle<UnknownBlob>>>,
    options: &Options,
) -> Result<()> {
    let mut reasons = Vec::new();
    if !corrupt.is_empty() && !options.allow_corrupt {
        reasons.push(corrupt_refusal(corrupt, false) + " (listed above under corrupt blobs)");
    }
    let absent: usize = readability
        .values()
        .map(|(_, absent, _)| absent.len())
        .sum();
    if absent > 0 && !options.allow_absent {
        reasons.push(format!(
            "{absent} believed foundation(s) of kept collections are not resident (listed \
             above). They are not resident in the source either: the filter keeps every valid \
             resident payload a kept record names. Pass --allow-absent to accept them"
        ));
    }
    if !reasons.is_empty() {
        bail!(reasons.join(". "));
    }
    Ok(())
}

pub fn run(source_path: PathBuf, args: LatticeV3Args) -> Result<()> {
    let attached = parse_attached(&args.attached_mappings)?;
    let named_roots = parse_roots(&args.roots, &args.roots_from)?;
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

    let options = Options {
        attached: &attached,
        named_roots: &named_roots,
        allow_absent: args.allow_absent,
        allow_corrupt: args.allow_corrupt,
        stable_len,
    };
    if args.dry_run {
        return dry_run(&source_path, &options);
    }
    let destination_path = args
        .into
        .ok_or_else(|| anyhow!("--into is required without --dry-run"))?;
    filter_into(&source_path, &destination_path, &options)
}

/// What both modes take from the command line.
struct Options<'a> {
    attached: &'a BTreeSet<Id>,
    named_roots: &'a BTreeSet<[u8; 32]>,
    allow_absent: bool,
    allow_corrupt: bool,
    stable_len: u64,
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

fn dry_run(source_path: &Path, options: &Options) -> Result<()> {
    let mut source = open_source(source_path)?;
    let planned = (|| -> Result<(String, Readability, BTreeSet<Inline<Handle<UnknownBlob>>>)> {
        let reader = source
            .snapshot()
            .map_err(|error| anyhow!("snapshot source: {error:?}"))?;
        let (resident, resident_bytes) = source_totals(&reader)?;
        let roots = resolve_roots(&reader, options.named_roots)?;
        let mut filter = V3Filter::new(&reader, options.attached);
        let plan = source
            .plan_retained_rewrite(
                &roots.retention(),
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
            corrupt: plan.corrupt_blobs.len(),
            corrupt_bytes: corrupt_bytes(&reader, &plan.corrupt_blobs)?,
        };
        check_source_len(source_path, options.stable_len)?;
        let accounting = FrameAccounting {
            filtered: plan.filtered_frames,
            superseded: plan.superseded_equations,
            drained: plan.drained_frames,
            repeated: plan.repeated_frames,
            opaque_carried: plan.opaque_frames,
            retired_carried: plan.retired_equations,
            proofs_carried: plan.capability_proofs,
            retired_proofs_carried: plan.retired_capability_proofs,
            corrupt: plan.corrupt_blobs,
        };
        let census = filter.census;
        let left = census.left_descriptors(|collection| {
            Ok(plan
                .retained
                .contains(&Inline::<Handle<UnknownBlob>>::new(collection)))
        })?;
        let mut keyless = Pile::new(
            PileFile::open_read_only(source_path)
                .map_err(|error| anyhow!("reopen source: {error:?}"))?,
        );
        let read = readability(
            &mut keyless,
            &census.kept_collections(),
            &accounting.corrupt,
        );
        keyless
            .close()
            .map_err(|error| anyhow!("close source: {error:?}"))?;
        let read = read?;
        let report = census.report(&accounting, blobs, &roots, &left, &read);
        Ok((report, read, accounting.corrupt))
    })();
    let closed = source
        .close()
        .map_err(|error| anyhow!("close source: {error:?}"));
    let (report, read, corrupt) = planned?;
    closed?;
    println!(
        "lattice-v3 dry run of {} (nothing written)",
        source_path.display()
    );
    print!("{report}");
    refuse(&read, &corrupt, options)
}

fn filter_into(source_path: &Path, destination_path: &Path, options: &Options) -> Result<()> {
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

    let operation = (|| -> Result<(Census, FrameAccounting, Roots, (usize, u64, u64), usize)> {
        let reader = source
            .snapshot()
            .map_err(|error| anyhow!("snapshot source: {error:?}"))?;
        let (resident, resident_bytes) = source_totals(&reader)?;
        let roots = resolve_roots(&reader, options.named_roots)?;
        let mut filter = V3Filter::new(&reader, options.attached);
        // Only the named roots: every other blob travels only when the
        // carried state reaches it. Corruption refuses before anything is
        // written unless the operator set it aside.
        let policy = if options.allow_corrupt {
            CorruptBlobPolicy::SetAside
        } else {
            CorruptBlobPolicy::Refuse
        };
        let stats = source
            .rewrite_retained_into_filtered(
                &mut destination,
                &roots.retention(),
                WantRewritePolicy::Preserve,
                &[],
                &mut filter,
                policy,
            )
            .map_err(|error| match error {
                PileRewriteError::Corrupt { blobs } => anyhow!(
                    "lattice v3 filter wrote nothing: {}",
                    corrupt_refusal(&blobs, true)
                ),
                error => anyhow!("lattice v3 filter: {error}"),
            })?;
        check_source_len(source_path, options.stable_len)?;
        let accounting = FrameAccounting {
            filtered: stats.filtered_frames,
            superseded: stats.superseded_equations,
            drained: stats.drained_frames,
            repeated: stats.repeated_frames,
            opaque_carried: stats.opaque_frames,
            retired_carried: stats.retired_equations,
            proofs_carried: stats.capability_proofs,
            retired_proofs_carried: stats.retired_capability_proofs,
            corrupt: stats.corrupt_blobs,
        };
        let corrupt = corrupt_bytes(&reader, &accounting.corrupt)?;
        Ok((
            filter.census,
            accounting,
            roots,
            (resident, resident_bytes, corrupt),
            stats.retained_blobs,
        ))
    })();
    let destination_close = destination
        .close()
        .map_err(|error| anyhow!("close destination: {error:?}"));
    let source_close = source
        .close()
        .map_err(|error| anyhow!("close source: {error:?}"));
    let (census, accounting, roots, (resident, resident_bytes, corrupt_bytes), retained) =
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
    let checked = (|| -> Result<(Readability, BlobAccounting, Vec<([u8; 32], bool)>)> {
        let mut written = Pile::new(
            PileFile::open_read_only(destination_path)
                .map_err(|error| anyhow!("reopen destination: {error:?}"))?,
        );
        let result = (|| -> Result<(Readability, BlobAccounting, Vec<([u8; 32], bool)>)> {
            let snapshot = written
                .snapshot()
                .map_err(|error| anyhow!("snapshot destination: {error:?}"))?;
            let (kept, kept_bytes) = blob_totals(&snapshot)?;
            if kept != retained {
                bail!("the destination holds {kept} blobs, the rewrite kept {retained}");
            }
            let left = census.left_descriptors(|collection| {
                snapshot
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(collection))
                    .map_err(|error| anyhow!("residency lookup: {error:?}"))
            })?;
            drop(snapshot);
            let blobs = BlobAccounting {
                resident,
                resident_bytes,
                kept,
                kept_bytes,
                corrupt: accounting.corrupt.len(),
                corrupt_bytes,
            };
            Ok((
                readability(
                    &mut written,
                    &census.kept_collections(),
                    &accounting.corrupt,
                )?,
                blobs,
                left,
            ))
        })();
        let closed = written
            .close()
            .map_err(|error| anyhow!("close destination: {error:?}"));
        let read = result?;
        closed?;
        Ok(read)
    })();
    let (read, blobs, left) = match checked {
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
    let digest = match content_digest(destination_path) {
        Ok(digest) => digest,
        Err(error) => return Err(cleanup_incomplete_destination(destination_path, error)),
    };
    println!(
        "lattice-v3 filter of {} into {}",
        source_path.display(),
        destination_path.display()
    );
    print!(
        "{}",
        census.report(&accounting, blobs, &roots, &left, &read)
    );
    println!(
        "destination: {} -> {destination_len} bytes",
        options.stable_len
    );
    println!(
        "destination digest (blob insertion timestamps left out): blake3:{}",
        hex::encode_upper(digest.as_bytes())
    );
    if let Err(error) = refuse(&read, &accounting.corrupt, options) {
        return Err(cleanup_incomplete_destination(
            destination_path,
            error.context("the destination was removed"),
        ));
    }
    Ok(())
}
