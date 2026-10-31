//! Native storage preparation over the same converters as `trible-migrate`.
//!
//! Inspection is read-only and builds no pile index. Preparation writes only
//! a fresh destination; it never activates, replaces, or deletes the source.
//! The owner must freeze the input for the entire call. A digest comparison
//! detects accidental changes, not hostile writers or unenforced immutability.
//!
//! These are storage outcomes, not a claim to understand every application
//! schema. Unknown application facts remain data. Known inert historical
//! records in an already current envelope remain inert; inspection neither
//! promotes them nor invents authority for them.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::collection::CollectionHandle;
use triblespace_core::id::Id;
use triblespace_core::repo::pile::{OpaqueKind, PileRecordContent, PileRecords, PileReframeStats};

use crate::cli::pile::migrate::{branch_to_collection, canonical, reframe_with_progress};

/// A bounded native preparation phase. Byte counters are zero when that
/// phase has no meaningful byte progress; counters can restart on a new pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Inspect,
    HashSource,
    Reframe,
    Describe,
    Branch,
    Canonical,
    Audit,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    pub stage: Stage,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

pub(crate) fn checkpoint(
    progress: &mut impl FnMut(Progress) -> bool,
    stage: Stage,
    completed_bytes: u64,
    total_bytes: u64,
) -> Result<()> {
    ensure!(
        progress(Progress {
            stage,
            completed_bytes,
            total_bytes
        }),
        "migration cancelled"
    );
    Ok(())
}

/// A bounded record kind this converter cannot rewrite, with its exact width.
/// Unknown kinds in current valid framing remain readable by native replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedKind {
    pub kind: OpaqueKind,
    pub occurrences: usize,
}

/// A choice the library will not make on the owner's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Requirement {
    /// Requires the existing `canonical` workflow: a frozen source digest,
    /// the original signing key and exact refreshes from foreign authors.
    Canonical { records: usize },
    /// Name, signing identity and trust root are semantic choices.
    Branch { branch: Id },
}

/// One read-only record inspection, never a stored migration ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inspection {
    /// Physical framing only; application schema readiness is not inferred.
    pub current_framing: bool,
    /// Existing live legacy pins, including pins deliberately retained by a
    /// previous branch conversion. Presence is not proof of unmigrated data.
    pub legacy_branches: Vec<Id>,
    pub requirements: Vec<Requirement>,
    pub unsupported: Vec<UnsupportedKind>,
}

/// An explicit branch adoption. There is deliberately no `Skip` decision.
pub struct BranchDecision<'a> {
    pub branch: Id,
    pub collection_name: &'a str,
    pub signer: &'a SigningKey,
    pub authority: VerifyingKey,
}

/// A successfully adopted branch, for the caller's existing configuration flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchTarget {
    pub branch: Id,
    pub collection: CollectionHandle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No physical rewrite is needed. Legacy pins, if present, are reported
    /// separately; this does not claim that they were adopted as collections.
    Current {
        legacy_branches: Vec<Id>,
    },
    /// The destination is prepared, not active. The owner must validate its
    /// actual configuration/workspace paths before switching its locator.
    Converted {
        destination: PathBuf,
        branches: Vec<BranchTarget>,
        reframe: PileReframeStats,
    },
    ChoiceRequired {
        requirements: Vec<Requirement>,
    },
    Unsupported {
        kinds: Vec<UnsupportedKind>,
    },
}

/// Native /32 assertion conversion under the caller's frozen-input custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalOutcome {
    /// Assertions passed the existing canonical converter's signature and
    /// indexed-identity audit. Allowed raw frames were copied exactly: inspect
    /// this candidate for any further framing/branch work before activation.
    Converted {
        destination: PathBuf,
        source_hash: [u8; 32],
        emitted_assertions: u64,
        /// Rebuildable caches retained only in the original, never fabricated.
        retained_original_caches: u64,
    },
    /// No destination was published. Only exact canonical refresh assertions
    /// from these original authors can discharge the missing foundations.
    ForeignRefreshRequired { authors: Vec<[u8; 32]> },
}

/// Convert supported /32 assertions with the existing signer, retaining the
/// complete original. Existing destinations/partials are refused. This does
/// not select a signer, adopt branches, or activate application configuration.
pub fn prepare_canonical(
    source: &Path,
    destination: &Path,
    signer: &SigningKey,
    refreshes: &[PathBuf],
) -> Result<CanonicalOutcome> {
    prepare_canonical_with_progress(source, destination, signer, refreshes, &mut |_| true)
}

/// Cancellation checkpoints cover input boundaries, each source/audit record
/// and acceptance before publication. Failed attempts may leave an unpublished
/// `.partial`; neither that file nor the retained source is deleted or resumed.
/// The caller must freeze the source and refresh inputs for the entire call.
pub fn prepare_canonical_with_progress(
    source: &Path,
    destination: &Path,
    signer: &SigningKey,
    refreshes: &[PathBuf],
    progress: &mut impl FnMut(Progress) -> bool,
) -> Result<CanonicalOutcome> {
    canonical::prepare_native(source, destination, signer, refreshes, progress)
}

/// Classify decoded record framing without opening the source for writing,
/// building an index, inspecting keys, or interpreting application facts.
pub fn inspect(source: &Path) -> Result<Inspection> {
    inspect_with_progress(source, &mut |_| true)
}

/// Optional branch labels for a native choice UI, keyed by upper-hex branch
/// ID. Unlike `inspect`, this replays a read-only pile index to follow names.
/// Absent, ambiguous or unreadable labels are omitted, never guessed.
pub fn legacy_branch_names(source: &Path) -> Result<BTreeMap<String, String>> {
    branch_to_collection::active_branch_names(source)
}

/// Inspect with cancellation at decoded-record boundaries.
pub fn inspect_with_progress(
    source: &Path,
    progress: &mut impl FnMut(Progress) -> bool,
) -> Result<Inspection> {
    checkpoint(progress, Stage::Inspect, 0, 0)?;
    let mut records = PileRecords::open(source)
        .map_err(|error| crate::cli::pile::pile_read_error(source, error))?;
    let total = records.bytes().len() as u64;
    let mut current_framing = true;
    let mut branches = BTreeMap::new();
    let mut unsupported = BTreeMap::new();
    let mut canonical_records = 0;
    while let Some(record) = records.next() {
        let record = record.map_err(|error| crate::cli::pile::pile_read_error(source, error))?;
        checkpoint(progress, Stage::Inspect, record.offset as u64, total)?;
        current_framing &= records.has_current_framing(&record);
        match record.content {
            PileRecordContent::Opaque { kind } => match kind {
                OpaqueKind::Described(raw) if canonical::frame::supported(raw) => {
                    canonical_records += 1;
                }
                other => *unsupported.entry(other).or_insert(0) += 1,
            },
            PileRecordContent::Branch { branch_id, .. } => {
                branches.insert(branch_id, true);
            }
            PileRecordContent::BranchTombstone { branch_id } => {
                branches.insert(branch_id, false);
            }
            _ => {}
        }
    }
    let mut requirements = Vec::new();
    if canonical_records != 0 {
        requirements.push(Requirement::Canonical {
            records: canonical_records,
        });
    }
    checkpoint(progress, Stage::Inspect, total, total)?;
    Ok(Inspection {
        current_framing,
        legacy_branches: branches
            .into_iter()
            .filter_map(|(id, live)| live.then_some(id))
            .collect(),
        requirements,
        unsupported: unsupported
            .into_iter()
            .map(|(kind, occurrences)| UnsupportedKind { kind, occurrences })
            .collect(),
    })
}

fn digest(source: &Path, progress: &mut impl FnMut(Progress) -> bool) -> Result<blake3::Hash> {
    let mut file = File::open(source).context("read frozen migration source")?;
    let total = file.metadata()?.len();
    let mut completed = 0;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        checkpoint(progress, Stage::HashSource, completed, total)?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        completed += n as u64;
    }
    Ok(hasher.finalize())
}

fn unchanged(source: &Path, before: &Metadata) -> Result<()> {
    let after = std::fs::metadata(source).context("reinspect frozen migration source")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "migration source path was replaced; candidate is not accepted"
        );
    }
    ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "migration source changed; candidate is not accepted"
    );
    Ok(())
}

/// Prepare a fresh candidate using explicit decisions and the existing
/// reframing/branch converters. A returned candidate is never activated here.
/// Existing destinations (including dangling symlinks and hardlinks) are
/// refused; candidates from previous runs are not trusted as completion flags.
pub fn prepare(
    source: &Path,
    destination: &Path,
    decisions: &[BranchDecision<'_>],
) -> Result<Outcome> {
    prepare_with_progress(source, destination, decisions, &mut |_| true)
}

/// Prepare with bounded checkpoints. One blob write, a branch publication,
/// native snapshot construction, and a flush can run until their own return;
/// cancellation does not imply rollback of the incomplete candidate.
pub fn prepare_with_progress(
    source: &Path,
    destination: &Path,
    decisions: &[BranchDecision<'_>],
    progress: &mut impl FnMut(Progress) -> bool,
) -> Result<Outcome> {
    let source_metadata = std::fs::metadata(source).context("inspect migration source identity")?;
    let inspection = inspect_with_progress(source, progress)?;
    unchanged(source, &source_metadata)?;
    checkpoint(progress, Stage::Inspect, 0, 0)?;
    let canonical = inspection
        .requirements
        .iter()
        .any(|r| matches!(r, Requirement::Canonical { .. }));
    if inspection.current_framing && !canonical && decisions.is_empty() {
        checkpoint(progress, Stage::Ready, 0, 0)?;
        unchanged(source, &source_metadata)?;
        return Ok(Outcome::Current {
            legacy_branches: inspection.legacy_branches,
        });
    }
    if !inspection.unsupported.is_empty() {
        return Ok(Outcome::Unsupported {
            kinds: inspection.unsupported,
        });
    }
    if canonical {
        return Ok(Outcome::ChoiceRequired {
            requirements: inspection.requirements,
        });
    }
    let mut selected = BTreeMap::new();
    for decision in decisions {
        ensure!(
            inspection.legacy_branches.contains(&decision.branch),
            "decision names a branch absent from the source's live pins"
        );
        ensure!(
            selected.insert(decision.branch, decision).is_none(),
            "more than one decision for the same branch"
        );
    }
    let mut requirements = inspection.requirements;
    requirements.extend(
        inspection
            .legacy_branches
            .iter()
            .filter(|branch| !selected.contains_key(*branch))
            .map(|branch| Requirement::Branch { branch: *branch }),
    );
    if !requirements.is_empty() {
        return Ok(Outcome::ChoiceRequired { requirements });
    }
    match std::fs::symlink_metadata(destination) {
        Ok(_) => bail!("migration destination already exists; use a fresh path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect migration destination"),
    }
    let before = digest(source, progress)?;
    unchanged(source, &source_metadata)?;
    checkpoint(progress, Stage::Reframe, 0, source_metadata.len())?;
    let (reframe, _) = reframe_with_progress(source, destination, |completed, total| {
        progress(Progress {
            stage: Stage::Reframe,
            completed_bytes: completed as u64,
            total_bytes: total as u64,
        })
    })?;
    let mut pile = crate::cli::pile::open_refreshed(destination)?;
    let result = (|| -> Result<Vec<BranchTarget>> {
        checkpoint(progress, Stage::Describe, 0, 0)?;
        pile.publish_record_kind_descriptions()
            .map_err(|error| anyhow::anyhow!("publish record-kind descriptions: {error:?}"))?;
        let mut branches = Vec::new();
        for decision in decisions {
            checkpoint(progress, Stage::Branch, 0, 0)?;
            let collection = branch_to_collection::apply(
                &mut pile,
                decision.branch,
                decision.collection_name,
                decision.authority,
                decision.signer,
            )?;
            branches.push(BranchTarget {
                branch: decision.branch,
                collection: collection.handle(),
            });
        }
        Ok(branches)
    })();
    let close = pile
        .close()
        .map_err(|error| anyhow::anyhow!("close migration candidate: {error}"));
    let branches = result?;
    close?;
    ensure!(
        digest(source, progress)? == before,
        "migration source changed; candidate is not accepted"
    );
    unchanged(source, &source_metadata)?;
    checkpoint(progress, Stage::Ready, 0, 0)?;
    unchanged(source, &source_metadata)?;
    Ok(Outcome::Converted {
        destination: destination.to_path_buf(),
        branches,
        reframe,
    })
}
