use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use triblespace_core::collection::CollectionRead;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStoreGet, SnapshotSource};

mod branch_to_collection;
mod canonical;
mod clean;
mod lattice_v3;
mod shortstring_to_utf8;
mod upgrade;

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    #[value(name = "monotone-wants")]
    MonotoneWants,
    #[value(name = "record-kind-descriptions")]
    RecordKindDescriptions,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Rewrite a frozen /32 pile without changing foundation authorship.
    /// Missing foreign refreshes or unsupported history refuse publication.
    Canonical(canonical::Args),
    /// Export only this key's verified foundations as a canonical refresh pile.
    /// This is NOT completion of a source migration.
    CanonicalRefresh(canonical::RefreshArgs),
    /// List known migrations and whether they are needed for this pile.
    List,
    /// Bring this pile to the current format by running to a fixpoint.
    ///
    /// Runs every step that needs no choice, stops at the first that does
    /// and prints exactly what to record, and on a rerun reads what is left
    /// from the piles themselves. The source is only read; everything is
    /// written into `--into`. Exit status 0: nothing left; 2: a choice is
    /// needed; 3: the pile holds frames with no path forward.
    Upgrade(upgrade::UpgradeArgs),
    /// Re-encode a whole pile into the current record framing.
    ///
    /// Only the markers released in v0.46.4 are a writable compatibility
    /// commitment. Exact retired boundaries remain structurally recognized so
    /// later stale concatenation stays harmless; reframe projects their final
    /// supported semantics once and drops the retired frames.
    Reframe {
        /// Destination pile. Must not already exist.
        #[arg(long = "into")]
        into: PathBuf,
    },
    /// Write a clean lattice v2 pile: one owner per payload, adopted
    /// generations, leaf DERIVEs re-emitted by locator, no MERGEs.
    ///
    /// LOSSY by design, unlike `compact`. Per current root and payload, the
    /// owner is the signer of the earliest COMMIT that verifies strictly and
    /// that the root admits as a writer; every COMMIT of that owner is kept
    /// and other signers' COMMITs of the payload are dropped. Payloads an
    /// adopted retired collection admitted and the current root lacks are
    /// re-signed into it with the first `--key`. Retired (v9) DERIVEs whose
    /// input is a kept foundation of their target's source are re-emitted as
    /// locator DERIVEs signed by that foundation's owner, derived collections
    /// upstream first; without the owner's key they are counted, and the owner
    /// derives them after the cutover. Signature-valid capability proofs,
    /// kept collections' descriptors, the record-kind descriptions and every
    /// blob those reach are kept. Every MERGE, retired kind, WANT, pin,
    /// COMMIT of a retired collection and duplicate-owner COMMIT is dropped
    /// and counted; maintenance rebuilds merges. The source is only read,
    /// through a read-only descriptor, and locked only while it is replayed.
    Clean(clean::CleanArgs),
    /// Write a lattice v3 pile from a frozen copy: every COMMIT of every
    /// generation, no MERGE, DERIVEs only of mappings that stay derived.
    ///
    /// A stop-the-world compaction filter. Every COMMIT of every generation
    /// is kept, and so are capability proofs, WANTs, legacy pins and frames
    /// of unknown kind. Every MERGE of every encoding and signer is left
    /// behind; each host rebuilds its own. A DERIVE is left behind when its
    /// target's descriptor names only mapping algorithms that become
    /// attached or are deleted, and kept when the mapping stays derived (the
    /// semantic index), is unrecognised, or the descriptor is not resident.
    /// A blob is kept only when the kept state or a `--root` reaches it by
    /// the conservative walk, so merge results and dropped images are left
    /// behind, and so is the descriptor of a collection no kept record names
    /// unless a root keeps it: archive the source first, and name with
    /// `--root` or `--roots-from` every handle something outside the pile
    /// opens. The source is only read, and a
    /// source another process holds open is refused. Afterwards every kept
    /// collection is read through the fold without a host key, and each
    /// believed foundation's payload must be resident. `--dry-run` decides
    /// the same frames and blobs, writes nothing and prints the same report.
    LatticeV3(lattice_v3::LatticeV3Args),
    /// Append the Handle<UTF8String> twin of every old ShortString fact.
    ///
    /// Text attributes moved off the 32-byte ShortString encoding, and the
    /// encoding is part of an attribute's id, so old facts sit under ids new
    /// code no longer reads. Name each retired declaration by its hex:
    /// `--pinned HEX` for `"HEX" unsafe as ..: ShortString` (old id = HEX),
    /// `--anchored HEX` for `"HEX" as ..: ShortString` (old id derived from
    /// HEX and ShortString). The new id is derived from HEX and
    /// Handle<UTF8String>. Every old fact in the collection's current view
    /// whose twin is absent gets one, text stored as a blob, in a single
    /// commit the collection's WRITE must admit. Nothing is deleted or
    /// rewritten, a second run writes nothing, and values that do not decode
    /// are counted and listed rather than dropped.
    ShortstringToUtf8(shortstring_to_utf8::ShortstringToUtf8Args),
    /// Re-sign one verified legacy branch as native collection commits.
    ///
    /// This is deliberately a same-pile migration: one frozen pin observation
    /// selects the head, a later append-only blob snapshot validates everything
    /// it reaches, and only then are native records appended to that pile. The
    /// target policy root defaults to the migration signer. Choosing a
    /// different root is allowed, but admission of the resulting commits then
    /// needs a resident proof granting the signer exact WRITE access to the
    /// collection.
    BranchToCollection {
        /// Legacy branch to migrate, by exact name or 32-hex-character id.
        #[arg(long)]
        branch: String,
        /// Immutable name of the target root collection.
        #[arg(long)]
        collection_name: String,
        /// Root for both target READ and WRITE policies. Defaults to the signer.
        #[arg(long)]
        authority: Option<String>,
        /// Durable target signing-key file (64-hex-character seed).
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Run one explicitly named migration.
    Run {
        /// Migration name. `monotone-wants` is deliberately never implicit:
        /// it is the one cutover that promotes retired history into live
        /// demand.
        #[arg(value_enum)]
        migration: Migration,
        /// Show what would change without mutating the pile.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

pub fn run(pile_path: PathBuf, cmd: Command) -> Result<()> {
    match cmd {
        Command::Canonical(args) => canonical::run(pile_path, args),
        Command::CanonicalRefresh(args) => canonical::export(pile_path, args),
        Command::List => list_migrations(&pile_path),
        Command::Upgrade(args) => {
            let status = upgrade::run(&pile_path, args)?;
            if status != 0 {
                std::process::exit(status);
            }
            Ok(())
        }
        Command::Reframe { into } => reframe(&pile_path, &into),
        Command::Clean(args) => clean::run(pile_path, args),
        Command::LatticeV3(args) => lattice_v3::run(pile_path, args),
        Command::ShortstringToUtf8(args) => shortstring_to_utf8::run(pile_path, args),
        Command::BranchToCollection {
            branch,
            collection_name,
            authority,
            signing_key,
        } => branch_to_collection::run(pile_path, branch, collection_name, authority, signing_key),
        Command::Run { migration, dry_run } => {
            match migration {
                Migration::MonotoneWants => migrate_monotone_wants(&pile_path, dry_run)?,
                Migration::RecordKindDescriptions => {
                    migrate_record_kind_descriptions(&pile_path, dry_run)?
                }
            }
            Ok(())
        }
    }
}

fn list_migrations(pile_path: &PathBuf) -> Result<()> {
    let mut pile = super::open_refreshed(pile_path)?;
    let res = (|| -> Result<(), anyhow::Error> {
        let wants = pile
            .want_cutover_status()
            .context("inspect monotone WANT cutover")?;
        let snapshot = pile.snapshot().context("pile snapshot")?;
        let (present, missing) = record_kind_description_census(&snapshot)?;
        let total = present + missing;

        println!("Known migrations:");
        if wants.missing_current == 0 {
            println!(
                "- monotone-wants: ok ({} retired record(s), {} resolved active request(s), all current)",
                wants.retired_records, wants.resolved_active,
            );
        } else {
            println!(
                "- monotone-wants: needed ({} of {} resolved active request(s) missing current markers; {} retired record(s))",
                wants.missing_current, wants.resolved_active, wants.retired_records,
            );
        }
        if missing == 0 {
            println!("- record-kind-descriptions: ok ({total} blob(s) resident)");
        } else {
            println!(
                "- record-kind-descriptions: needed ({missing} of {total} description \
                 blob(s) missing)"
            );
        }
        print_legacy_census(&legacy_census(pile_path)?);
        Ok(())
    })();

    let close_res = pile.close().map_err(|e| anyhow::anyhow!("{e:?}"));
    res.and(close_res)?;
    Ok(())
}

/// Records of retired or legacy kinds, and legacy branches whose last pin is a
/// head rather than a tombstone, as the
/// raw record reader decodes them. Descriptive only: what `reframe` carries,
/// projects or drops is its own report, so this never second-guesses it.
#[derive(Default)]
struct LegacyCensus {
    kinds: std::collections::BTreeMap<&'static str, usize>,
    opaque: usize,
    live_branches: usize,
}

fn legacy_census(pile_path: &PathBuf) -> Result<LegacyCensus> {
    use triblespace_core::repo::pile::{PileRecordContent, PileRecords};

    let mut census = LegacyCensus::default();
    let mut branches = std::collections::HashMap::new();
    let records =
        PileRecords::open(pile_path).map_err(|error| super::pile_read_error(pile_path, error))?;
    for record in records {
        let record = record.map_err(|error| super::pile_read_error(pile_path, error))?;
        let kind = match record.content {
            PileRecordContent::Branch { branch_id, .. } => {
                branches.insert(branch_id, true);
                continue;
            }
            PileRecordContent::BranchTombstone { branch_id } => {
                branches.insert(branch_id, false);
                continue;
            }
            PileRecordContent::Opaque { .. } => {
                census.opaque += 1;
                continue;
            }
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => "retired WANT log",
            PileRecordContent::LegacyCollectionV3 { .. } => "legacy V3 collection",
            PileRecordContent::LegacyUnsignedCollectionEquation { .. } => {
                "legacy unsigned equation"
            }
            PileRecordContent::RetiredCollectionEquation { .. } => "retired v8/v9 equation",
            PileRecordContent::RetiredCollectionDeriveV4 => "retired V4 derive",
            PileRecordContent::RetiredCapabilityProof => "retired capability proof",
            PileRecordContent::RetiredPeerEvidenceV1 => "retired PEER",
            PileRecordContent::RetiredStoreScopeV1 => "retired STORE_SCOPE",
            PileRecordContent::RetiredArtifactOfferV1 => "retired artifact offer",
            _ => continue,
        };
        *census.kinds.entry(kind).or_default() += 1;
    }
    census.live_branches = branches.values().filter(|live| **live).count();
    Ok(census)
}

fn print_legacy_census(census: &LegacyCensus) {
    if census.kinds.is_empty() {
        println!("- retired record kinds: none");
    } else {
        let kinds: Vec<String> = census
            .kinds
            .iter()
            .map(|(kind, count)| format!("{count} {kind}"))
            .collect();
        println!(
            "- retired record kinds: {} (`reframe --into <dest>` rewrites the pile in the \
             current framing and reports what it carries, projects and drops)",
            kinds.join(", ")
        );
    }
    if census.opaque != 0 {
        println!(
            "- unknown record kinds: {} (reframe refuses them; `pile diagnose census` lists their markers)",
            census.opaque
        );
    }
    if census.live_branches == 0 {
        println!("- legacy branch heads: none");
    } else {
        println!(
            "- legacy branch heads: {} (`branch-to-collection` copies a branch into a native \
             collection and appends to the pile it reads; it leaves the head in place, so this \
             count does not fall once a branch is migrated)",
            census.live_branches
        );
    }
}

/// Refuse a source that holds frames of the deployed /32 collection kinds.
///
/// `clean` and `lattice-v3` were written for lattice v2 and v3 piles, before
/// /33 made the /32 COMMIT, MERGE, DERIVE and MAP kinds opaque. Given such a
/// pile they would not convert those frames: `lattice-v3` carries /32 MERGEs
/// and MAPs past its frame filter, and `clean --drop-unknown` drops every /32
/// COMMIT. A /32 pile's path is `canonical`. This runs before either command
/// opens a destination, so a refusal writes nothing.
fn refuse_deployed32(source: &std::path::Path, command: &str) -> Result<()> {
    use triblespace_core::repo::pile::{OpaqueKind, PileRecordContent, PileRecords};

    let mut found = 0usize;
    let records =
        PileRecords::open(source).map_err(|error| super::pile_read_error(source, error))?;
    for record in records {
        let record = record.map_err(|error| super::pile_read_error(source, error))?;
        if let PileRecordContent::Opaque {
            kind: OpaqueKind::Described(raw),
        } = record.content
        {
            if canonical::frame::supported(raw) {
                found += 1;
            }
        }
    }
    if found != 0 {
        anyhow::bail!(
            "{command} refuses {}: it holds {found} frame(s) of the deployed /32 collection \
             kinds (COMMIT, MERGE, DERIVE, MAP). {command} predates /33, which made those kinds \
             opaque, so it would carry or drop them instead of converting them. A /32 pile goes \
             through `trible-migrate <FROZEN COPY> canonical --into <DEST> ...`, which may still \
             refuse history it does not support. The source was only read and nothing was written",
            source.display()
        );
    }
    Ok(())
}

/// Project the retired LWW WANT log into the fresh grow-only set in place.
///
/// New replay deliberately ignores the old records, so this migration must be
/// run before a pre-cutover pile is served. The pile-level operation holds one
/// exclusive lock across its raw scan and append phase; reruns are idempotent.
fn migrate_monotone_wants(pile_path: &PathBuf, dry_run: bool) -> Result<()> {
    // The mutating pile operation performs its own locked refresh. Opening an
    // unindexed Pile here avoids scanning a multi-gigabyte file once before
    // the authoritative scan. Dry-run has no locked operation, so it uses the
    // ordinary fail-loud refreshed open.
    let mut pile = if dry_run {
        super::open_refreshed(pile_path)?
    } else {
        Pile::open(pile_path)
            .map_err(|err| anyhow!("open pile {}: {err:?}", pile_path.display()))?
    };
    let res = (|| -> Result<(), anyhow::Error> {
        if dry_run {
            let status = pile
                .want_cutover_status()
                .context("inspect monotone WANT cutover")?;
            if status.missing_current == 0 {
                println!(
                    "monotone-wants: nothing to do ({} retired record(s), {} resolved active request(s), all current).",
                    status.retired_records, status.resolved_active,
                );
                return Ok(());
            }
            println!(
                "Would append {} monotone WANT marker(s) after resolving {} retired record(s) to {} active request(s) ({} already current).",
                status.missing_current,
                status.retired_records,
                status.resolved_active,
                status.already_current,
            );
            return Ok(());
        }

        let migrated = pile
            .migrate_retired_wants()
            .context("append monotone WANT markers")?;
        pile.flush().context("flush monotone WANT migration")?;
        if migrated.missing_current == 0 {
            println!(
                "monotone-wants: nothing to do ({} retired record(s), {} resolved active request(s), all current).",
                migrated.retired_records, migrated.resolved_active,
            );
            return Ok(());
        }
        println!(
            "Appended {} monotone WANT marker(s); resolved {} retired record(s) to {} active request(s) ({} were already current).",
            migrated.missing_current,
            migrated.retired_records,
            migrated.resolved_active,
            migrated.already_current,
        );
        Ok(())
    })();

    let close_res = pile.close().map_err(|e| anyhow::anyhow!("{e:?}"));
    res.and(close_res)?;
    Ok(())
}

/// Count how many of this reader's record-kind description blobs the pile
/// already holds.
///
/// The census is what makes a re-run honest: a pile that already carries the
/// descriptions reports nothing to do rather than repeating its whole worklist.
fn record_kind_description_census(
    reader: &(impl BlobStoreGet + triblespace_core::repo::BlobStoreList),
) -> Result<(usize, usize)> {
    let mut present = 0usize;
    let mut missing = 0usize;
    for blob in triblespace_core::repo::pile::description_blobs() {
        let handle = blob.get_handle();
        if reader
            .contains_blob(handle)
            .map_err(|err| anyhow!("residency lookup: {err:?}"))?
        {
            present += 1;
        } else {
            missing += 1;
        }
    }
    Ok((present, missing))
}

/// Make every record kind this binary writes resolvable inside the pile.
///
/// A record kind is the 32-byte handle of a description archive. That makes it
/// resolvable in principle; storing the archives makes it resolvable *here*,
/// so a reader holding nothing but the file can resolve every kind the current
/// binary writes. Retired read-only kinds are intentionally not republished.
fn migrate_record_kind_descriptions(pile_path: &PathBuf, dry_run: bool) -> Result<()> {
    let mut pile = super::open_refreshed(pile_path)?;

    let res = (|| -> Result<(), anyhow::Error> {
        let snapshot = pile.snapshot().context("pile snapshot")?;
        let (present, missing) = record_kind_description_census(&snapshot)?;

        if missing == 0 {
            println!(
                "record-kind-descriptions: nothing to do ({present} description blob(s) \
                 already resident)."
            );
            return Ok(());
        }
        if dry_run {
            println!(
                "Would store {missing} record-kind description blob(s) ({present} already \
                 resident)."
            );
            return Ok(());
        }

        // Content addressing makes this idempotent, so the already-resident
        // ones cost nothing and the count above is a report, not a plan the
        // write path has to honour.
        let stored = pile
            .publish_record_kind_descriptions()
            .map_err(|err| anyhow!("store record-kind descriptions: {err:?}"))?;
        println!("Published {stored} record-kind description blob(s) ({missing} were missing).");
        Ok(())
    })();

    let close_res = pile.close().map_err(|e| anyhow::anyhow!("{e:?}"));
    res.and(close_res)?;
    Ok(())
}

/// Re-encode `pile_path` into a fresh pile at `destination`.
///
/// The destination is created empty and must not already exist: a reframe that
/// appended into an existing file would produce exactly the mixed framing it
/// exists to eliminate.
///
/// Every commit in the result is verified afterwards. A signature covers a
/// domain-separated transcript over the record's fields rather than the bytes
/// of its frame, so re-encoding cannot invalidate one — but that is a claim
/// about two layers, and the cheap way to be sure is to check rather than to
/// reason.
fn reframe(pile_path: &PathBuf, destination: &PathBuf) -> Result<()> {
    if destination.exists() {
        anyhow::bail!(
            "destination {} already exists; reframe writes a fresh pile",
            destination.display()
        );
    }
    std::fs::File::create(destination)
        .with_context(|| format!("create {}", destination.display()))?;

    let mut out = Pile::open(destination).map_err(|e| anyhow!("open destination: {e:?}"))?;
    let res = (|| -> Result<(), anyhow::Error> {
        let stats = triblespace_core::repo::pile::reframe_into(pile_path, &mut out)
            .map_err(|e| anyhow!("reframe: {e}"))?;
        println!(
            "Reframed into {}:\n  blobs: {}\n  pin updates: {}\n  wants: {}\n  \
             retired WANT records projected: {}\n  capability proofs: {}\n  collection records: {}\n  \
             retired v8/v9 equations carried: {}\n  dropped inert records: {}",
            destination.display(),
            stats.blobs,
            stats.pin_updates,
            stats.wants,
            stats.retired_want_records,
            stats.capability_proofs,
            stats.collection_records,
            stats.retired_equations,
            stats.dropped_inert,
        );

        let (mut checked, mut invalid) = (0usize, 0usize);
        let snapshot = out.snapshot().context("snapshot reframed pile")?;
        for record in snapshot
            .records()
            .map_err(|e| anyhow!("read records: {e:?}"))?
        {
            let record = record.map_err(|e| anyhow!("read record: {e:?}"))?;
            if let triblespace_core::collection::CollectionRecord::Commit(commit) = record {
                checked += 1;
                if commit.verify_strict().is_err() {
                    invalid += 1;
                }
            }
        }
        println!("  commits verified: {checked} (signature-invalid {invalid})");
        if invalid > 0 {
            anyhow::bail!(
                "{invalid} commit(s) failed strict verification after reframing; \
                 keep the source pile and report this"
            );
        }
        Ok(())
    })();

    let close_res = out.close().map_err(|e| anyhow::anyhow!("{e:?}"));
    res.and(close_res)?;
    Ok(())
}
