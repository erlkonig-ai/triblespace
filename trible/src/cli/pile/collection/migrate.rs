//! `trible pile collection migrate` and the completeness proof beside it.
//!
//! Content moves between collections by being **re-signed**, never by being
//! pointed at. A record naming the retired collection was admitted under the
//! retired policy; unioning it into the new collection at read time would hand
//! whoever still holds the old key a way into the new one. So a migration signs
//! each assertion afresh under a key the target admits, and the old records stay
//! exactly where they are. [`triblespace_core::collection::migration`] holds the
//! semantics; this is the operator surface over them.
//!
//! Three things an operator needs and did not have.
//!
//! **A dry run that reports what would be written.** The number that decides
//! whether to proceed is net-new, and net-new is `(target, data, metadata,
//! signer)` tuples the pile does not already hold. Counting the source instead
//! gives the same figure on the first run, on the second run, and under a key
//! that reproduces nothing — which is to say, no signal at all.
//!
//! **Bulk.** Collapsing five generations of one name is one command, not one
//! command per edge run by hand at three in the morning; `--plan` does many
//! names at once and prints the whole thing before writing any of it.
//!
//! **A proof that it finished.** `reconcile` compares source and target by
//! content on the merged pile, names the difference, and exits non-zero while
//! anything the source admitted is missing. It stands alone, so a migration
//! somebody else ran months ago can be checked today.
//!
//! Not to be confused with `trible pile migrate`, which converts a pile's
//! *format*. This one moves a collection's content.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::VerifyingKey;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::migration::{
    self, CommitPair, MigrationSurvey, Scope, SourceSurvey,
};
use triblespace_core::collection::records::CollectionHandle;
use triblespace_core::collection::Collection;
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::SnapshotSource;

use super::super::open_refreshed;
use super::{
    anchor, enumerate, handle_hex, print_table, resolve, Align, Anchor, Enumerated, Fields,
};

/// Move committed content from one or more collections into another.
///
/// A collection's identity is the handle of its descriptor, so changing what a
/// descriptor says mints a new collection under the same name and leaves the
/// previous generation's records resident but unreachable. This carries them
/// forward: every content pair the sources hold is signed afresh as a COMMIT of
/// the target.
///
/// Nothing is written without `--apply`. The default is the dry run, and the
/// dry run's net-new figure is exactly what `--apply` then appends.
#[derive(clap::Args)]
pub struct MigrateArgs {
    /// Path to the pile file to update.
    pub pile: PathBuf,
    /// Target collection: name, or descriptor handle (`name:` / `blake3:`).
    #[arg(long, required_unless_present = "plan", conflicts_with = "plan")]
    pub into: Option<String>,
    /// Source collection; repeat for several. Every one is carried into
    /// `--into`.
    #[arg(long, conflicts_with = "plan")]
    pub from: Vec<String>,
    /// Add every other collection in this pile claiming the target's name.
    ///
    /// The generation cutover in one flag: all five retired generations of
    /// `wiki` into the current one, without looking up five handles by hand.
    #[arg(long, conflicts_with = "plan")]
    pub siblings: bool,
    /// Read `<source> -> <target>` edges from a file, one per line, `#` for
    /// comments. Many names in one reviewed, repeatable artifact.
    #[arg(long)]
    pub plan: Option<PathBuf>,
    /// Signing key for the carried commits. Defaults to TRIBLESPACE_KEY or
    /// self.key beside the pile.
    ///
    /// The key decides the size of the write: re-signing is deterministic, so
    /// the target's own writer reproduces records already there and appends
    /// only what is new, while any other key re-authors everything.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Append the records. Without it nothing is written.
    #[arg(long)]
    pub apply: bool,
    /// Also carry content no author the source admits ever asserted.
    ///
    /// Local storage is a claim ledger, so a process with pile-write access can
    /// append commits naming any collection; the source's policy filters them
    /// out at read time. Re-signing them under the target's key promotes them
    /// into the new generation. Deliberate, never implicit.
    #[arg(long, conflicts_with = "skip_unadmitted")]
    pub carry_unadmitted: bool,
    /// Leave such content behind, and say so in the report.
    #[arg(long)]
    pub skip_unadmitted: bool,
    /// Permit a source whose name differs from the target's.
    #[arg(long)]
    pub allow_cross_name: bool,
    /// Permit a signing key the target does not admit as a writer.
    ///
    /// Such a migration lands every record and reads as empty, which is the
    /// exact silence this tooling exists to break. Grant first where you can.
    #[arg(long)]
    pub allow_inadmissible_signer: bool,
    /// Print the content handles involved, not just their counts.
    #[arg(long)]
    pub list: bool,
}

/// One target and the sources being carried into it.
struct Group {
    target: CollectionHandle,
    sources: Vec<CollectionHandle>,
}

/// Parse a `--plan` file into source → target edges.
///
/// One edge per line, `#` starts a comment, blank lines ignored:
///
/// ```text
/// blake3:0f1e…  -> wiki
/// # the 2026-08-28 generation
/// blake3:2579…  -> wiki
/// ```
fn parse_plan(text: &str) -> Result<Vec<(String, String)>> {
    let mut edges = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((source, target)) = line.split_once("->") else {
            bail!(
                "plan line {}: expected `<source> -> <target>`, found {line:?}",
                number + 1
            );
        };
        let (source, target) = (source.trim(), target.trim());
        if source.is_empty() || target.is_empty() {
            bail!(
                "plan line {}: expected `<source> -> <target>`, found {line:?}",
                number + 1
            );
        }
        edges.push((source.to_owned(), target.to_owned()));
    }
    if edges.is_empty() {
        bail!("plan names no migrations");
    }
    Ok(edges)
}

/// The name a collection is known by in this pile, if it has a readable one.
///
/// Read from the descriptor rather than from the listing. A collection that
/// holds no records yet is named by nothing and so is absent from the listing
/// entirely — and on the day of a cutover that is exactly the state of the
/// generation everything is being carried *into*.
fn named(snapshot: &PileSnapshot, handle: CollectionHandle) -> Option<String> {
    match anchor(&Fields::load(snapshot, handle)) {
        Anchor::Root(Ok(name)) => Some(name),
        _ => None,
    }
}

/// Every other collection this pile references that claims `name`.
///
/// Sibling discovery is over referenced collections, which is the right domain:
/// a same-named collection holding no records has nothing to carry.
fn siblings_of(rows: &[Enumerated], handle: CollectionHandle, name: &str) -> Vec<CollectionHandle> {
    rows.iter()
        .filter(|row| row.handle != handle)
        .filter(|row| matches!(anchor(&row.fields), Anchor::Root(Ok(found)) if found == name))
        .map(|row| row.handle)
        .collect()
}

/// Render one collection as an operator reads it: short handle, then name.
fn label(snapshot: &PileSnapshot, handle: CollectionHandle) -> String {
    match named(snapshot, handle) {
        Some(name) => format!("blake3:{}  {name:?}", handle_hex(handle)),
        None => format!("blake3:{}  (no readable name)", handle_hex(handle)),
    }
}

/// Resolve the groups this invocation means, from either spelling.
fn plan_groups(
    snapshot: &PileSnapshot,
    rows: &[Enumerated],
    args: &MigrateArgs,
) -> Result<Vec<Group>> {
    let mut by_target: Vec<Group> = Vec::new();
    let mut push = |target: CollectionHandle, source: CollectionHandle| match by_target
        .iter_mut()
        .find(|group| group.target == target)
    {
        Some(group) => {
            if !group.sources.contains(&source) {
                group.sources.push(source);
            }
        }
        None => by_target.push(Group {
            target,
            sources: vec![source],
        }),
    };

    if let Some(path) = &args.plan {
        let text = std::fs::read_to_string(path)
            .map_err(|error| anyhow!("read plan {}: {error}", path.display()))?;
        for (source, target) in parse_plan(&text)? {
            let target = resolve(rows, &target)?;
            let source = resolve(rows, &source)?;
            if source == target {
                bail!("plan carries {} into itself", label(snapshot, target));
            }
            push(target, source);
        }
        // A chain has to be run as separate migrations: within one plan the
        // order is not expressed, and carrying A into B and B into C in the
        // wrong order silently under-delivers.
        let targets: BTreeSet<CollectionHandle> =
            by_target.iter().map(|group| group.target).collect();
        for group in &by_target {
            for source in &group.sources {
                if targets.contains(source) {
                    bail!(
                        "plan uses {} as both a source and a target; run the chain as separate \
                         migrations so each one's completeness can be proved",
                        label(snapshot, *source)
                    );
                }
            }
        }
        return Ok(by_target);
    }

    let Some(into) = args.into.as_deref() else {
        bail!("no target: pass --into, or --plan");
    };
    let target = resolve(rows, into)?;
    for reference in &args.from {
        let source = resolve(rows, reference)?;
        if source == target {
            bail!("source and target are the same collection");
        }
        push(target, source);
    }
    if args.siblings {
        let Some(name) = named(snapshot, target) else {
            bail!(
                "--siblings needs the target's name, and {} has no readable one; name the sources \
                 with --from",
                label(snapshot, target)
            );
        };
        for sibling in siblings_of(rows, target, &name) {
            push(target, sibling);
        }
    }
    if args.from.is_empty() && !args.siblings {
        bail!("no sources: pass --from, --siblings, or --plan");
    }
    if by_target.is_empty() {
        // `--siblings` on a name with no other generation is the answer "there
        // is nothing to carry", not a usage error. A cutover script should be
        // able to run it against every name and read zeroes where a name is
        // already settled.
        by_target.push(Group {
            target,
            sources: Vec::new(),
        });
    }
    Ok(by_target)
}

/// One row per source in the report table.
fn source_row(
    snapshot: &PileSnapshot,
    survey: &MigrationSurvey,
    source: &SourceSurvey,
    scope: Scope,
) -> Vec<String> {
    let carried: BTreeSet<CommitPair> = source.content(scope).copied().collect();
    let missing = carried.iter().filter(|pair| !survey.holds(pair)).count();
    vec![
        handle_hex(source.handle()),
        named(snapshot, source.handle()).unwrap_or_else(|| "-".to_owned()),
        source.pairs().to_string(),
        source.admitted().len().to_string(),
        if source.policy_readable() {
            source.unadmitted().len().to_string()
        } else {
            format!("{} (policy unreadable)", source.unadmitted().len())
        },
        missing.to_string(),
        source.other_records().to_string(),
        source.invalid_signatures().to_string(),
    ]
}

/// Print one target's survey: what it would move, and what it would write.
fn report(
    snapshot: &PileSnapshot,
    survey: &MigrationSurvey,
    scope: Scope,
    signer: VerifyingKey,
    signer_admitted: Option<bool>,
    list: bool,
) -> Result<()> {
    println!("target: {}", label(snapshot, survey.target()));
    println!(
        "        holds {} content pair(s), {} of them authored by this key",
        survey.target_pairs(),
        survey.target_pairs_by_signer(),
    );
    println!("signer: {}", hex::encode_upper(signer.to_bytes()));
    match signer_admitted {
        Some(true) => println!("        admitted as a writer on the target: yes"),
        Some(false) => println!(
            "        admitted as a writer on the target: NO — everything carried under this key \
             would be resident and invisible"
        ),
        None => println!(
            "        admitted as a writer on the target: unknown (this build cannot read the \
             target's descriptor)"
        ),
    }
    println!();

    let table: Vec<Vec<String>> = survey
        .sources()
        .iter()
        .map(|source| source_row(snapshot, survey, source, scope))
        .collect();
    print_table(
        &[
            "source",
            "name",
            "pairs",
            "admitted",
            "unadmitted",
            "missing",
            "other",
            "invalid",
        ],
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
        &table,
        "  ",
    );
    println!();

    let carried = survey.carried(scope);
    let missing = survey.missing(scope);
    let net_new = survey.net_new(scope);
    let redundant = survey.redundant(scope);
    let unresident = migration::unresident(snapshot, &net_new)
        .map_err(|error| anyhow!("probe carried content residency: {error}"))?;

    // One column for every figure, so the three that decide anything —
    // gain, net new, surplus — can be read against each other at a glance.
    let row = |label: &str, value: String| println!("  {label:<44}: {value}");
    row(
        "carrying",
        format!(
            "{} content pair(s) ({})",
            carried.len(),
            match scope {
                Scope::Admitted => "admitted by their own source",
                Scope::All => "including content the sources never admitted",
            }
        ),
    );
    row(
        "content the target does not yet hold",
        missing.len().to_string(),
    );
    row(
        "records this key would append (NET NEW)",
        net_new.len().to_string(),
    );
    row(
        "of those, adding no content the target lacks",
        format!(
            "{}{}",
            redundant.len(),
            if redundant.is_empty() {
                String::new()
            } else {
                "  <- this key did not author them; it re-signs content the target already holds"
                    .to_owned()
            }
        ),
    );
    row(
        "carried records naming absent content",
        format!("{unresident} (moved as claims)"),
    );
    if survey.target_invalid_signatures() > 0 {
        row(
            "target commits whose signature does not verify",
            format!(
                "{} (asserting nothing; their content still counts as missing)",
                survey.target_invalid_signatures()
            ),
        );
    }
    if list {
        for (data, metadata) in &net_new {
            println!(
                "    + data blake3:{} metadata blake3:{}",
                hex::encode(data.raw),
                hex::encode(metadata.raw)
            );
        }
    }
    Ok(())
}

/// Carry content between collections.
pub fn run_migrate(args: MigrateArgs) -> Result<()> {
    let key_path =
        triblespace_core::signing_key_file::resolve_path(args.key.as_deref(), &args.pile);
    let signing_key = triblespace_core::signing_key_file::load_existing(&key_path)
        .map_err(|error| anyhow!("load migrating signing key {}: {error}", key_path.display()))?;
    let signer = signing_key.verifying_key();

    let mut pile = open_refreshed(&args.pile)?;
    let res = (|| -> Result<()> {
        // One frozen view decides every collection, every record and every
        // figure printed. A concurrent append cannot change what this run
        // means, and the plan an operator approves is the plan that runs.
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        let rows = enumerate(&snapshot)?;
        let groups = plan_groups(&snapshot, &rows, &args)?;

        let mut surveys = Vec::new();
        let mut total_net_new = 0usize;
        let mut total_missing = 0usize;
        let mut unadmitted_total = 0usize;
        let mut cross_name = Vec::new();
        let mut inadmissible = Vec::new();

        for group in &groups {
            let survey = migration::survey(&snapshot, &group.sources, group.target, Some(signer))
                .map_err(|error| anyhow!("survey collection records: {error:?}"))?;
            let target_name = named(&snapshot, group.target);
            for source in &group.sources {
                let source_name = named(&snapshot, *source);
                if source_name.is_none() || source_name != target_name {
                    cross_name.push((*source, group.target));
                }
            }
            let signer_admitted = Collection::<SimpleArchive>::open(&snapshot, group.target)
                .ok()
                .and_then(|collection| collection.writer_is_admitted(&snapshot, signer).ok());
            if signer_admitted != Some(true) {
                inadmissible.push(group.target);
            }
            unadmitted_total += survey.unadmitted().len();
            surveys.push((survey, signer_admitted));
        }

        let scope = if args.carry_unadmitted {
            Scope::All
        } else {
            Scope::Admitted
        };

        for (index, (survey, signer_admitted)) in surveys.iter().enumerate() {
            if index > 0 {
                println!();
            }
            report(
                &snapshot,
                survey,
                scope,
                signer,
                *signer_admitted,
                args.list,
            )?;
            total_net_new += survey.net_new(scope).len();
            total_missing += survey.missing(scope).len();
        }
        if surveys.len() > 1 {
            println!();
            println!(
                "plan total: {total_net_new} record(s) to append across {} target(s), gaining \
                 {total_missing} content pair(s)",
                surveys.len()
            );
        }
        println!();

        // Refusals come after the full report: an operator who is about to be
        // stopped should still be able to read what the run would have done.
        if !cross_name.is_empty() && !args.allow_cross_name {
            for (source, target) in &cross_name {
                eprintln!(
                    "  {} is not a same-named generation of {}",
                    label(&snapshot, *source),
                    label(&snapshot, *target)
                );
            }
            bail!(
                "{} source(s) do not share the target's name. Carrying one collection's content \
                 into an unrelated one cannot be undone; pass --allow-cross-name if that is what \
                 you mean",
                cross_name.len()
            );
        }
        if !inadmissible.is_empty() && !args.allow_inadmissible_signer {
            bail!(
                "this key is not an admitted writer on {} of the target(s). Records carried under \
                 it would be resident and read as absent — the silence this tooling exists to \
                 break. Grant it first (`trible pile collection grant-write`), or pass \
                 --allow-inadmissible-signer if the grant is coming later",
                inadmissible.len()
            );
        }
        if unadmitted_total > 0 && !args.carry_unadmitted && !args.skip_unadmitted {
            bail!(
                "{unadmitted_total} content pair(s) in the sources were asserted only by authors \
                 the source itself does not admit, or by a source whose policy this build cannot \
                 read. They read as absent today. Carrying them re-signs them under this key and \
                 makes them admitted content of the target, which is a promotion, not a move. Say \
                 which you mean: --carry-unadmitted or --skip-unadmitted"
            );
        }

        if !args.apply {
            println!("dry run: nothing appended. Re-run with --apply to write.");
            return Ok(());
        }

        let before = file_len(&args.pile);
        drop(snapshot);
        let mut appended = 0usize;
        for ((survey, _), group) in surveys.iter().zip(groups.iter()) {
            appended += migration::carry(
                &mut pile,
                group.target,
                &signing_key,
                &survey.net_new(scope),
            )
            .map_err(|error| anyhow!("carry into {}: {error}", handle_hex(group.target)))?;
        }
        // Flush before measuring: an unflushed append has not reached the
        // file yet, and a byte figure that is not the file's is not evidence.
        pile.flush()
            .map_err(|error| anyhow!("flush appended records: {error:?}"))?;
        let after = file_len(&args.pile);
        println!(
            "appended {appended} record(s); the pile grew by {} byte(s)",
            after.saturating_sub(before)
        );

        // The assertion the old adopt never made: re-read the store and check
        // that every pair the sources offered is now committed to the target.
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        let mut outstanding = 0usize;
        for group in &groups {
            let after = migration::survey(&snapshot, &group.sources, group.target, Some(signer))
                .map_err(|error| anyhow!("verify collection records: {error:?}"))?;
            let left = after.missing(scope).len();
            outstanding += left;
            println!(
                "verified {}: {} content pair(s) still unreached",
                handle_hex(group.target),
                left
            );
        }
        println!();
        println!(
            "note: concatenation is the pile merge — `cat a.pile >> b.pile` appends both sides in \
             full, duplicates included, and this command does not compact. If this pile was built \
             that way, `trible pile diagnose` counts the duplicates and `trible pile compact` \
             reclaims them."
        );
        if outstanding > 0 {
            bail!(
                "{outstanding} content pair(s) are still held only by a source. The migration is \
                 not complete; re-run, and check `trible pile collection reconcile`"
            );
        }
        Ok(())
    })();
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close_res)
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// Prove a target holds everything its sources do, by content.
///
/// The standalone half of the tool: it takes no key, appends nothing, and can
/// be pointed at a migration somebody else ran months ago.
pub fn run_reconcile_exact(
    pile: &mut Pile,
    target_reference: &str,
    from: &[String],
    list: bool,
) -> Result<()> {
    let snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
    let rows = enumerate(&snapshot)?;
    let target = resolve(&rows, target_reference)?;

    let sources: Vec<CollectionHandle> = if from.is_empty() {
        let Some(name) = named(&snapshot, target) else {
            bail!(
                "{} has no readable name, so its same-named generations cannot be found; name the \
                 sources with --from",
                label(&snapshot, target)
            );
        };
        siblings_of(&rows, target, &name)
    } else {
        from.iter()
            .map(|reference| resolve(&rows, reference))
            .collect::<Result<Vec<_>>>()?
    };

    println!("target: {}", label(&snapshot, target));
    if sources.is_empty() {
        println!(
            "no other collection in this pile claims that name; there is nothing it could be \
             missing"
        );
        return Ok(());
    }

    let survey = migration::survey(&snapshot, &sources, target, None)
        .map_err(|error| anyhow!("survey collection records: {error:?}"))?;
    println!("        holds {} content pair(s)", survey.target_pairs());
    println!();

    let mut table = Vec::new();
    // Deduplicated across sources: two retired generations holding the same
    // payload are one piece of content the target is missing, not two.
    let mut missing_admitted: BTreeSet<CommitPair> = BTreeSet::new();
    let mut missing_unadmitted: BTreeSet<CommitPair> = BTreeSet::new();
    let mut unreadable = Vec::new();
    let mut listed: Vec<String> = Vec::new();
    for source in survey.sources() {
        let admitted_missing: BTreeSet<CommitPair> = source
            .admitted()
            .iter()
            .copied()
            .filter(|pair| !survey.holds(pair))
            .collect();
        let unadmitted_missing: BTreeSet<CommitPair> = source
            .unadmitted()
            .iter()
            .copied()
            .filter(|pair| !survey.holds(pair))
            .collect();
        missing_admitted.extend(admitted_missing.iter().copied());
        missing_unadmitted.extend(unadmitted_missing.iter().copied());
        if !source.policy_readable() {
            unreadable.push(source.handle());
        }
        table.push(vec![
            handle_hex(source.handle()),
            named(&snapshot, source.handle()).unwrap_or_else(|| "-".to_owned()),
            source.pairs().to_string(),
            source.admitted().len().to_string(),
            source.unadmitted().len().to_string(),
            admitted_missing.len().to_string(),
            unadmitted_missing.len().to_string(),
        ]);
        if list {
            for (data, metadata) in &admitted_missing {
                listed.push(format!(
                    "  {} missing data blake3:{} metadata blake3:{}",
                    handle_hex(source.handle()),
                    hex::encode(data.raw),
                    hex::encode(metadata.raw)
                ));
            }
        }
    }
    print_table(
        &[
            "source",
            "name",
            "pairs",
            "admitted",
            "unadmitted",
            "MISSING",
            "missing (unadmitted)",
        ],
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
        &table,
        "  ",
    );
    println!();
    for line in &listed {
        println!("{line}");
    }
    if !listed.is_empty() {
        println!();
    }
    for handle in &unreadable {
        println!(
            "  note: this build cannot read the WRITE policy of {}, so none of its content can be \
             shown to be admitted",
            handle_hex(*handle)
        );
    }
    let unsourced = survey.unsourced();
    if !unsourced.is_empty() {
        println!(
            "  note: the target holds {} content pair(s) that none of these sources does. Before \
             a new generation goes live that is content the migrating key introduced rather than \
             moved; afterwards it is simply its own writers at work.",
            unsourced.len()
        );
    }
    if !missing_unadmitted.is_empty() {
        println!(
            "  note: {} further pair(s) are absent from the target and were \
             never admitted by their own source either. They read as absent on both sides; \
             carrying them forward would promote them.",
            missing_unadmitted.len()
        );
    }
    if missing_admitted.is_empty() {
        println!(
            "complete: all {} content pair(s) these {} source(s) admit are committed to the target",
            survey.carried(Scope::Admitted).len(),
            survey.sources().len()
        );
        return Ok(());
    }
    bail!(
        "{} content pair(s) are held by a source and absent from the target. The \
         migration is incomplete; `trible pile collection migrate --into {} --siblings` carries \
         them forward",
        missing_admitted.len(),
        handle_hex(target)
    );
}

/// How many collections hold commits under a name this build cannot read.
///
/// The sweep groups by name, so a collection with no readable name is invisible
/// to it entirely — and that is where the largest arrears have historically
/// been. Saying how many were skipped turns a silent blind spot into a number.
pub fn unnamed_with_commits(rows: &[Enumerated]) -> usize {
    rows.iter()
        .filter(|row| row.refs.commits > 0)
        .filter(|row| !matches!(anchor(&row.fields), Anchor::Root(Ok(_))))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_is_source_arrow_target_lines() {
        let plan = parse_plan(
            "# the 2026-08-28 generation\nblake3:0f  ->  wiki\n\nname:wiki -> blake3:ab # trailing\n",
        )
        .unwrap();
        assert_eq!(
            plan,
            vec![
                ("blake3:0f".to_owned(), "wiki".to_owned()),
                ("name:wiki".to_owned(), "blake3:ab".to_owned()),
            ]
        );
    }

    #[test]
    fn a_plan_line_without_an_arrow_is_refused_by_line_number() {
        let error = parse_plan("wiki\n").unwrap_err().to_string();
        assert!(error.contains("line 1"), "{error}");
    }

    #[test]
    fn an_empty_plan_is_refused_rather_than_silently_doing_nothing() {
        assert!(parse_plan("# nothing here\n").is_err());
    }
}
