//! `trible-migrate <SOURCE> upgrade --into <DEST> [--decisions <FILE>]`:
//! bring an old pile to the current format by running to a fixpoint.
//!
//! Each run reads what is left from the piles themselves, never from a
//! record of earlier runs: the source's record kinds choose the path, the
//! destination's own state says which steps still change anything, and a
//! choice the operator recorded in the decisions file is applied by running
//! its step again, which leaves the pile byte-identical when it was already
//! applied. The source is only read.
//!
//! Two paths can be driven. A pile with no opaque frames (a released v0.46.4
//! pile, or any later one whose retired kinds reframe understands) is
//! reframed into the destination, given its record-kind descriptions, and
//! then each live legacy branch becomes a native collection once the
//! decisions file names its collection and signing key. A deployed /32 pile
//! needs `canonical`, which needs an operator-frozen copy, its hash, the
//! signing key and every foreign author's refresh, so the driver stops and
//! says exactly that. Anything else stops and names the frames that have no
//! path forward. Exit status: 0 nothing left, 2 a choice is needed, 3 no path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde_json::Value;
use triblespace_core::repo::SnapshotSource;

/// Exit status when the operator must record a choice and rerun.
pub const EXIT_CHOICE_NEEDED: i32 = 2;
/// Exit status when the pile holds frames no migration in this binary accepts.
pub const EXIT_NO_PATH: i32 = 3;

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// The upgraded pile. Created by the first run; later runs continue it.
    #[arg(long = "into")]
    into: PathBuf,
    /// JSON file of recorded choices, e.g.
    /// {"branches": {"<32-hex branch id>": {"collection": "events",
    /// "signing_key": "/path/self.key", "authority": "<64-hex>"}}}.
    /// A branch to leave unmigrated: {"skip": "why"}.
    #[arg(long)]
    decisions: Option<PathBuf>,
}

/// What the raw records of one pile say about the path it needs.
#[derive(Default)]
struct Kinds {
    /// /32 kinds (COMMIT, MERGE, DERIVE, MAP of the deployed format).
    deployed32: usize,
    /// Every other opaque frame, by its kind bytes in hex.
    dead_end: BTreeMap<String, usize>,
    /// Legacy branches whose last pin record is a head, in id order.
    live_branches: Vec<String>,
}

fn kinds(path: &Path) -> Result<Kinds> {
    let inspection = crate::migration::inspect(path)?;
    Ok(Kinds {
        deployed32: inspection.requirements.iter().filter_map(|requirement| {
            match requirement {
                crate::migration::Requirement::Canonical { records } => Some(*records),
                _ => None,
            }
        }).sum(),
        dead_end: inspection.unsupported.into_iter().map(|unsupported| {
            (hex::encode_upper(unsupported.kind.as_bytes()), unsupported.occurrences)
        }).collect(),
        live_branches: inspection.legacy_branches.into_iter()
            .map(|id| format!("{id:X}")).collect(),
    })
}

enum BranchChoice {
    Migrate {
        collection: String,
        signing_key: PathBuf,
        authority: Option<String>,
    },
    Skip(String),
}

fn decisions(path: Option<&Path>) -> Result<BTreeMap<String, BranchChoice>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read decisions {}", path.display()))?;
    let root: Value = serde_json::from_str(&text)
        .with_context(|| format!("decisions {} is not JSON", path.display()))?;
    let mut choices = BTreeMap::new();
    let Some(branches) = root.get("branches") else {
        return Ok(choices);
    };
    let branches = branches
        .as_object()
        .ok_or_else(|| anyhow!("decisions: \"branches\" must be an object"))?;
    for (id, choice) in branches {
        let id = id.trim().to_ascii_uppercase();
        let field = |name: &str| choice.get(name).and_then(Value::as_str).map(str::to_owned);
        let parsed = if let Some(reason) = field("skip") {
            BranchChoice::Skip(reason)
        } else {
            BranchChoice::Migrate {
                collection: field("collection")
                    .ok_or_else(|| anyhow!("decisions: branch {id} needs \"collection\" or \"skip\""))?,
                signing_key: field("signing_key")
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow!("decisions: branch {id} needs \"signing_key\""))?,
                authority: field("authority"),
            }
        };
        choices.insert(id, parsed);
    }
    Ok(choices)
}

fn file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Run to the fixpoint. Returns the process exit status.
pub fn run(source: &Path, args: UpgradeArgs) -> Result<i32> {
    let UpgradeArgs { into, decisions: decisions_path } = args;
    let choices = decisions(decisions_path.as_deref())?;

    // The path is chosen from the source; a later run continues the
    // destination, whose own state then answers every question.
    let source_kinds = kinds(source)?;
    if !source_kinds.dead_end.is_empty() {
        println!("No path forward: {} holds frames no migration here accepts:", source.display());
        for (kind, count) in &source_kinds.dead_end {
            println!("  {count} frame(s) of kind {kind}");
        }
        println!("The source was only read. `trible pile diagnose census` lists them by offset.");
        return Ok(EXIT_NO_PATH);
    }
    if source_kinds.deployed32 != 0 {
        println!(
            "{} is a deployed /32 pile ({} frame(s) of the /32 kinds). It needs `canonical`, \
             which this driver does not run on its own because it needs:",
            source.display(),
            source_kinds.deployed32
        );
        println!("  - an operator-frozen copy of the pile and its full BLAKE3 (--source-hash),");
        println!("  - the signing key that re-signs its assertions (--key),");
        println!("  - a `canonical-refresh` pile from every foreign author (--refresh).");
        println!(
            "Run `trible-migrate <FROZEN COPY> canonical --into <DEST> --key <KEY> \
             --source-hash <BLAKE3> [--refresh <PILE>]...` (and `run monotone-wants` on the \
             copy first if retired WANT history should become live demand), then point \
             `upgrade` at the canonical pile."
        );
        return Ok(EXIT_CHOICE_NEEDED);
    }

    if into.exists() {
        println!("continuing {} (reframe already ran)", into.display());
    } else {
        super::reframe(&source.to_path_buf(), &into)?;
    }

    // Record-kind descriptions: additive and idempotent; the census says
    // whether any is missing.
    let missing = {
        let mut pile = super::super::open_refreshed(&into)?;
        let census = pile
            .snapshot()
            .context("snapshot upgraded pile")
            .and_then(|snapshot| super::record_kind_description_census(&snapshot));
        let close = pile.close().map_err(|error| anyhow!("close pile: {error:?}"));
        let (_, missing) = census?;
        close?;
        missing
    };
    if missing != 0 {
        super::migrate_record_kind_descriptions(&into, false)?;
    } else {
        println!("record-kind descriptions: all resident");
    }

    let upgraded = kinds(&into)?;
    let mut pending = Vec::new();
    for id in &upgraded.live_branches {
        match choices.get(id) {
            None => pending.push(id.clone()),
            Some(BranchChoice::Skip(reason)) => {
                println!("branch {id}: left as a legacy branch ({reason})")
            }
            Some(BranchChoice::Migrate {
                collection,
                signing_key,
                authority,
            }) => {
                let before = file_len(&into)?;
                super::branch_to_collection::run(
                    into.clone(),
                    id.clone(),
                    collection.clone(),
                    authority.clone(),
                    signing_key.clone(),
                )
                .with_context(|| format!("branch {id} -> collection {collection:?}"))?;
                if file_len(&into)? == before {
                    println!("branch {id}: already in collection {collection:?}, nothing appended");
                } else {
                    println!("branch {id}: copied into collection {collection:?}");
                }
            }
        }
    }

    if !pending.is_empty() {
        println!();
        println!(
            "{} live legacy branch(es) need a choice: the collection each becomes (its name is \
             part of its permanent identity), the signing key that publishes it, and optionally \
             a different trust root. Record them in the decisions file and rerun:",
            pending.len()
        );
        let names = super::branch_to_collection::active_branch_names(&into).unwrap_or_default();
        for id in &pending {
            match names.get(id) {
                Some(name) => println!("  branch {id}, named {name:?}"),
                None => println!("  branch {id} (its name could not be read)"),
            }
        }
        let template: serde_json::Map<String, Value> = pending
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    serde_json::json!({"collection": "<name>", "signing_key": "<path to key>"}),
                )
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"branches": template}))?
        );
        println!("(or {{\"skip\": \"<why>\"}} to leave a branch as it is)");
        return Ok(EXIT_CHOICE_NEEDED);
    }

    println!();
    println!("Fixpoint reached: nothing left to do for {}.", into.display());
    println!(
        "Not detectable from the pile: whether old text attributes were stored as ShortString. \
         If so, name them with `trible-migrate {} shortstring-to-utf8`.",
        into.display()
    );
    Ok(0)
}
