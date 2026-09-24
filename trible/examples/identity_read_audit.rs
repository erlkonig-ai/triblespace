//! Compare old/new endpoint READ admission without changing the pile.
//!
//! Pass `--pile PATH` (or PILE), a selection file containing one complete
//! 64-hex collection handle per line (optional `blake3:` prefix), and all six
//! public endpoint keys through the named options. Blank lines and lines
//! beginning with `#` are ignored. No private keys are opened.
//!
//! Output is TSV, with one row per selected collection and old/new node pair.
//! `lost_read=true` means exactly `old_read=true,new_read=false`. Observation
//! failures produce `unknown`, never `false`. Exit status is 0 for no observed
//! losses, 1 for a loss, and 2 for unknown observations or operational errors.
//!
//! Admission is local to one coherent resident snapshot, not a claim about
//! remote evidence, reachability, or global revocation. The core audience API
//! strictly verifies proof prefixes and resolves their capability definitions;
//! invalid proofs and unavailable individual definitions grant nothing. AUTH
//! delegation alone is not READ invocation. No grants, writes, maintenance, or
//! network discovery are performed. Pile's existing open API uses an
//! append-capable descriptor, but this example only snapshots and closes it.

use std::fmt::Debug;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use triblespace_core::collection::{
    collection_read_audience, CollectionAdmissionError, CollectionHandle, CollectionReadAudience,
};
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::SnapshotSource;

#[derive(Parser)]
#[command(about = "Read-only comparison of resident READ admission for endpoint cutover")]
struct Args {
    /// Existing pile to observe; never created or repaired.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// File containing selected full collection handles, one per line.
    selections: PathBuf,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    mac_old: VerifyingKey,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    mac_new: VerifyingKey,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    sky_old: VerifyingKey,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    sky_new: VerifyingKey,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    stars_old: VerifyingKey,
    #[arg(long, value_name = "PUBLIC_KEY_HEX", value_parser = parse_public_key)]
    stars_new: VerifyingKey,
}

type EndpointPair = (&'static str, VerifyingKey, VerifyingKey);

#[derive(Default)]
struct Counts {
    lost_pairs: usize,
    unknown_pairs: usize,
}

fn parse_public_key(value: &str) -> Result<VerifyingKey, String> {
    let mut raw = [0; 32];
    hex::decode_to_slice(value, &mut raw)
        .map_err(|error| format!("expected a complete 64-hex public endpoint key: {error}"))?;
    VerifyingKey::from_bytes(&raw).map_err(|error| format!("invalid public endpoint key: {error}"))
}

fn read_selections(path: &Path) -> Result<Vec<CollectionHandle>> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("read selection file {}", path.display()))?;
    let mut collections = Vec::new();
    for (line, value) in input.lines().enumerate() {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let mut raw = [0; 32];
        hex::decode_to_slice(value.strip_prefix("blake3:").unwrap_or(value), &mut raw)
            .with_context(|| format!("expected a full collection handle on line {}", line + 1))?;
        collections.push(CollectionHandle::new(raw));
    }
    if collections.is_empty() {
        return Err(anyhow!("selection file contains no collection handles"));
    }
    Ok(collections)
}

fn state(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn lost_read(old: Option<bool>, new: Option<bool>) -> Option<bool> {
    match (old, new) {
        (Some(old), Some(new)) => Some(old && !new),
        _ => None,
    }
}

fn admitted(audience: &CollectionReadAudience, endpoint: &VerifyingKey) -> bool {
    match audience {
        CollectionReadAudience::Open => true,
        CollectionReadAudience::Restricted(subjects) => subjects.contains(endpoint),
    }
}

fn emit(
    output: &mut impl Write,
    collection: CollectionHandle,
    pairs: &[EndpointPair],
    audience: Option<&CollectionReadAudience>,
    error: &str,
    counts: &mut Counts,
) -> io::Result<()> {
    let error = error.replace(['\t', '\r', '\n'], " ");
    for (node, old_endpoint, new_endpoint) in pairs {
        let old = audience.map(|audience| admitted(audience, old_endpoint));
        let new = audience.map(|audience| admitted(audience, new_endpoint));
        let lost = lost_read(old, new);
        match lost {
            Some(true) => counts.lost_pairs += 1,
            None => counts.unknown_pairs += 1,
            Some(false) => {}
        }
        writeln!(
            output,
            "{}\t{node}\t{}\t{}\t{}\t{}\t{}\t{error}",
            hex::encode(collection.raw),
            hex::encode(old_endpoint.as_bytes()),
            hex::encode(new_endpoint.as_bytes()),
            state(old),
            state(new),
            state(lost),
        )?;
    }
    Ok(())
}

fn observation_error<P: Debug, G: Debug>(error: CollectionAdmissionError<P, G>) -> String {
    // Debug retains the typed Descriptor/Get/Invalid or Evidence/Proofs cause.
    format!("{error:?}")
}

fn audit_snapshot(
    output: &mut impl Write,
    snapshot: &PileSnapshot,
    collections: &[CollectionHandle],
    pairs: &[EndpointPair],
    counts: &mut Counts,
) -> io::Result<()> {
    for collection in collections {
        match collection_read_audience(snapshot, *collection) {
            Ok(audience) => emit(output, *collection, pairs, Some(&audience), "", counts)?,
            Err(error) => emit(
                output,
                *collection,
                pairs,
                None,
                &observation_error(error),
                counts,
            )?,
        }
    }
    Ok(())
}

fn emit_unknown(
    output: &mut impl Write,
    collections: &[CollectionHandle],
    pairs: &[EndpointPair],
    error: &str,
    counts: &mut Counts,
) -> io::Result<()> {
    for collection in collections {
        emit(output, *collection, pairs, None, error, counts)?;
    }
    Ok(())
}

fn run(args: Args) -> Result<ExitCode> {
    let collections = read_selections(&args.selections)?;
    let pairs = [
        ("mac", args.mac_old, args.mac_new),
        ("sky", args.sky_old, args.sky_new),
        ("stars", args.stars_old, args.stars_new),
    ];
    let mut counts = Counts::default();
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "collection\tnode\told_endpoint\tnew_endpoint\told_read\tnew_read\tlost_read\terror"
    )?;
    match Pile::open(&args.pile) {
        Ok(mut pile) => {
            // snapshot() refreshes once, then all queries use that same prefix.
            let observed = match pile.snapshot() {
                Ok(snapshot) => {
                    audit_snapshot(&mut output, &snapshot, &collections, &pairs, &mut counts)
                }
                Err(error) => emit_unknown(
                    &mut output,
                    &collections,
                    &pairs,
                    &format!("PileSnapshot({error:?})"),
                    &mut counts,
                ),
            };
            // Close even if snapshot acquisition or output failed. No operation
            // above dirties the handle, so close has no pending writes to flush.
            let closed = pile.close();
            observed?;
            closed.context("close observed pile")?;
        }
        Err(error) => emit_unknown(
            &mut output,
            &collections,
            &pairs,
            &format!("PileOpen({error:?})"),
            &mut counts,
        )?,
    }
    output.flush()?;
    eprintln!(
        "selected={} pairs={} lost_read={} unknown={} (resident evidence only)",
        collections.len(),
        collections.len() * pairs.len(),
        counts.lost_pairs,
        counts.unknown_pairs,
    );
    Ok(if counts.unknown_pairs != 0 {
        ExitCode::from(2)
    } else if counts.lost_pairs != 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("identity READ audit failed: {error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lost_read;

    #[test]
    fn only_admitted_to_unadmitted_is_a_loss() {
        assert_eq!(lost_read(Some(true), Some(false)), Some(true));
        assert_eq!(lost_read(Some(true), Some(true)), Some(false));
        assert_eq!(lost_read(Some(false), Some(true)), Some(false));
        assert_eq!(lost_read(Some(false), Some(false)), Some(false));
    }

    #[test]
    fn unknown_observations_are_not_denials() {
        for known in [None, Some(false), Some(true)] {
            assert_eq!(lost_read(None, known), None);
            assert_eq!(lost_read(known, None), None);
        }
    }
}
