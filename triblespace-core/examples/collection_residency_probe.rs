//! Count-only, resident snapshot diagnostic; never maintains or fetches.
//!
//! Usage: collection_residency_probe PILE [--limit N] MODE HANDLE [MODE HANDLE ...]
//! Modes: root (SimpleArchive), succinct, rank9. Handles are exact descriptor
//! hashes, optionally prefixed with `blake3:`. One frozen snapshot serves every
//! requested pair. `--limit` bounds each example/selected-cover list (default 8).
//!
//! `raw_records` means distinct current native records before admission, not
//! physical frame multiplicity or retired opaque equations. Root presence is a
//! structural index lookup. The public representation-dependency hook may read
//! and hash resident bytes; it does not validate the mathematical equation.
//! `snapshot.collection` resolves a cover but this probe never materializes its
//! facts. No blob payload, policy, key, or proof bytes are printed.
//!
//! Pile::open currently requires append permission even for snapshot readers.
//! This program takes one snapshot and immediately closes the unmodified Pile;
//! all diagnostic work uses only that immutable snapshot. It never truncates,
//! repairs, flushes a dirty handle, or calls a publication/acquisition API.

use std::collections::BTreeSet;
use std::error::Error;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace_core::collection::{
    admitted_record_witnesses, Collection, CollectionData, CollectionEncoding, CollectionHandle,
    CollectionRead, CollectionRealizationError, CollectionRecord, CollectionRecordSelector,
    CollectionSnapshotExt, Support,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::{BlobStoreList, SnapshotSource, StoreSnapshot};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn output(record: CollectionRecord) -> CollectionData {
    match record {
        CollectionRecord::Commit(record) => record.data(),
        CollectionRecord::Merge(record) => record.result(),
        CollectionRecord::Derive(record) => record.output(),
    }
}

fn error_class(error: &(dyn Error + 'static)) -> &'static str {
    match error.downcast_ref::<CollectionRealizationError>() {
        Some(CollectionRealizationError::Storage { .. }) => "storage",
        Some(CollectionRealizationError::InvalidCover(_)) => "invalid_cover",
        Some(CollectionRealizationError::Resolution(_)) => "resolution",
        Some(CollectionRealizationError::IncompleteCover { .. }) => "incomplete_cover",
        Some(CollectionRealizationError::UnauthorizedProducer { .. }) => "unauthorized_producer",
        Some(CollectionRealizationError::Derive { .. }) => "derive",
        Some(CollectionRealizationError::Merge { .. }) => "merge",
        Some(CollectionRealizationError::MissingDependency { .. }) => "missing_dependency",
        Some(CollectionRealizationError::UnrepresentableCover { .. }) => "unrepresentable_cover",
        Some(CollectionRealizationError::Stalled { .. }) => "stalled",
        None => "other",
    }
}

fn examples(label: &str, values: &BTreeSet<CollectionData>, limit: usize) {
    for value in values.iter().take(limit) {
        println!("{label}=blake3:{}", hex::encode(value.raw));
    }
    println!("{label}_omitted={}", values.len().saturating_sub(limit));
}

fn availability<E: CollectionEncoding>(
    snapshot: &PileSnapshot,
    label: &str,
    outputs: &BTreeSet<CollectionData>,
    limit: usize,
) -> Result<()> {
    let mut root_missing = BTreeSet::new();
    let mut complete = 0;
    let mut incomplete = 0;
    let mut errors = 0;
    let mut missing_dependencies = BTreeSet::new();
    let mut pairs = Vec::new();
    let mut error_roots = BTreeSet::new();
    for member in outputs {
        if !snapshot.contains_blob(Handle::<E>::from_hash(*member))? {
            root_missing.insert(*member);
            continue;
        }
        match E::missing_representation_dependencies(*member, snapshot) {
            Ok(missing) if missing.is_empty() => complete += 1,
            Ok(missing) => {
                incomplete += 1;
                for dependency in missing {
                    missing_dependencies.insert(dependency);
                    if pairs.len() < limit {
                        pairs.push((*member, dependency));
                    }
                }
            }
            Err(_) => {
                // Do not print an encoding error's arbitrary text: the root
                // handle is sufficient for a later explicitly scoped audit.
                errors += 1;
                error_roots.insert(*member);
            }
        }
    }
    println!("{label}_outputs={}", outputs.len());
    println!(
        "{label}_roots_present={}",
        outputs.len() - root_missing.len()
    );
    println!("{label}_roots_missing={}", root_missing.len());
    println!("{label}_representation_complete={complete}");
    println!("{label}_representation_incomplete={incomplete}");
    println!("{label}_representation_errors={errors}");
    println!(
        "{label}_missing_dependencies={}",
        missing_dependencies.len()
    );
    examples(&format!("{label}_missing_root"), &root_missing, limit);
    examples(&format!("{label}_error_root"), &error_roots, limit);
    examples(
        &format!("{label}_missing_dependency"),
        &missing_dependencies,
        limit,
    );
    for (root, dependency) in pairs {
        println!(
            "{label}_missing_dependency_pair=blake3:{} blake3:{}",
            hex::encode(root.raw),
            hex::encode(dependency.raw),
        );
    }
    Ok(())
}

fn inspect<E: CollectionEncoding>(
    snapshot: &PileSnapshot,
    handle: CollectionHandle,
    limit: usize,
) -> Result<()> {
    let records =
        snapshot.select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            handle,
        )]))?;
    let mut commits = 0;
    let mut merges = 0;
    let mut derives = 0;
    let mut outputs = BTreeSet::new();
    let mut missing_witnesses = BTreeSet::new();
    for record in &records {
        match record {
            CollectionRecord::Commit(_) => commits += 1,
            CollectionRecord::Merge(_) => merges += 1,
            CollectionRecord::Derive(_) => derives += 1,
        }
        outputs.insert(output(*record));
        for witness in record.record_references() {
            if snapshot.record(witness)?.is_none() {
                missing_witnesses.insert(witness);
            }
        }
    }
    println!("raw_records={}", records.len());
    println!("raw_commits={commits} raw_merges={merges} raw_derives={derives}");
    println!("raw_outputs={}", outputs.len());
    println!(
        "immediate_missing_record_witnesses={}",
        missing_witnesses.len()
    );
    for witness in missing_witnesses.iter().take(limit) {
        println!("missing_record_witness={}", hex::encode(witness.raw()));
    }
    println!(
        "missing_record_witness_omitted={}",
        missing_witnesses.len().saturating_sub(limit),
    );
    drop(records);
    println!("phase=admitted_record_witnesses");
    io::stdout().flush()?;
    let started = Instant::now();
    let witnesses = admitted_record_witnesses(snapshot, handle)?;
    println!("admitted_witnesses={}", witnesses.len());
    println!("admission_elapsed_ms={}", started.elapsed().as_millis());
    let admitted_outputs: BTreeSet<_> = witnesses
        .iter()
        .map(|(record, _)| output(*record))
        .collect();
    let support: Option<Support> = if let Some((_, first)) = witnesses.first() {
        let foundation = first.collection();
        if witnesses
            .iter()
            .any(|(_, support)| support.collection() != foundation)
        {
            return Err("admitted witnesses disagree on their foundation".into());
        }
        // Deduplicate before the bulk Cover constructor, rather than folding
        // thousands of overlapping supports through repeated trie unions.
        let members: BTreeSet<_> = witnesses
            .iter()
            .flat_map(|(_, support)| support.members())
            .collect();
        Some(foundation.cover(members))
    } else {
        None
    };
    println!(
        "admitted_union_support={}",
        support.as_ref().map_or(0, Support::len)
    );
    if let Some(support) = &support {
        println!(
            "foundation=blake3:{}",
            hex::encode(support.collection().handle().raw)
        );
    }
    drop(witnesses);

    // Scan each exact payload at most once; reuse the snapshot's validation
    // cache when ordinary cover resolution subsequently reads it.
    println!("phase=representation_availability");
    io::stdout().flush()?;
    availability::<E>(snapshot, "admitted", &admitted_outputs, limit)?;
    let unadmitted_outputs = outputs.difference(&admitted_outputs).copied().collect();
    availability::<E>(snapshot, "unadmitted", &unadmitted_outputs, limit)?;
    let collection = Collection::<E>::open(snapshot, handle)?;
    println!("phase=snapshot_collection");
    io::stdout().flush()?;
    let started = Instant::now();
    let observed = snapshot.collection(collection)?;
    println!("projection_elapsed_ms={}", started.elapsed().as_millis());
    println!("selected_cover={}", observed.cover().len());
    println!("selected_support={}", observed.support().len());
    for member in observed.cover().members().take(limit) {
        println!("selected_cover_handle=blake3:{}", hex::encode(member.raw));
    }
    println!(
        "selected_cover_handle_omitted={}",
        observed.cover().len().saturating_sub(limit)
    );
    if let Some(support) = support {
        let missing = support.difference(observed.support())?;
        let missing: BTreeSet<_> = missing
            .members()
            .map(Handle::<SimpleArchive>::to_hash)
            .collect();
        println!("admitted_support_unrepresented={}", missing.len());
        examples("unrepresented_support_member", &missing, limit);
    } else {
        println!("admitted_support_unrepresented=0");
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: collection_residency_probe PILE [--limit N] MODE HANDLE [MODE HANDLE ...]; modes: root, succinct, rank9";
    let path = args.next().ok_or(usage)?;
    let mut limit = 8;
    let mut selected = Vec::new();
    while let Some(mode) = args.next() {
        if mode == "--limit" {
            limit = args.next().ok_or(usage)?.parse::<usize>()?;
            if limit > 256 {
                return Err("--limit must be at most 256".into());
            }
            continue;
        }
        if !matches!(mode.as_str(), "root" | "succinct" | "rank9") {
            return Err(usage.into());
        }
        let raw = args.next().ok_or(usage)?;
        let raw = raw.strip_prefix("blake3:").unwrap_or(&raw);
        let mut bytes = [0; 32];
        hex::decode_to_slice(raw, &mut bytes)?;
        selected.push((mode, Inline::new(bytes)));
    }
    if selected.is_empty() {
        return Err(usage.into());
    }

    println!("phase=freeze_snapshot");
    io::stdout().flush()?;
    let mut pile = Pile::open(Path::new(&path))?;
    let snapshot = pile.snapshot();
    let closed = pile.close();
    let snapshot = snapshot?;
    closed?;
    println!("snapshot_instant={}", snapshot.instant());
    let mut failed = false;
    for (mode, handle) in selected {
        println!("collection=blake3:{} mode={mode}", hex::encode(handle.raw));
        let result = match mode.as_str() {
            "root" => inspect::<SimpleArchive>(&snapshot, handle, limit),
            "succinct" => inspect::<SuccinctArchiveBlob>(&snapshot, handle, limit),
            "rank9" => inspect::<Rank9AcceleratedSuccinctArchiveBlob>(&snapshot, handle, limit),
            _ => unreachable!("modes checked before opening the pile"),
        };
        if let Err(error) = result {
            failed = true;
            // Error class only: even malformed descriptors must not make a
            // diagnostic print arbitrary content from the selected collection.
            println!("collection_status=error");
            eprintln!(
                "collection {} diagnostic failed ({})",
                hex::encode(handle.raw),
                error_class(error.as_ref())
            );
        } else {
            println!("collection_status=ok");
        }
        io::stdout().flush()?;
    }
    if failed {
        Err("one or more selected collection diagnostics failed".into())
    } else {
        Ok(())
    }
}
