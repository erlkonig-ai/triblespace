//! Incrementally query a growing collection through exact Succinct full and
//! changed snapshots.
//!
//! Run with: `cargo run --example collection_pattern_changes`

use std::error::Error;
use std::io;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use rand::rngs::OsRng;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace::core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshot, CollectionSnapshotExt,
    CollectionStoreExt,
};
use triblespace::core::examples::literature;
use triblespace::core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace::prelude::*;

fn rebuild(
    full: &UnionArchive<OrderedUniverse>,
    consume: &mut impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut titles = Vec::new();
    for title in find!(
        title: String,
        pattern!(full, [
            { _?author @ literature::firstname: "Frank" },
            { _?book @
                literature::author: _?author,
                literature::title: ?title
            }
        ])
    ) {
        consume(&title)?;
        titles.push(title);
    }
    Ok(titles)
}

fn changes(
    full: &UnionArchive<OrderedUniverse>,
    changed: &UnionArchive<OrderedUniverse>,
    consume: &mut impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut titles = Vec::new();
    for title in find!(
        title: String,
        pattern_changes!(full, changed, [
            { _?author @ literature::firstname: "Frank" },
            { _?book @
                literature::author: _?author,
                literature::title: ?title
            }
        ])
    ) {
        consume(&title)?;
        titles.push(title);
    }
    Ok(titles)
}

// ANCHOR: collection_pattern_changes_observe
fn observe(
    store: &mut MemoryRepo,
    signing_key: &SigningKey,
    collection: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    checkpoint: &mut Option<
        CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    >,
    mut consume: impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let snapshot = store.snapshot()?;
    let current_support = collection.admitted(&snapshot)?;
    let changed_support = match checkpoint.as_ref() {
        Some(previous) if previous.support() == &current_support => return Ok(Vec::new()),
        Some(previous) => current_support.additions_since(previous.support()).ok(),
        None => None,
    };
    drop(snapshot);

    // Every mapping edge receives the same foundational support. Maintaining
    // the delta first lets complete maintenance reuse all persisted work.
    if let Some(changed) = changed_support.as_ref() {
        block_on(store.maintain_exact(raw, signing_key, changed))?;
        block_on(store.maintain_exact(accelerated, signing_key, changed))?;
    }
    block_on(store.maintain_exact(raw, signing_key, &current_support))?;
    let snapshot = block_on(store.maintain_exact(accelerated, signing_key, &current_support))?;
    let next = snapshot.collection_exact(accelerated, &current_support)?;

    let titles = match changed_support {
        Some(changed_support) => {
            let changed = snapshot.collection_exact(accelerated, &changed_support)?;
            let full: UnionArchive<OrderedUniverse> = next.view()?;
            let delta: UnionArchive<OrderedUniverse> = changed.view()?;
            changes(&full, &delta, &mut consume)?
        }
        None => {
            let full: UnionArchive<OrderedUniverse> = next.view()?;
            rebuild(&full, &mut consume)?
        }
    };

    // Adopt only after the complete fold succeeds. A failed consumer retries
    // the same exact Succinct delta, so external effects must be transactional
    // or idempotent when exactly-once delivery matters.
    *checkpoint = Some(next);
    Ok(titles)
}
// ANCHOR_END: collection_pattern_changes_observe

fn main() -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let authority = signing_key.verifying_key();
    let name = "incremental-literature";
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut store = MemoryRepo::default();
    let collection = store.collection(name, policy.clone())?;

    let author = entity! {
        literature::firstname: "Frank",
        literature::lastname: "Herbert",
    };
    let herbert = author.root().expect("intrinsic author id");
    store.commit(collection, &signing_key, author)?;
    store.commit(
        collection,
        &signing_key,
        entity! {
            literature::title: "Dune",
            literature::author: &herbert,
        },
    )?;

    let raw = store.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
    let accelerated = store.derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)?;
    let mut checkpoint = None;

    let first = observe(
        &mut store,
        &signing_key,
        collection,
        raw,
        accelerated,
        &mut checkpoint,
        |_| Ok(()),
    )?;
    assert_eq!(first, ["Dune"]);

    store.commit(
        collection,
        &signing_key,
        entity! {
            literature::title: "Dune Messiah",
            literature::author: &herbert,
        },
    )?;

    let before_failure = checkpoint
        .as_ref()
        .map(|snapshot| snapshot.support().clone());
    let failed = observe(
        &mut store,
        &signing_key,
        collection,
        raw,
        accelerated,
        &mut checkpoint,
        |_| Err(io::Error::other("simulated consumer failure").into()),
    );
    assert!(failed.is_err());
    assert_eq!(
        checkpoint
            .as_ref()
            .map(|snapshot| snapshot.support().clone()),
        before_failure,
    );

    let retry = observe(
        &mut store,
        &signing_key,
        collection,
        raw,
        accelerated,
        &mut checkpoint,
        |_| Ok(()),
    )?;
    assert_eq!(retry, ["Dune Messiah"]);

    let unchanged = observe(
        &mut store,
        &signing_key,
        collection,
        raw,
        accelerated,
        &mut checkpoint,
        |_| Ok(()),
    )?;
    assert!(unchanged.is_empty());

    println!("incremental titles: {first:?}, then {retry:?}");
    Ok(())
}
