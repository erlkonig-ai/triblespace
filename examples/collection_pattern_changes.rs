//! Incrementally query a growing collection: the Succinct target answers the
//! full side, the source payloads it newly stands on are the delta.
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
    CollectionStoreExt, CoverAdvanceError,
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
    changed: &TribleSet,
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
    source: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    checkpoint: &mut Option<
        CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    >,
    mut consume: impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Carry each mapping edge to its source's frontier, then read the target
    // from the snapshot that observes all of that work. What the source stood
    // on in that snapshot is the continuation token: supports are
    // collection-local, and the payloads are the source's.
    block_on(store.maintain(raw, signing_key))?;
    let snapshot = block_on(store.maintain(accelerated, signing_key))?;
    let next = snapshot.collection(accelerated)?;

    // The delta is a set of source payloads. Read it from the source through
    // the same snapshot; the Succinct target answers the full side.
    let changed = match checkpoint.as_ref() {
        Some(previous) => {
            let previous_source = previous.snapshot().collection(source)?;
            let current_source = snapshot.collection(source)?;
            let previous_support = previous_source.support()?;
            let current_support = current_source.support()?;
            if previous_support == current_support {
                return Ok(Vec::new());
            }
            match current_support.additions_since(previous_support) {
                Ok(additions) => {
                    let mut changed = TribleSet::new();
                    for member in additions.members() {
                        let payload: TribleSet = snapshot.get(member)?;
                        changed.union(payload);
                    }
                    Some(changed)
                }
                Err(CoverAdvanceError::ResetRequired { .. }) => None,
                Err(error) => return Err(error.into()),
            }
        }
        None => None,
    };

    let full: UnionArchive<OrderedUniverse> = next.view()?;
    let titles = match changed {
        Some(changed) => changes(&full, &changed, &mut consume)?,
        None => rebuild(&full, &mut consume)?,
    };

    // Adopt only after the complete fold succeeds. A failed consumer retries
    // the same delta, so external effects must be transactional or idempotent
    // when exactly-once delivery matters.
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
        .map(|snapshot| snapshot.support().cloned())
        .transpose()?;
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
            .map(|snapshot| snapshot.support().cloned())
            .transpose()?,
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
