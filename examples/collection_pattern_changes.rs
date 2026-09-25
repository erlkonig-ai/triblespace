//! Incrementally query a growing collection: the Succinct target answers the
//! full side, the source payloads the view chain newly absorbed are the delta.
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
    AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
    CoverAdvanceError, Support,
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
/// The source payloads the view chain has absorbed: every source foundation
/// the first view has a leaf for, provided the second view has caught up
/// with the first. `None` while the second view lags, since then the
/// accelerated view does not yet answer for everything the first stands on.
fn absorbed(
    snapshot: &MemoryRepoSnapshot,
    source: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
) -> Result<Option<Support>, Box<dyn Error>> {
    let source = snapshot.collection(source)?;
    let raw = snapshot.collection(raw)?;
    if !snapshot
        .collection(accelerated)?
        .missing_from(&raw)?
        .is_empty()
    {
        return Ok(None);
    }
    let lag = raw.missing_from(&source)?;
    Ok(Some(source.support()?.difference(&lag)?))
}

fn observe(
    store: &mut MemoryRepo,
    signing_key: &SigningKey,
    source: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    checkpoint: &mut Option<Support>,
    mut consume: impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Maintain each mapping edge -- this key's own leaves and merges -- then
    // read everything from the snapshot that observes all of that work.
    block_on(store.maintain(raw, signing_key))?;
    let snapshot = block_on(store.maintain(accelerated, signing_key))?;

    // The continuation token is the set of source payloads the view chain
    // has absorbed, not what the source stands on: another writer's payload
    // is in the source before its writer derives it, and a token that
    // advanced past it would never deliver it. A view that lags holds the
    // token back.
    let Some(current) = absorbed(&snapshot, source, raw, accelerated)? else {
        return Ok(Vec::new());
    };
    let changed = match checkpoint.as_ref() {
        Some(previous) => {
            if previous == &current {
                return Ok(Vec::new());
            }
            match current.additions_since(previous) {
                Ok(additions) => {
                    // The delta is a set of source payloads: read them from
                    // the source through the same snapshot.
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

    // The accelerated view answers the full side: it stands for everything
    // the token names.
    let full: UnionArchive<OrderedUniverse> = snapshot.collection(accelerated)?.view()?;
    let titles = match changed {
        Some(changed) => changes(&full, &changed, &mut consume)?,
        None => rebuild(&full, &mut consume)?,
    };

    // Adopt only after the complete fold succeeds. A failed consumer retries
    // the same delta, so external effects must be transactional or idempotent
    // when exactly-once delivery matters.
    *checkpoint = Some(current);
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

    let before_failure = checkpoint.clone();
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
    assert_eq!(checkpoint, before_failure);

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
