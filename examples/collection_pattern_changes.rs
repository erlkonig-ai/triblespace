//! Incrementally query a growing collection: the attached Succinct cover
//! answers the full side, the source payloads it newly stands for are the
//! delta.
//!
//! Run with: `cargo run --example collection_pattern_changes`

use std::error::Error;
use std::io;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use rand::rngs::OsRng;
use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace::core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
    CoverAdvanceError, Support,
};
use triblespace::core::examples::literature;
use triblespace::core::repo::memoryrepo::MemoryRepo;
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
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    checkpoint: &mut Option<Support>,
    mut consume: impl FnMut(&str) -> Result<(), Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    // Maintain both attachments -- the Succinct index, then the Rank9
    // accelerator that reads it -- and read from the snapshot that observes
    // all of that work.
    block_on(store.maintain_attached(raw, signing_key))?;
    let snapshot = block_on(store.maintain_attached(accelerated, signing_key))?;
    let attached = snapshot.attached(accelerated)?;

    // The continuation token is the set of source payloads the attached cover
    // stands for, not what the source holds: a payload without an attachment
    // yet is the cover's residual, and a token that advanced past it would
    // never deliver it.
    let current = attached.support().clone();
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

    // The attached cover answers the full side: it stands for everything the
    // token names.
    let full: UnionArchive<OrderedUniverse> = attached.view()?;
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
    // The store is opened as the key that maintains it: only its own MERGEs
    // and MAPs are believed.
    let mut store = MemoryRepo::for_host(authority);
    let collection = store.collection(name, policy)?;

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

    let raw = store.attach::<SuccinctArchiveBlob>(collection, ())?;
    let accelerated = store.attach::<Rank9AcceleratedSuccinctArchiveBlob>(collection, raw)?;
    let mut checkpoint = None;

    let first = observe(
        &mut store,
        &signing_key,
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
        raw,
        accelerated,
        &mut checkpoint,
        |_| Ok(()),
    )?;
    assert_eq!(retry, ["Dune Messiah"]);

    let unchanged = observe(
        &mut store,
        &signing_key,
        raw,
        accelerated,
        &mut checkpoint,
        |_| Ok(()),
    )?;
    assert!(unchanged.is_empty());

    println!("incremental titles: {first:?}, then {retry:?}");
    Ok(())
}
