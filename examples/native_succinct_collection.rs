//! Publish intrinsic entities to a native collection, then query its
//! SuccinctArchive projection without a branch, checkout, hook, or manifest.
//!
//! Run with: `cargo run --example native_succinct_collection`

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use rand::rngs::OsRng;
use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace::core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::examples::literature;
use triblespace::prelude::*;

fn main() {
    let tmp = tempfile::tempdir().expect("tmp dir");
    let path = tmp.path().join("native-succinct.pile");
    std::fs::File::create(&path).expect("create pile file");

    let mut pile = Pile::open(&path).expect("open pile");
    pile.refresh().expect("load pile");

    // A root collection is the handle of a self-contained descriptor. Its
    // independent READ and WRITE policies participate in that content identity.
    let name = "literature";
    let signing_key = SigningKey::generate(&mut OsRng);
    let authority = signing_key.verifying_key();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let collection = pile
        .collection(name, policy.clone())
        .expect("register source collection");

    // Each fragment is one independent signed collection member. Omitting an
    // explicit entity id makes every person intrinsic to their facts.
    for name in ["Ada", "Grace", "Barbara"] {
        pile.commit(
            collection,
            &signing_key,
            entity! { literature::firstname: name },
        )
        .expect("publish person");
    }

    // Freeze one coherent store observation, then discover what the source
    // stands on without reading the commits' data or metadata blobs.
    let snapshot = pile.snapshot().expect("freeze pile snapshot");
    let support = collection
        .admitted(&snapshot)
        .expect("discover exact support");
    assert_eq!(support.len(), 3);
    drop(snapshot);

    // Carry each mapping edge to its source's frontier: the raw Succinct
    // shards first, then their Rank9 fibers. The snapshot returned by the last
    // step observes all of that work, so the target read from it stands for
    // exactly the support admitted above.
    let raw = pile
        .derive::<SuccinctArchiveBlob>(collection, (), policy.clone())
        .expect("register raw Succinct projection");
    let accelerated = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .expect("register Rank9-accelerated projection");
    block_on(pile.maintain(raw, &signing_key)).expect("maintain raw Succinct collection");
    let snapshot = block_on(pile.maintain(accelerated, &signing_key))
        .expect("maintain Rank9-accelerated collection");
    let archive = snapshot
        .collection(accelerated)
        .expect("observe Rank9-accelerated collection");
    assert_eq!(archive.support().expect("resolve support"), &support);
    let view: UnionArchive<OrderedUniverse> = archive.view().expect("reconstruct Succinct view");
    let mut names: Vec<String> = find!(
        name: Inline<_>,
        pattern!(&view, [{ _?person @ literature::firstname: ?name }])
    )
    .map(|name| name.try_from_inline::<String>().expect("short string"))
    .collect();
    names.sort();

    println!("queried Succinct cover: {names:?}");
    assert_eq!(names, ["Ada", "Barbara", "Grace"]);

    pile.close().expect("close pile");
}
