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

    // A root collection is the handle of a self-contained descriptor. Its
    // independent READ and WRITE policies participate in that content identity.
    let name = "literature";
    let signing_key = SigningKey::generate(&mut OsRng);
    let authority = signing_key.verifying_key();
    // The pile is opened as the key that maintains it: only its own MERGEs
    // and MAPs are believed.
    let mut pile = Pile::open_as(&path, authority).expect("open pile");
    pile.refresh().expect("load pile");
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

    // Attach the Succinct index and the Rank9 accelerator that reads it to the
    // collection's own nodes. Maintaining them carries the collection and
    // attaches what the carry leaves, the Succinct index first. The snapshot
    // returned by the last step observes all of that work.
    let raw = pile
        .attach::<SuccinctArchiveBlob>(collection, ())
        .expect("attach the Succinct index");
    let accelerated = pile
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(collection, raw)
        .expect("attach the Rank9 accelerator");
    block_on(pile.maintain_attached(raw, &signing_key)).expect("maintain Succinct attachments");
    let snapshot = block_on(pile.maintain_attached(accelerated, &signing_key))
        .expect("maintain Rank9 attachments");
    let archive = snapshot
        .attached(accelerated)
        .expect("observe the Rank9 attachments");
    // An attached collection stands for its parent's foundations; what no
    // attachment reaches yet is the residual.
    assert_eq!(archive.support(), &support);
    assert!(archive.residual().is_empty());
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
