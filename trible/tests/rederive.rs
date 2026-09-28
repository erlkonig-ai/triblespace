//! `pile collection rederive`: the explicit supplement to a leaf known to be
//! bad. Maintenance never derives a member again while one of its leaves has
//! bytes here; rederive adds a leaf beside it and replaces none.
#![cfg(feature = "search")]

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::path::Path;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::records::CollectionHandle;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionData, CollectionDerive, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionRecordSelector, CollectionStore,
    CollectionStoreExt, SourceLocator,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_core::trible::{Fragment, Trible, TribleSet};
use triblespace_search::schemas::Embedding;

const ATTRIBUTE: &str = "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A1";

fn trible() -> Command {
    Command::cargo_bin("trible").unwrap()
}

fn policy(key: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    )
}

fn hex_of(raw: [u8; 32]) -> String {
    format!("blake3:{}", hex::encode(raw))
}

/// One commit holding one entity whose attribute names `vector`; its data.
fn commit_vector(
    pile: &mut Pile,
    root: Collection<SimpleArchive>,
    key: &SigningKey,
    entity: u8,
    vector: Vec<f32>,
) -> [u8; 32] {
    let embedding = pile.put::<Embedding, _>(vector).unwrap();
    let mut facts = TribleSet::new();
    facts.insert(&Trible::force(
        &Id::new([entity; 16]).unwrap(),
        &Id::from_hex(ATTRIBUTE).unwrap(),
        &embedding,
    ));
    pile.commit(root, key, Fragment::from(facts))
        .unwrap()
        .data()
        .raw
}

/// Every output a leaf of `collection` gives the member with data `member`.
fn outputs(path: &Path, collection: CollectionHandle, member: [u8; 32]) -> BTreeSet<[u8; 32]> {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let outputs = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::DeriveTarget(
            collection,
        )]))
        .unwrap()
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.input() == SourceLocator::of(member) => {
                Some(derive.output().raw)
            }
            _ => None,
        })
        .collect();
    drop(snapshot);
    pile.close().unwrap();
    outputs
}

struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run(
    args: &[&str],
    path: &Path,
    collection: CollectionHandle,
    key: &Path,
    tail: &[String],
) -> Run {
    let output = trible()
        .args(args)
        .arg(path)
        .arg(hex_of(collection.raw))
        .args(tail)
        .arg("--key")
        .arg(key)
        .output()
        .unwrap();
    Run {
        success: output.status.success(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn rederive(path: &Path, key: &Path, collection: CollectionHandle, member: [u8; 32]) -> Run {
    run(
        &["pile", "collection", "rederive"],
        path,
        collection,
        key,
        &[hex_of(member)],
    )
}

#[test]
fn rederive_adds_a_leaf_beside_a_bad_one_and_replaces_none() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vectors.pile");
    let key_path = directory.path().join("writer.key");
    std::fs::File::create(&path).unwrap();
    let key = triblespace_core::signing_key_file::init(&key_path).unwrap();

    let mut pile = Pile::open(&path).unwrap();
    let root = pile.collection("vectors", policy(&key)).unwrap();
    let good = commit_vector(&mut pile, root, &key, 1, vec![1.0, 0.0, 0.0, 0.0]);
    let bad = commit_vector(&mut pile, root, &key, 2, vec![0.0, 1.0, 0.0, 0.0]);
    // Bytes that are here and are no image of the bad member: a broken
    // derivation's output.
    let wrong: CollectionData =
        Handle::<Embedding>::to_hash(pile.put::<Embedding, _>(vec![0.5, 0.5, 0.5, 0.5]).unwrap());
    pile.close().unwrap();

    let derived = run(
        &["pile", "collection", "derive"],
        &path,
        root.handle(),
        &key_path,
        &[
            "nvfp4".to_owned(),
            "--attribute".to_owned(),
            ATTRIBUTE.to_owned(),
            "--dimension".to_owned(),
            "4".to_owned(),
        ],
    );
    assert!(derived.success, "{}", derived.stderr);
    let handle: CollectionHandle = Inline::new(
        hex::decode(derived.stdout.trim().strip_prefix("blake3:").unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let mut pile = Pile::open(&path).unwrap();
    pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
        &key,
        handle,
        SourceLocator::of(bad),
        wrong,
    )))
    .unwrap();
    pile.close().unwrap();

    // Maintenance derives the good member and leaves the bad one alone: a
    // leaf of it has bytes here, and any admitted leaf suffices.
    let maintained = run(
        &["pile", "collection", "maintain"],
        &path,
        handle,
        &key_path,
        &[],
    );
    assert!(maintained.success, "{}", maintained.stderr);
    let good_leaves = outputs(&path, handle, good);
    assert_eq!(good_leaves.len(), 1);
    assert_eq!(outputs(&path, handle, bad), BTreeSet::from([wrong.raw]));

    // Rederiving the good member gives the bytes its leaf already names.
    let result = rederive(&path, &key_path, handle, good);
    assert!(result.success, "{}", result.stderr);
    assert!(
        result.stdout.contains(": 0 new leaf(s)"),
        "{}",
        result.stdout
    );
    assert_eq!(outputs(&path, handle, good), good_leaves);

    // The bad member gets a second leaf beside the wrong one.
    let result = rederive(&path, &key_path, handle, bad);
    assert!(result.success, "{}", result.stderr);
    assert!(
        result.stdout.contains(": 1 new leaf(s)"),
        "{}",
        result.stdout
    );
    let bad_leaves = outputs(&path, handle, bad);
    assert_eq!(bad_leaves.len(), 2);
    assert!(bad_leaves.contains(&wrong.raw));

    // Asking again adds nothing.
    let result = rederive(&path, &key_path, handle, bad);
    assert!(result.success, "{}", result.stderr);
    assert!(
        result.stdout.contains(": 0 new leaf(s)"),
        "{}",
        result.stdout
    );
    assert_eq!(outputs(&path, handle, bad), bad_leaves);

    // Only a believed member of the collection's source.
    let result = rederive(&path, &key_path, handle, [0x55; 32]);
    assert!(!result.success);
    assert!(
        result.stderr.contains("is not a believed foundation"),
        "{}",
        result.stderr
    );
}
