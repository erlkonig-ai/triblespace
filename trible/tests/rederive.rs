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

/// Register the NVFP4 derived collection of `root` with `key`, as the CLI
/// does: the collection admits only `key` to write.
fn derive_nvfp4(path: &Path, root: Collection<SimpleArchive>, key: &Path) -> CollectionHandle {
    let derived = run(
        &["pile", "collection", "derive"],
        path,
        root.handle(),
        key,
        &[
            "nvfp4".to_owned(),
            "--attribute".to_owned(),
            ATTRIBUTE.to_owned(),
            "--dimension".to_owned(),
            "4".to_owned(),
        ],
    );
    assert!(derived.success, "{}", derived.stderr);
    Inline::new(
        hex::decode(derived.stdout.trim().strip_prefix("blake3:").unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

/// The one completed-pass line `maintain` printed.
fn pass_line(stdout: &str) -> &str {
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("maintenance pass "))
        .collect();
    assert_eq!(lines.len(), 1, "{stdout}");
    lines[0]
}

/// Review finding, 2026-09-28: `maintain` opens a plain pile, whose
/// acquisition answers from its own blobs. A leaf whose record is here and
/// whose image has not arrived was derived again at once, a second leaf for
/// a member that already had one. A plain pile cannot tell whether the image
/// can be had elsewhere, so the member now waits for it.
#[test]
fn maintain_through_a_plain_pile_waits_for_a_leafs_image() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vectors.pile");
    let key_path = directory.path().join("writer.key");
    std::fs::File::create(&path).unwrap();
    let key = triblespace_core::signing_key_file::init(&key_path).unwrap();

    let mut pile = Pile::open(&path).unwrap();
    let root = pile.collection("vectors", policy(&key)).unwrap();
    let waiting = commit_vector(&mut pile, root, &key, 1, vec![1.0, 0.0, 0.0, 0.0]);
    pile.close().unwrap();
    let handle = derive_nvfp4(&path, root, &key_path);

    // A leaf whose image is elsewhere: its record arrived, its bytes not yet.
    let elsewhere: CollectionData = Inline::new([0x77; 32]);
    let mut pile = Pile::open(&path).unwrap();
    pile.insert(CollectionRecord::Derive(CollectionDerive::sign(
        &key,
        handle,
        SourceLocator::of(waiting),
        elsewhere,
    )))
    .unwrap();
    pile.close().unwrap();

    let maintained = run(
        &["pile", "collection", "maintain"],
        &path,
        handle,
        &key_path,
        &[],
    );
    assert!(maintained.success, "{}", maintained.stderr);
    assert!(
        pass_line(&maintained.stdout).ends_with(", failed 0"),
        "{}",
        maintained.stdout
    );
    assert_eq!(
        outputs(&path, handle, waiting),
        BTreeSet::from([elsewhere.raw]),
        "no second leaf while the first one's image may still arrive"
    );
}

/// Review finding, 2026-09-28: a key the derived collection does not admit
/// carried it and then reported `UnauthorizedProducer` for its own members,
/// which `maintain` counted as a failed selection on every pass. Its work
/// there is the carry; it now carries and succeeds.
#[test]
fn a_maintainer_the_collection_does_not_admit_carries_it_and_does_not_fail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vectors.pile");
    let writer_path = directory.path().join("writer.key");
    let host_path = directory.path().join("host.key");
    std::fs::File::create(&path).unwrap();
    let writer = triblespace_core::signing_key_file::init(&writer_path).unwrap();
    let host = triblespace_core::signing_key_file::init(&host_path).unwrap();

    let mut pile = Pile::open(&path).unwrap();
    let root = pile
        .collection(
            "vectors",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap();
    for entity in 1..=8u8 {
        let mut vector = vec![0.0f32; 4];
        vector[usize::from(entity) % 4] = f32::from(entity);
        commit_vector(&mut pile, root, &writer, entity, vector);
    }
    pile.close().unwrap();
    // Only the writer may write the derived collection.
    let handle = derive_nvfp4(&path, root, &writer_path);
    let maintained = run(
        &["pile", "collection", "maintain"],
        &path,
        handle,
        &writer_path,
        &[],
    );
    assert!(maintained.success, "{}", maintained.stderr);
    // The host commits a member of its own, which it may not derive.
    let mut pile = Pile::open(&path).unwrap();
    commit_vector(&mut pile, root, &host, 9, vec![0.0, 0.0, 0.0, 9.0]);
    pile.close().unwrap();

    let carried = run(
        &["pile", "collection", "maintain"],
        &path,
        handle,
        &host_path,
        &[],
    );
    assert!(carried.success, "{}", carried.stderr);
    assert!(
        pass_line(&carried.stdout).ends_with(", published 1, failed 0"),
        "{}",
        carried.stdout
    );
    // The host's own MERGE of the writer's eight leaves.
    let mut pile = Pile::open(&path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let merges: Vec<_> = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            handle,
        )]))
        .unwrap()
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) => Some(merge),
            _ => None,
        })
        .filter(|merge| merge.public_key().raw == host.verifying_key().to_bytes())
        .collect();
    assert_eq!(merges.len(), 1);
    assert_eq!(merges[0].inputs().len(), 8);
    drop(snapshot);
    pile.close().unwrap();
}
