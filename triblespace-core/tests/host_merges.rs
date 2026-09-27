//! A pile's MERGEs are believed only for the key it is opened as.
//!
//! Every host joins the foundations it holds into a tree of its own. Join is
//! associative, commutative and idempotent, so those trees stand for the same
//! set: a pile opened as one host, as another, or with no host at all reads
//! the same foundations, each through its own merges or none. Another host's
//! MERGEs stay in the file and fold into nothing, so `cat` of two hosts' piles
//! leaves each host's carry exactly where its own records put it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionData, CollectionMerge, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionStoreExt, MERGE_FAN_IN,
};
use triblespace_core::inline::Inline;
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn empty_pile(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::File::create(&path).unwrap();
    path
}

fn shared(pile: &mut Pile) -> Collection<SimpleArchive> {
    pile.collection(
        "shared",
        CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
    )
    .unwrap()
}

/// Commit `count` distinct payloads signed by `signer`.
fn commit_many(pile: &mut Pile, collection: Collection<SimpleArchive>, signer: u8, count: usize) {
    for entity in 0..count {
        let name = pile
            .put::<UTF8String, _>(format!("payload {signer} {entity}"))
            .unwrap();
        pile.commit(collection, &key(signer), entity! { metadata::name: name })
            .unwrap();
    }
}

/// The payloads of the COMMITs `signer` made into `collection`.
fn commits_by(
    pile: &mut Pile,
    collection: Collection<SimpleArchive>,
    signer: u8,
) -> BTreeSet<CollectionData> {
    let signer = Inline::new(key(signer).verifying_key().to_bytes());
    pile.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .map(Result::unwrap)
        .filter_map(|record| match record {
            CollectionRecord::Commit(commit)
                if commit.collection() == collection.handle() && commit.public_key() == signer =>
            {
                Some(commit.data())
            }
            _ => None,
        })
        .collect()
}

/// The MERGE records of `collection`, whoever signed them.
fn merges(pile: &mut Pile, collection: Collection<SimpleArchive>) -> Vec<CollectionMerge> {
    pile.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .map(Result::unwrap)
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) if merge.collection() == collection.handle() => {
                Some(merge)
            }
            _ => None,
        })
        .collect()
}

/// What one open reads: its frontier and the foundations the frontier
/// stands for, and how many joins its fold keeps.
fn observe(
    pile: &mut Pile,
    collection: Collection<SimpleArchive>,
) -> (BTreeSet<CollectionData>, BTreeSet<CollectionData>, usize) {
    let index = pile.snapshot().unwrap().coverage_index();
    let coverage = index.published();
    let frontier = coverage.frontier(collection.handle()).collect();
    let (support, unattested) = coverage.frontier_support(collection.handle());
    assert!(unattested.is_empty());
    let support = support
        .iter_ordered()
        .map(|raw| Inline::new(*raw))
        .collect();
    (frontier, support, index.stored_joins())
}

fn open(path: &Path, host: Option<u8>) -> Pile {
    match host {
        Some(host) => Pile::open_as(path, key(host).verifying_key()).unwrap(),
        None => Pile::open(path).unwrap(),
    }
}

/// One pile holding two hosts' commits and each host's carry, opened as
/// each host and with none: each open believes exactly its own MERGEs, and
/// all three stand for the same foundations.
#[test]
fn one_pile_opened_as_two_hosts_and_as_none_believes_only_its_own_merges() {
    let dir = tempfile::tempdir().unwrap();
    let path = empty_pile(&dir, "shared.pile");
    let (first, second) = (41, 42);

    let mut pile = open(&path, Some(first));
    let collection = shared(&mut pile);
    commit_many(&mut pile, collection, first, MERGE_FAN_IN);
    drop(block_on(pile.maintain(collection, &key(first))).unwrap());
    pile.close().unwrap();

    let mut pile = open(&path, Some(second));
    commit_many(&mut pile, collection, second, MERGE_FAN_IN);
    drop(block_on(pile.maintain(collection, &key(second))).unwrap());
    let all = merges(&mut pile, collection);
    let second_commits = commits_by(&mut pile, collection, second);
    pile.close().unwrap();
    let signed_by = |signer: u8| {
        all.iter()
            .filter(|merge| {
                merge.public_key() == Inline::new(key(signer).verifying_key().to_bytes())
            })
            .map(|merge| merge.result())
            .collect::<BTreeSet<_>>()
    };
    let (first_merges, second_merges) = (signed_by(first), signed_by(second));
    // The first host carried its own eight; the second saw sixteen held
    // commits (the first host's merge folds into nothing for it) and
    // carried them in two groups of eight.
    assert_eq!(first_merges.len(), 1);
    assert_eq!(second_merges.len(), 2);
    assert_eq!(all.len(), 3);

    let mut observed = Vec::new();
    for host in [Some(first), Some(second), None] {
        let mut pile = open(&path, host);
        observed.push(observe(&mut pile, collection));
        pile.close().unwrap();
    }
    let [(first_frontier, first_support, first_joins), (second_frontier, second_support, second_joins), (keyless_frontier, keyless_support, keyless_joins)] =
        <[_; 3]>::try_from(observed).unwrap();

    assert_eq!(first_support.len(), 2 * MERGE_FAN_IN);
    assert_eq!(first_support, second_support);
    assert_eq!(first_support, keyless_support);

    // Each fold keeps its own joins and no other key's.
    assert_eq!(first_joins, 1);
    assert_eq!(second_joins, 2);
    assert_eq!(keyless_joins, 0);
    // With no host every foundation is its own frontier node; each host's
    // frontier is what its own merges left: the first host's tree beside the
    // second host's commits, which it has not carried yet, and the second
    // host's two trees.
    assert_eq!(keyless_frontier, keyless_support);
    assert_eq!(
        first_frontier,
        first_merges.union(&second_commits).copied().collect()
    );
    assert_eq!(second_frontier, second_merges);
}

/// `cat` of two hosts' piles is the merge of the two. Each host, opening
/// the result, sees the other's commits as held foundations and the other's
/// merges as nothing, carries the other's commits into its own tree, and
/// reaches a fixed point: no stall, and both stand for every foundation.
#[test]
fn after_cat_of_two_hosts_piles_each_host_carries_on_without_a_stall() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (51, 52);
    let mut collections = Vec::new();
    let mut paths = Vec::new();
    for host in [a, b] {
        let path = empty_pile(&dir, &format!("host-{host}.pile"));
        let mut pile = open(&path, Some(host));
        let collection = shared(&mut pile);
        commit_many(&mut pile, collection, host, MERGE_FAN_IN);
        drop(block_on(pile.maintain(collection, &key(host))).unwrap());
        assert_eq!(merges(&mut pile, collection).len(), 1);
        pile.close().unwrap();
        collections.push(collection);
        paths.push(path);
    }
    assert_eq!(collections[0].handle(), collections[1].handle());
    let collection = collections[0];

    let united = dir.path().join("united.pile");
    let mut bytes = std::fs::read(&paths[0]).unwrap();
    bytes.extend(std::fs::read(&paths[1]).unwrap());
    std::fs::write(&united, bytes).unwrap();

    let mut supports = Vec::new();
    for host in [a, b] {
        let mut pile = open(&united, Some(host));
        let before = merges(&mut pile, collection).len();
        // The other host's eight commits are held, its merge is not folded:
        // one merge of its own for them, and a fixed point after it.
        drop(block_on(pile.maintain(collection, &key(host))).unwrap());
        let after = merges(&mut pile, collection);
        assert_eq!(after.len(), before + 1);
        drop(block_on(pile.maintain(collection, &key(host))).unwrap());
        assert_eq!(merges(&mut pile, collection).len(), after.len());
        let (frontier, support, _) = observe(&mut pile, collection);
        assert_eq!(frontier.len(), 2, "one tree per group of eight");
        assert_eq!(support.len(), 2 * MERGE_FAN_IN);
        supports.push(support);
        pile.close().unwrap();
    }
    assert_eq!(supports[0], supports[1]);
}
