//! Cached decode completion against the per-key computation it replaced.
//! The oracle edits one key at a time and materializes the union with stand-in
//! values; the production path takes one structural difference and a sparse
//! union summary. Values never take part in either summary.

use std::time::Instant;

use ed25519_dalek::SigningKey;
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::collection::{CollectionRecordView, read_capability};

use super::*;
use crate::walk::tests::walking::{Node, open};

type Key = [u8; KEY_BYTES];

/// Deterministic splitmix64 stream.
struct Keys(u64);

impl Keys {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Hash-like keys, with every eighth one sharing a long prefix with its
    /// predecessor so compressed paths and deep branches occur as well.
    fn take(&mut self, n: usize) -> Vec<Key> {
        let mut keys: Vec<Key> = Vec::with_capacity(n);
        while keys.len() < n {
            let mut key = [0; KEY_BYTES];
            for chunk in key.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            if keys.len() % 8 == 7 {
                let shared = 3 + (self.next_u64() % 26) as usize;
                let previous = keys[keys.len() - 1];
                key[..shared].copy_from_slice(&previous[..shared]);
            }
            keys.push(key);
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// `n` distinct keys of `keys` in random order, as a decoder recovers them.
    fn pick(&mut self, keys: &[Key], n: usize) -> Vec<Key> {
        let mut keys = keys.to_vec();
        let n = n.min(keys.len());
        for i in 0..n {
            let j = i + (self.next_u64() % (keys.len() - i) as u64) as usize;
            keys.swap(i, j);
        }
        keys.truncate(n);
        keys
    }
}

/// One kind with one stand-in value for every key.
#[derive(Clone)]
enum Kind {
    References,
    Commit(Value),
    Authorization(CollectionHandle, Value),
}

impl Kind {
    fn all() -> Vec<Kind> {
        let mut node = Node::new(171);
        let collection = node.hold("riblt-completion", open());
        let record = node.commit(collection, 1);
        let view = CollectionRecordView::from(record)
            .as_commit()
            .unwrap()
            .clone();
        let proof = CapabilityProof::new(
            CapabilityResource::new(collection.raw),
            &SigningKey::from_bytes(&[172; 32]),
            read_capability(),
            SigningKey::from_bytes(&[173; 32]).verifying_key(),
        );
        vec![
            Kind::References,
            Kind::Commit(Value::Commit(view)),
            Kind::Authorization(collection, Value::Proof(proof)),
        ]
    }

    fn value(&self) -> Value {
        match self {
            Kind::References => Value::Handle,
            Kind::Commit(value) | Kind::Authorization(_, value) => value.clone(),
        }
    }

    fn tree(&self, keys: &[Key]) -> Tree {
        let mut tree = match self {
            Kind::References => {
                return Tree::References(PATCH::from_keys(keys.iter().copied()));
            }
            Kind::Commit(_) => Tree::Commit(PATCH::new()),
            Kind::Authorization(collection, _) => Tree::Authorization(*collection, PATCH::new()),
        };
        for key in keys {
            tree.insert(*key, self.value());
        }
        tree
    }
}

/// The removed single-key edit, kept only as the oracle.
fn remove_one(tree: &mut Tree, key: Key) {
    match tree {
        Tree::Commit(patch) => patch.remove(&key),
        Tree::Derive(patch) => patch.remove(&key),
        Tree::Authorization(collection, patch) => patch.remove(&absolute_key(collection, key)),
        Tree::References(patch) => patch.remove(&key),
    }
}

/// The per-key completion this file replaced: clone, remove each local key,
/// check each remote key, then compare the materialized union.
fn oracle_completion(
    kind: &Kind,
    delta: &Tree,
    local: &[Key],
    remote: &[Key],
    peer_root: Option<PatchSummary>,
) -> Result<PatchSummary, Failure> {
    let mut retained = delta.clone();
    let mut removed = PATCH::<32, IdentitySchema>::new();
    for key in local {
        if delta.at(key).is_none() || removed.get(key).is_some() {
            return Err(Failure::BadNode);
        }
        removed.insert(&Entry::new(key));
        remove_one(&mut retained, *key);
    }
    let mut added = PATCH::<32, IdentitySchema>::new();
    for key in remote {
        if delta.at(key).is_some() || added.get(key).is_some() {
            return Err(Failure::BadNode);
        }
        added.insert(&Entry::new(key));
        retained.insert(*key, kind.value());
    }
    let summary = retained.summary();
    if Some(summary) != peer_root {
        return Err(Failure::CountMismatch);
    }
    Ok(summary)
}

fn completion(
    delta: &Tree,
    local: &[Key],
    remote: &[Key],
    peer_root: Option<PatchSummary>,
) -> Result<PatchSummary, Failure> {
    let summary = decoded_summary(delta, local.iter().copied(), remote.iter().copied())?;
    if Some(summary) != peer_root {
        return Err(Failure::CountMismatch);
    }
    Ok(summary)
}

fn oracle_drop(peer: &mut Tree, delta: &Tree, local: &[Key]) -> Result<(), Failure> {
    for key in local {
        if delta.at(key).is_none() {
            return Err(Failure::BadNode);
        }
        remove_one(peer, *key);
    }
    Ok(())
}

fn key_set(tree: &Tree) -> Vec<Key> {
    let mut keys = Vec::new();
    tree.for_each_key(|key| keys.push(key));
    keys
}

/// Same completion outcome, and the same peer proof afterwards.
fn agree(
    kind: &Kind,
    delta: &Tree,
    peer: &Tree,
    local: &[Key],
    remote: &[Key],
    peer_root: Option<PatchSummary>,
) -> Result<PatchSummary, Failure> {
    let expected = oracle_completion(kind, delta, local, remote, peer_root);
    assert_eq!(completion(delta, local, remote, peer_root), expected);

    let (mut old, mut new) = (peer.clone(), peer.clone());
    assert_eq!(
        drop_local(&mut new, delta, local),
        oracle_drop(&mut old, delta, local)
    );
    assert_eq!(new.summary(), old.summary());
    assert_eq!(key_set(&new), key_set(&old));
    expected
}

#[test]
fn completion_matches_the_per_key_oracle() {
    let mut rng = Keys(0x5EED);
    for kind in Kind::all() {
        let sizes: &[(usize, usize, usize)] = match &kind {
            Kind::References => &[
                (0, 0, 0),
                (1, 1, 0),
                (64, 3, 5),
                (5000, 900, 700),
                (60_000, 25_000, 9000),
            ],
            _ => &[
                (0, 0, 1),
                (1, 1, 1),
                (64, 64, 0),
                (5000, 1200, 300),
                (20_000, 7000, 2000),
            ],
        };
        for &(n, k, m) in sizes {
            let mut fresh = rng.take(n + m + 2);
            let outside = fresh.split_off(n);
            let delta = kind.tree(&fresh);
            let local = rng.pick(&fresh, k);
            let remote = outside[..m].to_vec();
            let stranger = outside[m];

            // The true peer root: the source without its local-only keys,
            // with the peer-only keys.
            let mut truth = delta.clone();
            for key in &local {
                remove_one(&mut truth, *key);
            }
            for key in &remote {
                truth.insert(*key, kind.value());
            }
            let root = Some(truth.summary());
            assert_eq!(
                agree(&kind, &delta, &delta, &local, &remote, root),
                Ok(truth.summary())
            );

            // A peer proof that already gained peer-only keys.
            let mut peer = delta.clone();
            for key in &remote {
                peer.insert(*key, kind.value());
            }
            assert!(agree(&kind, &delta, &peer, &local, &remote, root).is_ok());

            // CountMismatch: a ROOT that is not this difference.
            if !local.is_empty() || !remote.is_empty() {
                assert_eq!(
                    agree(
                        &kind,
                        &delta,
                        &delta,
                        &local,
                        &remote,
                        Some(delta.summary())
                    ),
                    Err(Failure::CountMismatch)
                );
            }
            assert_eq!(
                agree(&kind, &delta, &delta, &local, &remote, None),
                Err(Failure::CountMismatch)
            );

            // BadNode: a local key outside the source, in the middle, so
            // the peer proof keeps exactly the edits before it.
            let mut bad = local.clone();
            bad.insert(bad.len() / 2, stranger);
            assert_eq!(
                agree(&kind, &delta, &peer, &bad, &remote, root),
                Err(Failure::BadNode)
            );
            // BadNode: a repeated local key, a remote key inside the source,
            // a repeated remote key.
            if let Some(&first) = local.first() {
                let mut repeated = local.clone();
                repeated.push(first);
                assert_eq!(
                    agree(&kind, &delta, &peer, &repeated, &remote, root),
                    Err(Failure::BadNode)
                );
            }
            if let Some(&held) = fresh.first() {
                let mut inside = remote.clone();
                inside.push(held);
                assert_eq!(
                    agree(&kind, &delta, &peer, &local, &inside, root),
                    Err(Failure::BadNode)
                );
            }
            if let Some(&first) = remote.first() {
                let mut repeated = remote.clone();
                repeated.insert(0, first);
                assert_eq!(
                    agree(&kind, &delta, &peer, &local, &repeated, root),
                    Err(Failure::BadNode)
                );
            }
        }
    }
}

#[test]
fn without_keys_matches_single_key_removal_for_every_kind() {
    let mut rng = Keys(0xE1C1);
    for kind in Kind::all() {
        let keys = rng.take(3000);
        let tree = kind.tree(&keys);
        let mut removed = rng.pick(&keys, 1000);
        removed.extend(rng.take(50)); // absent keys are no-ops
        let mut expected = tree.clone();
        for key in &removed {
            remove_one(&mut expected, *key);
        }
        let got = tree.without_keys(removed.iter().rev().copied());
        assert_eq!(got.summary(), expected.summary());
        assert_eq!(key_set(&got), key_set(&expected));
        for key in &keys {
            assert_eq!(got.at(key).is_some(), expected.at(key).is_some(),);
        }
        assert_eq!(tree.without_keys([]).summary(), tree.summary());
        assert!(
            tree.without_keys(keys.iter().copied())
                .summary()
                .root()
                .is_none()
        );
    }
}

/// Wall time of the per-key oracle against the structural completion.
/// `cargo test --release -p triblespace-net completion_timing -- --ignored --nocapture`
#[test]
#[ignore]
fn completion_timing() {
    let mut rng = Keys(0x7111);
    for (kind, n, k, m) in [
        (Kind::References, 1_000_000, 200_000, 20_000),
        (Kind::all().swap_remove(1), 200_000, 50_000, 5000),
    ] {
        let mut fresh = rng.take(n + m);
        let remote = fresh.split_off(n);
        let delta = kind.tree(&fresh);
        let local = rng.pick(&fresh, k);
        let label = match kind {
            Kind::References => "references",
            _ => "commit",
        };

        let start = Instant::now();
        let new_root = decoded_summary(&delta, local.iter().copied(), remote.iter().copied());
        let new_completion = start.elapsed();
        let start = Instant::now();
        let mut new_peer = delta.clone();
        drop_local(&mut new_peer, &delta, &local).unwrap();
        let new_drop = start.elapsed();

        // The old completion, as it was: clone and remove per key, then a
        // sparse union summary of per-key inserted additions.
        let start = Instant::now();
        let mut retained = delta.clone();
        let mut removed = PATCH::<32, IdentitySchema>::new();
        for key in &local {
            assert!(delta.at(key).is_some() && removed.get(key).is_none());
            removed.insert(&Entry::new(key));
            remove_one(&mut retained, *key);
        }
        let mut additions = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
        for key in &remote {
            assert!(delta.at(key).is_none() && additions.get(key).is_none());
            additions.insert(&Entry::new(key));
        }
        let old_root = retained.summary_with_keys(&additions);
        let old_completion = start.elapsed();
        let start = Instant::now();
        let mut old_peer = delta.clone();
        oracle_drop(&mut old_peer, &delta, &local).unwrap();
        let old_drop = start.elapsed();

        assert_eq!(new_root, Ok(old_root));
        assert_eq!(new_peer.summary(), old_peer.summary());
        println!(
            "{label}: source {n}, local {}, remote {}: completion old {old_completion:?} new \
             {new_completion:?}; peer drop old {old_drop:?} new {new_drop:?}",
            local.len(),
            remote.len(),
        );
    }
}
