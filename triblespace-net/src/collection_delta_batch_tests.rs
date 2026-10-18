//! Exact batch-operation controls against ordinary canonical construction.
use super::*;
use ed25519_dalek::SigningKey;
use std::convert::Infallible;
use triblespace_core::collection::{
    CollectionCommit, CollectionData, CollectionMerge, empty_metadata_handle,
};

struct Delta {
    collection: CollectionHandle,
    added: Vec<CollectionRecord>,
    removed: Vec<CollectionRecord>,
}

impl CollectionRead for Delta {
    type RecordsError = Infallible;
    type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Infallible>>;
    fn records(&self) -> Result<Self::RecordIter<'_>, Infallible> {
        panic!("batch update must use exact selector delta")
    }
    fn collections(&self) -> Result<Vec<CollectionHandle>, Infallible> {
        panic!("no global enumeration")
    }
    fn select_record_changes(
        &self,
        previous: &Self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<(Vec<CollectionRecord>, Vec<CollectionRecord>), Infallible> {
        assert_eq!(self.collection, previous.collection);
        assert_eq!(
            selectors,
            &BTreeSet::from([CollectionRecordSelector::Foundations(self.collection)])
        );
        Ok((self.added.clone(), self.removed.clone()))
    }
}

fn record(collection: CollectionHandle, n: u64) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[47; 32]),
        collection,
        CollectionData::new(*blake3::hash(&n.to_be_bytes()).as_bytes()),
        empty_metadata_handle(),
    ))
}

#[test]
fn batch_matches_native_oracle_for_add_remove_overlap_duplicates_and_old_pin() {
    let collection = CollectionHandle::new([48; 32]);
    let all: Vec<_> = (0..320).map(|n| record(collection, n)).collect();
    let prior = canonical_records(collection, all[..256].iter().copied()).unwrap();
    let pinned = prior.clone();
    let before = Delta {
        collection,
        added: vec![],
        removed: vec![],
    };
    // Duplicate additions, existing additions, absent removal, and remove+add
    // overlap retain the old per-record remove-then-add semantics.
    let mut added = all[256..].to_vec();
    added.extend([all[0], all[300], all[100]]);
    let mut removed = all[..64].to_vec();
    removed.extend([all[0], all[300]]);
    let after = Delta {
        collection,
        added,
        removed,
    };
    let next = update_collection_record_patch(&after, &before, &prior).unwrap();
    let expected =
        canonical_records(collection, all[64..].iter().copied().chain([all[0]])).unwrap();
    assert_eq!(next.summaries(), expected.summaries());
    assert_eq!(
        next.records().collect::<Vec<_>>(),
        expected.records().collect::<Vec<_>>()
    );
    assert_eq!(pinned.summaries(), prior.summaries());
    assert!(
        all[..256]
            .iter()
            .all(|r| pinned.get(r.fingerprint()) == Some(*r))
    );
    let same = update_collection_record_patch(&before, &before, &prior).unwrap();
    assert_eq!(same.summaries(), prior.summaries());
    let clear = Delta {
        collection,
        added: vec![],
        removed: all[..256].to_vec(),
    };
    assert!(
        update_collection_record_patch(&clear, &before, &prior)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn batch_keeps_wrong_collection_and_nonfoundation_rejections() {
    let collection = CollectionHandle::new([49; 32]);
    let before = Delta {
        collection,
        added: vec![],
        removed: vec![],
    };
    let prior = canonical_records(collection, [] as [CollectionRecord; 0]).unwrap();
    let wrong = Delta {
        collection,
        added: vec![record(CollectionHandle::new([50; 32]), 1)],
        removed: vec![],
    };
    assert!(matches!(
        update_collection_record_patch(&wrong, &before, &prior),
        Err(CollectionRecordPatchError::Evidence(
            CollectionDeltaError::WrongCollection
        ))
    ));
    let merge = CollectionRecord::Merge(
        CollectionMerge::sign(
            &SigningKey::from_bytes(&[47; 32]),
            collection,
            (1..=8).map(|byte| CollectionData::new([byte; 32])),
            CollectionData::new([3; 32]),
        )
        .unwrap(),
    );
    for added in [false, true] {
        let delta = Delta {
            collection,
            added: if added { vec![merge] } else { vec![] },
            removed: if added { vec![] } else { vec![merge] },
        };
        assert!(matches!(
            update_collection_record_patch(&delta, &before, &prior),
            Err(CollectionRecordPatchError::Evidence(
                CollectionDeltaError::NotReplicated
            ))
        ));
    }
}

#[test]
fn batch_does_not_let_key_equality_hide_conflicting_attached_values() {
    let collection = CollectionHandle::new([51; 32]);
    let a = record(collection, 1);
    let b = record(collection, 2);
    let before = Delta {
        collection,
        added: vec![],
        removed: vec![],
    };
    // Deliberately invalid valued index models a fingerprint collision without
    // requiring a cryptographic collision or changing record fingerprints.
    let mut prior = canonical_records(collection, [] as [CollectionRecord; 0]).unwrap();
    prior
        .commits
        .insert(&PatchEntry::with_value(&a.fingerprint().raw(), CollectionRecordView::from(b).as_commit().unwrap().clone()));
    for adding in [false, true] {
        let delta = Delta {
            collection,
            added: if adding { vec![a] } else { vec![] },
            removed: if adding { vec![] } else { vec![a] },
        };
        assert!(
            matches!(update_collection_record_patch(&delta, &before, &prior), Err(CollectionRecordPatchError::Evidence(CollectionDeltaError::FingerprintCollision(key))) if key == a.fingerprint())
        );
    }
    // The same insertion helper guards a batch-local map, before native union.
    assert!(
        matches!(insert_record(collection, &mut prior, a), Err(CollectionDeltaError::FingerprintCollision(key)) if key == a.fingerprint())
    );
}
