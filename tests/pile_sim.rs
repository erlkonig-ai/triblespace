use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use std::collections::HashMap;
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use triblespace::core::collection::{
    CollectionCommit, CollectionMerge, CollectionRead, CollectionRecord,
    CollectionRecordFingerprint, CollectionStore,
};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Put(Vec<u8>),
    Flush,
    Refresh,
    Amputate,
    Get(usize),
    MergeRecord {
        collection: usize,
        left: usize,
        right: usize,
        result: usize,
    },
    CollectionList,
}

#[derive(Debug, Clone)]
enum ActorOp {
    Run { actor: usize, op: Op },
    Check,
}

#[derive(Debug, Clone)]
struct Scenario {
    actors: usize,
    ops: Vec<ActorOp>,
}

fn actor_op_strategy(actors: usize) -> impl Strategy<Value = ActorOp> {
    let data = prop::collection::vec(any::<u8>(), 0..32);
    let idx = 0usize..20;
    prop_oneof![
        (0..actors, data).prop_map(|(actor, data)| ActorOp::Run {
            actor,
            op: Op::Put(data),
        }),
        (0..actors).prop_map(|actor| ActorOp::Run {
            actor,
            op: Op::Flush,
        }),
        (0..actors).prop_map(|actor| ActorOp::Run {
            actor,
            op: Op::Refresh,
        }),
        (0..actors).prop_map(|actor| ActorOp::Run {
            actor,
            op: Op::Amputate,
        }),
        (0..actors, idx.clone()).prop_map(|(actor, index)| ActorOp::Run {
            actor,
            op: Op::Get(index),
        }),
        (0..actors, idx.clone(), idx.clone(), idx.clone(), idx,).prop_map(
            |(actor, collection, left, right, result)| ActorOp::Run {
                actor,
                op: Op::MergeRecord {
                    collection,
                    left,
                    right,
                    result,
                },
            }
        ),
        (0..actors).prop_map(|actor| ActorOp::Run {
            actor,
            op: Op::CollectionList,
        }),
        Just(ActorOp::Check),
    ]
}

fn scenario_strategy(max_actors: usize) -> impl Strategy<Value = Scenario> {
    (1..=max_actors).prop_flat_map(move |actors| {
        prop::collection::vec(actor_op_strategy(actors), 1..20)
            .prop_map(move |ops| Scenario { actors, ops })
    })
}

fn observed_records(pile: &mut Pile) -> Vec<CollectionRecord> {
    pile.refresh().unwrap();
    pile.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn assert_known_records(
    pile: &mut Pile,
    expected: &HashMap<CollectionRecordFingerprint, CollectionRecord>,
) -> Result<(), TestCaseError> {
    let found = observed_records(pile);
    prop_assert_eq!(found.len(), expected.len());
    for record in found {
        prop_assert_eq!(expected.get(&record.fingerprint()), Some(&record));
    }
    Ok(())
}

proptest! {
    #[test]
    fn pile_operation_sequences_are_consistent(scenario in scenario_strategy(4)) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sim.pile");
        std::fs::File::create(&path).unwrap();
        let mut piles: Vec<Pile> =
            (0..scenario.actors).map(|_| Pile::open(&path).unwrap()).collect();
        let mut expected_blobs: HashMap<Inline<Handle<UnknownBlob>>, Vec<u8>> = HashMap::new();
        let mut handles: Vec<Inline<Handle<UnknownBlob>>> = Vec::new();
        let mut expected_records: HashMap<CollectionRecordFingerprint, CollectionRecord> = HashMap::new();
        // This tests physical record union, without descriptors or admission.
        // One fixture signer preserves identical-record dedup across actors.
        let signing_key = SigningKey::from_bytes(&[1; 32]);
        let metadata_blob: Blob<SimpleArchive> = TribleSet::new().to_blob();
        let metadata = piles[0].put::<SimpleArchive, _>(metadata_blob.clone()).unwrap();
        expected_blobs.insert(metadata.transmute(), metadata_blob.bytes.as_ref().to_vec());

        for actor_op in scenario.ops {
            match actor_op {
                ActorOp::Run { actor, op } => match op {
                    Op::Put(data) => {
                        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
                        let handle = piles[actor].put::<UnknownBlob, _>(blob).unwrap();
                        expected_blobs.insert(handle, data);
                        handles.push(handle);
                    }
                    Op::Flush => piles[actor].flush().unwrap(),
                    Op::Refresh => {
                        let _ = piles[actor].refresh();
                    }
                    Op::Amputate => {
                        piles[actor] = Pile::open(&path).unwrap();
                        piles[actor].amputate().unwrap();
                    }
                    Op::Get(index) => {
                        if let Some(handle) = handles.get(index % handles.len().max(1)).copied() {
                            piles[actor].refresh().unwrap();
                            if let Ok(blob) = piles[actor]
                                .snapshot()
                                .unwrap()
                                .get::<Blob<UnknownBlob>, _>(handle)
                            {
                                prop_assert_eq!(
                                    blob.bytes.as_ref(),
                                    expected_blobs.get(&handle).unwrap().as_slice(),
                                );
                            }
                        }
                    }
                    Op::MergeRecord { collection, left, right, result } => {
                        if !handles.is_empty() {
                            let at = |index: usize| handles[index % handles.len()].transmute();
                            let collection = at(collection);
                            let [left, right] = [left, right].map(|index| {
                                CollectionCommit::sign(
                                    &signing_key,
                                    collection,
                                    at(index).into(),
                                    metadata,
                                )
                            });
                            // Persist the exact input witnesses before the endorsement;
                            // their physical union is part of the state-machine oracle.
                            for witness in [left, right] {
                                let record = CollectionRecord::Commit(witness);
                                piles[actor].insert(record).unwrap();
                                expected_records.insert(record.fingerprint(), record);
                            }
                            let record = CollectionRecord::Merge(CollectionMerge::sign(
                                &signing_key,
                                collection,
                                (left.data(), left.fingerprint()),
                                (right.data(), right.fingerprint()),
                                at(result).into(),
                            ));
                            piles[actor].insert(record).unwrap();
                            expected_records.insert(record.fingerprint(), record);
                        }
                    }
                    Op::CollectionList => {
                        assert_known_records(&mut piles[actor], &expected_records)?;
                    }
                },
                ActorOp::Check => {
                    for pile in &mut piles {
                        pile.refresh().unwrap();
                        let snapshot = pile.snapshot().unwrap();
                        for (handle, data) in &expected_blobs {
                            if let Ok(blob) = snapshot.get::<Blob<UnknownBlob>, _>(*handle) {
                                prop_assert_eq!(blob.bytes.as_ref(), data.as_slice());
                            }
                        }
                        assert_known_records(pile, &expected_records)?;
                    }
                }
            }
        }

        for pile in &mut piles {
            pile.flush().unwrap();
            pile.refresh().unwrap();
        }
        for pile in piles {
            pile.close().unwrap();
        }

        let mut final_pile = Pile::open(&path).unwrap();
        final_pile.amputate().unwrap();
        let snapshot = final_pile.snapshot().unwrap();
        for (handle, data) in &expected_blobs {
            let blob = snapshot.get::<Blob<UnknownBlob>, _>(*handle).unwrap();
            prop_assert_eq!(blob.bytes.as_ref(), data.as_slice());
        }
        drop(snapshot);
        assert_known_records(&mut final_pile, &expected_records)?;
        final_pile.close().unwrap();
    }
}
