//! Exact record ancestry endorsed by a signed collection equation.
//!
//! This walk establishes closure, not a second authorization decision. The
//! caller admits the selected producer; that producer attests the validity of
//! these exact input records. No ancestor payload, metadata, capability proof,
//! or signature is read or checked here. Missing records remain unknown, never
//! an empty support and never an instruction to disclose another collection.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Collection, CollectionData, CollectionHandle, CollectionRead, CollectionRecord,
    CollectionRecordFingerprint, Support,
};
use crate::blob::encodings::simplearchive::SimpleArchive;

/// Operation-local memoization of immutable record references. Not persisted.
#[derive(Default)]
pub(super) struct WitnessClosure {
    records: BTreeMap<CollectionRecordFingerprint, CollectionRecord>,
    support: BTreeMap<CollectionRecordFingerprint, Option<Support>>,
}

pub(super) fn output(record: CollectionRecord) -> CollectionData {
    match record {
        CollectionRecord::Commit(record) => record.data(),
        CollectionRecord::Merge(record) => record.result(),
        CollectionRecord::Derive(record) => record.output(),
    }
}

impl WitnessClosure {
    /// Resolve only the references named by this record, iteratively so an
    /// arbitrarily deep retained history does not consume the call stack.
    pub(super) fn support<R: CollectionRead>(
        &mut self,
        snapshot: &R,
        foundation: Collection<SimpleArchive>,
        source_by_target: &BTreeMap<CollectionHandle, CollectionHandle>,
        root: CollectionRecord,
    ) -> Result<Option<Support>, R::RecordsError> {
        let root_id = root.fingerprint();
        self.records.entry(root_id).or_insert(root);
        let mut pending = vec![(root_id, false)];
        let mut visiting = BTreeSet::new();
        while let Some((id, finish)) = pending.pop() {
            if self.support.contains_key(&id) {
                continue;
            }
            let record = match self.records.get(&id).copied() {
                Some(record) => record,
                None => match snapshot.record(id)? {
                    Some(record) => {
                        self.records.insert(id, record);
                        record
                    }
                    None => {
                        self.support.insert(id, None);
                        continue;
                    }
                },
            };
            if let CollectionRecord::Commit(commit) = record {
                self.support.insert(
                    id,
                    (commit.collection() == foundation.handle())
                        .then(|| Support::from_data(foundation, [commit.data()])),
                );
                continue;
            }
            if finish {
                visiting.remove(&id);
                let mut support = Support::from_data(foundation, []);
                let mut closed = true;
                for input in record.record_references() {
                    match self.support.get(&input).and_then(Option::as_ref) {
                        Some(input_support) => {
                            support = support.union(input_support).expect("one foundation");
                        }
                        None => {
                            closed = false;
                            break;
                        }
                    }
                }
                self.support.insert(id, closed.then_some(support));
                continue;
            }
            if !visiting.insert(id) {
                self.support.insert(id, None);
                continue;
            }
            let expected: Vec<_> = match record {
                CollectionRecord::Commit(_) => unreachable!(),
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    let (low_record, high_record) = merge.input_witnesses();
                    vec![
                        (low_record, merge.collection(), low),
                        (high_record, merge.collection(), high),
                    ]
                }
                CollectionRecord::Derive(derive) => {
                    let Some(source) = source_by_target.get(&derive.collection()) else {
                        self.support.insert(id, None);
                        continue;
                    };
                    vec![(derive.input_witness(), *source, derive.input())]
                }
            };
            let mut closed = true;
            for (input, collection, data) in &expected {
                let predecessor = match self.records.get(input).copied() {
                    Some(record) => Some(record),
                    None => snapshot.record(*input)?,
                };
                let Some(predecessor) = predecessor else {
                    closed = false;
                    break;
                };
                if predecessor.collection() != *collection || output(predecessor) != *data {
                    closed = false;
                    break;
                }
                self.records.insert(*input, predecessor);
            }
            if !closed {
                self.support.insert(id, None);
                continue;
            }
            pending.push((id, true));
            pending.extend(expected.into_iter().map(|(input, _, _)| (input, false)));
        }
        Ok(self.support.get(&root_id).cloned().flatten())
    }

    /// Retain the exact closed witness DAG reachable from accepted producers.
    /// Unrelated equations sharing a payload hash never enter this set.
    pub(super) fn records_for(
        &self,
        roots: impl IntoIterator<Item = CollectionRecordFingerprint>,
    ) -> Vec<CollectionRecord> {
        let mut selected = BTreeSet::new();
        let mut pending: Vec<_> = roots.into_iter().collect();
        while let Some(id) = pending.pop() {
            if !selected.insert(id) {
                continue;
            }
            let record = self.records[&id];
            pending.extend(record.record_references());
        }
        selected.into_iter().map(|id| self.records[&id]).collect()
    }
}
