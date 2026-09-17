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
///
/// A closed record's support is a property of that record's own immutable
/// witness DAG and of the descriptor lineage naming each `DERIVE`'s source.
/// Records are content addressed and storage is grow-only, so one operation
/// establishes it once and every later resolution over the same lineage reads
/// the same answer. Both inputs are remembered here: a different lineage names
/// different sources and starts a new memo rather than answering from the old
/// one.
///
/// Only closed results are retained. That a record is not *yet* closed is an
/// absence in one snapshot rather than a fact about the record, and the same
/// operation may close it by publishing the witness it was missing.
#[derive(Default)]
pub(super) struct WitnessMemo {
    lineage: Option<(
        Collection<SimpleArchive>,
        BTreeMap<CollectionHandle, CollectionHandle>,
    )>,
    records: BTreeMap<CollectionRecordFingerprint, CollectionRecord>,
    support: BTreeMap<CollectionRecordFingerprint, Support>,
}

impl WitnessMemo {
    /// Open one resolution over `foundation` and `source_by_target`, reusing
    /// whatever an earlier resolution over that same lineage established.
    pub(super) fn closure<'a>(
        &'a mut self,
        foundation: Collection<SimpleArchive>,
        source_by_target: &'a BTreeMap<CollectionHandle, CollectionHandle>,
    ) -> WitnessClosure<'a> {
        let bound = self
            .lineage
            .as_ref()
            .is_some_and(|(known, sources)| *known == foundation && sources == source_by_target);
        if !bound {
            self.records.clear();
            self.support.clear();
            self.lineage = Some((foundation, source_by_target.clone()));
        }
        WitnessClosure {
            memo: self,
            foundation,
            source_by_target,
            unresolved: BTreeSet::new(),
        }
    }
}

pub(super) fn output(record: CollectionRecord) -> CollectionData {
    match record {
        CollectionRecord::Commit(record) => record.data(),
        CollectionRecord::Merge(record) => record.result(),
        CollectionRecord::Derive(record) => record.output(),
    }
}

/// One resolution's walk over a [`WitnessMemo`].
pub(super) struct WitnessClosure<'a> {
    memo: &'a mut WitnessMemo,
    foundation: Collection<SimpleArchive>,
    source_by_target: &'a BTreeMap<CollectionHandle, CollectionHandle>,
    unresolved: BTreeSet<CollectionRecordFingerprint>,
}

impl WitnessClosure<'_> {
    /// Resolve only the references named by this record, iteratively so an
    /// arbitrarily deep retained history does not consume the call stack.
    pub(super) fn support<R: CollectionRead>(
        &mut self,
        snapshot: &R,
        root: CollectionRecord,
    ) -> Result<Option<Support>, R::RecordsError> {
        let root_id = root.fingerprint();
        self.memo.records.entry(root_id).or_insert(root);
        let mut pending = vec![(root_id, false)];
        let mut visiting = BTreeSet::new();
        while let Some((id, finish)) = pending.pop() {
            if self.memo.support.contains_key(&id) || self.unresolved.contains(&id) {
                continue;
            }
            let record = match self.memo.records.get(&id).copied() {
                Some(record) => record,
                None => match snapshot.record(id)? {
                    Some(record) => {
                        self.memo.records.insert(id, record);
                        record
                    }
                    None => {
                        self.unresolved.insert(id);
                        continue;
                    }
                },
            };
            if let CollectionRecord::Commit(commit) = record {
                if commit.collection() == self.foundation.handle() {
                    self.memo
                        .support
                        .insert(id, Support::from_data(self.foundation, [commit.data()]));
                } else {
                    self.unresolved.insert(id);
                }
                continue;
            }
            if finish {
                visiting.remove(&id);
                let mut support = Support::from_data(self.foundation, []);
                let mut closed = true;
                for input in record.record_references() {
                    match self.memo.support.get(&input) {
                        Some(input_support) => {
                            support = support.union(input_support).expect("one foundation");
                        }
                        None => {
                            closed = false;
                            break;
                        }
                    }
                }
                if closed {
                    self.memo.support.insert(id, support);
                } else {
                    self.unresolved.insert(id);
                }
                continue;
            }
            if !visiting.insert(id) {
                self.unresolved.insert(id);
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
                    let Some(source) = self.source_by_target.get(&derive.collection()) else {
                        self.unresolved.insert(id);
                        continue;
                    };
                    vec![(derive.input_witness(), *source, derive.input())]
                }
            };
            let mut closed = true;
            for (input, collection, data) in &expected {
                let predecessor = match self.memo.records.get(input).copied() {
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
                self.memo.records.insert(*input, predecessor);
            }
            if !closed {
                self.unresolved.insert(id);
                continue;
            }
            pending.push((id, true));
            pending.extend(expected.into_iter().map(|(input, _, _)| (input, false)));
        }
        Ok(self.memo.support.get(&root_id).cloned())
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
            let record = self.memo.records[&id];
            pending.extend(record.record_references());
        }
        selected
            .into_iter()
            .map(|id| self.memo.records[&id])
            .collect()
    }
}
