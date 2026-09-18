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
    CollectionRecordFingerprint,
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
            self.lineage = Some((foundation, source_by_target.clone()));
        }
        WitnessClosure {
            memo: self,
            source_by_target,
            produced: BTreeMap::new(),
        }
    }
}

pub(super) fn output(record: CollectionRecord) -> CollectionData {
    super::coverage::Attestation::of(&record).result()
}

/// One resolution's view of which records exist and what they produce.
pub(super) struct WitnessClosure<'a> {
    memo: &'a mut WitnessMemo,
    source_by_target: &'a BTreeMap<CollectionHandle, CollectionHandle>,
    /// Which records produce each `(collection, payload)`.
    ///
    /// The production graph. Expansion follows it instead of a record's cited
    /// witnesses: a record names its input PAYLOADS, and this says who makes
    /// them. Content-addressed, so it needs nothing stored on the record —
    /// which is what lets the witness fields go.
    produced: BTreeMap<(CollectionHandle, CollectionData), Vec<CollectionRecordFingerprint>>,
}

impl WitnessClosure<'_> {
    /// Index what exists and what produces what.
    ///
    /// No admission decision is made here any more. Whether an attestation is
    /// believed is settled once, in the coverage fold, and a record's support
    /// is read from that index rather than walked. This answers only the
    /// existential question -- which records are here, and which of them make
    /// each payload -- because that is the one the coverage index deliberately
    /// does not keep.
    pub(super) fn index_edges<R: CollectionRead>(
        &mut self,
        snapshot: &R,
    ) -> Result<(), R::RecordsError> {
        if !self.produced.is_empty() {
            return Ok(());
        }
        for record in snapshot.records()? {
            let record = record?;
            self.memo.records.insert(record.fingerprint(), record);
            self.produced
                .entry((record.collection(), output(record)))
                .or_default()
                .push(record.fingerprint());
        }
        Ok(())
    }

    /// Retain every record needed to account for the selected endorsements.
    ///
    /// Expansion follows PRODUCTION, not citation: a record names its input
    /// payloads, and [`Self::produced`] says which records make them. That
    /// reaches the same closure a cited-witness walk did, without reading a
    /// witness — content addressing already relates a consumer to its inputs,
    /// and storing the relation again on the record was the redundancy.
    ///
    /// Where a citation named one route, production names every record that
    /// makes the payload. That is wider, and deliberately so: which route a
    /// producer happened to mean is not a fact a reader needs, and retaining
    /// the alternatives is the conservative direction for a set whose purpose
    /// is to decide what to keep and transfer.
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
            let Some(record) = self.memo.records.get(&id).copied() else {
                continue;
            };
            let collection = record.collection();
            let inputs: Vec<(CollectionHandle, CollectionData)> = match record {
                CollectionRecord::Commit(_) => Vec::new(),
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    vec![(collection, low), (collection, high)]
                }
                CollectionRecord::Derive(derive) => self
                    .source_by_target
                    .get(&collection)
                    .map(|source| vec![(*source, derive.input())])
                    .unwrap_or_default(),
            };
            for key in inputs {
                if let Some(producers) = self.produced.get(&key) {
                    pending.extend(producers.iter().copied());
                }
            }
        }
        selected
            .into_iter()
            .filter_map(|id| self.memo.records.get(&id).copied())
            .collect()
    }
}
