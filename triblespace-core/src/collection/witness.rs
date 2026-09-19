//! Which records must survive to account for a set of selected endorsements.
//!
//! Support is a different question and has a different answer: the coverage
//! index says what a node stands for, and says it in one lookup. This says
//! which RECORDS have to be here, which is exactly what that index forgets.
//! No ancestor payload, metadata, capability proof, or signature is read or
//! checked here, and a missing record stays unknown rather than becoming an
//! empty answer.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CollectionData, CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector,
};

/// Retain every record needed to account for the selected endorsements.
///
/// Expansion follows PRODUCTION, not citation: a record names its input
/// PAYLOADS, and the store says which records make them. That reaches the
/// same closure a cited-witness walk did, without reading a witness --
/// content addressing already relates a consumer to its inputs, and storing
/// the relation again on the record was the redundancy.
///
/// Where a citation named one route, production names every record that makes
/// the payload. That is wider, and deliberately so: which route a producer
/// happened to mean is not a fact a reader needs, and retaining the
/// alternatives is the conservative direction for a set whose purpose is to
/// decide what to keep and transfer.
///
/// The one step is an indexed selection -- the producers of one
/// `(collection, payload)` -- so a store that maintains that relation answers
/// without enumerating anything. An earlier version built the production map
/// by scanning every record once per resolution, which is the same answer at
/// the cost of a full pass over the pile.
pub(super) fn records_for<R: CollectionRead>(
    snapshot: &R,
    roots: impl IntoIterator<Item = CollectionRecord>,
    source_by_target: &BTreeMap<CollectionHandle, CollectionHandle>,
) -> Result<Vec<CollectionRecord>, R::RecordsError> {
    let mut selected = BTreeSet::new();
    let mut pending: Vec<_> = roots.into_iter().collect();
    while let Some(record) = pending.pop() {
        if !selected.insert(record) {
            continue;
        }
        let collection = record.collection();
        let inputs: Vec<(CollectionHandle, CollectionData)> = match record {
            CollectionRecord::Commit(_) => Vec::new(),
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                vec![(collection, low), (collection, high)]
            }
            // A DERIVE's input lives in the collection its descriptor names as
            // the source, so the lineage supplies the owner the payload is
            // produced under.
            CollectionRecord::Derive(derive) => source_by_target
                .get(&collection)
                .map(|source| vec![(*source, derive.input())])
                .unwrap_or_default(),
        };
        for key in inputs {
            let producers = snapshot.select_records(&BTreeSet::from([
                CollectionRecordSelector::ProducedMember(key.0, key.1),
            ]))?;
            pending.extend(producers);
        }
    }
    Ok(selected.into_iter().collect())
}
