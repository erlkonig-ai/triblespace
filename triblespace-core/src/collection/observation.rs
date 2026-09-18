//! Target-first, passive collection attachment.
//!
//! A producer's accepted signature endorses its output and input validation.
//! Reading that output therefore does not require reconstructing its historical
//! support. Exact native witnesses are retained for an explicit provenance read.

use std::collections::{BTreeMap, BTreeSet};

use crate::repo::StoreRead;

use super::encoding::{collection_member_availability, CollectionMemberAvailability};
use super::{
    descriptor, Collection, CollectionData, CollectionEncoding, CollectionHandle, CollectionRead,
    CollectionRealizationError, CollectionRecord, CollectionRecordFingerprint,
    CollectionRecordSelector, CollectionSnapshot, Cover,
};

/// Admit only target producers and select their resident output frontier.
pub(super) fn attach<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<CollectionSnapshot<R, E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let observed = super::observed_store::ObservedStore::new(snapshot.clone());
    let snapshot = &observed;
    let loaded = super::api::load_collection_descriptor(snapshot, target.handle())
        .map_err(|error| CollectionRealizationError::storage("read target descriptor", error))?;
    super::encoding::validate_descriptor_type::<E>(&loaded.fragment)
        .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
    let source = descriptor::source(loaded.fragment.facts())
        .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
    let evidence = super::api::discover_admission_evidence(
        snapshot,
        descriptor::admission_policies(
            snapshot,
            loaded.fragment.facts(),
            super::ACTION_WRITE,
            Some(E::id()),
        ),
        super::ACTION_WRITE,
        target.handle(),
    )
    .map_err(|error| CollectionRealizationError::storage("read target WRITE evidence", error))?;
    let candidates = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            target.handle(),
        )]))
        .map_err(|error| CollectionRealizationError::storage("read target records", error))?;
    let mut admitted = BTreeMap::new();
    let mut records = BTreeMap::new();
    for record in candidates {
        if matches!(record, CollectionRecord::Commit(_)) && source.is_some()
            || matches!(record, CollectionRecord::Derive(_)) && source.is_none()
        {
            continue;
        }
        let authorized = *admitted.entry(record.public_key().raw).or_insert_with(|| {
            ed25519_dalek::VerifyingKey::from_bytes(&record.public_key().raw)
                .ok()
                .is_some_and(|key| evidence.authorizes(snapshot, key))
        });
        if authorized {
            records.insert(record.fingerprint(), record);
        }
    }

    // Conflicting endorsed outputs are not an ordering choice. Check the
    // target's stated operations only; this neither reconstructs support nor
    // recomputes any result.
    super::resolution::check_functional(
        records.values().filter_map(|record| match record {
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                Some((
                    (merge.collection(), low, high, merge.result()),
                    Some(*merge),
                ))
            }
            _ => None,
        }),
        records.values().filter_map(|record| match record {
            CollectionRecord::Derive(derive) => Some((
                (derive.collection(), derive.input(), derive.output()),
                Some(*derive),
            )),
            _ => None,
        }),
    )
    .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;

    // The raw same-target relationships order the search, not admission.
    // An unavailable parent leaves its finer admitted inputs available. A
    // rejected producer never enters this graph and cannot hide its children.
    let mut consumed = BTreeSet::new();
    for record in records.values() {
        consumed.extend(merge_inputs(*record, &records));
    }
    let mut pending: Vec<_> = records
        .keys()
        .filter(|id| !consumed.contains(*id))
        .copied()
        .collect();
    let mut visited = BTreeSet::new();
    let mut suppressed = BTreeSet::new();
    let mut selected = BTreeSet::new();
    let mut available = BTreeMap::new();
    loop {
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            let record = records[&id];
            let member = super::witness::output(record);
            let complete = match available.get(&member) {
                Some(complete) => *complete,
                None => {
                    let complete = matches!(
                        collection_member_availability::<E, _>(member, snapshot).map_err(
                            |error| CollectionRealizationError::storage(
                                "inspect target representation residency",
                                error,
                            ),
                        )?,
                        CollectionMemberAvailability::Complete
                    );
                    available.insert(member, complete);
                    complete
                }
            };
            let inputs = merge_inputs(record, &records);
            if complete {
                selected.insert(id);
                // Only exact same-lattice witness ancestry is removed. An
                // equal payload with a different witness remains independent.
                let mut covered = inputs;
                while let Some(input) = covered.pop() {
                    if suppressed.insert(input) {
                        visited.insert(input);
                        selected.remove(&input);
                        covered.extend(merge_inputs(records[&input], &records));
                    }
                }
            } else {
                pending.extend(inputs);
            }
        }
        // A malformed/ungrounded cycle must not hide an otherwise admitted
        // resident output. No ancestry closure is asserted by attachment.
        match records.keys().find(|id| !visited.contains(*id)) {
            Some(id) => pending.push(*id),
            None => break,
        }
    }

    if let Some(source) = source {
        coarsen_images(snapshot, target.handle(), source, &records, &mut selected)?;
    }
    let witnesses: Vec<_> = selected.into_iter().map(|id| records[&id]).collect();
    let cover = Cover::from_data(
        target,
        witnesses.iter().copied().map(super::witness::output),
    );
    Ok(CollectionSnapshot::from_endorsements(
        observed.inner().clone(),
        cover,
        loaded.fragment,
        witnesses,
        observed.tracker(),
    ))
}

#[cfg(test)]
mod tests;

/// Which records in this set produce a merge's inputs.
///
/// A merge names its input PAYLOADS, so its inputs are whatever produces them
/// in the same collection. That is what the old cited-witness form checked for
/// anyway -- it looked a fingerprint up and then verified the record was in
/// this collection and produced this payload, which is exactly the
/// `(collection, payload)` key. Content addressing already holds the relation;
/// the citation was a second copy of it.
fn merge_inputs(
    record: CollectionRecord,
    records: &BTreeMap<CollectionRecordFingerprint, CollectionRecord>,
) -> Vec<CollectionRecordFingerprint> {
    let CollectionRecord::Merge(merge) = record else {
        return Vec::new();
    };
    let (low, high) = merge.inputs();
    let self_id = record.fingerprint();
    records
        .iter()
        .filter(|(id, input)| {
            // A merge may name its own result as an input -- `MERGE(x, x) -> x`
            // is legal and appears in practice. Under content addressing it
            // would then be its own input, be marked consumed, and never be
            // reachable as a root. A citation could not express that because a
            // witness named some other record; the payload form has to say so.
            **id != self_id
                && input.collection() == merge.collection()
                && {
                    let produced = super::witness::output(**input);
                    produced == low || produced == high
                }
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Reuse a coarser image when source order proves it covers a selected finer
/// image. Walk consumers upward, never foundational leaves downward. Missing
/// relationships merely leave a finer cover.
///
/// The walk is over PAYLOADS rather than over cited records: from the payload
/// a candidate image reads, upward through whatever consumes it. A merge in
/// the source consumes its two inputs; a derive into the target consumes the
/// source payload it maps. Neither needs a witness to say so, because both
/// already name the payload.
fn coarsen_images<R: StoreRead>(
    snapshot: &R,
    target: CollectionHandle,
    source: CollectionHandle,
    records: &BTreeMap<CollectionRecordFingerprint, CollectionRecord>,
    selected: &mut BTreeSet<CollectionRecordFingerprint>,
) -> Result<(), CollectionRealizationError> {
    let images: Vec<_> = selected
        .iter()
        .filter_map(|id| match records[id] {
            CollectionRecord::Derive(derive) => Some((*id, derive)),
            _ => None,
        })
        .collect();
    if images.len() < 2 {
        return Ok(());
    }
    // Every record that could sit above a source payload, in one read.
    let upward = snapshot
        .select_records(&BTreeSet::from([
            CollectionRecordSelector::Collection(source),
            CollectionRecordSelector::DeriveTarget(target),
        ]))
        .map_err(|error| CollectionRealizationError::storage("read source order", error))?;
    let mut consumers: BTreeMap<CollectionData, Vec<CollectionRecord>> = BTreeMap::new();
    for record in upward {
        match record {
            CollectionRecord::Merge(merge) if merge.collection() == source => {
                let (low, high) = merge.inputs();
                consumers.entry(low).or_default().push(record);
                if high != low {
                    consumers.entry(high).or_default().push(record);
                }
            }
            CollectionRecord::Derive(derive) if derive.collection() == target => {
                consumers.entry(derive.input()).or_default().push(record);
            }
            _ => {}
        }
    }
    for (candidate, derive) in images {
        if !selected.contains(&candidate) {
            continue;
        }
        let mut pending = vec![derive.input()];
        let mut visited = BTreeSet::new();
        let mut subsumed = false;
        while let Some(data) = pending.pop() {
            if !visited.insert(data) {
                continue;
            }
            for record in consumers.get(&data).into_iter().flatten() {
                match record {
                    CollectionRecord::Merge(merge) => pending.push(merge.result()),
                    CollectionRecord::Derive(parent)
                        if record.fingerprint() != candidate
                            && selected.contains(&record.fingerprint()) =>
                    {
                        let _ = parent;
                        subsumed = true;
                        break;
                    }
                    _ => {}
                }
            }
            if subsumed {
                break;
            }
        }
        if subsumed {
            selected.remove(&candidate);
        }
    }
    Ok(())
}
