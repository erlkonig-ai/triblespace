//! Native storage for collection-calculus records.
//!
//! A collection store is a grow-only set keyed by a full-width fingerprint of
//! each record's canonical bytes.
//! It deliberately exposes no mutable head, deletion, compare-and-swap, or
//! read-through-writer path. A [`CollectionRead`] implementation belongs to an
//! immutable store snapshot, while [`CollectionStore`] only admits new records.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;

use crate::repo::WantRequest;

use super::{CollectionData, CollectionHandle, CollectionRecord, CollectionRecordFingerprint};

/// One semantic route into the grow-only collection-record set.
///
/// A batch of selectors is interpreted as set union. Exact operation lookup
/// deliberately names only the inputs: every distinct asserted result remains
/// visible to callers as conflicting evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CollectionRecordSelector {
    /// Select one record by its non-semantic canonical-byte fingerprint.
    Fingerprint(CollectionRecordFingerprint),
    /// Select every record whose intrinsic collection is exactly `C`.
    ///
    /// This is the canonical construction route for one collection's sparse
    /// overlay inventory. It includes signed `COMMIT`s and unsigned `MERGE`
    /// and `DERIVE` equations without exposing or enumerating unrelated
    /// collections.
    Collection(CollectionHandle),
    /// Select every signed membership claim for one exact collection element.
    ///
    /// Several authors or metadata archives may attest the same data member;
    /// all of those claims remain provenance over one payload identity.
    CommitMember(CollectionHandle, CollectionData),
    /// Select every `MERGE` asserted for one collection descriptor.
    MergeCollection(CollectionHandle),
    /// Select every `DERIVE` into one exact target descriptor.
    ///
    /// The source is not part of the selector: a target has one source, named
    /// by its descriptor, so selecting the target selects the mapping.
    DeriveTarget(CollectionHandle),
    /// Select every receipt answering one exact merge or derive request.
    ///
    /// Blob requests have no collection-record answer and select nothing.
    Operation(WantRequest),
}

fn collection_record_operation(record: CollectionRecord) -> Option<WantRequest> {
    match record {
        CollectionRecord::Commit(_) => None,
        CollectionRecord::Merge(record) => {
            let (low, high) = record.inputs();
            Some(WantRequest::merge(record.collection(), low, high))
        }
        CollectionRecord::Derive(record) => {
            let (input, _) = (record.input(), record.output());
            Some(WantRequest::derive(record.collection(), input))
        }
    }
}

pub(crate) fn selectors_match_record(
    selectors: &BTreeSet<CollectionRecordSelector>,
    record: CollectionRecord,
) -> bool {
    if selectors.contains(&CollectionRecordSelector::Fingerprint(record.fingerprint())) {
        return true;
    }
    let collection = match record {
        CollectionRecord::Commit(commit) => commit.collection(),
        CollectionRecord::Merge(merge) => merge.collection(),
        CollectionRecord::Derive(derive) => derive.collection(),
    };
    if selectors.contains(&CollectionRecordSelector::Collection(collection)) {
        return true;
    }
    match record {
        CollectionRecord::Commit(commit) => selectors.contains(
            &CollectionRecordSelector::CommitMember(commit.collection(), commit.data()),
        ),
        CollectionRecord::Merge(merge) => {
            selectors.contains(&CollectionRecordSelector::MergeCollection(
                merge.collection(),
            )) || selectors.contains(&CollectionRecordSelector::Operation(
                collection_record_operation(record).expect("MERGE has an operation key"),
            ))
        }
        CollectionRecord::Derive(derive) => {
            selectors.contains(&CollectionRecordSelector::DeriveTarget(derive.collection()))
                || selectors.contains(&CollectionRecordSelector::Operation(
                    collection_record_operation(record).expect("DERIVE has an operation key"),
                ))
        }
    }
}

/// Immutable read surface for canonical collection-calculus records.
///
/// Implementations enumerate one coherent store snapshot in deterministic
/// fingerprint order. Mutation lives on [`CollectionStore`], so admission and
/// physical-cover resolution cannot accidentally observe different prefixes.
/// Signatures are trusted here: foreign dense records are checked at ingress,
/// and local constructors sign their own records. Opening or concatenating a
/// raw pile is an explicit trust decision; audit unfamiliar piles before using
/// them as trusted storage. This contract does not grant WRITE authority,
/// which is evaluated against each snapshot's policy, proofs, and instant.
pub trait CollectionRead {
    /// Failure while enumerating stored records.
    type RecordsError: Error + Debug + Send + Sync + 'static;
    /// Borrowing iterator over one deterministic view of known records.
    type RecordIter<'a>: Iterator<Item = Result<CollectionRecord, Self::RecordsError>>
    where
        Self: 'a;

    /// Enumerate currently known records in deterministic fingerprint order.
    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError>;

    /// Look up one record by its canonical-byte fingerprint.
    ///
    /// The default implementation scans the deterministic record view once
    /// and stops as soon as it reaches or passes `fingerprint`. Backends with a keyed
    /// primary index should override this method.
    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        for record in self.records()? {
            let record = record?;
            match record.fingerprint().cmp(&fingerprint) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Ok(Some(record)),
                std::cmp::Ordering::Greater => break,
            }
        }
        Ok(None)
    }

    /// Select one deterministic union of semantic record routes.
    ///
    /// The default implementation performs exactly one ordinary enumeration
    /// and filters it. Backends with primary or secondary indexes may override
    /// this method without changing the grow-only set contract. Returned
    /// records remain deduplicated and sorted by fingerprint. An empty union
    /// returns immediately without asking the backend for a view.
    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        if selectors.is_empty() {
            return Ok(Vec::new());
        }
        let records = self.records()?;
        let mut selected = Vec::new();
        for record in records {
            let record = record?;
            if selectors_match_record(selectors, record) {
                selected.push(record);
            }
        }
        Ok(selected)
    }
}

impl<R> CollectionRead for &R
where
    R: CollectionRead + ?Sized,
{
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        (**self).records()
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        (**self).record(fingerprint)
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        (**self).select_records(selectors)
    }
}

/// Grow-only write surface for canonical collection-calculus records.
///
/// Inserting the same canonical record more than once is an idempotent
/// success. Records are never replaced through this interface. Read access is
/// deliberately obtained from the store's immutable snapshot instead.
pub trait CollectionStore {
    /// Failure while admitting one canonical record.
    type InsertError: Error + Debug + Send + Sync + 'static;

    /// Insert one canonical record.
    ///
    /// Re-inserting a record with the same canonical bytes is success and does not
    /// add another logical set member.
    ///
    /// This is the trusted typed boundary, not a foreign-byte decoder. The
    /// public dense record decoder verifies signatures before returning a
    /// value; local signing constructs one directly. Backends and transparent
    /// adapters must not repeat that cryptographic work. No capability proof
    /// is required for insertion: a signed record can arrive before the proof
    /// that later authorizes its producer.
    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError>;
}

impl<S> CollectionStore for &mut S
where
    S: CollectionStore + ?Sized,
{
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        (**self).insert(record)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::collection::{
        empty_metadata_handle, CollectionCommit, CollectionData, CollectionDerive, CollectionMerge,
    };
    use crate::inline::Inline;

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    fn fixture() -> Vec<CollectionRecord> {
        let source = collection(1);
        let target = collection(2);
        let other = collection(3);
        let input = data(10);
        let mut records = vec![
            CollectionRecord::Commit(CollectionCommit::sign(
                &SigningKey::from_bytes(&[7; 32]),
                source,
                data(4),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                source,
                data(4),
                data(5),
                data(6),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                other,
                data(4),
                data(5),
                data(7),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                target,
                input,
                data(11),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                target,
                input,
                data(12),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                target,
                data(13),
                data(14),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                other,
                input,
                data(15),
            )),
        ];
        records.sort_unstable_by_key(CollectionRecord::fingerprint);
        records
    }

    #[derive(Default)]
    struct FallbackStore {
        records: Vec<CollectionRecord>,
        enumerations: Cell<usize>,
    }

    impl CollectionRead for FallbackStore {
        type RecordsError = Infallible;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Infallible>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            self.enumerations.set(self.enumerations.get() + 1);
            Ok(self
                .records
                .iter()
                .copied()
                .map(Ok)
                .collect::<Vec<_>>()
                .into_iter())
        }
    }

    impl CollectionStore for FallbackStore {
        type InsertError = Infallible;

        fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
            self.records.push(record);
            self.records
                .sort_unstable_by_key(CollectionRecord::fingerprint);
            self.records.dedup_by_key(|record| record.fingerprint());
            Ok(())
        }
    }

    #[test]
    fn default_selection_scans_once_unions_routes_and_retains_operation_conflicts() {
        let records = fixture();
        let commit = records
            .iter()
            .find(|record| matches!(record, CollectionRecord::Commit(_)))
            .copied()
            .unwrap();
        let source = collection(1);
        let target = collection(2);
        let exact_derive = WantRequest::derive(target, data(10));
        let overlapping_fingerprint = records
            .iter()
            .find(|record| match record {
                CollectionRecord::Derive(derive) => {
                    derive.collection() == target && derive.input() == data(10)
                }
                _ => false,
            })
            .unwrap()
            .fingerprint();
        let selectors = [
            CollectionRecordSelector::Fingerprint(commit.fingerprint()),
            CollectionRecordSelector::Fingerprint(overlapping_fingerprint),
            CollectionRecordSelector::MergeCollection(source),
            CollectionRecordSelector::Operation(exact_derive),
        ]
        .into_iter()
        .collect();
        let store = FallbackStore {
            records: records.clone(),
            ..FallbackStore::default()
        };

        let selected = store.select_records(&selectors).unwrap();

        let mut expected: Vec<_> = records
            .into_iter()
            .filter(|record| match record {
                CollectionRecord::Commit(_) => record.fingerprint() == commit.fingerprint(),
                CollectionRecord::Merge(merge) => merge.collection() == source,
                CollectionRecord::Derive(derive) => {
                    derive.collection() == target && derive.input() == data(10)
                }
            })
            .collect();
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);
        assert_eq!(selected, expected);
        assert_eq!(store.enumerations.get(), 1);
        assert_eq!(
            selected
                .iter()
                .filter(|record| matches!(record, CollectionRecord::Derive(_)))
                .count(),
            2,
            "different outputs for one exact DERIVE remain visible"
        );
    }

    #[test]
    fn default_point_lookup_scans_one_ordered_view() {
        let records = fixture();
        let expected = records[records.len() / 2];
        let store = FallbackStore {
            records,
            ..FallbackStore::default()
        };

        assert_eq!(
            store.record(expected.fingerprint()).unwrap(),
            Some(expected)
        );
        assert_eq!(store.enumerations.get(), 1);
        assert_eq!(
            store
                .record(CollectionRecordFingerprint::from_raw([0xff; 32]))
                .unwrap(),
            None
        );
        assert_eq!(store.enumerations.get(), 2);
    }

    #[test]
    fn default_pair_selection_includes_all_inputs_and_excludes_other_pairs() {
        let records = fixture();
        let target = collection(2);
        let pair = [CollectionRecordSelector::DeriveTarget(target)]
            .into_iter()
            .collect();
        let store = FallbackStore {
            records,
            ..FallbackStore::default()
        };

        let selected = store.select_records(&pair).unwrap();

        assert_eq!(selected.len(), 3);
        assert!(selected.iter().all(|record| match record {
            CollectionRecord::Derive(derive) => derive.collection() == target,
            _ => false,
        }));
    }

    #[test]
    fn exact_collection_selection_includes_every_record_kind_and_no_other_collection() {
        let expected = collection(1);
        let other = collection(2);
        let author = SigningKey::from_bytes(&[9; 32]);
        let mut records = vec![
            CollectionRecord::Commit(CollectionCommit::sign(
                &author,
                expected,
                data(1),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                expected,
                data(1),
                data(2),
                data(3),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                expected,
                data(3),
                data(4),
            )),
            CollectionRecord::Commit(CollectionCommit::sign(
                &author,
                other,
                data(1),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                other,
                data(1),
                data(2),
                data(3),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                other,
                data(3),
                data(4),
            )),
        ];
        records.sort_unstable_by_key(CollectionRecord::fingerprint);
        let store = FallbackStore {
            records,
            ..FallbackStore::default()
        };
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(expected)]);

        let selected = store.select_records(&selectors).unwrap();

        assert_eq!(selected.len(), 3);
        assert!(selected
            .iter()
            .any(|record| matches!(record, CollectionRecord::Commit(_))));
        assert!(selected
            .iter()
            .any(|record| matches!(record, CollectionRecord::Merge(_))));
        assert!(selected
            .iter()
            .any(|record| matches!(record, CollectionRecord::Derive(_))));
        assert!(selected.iter().all(|record| match record {
            CollectionRecord::Commit(record) => record.collection() == expected,
            CollectionRecord::Merge(record) => record.collection() == expected,
            CollectionRecord::Derive(record) => record.collection() == expected,
        }));
        assert_eq!(store.enumerations.get(), 1);
    }

    #[test]
    fn empty_selection_returns_without_enumeration() {
        let store = FallbackStore {
            records: fixture(),
            ..FallbackStore::default()
        };

        assert!(store.select_records(&BTreeSet::new()).unwrap().is_empty());
        assert_eq!(store.enumerations.get(), 0);
    }

    #[derive(Default)]
    struct OverrideStore {
        records_calls: Cell<usize>,
        selection_calls: Cell<usize>,
    }

    impl CollectionRead for OverrideStore {
        type RecordsError = Infallible;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Infallible>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            self.records_calls.set(self.records_calls.get() + 1);
            Ok(Vec::new().into_iter())
        }

        fn select_records(
            &self,
            _selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            self.selection_calls.set(self.selection_calls.get() + 1);
            Ok(Vec::new())
        }
    }

    impl CollectionStore for OverrideStore {
        type InsertError = Infallible;

        fn insert(&mut self, _record: CollectionRecord) -> Result<(), Self::InsertError> {
            Ok(())
        }
    }

    #[test]
    fn shared_reference_forwards_selection_override() {
        let store = OverrideStore::default();
        let borrowed = &store;
        let selectors = [CollectionRecordSelector::Fingerprint(
            CollectionRecordFingerprint::from_raw([1; 32]),
        )]
        .into_iter()
        .collect();
        CollectionRead::select_records(&borrowed, &selectors).unwrap();
        assert_eq!(store.selection_calls.get(), 1);
        assert_eq!(store.records_calls.get(), 0);
    }
}
