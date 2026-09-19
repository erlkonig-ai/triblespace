//! Native storage for collection-calculus records.
//!
//! A collection store is a grow-only set of canonical records: a record's
//! exact bytes are its identity, and inserting one the store already holds
//! adds nothing. It deliberately exposes no mutable head, deletion, compare-and-swap, or
//! read-through-writer path. A [`CollectionRead`] implementation belongs to an
//! immutable store snapshot, while [`CollectionStore`] only admits new records.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;

use crate::repo::{BlobStoreGet, CapabilityProofRead};

use super::coverage::{coverage_of, Coverage, CoverageIndex};
use super::{CollectionData, CollectionHandle, CollectionRecord};

/// One raw selection route into the grow-only collection-record set.
///
/// A batch of selectors is interpreted as set union. Exact operation lookup
/// deliberately names only the inputs: every distinct asserted result remains
/// visible to callers as conflicting evidence. Selection does not establish
/// authority, output residency, or the validity of an input witness closure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CollectionRecordSelector {
    /// Select every record whose intrinsic collection is exactly `C`.
    ///
    /// This is the canonical construction route for one collection's sparse
    /// overlay inventory. It includes signed `COMMIT`, `MERGE`,
    /// and `DERIVE` equations without exposing or enumerating unrelated
    /// collections.
    Collection(CollectionHandle),
    /// Select every signed membership claim for one exact collection element.
    ///
    /// Several authors or metadata archives may attest the same data member;
    /// all of those claims remain provenance over one payload identity.
    CommitMember(CollectionHandle, CollectionData),
    /// Select every raw record producing one exact collection member.
    ///
    /// This matches `COMMIT.data`, `MERGE.result`, and `DERIVE.output` at
    /// exactly `(C, H)`. Distinct producers and input witnesses remain distinct
    /// records; neither authority nor witness closure is evaluated here.
    ProducedMember(CollectionHandle, CollectionData),
    /// Select every `MERGE` asserted for one collection descriptor.
    MergeCollection(CollectionHandle),
    /// Select every `DERIVE` into one exact target descriptor.
    ///
    /// The source is not part of the selector: a target has one source, named
    /// by its descriptor, so selecting the target selects the mapping.
    DeriveTarget(CollectionHandle),
}

pub(crate) fn selectors_match_record(
    selectors: &BTreeSet<CollectionRecordSelector>,
    record: CollectionRecord,
) -> bool {
    let collection = match record {
        CollectionRecord::Commit(commit) => commit.collection(),
        CollectionRecord::Merge(merge) => merge.collection(),
        CollectionRecord::Derive(derive) => derive.collection(),
    };
    if selectors.contains(&CollectionRecordSelector::Collection(collection)) {
        return true;
    }
    let output = match record {
        CollectionRecord::Commit(commit) => commit.data(),
        CollectionRecord::Merge(merge) => merge.result(),
        CollectionRecord::Derive(derive) => derive.output(),
    };
    if selectors.contains(&CollectionRecordSelector::ProducedMember(
        collection, output,
    )) {
        return true;
    }
    let matches_fields = match record {
        CollectionRecord::Commit(commit) => selectors.contains(
            &CollectionRecordSelector::CommitMember(commit.collection(), commit.data()),
        ),
        CollectionRecord::Merge(merge) => {
            selectors.contains(&CollectionRecordSelector::MergeCollection(
                merge.collection(),
            ))
        }
        CollectionRecord::Derive(derive) => {
            selectors.contains(&CollectionRecordSelector::DeriveTarget(derive.collection()))
        }
    };
    matches_fields
}

/// Immutable read surface for canonical collection-calculus records.
///
/// Implementations enumerate one coherent store snapshot in a deterministic
/// order of their own. Mutation lives on [`CollectionStore`], so admission and
/// physical-cover resolution cannot accidentally observe different prefixes.
/// Signatures are trusted here: foreign dense records are checked at ingress,
/// and local constructors sign their own records. Opening or concatenating a
/// raw pile is an explicit trust decision; audit unfamiliar piles before using
/// them as trusted storage. This contract does not grant WRITE authority,
/// which is evaluated against each snapshot's policy and proofs. Equation
/// witnesses are references to other records, not ingress prerequisites:
/// a record may be persisted before its witnesses or WRITE proofs arrive.
pub trait CollectionRead {
    /// Failure while enumerating stored records.
    type RecordsError: Error + Debug + Send + Sync + 'static;
    /// Borrowing iterator over one deterministic view of known records.
    type RecordIter<'a>: Iterator<Item = Result<CollectionRecord, Self::RecordsError>>
    where
        Self: 'a;

    /// Enumerate currently known records, each once, in a deterministic
    /// order.
    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError>;

    /// Select one deterministic union of raw record routes.
    ///
    /// The default implementation performs exactly one ordinary enumeration
    /// and filters it. Backends with primary or secondary indexes may override
    /// this method without changing the grow-only set contract. Each selected
    /// record is returned once, in the backend's deterministic order. An empty
    /// union returns immediately without asking the backend for a view.
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

/// Downward coverage for every lattice node this store has admitted.
///
/// Deliberately not a method of [`CollectionRead`], and deliberately without
/// a default. A store that maintains the index -- a pile during replay, a
/// [`crate::repo::memoryrepo::MemoryRepo`] across inserts -- hands out its
/// published root, a constant-time clone. A wrapper delegates. A reader that
/// can do neither says so by not implementing this, and then cannot be passed
/// where coverage is needed: a compile error, where the alternative was a
/// default that refolded every record with an admission query for each one
/// the store did not admit -- found doing exactly that, silently, in four
/// wrappers that had simply never overridden it.
///
/// `lineage` names every collection whose rows the caller may consult -- the
/// target and each of its sources down to the foundation. The index itself
/// is snapshot-wide and no implementor needs to narrow what it hands back,
/// but a reader that TRACKS what was read does need it: the fold only
/// propagates along a lineage, so a row under one can change only when a
/// record arrives in one of these collections. Without the parameter the
/// honest read set of a coverage read is every record in the store, which
/// makes every observation wake on every arrival.
pub trait CoverageRead: CollectionRead {
    /// The settled index itself, a constant-time clone.
    ///
    /// This is what a reader that composes on top of another needs: an
    /// operation frontier clones its control's index, parks the records it
    /// authored, and settles -- the same fold the control ran, continued for
    /// a few records, instead of restarted for all of them.
    fn index(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<CoverageIndex, Self::RecordsError>;

    /// The published half of [`Self::index`]: what a reader that only asks
    /// questions needs. Exact and constant-time by construction, so it may be
    /// provided; the trait's refusal is of defaults that would refold.
    fn coverage(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<Coverage, Self::RecordsError> {
        Ok(self.index(lineage)?.published().clone())
    }
}

impl<R: CoverageRead> CoverageRead for &R {
    fn index(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<CoverageIndex, Self::RecordsError> {
        (**self).index(lineage)
    }

    fn coverage(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<Coverage, Self::RecordsError> {
        (**self).coverage(lineage)
    }
}

/// Fold coverage from scratch over one reader.
///
/// This is the cost [`CoverageRead`] refuses to hide: one enumeration of
/// every record, and an admission query for each one this reader does not
/// admit. It is the right answer for a reader that has no index of its own
/// and no inner store to delegate to, and it is written at the call site so
/// that it is visible there.
pub fn fold_index<R>(reader: &R) -> Result<CoverageIndex, R::RecordsError>
where
    R: CollectionRead + BlobStoreGet + CapabilityProofRead,
{
    coverage_of(reader)
}

/// [`fold_index`]'s published half.
pub fn fold_coverage<R>(reader: &R) -> Result<Coverage, R::RecordsError>
where
    R: CollectionRead + BlobStoreGet + CapabilityProofRead,
{
    Ok(fold_index(reader)?.published().clone())
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
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    /// A merge or derive names its input PAYLOAD. This used to wrap it
    /// beside a fingerprint citing a record that produced it; nothing
    /// cites anything now, so it is just the payload.
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
    fn field_selectors_do_not_recompute_record_fingerprints() {
        use crate::collection::records::FINGERPRINT_CALLS;

        let records = fixture();
        let selectors = [
            CollectionRecordSelector::Collection(collection(1)),
            CollectionRecordSelector::Collection(collection(99)),
            CollectionRecordSelector::CommitMember(collection(1), data(4)),
            CollectionRecordSelector::ProducedMember(collection(2), data(11)),
            CollectionRecordSelector::MergeCollection(collection(1)),
            CollectionRecordSelector::DeriveTarget(collection(2)),
        ];
        let before = FINGERPRINT_CALLS.get();
        for selector in selectors {
            for &record in &records {
                selectors_match_record(&BTreeSet::from([selector]), record);
            }
        }
        for &record in &records {
            assert!(!selectors_match_record(&BTreeSet::new(), record));
        }
        assert_eq!(FINGERPRINT_CALLS.get() - before, 0);
    }

    #[test]
    fn default_relationship_selection_does_not_require_present_witnesses() {
        let records = fixture();
        let store = FallbackStore {
            records: records.clone(),
            ..FallbackStore::default()
        };
        let selectors = BTreeSet::from([
            CollectionRecordSelector::ProducedMember(collection(1), data(4)),
            CollectionRecordSelector::ProducedMember(collection(1), data(6)),
            CollectionRecordSelector::ProducedMember(collection(2), data(11)),
        ]);
        let selected = store.select_records(&selectors).unwrap();
        assert_eq!(store.enumerations.get(), 1);
        let expected: Vec<_> = records
            .into_iter()
            .filter(|record| match record {
                CollectionRecord::Commit(commit) => {
                    commit.collection() == collection(1) && commit.data() == data(4)
                }
                CollectionRecord::Merge(merge) => {
                    merge.collection() == collection(1) && merge.result() == data(6)
                }
                // Selected as the producer of (collection(2), data(11)),
                // which is what the removed citation selector was standing in
                // for here.
                CollectionRecord::Derive(derive) => {
                    derive.collection() == collection(2) && derive.output() == data(11)
                }
            })
            .collect();
        assert_eq!(selected, expected);
        assert!(selected
            .windows(2)
            .all(|pair| pair[0].fingerprint() < pair[1].fingerprint()));
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
        let selectors = [CollectionRecordSelector::Collection(collection(1))]
            .into_iter()
            .collect();
        CollectionRead::select_records(&borrowed, &selectors).unwrap();
        assert_eq!(store.selection_calls.get(), 1);
        assert_eq!(store.records_calls.get(), 0);
    }
}
