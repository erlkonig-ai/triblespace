//! Policy-independent collection-record delta mechanics.
//!
//! This module owns only the immutable evidence boundary: strict framing,
//! intrinsic collection matching, ingress signature verification, canonical
//! fingerprint ordering, and bounded `current - previous` selection. It deliberately
//! does not resolve referenced blobs or decide READ/WRITE policy. A future
//! authorized overlay can therefore store sparse MERGE/DERIVE equations as
//! inert evidence and apply semantic validation only when a resolver uses one.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use triblespace_core::collection::{
    CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordFingerprint,
    CollectionRecordSelector, RecordDecodeError,
};
use triblespace_core::patch::{Blake3Merkle, Entry as PatchEntry, IdentitySchema, PATCH};

use crate::patch_repair::PatchSummary;

/// Canonical valued PATCH of the records naming one exact collection.
#[derive(Clone, Debug)]
pub struct CollectionRecordPatch {
    collection: CollectionHandle,
    records: PATCH<32, IdentitySchema, CollectionRecord, Blake3Merkle>,
}

impl CollectionRecordPatch {
    /// Exact collection named by every record in this PATCH.
    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Root and count of this immutable per-collection PATCH.
    pub fn summary(&self) -> PatchSummary {
        PatchSummary::from_patch(&self.records)
    }

    /// Number of canonical records in this collection overlay.
    pub fn len(&self) -> u64 {
        self.records.len()
    }

    /// Whether this collection overlay has no known records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up one record by its full-width physical fingerprint.
    pub fn get(&self, fingerprint: CollectionRecordFingerprint) -> Option<CollectionRecord> {
        self.records.get(&fingerprint.raw()).copied()
    }

    /// Enumerate canonical records in fingerprint order.
    pub fn records(&self) -> impl Iterator<Item = CollectionRecord> + '_ {
        self.records.iter_ordered().map(|id| {
            *self
                .records
                .get(id)
                .expect("an ordered per-collection PATCH key retains its record value")
        })
    }

    pub(crate) const fn patch(&self) -> &PATCH<32, IdentitySchema, CollectionRecord, Blake3Merkle> {
        &self.records
    }
}

/// Failure while constructing an exact per-collection record PATCH.
#[derive(Debug)]
pub enum CollectionRecordPatchError<E> {
    Store(E),
    Evidence(CollectionDeltaError),
}

impl<E: fmt::Display> fmt::Display for CollectionRecordPatchError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "select collection records: {error}"),
            Self::Evidence(error) => error.fmt(f),
        }
    }
}

impl<E> Error for CollectionRecordPatchError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Evidence(error) => Some(error),
        }
    }
}

/// Failure at the sparse immutable-evidence boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionDeltaError {
    Decode(RecordDecodeError),
    WrongCollection,
    FingerprintCollision(CollectionRecordFingerprint),
}

impl fmt::Display for CollectionDeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "decode collection record: {error}"),
            Self::WrongCollection => write!(f, "record names another collection"),
            Self::FingerprintCollision(fingerprint) => {
                write!(
                    f,
                    "distinct records share full-width fingerprint {fingerprint}"
                )
            }
        }
    }
}

impl Error for CollectionDeltaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RecordDecodeError> for CollectionDeltaError {
    fn from(error: RecordDecodeError) -> Self {
        Self::Decode(error)
    }
}

/// Build the exact valued PATCH for one collection through its semantic
/// selector.
///
/// This is the sole collection-overlay construction path: it never asks the
/// caller for the store's global record stream. Backends remain free to answer
/// the selector from a secondary index or another sparse representation.
pub fn collection_record_patch<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<CollectionRecordPatch, CollectionRecordPatchError<R::RecordsError>>
where
    R: CollectionRead,
{
    let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection)]);
    let records = snapshot
        .select_records(&selectors)
        .map_err(CollectionRecordPatchError::Store)?;
    canonical_records(collection, records).map_err(CollectionRecordPatchError::Evidence)
}

/// Advance the PATCH built from `previous` using only selected semantic record
/// additions and removals. `prior` must describe that previous snapshot and
/// retains its unchanged persistent Merkle subtrees; no old record body is
/// rehashed simply because another record arrived in its collection.
pub fn update_collection_record_patch<R>(
    current: &R,
    previous: &R,
    prior: &CollectionRecordPatch,
) -> Result<CollectionRecordPatch, CollectionRecordPatchError<R::RecordsError>>
where
    R: CollectionRead,
{
    let expected = prior.collection;
    let selectors = BTreeSet::from([CollectionRecordSelector::Collection(expected)]);
    let (added, removed) = current
        .select_record_changes(previous, &selectors)
        .map_err(CollectionRecordPatchError::Store)?;
    let mut next = prior.clone();
    for record in removed {
        validate_record(expected, record).map_err(CollectionRecordPatchError::Evidence)?;
        let fingerprint = record.fingerprint();
        let key = fingerprint.raw();
        if let Some(existing) = next.records.get(&key) {
            if existing != &record {
                return Err(CollectionRecordPatchError::Evidence(
                    CollectionDeltaError::FingerprintCollision(fingerprint),
                ));
            }
            next.records.remove(&key);
        }
    }
    for record in added {
        insert_record(expected, &mut next.records, record)
            .map_err(CollectionRecordPatchError::Evidence)?;
    }
    Ok(next)
}

/// Encode one trusted local record after checking its intrinsic collection.
/// Signatures are not re-verified on output. WRITE authorization is absent: it
/// governs derived admission, not whether canonical inert evidence may exist.
pub fn encode_record(
    expected: CollectionHandle,
    record: CollectionRecord,
) -> Result<Vec<u8>, CollectionDeltaError> {
    validate_record(expected, record)?;
    Ok(record.to_bytes())
}

/// Strictly decode one complete self-tagged record for an implicit collection
/// overlay. Trailing bytes, noncanonical MERGE inputs, unknown tags, wrong
/// collections, and invalid signatures fail before insertion.
pub fn decode_record(
    expected: CollectionHandle,
    bytes: &[u8],
) -> Result<CollectionRecord, CollectionDeltaError> {
    let record = CollectionRecord::from_bytes(bytes)?;
    validate_record(expected, record)?;
    Ok(record)
}

fn validate_record(
    expected: CollectionHandle,
    record: CollectionRecord,
) -> Result<(), CollectionDeltaError> {
    if record.collection() != expected {
        return Err(CollectionDeltaError::WrongCollection);
    }
    Ok(())
}

fn canonical_records(
    expected: CollectionHandle,
    records: impl IntoIterator<Item = CollectionRecord>,
) -> Result<CollectionRecordPatch, CollectionDeltaError> {
    let mut canonical = PATCH::new();
    for record in records {
        insert_record(expected, &mut canonical, record)?;
    }
    Ok(CollectionRecordPatch {
        collection: expected,
        records: canonical,
    })
}

fn insert_record(
    expected: CollectionHandle,
    canonical: &mut PATCH<32, IdentitySchema, CollectionRecord, Blake3Merkle>,
    record: CollectionRecord,
) -> Result<(), CollectionDeltaError> {
    validate_record(expected, record)?;
    let fingerprint = record.fingerprint();
    let key = fingerprint.raw();
    if let Some(existing) = canonical.get(&key) {
        if existing != &record {
            return Err(CollectionDeltaError::FingerprintCollision(fingerprint));
        }
        return Ok(());
    }
    canonical.insert(&PatchEntry::with_value(&key, record));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;
    use triblespace_core::collection::{
        empty_metadata_handle, CollectionCommit, CollectionData, CollectionDerive, CollectionMerge,
        COLLECTION_RECORD_KIND_MERGE_V4,
    };
    use triblespace_core::inline::Inline;

    use super::*;

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    fn records(expected: CollectionHandle) -> [CollectionRecord; 3] {
        [
            CollectionRecord::Commit(CollectionCommit::sign(
                &SigningKey::from_bytes(&[7; 32]),
                expected,
                data(1),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(
                CollectionMerge::sign(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    expected,
                    [data(2), data(3)],
                    data(4),
                )
                .unwrap(),
            ),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                expected,
                triblespace_core::collection::SourceLocator::of(data(4).raw),
                data(5),
            )),
        ]
    }

    #[test]
    fn all_sparse_record_variants_roundtrip_for_the_implicit_collection() {
        let expected = collection(1);
        for record in records(expected) {
            let bytes = encode_record(expected, record).unwrap();
            assert_eq!(decode_record(expected, &bytes).unwrap(), record);
        }
    }

    #[test]
    fn framing_collection_and_signatures_fail_before_admission() {
        let expected = collection(1);
        let commit = records(expected)[0];
        let bytes = encode_record(expected, commit).unwrap();

        assert_eq!(
            decode_record(collection(2), &bytes),
            Err(CollectionDeltaError::WrongCollection)
        );
        for record in records(expected) {
            let mut tampered = encode_record(expected, record).unwrap();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(matches!(
                decode_record(expected, &tampered),
                Err(CollectionDeltaError::Decode(
                    RecordDecodeError::Verification(_)
                ))
            ));
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_record(expected, &trailing),
            Err(CollectionDeltaError::Decode(_))
        ));
        assert!(decode_record(expected, &bytes[..bytes.len() - 1]).is_err());
        assert!(decode_record(expected, &[99]).is_err());
    }

    #[test]
    fn trusted_local_index_and_outbound_encoding_do_not_reverify() {
        use triblespace_core::collection::CollectionStore;
        use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};

        let expected = collection(1);
        let record = records(expected)[1];
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(file.path()).unwrap();
        pile.insert(record).unwrap();
        pile.close().unwrap();
        let physical = PileRecords::open(file.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let mut bytes = std::fs::read(file.path()).unwrap();
        bytes[physical.offset + 64 + record.to_bytes().len() - 2] ^= 1;
        std::fs::write(file.path(), bytes).unwrap();
        let physical = PileRecords::open(file.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let PileRecordContent::Collection { record: evidence } = physical.content else {
            panic!("native fixture is not a collection record");
        };
        assert!(evidence.verify_strict().is_err());
        let patch = canonical_records(expected, [evidence]).unwrap();
        assert_eq!(patch.get(evidence.fingerprint()), Some(evidence));
        let outbound = encode_record(expected, evidence).unwrap();
        assert!(decode_record(expected, &outbound).is_err());
    }

    #[test]
    fn derives_roundtrip_before_their_input_record_or_proofs_are_present() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let source = collection(44);
        let target = collection(45);
        let commit = CollectionCommit::sign(&signer, source, data(46), empty_metadata_handle());
        let derive = CollectionRecord::Derive(CollectionDerive::sign(
            &signer,
            target,
            triblespace_core::collection::SourceLocator::of(commit.data().raw),
            data(47),
        ));
        let bytes = encode_record(target, derive).unwrap();
        let decoded = decode_record(target, &bytes).unwrap();
        assert_eq!(decoded, derive);
        // The record names the input PAYLOAD and nothing that has to arrive
        // first. Which record produced that payload -- the commit here -- is
        // a relation a reader recovers by content, so the derive travels
        // alone and stays meaningful on the far side.
        assert_eq!(canonical_records(target, [decoded]).unwrap().len(), 1);
        let mut tampered = bytes;
        // Every field is in the signature transcript, not an unauthenticated
        // retrieval hint: flipping one bit of the output breaks the record.
        tampered[1 + 2 * 32] ^= 1;
        assert!(decode_record(target, &tampered).is_err());
    }

    #[test]
    fn noncanonical_merge_inputs_fail_before_admission() {
        let expected = collection(1);
        let merge = CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            expected,
            [data(2), data(3)],
            data(4),
        )
        .unwrap();
        let mut bytes = merge.to_bytes();
        // The inputs follow the six fixed 32-byte slots.
        bytes[192..224].fill(9);
        bytes[224..256].fill(1);
        let mut tagged = Vec::with_capacity(1 + bytes.len());
        tagged.push(COLLECTION_RECORD_KIND_MERGE_V4);
        tagged.extend_from_slice(&bytes);
        assert!(matches!(
            decode_record(expected, &tagged),
            Err(CollectionDeltaError::Decode(
                RecordDecodeError::NonCanonicalMergeInputs
            ))
        ));
    }

    #[test]
    fn relay_roundtrip_preserves_the_embedded_commit_author() {
        let expected = collection(1);
        let commit = records(expected)[0];
        let CollectionRecord::Commit(before) = commit else {
            unreachable!()
        };
        let after = decode_record(expected, &encode_record(expected, commit).unwrap()).unwrap();
        let CollectionRecord::Commit(after) = after else {
            unreachable!()
        };
        assert_eq!(after.public_key(), before.public_key());
        assert_eq!(after, before);
    }

    struct ExactSelectorStore {
        expected: CollectionHandle,
        selected: Vec<CollectionRecord>,
        global_enumerations: Cell<usize>,
        selections: Cell<usize>,
    }

    impl CollectionRead for ExactSelectorStore {
        type RecordsError = Infallible;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Infallible>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            self.global_enumerations
                .set(self.global_enumerations.get() + 1);
            Ok(Vec::new().into_iter())
        }

        fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
            Ok(Vec::new())
        }

        fn select_records(
            &self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            assert_eq!(
                selectors,
                &BTreeSet::from([CollectionRecordSelector::Collection(self.expected)])
            );
            self.selections.set(self.selections.get() + 1);
            Ok(self.selected.clone())
        }
    }

    #[test]
    fn overlay_patch_uses_only_the_exact_collection_selector() {
        let expected = collection(1);
        let selected = records(expected).to_vec();
        let store = ExactSelectorStore {
            expected,
            selected: selected.clone(),
            global_enumerations: Cell::new(0),
            selections: Cell::new(0),
        };

        let overlay = collection_record_patch(&store, expected).unwrap();

        assert_eq!(overlay.len(), selected.len() as u64);
        assert!(selected
            .iter()
            .all(|record| { overlay.get(record.fingerprint()) == Some(*record) }));
        assert_eq!(store.selections.get(), 1);
        assert_eq!(store.global_enumerations.get(), 0);
    }
}
