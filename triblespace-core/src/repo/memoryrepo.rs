use std::collections::BTreeSet;
use std::collections::HashSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::UnknownBlob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::blob::{MemoryBlobStore, MemoryBlobStoreSnapshot, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::collection::coverage::{Coverage, CoverageArrivals, CoverageIndex, StoreWriters};
use crate::collection::store::selectors_match_record;
use crate::collection::{
    CollectionRead, CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector,
    CollectionStore,
};
use crate::inline::INLINE_LEN;
use crate::patch::{Entry, IdentitySchema, XorSip128, PATCH};
use crate::prelude::*;
use crate::repo::proof::{CapabilityProofRead, CapabilityProofStore};
use crate::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, SnapshotSource,
    StoreChanges, StoreSnapshot, WantRead, WantRequest, WantStore,
};

use crate::inline::encodings::hash::Handle;
use crate::inline::InlineEncoding;

type CollectionRecordIndex = PATCH<INLINE_LEN, IdentitySchema, CollectionRecord, XorSip128>;
type CapabilityProofIndex = PATCH<INLINE_LEN, IdentitySchema, CapabilityProof, XorSip128>;

/// Simple in-memory implementation of the repository storage traits.
///
/// Useful for unit tests or ephemeral repositories where persistence is not
/// required.
#[derive(Clone, Debug, Default)]
pub struct MemoryRepo {
    /// In-memory blob store for all repository blobs.
    pub blobs: MemoryBlobStore,
    /// Grow-only typed requests (see [`WantStore`]). Wants here are exactly as
    /// ephemeral as the blobs themselves — the trait is a capability,
    /// durability is the store's own property.
    wants: HashSet<WantRequest>,
    /// Canonical collection records keyed by full-width record fingerprint.
    collection_records: CollectionRecordIndex,
    /// Canonical complete capability proofs keyed by exact-body content id.
    capability_proofs: CapabilityProofIndex,
    /// Downward coverage, folded incrementally as records arrive and settled
    /// when a snapshot is taken -- the same arrangement a pile keeps across
    /// appends. Without it every `coverage()` read is the trait default: a
    /// full refold with an admission query per unadmitted record, which is
    /// both the cost and, for a reader that must not repeat ancestors'
    /// admission decisions, the wrong answer.
    coverage: CoverageIndex,
    coverage_arrivals: CoverageArrivals,
}

/// One O(1)-clone immutable observation of a [`MemoryRepo`].
///
/// The blob snapshot and all semantic indexes are frozen together, so
/// collection admission, capability verification, and payload decoding cannot
/// observe different prefixes.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryRepoSnapshot {
    blobs: MemoryBlobStoreSnapshot,
    collection_records: CollectionRecordIndex,
    capability_proofs: CapabilityProofIndex,
    wants: HashSet<WantRequest>,
    coverage: CoverageIndex,
}

impl StoreSnapshot for MemoryRepoSnapshot {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        let mut changes = StoreChanges::NONE;
        if self
            .blobs
            .changes_since(&previous.blobs)
            .contains(StoreChanges::BLOBS)
        {
            changes = changes.union(StoreChanges::BLOBS);
        }
        if previous.collection_records != self.collection_records {
            changes = changes.union(StoreChanges::COLLECTION_RECORDS);
        }
        if previous.capability_proofs != self.capability_proofs {
            changes = changes.union(StoreChanges::CAPABILITY_PROOFS);
        }
        if previous.wants != self.wants {
            changes = changes.union(StoreChanges::WANTS);
        }
        changes
    }
}

impl SnapshotSource for MemoryRepo {
    type Snapshot = MemoryRepoSnapshot;
    type SnapshotError = Infallible;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.resolve_coverage();
        Ok(MemoryRepoSnapshot {
            blobs: self.blobs.snapshot()?,
            collection_records: self.collection_records.clone(),
            capability_proofs: self.capability_proofs.clone(),
            wants: self.wants.clone(),
            coverage: self.coverage.clone(),
        })
    }
}

impl MemoryRepo {
    /// Decide every attestation parked since the last snapshot, and re-drive
    /// any earlier decision that an arrival since then could change.
    fn resolve_coverage(&mut self) {
        let arrivals = std::mem::take(&mut self.coverage_arrivals);
        if !self.coverage.has_fresh() && !arrivals.woke_anything() {
            return;
        }
        let mut coverage = std::mem::take(&mut self.coverage);
        let Ok(blobs) = self.blobs.snapshot();
        let reader = MemoryRepoSnapshot {
            blobs,
            collection_records: self.collection_records.clone(),
            capability_proofs: self.capability_proofs.clone(),
            wants: self.wants.clone(),
            coverage: CoverageIndex::default(),
        };
        coverage.settle(
            &StoreWriters::new(&reader),
            arrivals.descriptors,
            arrivals.proofs,
        );
        self.coverage = coverage;
    }
}

/// Deterministic persistent snapshot of in-memory collection records.
pub struct MemoryCollectionRecordIter {
    keys: crate::patch::PATCHIntoOrderedIterator<
        INLINE_LEN,
        IdentitySchema,
        CollectionRecord,
        XorSip128,
    >,
    lookup: CollectionRecordIndex,
}

impl Iterator for MemoryCollectionRecordIter {
    type Item = Result<CollectionRecord, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let record = *self
            .lookup
            .get(&key)
            .expect("collection key from PATCH snapshot must retain its value");
        debug_assert_eq!(record.fingerprint().raw(), key);
        Some(Ok(record))
    }
}

/// Deterministic persistent snapshot of in-memory capability proofs.
pub struct MemoryCapabilityProofIter {
    keys: crate::patch::PATCHIntoOrderedIterator<
        INLINE_LEN,
        IdentitySchema,
        CapabilityProof,
        XorSip128,
    >,
    lookup: CapabilityProofIndex,
}

impl Iterator for MemoryCapabilityProofIter {
    type Item = Result<CapabilityProof, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let proof = self
            .lookup
            .get(&key)
            .expect("proof key from PATCH snapshot must retain its value");
        debug_assert_eq!(proof.id().raw, key);
        Some(Ok(proof.clone()))
    }
}

/// Failure while admitting a proof to [`MemoryRepo`].
#[derive(Debug)]
pub enum MemoryProofInsertError {
    /// The proof's byte-only signature chain is invalid.
    Invalid(crate::capability::CapabilityProofError),
    /// An infeasible BLAKE3 collision named different canonical proof bytes.
    IdCollision { id: CapabilityProofId },
}

impl fmt::Display for MemoryProofInsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "invalid capability proof: {error}"),
            Self::IdCollision { id } => {
                write!(f, "capability proof id {id:?} names different bytes")
            }
        }
    }
}

impl Error for MemoryProofInsertError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::IdCollision { .. } => None,
        }
    }
}

/// Failure while inserting a collection record into [`MemoryRepo`].
#[derive(Debug)]
pub enum MemoryCollectionInsertError {
    /// An infeasible full-width fingerprint collision named different records.
    FingerprintCollision {
        fingerprint: CollectionRecordFingerprint,
    },
}

impl fmt::Display for MemoryCollectionInsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FingerprintCollision { fingerprint } => {
                write!(
                    f,
                    "collection record fingerprint {fingerprint} names different records"
                )
            }
        }
    }
}

impl Error for MemoryCollectionInsertError {}

impl CapabilityProofRead for MemoryRepoSnapshot {
    type ProofsError = Infallible;
    type ProofIter<'a> = MemoryCapabilityProofIter;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        let keys = self.capability_proofs.clone().into_iter_ordered();
        Ok(MemoryCapabilityProofIter {
            keys,
            lookup: self.capability_proofs.clone(),
        })
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        Ok(self.capability_proofs.get(&id.raw).cloned())
    }
}

impl CapabilityProofStore for MemoryRepo {
    type InsertError = MemoryProofInsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        proof
            .verify_signatures()
            .map_err(MemoryProofInsertError::Invalid)?;
        let id = proof.id();
        if let Some(existing) = self.capability_proofs.get(&id.raw) {
            return if existing.as_bytes() == proof.as_bytes() {
                Ok(())
            } else {
                Err(MemoryProofInsertError::IdCollision { id })
            };
        }
        self.capability_proofs
            .insert(&Entry::with_value(&id.raw, proof));
        self.coverage_arrivals.proofs = true;
        Ok(())
    }
}

impl crate::collection::covered::RecordDelta for MemoryRepoSnapshot {
    fn for_each_record_since(
        &self,
        since: Option<&Self>,
        each: &mut dyn FnMut(&CollectionRecord),
    ) {
        let fresh = match since {
            Some(since) => self.collection_records.difference(&since.collection_records),
            None => self.collection_records.clone(),
        };
        for key in fresh.iter_ordered() {
            each(fresh.get(key).expect("record index key retains its record"));
        }
    }
}

impl crate::collection::CoverageRead for MemoryRepoSnapshot {
    /// The index settled when this snapshot was taken; a persistent-root clone.
    fn index(
        &self,
        _lineage: &BTreeSet<crate::collection::CollectionHandle>,
    ) -> Result<CoverageIndex, Self::RecordsError> {
        Ok(self.coverage.clone())
    }
}

impl CollectionRead for MemoryRepoSnapshot {
    type RecordsError = Infallible;
    type RecordIter<'a> = MemoryCollectionRecordIter;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        let keys = self.collection_records.clone().into_iter_ordered();
        Ok(MemoryCollectionRecordIter {
            keys,
            lookup: self.collection_records.clone(),
        })
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        Ok(self.collection_records.get(&fingerprint.raw()).copied())
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        if selectors.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .collection_records
            .iter_ordered()
            .map(|key| {
                *self
                    .collection_records
                    .get(key)
                    .expect("collection key from PATCH must retain its value")
            })
            .filter(|record| selectors_match_record(selectors, *record))
            .collect())
    }
}

impl CollectionStore for MemoryRepo {
    type InsertError = MemoryCollectionInsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        let fingerprint = record.fingerprint();
        if let Some(existing) = self.collection_records.get(&fingerprint.raw()) {
            return if existing == &record {
                Ok(())
            } else {
                Err(MemoryCollectionInsertError::FingerprintCollision { fingerprint })
            };
        }
        self.collection_records
            .insert(&Entry::with_value(&fingerprint.raw(), record));
        self.coverage.park_record(&record);
        Ok(())
    }
}

impl crate::repo::BlobStorePut for MemoryRepo {
    type PutError = <MemoryBlobStore as crate::repo::BlobStorePut>::PutError;
    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let handle = self.blobs.put(item)?;
        // A descriptor is an ordinary blob, so this is the arrival that can
        // unblock an attestation parked on an unresolved lineage.
        let descriptor = Inline::new(handle.raw);
        if self.coverage.blob_arrived(descriptor) {
            self.coverage_arrivals.descriptors.push(descriptor);
        }
        Ok(handle)
    }
}

impl BlobStoreList for MemoryRepoSnapshot {
    type Iter<'a>
        = <MemoryBlobStoreSnapshot as BlobStoreList>::Iter<'a>
    where
        Self: 'a;
    type Err = <MemoryBlobStoreSnapshot as BlobStoreList>::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.blobs.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.blobs.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.blobs.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
        self.blobs.blobs_diff(&old.blobs)
    }
}

impl BlobStoreMeta for MemoryRepoSnapshot {
    type MetaError = <MemoryBlobStoreSnapshot as BlobStoreMeta>::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.blobs.metadata(handle)
    }
}

impl BlobStoreGet for MemoryRepoSnapshot {
    type GetError<E: Error + Send + Sync + 'static> =
        <MemoryBlobStoreSnapshot as BlobStoreGet>::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.blobs.get(handle)
    }
}

impl crate::repo::BlobChildren for MemoryRepoSnapshot {}

impl crate::repo::BlobStoreKeep for MemoryRepo {
    fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
    {
        let reader = self
            .blobs
            .snapshot()
            .expect("memory snapshot is infallible");
        let mut roots = crate::repo::RetentionRoots::new();
        for key in self.collection_records.iter() {
            let record = self
                .collection_records
                .get(key)
                .expect("collection key from PATCH must retain its value");
            for root in record.blob_references() {
                if crate::repo::BlobStoreList::contains_blob(&reader, root).unwrap_or(false) {
                    roots.retain_recursive(root);
                }
            }
        }
        for request in &self.wants {
            for root in request.blob_references() {
                if crate::repo::BlobStoreList::contains_blob(&reader, root).unwrap_or(false) {
                    roots.retain_recursive(root);
                }
            }
        }
        self.blobs
            .keep(handles.into_iter().chain(roots.expanded(&reader)));
    }
}

impl WantStore for MemoryRepo {
    type WantError = Infallible;

    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.wants.insert(request);
        Ok(())
    }
}

impl WantRead for MemoryRepoSnapshot {
    type WantsError = Infallible;
    type WantIter<'a> = std::vec::IntoIter<Result<WantRequest, Self::WantsError>>;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        // Want enumeration feeds sync-daemon fetch order, and HashSet's
        // per-instance seed would break deterministic simulation replay.
        let mut requests: Vec<WantRequest> = self.wants.iter().copied().collect();
        requests.sort();
        Ok(requests.into_iter().map(Ok).collect::<Vec<_>>().into_iter())
    }
}

impl crate::repo::StorageFlush for MemoryRepo {
    type Error = Infallible;

    fn flush(&mut self) -> Result<(), Self::Error> {
        // In-memory state has no sync point; durability is exactly the
        // process lifetime, same as the blobs themselves.
        Ok(())
    }
}

impl crate::repo::StorageClose for MemoryRepo {
    type Error = Infallible;

    fn close(self) -> Result<(), Self::Error> {
        // Nothing to do for the in-memory backend.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    /// An equation names its input PAYLOAD; this used to pair it with a
    /// fingerprint citing a record that produced it.
    use super::*;
    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::capability::{CapabilityProof, CapabilityResource};
    use crate::collection::descriptor::{identity_for_tests, named_for_tests};
    use crate::collection::{CollectionDerive, CollectionMerge, CollectionPolicy};

    fn handle(byte: u8) -> Inline<Handle<UnknownBlob>> {
        Inline::new([byte; 32])
    }

    #[test]
    fn capability_proofs_are_an_idempotent_set_without_resident_definitions() {
        let mut repo = MemoryRepo::default();
        let root = SigningKey::from_bytes(&[61; 32]);
        let leaf = SigningKey::from_bytes(&[62; 32]);
        let capability = Inline::new([63; 32]);
        let proof = CapabilityProof::new(
            CapabilityResource::new([64; 32]),
            &root,
            capability,
            leaf.verifying_key(),
        );

        repo.insert_proof(proof.clone()).unwrap();
        repo.insert_proof(proof.clone()).unwrap();
        let snapshot = repo.snapshot().unwrap();
        assert_eq!(snapshot.proof(proof.id()).unwrap(), Some(proof.clone()));
        assert_eq!(snapshot.proof(Inline::new([0; 32])).unwrap(), None);
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof]
        );
    }

    #[test]
    fn capability_proof_insert_rejects_bad_signatures_without_mutation() {
        let mut repo = MemoryRepo::default();
        let root = SigningKey::from_bytes(&[65; 32]);
        let leaf = SigningKey::from_bytes(&[66; 32]);
        let proof = CapabilityProof::new(
            CapabilityResource::new([67; 32]),
            &root,
            Inline::new([68; 32]),
            leaf.verifying_key(),
        );
        let before = repo.snapshot().unwrap();
        let mut bytes = proof.as_bytes().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let invalid = CapabilityProof::from_bytes(&bytes).unwrap();
        assert!(matches!(
            repo.insert_proof(invalid),
            Err(MemoryProofInsertError::Invalid(_))
        ));
        let after = repo.snapshot().unwrap();
        assert_eq!(after.changes_since(&before), StoreChanges::NONE);
        assert_eq!(after.proofs().unwrap().count(), 0);
    }

    /// Wants form an idempotent grow-only set. Enumeration is sorted (stable
    /// across runs despite HashSet backing).
    #[test]
    fn wants_are_grow_only_and_idempotent() {
        let mut repo = MemoryRepo::default();
        assert_eq!(repo.snapshot().unwrap().wants().unwrap().count(), 0);

        let first = WantRequest::blob(handle(1));
        let second = WantRequest::blob(handle(2));
        repo.want(second).unwrap();
        repo.want(first).unwrap();
        // Reasserting an existing want is idempotent.
        repo.want(first).unwrap();
        let wants: Vec<_> = repo
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(wants, vec![first, second], "sorted enumeration");

        repo.want(first).unwrap();
        assert_eq!(repo.snapshot().unwrap().wants().unwrap().count(), 2);
    }

    #[test]
    fn collection_records_are_idempotent_and_fingerprint_ordered() {
        let descriptor = named_for_tests("merged", Id::new([2; 16]).unwrap());
        let target = named_for_tests("derived", Id::new([8; 16]).unwrap());
        let merge = CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            Inline::new([4; 32]),
            Inline::new([5; 32]),
            Inline::new([6; 32]),
        ));
        let derive = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&target),
            Inline::new([10; 32]),
            Inline::new([11; 32]),
        ));
        let mut expected = vec![derive, merge];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);

        let mut repo = MemoryRepo::default();
        CollectionStore::insert(&mut repo, merge).unwrap();
        CollectionStore::insert(&mut repo, derive).unwrap();
        CollectionStore::insert(&mut repo, merge).unwrap();

        let snapshot = repo.snapshot().unwrap();
        let actual = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(snapshot.record(merge.fingerprint()).unwrap(), Some(merge));
        assert_eq!(
            snapshot
                .record(CollectionRecordFingerprint::from_raw([0xff; 32]))
                .unwrap(),
            None
        );
    }

    #[test]
    fn collection_index_rejects_a_different_body_under_an_existing_key() {
        let target = identity_for_tests(&named_for_tests("target", Id::new([12; 16]).unwrap()));
        let expected = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            Inline::new([14; 32]),
            Inline::new([15; 32]),
        ));
        let mismatched = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            Inline::new([16; 32]),
            Inline::new([17; 32]),
        ));
        let fingerprint = expected.fingerprint();

        let mut repo = MemoryRepo::default();
        repo.collection_records
            .insert(&Entry::with_value(&fingerprint.raw(), mismatched));

        assert!(matches!(
            repo.insert(expected),
            Err(MemoryCollectionInsertError::FingerprintCollision { fingerprint: found })
                if found == fingerprint
        ));
        assert_eq!(
            repo.collection_records.get(&fingerprint.raw()),
            Some(&mismatched)
        );
    }

    #[test]
    fn collection_primary_selection_answers_group_and_exact_conflicting_operations() {
        let source = identity_for_tests(&named_for_tests("source", Id::new([22; 16]).unwrap()));
        let target = identity_for_tests(&named_for_tests("target", Id::new([25; 16]).unwrap()));
        let other = identity_for_tests(&named_for_tests("other", Id::new([28; 16]).unwrap()));
        let input = Inline::new([30; 32]);
        let merge = CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            source,
            Inline::new([31; 32]),
            Inline::new([32; 32]),
            Inline::new([33; 32]),
        ));
        let first = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            input,
            Inline::new([34; 32]),
        ));
        let conflicting = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            input,
            Inline::new([35; 32]),
        ));
        let sibling = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            Inline::new([36; 32]),
            Inline::new([37; 32]),
        ));
        let unrelated = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            other,
            input,
            Inline::new([38; 32]),
        ));
        let mut repo = MemoryRepo::default();
        for record in [unrelated, conflicting, merge, first, sibling, first] {
            repo.insert(record).unwrap();
        }

        let exact = [CollectionRecordSelector::Operation(WantRequest::derive(
            target, input,
        ))]
        .into_iter()
        .collect();
        let mut expected = vec![first, conflicting];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);
        let snapshot = repo.snapshot().unwrap();
        assert_eq!(snapshot.select_records(&exact).unwrap(), expected);

        let grouped = [
            CollectionRecordSelector::MergeCollection(source),
            CollectionRecordSelector::DeriveTarget(target),
        ]
        .into_iter()
        .collect();
        let mut expected = vec![merge, first, conflicting, sibling];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);
        assert_eq!(snapshot.select_records(&grouped).unwrap(), expected);
        assert!(!snapshot
            .select_records(&grouped)
            .unwrap()
            .contains(&unrelated));
    }

    #[test]
    fn collection_commits_and_owned_closure_survive_memory_keep() {
        use ed25519_dalek::SigningKey;

        use crate::blob::encodings::utf8string::UTF8String;
        use crate::collection::{simplearchive_union, CollectionStoreExt};
        use crate::repo::{BlobStoreGet, BlobStoreKeep};

        let mut repo = MemoryRepo::default();
        let child = repo.put::<UTF8String, _>("owned child".to_owned()).unwrap();
        let fragment = entity! { crate::metadata::name: child };
        let name = "owned";
        let key = SigningKey::from_bytes(&[23; 32]);
        let policy = CollectionPolicy::new(
            crate::collection::AdmissionPolicy::direct(key.verifying_key()),
            crate::collection::AdmissionPolicy::direct(key.verifying_key()),
        );
        let descriptor = simplearchive_union::descriptor(name, policy.clone());
        let expected_collection = identity_for_tests(&descriptor);
        let collection: crate::collection::Collection<SimpleArchive> =
            repo.collection(name, policy).unwrap();
        assert_eq!(collection.handle(), expected_collection);
        let commit = repo.commit(collection, &key, fragment).unwrap();
        let orphan = repo.put::<UTF8String, _>("orphan".to_owned()).unwrap();

        repo.keep(std::iter::empty::<Inline<Handle<UnknownBlob>>>());

        let reader = repo.snapshot().unwrap();
        for retained in [
            collection.handle().transmute(),
            Inline::<Handle<UnknownBlob>>::new(commit.data().raw),
            commit.metadata().transmute(),
            child.transmute(),
        ] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(retained).is_ok());
        }
        assert!(reader
            .get::<Blob<UnknownBlob>, _>(orphan.transmute())
            .is_err());
    }

    #[test]
    fn equations_and_wants_own_each_resident_reference_independently() {
        use crate::repo::{BlobStoreGet, BlobStoreKeep};

        let mut repo = MemoryRepo::default();
        let child = repo
            .put::<UnknownBlob, _>(Bytes::from_source(b"recursive child".to_vec()))
            .unwrap();
        let merge_input = repo
            .put::<UnknownBlob, _>(Bytes::from_source(child.raw.to_vec()))
            .unwrap();
        let merge_output = repo
            .put::<UnknownBlob, _>(Bytes::from_source(b"merge output".to_vec()))
            .unwrap();
        let descriptor = repo
            .put::<UnknownBlob, _>(Bytes::from_source(b"descriptor".to_vec()))
            .unwrap();
        let wanted_input = repo
            .put::<UnknownBlob, _>(Bytes::from_source(b"wanted input".to_vec()))
            .unwrap();
        let orphan = repo
            .put::<UnknownBlob, _>(Bytes::from_source(b"orphan".to_vec()))
            .unwrap();

        repo.insert(CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            descriptor.transmute(),
            Inline::new(merge_input.raw),
            Inline::new([0xff; 32]),
            Inline::new(merge_output.raw),
        )))
        .unwrap();
        repo.want(WantRequest::derive(
            descriptor.transmute(),
            Inline::new(wanted_input.raw),
        ))
        .unwrap();

        repo.keep(std::iter::empty::<Inline<Handle<UnknownBlob>>>());

        let reader = repo.snapshot().unwrap();
        for retained in [child, merge_input, merge_output, descriptor, wanted_input] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(retained).is_ok());
        }
        assert!(reader.get::<Blob<UnknownBlob>, _>(orphan).is_err());
    }

    #[test]
    fn proof_admission_is_frozen_with_snapshot_evidence() {
        use crate::collection::{AdmissionPolicy, CollectionStoreExt};

        let root = SigningKey::from_bytes(&[91; 32]);
        let writer = SigningKey::from_bytes(&[92; 32]);
        let mut repo = MemoryRepo::default();
        let collection = repo
            .collection(
                "snapshot-evidence",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();
        let before = repo.snapshot().unwrap();
        repo.insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            crate::collection::write_capability(),
            writer.verifying_key(),
        ))
        .unwrap();

        let admitted = repo.snapshot().unwrap();
        assert!(!collection
            .writer_is_admitted(&before, writer.verifying_key())
            .unwrap());
        assert!(collection
            .writer_is_admitted(&admitted, writer.verifying_key())
            .unwrap());

        let later = repo.snapshot().unwrap();
        assert!(collection
            .writer_is_admitted(&later, writer.verifying_key())
            .unwrap());
        let retained = admitted.clone();
        assert!(collection
            .writer_is_admitted(&retained, writer.verifying_key())
            .unwrap());
        assert_eq!(
            admitted.changes_since(&before),
            StoreChanges::CAPABILITY_PROOFS
        );
        assert_eq!(later.changes_since(&admitted), StoreChanges::NONE);
    }

    #[test]
    fn snapshot_changes_track_exactly_the_semantic_sets() {
        use crate::blob::encodings::utf8string::UTF8String;

        let mut repo = MemoryRepo::default();
        let empty = repo.snapshot().unwrap();

        repo.want(WantRequest::blob(handle(1))).unwrap();
        let after_want = repo.snapshot().unwrap();
        assert!(empty.wants().unwrap().next().is_none());
        assert_eq!(after_want.wants().unwrap().count(), 1);
        assert_eq!(after_want.changes_since(&empty), StoreChanges::WANTS);

        repo.put::<UTF8String, _>("revision fixture".to_owned())
            .unwrap();
        let after_blob = repo.snapshot().unwrap();
        assert!(after_want != after_blob);
        assert_eq!(after_blob.changes_since(&after_want), StoreChanges::BLOBS,);

        let target = identity_for_tests(&named_for_tests(
            "revision-target",
            Id::new([71; 16]).unwrap(),
        ));
        repo.insert(CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            handle(73).into(),
            handle(74).into(),
        )))
        .unwrap();
        let after_record = repo.snapshot().unwrap();
        assert!(after_blob != after_record);
        assert_eq!(
            after_record.changes_since(&after_blob),
            StoreChanges::COLLECTION_RECORDS,
        );

        let root = SigningKey::from_bytes(&[75; 32]);
        let leaf = SigningKey::from_bytes(&[76; 32]);
        let proof = CapabilityProof::new(
            CapabilityResource::new([78; 32]),
            &root,
            Inline::new([77; 32]),
            leaf.verifying_key(),
        );
        repo.insert_proof(proof).unwrap();
        let after_proof = repo.snapshot().unwrap();
        assert!(after_record != after_proof);
        assert_eq!(
            after_proof.changes_since(&after_record),
            StoreChanges::CAPABILITY_PROOFS,
        );
    }

    #[test]
    fn snapshot_freezes_blob_and_collection_reads_together() {
        use crate::blob::encodings::utf8string::UTF8String;

        let mut repo = MemoryRepo::default();
        let before = repo.snapshot().unwrap();
        let blob = repo
            .put::<UTF8String, _>("after snapshot".to_owned())
            .unwrap();
        let target = identity_for_tests(&named_for_tests(
            "snapshot-target",
            Id::new([81; 16]).unwrap(),
        ));
        let record = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            handle(82).into(),
            handle(83).into(),
        ));
        repo.insert(record).unwrap();
        let after = repo.snapshot().unwrap();

        assert!(!before.contains_blob(blob).unwrap());
        assert_eq!(before.record(record.fingerprint()).unwrap(), None);

        assert!(after.contains_blob(blob).unwrap());
        assert_eq!(after.record(record.fingerprint()).unwrap(), Some(record));
    }
}
