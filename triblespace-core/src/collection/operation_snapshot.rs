//! One frozen control plane observed through a later blob snapshot.
//!
//! Active collection work may acquire immutable bytes and therefore has to
//! resnapshot the backing store. It must not accidentally admit collection
//! records or capability proofs which arrived while that work was in flight.
//! The initial snapshot remains the exact control-plane observation, while a
//! later snapshot contributes only newly resident blob bytes. `MERGE` and
//! `DERIVE` records authored by the operation itself are the sole overlay.

use std::collections::BTreeSet;
use std::marker::PhantomData;

use crate::blob::{BlobEncoding, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::patch::{Entry, IdentitySchema, XorSip128, PATCH};
use crate::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, CapabilityProofRead,
    StoreChanges, StoreSnapshot, WantRead,
};

use super::store::selectors_match_record;
use super::{CollectionRead, CollectionRecord, CollectionRecordSelector};

type AuthoredRecords = PATCH<32, IdentitySchema, CollectionRecord, XorSip128>;

/// The immutable control-plane observation for one active operation.
#[derive(Clone)]
pub(crate) struct OperationFrontier<C> {
    control: C,
    authored: AuthoredRecords,
}

impl<C> OperationFrontier<C> {
    pub(crate) fn new(control: C) -> Self {
        Self {
            control,
            authored: AuthoredRecords::new(),
        }
    }

    pub(crate) fn include_record(&mut self, record: CollectionRecord) {
        assert!(
            !matches!(record, CollectionRecord::Commit(_)),
            "an active realization may author only MERGE or DERIVE equations",
        );
        self.authored
            .insert(&Entry::with_value(&record.fingerprint().raw(), record));
    }

    pub(crate) fn view<R>(&self, residency: R) -> OperationSnapshot<C, R>
    where
        C: Clone,
    {
        OperationSnapshot {
            control: self.control.clone(),
            residency,
            authored: self.authored.clone(),
        }
    }
}

/// A later immutable blob observation bounded by an earlier control snapshot.
#[derive(Clone)]
pub(crate) struct OperationSnapshot<C, R> {
    control: C,
    residency: R,
    authored: AuthoredRecords,
}

/// The control snapshot's records, then the authored records it does not
/// already hold.
pub(crate) struct OperationRecordIter<I, E>
where
    I: Iterator<Item = Result<CollectionRecord, E>>,
{
    control: I,
    fresh: std::vec::IntoIter<CollectionRecord>,
    error: PhantomData<fn() -> E>,
}

impl<I, E> Iterator for OperationRecordIter<I, E>
where
    I: Iterator<Item = Result<CollectionRecord, E>>,
{
    type Item = Result<CollectionRecord, E>;

    fn next(&mut self) -> Option<Self::Item> {
        self.control.next().or_else(|| self.fresh.next().map(Ok))
    }
}

impl<C, R> StoreSnapshot for OperationSnapshot<C, R>
where
    C: StoreSnapshot,
    R: StoreSnapshot,
{
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        let control = self.control.changes_since(&previous.control);
        let residency = self.residency.changes_since(&previous.residency);
        let mut changes = StoreChanges::NONE;
        if residency.contains(StoreChanges::BLOBS) {
            changes = changes.union(StoreChanges::BLOBS);
        }
        for component in [
            StoreChanges::COLLECTION_RECORDS,
            StoreChanges::CAPABILITY_PROOFS,
            StoreChanges::WANTS,
        ] {
            if control.contains(component) {
                changes = changes.union(component);
            }
        }
        if self.authored != previous.authored {
            changes = changes.union(StoreChanges::COLLECTION_RECORDS);
        }
        changes
    }
}

impl<C, R> BlobStoreGet for OperationSnapshot<C, R>
where
    R: BlobStoreGet,
{
    type GetError<E: std::error::Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.residency.get(handle)
    }
}

impl<C, R> BlobStoreList for OperationSnapshot<C, R>
where
    R: BlobStoreList,
{
    type Iter<'a>
        = R::Iter<'a>
    where
        Self: 'a;
    type Err = R::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.residency.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.residency.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.residency.blob_info(handle)
    }
}

impl<C, R> BlobStoreMeta for OperationSnapshot<C, R>
where
    R: BlobStoreMeta,
{
    type MetaError = R::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.residency.metadata(handle)
    }
}

/// A frontier's coverage is its control's index, continued: clone it (every
/// part is a persistent root), park the records this operation authored, and
/// settle them against the frontier's own view. The fold the control ran is
/// not restarted, so nothing beneath the authored records is re-decided and
/// no record is enumerated -- which is also why a reader tracking what was
/// consulted sees the lineage it named rather than every record in the store.
impl<C, R> super::store::CoverageRead for OperationSnapshot<C, R>
where
    C: super::store::CoverageRead,
    Self: crate::repo::BlobStoreGet + crate::repo::CapabilityProofRead,
{
    fn index(
        &self,
        lineage: &BTreeSet<super::CollectionHandle>,
    ) -> Result<super::coverage::CoverageIndex, Self::RecordsError> {
        let mut index = self.control.index(lineage)?;
        for key in self.authored.iter_ordered() {
            let record = self
                .authored
                .get(key)
                .expect("authored PATCH key must retain its record");
            index.park_record(record);
        }
        index.settle_collections(&super::coverage::StoreWriters::new(self), lineage);
        Ok(index)
    }
}

impl<C, R> CollectionRead for OperationSnapshot<C, R>
where
    C: CollectionRead,
{
    type RecordsError = C::RecordsError;
    type RecordIter<'a>
        = OperationRecordIter<C::RecordIter<'a>, Self::RecordsError>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        // An authored record the control snapshot already holds is yielded
        // once, from the control side. The producers of its member are the
        // only records it could be, so ask for exactly those.
        let mut fresh = Vec::new();
        for key in self.authored.iter_ordered() {
            let record = *self
                .authored
                .get(key)
                .expect("authored PATCH key must retain its record");
            let producers = BTreeSet::from([CollectionRecordSelector::ProducedMember(
                record.collection(),
                super::coverage::produced(record),
            )]);
            if !self.control.select_records(&producers)?.contains(&record) {
                fresh.push(record);
            }
        }
        Ok(OperationRecordIter {
            control: self.control.records()?,
            fresh: fresh.into_iter(),
            error: PhantomData,
        })
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        let mut selected = self.control.select_records(selectors)?;
        let control_len = selected.len();
        for key in self.authored.iter_ordered() {
            let record = *self
                .authored
                .get(key)
                .expect("authored PATCH key must retain its record");
            // Anything the control view selected by these routes is already
            // in `selected`, so a duplicate can only be among those.
            if selectors_match_record(selectors, record) && !selected[..control_len].contains(&record)
            {
                selected.push(record);
            }
        }
        Ok(selected)
    }
}

impl<C, R> CapabilityProofRead for OperationSnapshot<C, R>
where
    C: CapabilityProofRead,
{
    type ProofsError = C::ProofsError;
    type ProofIter<'a>
        = C::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.control.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.control.proof(id)
    }
}

// WANT is an independent durable residency assertion, not part of active
// collection realization. Keep the exact initial observation rather than
// admitting concurrent demand into the bounded operation.
impl<C, R> WantRead for OperationSnapshot<C, R>
where
    C: WantRead,
{
    type WantsError = C::WantsError;
    type WantIter<'a>
        = C::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.control.wants()
    }
}

#[cfg(test)]
mod tests {
    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
    use crate::capability::{CapabilityHandle, CapabilityResource};
    use crate::collection::{
        empty_metadata_handle, CollectionCommit, CollectionDerive, CollectionStore,
    };
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{BlobStorePut, CapabilityProofStore, SnapshotSource, WantRequest, WantStore};

    fn record(byte: u8) -> CollectionRecord {
        let key = SigningKey::from_bytes(&[7; 32]);
        let _input = CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            Inline::<Handle<SimpleArchive>>::new([2; 32]),
            Inline::new([byte; 32]),
            empty_metadata_handle(),
        ));
        CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            Inline::<Handle<SimpleArchive>>::new([1; 32]),
            Inline::new([byte; 32]),
            Inline::new([byte.wrapping_add(1); 32]),
        ))
    }

    fn proof(byte: u8) -> CapabilityProof {
        let root = SigningKey::from_bytes(&[byte; 32]);
        let leaf = SigningKey::from_bytes(&[byte.wrapping_add(1); 32]);
        CapabilityProof::new(
            CapabilityResource::new([byte; 32]),
            &root,
            CapabilityHandle::new([byte; 32]),
            leaf.verifying_key(),
        )
    }

    #[test]
    fn later_snapshots_supply_only_residency_plus_operation_authored_equations() {
        let mut store = MemoryRepo::default();
        let initial_record = record(10);
        let concurrent_record = record(20);
        let authored_record = record(30);
        let initial_proof = proof(40);
        let concurrent_proof = proof(50);
        let initial_want = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([60; 32]));
        let concurrent_want = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([61; 32]));

        store.insert(initial_record).unwrap();
        store.insert_proof(initial_proof.clone()).unwrap();
        store.want(initial_want).unwrap();
        let control = store.snapshot().unwrap();

        store.insert(concurrent_record).unwrap();
        store.insert_proof(concurrent_proof).unwrap();
        store.want(concurrent_want).unwrap();
        let bytes = Bytes::from_source(b"arrived after the control snapshot".to_vec());
        let arrived = store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
        let residency = store.snapshot().unwrap();

        let mut frontier = OperationFrontier::new(control);
        frontier.include_record(authored_record);
        let observed = frontier.view(residency);
        let later = frontier.view(store.snapshot().unwrap());
        assert_eq!(
            observed.clone().changes_since(&observed),
            StoreChanges::NONE
        );
        assert_eq!(later.changes_since(&observed), StoreChanges::NONE);

        let records = observed
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&initial_record));
        assert!(records.contains(&authored_record));
        assert!(!records.contains(&concurrent_record));

        let proofs = observed
            .proofs()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(proofs, vec![initial_proof]);
        let wants = observed
            .wants()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(wants, vec![initial_want]);
        assert_eq!(observed.get::<Bytes, UnknownBlob>(arrived).unwrap(), bytes,);
    }

    /// A fingerprint is a BLAKE3 digest of the record's whole canonical
    /// payload. Selection no longer recovers any order from it: the control
    /// view answers first and the authored records this operation added
    /// follow, so nothing here is hashed at all -- with or without an
    /// authored record in the result.
    #[test]
    fn selection_never_hashes_a_record() {
        use crate::collection::records::FINGERPRINT_CALLS;

        let mut store = MemoryRepo::default();
        let control_records: Vec<_> = (0u8..64).map(record).collect();
        for record in &control_records {
            store.insert(*record).unwrap();
        }
        let control = store.snapshot().unwrap();
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(
            Inline::<Handle<SimpleArchive>>::new([1; 32]),
        )]);

        let warm = OperationFrontier::new(control.clone()).view(control.clone());
        assert_eq!(warm.select_records(&selectors).unwrap().len(), 64);
        let before = FINGERPRINT_CALLS.get();
        assert_eq!(warm.select_records(&selectors).unwrap().len(), 64);
        assert_eq!(FINGERPRINT_CALLS.get() - before, 0);

        let mut frontier = OperationFrontier::new(control.clone());
        frontier.include_record(record(200));
        let authored = frontier.view(control);
        let warm = authored.select_records(&selectors).unwrap();
        assert_eq!(warm.len(), 65);
        let before = FINGERPRINT_CALLS.get();
        let selected = authored.select_records(&selectors).unwrap();
        assert_eq!(selected, warm);
        assert_eq!(FINGERPRINT_CALLS.get() - before, 0);
    }
}
