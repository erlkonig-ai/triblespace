use crate::blob::encodings::UnknownBlob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::blob::TryFromBlob;
use crate::capability::CapabilityProof;
use crate::collection::{CollectionRead, CollectionRecord, CollectionStore};
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::repo::BlobChildren;
use crate::repo::BlobInfo;
use crate::repo::BlobMetadata;
use crate::repo::BlobStoreGet;
use crate::repo::BlobStoreList;
use crate::repo::BlobStoreMeta;
use crate::repo::BlobStorePut;
use crate::repo::CapabilityProofRead;
use crate::repo::CapabilityProofStore;
use crate::repo::SnapshotSource;
use crate::repo::StorageFlush;
use crate::repo::StoreChanges;
use crate::repo::StoreSnapshot;
use crate::repo::{WantRead, WantRequest, WantStore};
use std::error::Error;
use std::fmt;

/// Store that delegates blob/want and collection-record operations to two
/// independent stores.
///
/// This allows mixing different storage implementations, for example an
/// on-disk blob store with an in-memory collection-record store.
#[derive(Debug)]
pub struct HybridStore<B, R> {
    /// Storage for content-addressed blobs and durable typed wants.
    pub blobs: B,
    /// Storage for native collection records.
    pub records: R,
}

/// One immutable, dependency-consistent observation of both halves of a
/// [`HybridStore`].
///
/// Blob capabilities come exclusively from `blobs`; collection and proof
/// capabilities come exclusively from `records`. Wants come from the frozen
/// blob-side observation. The record
/// half is sampled first and the blob half second, mirroring dependency-first
/// publication: every semantic record observed by a conforming writer can
/// therefore see the blobs published before it.
#[derive(Clone, Debug)]
pub struct HybridSnapshot<B, R> {
    /// Frozen blob-side observation.
    blobs: B,
    /// Frozen semantic-record-side observation.
    records: R,
}

impl<B, R> StoreSnapshot for HybridSnapshot<B, R>
where
    B: StoreSnapshot,
    R: StoreSnapshot,
{
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        let blob_changes = self.blobs.changes_since(&previous.blobs);
        let record_changes = self.records.changes_since(&previous.records);
        let mut changes = StoreChanges::NONE;
        if blob_changes.contains(StoreChanges::BLOBS) {
            changes = changes.union(StoreChanges::BLOBS);
        }
        if blob_changes.contains(StoreChanges::WANTS) {
            changes = changes.union(StoreChanges::WANTS);
        }
        for component in [
            StoreChanges::COLLECTION_RECORDS,
            StoreChanges::CAPABILITY_PROOFS,
        ] {
            if record_changes.contains(component) {
                changes = changes.union(component);
            }
        }
        changes
    }
}

/// Failure while freezing one side of a [`HybridStore`].
#[derive(Debug)]
pub enum HybridSnapshotError<BlobError, RecordError> {
    /// The blob-side snapshot could not be frozen.
    Blobs(BlobError),
    /// The semantic-record-side snapshot could not be frozen.
    Records(RecordError),
}

impl<BlobError, RecordError> fmt::Display for HybridSnapshotError<BlobError, RecordError>
where
    BlobError: fmt::Display,
    RecordError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blobs(error) => {
                write!(formatter, "failed to snapshot hybrid blob store: {error}")
            }
            Self::Records(error) => {
                write!(formatter, "failed to snapshot hybrid record store: {error}")
            }
        }
    }
}

impl<BlobError, RecordError> Error for HybridSnapshotError<BlobError, RecordError>
where
    BlobError: Error + 'static,
    RecordError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Blobs(error) => Some(error),
            Self::Records(error) => Some(error),
        }
    }
}

impl<B, R> HybridStore<B, R> {
    /// Creates a new [`HybridStore`] from the given blob and record stores.
    pub fn new(blobs: B, records: R) -> Self {
        Self { blobs, records }
    }
}

/// Failure while crash-ordering writes across a [`HybridStore`].
#[derive(Debug)]
pub enum HybridFlushError<BlobError, RecordError> {
    /// The content-addressed blob store could not make staged data durable.
    Blobs(BlobError),
    /// The record store could not make collection evidence durable.
    Records(RecordError),
}

impl<BlobError, RecordError> fmt::Display for HybridFlushError<BlobError, RecordError>
where
    BlobError: fmt::Display,
    RecordError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blobs(error) => write!(formatter, "failed to flush hybrid blob store: {error}"),
            Self::Records(error) => {
                write!(formatter, "failed to flush hybrid record store: {error}")
            }
        }
    }
}

impl<BlobError, RecordError> Error for HybridFlushError<BlobError, RecordError>
where
    BlobError: Error + 'static,
    RecordError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Blobs(error) => Some(error),
            Self::Records(error) => Some(error),
        }
    }
}

impl<B, R> StorageFlush for HybridStore<B, R>
where
    B: StorageFlush,
    R: StorageFlush,
{
    type Error = HybridFlushError<B::Error, R::Error>;

    fn flush(&mut self) -> Result<(), Self::Error> {
        // Never let authoritative records become durable ahead of the blobs
        // they name. If the first barrier fails, leave record durability
        // untouched; if the second fails, only harmless orphan blobs remain.
        self.blobs.flush().map_err(HybridFlushError::Blobs)?;
        self.records.flush().map_err(HybridFlushError::Records)
    }
}

impl<B, R> BlobStorePut for HybridStore<B, R>
where
    B: BlobStorePut,
{
    type PutError = B::PutError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.blobs.put(item)
    }
}

impl<B, R> SnapshotSource for HybridStore<B, R>
where
    B: SnapshotSource,
    R: SnapshotSource,
{
    type Snapshot = HybridSnapshot<B::Snapshot, R::Snapshot>;
    type SnapshotError = HybridSnapshotError<B::SnapshotError, R::SnapshotError>;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        // Publication stores dependencies before the records which name them.
        // Reading in the opposite order makes the non-atomic split safe: a
        // record observed here cannot name a dependency published only after
        // the later blob observation.
        let records = self
            .records
            .snapshot()
            .map_err(HybridSnapshotError::Records)?;
        let blobs = self.blobs.snapshot().map_err(HybridSnapshotError::Blobs)?;
        Ok(HybridSnapshot { blobs, records })
    }
}

impl<B, R> BlobStoreGet for HybridSnapshot<B, R>
where
    B: BlobStoreGet,
{
    type GetError<E: Error + Send + Sync + 'static> = B::GetError<E>;

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

impl<B, R> BlobStoreList for HybridSnapshot<B, R>
where
    B: BlobStoreList,
{
    type Iter<'a>
        = B::Iter<'a>
    where
        Self: 'a;
    type Err = B::Err;

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

impl<B, R> BlobStoreMeta for HybridSnapshot<B, R>
where
    B: BlobStoreMeta,
{
    type MetaError = B::MetaError;

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

impl<B, R> BlobChildren for HybridSnapshot<B, R>
where
    B: BlobChildren,
{
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        self.blobs.children(handle)
    }
}

/// A hybrid has no index of its own: its blobs -- and so the descriptors a
/// fold resolves lineages from -- come from one side, its records and proofs
/// from the other. `Covered<HybridStore<B, R>>` maintains one over the pair,
/// fed by the record side's difference, where this used to refold on every
/// read.
impl<B, R> crate::collection::covered::RecordDelta for HybridSnapshot<B, R>
where
    R: crate::collection::covered::RecordDelta,
{
    fn for_each_record_since(
        &self,
        since: Option<&Self>,
        each: &mut dyn FnMut(&CollectionRecord),
    ) {
        self.records
            .for_each_record_since(since.map(|since| &since.records), each)
    }
}

impl<B, R> CollectionRead for HybridSnapshot<B, R>
where
    R: CollectionRead,
{
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.records.records()
    }

    fn record(
        &self,
        fingerprint: crate::collection::CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.records.record(fingerprint)
    }

    fn select_records(
        &self,
        selectors: &std::collections::BTreeSet<crate::collection::CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.records.select_records(selectors)
    }
}

impl<B, R> CapabilityProofRead for HybridSnapshot<B, R>
where
    R: CapabilityProofRead,
{
    type ProofsError = R::ProofsError;
    type ProofIter<'a>
        = R::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.records.proofs()
    }

    fn proof(
        &self,
        id: crate::capability::CapabilityProofId,
    ) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.records.proof(id)
    }
}

impl<B, R> CollectionStore for HybridStore<B, R>
where
    R: CollectionStore,
{
    type InsertError = R::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.records.insert(record)
    }
}

impl<B, R> CapabilityProofStore for HybridStore<B, R>
where
    R: CapabilityProofStore,
{
    type InsertError = R::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.records.insert_proof(proof)
    }
}

impl<B, R> WantStore for HybridStore<B, R>
where
    B: WantStore,
{
    type WantError = B::WantError;

    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.blobs.want(request)
    }
}

impl<B, R> WantRead for HybridSnapshot<B, R>
where
    B: WantRead,
{
    type WantsError = B::WantsError;
    type WantIter<'a>
        = B::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.blobs.wants()
    }
}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    /// An equation names its input PAYLOAD; this used to pair it with a
    /// fingerprint citing a record that produced it.
    use super::*;
    use crate::id::Id;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::IntoBlob;
    use crate::collection::{
        descriptor, CollectionHandle, CollectionMerge, CollectionPolicy, CollectionRead,
        CollectionRecordSelector, CollectionStoreExt,
    };
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::SnapshotSource;
    use crate::trible::Fragment;
    use crate::trible::TribleSet;
    use ed25519_dalek::SigningKey;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    #[test]
    fn snapshots_freeze_content_from_both_halves() {
        let mut hybrid = HybridStore::new(MemoryRepo::default(), MemoryRepo::default());
        let before = hybrid.snapshot().unwrap();
        let unchanged = hybrid.snapshot().unwrap();
        assert_eq!(unchanged.changes_since(&before), StoreChanges::NONE);

        let handle = hybrid.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        let record = CollectionRecord::Commit(crate::collection::CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            CollectionHandle::new([2; 32]),
            Handle::<SimpleArchive>::to_hash(handle),
            crate::collection::empty_metadata_handle(),
        ));
        hybrid.insert(record).unwrap();
        let after = hybrid.snapshot().unwrap();
        assert_eq!(
            after.changes_since(&before),
            StoreChanges::BLOBS.union(StoreChanges::COLLECTION_RECORDS)
        );
        assert!(!before.contains_blob(handle).unwrap());
        assert_eq!(before.clone().records().unwrap().count(), 0);
        assert!(after.contains_blob(handle).unwrap());
        assert_eq!(after.records().unwrap().count(), 1);

        let current = hybrid.snapshot().unwrap();
        assert_eq!(current.changes_since(&after), StoreChanges::NONE);
    }

    #[test]
    fn collection_records_delegate_only_to_the_record_side() {
        let facts = descriptor::named_for_tests("hybrid", id(2)).into_facts();
        // Only the identity matters here; nothing resolves this descriptor.
        let collection: CollectionHandle = IntoBlob::<SimpleArchive>::to_blob(facts).get_handle();
        let record = CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            collection,
            Inline::new([4; 32]),
            Inline::new([5; 32]),
            Inline::new([6; 32]),
        ));
        let mut hybrid = HybridStore::new(MemoryRepo::default(), MemoryRepo::default());

        CollectionStore::insert(&mut hybrid, record).unwrap();
        let snapshot = hybrid.snapshot().unwrap();
        assert_eq!(
            snapshot
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![record]
        );
        let selectors = [CollectionRecordSelector::MergeCollection(collection)]
            .into_iter()
            .collect();
        assert_eq!(snapshot.select_records(&selectors).unwrap(), vec![record]);
        let record_snapshot = hybrid.records.snapshot().unwrap();
        assert_eq!(record_snapshot.records().unwrap().count(), 1);
        let blob_snapshot = hybrid.blobs.snapshot().unwrap();
        assert_eq!(blob_snapshot.records().unwrap().count(), 0);
    }

    #[test]
    fn collection_publication_and_read_work_across_both_sides() {
        // Reading a collection needs coverage, which a hybrid gets from the
        // wrapper over the pair, not from either side.
        let mut hybrid = crate::collection::covered::Covered::new(HybridStore::new(
            MemoryRepo::default(),
            MemoryRepo::default(),
        ));
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let name = "hybrid";
        let target = hybrid
            .collection(
                name,
                CollectionPolicy::new(
                    crate::collection::AdmissionPolicy::direct(signing_key.verifying_key()),
                    crate::collection::AdmissionPolicy::direct(signing_key.verifying_key()),
                ),
            )
            .unwrap();

        let commit = hybrid
            .commit(target, &signing_key, Fragment::empty())
            .unwrap();
        let snapshot = hybrid.snapshot().unwrap();
        let facts: TribleSet = target.read(&snapshot).unwrap();
        assert_eq!(facts.len(), 0);
        assert_eq!(commit.collection(), target.handle());
        assert!(hybrid.blobs.blobs.len() >= 2);
        let record_snapshot = hybrid.records.snapshot().unwrap();
        assert_eq!(
            record_snapshot
                .records()
                .unwrap()
                .filter_map(Result::ok)
                .filter(|record| {
                    matches!(record, CollectionRecord::Commit(commit) if commit.collection() == target.handle())
                })
                .count(),
            1
        );
        let blob_snapshot = hybrid.blobs.snapshot().unwrap();
        assert_eq!(blob_snapshot.records().unwrap().count(), 0);
    }

    #[test]
    fn wants_delegate_only_to_the_blob_side() {
        use crate::blob::encodings::UnknownBlob;

        let handle = Inline::<Handle<UnknownBlob>>::new([9; 32]);
        let request = WantRequest::blob(handle);
        let mut hybrid = HybridStore::new(MemoryRepo::default(), MemoryRepo::default());

        hybrid.want(request).unwrap();
        let snapshot = hybrid.snapshot().unwrap();
        assert_eq!(
            snapshot
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![request]
        );
        assert_eq!(hybrid.blobs.snapshot().unwrap().wants().unwrap().count(), 1);
        assert_eq!(
            hybrid.records.snapshot().unwrap().wants().unwrap().count(),
            0
        );
    }
}
