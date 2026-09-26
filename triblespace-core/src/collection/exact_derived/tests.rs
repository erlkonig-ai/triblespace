use super::*;

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anybytes::Bytes;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::executor::block_on;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
use crate::capability::{CapabilityHandle, CapabilityProof, CapabilityProofId, CapabilityResource};
use crate::collection::{
    collection_read_audience, read_capability, write_capability, AdmissionPolicy, CollectionCommit,
    CollectionDerive, CollectionMerge, CollectionOperationError, CollectionPolicy, CollectionRead,
    CollectionReadAudience, CollectionRecord, CollectionRecordSelector, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt, Cover, Support,
};
use crate::id::{ExclusiveId, Id};
use crate::id_hex;
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::metadata::MetaDescribe;
use crate::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use crate::repo::{
    async_store::AsyncBlobStoreAcquire, BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList,
    BlobStoreMeta, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
    StoreChanges, StoreSnapshot, WantRead,
};
use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

fn policy() -> CollectionPolicy {
    CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open)
}

fn equation_signer() -> SigningKey {
    SigningKey::from_bytes(&[31; 32])
}

fn row(entity: u8, value: u8) -> Trible {
    let mut raw = [value; TRIBLE_LEN];
    raw[..16].fill(entity);
    raw[16..32].fill(9);
    Trible::force_raw(raw).unwrap()
}

fn archive(entity: u8, value: u8) -> Blob<SimpleArchive> {
    let mut facts = TribleSet::new();
    facts.insert(&row(entity, value));
    facts.to_blob()
}

fn data<E: BlobEncoding>(blob: &Blob<E>) -> CollectionData
where
    Handle<E>: crate::inline::InlineEncoding,
{
    Handle::<E>::to_hash(blob.get_handle())
}

/// The identity of `source`'s image in the first view, computed without
/// calling (and counting) the mapping: its bytes followed by `0xA5`.
fn first_image(source: &Blob<SimpleArchive>) -> CollectionData {
    let mut bytes = source.bytes.as_ref().to_vec();
    bytes.push(0xA5);
    data(&Blob::<FirstEncoding>::new(bytes.into()))
}

fn append_adversarial_proof_edge(
    proof: CapabilityProof,
    issuer: &SigningKey,
    action: CapabilityHandle,
    delegate: VerifyingKey,
) -> CapabilityProof {
    let mut bytes = proof.into_bytes();
    bytes.extend_from_slice(&action.raw);
    bytes.extend_from_slice(&delegate.to_bytes());
    let signature = issuer.sign(&bytes);
    bytes.extend_from_slice(&signature.to_bytes());
    CapabilityProof::from_bytes(&bytes).expect("adversarial proof wire remains structurally valid")
}

fn support(collection: Collection<SimpleArchive>, blobs: &[Blob<SimpleArchive>]) -> Support {
    Cover::from_members(collection, blobs.iter().map(Blob::get_handle))
}

fn publish_root(
    store: &mut MemoryRepo,
    collection: Collection<SimpleArchive>,
    blob: &Blob<SimpleArchive>,
    key: u8,
) -> CollectionCommit {
    store.put::<SimpleArchive, _>(blob.clone()).unwrap();
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    let commit = CollectionCommit::sign(
        &SigningKey::from_bytes(&[key; 32]),
        collection.handle(),
        data(blob),
        metadata,
    );
    store.insert(CollectionRecord::Commit(commit)).unwrap();
    commit
}

/// A merge or derive names its input PAYLOAD. This used to wrap it
/// beside a fingerprint citing a record that produced it; nothing
/// cites anything now, so it is just the payload.
/// Test encoding `SimpleArchive || 0xA5`; id originally minted for the old
/// exact-derived tests with `trible genid` on 2026-08-29.
const FIRST_ENCODING: Id = id_hex!("39B18B6D13B2B1872F2394EF6588F1B5");
struct FirstEncoding;

impl BlobEncoding for FirstEncoding {}

impl MetaDescribe for FirstEncoding {
    fn describe() -> Fragment {
        let id = FIRST_ENCODING;
        crate::macros::entity! { ExclusiveId::force_ref(&id) @
            crate::metadata::name: "invariant-support-test-first",
            crate::metadata::tag: crate::metadata::KIND_BLOB_ENCODING,
        }
    }
}

fn decode_first(
    blob: &Blob<FirstEncoding>,
) -> Result<Blob<SimpleArchive>, CollectionOperationError> {
    let bytes = blob.bytes.as_ref().strip_suffix(&[0xA5]).ok_or_else(|| {
        CollectionOperationError::Fatal("first test encoding lacks suffix".to_owned())
    })?;
    let archive = Blob::new(bytes.to_vec().into());
    crate::collection::simplearchive_union::validate_element(&archive)
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    Ok(archive)
}

fn join_first(
    low: &Blob<FirstEncoding>,
    high: &Blob<FirstEncoding>,
) -> Result<Blob<FirstEncoding>, CollectionOperationError> {
    let low = decode_first(low)?;
    let high = decode_first(high)?;
    let joined = crate::collection::simplearchive_union::join(&low, &high)
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    let mut bytes = joined.bytes.as_ref().to_vec();
    bytes.push(0xA5);
    Ok(Blob::new(bytes.into()))
}

impl CollectionEncoding for FirstEncoding {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        decode_first(member).map(drop)
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        _low: &Blob<Self>,
        _high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        // A missing optional target-join dependency must leave the exact fine
        // cover intact, not cause construction back in SimpleArchive.
        Err(CollectionOperationError::MissingDependency(
            crate::inline::Inline::new([0xDD; 32]),
        ))
    }
}

/// Test encoding `(SimpleArchive || 0xA5) || 0xB6`; id originally minted for
/// the old exact-derived tests with `trible genid` on 2026-08-29.
const SECOND_ENCODING: Id = id_hex!("9318ADD9A6257CB8973AC8BE806D12EC");
struct SecondEncoding;

impl BlobEncoding for SecondEncoding {}

impl MetaDescribe for SecondEncoding {
    fn describe() -> Fragment {
        let id = SECOND_ENCODING;
        crate::macros::entity! { ExclusiveId::force_ref(&id) @
            crate::metadata::name: "invariant-support-test-second",
            crate::metadata::tag: crate::metadata::KIND_BLOB_ENCODING,
        }
    }
}

fn decode_second(
    blob: &Blob<SecondEncoding>,
) -> Result<Blob<FirstEncoding>, CollectionOperationError> {
    let bytes = blob.bytes.as_ref().strip_suffix(&[0xB6]).ok_or_else(|| {
        CollectionOperationError::Fatal("second test encoding lacks suffix".to_owned())
    })?;
    let first = Blob::new(bytes.to_vec().into());
    decode_first(&first)?;
    Ok(first)
}

impl CollectionEncoding for SecondEncoding {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        decode_second(member).map(drop)
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        SECOND_JOIN_CALLS.set(SECOND_JOIN_CALLS.get() + 1);
        let low = decode_first(&decode_second(low)?)?;
        let high = decode_first(&decode_second(high)?)?;
        let joined = crate::collection::simplearchive_union::join(&low, &high)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let mut bytes = joined.bytes.as_ref().to_vec();
        bytes.extend_from_slice(&[0xA5, 0xB6]);
        Ok(Blob::new(bytes.into()))
    }
}

const FIRST_MAPPING: Id = id_hex!("70D406F7483E8A1D384354D0AFD0D717");
struct FirstMappingAlgorithm;

impl MetaDescribe for FirstMappingAlgorithm {
    fn describe() -> Fragment {
        let id = FIRST_MAPPING;
        crate::macros::entity! { ExclusiveId::force_ref(&id) @
            crate::metadata::name: "invariant-support-test-first-mapping",
            crate::metadata::tag: crate::metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

thread_local! {
    static FIRST_MAP_CALLS: Cell<usize> = const { Cell::new(0) };
    static SECOND_MAP_CALLS: Cell<usize> = const { Cell::new(0) };
    static SECOND_JOIN_CALLS: Cell<usize> = const { Cell::new(0) };
    static FIRST_MAP_MISSING: Cell<bool> = const { Cell::new(false) };
    static FIRST_MAP_CAPACITY: RefCell<Option<CollectionData>> = const { RefCell::new(None) };
    static FIRST_MAP_FATAL: RefCell<Option<CollectionData>> = const { RefCell::new(None) };
}

fn reset_mapping_calls() {
    FIRST_MAP_CALLS.set(0);
    SECOND_MAP_CALLS.set(0);
    SECOND_JOIN_CALLS.set(0);
    FIRST_MAP_MISSING.set(false);
    FIRST_MAP_CAPACITY.replace(None);
    FIRST_MAP_FATAL.replace(None);
}

impl CollectionDerivation for FirstEncoding {
    type Source = SimpleArchive;
    type Argument = ();

    fn fragment(_argument: &Self::Argument) -> Fragment {
        crate::macros::entity! {
            crate::metadata::tag: crate::collection::KIND_COLLECTION_MAPPING,
            crate::collection::mapping_algorithm*: <FirstMappingAlgorithm as MetaDescribe>::describe(),
        }
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        require_mapping(target, FIRST_MAPPING)?;
        Ok(())
    }

    fn map<R>(
        _argument: &Self::Argument,
        source: &Blob<Self::Source>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        FIRST_MAP_CALLS.set(FIRST_MAP_CALLS.get() + 1);
        if FIRST_MAP_MISSING.get() {
            return Err(CollectionOperationError::MissingDependency(
                crate::inline::Inline::new([0xEE; 32]),
            ));
        }
        if FIRST_MAP_CAPACITY.with_borrow(|blocked| *blocked == Some(data(source))) {
            return Err(CollectionOperationError::Capacity(
                "injected source capacity".to_owned(),
            ));
        }
        if FIRST_MAP_FATAL.with_borrow(|refused| *refused == Some(data(source))) {
            return Err(CollectionOperationError::Fatal(
                "injected source refusal".to_owned(),
            ));
        }
        let mut bytes = source.bytes.as_ref().to_vec();
        bytes.push(0xA5);
        Ok(Blob::new(bytes.into()))
    }
}

const SECOND_MAPPING: Id = id_hex!("4B671CE9A7CF6F2AEC3AD5F9B2A59FBC");
struct SecondMappingAlgorithm;

impl MetaDescribe for SecondMappingAlgorithm {
    fn describe() -> Fragment {
        let id = SECOND_MAPPING;
        crate::macros::entity! { ExclusiveId::force_ref(&id) @
            crate::metadata::name: "invariant-support-test-second-mapping",
            crate::metadata::tag: crate::metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

impl CollectionDerivation for SecondEncoding {
    type Source = FirstEncoding;
    type Argument = ();

    fn fragment(_argument: &Self::Argument) -> Fragment {
        crate::macros::entity! {
            crate::metadata::tag: crate::collection::KIND_COLLECTION_MAPPING,
            crate::collection::mapping_algorithm*: <SecondMappingAlgorithm as MetaDescribe>::describe(),
        }
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        require_mapping(target, SECOND_MAPPING)?;
        Ok(())
    }

    fn map<R>(
        _argument: &Self::Argument,
        source: &Blob<Self::Source>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        SECOND_MAP_CALLS.set(SECOND_MAP_CALLS.get() + 1);
        decode_first(source)?;
        let mut bytes = source.bytes.as_ref().to_vec();
        bytes.push(0xB6);
        Ok(Blob::new(bytes.into()))
    }
}

fn require_mapping(target: &Fragment, expected: Id) -> Result<(), CollectionOperationError> {
    let actual = descriptor::mapping_algorithm(target.facts())
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(CollectionOperationError::Fatal(format!(
            "mapping algorithm {actual:?} does not match {expected:X}"
        )))
    }
}

fn collections() -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<FirstEncoding>,
    Collection<SecondEncoding>,
) {
    let mut store = MemoryRepo::default();
    let root = store.collection("root", policy()).unwrap();
    let first = store.derive::<FirstEncoding>(root, (), policy()).unwrap();
    let second = store.derive::<SecondEncoding>(first, (), policy()).unwrap();
    (store, root, first, second)
}

fn records(store: &mut MemoryRepo) -> Vec<CollectionRecord> {
    store
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteEvent {
    Put(CollectionData),
    Insert(CollectionRecord),
}

#[derive(Debug)]
enum GuardStoreError {
    Injected(&'static str),
    Backend(String),
}

impl fmt::Display for GuardStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Injected(operation) => write!(formatter, "injected {operation} failure"),
            Self::Backend(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for GuardStoreError {}

struct GuardSnapshot {
    inner: MemoryRepoSnapshot,
    live: Arc<AtomicUsize>,
    semantic_probes: Arc<AtomicUsize>,
    selected_collections: Arc<Mutex<Vec<BTreeSet<CollectionRecordSelector>>>>,
}

impl Clone for GuardSnapshot {
    fn clone(&self) -> Self {
        self.live.fetch_add(1, Ordering::SeqCst);
        Self {
            inner: self.inner.clone(),
            live: Arc::clone(&self.live),
            semantic_probes: Arc::clone(&self.semantic_probes),
            selected_collections: Arc::clone(&self.selected_collections),
        }
    }
}

impl Drop for GuardSnapshot {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl StoreSnapshot for GuardSnapshot {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }
}

impl WantRead for GuardSnapshot {
    type WantsError = <MemoryRepoSnapshot as WantRead>::WantsError;
    type WantIter<'a> = <MemoryRepoSnapshot as WantRead>::WantIter<'a>;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

impl BlobStoreMeta for GuardSnapshot {
    type MetaError = <MemoryRepoSnapshot as BlobStoreMeta>::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.metadata(handle)
    }
}

impl BlobStoreGet for GuardSnapshot {
    type GetError<E: Error + Send + Sync + 'static> =
        <MemoryRepoSnapshot as BlobStoreGet>::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.inner.get(handle)
    }
}

impl BlobStoreList for GuardSnapshot {
    type Iter<'a>
        = <MemoryRepoSnapshot as BlobStoreList>::Iter<'a>
    where
        Self: 'a;
    type Err = <MemoryRepoSnapshot as BlobStoreList>::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.inner.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, previous: &Self) -> Self::Iter<'a> {
        self.inner.blobs_diff(&previous.inner)
    }
}

impl crate::collection::CoverageRead for GuardSnapshot {
    fn index(
        &self,
        lineage: &BTreeSet<crate::collection::CollectionHandle>,
    ) -> Result<crate::collection::coverage::CoverageIndex, Self::RecordsError> {
        self.inner.index(lineage)
    }
}

impl CollectionRead for GuardSnapshot {
    type RecordsError = <MemoryRepoSnapshot as CollectionRead>::RecordsError;
    type RecordIter<'a>
        = <MemoryRepoSnapshot as CollectionRead>::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.inner.records()
    }

    fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
        self.inner.collections()
    }

    fn select_records(
        &self,
        selectors: &std::collections::BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        // A semantic PROBE is a lineage resolution, which selects by
        // collection. Retention expansion also selects, by produced member,
        // but that is one indexed lookup inside a probe rather than another
        // probe -- it used to be a full enumeration and counted as neither.
        // Counting both together would call an implementation detail a
        // re-resolution.
        if selectors
            .iter()
            .any(|selector| matches!(selector, CollectionRecordSelector::Collection(_)))
        {
            self.semantic_probes.fetch_add(1, Ordering::SeqCst);
        }
        self.selected_collections
            .lock()
            .unwrap()
            .push(selectors.clone());
        self.inner.select_records(selectors)
    }
}

impl CapabilityProofRead for GuardSnapshot {
    type ProofsError = <MemoryRepoSnapshot as CapabilityProofRead>::ProofsError;
    type ProofIter<'a>
        = <MemoryRepoSnapshot as CapabilityProofRead>::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.inner.proof(id)
    }
}

struct GuardStore {
    inner: MemoryRepo,
    live: Arc<AtomicUsize>,
    semantic_probes: Arc<AtomicUsize>,
    selected_collections: Arc<Mutex<Vec<BTreeSet<CollectionRecordSelector>>>>,
    events: Vec<WriteEvent>,
    put_calls: usize,
    insert_calls: usize,
    reject_put_at: Option<usize>,
    reject_insert_at: Option<usize>,
    acquirable: BTreeMap<CollectionData, Bytes>,
    acquired: Vec<CollectionData>,
    inject_record_on_acquire: Option<CollectionRecord>,
    inject_proof_on_acquire: Option<CapabilityProof>,
}

impl GuardStore {
    fn new(inner: MemoryRepo) -> Self {
        Self {
            inner,
            live: Arc::new(AtomicUsize::new(0)),
            semantic_probes: Arc::new(AtomicUsize::new(0)),
            selected_collections: Arc::new(Mutex::new(Vec::new())),
            events: Vec::new(),
            put_calls: 0,
            insert_calls: 0,
            reject_put_at: None,
            reject_insert_at: None,
            acquirable: BTreeMap::new(),
            acquired: Vec::new(),
            inject_record_on_acquire: None,
            inject_proof_on_acquire: None,
        }
    }

    fn offer<E: BlobEncoding>(&mut self, blob: &Blob<E>)
    where
        Handle<E>: InlineEncoding,
    {
        self.acquirable.insert(data(blob), blob.bytes.clone());
    }

    /// A publishing operation holds exactly its frozen control snapshot.
    fn assert_only_control_snapshot(&self) {
        assert_eq!(
            self.live.load(Ordering::SeqCst),
            1,
            "unexpected number of live snapshots while publishing",
        );
    }

    /// Acquisition ends the operation: nothing observes the store while bytes
    /// are fetched, so the retry's fresh snapshot sees everything that landed.
    fn assert_no_snapshot_while_acquiring(&self) {
        assert_eq!(
            self.live.load(Ordering::SeqCst),
            0,
            "a snapshot was held across an acquisition",
        );
    }
}

impl AsyncBlobStoreAcquire for GuardStore {
    type AcquireError = GuardStoreError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        self.assert_no_snapshot_while_acquiring();
        let member = Handle::<UnknownBlob>::to_hash(handle);
        self.acquired.push(member);
        let result = match self.acquirable.get(&member).cloned() {
            Some(bytes) => self
                .inner
                .put::<UnknownBlob, _>(bytes.clone())
                .map_err(|error| GuardStoreError::Backend(error.to_string()))
                .map(|_| Some(bytes)),
            None => Ok(None),
        };
        let result = result.and_then(|bytes| {
            if let Some(record) = self.inject_record_on_acquire.take() {
                self.inner
                    .insert(record)
                    .map_err(|error| GuardStoreError::Backend(error.to_string()))?;
            }
            if let Some(proof) = self.inject_proof_on_acquire.take() {
                self.inner
                    .insert_proof(proof)
                    .map_err(|error| GuardStoreError::Backend(error.to_string()))?;
            }
            Ok(bytes)
        });
        std::future::ready(result)
    }
}

impl BlobStorePut for GuardStore {
    type PutError = GuardStoreError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.assert_only_control_snapshot();
        let blob = item.to_blob();
        self.put_calls += 1;
        self.events
            .push(WriteEvent::Put(Handle::<S>::to_hash(blob.get_handle())));
        if self.reject_put_at == Some(self.put_calls) {
            return Err(GuardStoreError::Injected("put"));
        }
        self.inner
            .put::<S, _>(blob)
            .map_err(|error| GuardStoreError::Backend(error.to_string()))
    }
}

impl SnapshotSource for GuardStore {
    type Snapshot = GuardSnapshot;
    type SnapshotError = <MemoryRepo as SnapshotSource>::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        let inner = self.inner.snapshot()?;
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(GuardSnapshot {
            inner,
            live: Arc::clone(&self.live),
            semantic_probes: Arc::clone(&self.semantic_probes),
            selected_collections: Arc::clone(&self.selected_collections),
        })
    }
}

impl CollectionStore for GuardStore {
    type InsertError = GuardStoreError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.assert_only_control_snapshot();
        self.insert_calls += 1;
        self.events.push(WriteEvent::Insert(record));
        if self.reject_insert_at == Some(self.insert_calls) {
            return Err(GuardStoreError::Injected("collection insert"));
        }
        self.inner
            .insert(record)
            .map_err(|error| GuardStoreError::Backend(error.to_string()))
    }
}

impl CapabilityProofStore for GuardStore {
    type InsertError = GuardStoreError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.assert_only_control_snapshot();
        self.inner
            .insert_proof(proof)
            .map_err(|error| GuardStoreError::Backend(error.to_string()))
    }
}

#[test]
fn foundation_walks_the_complete_descriptor_ancestry() {
    let (mut store, root, _first, second) = collections();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(foundation(&snapshot, second).unwrap(), root);
}

#[test]
fn downstream_ensure_stands_on_nothing_without_an_immediate_source_realization() {
    let (mut store, root, first, second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);

    // The target stands for what its immediate source's frontier stands on.
    // An unrealized source stands on nothing, so nothing is owed, nothing is
    // an error, and nothing upstream is ever constructed.
    ensure_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();
    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.collection(second).unwrap();
    assert!(observed.support().unwrap().is_empty());
    assert!(observed.cover().is_empty());
    drop(observed);
    drop(snapshot);
    assert!(!records(&mut store).iter().any(|record| matches!(
        record,
        CollectionRecord::Derive(derive)
            if derive.collection() == first.handle() || derive.collection() == second.handle()
    )));
}

#[test]
fn two_hops_reuse_one_invariant_foundational_support() {
    let (mut store, root, first, second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));

    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    ensure_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();
    let snapshot = store.snapshot().unwrap();
    let attached = snapshot.collection(second).unwrap();
    let (observed_support, cover) = (
        crate::collection::test_support::stood_for(&attached),
        attached.cover().clone(),
    );

    assert_eq!(observed_support, support);
    assert_eq!(cover.len(), 1);
    let output: Blob<SecondEncoding> = snapshot.get(cover.members().next().unwrap()).unwrap();
    assert_eq!(output.bytes.as_ref().last(), Some(&0xB6));

    let second_derive = records(&mut store)
        .into_iter()
        .find_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.collection() == second.handle() => {
                Some(derive)
            }
            _ => None,
        })
        .unwrap();
    assert_ne!(
        second_derive.input(),
        crate::collection::SourceLocator::of(data(&source).raw)
    );
}

#[test]
fn ordinary_attachment_reports_only_support_realized_in_its_snapshot() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    // The maintaining key wrote the commit, so the leaf is its to derive.
    publish_root(&mut store, root, &left, 31);
    let left_support = support(root, std::slice::from_ref(&left));
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    // The source grows after the target was realized: an attachment reports
    // what the target stands on in its snapshot, not what the source admits.
    publish_root(&mut store, root, &right, 31);

    let snapshot = store.snapshot().unwrap();
    let observed = super::super::observation::attach(&snapshot, first).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&observed),
        left_support
    );
    assert_eq!(observed.cover().len(), 1);
    // The gap is the view's freshness, asked of its source explicitly.
    let source = snapshot.collection(root).unwrap();
    assert_eq!(
        observed.missing_from(&source).unwrap(),
        support(root, std::slice::from_ref(&right))
    );
}

#[test]
fn duplicate_commit_fibers_collapse_to_one_support_member() {
    let (mut store, root, _first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 1);
    publish_root(&mut store, root, &source, 2);

    let snapshot = store.snapshot().unwrap();
    let admitted = root.admitted(&snapshot).unwrap();
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted.members().next(), Some(source.get_handle()));
    assert_eq!(
        snapshot
            .select_records(&BTreeSet::from([CollectionRecordSelector::CommitMember(
                root.handle(),
                data(&source),
            )]))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn ensure_drops_every_residency_snapshot_and_stores_the_blob_before_derive() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut inner, root, &source, 31);
    let mut store = GuardStore::new(inner);

    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();

    assert_eq!(store.live.load(Ordering::SeqCst), 0);
    let (insert_position, derive) = store
        .events
        .iter()
        .enumerate()
        .find_map(|(position, event)| match event {
            WriteEvent::Insert(CollectionRecord::Derive(derive)) => Some((position, *derive)),
            _ => None,
        })
        .expect("ensure must publish one DERIVE");
    derive.verify_strict().unwrap();
    assert_eq!(
        derive.public_key().raw,
        equation_signer().verifying_key().to_bytes()
    );
    let put_position = store
        .events
        .iter()
        .position(|event| matches!(event, WriteEvent::Put(data) if *data == derive.output()))
        .expect("ensure must store its target member");
    assert!(put_position < insert_position);
}

#[test]
fn derived_ensure_acquires_only_its_maintainers_own_cold_payload() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let metadata = inner
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    inner
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[42; 32]),
            root.handle(),
            data(&source),
            metadata,
        )))
        .unwrap();
    let mut store = GuardStore::new(inner);
    store.offer(&source);
    let concurrent = archive(9, 9);
    store
        .inner
        .put::<SimpleArchive, _>(concurrent.clone())
        .unwrap();
    store.inject_record_on_acquire = Some(CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[43; 32]),
        root.handle(),
        data(&concurrent),
        metadata,
    )));

    // Neither commit is the maintaining key's: a view derives what its
    // maintainer wrote, so this ensure owes nothing and reads nobody else's
    // payload, cold or not.
    let snapshot = block_on(store.ensure(first, &equation_signer())).unwrap();

    assert!(store.acquired.is_empty());
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    let observed = snapshot.collection(first).unwrap();
    assert!(observed.support().unwrap().is_empty());
    assert!(observed.cover().is_empty());
    drop(observed);
    drop(snapshot);

    // The cold commit's writer owes its leaf, and fetches its own payload
    // to map it -- that one blob and nothing else. The commit that lands
    // while it fetches is somebody else's, so not its to derive.
    drop(block_on(store.ensure(first, &SigningKey::from_bytes(&[42; 32]))).unwrap());
    assert_eq!(store.acquired, vec![data(&source)]);
    assert!(store.inject_record_on_acquire.is_none());
    let leaves: Vec<_> = records(&mut store.inner)
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.collection() == first.handle() => {
                Some(derive.input())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        leaves,
        vec![crate::collection::SourceLocator::of(data(&source).raw)]
    );

    // Its writer derives the concurrent one, and fetches nothing.
    let snapshot = block_on(store.ensure(first, &SigningKey::from_bytes(&[43; 32]))).unwrap();
    assert_eq!(store.acquired, vec![data(&source)]);
    let observed = snapshot.collection(first).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&observed),
        support(root, &[source, concurrent])
    );
    assert_eq!(observed.cover().len(), 2);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
}

#[test]
fn exact_maintenance_fetches_a_known_derive_output_without_recomputing() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let _source_commit = publish_root(&mut inner, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));
    let output = FirstEncoding::map(&(), &source, &inner.snapshot().unwrap()).unwrap();
    let output_data = data(&output);
    let pending = CollectionRecord::Derive(CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        crate::collection::SourceLocator::of(data(&source).raw),
        output_data,
    ));
    inner.insert(pending).unwrap();

    let mut store = GuardStore::new(inner);
    store.offer(&output);
    reset_mapping_calls();
    // The per-write ensure owes nothing here: the leaf exists, and fetching
    // its absent image back is maintenance's work, never the write path's.
    drop(block_on(store.ensure(first, &equation_signer())).unwrap());
    assert!(store.acquired.is_empty());
    assert!(store.events.is_empty());
    let snapshot = block_on(store.maintain(first, &equation_signer())).unwrap();

    assert_eq!(store.acquired, vec![output_data]);
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert!(
        store.events.is_empty(),
        "acquisition must not publish algebra"
    );
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    let observed = snapshot.collection(first).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&observed),
        support
    );
    assert_eq!(
        observed.cover().data_members().collect::<Vec<_>>(),
        vec![output_data],
    );
}

#[test]
fn ensure_reuses_a_resident_image_without_mapping() {
    let (mut inner, root, first, _second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let _a_commit = publish_root(&mut inner, root, &a, 31);
    let _b_commit = publish_root(&mut inner, root, &b, 31);
    // The same payload b has two genuine witnesses: its own COMMIT [B], and
    // join(a, b) = b [A, B]. No mapping result is invented for this fixture.
    assert_eq!(
        data(&crate::collection::simplearchive_union::join(&a, &b).unwrap()),
        data(&b),
    );
    let ab = CollectionMerge::sign(&signer, root.handle(), [data(&a), data(&b)], data(&b)).unwrap();
    inner.insert(CollectionRecord::Merge(ab)).unwrap();
    let output = FirstEncoding::map(&(), &b, &inner.snapshot().unwrap()).unwrap();
    inner.put::<FirstEncoding, _>(output.clone()).unwrap();
    let previous = CollectionDerive::sign(
        &signer,
        first.handle(),
        crate::collection::SourceLocator::of(data(&b).raw),
        data(&output),
    );
    inner.insert(CollectionRecord::Derive(previous)).unwrap();
    // A leaf is the image of one foundation. b's image stands for b alone,
    // whatever the root's absorption MERGE(a, b) -> b says about b's node:
    // a is a foundation of its own, still owed its own leaf.
    let before = inner.snapshot().unwrap();
    let view = before.collection(first).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&view),
        support(root, std::slice::from_ref(&b)),
    );
    assert_eq!(
        view.missing_from(&before.collection(root).unwrap())
            .unwrap(),
        support(root, std::slice::from_ref(&a)),
    );
    drop(view);
    drop(before);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let after = block_on(store.ensure(first, &signer)).unwrap();

    // Only a is mapped; b's resident image is reused as it stands.
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    let a_image = first_image(&a);
    let selected = after.collection(first).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&selected),
        support(root, &[a.clone(), b.clone()])
    );
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(&output), a_image]),
    );
    let published: Vec<_> = store
        .events
        .iter()
        .filter_map(|event| match event {
            WriteEvent::Insert(record) => Some(*record),
            WriteEvent::Put(_) => None,
        })
        .collect();
    assert_eq!(
        published,
        vec![CollectionRecord::Derive(CollectionDerive::sign(
            &signer,
            first.handle(),
            crate::collection::SourceLocator::of(data(&a).raw),
            a_image,
        ))],
        "only a's leaf is new",
    );
    assert!(after
        .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
            first.handle(),
            data(&output),
        )]))
        .unwrap()
        .contains(&CollectionRecord::Derive(previous)));
}

#[test]
fn passive_derived_snapshot_keeps_dangling_output_as_raw_evidence_only() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let _source_commit = publish_root(&mut inner, root, &source, 42);
    let support = support(root, std::slice::from_ref(&source));
    let output = FirstEncoding::map(&(), &source, &inner.snapshot().unwrap()).unwrap();
    let pending = CollectionRecord::Derive(CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        crate::collection::SourceLocator::of(data(&source).raw),
        data(&output),
    ));
    inner.insert(pending).unwrap();

    let mut store = GuardStore::new(inner);
    store.offer(&output);
    reset_mapping_calls();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(root.admitted(&snapshot).unwrap(), support);
    let observed = snapshot.collection(first).unwrap();
    assert!(observed.support().unwrap().is_empty());
    assert!(observed.cover().is_empty());
    let selectors = BTreeSet::from([CollectionRecordSelector::DeriveTarget(first.handle())]);
    assert_eq!(snapshot.select_records(&selectors).unwrap(), vec![pending]);
    assert!(store.acquired.is_empty());
    assert!(store.events.is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
}

#[test]
fn exact_maintenance_recovers_a_pending_derive_with_a_missing_output() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let _source_commit = publish_root(&mut inner, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));
    let snapshot = inner.snapshot().unwrap();
    let output = FirstEncoding::map(&(), &source, &snapshot).unwrap();
    drop(snapshot);
    let output_data = data(&output);
    let pending = CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        crate::collection::SourceLocator::of(data(&source).raw),
        output_data,
    );
    inner.insert(CollectionRecord::Derive(pending)).unwrap();
    drop(output);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let snapshot = block_on(store.maintain(first, &equation_signer())).unwrap();

    assert_eq!(store.acquired, vec![output_data]);
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
    assert!(snapshot
        .metadata(Handle::<FirstEncoding>::from_hash(output_data))
        .unwrap()
        .is_some());
    let attached = snapshot.collection(first).unwrap();
    let (observed, cover) = (
        crate::collection::test_support::stood_for(&attached),
        attached.cover().clone(),
    );
    assert_eq!(observed, support);
    assert_eq!(cover.data_members().collect::<Vec<_>>(), vec![output_data]);
    drop(snapshot);
    assert_eq!(
        records(&mut store.inner)
            .iter()
            .filter(|record| **record == CollectionRecord::Derive(pending))
            .count(),
        1,
        "deterministic recovery reuses the pending equation",
    );
}

#[test]
fn root_ensure_admits_authority_that_arrives_during_acquisition() {
    let authority = SigningKey::from_bytes(&[83; 32]);
    let first_writer = SigningKey::from_bytes(&[84; 32]);
    let concurrent_writer = SigningKey::from_bytes(&[85; 32]);
    let restricted = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let mut registry = MemoryRepo::default();
    let root = registry
        .collection("bounded-cold-write", restricted)
        .unwrap();
    let descriptor: Blob<SimpleArchive> = registry.snapshot().unwrap().get(root.handle()).unwrap();
    let resource = CapabilityResource::from(root.handle());
    let proof = |writer: &SigningKey| {
        CapabilityProof::new(
            resource,
            &authority,
            write_capability(),
            writer.verifying_key(),
        )
    };
    let first_source = archive(31, 31);
    let first_metadata = archive(32, 32);
    let concurrent_source = archive(33, 33);
    let concurrent_metadata = archive(34, 34);
    let mut inner = MemoryRepo::default();
    for definition in [
        crate::collection::policy::read_definition(),
        crate::collection::policy::write_definition(),
    ] {
        inner
            .put::<SimpleArchive, _>(definition.facts().clone())
            .unwrap();
    }
    inner.insert_proof(proof(&first_writer)).unwrap();
    for (writer, source, metadata) in [
        (&first_writer, &first_source, &first_metadata),
        (&concurrent_writer, &concurrent_source, &concurrent_metadata),
    ] {
        inner
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                writer,
                root.handle(),
                data(source),
                metadata.get_handle(),
            )))
            .unwrap();
    }
    let mut store = GuardStore::new(inner);
    for blob in [
        &descriptor,
        &first_source,
        &first_metadata,
        &concurrent_source,
        &concurrent_metadata,
    ] {
        store.offer(blob);
    }
    store.inject_proof_on_acquire = Some(proof(&concurrent_writer));

    let first_snapshot = block_on(store.ensure(root, &equation_signer())).unwrap();
    // Acquiring the descriptor ended the first look. The grant that landed
    // with it is ordinary evidence to the next one, so the concurrent commit
    // is admitted and its payload fetched within the same ensure.
    assert_eq!(store.acquired[0], data(&descriptor));
    assert_eq!(
        store.acquired[1..].iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(&first_source), data(&concurrent_source)]),
    );
    assert_eq!(
        first_snapshot.collection(root).unwrap().support().unwrap(),
        &support(root, &[first_source.clone(), concurrent_source.clone()]),
    );
    assert_eq!(first_snapshot.wants().unwrap().count(), 0);
    assert!(
        store.events.is_empty(),
        "root ensure must not author equations"
    );
    drop(first_snapshot);

    let second_snapshot = block_on(store.ensure(root, &equation_signer())).unwrap();
    assert_eq!(
        second_snapshot.collection(root).unwrap().support().unwrap(),
        &support(root, &[first_source, concurrent_source]),
    );
    assert_eq!(store.acquired.len(), 3, "nothing was left to acquire");
    assert_eq!(second_snapshot.wants().unwrap().count(), 0);
}

#[test]
fn root_ensure_acquires_shared_capability_definitions_once_without_wants() {
    let authority = SigningKey::from_bytes(&[86; 32]);
    let intermediate = SigningKey::from_bytes(&[87; 32]);
    let writer = SigningKey::from_bytes(&[88; 32]);
    let mut registry = MemoryRepo::default();
    let root = registry
        .collection(
            "cold-authority-definitions",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(authority.verifying_key()),
            ),
        )
        .unwrap();
    let descriptor: Blob<SimpleArchive> = registry.snapshot().unwrap().get(root.handle()).unwrap();
    let read: Blob<SimpleArchive> = crate::collection::policy::read_definition()
        .facts()
        .clone()
        .to_blob();
    let write: Blob<SimpleArchive> = crate::collection::policy::write_definition()
        .facts()
        .clone()
        .to_blob();
    let delegable: Blob<SimpleArchive> = crate::prelude::entity! {
        crate::capability::capability_action: crate::collection::ACTION_WRITE,
        crate::capability::capability_delegate_action: crate::collection::ACTION_WRITE,
    }
    .facts()
    .clone()
    .to_blob();
    let proof = CapabilityProof::new(
        CapabilityResource::from(root.handle()),
        &authority,
        delegable.get_handle(),
        intermediate.verifying_key(),
    )
    .delegate(&intermediate, write.get_handle(), writer.verifying_key())
    .unwrap();
    let source = archive(35, 35);
    let metadata = archive(36, 36);
    let mut inner = MemoryRepo::default();
    inner.put::<SimpleArchive, _>(descriptor).unwrap();
    inner.insert_proof(proof).unwrap();
    inner
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &writer,
            root.handle(),
            data(&source),
            metadata.get_handle(),
        )))
        .unwrap();
    assert!(inner
        .snapshot()
        .unwrap()
        .collection(root)
        .unwrap()
        .cover()
        .is_empty());
    let mut store = GuardStore::new(inner);
    for blob in [&read, &write, &delegable, &source, &metadata] {
        store.offer(blob);
    }

    let observed = block_on(store.ensure(root, &equation_signer())).unwrap();
    assert_eq!(
        observed.collection(root).unwrap().support().unwrap(),
        &support(root, &[source.clone()])
    );
    assert_eq!(observed.wants().unwrap().count(), 0);
    assert_eq!(store.acquired.len(), 4);
    assert_eq!(
        store.acquired.iter().copied().collect::<BTreeSet<_>>(),
        [&read, &write, &delegable, &source]
            .into_iter()
            .map(data)
            .collect(),
    );
    drop(observed);
    drop(block_on(store.ensure(root, &equation_signer())).unwrap());
    assert_eq!(store.acquired.len(), 4, "resident definitions are reused");
}

#[test]
fn root_ensure_reuses_a_signed_union_without_fetching_ancestor_bytes() {
    let (mut inner, root, _, _) = collections();
    let left = archive(46, 46);
    let right = archive(47, 47);
    let metadata = archive(48, 48);
    let a = CollectionRecord::Commit(CollectionCommit::sign(
        &equation_signer(),
        root.handle(),
        data(&left),
        metadata.get_handle(),
    ));
    let b = CollectionRecord::Commit(CollectionCommit::sign(
        &equation_signer(),
        root.handle(),
        data(&right),
        metadata.get_handle(),
    ));
    inner.insert(a).unwrap();
    inner.insert(b).unwrap();
    let joined = crate::collection::simplearchive_union::join(&left, &right).unwrap();
    inner.put::<SimpleArchive, _>(joined.clone()).unwrap();
    inner
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &equation_signer(),
                root.handle(),
                [data(&left), data(&right)],
                data(&joined),
            )
            .unwrap(),
        ))
        .unwrap();
    let mut store = GuardStore::new(inner);
    for blob in [&left, &right, &metadata] {
        store.offer(blob);
    }
    let snapshot = block_on(store.ensure(root, &equation_signer())).unwrap();
    let attached = snapshot.collection(root).unwrap();
    assert_eq!(
        attached.support().unwrap(),
        &support(root, &[left.clone(), right.clone()])
    );
    assert_eq!(
        attached.cover().members().collect::<Vec<_>>(),
        vec![joined.get_handle()]
    );
    assert_eq!(attached.view::<TribleSet>().unwrap().len(), 2);
    for blob in [&left, &right, &metadata] {
        assert!(!snapshot.contains_blob(blob.get_handle()).unwrap());
    }
    assert!(store.acquired.is_empty());
    assert!(store.events.is_empty());
    assert_eq!(snapshot.wants().unwrap().count(), 0);
}

#[test]
fn root_maintenance_only_merges_and_warm_ensure_is_write_free() {
    let (mut inner, root, _, _) = collections();
    // One tier's worth of the maintaining key's own commits: the root carry
    // joins them into one MERGE.
    for member in 0..crate::collection::MERGE_FAN_IN as u8 {
        publish_root(&mut inner, root, &archive(36 + member, 36 + member), 31);
    }
    let mut store = GuardStore::new(inner);

    let maintained = block_on(store.maintain(root, &equation_signer())).unwrap();
    assert_eq!(maintained.collection(root).unwrap().cover().len(), 1);
    assert!(store
        .events
        .iter()
        .any(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Merge(_)))));
    assert!(store.events.iter().all(|event| !matches!(
        event,
        WriteEvent::Insert(CollectionRecord::Derive(_) | CollectionRecord::Commit(_))
    )));
    drop(maintained);
    store.events.clear();
    let ensured = block_on(store.ensure(root, &equation_signer())).unwrap();
    assert_eq!(
        ensured
            .collection(root)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .len(),
        crate::collection::MERGE_FAN_IN
    );
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
}

#[test]
fn active_read_audience_acquires_a_cold_descriptor() {
    let authority = SigningKey::from_bytes(&[70; 32]);
    let reader = SigningKey::from_bytes(&[71; 32]);
    let mut registry = MemoryRepo::default();
    let collection = registry
        .collection(
            "cold-restricted-read",
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let descriptor: Blob<SimpleArchive> = registry
        .snapshot()
        .unwrap()
        .get(collection.handle())
        .unwrap();

    let proof = CapabilityProof::new(
        CapabilityResource::from(collection.handle()),
        &authority,
        read_capability(),
        reader.verifying_key(),
    );
    let mut inner = MemoryRepo::default();
    inner.insert_proof(proof).unwrap();
    for definition in [
        crate::collection::policy::read_definition(),
        crate::collection::policy::write_definition(),
    ] {
        inner
            .put::<SimpleArchive, _>(definition.facts().clone())
            .unwrap();
    }

    let mut store = GuardStore::new(inner);
    store.offer(&descriptor);

    let snapshot = block_on(store.ensure(collection, &equation_signer())).unwrap();
    let audience = collection_read_audience(&snapshot, collection.handle()).unwrap();

    assert_eq!(store.acquired, vec![data(&descriptor)]);
    let mut expected_audience = vec![authority.verifying_key(), reader.verifying_key()];
    expected_audience.sort_unstable_by_key(VerifyingKey::to_bytes);
    assert_eq!(
        audience,
        CollectionReadAudience::Restricted(expected_audience)
    );
    assert_eq!(store.inner.snapshot().unwrap().wants().unwrap().count(), 0);
}

#[test]
fn active_read_audience_ignores_irrelevant_or_forged_proofs() {
    let authority = SigningKey::from_bytes(&[63; 32]);
    let irrelevant_authority = SigningKey::from_bytes(&[64; 32]);
    let irrelevant_reader = SigningKey::from_bytes(&[65; 32]);
    let forged_reader = SigningKey::from_bytes(&[66; 32]);
    let mut inner = MemoryRepo::default();
    let collection = inner
        .collection(
            "filtered-read-evidence",
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let resource = CapabilityResource::from(collection.handle());
    let irrelevant_proof = CapabilityProof::new(
        resource,
        &irrelevant_authority,
        read_capability(),
        irrelevant_reader.verifying_key(),
    );
    inner.insert_proof(irrelevant_proof).unwrap();

    let forged_proof = CapabilityProof::new(
        resource,
        &authority,
        read_capability(),
        forged_reader.verifying_key(),
    );
    let mut forged_bytes = forged_proof.into_bytes();
    *forged_bytes.last_mut().unwrap() ^= 1;
    assert!(inner
        .insert_proof(CapabilityProof::from_bytes(&forged_bytes).unwrap())
        .is_err());

    let mut store = GuardStore::new(inner);

    let snapshot = block_on(store.ensure(collection, &equation_signer())).unwrap();
    let audience = collection_read_audience(&snapshot, collection.handle()).unwrap();

    assert!(store.acquired.is_empty());
    assert_eq!(
        audience,
        CollectionReadAudience::Restricted(vec![authority.verifying_key()])
    );
    assert_eq!(store.inner.snapshot().unwrap().wants().unwrap().count(), 0);
}

#[test]
fn active_read_audience_walks_a_valid_delegated_proof_path() {
    let authority = SigningKey::from_bytes(&[75; 32]);
    let intermediate = SigningKey::from_bytes(&[76; 32]);
    let reader = SigningKey::from_bytes(&[77; 32]);
    let mut inner = MemoryRepo::default();
    let collection = inner
        .collection(
            "delegated-read",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(authority.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let resource = CapabilityResource::from(collection.handle());
    let grant = crate::prelude::entity! {
        crate::capability::capability_action: crate::collection::ACTION_READ,
        crate::capability::capability_delegate_action: crate::collection::ACTION_READ,
    };
    let delegable = inner
        .put::<SimpleArchive, _>(grant.facts().clone())
        .unwrap();
    let proof = CapabilityProof::new(
        resource,
        &authority,
        delegable,
        intermediate.verifying_key(),
    )
    .delegate(&intermediate, read_capability(), reader.verifying_key())
    .unwrap();
    inner.insert_proof(proof).unwrap();

    let mut store = GuardStore::new(inner);

    let snapshot = block_on(store.ensure(collection, &equation_signer())).unwrap();
    let audience = collection_read_audience(&snapshot, collection.handle()).unwrap();

    assert!(store.acquired.is_empty());
    let mut expected_audience = vec![
        authority.verifying_key(),
        intermediate.verifying_key(),
        reader.verifying_key(),
    ];
    expected_audience.sort_unstable_by_key(VerifyingKey::to_bytes);
    assert_eq!(
        audience,
        CollectionReadAudience::Restricted(expected_audience)
    );
    assert_eq!(store.inner.snapshot().unwrap().wants().unwrap().count(), 0);
}

#[test]
fn active_read_audience_stops_before_a_signed_but_semantically_impossible_tail() {
    let authority = SigningKey::from_bytes(&[72; 32]);
    let direct_reader = SigningKey::from_bytes(&[73; 32]);
    let tail_reader = SigningKey::from_bytes(&[74; 32]);
    let mut inner = MemoryRepo::default();
    let collection = inner
        .collection(
            "invoke-only-read",
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let resource = CapabilityResource::from(collection.handle());
    let action = read_capability();
    let root_proof =
        CapabilityProof::new(resource, &authority, action, direct_reader.verifying_key());
    let proof = append_adversarial_proof_edge(
        root_proof,
        &direct_reader,
        action,
        tail_reader.verifying_key(),
    );
    proof.verify_signatures().unwrap();
    inner.insert_proof(proof).unwrap();

    let mut store = GuardStore::new(inner);

    let snapshot = block_on(store.ensure(collection, &equation_signer())).unwrap();
    let audience = collection_read_audience(&snapshot, collection.handle()).unwrap();

    assert!(store.acquired.is_empty());
    assert_eq!(
        audience,
        CollectionReadAudience::Restricted({
            let mut subjects = vec![authority.verifying_key(), direct_reader.verifying_key()];
            subjects.sort_unstable_by_key(VerifyingKey::to_bytes);
            subjects
        })
    );
    assert_eq!(store.inner.snapshot().unwrap().wants().unwrap().count(), 0);
}

#[test]
fn snapshot_read_audience_defers_later_proofs_after_descriptor_acquisition() {
    let authority = SigningKey::from_bytes(&[67; 32]);
    let first_reader = SigningKey::from_bytes(&[68; 32]);
    let later_reader = SigningKey::from_bytes(&[69; 32]);
    let mut registry = MemoryRepo::default();
    let collection = registry
        .collection(
            "frozen-read-evidence",
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let descriptor: Blob<SimpleArchive> = registry
        .snapshot()
        .unwrap()
        .get(collection.handle())
        .unwrap();
    let resource = CapabilityResource::from(collection.handle());
    let mut inner = MemoryRepo::default();
    for definition in [
        crate::collection::policy::read_definition(),
        crate::collection::policy::write_definition(),
    ] {
        inner
            .put::<SimpleArchive, _>(definition.facts().clone())
            .unwrap();
    }
    inner
        .insert_proof(CapabilityProof::new(
            resource,
            &authority,
            read_capability(),
            first_reader.verifying_key(),
        ))
        .unwrap();
    let mut store = GuardStore::new(inner);
    store.offer(&descriptor);

    let before = block_on(store.ensure(collection, &equation_signer())).unwrap();
    let first_audience = collection_read_audience(&before, collection.handle()).unwrap();
    let mut expected = vec![authority.verifying_key(), first_reader.verifying_key()];
    expected.sort_unstable_by_key(VerifyingKey::to_bytes);
    assert_eq!(
        first_audience,
        CollectionReadAudience::Restricted(expected.clone())
    );
    assert_eq!(store.acquired, vec![data(&descriptor)]);

    store
        .inner
        .insert_proof(CapabilityProof::new(
            resource,
            &authority,
            read_capability(),
            later_reader.verifying_key(),
        ))
        .unwrap();
    assert_eq!(
        collection_read_audience(&before, collection.handle()).unwrap(),
        first_audience
    );
    let later = store.snapshot().unwrap();
    expected.push(later_reader.verifying_key());
    expected.sort_unstable_by_key(VerifyingKey::to_bytes);
    assert_eq!(
        collection_read_audience(&later, collection.handle()).unwrap(),
        CollectionReadAudience::Restricted(expected)
    );
    assert_eq!(later.wants().unwrap().count(), 0);
    assert_eq!(
        store.acquired,
        vec![data(&descriptor)],
        "snapshot reads never acquire blobs"
    );
}

/// `members` commits of the maintaining key, carried in the root, derived and
/// mirrored in the first view, and derived as leaves in the second: all a
/// maintenance of the second view has left to do is mirror the first's
/// merges.
fn carried_chain(
    store: &mut MemoryRepo,
    root: Collection<SimpleArchive>,
    first: Collection<FirstEncoding>,
    second: Collection<SecondEncoding>,
    members: u8,
) {
    for member in 1..=members {
        publish_root(store, root, &archive(member, member), 31);
    }
    drop(block_on(store.maintain(root, &equation_signer())).unwrap());
    maintain_resident::<_, FirstEncoding>(store, first, &equation_signer()).unwrap();
    ensure_resident::<_, SecondEncoding>(store, second, &equation_signer()).unwrap();
}

#[test]
fn maintenance_drops_every_residency_snapshot_and_stores_the_blob_before_merge() {
    let (mut inner, root, first, second) = collections();
    carried_chain(
        &mut inner,
        root,
        first,
        second,
        crate::collection::MERGE_FAN_IN as u8,
    );
    let mut store = GuardStore::new(inner);

    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();

    assert_eq!(store.live.load(Ordering::SeqCst), 0);
    let (insert_position, merge) = store
        .events
        .iter()
        .enumerate()
        .find_map(|(position, event)| match event {
            WriteEvent::Insert(CollectionRecord::Merge(merge)) => Some((position, *merge)),
            _ => None,
        })
        .expect("maintenance must publish one MERGE");
    merge.verify_strict().unwrap();
    assert_eq!(
        merge.public_key().raw,
        equation_signer().verifying_key().to_bytes()
    );
    let put_position = store
        .events
        .iter()
        .position(|event| matches!(event, WriteEvent::Put(data) if *data == merge.result()))
        .expect("maintenance must store its joined target member");
    assert!(put_position < insert_position);
}

#[test]
fn target_maintenance_never_enumerates_records() {
    let (mut inner, root, first, second) = collections();
    carried_chain(
        &mut inner,
        root,
        first,
        second,
        crate::collection::MERGE_FAN_IN as u8,
    );

    let mut store = GuardStore::new(inner);
    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();

    let merges = store
        .events
        .iter()
        .filter(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Merge(_))))
        .count();
    assert_eq!(merges, 1, "the first view's one merge, mirrored");
    assert_eq!(
        store.semantic_probes.load(Ordering::SeqCst),
        0,
        "every round reads the frontier from the index; no record is enumerated",
    );

    let snapshot = store.inner.snapshot().unwrap();
    let attached = snapshot.collection(second).unwrap();
    let (_, cover) = (
        attached.support().unwrap().clone(),
        attached.cover().clone(),
    );
    assert_eq!(cover.len(), 1);
}

#[test]
fn failed_target_batch_preserves_every_published_prefix_carry() {
    for fail_insert in [false, true] {
        let (mut inner, root, first, second) = collections();
        // Two groups of eight: the root carries two MERGEs, so maintaining
        // the second view mirrors two, one blob and one MERGE each, and the
        // second write of either kind fails.
        carried_chain(
            &mut inner,
            root,
            first,
            second,
            2 * crate::collection::MERGE_FAN_IN as u8,
        );

        let mut store = GuardStore::new(inner);
        if fail_insert {
            store.reject_insert_at = Some(2);
        } else {
            store.reject_put_at = Some(2);
        }

        assert!(matches!(
            maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()),
            Err(CollectionRealizationError::Storage { .. })
        ));
        assert_eq!(store.live.load(Ordering::SeqCst), 0);
        let merges = records(&mut store.inner)
            .into_iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Merge(merge) if merge.collection() == second.handle())
            })
            .count();
        assert_eq!(merges, 1, "the first mirror remains visible");
    }
}

#[test]
fn later_put_or_insert_failure_preserves_the_published_prefix() {
    for fail_insert in [false, true] {
        let (mut inner, root, first, _second) = collections();
        let left = archive(1, 1);
        let right = archive(2, 2);
        for blob in [&left, &right] {
            publish_root(&mut inner, root, blob, 31);
        }
        let mut store = GuardStore::new(inner);
        if fail_insert {
            store.reject_insert_at = Some(2);
        } else {
            store.reject_put_at = Some(2);
        }

        assert!(matches!(
            ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()),
            Err(CollectionRealizationError::Storage { .. })
        ));
        let derives = records(&mut store.inner)
            .into_iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Derive(derive) if derive.collection() == first.handle())
            })
            .count();
        assert_eq!(derives, 1, "the first successful mapping remains visible");
    }
}

#[test]
fn missing_mapping_dependency_publishes_nothing() {
    let (mut store, root, first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);
    let before = store.snapshot().unwrap();
    FIRST_MAP_MISSING.set(true);

    let result = ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer());
    FIRST_MAP_MISSING.set(false);

    assert!(matches!(
        result,
        Err(CollectionRealizationError::MissingDependency { .. })
    ));
    assert!(store.snapshot().unwrap().changes_since(&before).is_empty());
}

#[test]
fn capacity_blocked_source_upper_falls_back_to_its_resident_children() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let joined = crate::collection::simplearchive_union::join(&left, &right).unwrap();
    store.put::<SimpleArchive, _>(joined.clone()).unwrap();
    let before = store.snapshot().unwrap();
    let left_witness = data(&left);
    let right_witness = data(&right);
    drop(before);
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &equation_signer(),
                root.handle(),
                [left_witness, right_witness],
                data(&joined),
            )
            .unwrap(),
        ))
        .unwrap();
    reset_mapping_calls();
    FIRST_MAP_CAPACITY.replace(Some(data(&joined)));

    // The two leaves are mapped, then the mirror of the root's MERGE maps
    // the joined node from its own bytes, and the mapping declines it.
    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    FIRST_MAP_CAPACITY.replace(None);

    assert_eq!(FIRST_MAP_CALLS.get(), 3);
    let all = records(&mut store);
    let inputs: std::collections::BTreeSet<_> = all
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.collection() == first.handle() => {
                Some(derive.input())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        inputs,
        std::collections::BTreeSet::from([
            crate::collection::SourceLocator::of(data(&left).raw),
            crate::collection::SourceLocator::of(data(&right).raw),
        ])
    );
    // Nothing is mirrored, so the view stands on the two leaves beneath.
    assert!(!all.iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge) if merge.collection() == first.handle()
    )));
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        snapshot
            .collection(first)
            .unwrap()
            .cover()
            .data_members()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([first_image(&left), first_image(&right)])
    );
}

#[test]
fn warm_exact_ensure_is_a_zero_write_zero_algebra_observation() {
    let (mut store, root, first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();

    reset_mapping_calls();
    let before = store.snapshot().unwrap();
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    let after = store.snapshot().unwrap();
    assert!(after.changes_since(&before).is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
}

/// Produce a genuine first-hop leaf, then replicate only what exists at the
/// boundary before the target's own work: the writer's root proof and its
/// first-hop grant remain in the replica, but the grant's definition and the
/// root payload do not, so the first-hop leaf is not admitted -- and the
/// source has no rows -- until the definition arrives.
///
/// One key writes every hop, because a view derives what its maintainer
/// wrote: the target's leaf is owed by whoever owns the first-hop leaf,
/// which is whoever wrote the root commit beneath it.
fn cold_source_authority_fixture() -> (
    GuardStore,
    Collection<SecondEncoding>,
    Support,
    Blob<SimpleArchive>,
) {
    let authority = SigningKey::from_bytes(&[90; 32]);
    let owner = equation_signer();
    let root_writer = owner.clone();
    let first_writer = owner.clone();
    let source_policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let mut staging = MemoryRepo::default();
    let root = staging
        .collection("warm-target-cold-source-authority", source_policy.clone())
        .unwrap();
    let first = staging
        .derive::<FirstEncoding>(root, (), source_policy)
        .unwrap();
    let target = staging
        .derive::<SecondEncoding>(
            first,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(owner.verifying_key()),
            ),
        )
        .unwrap();
    let definition: Blob<SimpleArchive> = crate::prelude::entity! {
        crate::capability::capability_action: crate::collection::ACTION_WRITE,
        crate::metadata::name: "warm-target-source-grant",
    }
    .facts()
    .clone()
    .to_blob();
    staging.put::<SimpleArchive, _>(definition.clone()).unwrap();
    let root_proof = CapabilityProof::new(
        CapabilityResource::from(root.handle()),
        &authority,
        write_capability(),
        root_writer.verifying_key(),
    );
    staging.insert_proof(root_proof.clone()).unwrap();
    let first_proof = CapabilityProof::new(
        CapabilityResource::from(first.handle()),
        &authority,
        definition.get_handle(),
        first_writer.verifying_key(),
    );
    staging.insert_proof(first_proof.clone()).unwrap();
    let source = archive(44, 44);
    let commit = publish_root(&mut staging, root, &source, 31);
    assert_eq!(
        commit.public_key().raw,
        root_writer.verifying_key().to_bytes()
    );
    let selected = support(root, std::slice::from_ref(&source));
    drop(block_on(staging.ensure(first, &first_writer)).unwrap());
    let realized = staging.snapshot().unwrap();
    let omitted = BTreeSet::from([
        commit.data(),
        Handle::<SimpleArchive>::to_hash(commit.metadata()),
        data(&definition),
    ]);
    let mut inner = MemoryRepo::default();
    for info in realized.blobs() {
        let info = info.unwrap();
        if !omitted.contains(&Handle::<UnknownBlob>::to_hash(info.handle)) {
            inner
                .put::<UnknownBlob, _>(realized.get::<Blob<UnknownBlob>, _>(info.handle).unwrap())
                .unwrap();
        }
    }
    for record in realized.records().unwrap() {
        inner.insert(record.unwrap()).unwrap();
    }
    inner.insert_proof(root_proof).unwrap();
    inner.insert_proof(first_proof).unwrap();
    let observed = inner.snapshot().unwrap();
    assert!(root
        .writer_is_admitted(&observed, root_writer.verifying_key())
        .unwrap());
    assert!(!first
        .writer_is_admitted(&observed, first_writer.verifying_key())
        .unwrap());
    assert!(observed
        .collection(first)
        .unwrap()
        .support()
        .unwrap()
        .is_empty());
    assert!(observed
        .collection(target)
        .unwrap()
        .support()
        .unwrap()
        .is_empty());
    assert!(!observed.contains_blob(source.get_handle()).unwrap());
    assert!(!observed.contains_blob(commit.metadata()).unwrap());
    assert!(!observed.contains_blob(definition.get_handle()).unwrap());
    (GuardStore::new(inner), target, selected, definition)
}

#[test]
fn new_work_still_requires_the_immediate_source_grant_definition() {
    for available_definition in [false, true] {
        let (mut store, target, selected, definition) = cold_source_authority_fixture();
        if available_definition {
            store.offer(&definition);
        }
        reset_mapping_calls();
        let result = block_on(store.ensure(target, &equation_signer()));
        assert_eq!(store.acquired, vec![data(&definition)]);
        assert_eq!(FIRST_MAP_CALLS.get(), 0, "never rebuild the source");
        if available_definition {
            let after = result.unwrap();
            assert_eq!(
                crate::collection::test_support::stood_for(&after.collection(target).unwrap()),
                selected
            );
            assert_eq!(SECOND_MAP_CALLS.get(), 1);
        } else {
            // Without the grant's definition the source producer is not
            // admitted, so the source has no rows: the target owes nothing,
            // reports nothing, and has nothing until the grant arrives.
            let after = result.unwrap();
            assert!(after
                .collection(target)
                .unwrap()
                .support()
                .unwrap()
                .is_empty());
            assert!(store.events.is_empty());
            assert_eq!(SECOND_MAP_CALLS.get(), 0);
        }
    }
}

#[test]
fn warm_reuse_keeps_representation_and_mapping_checks() {
    struct WrongSecondMapping;

    impl CollectionMapping for WrongSecondMapping {
        type Source = FirstEncoding;
        type Target = SecondEncoding;

        fn fragment(&self) -> Fragment {
            FirstEncoding::fragment(&())
        }

        fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
            require_mapping(target, FIRST_MAPPING)?;
            Ok(Self)
        }

        fn map<R>(
            &self,
            _source: &Blob<Self::Source>,
            _reader: &R,
        ) -> Result<Blob<Self::Target>, CollectionOperationError>
        where
            R: StoreRead,
        {
            panic!("a mismatched mapping must never execute")
        }
    }

    for maintain in [false, true] {
        let (mut inner, root, first, target) = collections();
        let source = archive(1, 1);
        publish_root(&mut inner, root, &source, 31);
        ensure_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer()).unwrap();
        ensure_resident::<_, SecondEncoding>(&mut inner, target, &equation_signer()).unwrap();
        let mut store = GuardStore::new(inner);
        reset_mapping_calls();

        let wrong_type = Collection::<FirstEncoding>::from_handle(target.handle());
        let wrong_representation = if maintain {
            block_on(store.maintain(wrong_type, &equation_signer()))
        } else {
            block_on(store.ensure(wrong_type, &equation_signer()))
        };
        assert!(matches!(
            wrong_representation,
            Err(CollectionRealizationError::Resolution(reason))
                if reason.contains("target descriptor has the wrong representation"),
        ));

        let wrong_mapping = if maintain {
            block_on(store.maintain_with::<WrongSecondMapping>(target, &equation_signer()))
        } else {
            block_on(store.ensure_with::<WrongSecondMapping>(target, &equation_signer()))
        };
        assert!(matches!(
            wrong_mapping,
            Err(CollectionRealizationError::Resolution(reason))
                if reason.contains("does not bind the requested mapping"),
        ));
        assert!(store.acquired.is_empty());
        assert!(store.events.is_empty());
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(SECOND_MAP_CALLS.get(), 0);
    }
}

#[test]
fn complete_realization_is_reused_without_write_authority() {
    let (mut inner, root, _first, _second) = collections();
    let owner = equation_signer();
    let reader = SigningKey::from_bytes(&[32; 32]);
    let target = inner
        .derive::<FirstEncoding>(
            root,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(owner.verifying_key()),
            ),
        )
        .unwrap();
    let source = archive(1, 1);
    // Both keys wrote the commit, so both own it; the owner, who may write
    // the view, derived its leaf. The reader owes nothing, and so needs no
    // WRITE to find its own work already done.
    publish_root(&mut inner, root, &source, 31);
    publish_root(&mut inner, root, &source, 32);
    block_on(inner.ensure(target, &owner)).unwrap();
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    for maintain in [false, true] {
        let snapshot = if maintain {
            block_on(store.maintain(target, &reader))
        } else {
            block_on(store.ensure(target, &reader))
        }
        .unwrap();
        assert_eq!(snapshot.collection(target).unwrap().cover().len(), 1);
        assert!(snapshot
            .collection(target)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
    }
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
}

#[test]
fn missing_realization_requires_write_before_computation_or_publication() {
    let (mut inner, root, _first, _second) = collections();
    let owner = equation_signer();
    let reader = SigningKey::from_bytes(&[32; 32]);
    let target = inner
        .derive::<FirstEncoding>(
            root,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(owner.verifying_key()),
            ),
        )
        .unwrap();
    let source = archive(1, 1);
    // The reader wrote this commit, so its leaf is the reader's to derive;
    // the target's WRITE admits only the owner.
    publish_root(&mut inner, root, &source, 32);
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    for maintain in [false, true] {
        let result = if maintain {
            block_on(store.maintain(target, &reader))
        } else {
            block_on(store.ensure(target, &reader))
        };
        assert!(matches!(result,
            Err(CollectionRealizationError::UnauthorizedProducer { collection })
                if collection == target.handle()
        ));
    }
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
}

#[test]
fn optional_maintenance_without_write_keeps_the_fine_cover_without_algebra() {
    let owner = equation_signer();
    let reader = SigningKey::from_bytes(&[32; 32]);
    let private_write = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let mut inner = MemoryRepo::default();
    let root = inner.collection("read-only-maintenance", policy()).unwrap();
    let first = inner
        .derive::<FirstEncoding>(root, (), private_write.clone())
        .unwrap();
    let second = inner
        .derive::<SecondEncoding>(first, (), private_write)
        .unwrap();
    let left = archive(1, 1);
    let right = archive(2, 2);
    // Both keys wrote both members, so both own them; only the owner may
    // write either view, and it derived the leaves.
    for member in [&left, &right] {
        publish_root(&mut inner, root, member, 31);
        publish_root(&mut inner, root, member, 32);
    }
    block_on(inner.ensure(first, &owner)).unwrap();
    block_on(inner.ensure(second, &owner)).unwrap();
    let upper = crate::collection::simplearchive_union::join(&left, &right).unwrap();
    inner.put::<SimpleArchive, _>(upper.clone()).unwrap();
    let root_merge = |key: &SigningKey| {
        CollectionRecord::Merge(
            CollectionMerge::sign(
                key,
                root.handle(),
                [data(&left), data(&right)],
                data(&upper),
            )
            .unwrap(),
        )
    };
    // The reader's own root MERGE is owed a mirror in `first`, which the
    // reader may not write.
    inner.insert(root_merge(&reader)).unwrap();
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    let snapshot = block_on(store.maintain(first, &reader)).unwrap();
    assert_eq!(snapshot.collection(first).unwrap().cover().len(), 2);
    drop(snapshot);
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(
        FIRST_MAP_CALLS.get(),
        0,
        "no image is computed for a mirror that cannot be published"
    );

    // The owner signs the same MERGE and pays for its image in `first`.
    // Then the reader gains WRITE on `first` and co-signs everything there,
    // so it owns `first`'s nodes too -- and still may not write `second`.
    store.inner.insert(root_merge(&owner)).unwrap();
    drop(block_on(store.maintain(first, &owner)).unwrap());
    store
        .inner
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(first.handle()),
            &owner,
            write_capability(),
            reader.verifying_key(),
        ))
        .unwrap();
    let mut mirrored = 0;
    for record in records(&mut store.inner) {
        let copy = match record {
            CollectionRecord::Derive(derive) if derive.collection() == first.handle() => {
                CollectionRecord::Derive(CollectionDerive::sign(
                    &reader,
                    first.handle(),
                    derive.input(),
                    derive.output(),
                ))
            }
            CollectionRecord::Merge(merge) if merge.collection() == first.handle() => {
                mirrored += 1;
                CollectionRecord::Merge(
                    CollectionMerge::sign(
                        &reader,
                        first.handle(),
                        merge.inputs().iter().copied(),
                        merge.result(),
                    )
                    .unwrap(),
                )
            }
            _ => continue,
        };
        store.inner.insert(copy).unwrap();
    }
    assert_eq!(
        mirrored, 1,
        "the owner mirrored its root MERGE into `first`"
    );
    store.events.clear();
    reset_mapping_calls();
    let snapshot = block_on(store.maintain(second, &reader)).unwrap();
    assert_eq!(snapshot.collection(second).unwrap().cover().len(), 2);
    drop(snapshot);
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);

    // WRITE is the only thing that held it back: the owner mirrors it.
    let snapshot = block_on(store.maintain(second, &owner)).unwrap();
    assert_eq!(snapshot.collection(second).unwrap().cover().len(), 1);
    assert_eq!(SECOND_MAP_CALLS.get(), 1);
}

#[test]
fn existing_target_support_is_not_mapped_again_when_support_grows() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    publish_root(&mut store, root, &left, 31);
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();

    reset_mapping_calls();
    publish_root(&mut store, root, &right, 31);
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
}

#[test]
fn a_source_upper_is_mirrored_from_its_own_bytes_without_a_join() {
    let (mut store, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();

    let snapshot = store.snapshot().unwrap();
    let attached = snapshot.collection(first).unwrap();
    let (_, first_cover) = (
        attached.support().unwrap().clone(),
        attached.cover().clone(),
    );
    let mut children = first_cover.members().map(|handle| {
        snapshot
            .get::<Blob<FirstEncoding>, FirstEncoding>(handle)
            .unwrap()
    });
    let low = children.next().unwrap();
    let high = children.next().unwrap();
    let low_witness = data(&low);
    let high_witness = data(&high);
    drop(snapshot);
    let upper = join_first(&low, &high).unwrap();
    store.put::<FirstEncoding, _>(upper.clone()).unwrap();
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &equation_signer(),
                first.handle(),
                [low_witness, high_witness],
                data(&upper),
            )
            .unwrap(),
        ))
        .unwrap();

    reset_mapping_calls();
    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();
    // Each leaf is mapped from its foundation, and the upper -- the first
    // view's own MERGE, not a foundation -- is mapped once from its own
    // bytes to mirror that MERGE. Nothing in the second view is joined.
    assert_eq!(SECOND_MAP_CALLS.get(), 3);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    let second_image = |blob: &Blob<FirstEncoding>| {
        let mut bytes = blob.bytes.as_ref().to_vec();
        bytes.push(0xB6);
        data(&Blob::<SecondEncoding>::new(bytes.into()))
    };
    let all = records(&mut store);
    let leaves: BTreeSet<_> = all
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.collection() == second.handle() => {
                Some(derive.input())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        leaves,
        BTreeSet::from([
            crate::collection::SourceLocator::of(low_witness.raw),
            crate::collection::SourceLocator::of(high_witness.raw),
        ]),
        "no leaf names the upper",
    );
    let mirrors: Vec<_> = all
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) if merge.collection() == second.handle() => Some(*merge),
            _ => None,
        })
        .collect();
    assert_eq!(mirrors.len(), 1);
    assert_eq!(
        mirrors[0].inputs().iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([second_image(&low), second_image(&high)])
    );
    assert_eq!(mirrors[0].result(), second_image(&upper));
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .collection(second)
            .unwrap()
            .cover()
            .data_members()
            .collect::<Vec<_>>(),
        vec![second_image(&upper)]
    );
}

#[test]
fn optional_target_dependency_keeps_the_finer_cover() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }

    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    let snapshot = store.snapshot().unwrap();
    let attached = snapshot.collection(first).unwrap();
    let (_, cover) = (
        attached.support().unwrap().clone(),
        attached.cover().clone(),
    );
    assert_eq!(cover.len(), 2);
    drop(snapshot);
    let first_result = store.snapshot().unwrap();
    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .changes_since(&first_result)
        .is_empty());
    assert!(!records(&mut store).iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge) if merge.collection() == root.handle()
    )));
}

#[test]
fn own_source_merges_are_mirrored_bottom_up_and_repeat_without_work() {
    let (mut inner, root, first, _second) = collections();
    let members = [archive(1, 1), archive(2, 2), archive(3, 3)];
    for member in &members {
        publish_root(&mut inner, root, member, 31);
    }
    ensure_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer()).unwrap();
    let mut store = GuardStore::new(inner);

    // Three leaves and no source merge: a derived collection has no carry
    // of its own, so there is nothing to mirror and nothing to fetch.
    reset_mapping_calls();
    block_on(store.maintain(first, &equation_signer())).unwrap();
    assert!(store.events.is_empty(), "no source merge, no target merge");
    assert!(store.acquired.is_empty(), "maintenance fetched nothing");
    assert_eq!(FIRST_MAP_CALLS.get(), 0);

    let intermediate =
        crate::collection::simplearchive_union::join(&members[0], &members[1]).unwrap();
    let upper = crate::collection::simplearchive_union::join(&intermediate, &members[2]).unwrap();
    for member in [&intermediate, &upper] {
        store.inner.put::<SimpleArchive, _>(member.clone()).unwrap();
    }
    for (low, high, result) in [
        (&members[0], &members[1], &intermediate),
        (&intermediate, &members[2], &upper),
    ] {
        let before = store.inner.snapshot().unwrap();
        let low_witness = data(low);
        let high_witness = data(high);
        drop(before);
        store
            .inner
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(
                    &equation_signer(),
                    root.handle(),
                    [low_witness, high_witness],
                    data(result),
                )
                .unwrap(),
            ))
            .unwrap();
    }

    let after = block_on(store.maintain(first, &equation_signer())).unwrap();
    assert_eq!(after.collection(first).unwrap().cover().len(), 1);
    drop(after);
    // Aligned merges, bottom-up: the intermediate is mirrored first, then
    // the upper over the intermediate's image and the third leaf. Each is
    // mapped once from its own bytes, and no image is joined for it.
    assert_eq!(FIRST_MAP_CALLS.get(), 2, "one mapping per source merge");
    let mirror = |inputs: [&Blob<SimpleArchive>; 2], result: &Blob<SimpleArchive>| {
        WriteEvent::Insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &equation_signer(),
                first.handle(),
                inputs.map(first_image),
                first_image(result),
            )
            .unwrap(),
        ))
    };
    assert_eq!(
        store.events,
        vec![
            WriteEvent::Put(first_image(&intermediate)),
            mirror([&members[0], &members[1]], &intermediate),
            WriteEvent::Put(first_image(&upper)),
            mirror([&intermediate, &members[2]], &upper),
        ],
        "each image is stored before the MERGE that names it"
    );
    assert!(store.acquired.is_empty());

    store.events.clear();
    reset_mapping_calls();
    block_on(store.maintain(first, &equation_signer())).unwrap();
    assert!(store.events.is_empty());
    assert_eq!(
        FIRST_MAP_CALLS.get(),
        0,
        "a mirror already published is found, not mapped again"
    );
}

#[test]
fn target_maintenance_publishes_only_horizontal_target_merges() {
    let (mut store, root, first, second) = collections();
    carried_chain(
        &mut store,
        root,
        first,
        second,
        crate::collection::MERGE_FAN_IN as u8,
    );
    let before = records(&mut store);
    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();

    let snapshot = store.snapshot().unwrap();
    let attached = snapshot.collection(second).unwrap();
    let (_, cover) = (
        attached.support().unwrap().clone(),
        attached.cover().clone(),
    );
    assert_eq!(cover.len(), 1);
    // Mirroring the first view's merge publishes into the second view only:
    // nothing is written into the source or the root on the way.
    let published: Vec<_> = records(&mut store)
        .into_iter()
        .filter(|record| !before.contains(record))
        .collect();
    assert!(published.iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge) if merge.collection() == second.handle()
    )));
    assert!(published
        .iter()
        .all(|record| record.collection() == second.handle()));
}

#[test]
fn target_maintenance_reendorses_a_resident_upper_without_joining_again() {
    let (mut inner, root, first, second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let c = archive(3, 3);
    let _a_commit = publish_root(&mut inner, root, &a, 31);
    let _b_commit = publish_root(&mut inner, root, &b, 31);
    let _c_commit = publish_root(&mut inner, root, &c, 31);
    let ab = CollectionMerge::sign(&signer, root.handle(), [data(&a), data(&b)], data(&b)).unwrap();
    inner.insert(CollectionRecord::Merge(ab)).unwrap();
    let snapshot = inner.snapshot().unwrap();
    let first_b = FirstEncoding::map(&(), &b, &snapshot).unwrap();
    let first_c = FirstEncoding::map(&(), &c, &snapshot).unwrap();
    drop(snapshot);
    inner.put::<FirstEncoding, _>(first_b.clone()).unwrap();
    inner.put::<FirstEncoding, _>(first_c.clone()).unwrap();
    let first_b_record = CollectionDerive::sign(
        &signer,
        first.handle(),
        crate::collection::SourceLocator::of(data(&b).raw),
        data(&first_b),
    );
    let first_ab_record = CollectionDerive::sign(
        &signer,
        first.handle(),
        crate::collection::SourceLocator::of(data(&b).raw),
        data(&first_b),
    );
    let first_c_record = CollectionDerive::sign(
        &signer,
        first.handle(),
        crate::collection::SourceLocator::of(data(&c).raw),
        data(&first_c),
    );
    for record in [first_b_record, first_ab_record, first_c_record] {
        inner.insert(CollectionRecord::Derive(record)).unwrap();
    }
    let snapshot = inner.snapshot().unwrap();
    let x = SecondEncoding::map(&(), &first_b, &snapshot).unwrap();
    let y = SecondEncoding::map(&(), &first_c, &snapshot).unwrap();
    let z = SecondEncoding::join_members(&Fragment::empty(), &x, &y, &snapshot).unwrap();
    drop(snapshot);
    for blob in [&x, &y, &z] {
        inner.put::<SecondEncoding, _>(blob.clone()).unwrap();
    }
    let x_b = CollectionDerive::sign(
        &signer,
        second.handle(),
        crate::collection::SourceLocator::of(data(&first_b).raw),
        data(&x),
    );
    let x_ab = CollectionDerive::sign(
        &signer,
        second.handle(),
        crate::collection::SourceLocator::of(data(&first_b).raw),
        data(&x),
    );
    let y_c = CollectionDerive::sign(
        &signer,
        second.handle(),
        crate::collection::SourceLocator::of(data(&first_c).raw),
        data(&y),
    );
    for record in [x_b, x_ab, y_c] {
        inner.insert(CollectionRecord::Derive(record)).unwrap();
    }
    let z_bc =
        CollectionMerge::sign(&signer, second.handle(), [data(&x), data(&y)], data(&z)).unwrap();
    inner.insert(CollectionRecord::Merge(z_bc)).unwrap();
    // x is b's image and y is c's, one leaf each, and z = join(x, y) is the
    // second view's own MERGE over them, so z alone is the view's point. a
    // is a root foundation the first view has no leaf for: a leaf stands for
    // its one foundation, so b's image never inherits a through the root's
    // absorption MERGE(a, b) -> b, and nothing above stands for a.
    let requested = support(root, &[b.clone(), c.clone()]);
    assert_eq!(x.bytes.len().ilog2(), z.bytes.len().ilog2());
    let before = inner.snapshot().unwrap();
    assert_eq!(
        before
            .collection(first)
            .unwrap()
            .missing_from(&before.collection(root).unwrap())
            .unwrap(),
        support(root, std::slice::from_ref(&a)),
    );
    let selected = before.collection(second).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&selected),
        requested
    );
    // z = join(x, y) stands for both leaves, so x and y are beneath it and
    // nothing needs a second endorsement to say so.
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(&z)]),
    );
    drop(selected);
    drop(before);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let after = block_on(store.maintain(second, &signer)).unwrap();

    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    let selected = after.collection(second).unwrap();
    assert_eq!(
        crate::collection::test_support::stood_for(&selected),
        requested
    );
    assert_eq!(
        selected.cover().data_members().collect::<Vec<_>>(),
        vec![data(&z)],
    );
    let published: Vec<_> = store
        .events
        .iter()
        .filter_map(|event| match event {
            WriteEvent::Insert(record) => Some(*record),
            WriteEvent::Put(_) => None,
        })
        .collect();
    // Nothing to endorse: both own leaves exist and are resident, and the
    // first view has no merge of its own to mirror. The second view's own
    // MERGE is not re-joined, and a is left to whoever derives it into the
    // first view.
    assert!(published.is_empty(), "nothing to endorse: {published:?}");
    assert!(after
        .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
            second.handle(),
            data(&z),
        )]))
        .unwrap()
        .contains(&CollectionRecord::Merge(z_bc)));
}

#[test]
fn target_maintenance_is_deterministic_and_repeatedly_idempotent() {
    let (mut store, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    ensure_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();
    let first_result = store.snapshot().unwrap();

    maintain_resident::<_, SecondEncoding>(&mut store, second, &equation_signer()).unwrap();
    let second_result = store.snapshot().unwrap();
    assert!(second_result.changes_since(&first_result).is_empty());
}

/// Four genuine root values with two different certificates for B:
/// A | D = B [a,d], and B | Z = Z [b,z]. B's COMMIT and its MERGE are
/// different support routes to exactly the same bytes. Only D is evicted.
fn redundant_support_fixture() -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    [Blob<SimpleArchive>; 4],
) {
    // Fix the deterministic carry order without inventing content hashes.
    // Four/five/six facts all occupy the same serialized-size tier. The
    // bounded search changes only test values, not the mathematical fixture.
    let blobs = (1..=u8::MAX)
        .find_map(|value| {
            let a = (1..=4)
                .map(|entity| row(entity, value))
                .collect::<TribleSet>()
                .to_blob();
            let d = archive(5, value);
            let b = crate::collection::simplearchive_union::join(&a, &d).unwrap();
            let z = crate::collection::simplearchive_union::join(&b, &archive(6, value)).unwrap();
            (data(&a) < data(&b) && data(&b) < data(&z)).then_some([a, b, z, d])
        })
        .expect("a deterministic fixture with H(A) < H(B) < H(Z)");
    let [a, b, z, d] = &blobs;
    assert_eq!(a.bytes.len().ilog2(), b.bytes.len().ilog2());
    assert_eq!(b.bytes.len().ilog2(), z.bytes.len().ilog2());
    let mut store = MemoryRepo::default();
    let collection = store.collection("compaction-progress", policy()).unwrap();
    let commits = blobs
        .each_ref()
        .map(|blob| publish_root(&mut store, collection, blob, 31));
    for (low, high, output) in [(0, 3, b), (1, 2, z)] {
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(
                    &equation_signer(),
                    collection.handle(),
                    [commits[low].data(), commits[high].data()],
                    data(output),
                )
                .unwrap(),
            ))
            .unwrap();
    }
    let retained = store
        .blobs
        .snapshot()
        .unwrap()
        .iter()
        .map(|(handle, _)| handle)
        .filter(|handle| handle.raw != d.get_handle().raw)
        .collect::<Vec<_>>();
    store.blobs.keep(retained);
    (store, collection, blobs)
}

#[test]
fn support_repair_removes_an_earlier_member_made_redundant_by_a_later_one() {
    let (mut store, collection, blobs) = redundant_support_fixture();
    let [a, _b, z, _] = &blobs;
    let requested = support(collection, &blobs);
    let snapshot = store.snapshot().unwrap();
    let selected = snapshot.collection(collection).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    // Z's row is the whole requested support, so it subsumes every other
    // member. The old expectation {b, z} was the route-selected cover.
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(z)]),
    );
    assert_eq!(
        selected.view::<TribleSet>().unwrap(),
        TribleSet::try_from_blob(z.clone()).unwrap(),
    );
    assert!(snapshot.contains_blob(a.get_handle()).unwrap());
}

#[test]
fn target_maintenance_does_not_repeat_a_support_redundant_carry() {
    let (inner, collection, blobs) = redundant_support_fixture();
    let [_, _, z, d] = &blobs;
    let requested = support(collection, &blobs);
    let mut store = GuardStore::new(inner);
    // On the unfixed selector this tries A | B = B even though B's existing
    // witnesses already cover A, then errors on the same three-member cover.
    let after = block_on(store.maintain(collection, &equation_signer())).unwrap();
    let selected = after.collection(collection).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    assert_eq!(
        selected.cover().data_members().collect::<Vec<_>>(),
        vec![data(z)]
    );
    assert!(!after.contains_blob(d.get_handle()).unwrap());
    assert!(store.acquired.is_empty());
    assert!(store
        .events
        .iter()
        .filter_map(|event| match event {
            WriteEvent::Insert(CollectionRecord::Merge(merge)) => Some(merge),
            _ => None,
        })
        .all(|merge| merge.result() == data(z)));
    drop(selected);
    drop(after);

    let before = records(&mut store.inner);
    store.events.clear();
    let after = block_on(store.maintain(collection, &equation_signer())).unwrap();
    assert_eq!(
        after.collection(collection).unwrap().support().unwrap(),
        &requested
    );
    assert!(
        store.events.is_empty(),
        "the maintained cover is a true fixed point"
    );
    assert!(store.acquired.is_empty());
    drop(after);
    assert_eq!(records(&mut store.inner), before);
}

#[test]
fn equal_payload_commit_does_not_restart_completed_target_maintenance() {
    let (mut store, collection, blobs) = redundant_support_fixture();
    let requested = support(collection, &blobs);
    drop(block_on(store.maintain(collection, &equation_signer())).unwrap());
    // A different signer attests B, not a new foundational payload. This must
    // not make the old fine member or its redundant carries reappear.
    publish_root(&mut store, collection, &blobs[1], 32);
    let before = records(&mut store);
    let mut store = GuardStore::new(store);
    let after = block_on(store.maintain(collection, &equation_signer())).unwrap();
    assert_eq!(
        after.collection(collection).unwrap().support().unwrap(),
        &requested
    );
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    drop(after);
    assert_eq!(records(&mut store.inner), before);
}

// The two tests that lived here exercised a memoized support walk. Support
// is read from the coverage index now, and the memo that replaced the walk is
// itself gone: expansion selects producers from the store's own index, so
// there is nothing left to cache or invalidate. The properties they protected
// did not go with them --
//
//   "an open record must never be memoized, because the same operation may
//    publish the witness that closes it"
//       -> collection::coverage::tests::records_arriving_before_their_inputs_still_land
//          and ::settling_without_the_awaited_arrival_does_nothing
//
//   "another lineage must not answer from the previous lineage's memo"
//       -> cannot arise: nothing memoizes support to become stale, and
//          coverage rows are keyed by collection rather than by a walk.

/// Lattice v2: per-owner root carries, "derive what you wrote", aligned
/// merges and freshness.
mod lattice_v2 {
    use super::*;

    use crate::blob::encodings::entity_id_set::{EntityIdSet, EntityIdSetBlob};
    use crate::blob::encodings::succinctarchive::{
        OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
    };
    use crate::collection::{
        maintain_downstream, simplearchive_union, CollectionHandle, CoreRealizer, CoverageRead,
        SourceLocator, MERGE_FAN_IN,
    };

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn public(byte: u8) -> Inline<crate::inline::encodings::ed25519::ED25519PublicKey> {
        Inline::new(key(byte).verifying_key().to_bytes())
    }

    /// The payload `signer` commits as its `entity`-th member: distinct per
    /// signer and entity.
    fn payload(signer: u8, entity: u8) -> Blob<SimpleArchive> {
        // Entity byte zero would be the nil id.
        archive(entity + 1, signer)
    }

    /// Commit a resident payload into `root`, signed by `signer`.
    fn own_commit(
        store: &mut MemoryRepo,
        root: Collection<SimpleArchive>,
        signer: u8,
        entity: u8,
    ) -> CollectionData {
        publish_root(store, root, &payload(signer, entity), signer).data()
    }

    /// Only the signed record of `signer`'s commit arrives; its payload stays
    /// elsewhere.
    fn foreign_commit(
        store: &mut MemoryRepo,
        root: Collection<SimpleArchive>,
        signer: u8,
        entity: u8,
    ) -> CollectionData {
        let metadata = store
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        let data = data(&payload(signer, entity));
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &key(signer),
                root.handle(),
                data,
                metadata,
            )))
            .unwrap();
        data
    }

    fn merges_in(store: &mut MemoryRepo, collection: CollectionHandle) -> Vec<CollectionMerge> {
        records(store)
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Merge(merge) if merge.collection() == collection => Some(merge),
                _ => None,
            })
            .collect()
    }

    fn derives_in(store: &mut MemoryRepo, collection: CollectionHandle) -> Vec<CollectionDerive> {
        records(store)
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Derive(derive) if derive.collection() == collection => {
                    Some(derive)
                }
                _ => None,
            })
            .collect()
    }

    fn frontier(store: &mut MemoryRepo, collection: CollectionHandle) -> BTreeSet<CollectionData> {
        let snapshot = store.snapshot().unwrap();
        let coverage = CoverageRead::coverage(&snapshot, &BTreeSet::from([collection])).unwrap();
        coverage.frontier(collection).collect()
    }

    fn inputs(merge: &CollectionMerge) -> BTreeSet<CollectionData> {
        merge.inputs().iter().copied().collect()
    }

    #[test]
    fn seven_own_nodes_stay_and_the_eighth_makes_one_eight_input_merge() {
        let (mut store, root, _, _) = collections();
        let owner = key(41);
        for entity in 0..7 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.maintain(root, &owner)).unwrap();
        assert!(merges_in(&mut store, root.handle()).is_empty());
        assert_eq!(frontier(&mut store, root.handle()).len(), 7);

        own_commit(&mut store, root, 41, 7);
        block_on(store.maintain(root, &owner)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].inputs().len(), MERGE_FAN_IN);
        let payloads: Vec<_> = (0..8).map(|entity| payload(41, entity)).collect();
        assert_eq!(inputs(&merges[0]), payloads.iter().map(data).collect());
        let union = simplearchive_union::join_all(&payloads).unwrap();
        assert_eq!(merges[0].result(), data(&union));
        let snapshot = store.snapshot().unwrap();
        assert!(snapshot
            .metadata(Handle::<SimpleArchive>::from_hash(merges[0].result()))
            .unwrap()
            .is_some());
        drop(snapshot);
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([merges[0].result()])
        );

        let before = records(&mut store).len();
        block_on(store.maintain(root, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn two_owners_carry_two_trees_that_never_merge_each_others_nodes() {
        let (mut store, root, _, _) = collections();
        let a = key(41);
        let b = key(42);
        let mut own_a: BTreeSet<_> = (0..4)
            .map(|entity| own_commit(&mut store, root, 41, entity))
            .collect();
        // B's payloads are elsewhere: A's carry neither reads nor waits
        // for them.
        let mut own_b: BTreeSet<_> = (0..4)
            .map(|entity| foreign_commit(&mut store, root, 42, entity))
            .collect();
        // Eight nodes share tier 0, but neither owner holds eight.
        block_on(store.maintain(root, &a)).unwrap();
        assert!(merges_in(&mut store, root.handle()).is_empty());

        own_a.extend((4..8).map(|entity| own_commit(&mut store, root, 41, entity)));
        block_on(store.maintain(root, &a)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].public_key(), public(41));
        assert_eq!(inputs(&merges[0]), own_a);
        let tree_a = merges[0].result();
        assert_eq!(
            frontier(&mut store, root.handle()),
            own_b.iter().copied().chain([tree_a]).collect()
        );

        // B's payloads land and B writes four more: B's own carry takes
        // exactly B's eight, and A's tree stays A's.
        for entity in 0..4 {
            store.put::<SimpleArchive, _>(payload(42, entity)).unwrap();
        }
        own_b.extend((4..8).map(|entity| own_commit(&mut store, root, 42, entity)));
        block_on(store.maintain(root, &b)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        assert_eq!(merges.len(), 2);
        let tree_b = merges
            .iter()
            .find(|merge| merge.public_key() == public(42))
            .expect("B carried its own nodes");
        assert_eq!(inputs(tree_b), own_b);
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([tree_a, tree_b.result()])
        );

        // Two tier-1 nodes, one per owner: neither maintainer touches the
        // other's.
        let before = records(&mut store).len();
        block_on(store.maintain(root, &a)).unwrap();
        block_on(store.maintain(root, &b)).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn an_own_node_inside_another_own_node_is_absorbed_and_a_foreign_one_is_not() {
        let (mut store, root, _, _) = collections();
        let owner = key(41);
        let commits: Vec<_> = (0..8)
            .map(|entity| own_commit(&mut store, root, 41, entity))
            .collect();
        block_on(store.maintain(root, &owner)).unwrap();
        let wide = merges_in(&mut store, root.handle())[0].result();

        // The same key grouped two members again elsewhere: an own node
        // inside the wide one.
        let narrow = simplearchive_union::join(&payload(41, 0), &payload(41, 1)).unwrap();
        let narrow =
            Handle::<SimpleArchive>::to_hash(store.put::<SimpleArchive, _>(narrow).unwrap());
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&owner, root.handle(), [commits[0], commits[1]], narrow)
                    .unwrap(),
            ))
            .unwrap();
        // Someone else's node inside it too.
        let foreign = simplearchive_union::join(&payload(41, 2), &payload(41, 3)).unwrap();
        let foreign =
            Handle::<SimpleArchive>::to_hash(store.put::<SimpleArchive, _>(foreign).unwrap());
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&key(42), root.handle(), [commits[2], commits[3]], foreign)
                    .unwrap(),
            ))
            .unwrap();
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([wide, narrow, foreign])
        );

        block_on(store.maintain(root, &owner)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        let absorbed: Vec<_> = merges
            .iter()
            .filter(|merge| merge.public_key() == public(41) && merge.result() == wide)
            .filter(|merge| merge.inputs().len() == 2)
            .collect();
        assert_eq!(absorbed.len(), 1);
        assert_eq!(inputs(absorbed[0]), BTreeSet::from([narrow, wide]));
        assert!(merges
            .iter()
            .all(|merge| merge.public_key() != public(41) || !merge.inputs().contains(&foreign)));
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([wide, foreign])
        );
    }

    #[test]
    fn ensure_derives_only_its_keys_own_leaves_and_freshness_names_the_rest() {
        let (mut store, root, first, _) = collections();
        let a1 = own_commit(&mut store, root, 41, 1);
        let a2 = own_commit(&mut store, root, 41, 2);
        let b1 = own_commit(&mut store, root, 42, 1);
        let missing = |store: &mut MemoryRepo| -> BTreeSet<CollectionData> {
            let snapshot = store.snapshot().unwrap();
            let view = snapshot.collection(first).unwrap();
            let source = snapshot.collection(root).unwrap();
            view.missing_from(&source).unwrap().data_members().collect()
        };
        assert_eq!(missing(&mut store), BTreeSet::from([a1, a2, b1]));

        block_on(store.ensure(first, &key(41))).unwrap();
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 2);
        assert!(leaves.iter().all(|leaf| leaf.public_key() == public(41)));
        assert_eq!(
            leaves
                .iter()
                .map(|leaf| leaf.input())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([SourceLocator::of(a1.raw), SourceLocator::of(a2.raw)])
        );
        assert!(leaves
            .iter()
            .any(|leaf| leaf.output() == first_image(&payload(41, 1))));
        assert_eq!(missing(&mut store), BTreeSet::from([b1]));
        // A second pass has nothing left of its own to derive.
        let before = records(&mut store).len();
        block_on(store.ensure(first, &key(41))).unwrap();
        assert_eq!(records(&mut store).len(), before);

        block_on(store.ensure(first, &key(42))).unwrap();
        assert!(missing(&mut store).is_empty());
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 3);
        assert!(leaves.iter().any(
            |leaf| leaf.public_key() == public(42) && leaf.input() == SourceLocator::of(b1.raw)
        ));

        // Freshness is asked of the view's own source, nothing else.
        let other = store.collection("unrelated", policy()).unwrap();
        publish_root(&mut store, other, &archive(9, 9), 41);
        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(first).unwrap();
        let unrelated = snapshot.collection(other).unwrap();
        assert!(matches!(
            view.missing_from(&unrelated),
            Err(CollectionRealizationError::InvalidCover(_))
        ));
    }

    #[test]
    fn a_view_publishes_an_empty_image_as_a_leaf() {
        let id = |byte: u8| Id::new([byte; 16]).unwrap();
        let owner = key(41);
        let mut store = MemoryRepo::default();
        let root = store.collection("receipts", policy()).unwrap();
        let ids = store
            .derive::<EntityIdSetBlob>(root, crate::metadata::supersedes.id(), policy())
            .unwrap();
        let receipt = id(31);
        store
            .commit(
                root,
                &owner,
                crate::macros::entity! { ExclusiveId::force_ref(&receipt) @
                    crate::metadata::supersedes: id(1),
                },
            )
            .unwrap();
        let unrelated = store
            .commit(
                root,
                &owner,
                crate::macros::entity! { crate::metadata::name: "nothing superseded" },
            )
            .unwrap();
        block_on(store.ensure(ids, &owner)).unwrap();

        let leaves = derives_in(&mut store, ids.handle());
        assert_eq!(leaves.len(), 2);
        let snapshot = store.snapshot().unwrap();
        let empty = <EntityIdSetBlob as CollectionDerivation>::map(
            &crate::metadata::supersedes.id(),
            &TribleSet::new().to_blob(),
            &snapshot,
        )
        .unwrap();
        let leaf = leaves
            .iter()
            .find(|leaf| leaf.input() == SourceLocator::of(unrelated.data().raw))
            .expect("the unrelated commit has its leaf");
        assert_eq!(leaf.output(), data(&empty));
        let view = snapshot.collection(ids).unwrap();
        let source = snapshot.collection(root).unwrap();
        assert!(view.missing_from(&source).unwrap().is_empty());
        assert_eq!(view.support().unwrap().len(), 2);
        assert_eq!(
            view.view::<EntityIdSet>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [id(1)]
        );
    }

    #[test]
    fn an_own_commit_whose_payload_is_nowhere_is_reported_after_the_rest() {
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        let resident = own_commit(&mut store, root, 41, 0);
        // The key's own COMMIT arrived, its payload did not, and nothing can
        // hand it over: nothing upstream of a root can restore it.
        let cold = foreign_commit(&mut store, root, 41, 1);
        let result = block_on(store.ensure(first, &owner));
        assert!(
            matches!(
                &result,
                Err(CollectionRealizationError::Unmappable { blocked })
                    if blocked.iter().map(|(member, _)| *member).collect::<Vec<_>>() == [cold]
            ),
            "{:?}",
            result.err()
        );
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 1, "the resident commit was derived anyway");
        assert_eq!(leaves[0].input(), SourceLocator::of(resident.raw));
    }

    #[test]
    fn an_own_image_of_a_derived_source_that_is_nowhere_is_that_sources_lag() {
        let (mut store, root, first, second) = collections();
        let owner = key(41);
        own_commit(&mut store, root, 41, 0);
        block_on(store.ensure(first, &owner)).unwrap();
        // The key's own leaf in the first view arrived ahead of its image,
        // and nothing can hand the image over. Maintaining the first view
        // would map it again; deriving the second one neither requires nor
        // repairs it.
        let elsewhere = payload(41, 1);
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &owner,
                first.handle(),
                SourceLocator::of(data(&elsewhere).raw),
                first_image(&elsewhere),
            )))
            .unwrap();
        let before = records(&mut store);
        let snapshot = block_on(store.maintain(second, &owner)).unwrap();
        assert_eq!(snapshot.collection(second).unwrap().cover().len(), 1);
        drop(snapshot);
        let published: Vec<_> = records(&mut store)
            .into_iter()
            .filter(|record| !before.contains(record))
            .collect();
        assert_eq!(published.len(), 1);
        assert!(matches!(
            published[0],
            CollectionRecord::Derive(derive) if derive.collection() == second.handle()
        ));
    }

    #[test]
    fn an_own_source_merge_is_mirrored_exactly_once_across_passes() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.maintain(root, &owner)).unwrap();
        let merged = merges_in(&mut store, root.handle())[0].result();

        block_on(store.maintain(first, &owner)).unwrap();
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 8);
        let mirrors = merges_in(&mut store, first.handle());
        assert_eq!(mirrors.len(), 1);
        assert_eq!(
            inputs(&mirrors[0]),
            leaves.iter().map(|leaf| leaf.output()).collect()
        );
        // f(R) is R's own bytes mapped, not a join of the images.
        let snapshot = store.snapshot().unwrap();
        let merged_blob: Blob<SimpleArchive> = snapshot
            .get(Handle::<SimpleArchive>::from_hash(merged))
            .unwrap();
        drop(snapshot);
        assert_eq!(mirrors[0].result(), first_image(&merged_blob));
        assert_eq!(FIRST_MAP_CALLS.get(), 9);
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([mirrors[0].result()])
        );

        reset_mapping_calls();
        let before = records(&mut store).len();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
    }

    #[test]
    fn a_merge_the_mapping_declines_is_not_mirrored_nor_is_anything_above_it() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        for entity in 0..64 {
            own_commit(&mut store, root, 41, entity);
        }
        // 64 own nodes carry through two tiers: eight merges of eight, then
        // one merge of those eight.
        block_on(store.maintain(root, &owner)).unwrap();
        let root_merges = merges_in(&mut store, root.handle());
        assert_eq!(root_merges.len(), 9);
        let top = root_merges
            .iter()
            .find(|merge| {
                merge.inputs().len() == MERGE_FAN_IN && {
                    let snapshot = store.snapshot().unwrap();
                    let coverage =
                        CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
                            .unwrap();
                    coverage.of(root.handle(), merge.result()).unwrap().len() == 64
                }
            })
            .expect("one merge stands for all 64")
            .result();
        assert_eq!(frontier(&mut store, root.handle()), BTreeSet::from([top]));
        let declined = root_merges
            .iter()
            .filter(|merge| merge.result() != top)
            .map(|merge| merge.result())
            .min()
            .unwrap();
        FIRST_MAP_CAPACITY.replace(Some(declined));

        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(derives_in(&mut store, first.handle()).len(), 64);
        // The seven other tier-1 merges are mirrored; the declined one and
        // the top merge that needs it are not, and the declined node's eight
        // children stay on the target frontier.
        assert_eq!(merges_in(&mut store, first.handle()).len(), 7);
        assert_eq!(frontier(&mut store, first.handle()).len(), 8 + 7);

        reset_mapping_calls();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(merges_in(&mut store, first.handle()).len(), 9);
        // Only the declined node and the top were mapped this time.
        assert_eq!(FIRST_MAP_CALLS.get(), 2);
        assert_eq!(frontier(&mut store, first.handle()).len(), 1);
    }

    #[test]
    fn a_chain_is_maintained_upstream_first_in_one_pass() {
        let owner = key(41);
        let mut store = MemoryRepo::default();
        let root = store.collection("facts", policy()).unwrap();
        let raw = store
            .derive::<SuccinctArchiveBlob>(root, (), policy())
            .unwrap();
        let accelerated = store
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy())
            .unwrap();
        // Whoever registers a view realizes it once; from then on the
        // store lists it.
        own_commit(&mut store, root, 41, 0);
        block_on(store.ensure(raw, &owner)).unwrap();
        block_on(store.ensure(accelerated, &owner)).unwrap();

        for entity in 1..8 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.maintain(root, &owner)).unwrap();
        let report = block_on(maintain_downstream(
            &mut store,
            root.handle(),
            &owner,
            &mut CoreRealizer,
        ))
        .unwrap();
        assert_eq!(report.realized, vec![raw.handle(), accelerated.handle()]);

        // Rank9's leaves name Succinct's own foundations, and its one merge
        // mirrors Succinct's, which had to exist first.
        let raw_leaves = derives_in(&mut store, raw.handle());
        assert_eq!(raw_leaves.len(), 8);
        let raw_images: BTreeSet<_> = raw_leaves
            .iter()
            .map(|leaf| SourceLocator::of(leaf.output().raw))
            .collect();
        let accelerated_leaves = derives_in(&mut store, accelerated.handle());
        assert_eq!(accelerated_leaves.len(), 8);
        assert_eq!(
            accelerated_leaves
                .iter()
                .map(|leaf| leaf.input())
                .collect::<BTreeSet<_>>(),
            raw_images
        );
        let raw_mirrors = merges_in(&mut store, raw.handle());
        let accelerated_mirrors = merges_in(&mut store, accelerated.handle());
        assert_eq!(raw_mirrors.len(), 1);
        assert_eq!(accelerated_mirrors.len(), 1);
        assert_eq!(
            frontier(&mut store, accelerated.handle()),
            BTreeSet::from([accelerated_mirrors[0].result()])
        );

        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(accelerated).unwrap();
        let facts: UnionArchive<OrderedUniverse> = view.view().unwrap();
        let expected: TribleSet = (0..8).map(|entity| row(entity + 1, 41)).collect();
        assert_eq!(facts.iter().collect::<TribleSet>(), expected);
        let raw_view = snapshot.collection(raw).unwrap();
        let source = snapshot.collection(root).unwrap();
        assert!(raw_view.missing_from(&source).unwrap().is_empty());
        assert!(view.missing_from(&raw_view).unwrap().is_empty());
    }

    #[test]
    fn a_view_mirrors_only_merges_its_maintainer_signed() {
        let owner = key(41);
        let mut store = MemoryRepo::default();
        // The owner roots the root's WRITE and grants it to 42; 43 is
        // admitted nowhere.
        let root = store
            .collection(
                "claims about somebody else's node",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(owner.verifying_key()),
                ),
            )
            .unwrap();
        let first = store.derive::<FirstEncoding>(root, (), policy()).unwrap();
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(root.handle()),
                &owner,
                write_capability(),
                key(42).verifying_key(),
            ))
            .unwrap();
        let own: Vec<_> = (0..8)
            .map(|entity| own_commit(&mut store, root, 41, entity))
            .collect();
        block_on(store.maintain(root, &owner)).unwrap();
        let merged = merges_in(&mut store, root.handle())[0].result();
        let theirs = own_commit(&mut store, root, 42, 0);
        block_on(store.ensure(first, &key(42))).unwrap();
        // Claims about the owner's node the owner never made: that it
        // absorbed the other writer's commit, and that it is the join of two
        // of its own commits. 43's are unbelieved; 42's are believed, and
        // still not the owner's to mirror.
        for signer in [43, 42] {
            for inputs in [[theirs, merged], [own[0], own[1]]] {
                store
                    .insert(CollectionRecord::Merge(
                        CollectionMerge::sign(&key(signer), root.handle(), inputs, merged).unwrap(),
                    ))
                    .unwrap();
            }
        }

        block_on(store.maintain(first, &owner)).unwrap();
        let their_image = first_image(&payload(42, 0));
        let mirrors = merges_in(&mut store, first.handle());
        assert_eq!(mirrors.len(), 1, "only the owner's own carry is mirrored");
        assert_eq!(mirrors[0].public_key(), public(41));
        assert_eq!(
            inputs(&mirrors[0]),
            (0..8)
                .map(|entity| first_image(&payload(41, entity)))
                .collect()
        );
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([mirrors[0].result(), their_image]),
            "the other writer's image is nobody's input in the view"
        );
    }

    #[test]
    fn a_derived_collection_in_a_roots_encoding_has_no_carry() {
        struct Identity;

        impl CollectionMapping for Identity {
            type Source = SimpleArchive;
            type Target = SimpleArchive;

            fn fragment(&self) -> Fragment {
                FirstEncoding::fragment(&())
            }

            fn bind(
                _source: &Fragment,
                _target: &Fragment,
            ) -> Result<Self, CollectionOperationError> {
                Ok(Self)
            }

            fn map<R>(
                &self,
                source: &Blob<SimpleArchive>,
                _reader: &R,
            ) -> Result<Blob<SimpleArchive>, CollectionOperationError>
            where
                R: StoreRead,
            {
                Ok(source.clone())
            }
        }

        let owner = key(41);
        let (mut store, root, _, _) = collections();
        let copy = store.derive_with(root, Identity, policy()).unwrap();
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.ensure_with::<Identity>(copy, &owner)).unwrap();
        assert_eq!(derives_in(&mut store, copy.handle()).len(), 8);
        // Eight own leaves in one tier, and still no carry: the view's merges
        // are its source's, mirrored through its mapping.
        let before = records(&mut store);
        let result = block_on(store.maintain(copy, &owner));
        assert!(
            matches!(result, Err(CollectionRealizationError::InvalidCover(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(records(&mut store), before);
    }

    #[test]
    fn an_own_merge_that_returns_one_of_its_inputs_is_mirrored_onto_its_leaf() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        // Seven members, and an eighth holding all of them and one fact
        // more: the join of the eight is the eighth's own bytes.
        let members: Vec<_> = (0..7).map(|entity| payload(41, entity)).collect();
        let mut all = TribleSet::new();
        for member in &members {
            all.union(TribleSet::try_from_blob(member.clone()).unwrap());
        }
        all.insert(&row(99, 41));
        let wide: Blob<SimpleArchive> = all.to_blob();
        for member in members.iter().chain([&wide]) {
            publish_root(&mut store, root, member, 41);
        }
        block_on(store.maintain(root, &owner)).unwrap();
        let carried = merges_in(&mut store, root.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].result(), data(&wide));
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([data(&wide)])
        );

        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(derives_in(&mut store, first.handle()).len(), 8);
        let mirrors = merges_in(&mut store, first.handle());
        assert_eq!(mirrors.len(), 1);
        assert_eq!(mirrors[0].result(), first_image(&wide));
        assert_eq!(
            inputs(&mirrors[0]),
            members.iter().chain([&wide]).map(first_image).collect()
        );
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([first_image(&wide)])
        );
        assert_eq!(FIRST_MAP_CALLS.get(), 8, "the leaves alone are mapped");

        let before = records(&mut store).len();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    /// A payload holding one fact per entity in `entities`, all signed `41`.
    fn facts(entities: &[u8]) -> Blob<SimpleArchive> {
        let mut facts = TribleSet::new();
        for &entity in entities {
            facts.insert(&row(entity, 41));
        }
        facts.to_blob()
    }

    #[test]
    fn every_own_producer_of_a_merged_node_is_mirrored() {
        // A review control, 2026-09-25: R = A+B = C+D, both merges the owner's.
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        let [a, b, c, d] = [[1, 2], [3, 4], [1, 3], [2, 4]].map(|entities| facts(&entities));
        let r = facts(&[1, 2, 3, 4]);
        for payload in [&a, &b, &c, &d] {
            publish_root(&mut store, root, payload, 41);
        }
        store.put::<SimpleArchive, _>(r.clone()).unwrap();
        for pair in [[&a, &b], [&c, &d]] {
            store
                .insert(CollectionRecord::Merge(
                    CollectionMerge::sign(&owner, root.handle(), pair.map(data), data(&r))
                        .unwrap(),
                ))
                .unwrap();
        }

        block_on(store.maintain(first, &owner)).unwrap();
        let mirrors = merges_in(&mut store, first.handle());
        assert_eq!(mirrors.len(), 2, "one mirror per producer");
        assert!(mirrors
            .iter()
            .all(|mirror| mirror.result() == first_image(&r)));
        assert_eq!(
            mirrors.iter().map(inputs).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                BTreeSet::from([first_image(&a), first_image(&b)]),
                BTreeSet::from([first_image(&c), first_image(&d)]),
            ])
        );
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([first_image(&r)])
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.collection(first).unwrap().support().unwrap().len(), 4);
        drop(snapshot);

        let before = records(&mut store).len();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn a_leaf_whose_image_is_not_here_is_still_missing() {
        // A review control, 2026-09-25: the DERIVE arrives before its output.
        let (mut store, root, first, _) = collections();
        let commit = own_commit(&mut store, root, 41, 0);
        let mut image = payload(41, 0).bytes.as_ref().to_vec();
        image.push(0xA5);
        let image = Blob::<FirstEncoding>::new(image.into());
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &key(41),
                first.handle(),
                SourceLocator::of(commit.raw),
                data(&image),
            )))
            .unwrap();

        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(first).unwrap();
        assert!(view.support().unwrap().is_empty());
        assert_eq!(
            view.missing_from(&snapshot.collection(root).unwrap())
                .unwrap()
                .len(),
            1,
            "a leaf record is not delivery"
        );
        drop((view, snapshot));

        store.put::<FirstEncoding, _>(image).unwrap();
        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(first).unwrap();
        assert_eq!(view.support().unwrap().len(), 1);
        assert!(view
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn maintenance_derives_an_absent_owners_foundations_and_ensure_does_not() {
        // JP, 2026-09-25: merge is a choice, derive is a function. A view
        // must not lag behind an owner who is offline or on an older build.
        let (mut store, root, first, _) = collections();
        let a1 = own_commit(&mut store, root, 41, 1);
        let b1 = own_commit(&mut store, root, 42, 1);
        let missing = |store: &mut MemoryRepo| -> BTreeSet<CollectionData> {
            let snapshot = store.snapshot().unwrap();
            let view = snapshot.collection(first).unwrap();
            let source = snapshot.collection(root).unwrap();
            view.missing_from(&source).unwrap().data_members().collect()
        };

        // The per-write ensure derives only what 41 wrote.
        block_on(store.ensure(first, &key(41))).unwrap();
        assert_eq!(missing(&mut store), BTreeSet::from([b1]));

        // Maintenance by 41 derives 42's foundation too, with 42 absent.
        block_on(store.maintain(first, &key(41))).unwrap();
        assert!(missing(&mut store).is_empty());
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 2);
        assert!(leaves.iter().all(|leaf| leaf.public_key() == public(41)));
        assert!(leaves
            .iter()
            .any(|leaf| leaf.input() == SourceLocator::of(b1.raw)
                && leaf.output() == first_image(&payload(42, 1))));
        let _ = a1;

        // When 42 comes back, its own pass converges on the same image and
        // publishes nothing: the foundation already has a leaf.
        let before = records(&mut store).len();
        block_on(store.maintain(first, &key(42))).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn maintainers_racing_on_an_absent_owners_foundations_converge_and_leave_its_merges() {
        // A bounded race: 41 and 42 each maintain their own replica of one
        // state while 43 is away, then the replicas are united, as `cat` does.
        // 43 holds eight nodes in one tier, so a merge is on offer to steal.
        let replica = || {
            let (mut store, root, first, _) = collections();
            own_commit(&mut store, root, 41, 0);
            own_commit(&mut store, root, 42, 0);
            for entity in 0..8 {
                own_commit(&mut store, root, 43, entity);
            }
            (store, root, first)
        };
        let (mut left, root, first) = replica();
        let (mut right, right_root, right_first) = replica();
        assert_eq!(
            (right_root.handle(), right_first.handle()),
            (root.handle(), first.handle())
        );
        for (store, racer) in [(&mut left, 41), (&mut right, 42)] {
            block_on(store.maintain(root, &key(racer))).unwrap();
            block_on(store.maintain(first, &key(racer))).unwrap();
            // A merge is a choice: neither racer merged 43's nodes, in the
            // root or as a mirror in the view.
            assert!(merges_in(store, root.handle()).is_empty());
            assert!(merges_in(store, first.handle()).is_empty());
        }
        let alone = frontier(&mut left, first.handle());
        assert_eq!(alone.len(), 10);

        for record in records(&mut right) {
            left.insert(record).unwrap();
        }

        // Every foundation now has a leaf from each racer, and both leaves
        // name the same image: a derive is a function.
        let leaves = derives_in(&mut left, first.handle());
        assert_eq!(leaves.len(), 20);
        let mut outputs = std::collections::BTreeMap::<_, BTreeSet<_>>::new();
        for leaf in &leaves {
            outputs.entry(leaf.input()).or_default().insert(leaf.output());
        }
        assert_eq!(outputs.len(), 10);
        assert!(outputs.values().all(|images| images.len() == 1));
        assert_eq!(frontier(&mut left, first.handle()), alone);
        let snapshot = left.snapshot().unwrap();
        assert!(snapshot
            .collection(first)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
        drop(snapshot);

        // Converged: another pass by either racer publishes nothing.
        let before = records(&mut left).len();
        block_on(left.maintain(first, &key(41))).unwrap();
        block_on(left.maintain(first, &key(42))).unwrap();
        assert_eq!(records(&mut left).len(), before);

        // When 43 returns, it makes its own merge and mirrors it over the
        // racers' leaves, and nobody else's merge appears.
        block_on(left.maintain(root, &key(43))).unwrap();
        block_on(left.maintain(first, &key(43))).unwrap();
        let merges = merges_in(&mut left, root.handle());
        assert_eq!(merges.len(), 1);
        let mirrors = merges_in(&mut left, first.handle());
        assert_eq!(mirrors.len(), 1);
        assert!(merges
            .iter()
            .chain(&mirrors)
            .all(|merge| merge.public_key() == public(43)));
    }
    #[test]
    fn a_foreign_foundation_the_mapping_refuses_is_its_owners_lag_not_this_keys_failure() {
        // Review finding, 2026-09-26: a Fatal or capacity refusal on another
        // owner's foundation must not fail this key's pass or stop its own
        // mirroring, nor be reported as this key's lag.
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        let refused = own_commit(&mut store, root, 42, 1);
        let too_big = own_commit(&mut store, root, 42, 2);
        let fine = own_commit(&mut store, root, 42, 3);
        FIRST_MAP_FATAL.replace(Some(refused));
        FIRST_MAP_CAPACITY.replace(Some(too_big));

        block_on(store.maintain(root, &key(41))).unwrap();
        block_on(store.maintain(first, &key(41))).unwrap();

        // 41's own merge is mirrored, and every foundation but the two the
        // mapping refused has a leaf.
        let mirrors = merges_in(&mut store, first.handle());
        assert_eq!(mirrors.len(), 1);
        assert!(mirrors.iter().all(|mirror| mirror.public_key() == public(41)));
        let snapshot = store.snapshot().unwrap();
        let missing: BTreeSet<CollectionData> = snapshot
            .collection(first)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .data_members()
            .collect();
        drop(snapshot);
        assert_eq!(missing, BTreeSet::from([refused, too_big]));
        assert!(derives_in(&mut store, first.handle())
            .iter()
            .any(|leaf| leaf.input() == SourceLocator::of(fine.raw)));

        // Another pass is quiet and still succeeds.
        let before = records(&mut store).len();
        block_on(store.maintain(first, &key(41))).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn maintenance_never_fetches_another_owners_payload() {
        // Review finding, 2026-09-26: foreign work is derived only from
        // payloads already here; an absent owner's missing payload costs no
        // acquisition, on this pass or any later one.
        let (mut inner, root, first, _) = collections();
        let own = own_commit(&mut inner, root, 41, 1);
        let absent = foreign_commit(&mut inner, root, 42, 1);
        let mut store = GuardStore::new(inner);

        block_on(store.maintain(first, &key(41))).unwrap();
        block_on(store.maintain(first, &key(41))).unwrap();
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);

        // The own foundation has its leaf; the absent payload's foundation
        // has none. (Freshness does not name it: a source stands only for
        // payloads it holds.)
        let leaves: BTreeSet<SourceLocator> = derives_in(&mut store.inner, first.handle())
            .iter()
            .map(|leaf| leaf.input())
            .collect();
        assert_eq!(leaves, BTreeSet::from([SourceLocator::of(own.raw)]));
        assert!(!leaves.contains(&SourceLocator::of(absent.raw)));
    }

    #[test]
    fn a_mapping_bound_to_its_producers_replica_is_left_to_each_owner() {
        use crate::collection::encoding::CanonicalDerivation;
        use crate::collection::reference_summary::ReferenceSummaryBlob;
        assert!(<CanonicalDerivation<FirstEncoding> as CollectionMapping>::REPLICA_INDEPENDENT);
        assert!(
            !<CanonicalDerivation<ReferenceSummaryBlob> as CollectionMapping>::REPLICA_INDEPENDENT
        );
    }
}
