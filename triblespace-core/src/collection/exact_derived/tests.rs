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
    CollectionMerge, CollectionPolicy, CollectionRead, CollectionReadAudience,
    CollectionRecordFingerprint, CollectionRecordSelector, CollectionSnapshotExt, CollectionStore,
    CollectionStoreExt,
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

fn witnessed_input(
    snapshot: &MemoryRepoSnapshot,
    collection: crate::collection::CollectionHandle,
    data: CollectionData,
) -> (CollectionData, CollectionRecordFingerprint) {
    let record = snapshot
        .records()
        .unwrap()
        .map(Result::unwrap)
        .find(|record| {
            record.collection() == collection
                && match record {
                    CollectionRecord::Commit(commit) => commit.data() == data,
                    CollectionRecord::Merge(merge) => merge.result() == data,
                    CollectionRecord::Derive(derive) => derive.output() == data,
                }
        })
        .expect("fixture input has an actual persisted predecessor");
    (data, record.fingerprint())
}

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
}

fn reset_mapping_calls() {
    FIRST_MAP_CALLS.set(0);
    SECOND_MAP_CALLS.set(0);
    SECOND_JOIN_CALLS.set(0);
    FIRST_MAP_MISSING.set(false);
    FIRST_MAP_CAPACITY.replace(None);
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

impl CollectionRead for GuardSnapshot {
    type RecordsError = <MemoryRepoSnapshot as CollectionRead>::RecordsError;
    type RecordIter<'a>
        = <MemoryRepoSnapshot as CollectionRead>::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.inner.records()
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.inner.record(fingerprint)
    }

    fn select_records(
        &self,
        selectors: &std::collections::BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.semantic_probes.fetch_add(1, Ordering::SeqCst);
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
    expected_live_during_write: usize,
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
            expected_live_during_write: 1,
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

    fn assert_only_control_snapshot(&self) {
        assert_eq!(
            self.live.load(Ordering::SeqCst),
            self.expected_live_during_write,
            "unexpected number of live snapshots while acquiring immutable residency",
        );
    }
}

impl AsyncBlobStoreAcquire for GuardStore {
    type AcquireError = GuardStoreError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        self.assert_only_control_snapshot();
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
fn aggregate_support_uses_selected_dag_leaves_without_clipping_certificates() {
    let (mut store, root, first, _second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let ca = publish_root(&mut store, root, &a, 31);
    let cb = publish_root(&mut store, root, &b, 31);
    let a_support = support(root, std::slice::from_ref(&a));
    let b_support = support(root, std::slice::from_ref(&b));
    let ab_support = support(root, &[a.clone(), b.clone()]);
    let a_output = FirstEncoding::map(&(), &a, &store.snapshot().unwrap()).unwrap();
    let da = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&a), ca.fingerprint()),
        data(&a_output),
    );
    store.insert(CollectionRecord::Derive(da)).unwrap();
    let selected = BTreeSet::from([first.handle()]);
    let before = store.snapshot().unwrap();
    let lineage = load_lineage(&before, first).unwrap();
    let partial =
        resolve_endorsed_lineage(&before, &lineage, &selected, Some(&ab_support)).unwrap();
    assert_eq!(
        partial.support, a_support,
        "requested AB is not yet certified",
    );

    // b contains a, but its COMMIT is a distinct foundational member. The
    // source merge certifies both members despite producing b's same bytes.
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), ca.fingerprint()),
        (data(&b), cb.fingerprint()),
        data(&b),
    );
    store.insert(CollectionRecord::Merge(ab)).unwrap();
    let b_output = FirstEncoding::map(&(), &b, &store.snapshot().unwrap()).unwrap();
    let dab = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&b), ab.fingerprint()),
        data(&b_output),
    );
    store.insert(CollectionRecord::Derive(dab)).unwrap();
    let after = store.snapshot().unwrap();
    reset_mapping_calls();
    for requested in [None, Some(&ab_support), Some(&a_support), Some(&b_support)] {
        let resolved = resolve_endorsed_lineage(&after, &lineage, &selected, requested).unwrap();
        let expected = match requested {
            None => ab_support.clone(),
            Some(requested) if requested == &ab_support => ab_support.clone(),
            Some(requested) if requested == &a_support => a_support.clone(),
            Some(_) => Support::from_data(root, []),
        };
        assert_eq!(resolved.support, expected);
        // Image reuse remains independent of the requested-support filter.
        assert_eq!(
            resolved.images[&(first.handle(), data(&b))],
            BTreeSet::from([data(&b_output)]),
        );
    }
    assert_eq!(
        FIRST_MAP_CALLS.get(),
        0,
        "resolution never recomputes a map"
    );
}

#[test]
fn aggregate_support_deduplicates_leaves_but_keeps_alternative_certifications() {
    let (mut store, root, first, _second) = collections();
    let signer = equation_signer();
    let other_signer = SigningKey::from_bytes(&[32; 32]);
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let ca = publish_root(&mut store, root, &a, 31);
    let cb = publish_root(&mut store, root, &b, 31);
    let cb_other = publish_root(&mut store, root, &b, 32);
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), ca.fingerprint()),
        (data(&b), cb.fingerprint()),
        data(&b),
    );
    store.insert(CollectionRecord::Merge(ab)).unwrap();
    let output = FirstEncoding::map(&(), &b, &store.snapshot().unwrap()).unwrap();
    let mut target_records = Vec::new();
    for (key, witness) in [
        (&signer, ab.fingerprint()),
        (&signer, cb.fingerprint()),
        (&signer, cb_other.fingerprint()),
        (&other_signer, cb.fingerprint()),
    ] {
        let derive =
            CollectionDerive::sign(key, first.handle(), (data(&b), witness), data(&output));
        store.insert(CollectionRecord::Derive(derive)).unwrap();
        target_records.push(derive);
    }
    let snapshot = store.snapshot().unwrap();
    let lineage = load_lineage(&snapshot, first).unwrap();
    let selected = BTreeSet::from([first.handle()]);
    let ab_support = support(root, &[a.clone(), b.clone()]);
    let b_support = support(root, &[b]);
    let whole = resolve_endorsed_lineage(&snapshot, &lineage, &selected, None).unwrap();
    assert_eq!(whole.support, ab_support);
    let alternatives = &whole.witnesses[&(first.handle(), data(&output))];
    assert_eq!(alternatives.len(), 4);
    for record in &target_records {
        let expected = if record.input_witness() == ab.fingerprint() {
            &ab_support
        } else {
            &b_support
        };
        assert!(alternatives.iter().any(|(fingerprint, support)| {
            *fingerprint == record.fingerprint() && support == expected
        }));
    }
    let exact = resolve_endorsed_lineage(&snapshot, &lineage, &selected, Some(&b_support)).unwrap();
    assert_eq!(exact.support, b_support);
    assert_eq!(exact.witnesses[&(first.handle(), data(&output))].len(), 3);
    assert!(!exact.witnesses.contains_key(&(root.handle(), data(&a))));
}

#[test]
fn aggregate_support_excludes_missing_witnesses_and_unadmitted_producers() {
    let mut store = MemoryRepo::default();
    let signer = equation_signer();
    let other_signer = SigningKey::from_bytes(&[32; 32]);
    let root = store.collection("root", policy()).unwrap();
    let first = store
        .derive::<FirstEncoding>(
            root,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(signer.verifying_key()),
            ),
        )
        .unwrap();
    let a = archive(1, 1);
    let b = archive(2, 2);
    let c = archive(3, 3);
    let ca = publish_root(&mut store, root, &a, 31);
    let cc = publish_root(&mut store, root, &c, 31);
    let metadata = store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
    // This is the actual predecessor, deliberately not persisted yet.
    let cb = CollectionCommit::sign(&signer, root.handle(), data(&b), metadata);
    let mut a_output = None;
    for (key, source, witness) in [
        (&signer, &a, ca.fingerprint()),
        (&signer, &b, cb.fingerprint()),
        (&other_signer, &c, cc.fingerprint()),
    ] {
        let output = FirstEncoding::map(&(), source, &store.snapshot().unwrap()).unwrap();
        if source.get_handle() == a.get_handle() {
            a_output = Some(data(&output));
        }
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                key,
                first.handle(),
                (data(source), witness),
                data(&output),
            )))
            .unwrap();
    }
    let before = store.snapshot().unwrap();
    let lineage = load_lineage(&before, first).unwrap();
    let selected = BTreeSet::from([first.handle()]);
    let resolved = resolve_endorsed_lineage(&before, &lineage, &selected, None).unwrap();
    assert_eq!(resolved.support, support(root, std::slice::from_ref(&a)));
    assert_eq!(resolved.images.len(), 1);
    assert_eq!(
        resolved.images[&(first.handle(), data(&a))],
        BTreeSet::from([a_output.unwrap()]),
    );

    store.insert(CollectionRecord::Commit(cb)).unwrap();
    let after = store.snapshot().unwrap();
    let resolved = resolve_endorsed_lineage(&after, &lineage, &selected, None).unwrap();
    assert_eq!(resolved.support, support(root, &[a.clone(), b.clone()]));
    assert_eq!(resolved.images.len(), 2);

    // Complete coverage is not an excuse to stop scanning: this admitted,
    // closed claim conflicts with the already certified image of a.
    let wrong = FirstEncoding::map(&(), &b, &after).unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &signer,
            first.handle(),
            (data(&a), ca.fingerprint()),
            data(&wrong),
        )))
        .unwrap();
    assert!(matches!(
        resolve_endorsed_lineage(&store.snapshot().unwrap(), &lineage, &selected, None),
        Err(CollectionRealizationError::Resolution(reason)) if reason.contains("conflicting outputs")
    ));
}

#[test]
fn downstream_ensure_requires_an_existing_immediate_source_realization() {
    let (mut store, root, first, second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));

    let result = ensure_exact_resident::<_, SecondEncoding>(
        &mut store,
        second,
        &equation_signer(),
        &support,
    );
    assert!(matches!(
        result,
        Err(CollectionRealizationError::IncompleteCover { .. })
    ));
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

    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    ensure_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let (observed_support, cover) = attach_collection_exact(&snapshot, second, &support).unwrap();

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
    assert_ne!(second_derive.input(), data(&source));
}

#[test]
fn ordinary_attachment_reports_only_support_realized_in_its_snapshot() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    publish_root(&mut store, root, &left, 1);
    publish_root(&mut store, root, &right, 2);
    let left_support = support(root, std::slice::from_ref(&left));
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &left_support)
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let (observed, cover) = attach_collection(&snapshot, first).unwrap();
    assert_eq!(observed, left_support);
    assert_eq!(cover.len(), 1);
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
    assert_eq!(admitted.commits(&snapshot).unwrap().len(), 2);
}

#[test]
fn ensure_drops_every_residency_snapshot_and_stores_the_blob_before_derive() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut inner, root, &source, 31);
    let support = support(root, &[source]);
    let mut store = GuardStore::new(inner);

    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();

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
fn exact_ensure_acquires_explicit_foundational_support_without_want() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let metadata = inner.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
    inner
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &equation_signer(),
            root.handle(),
            data(&source),
            metadata,
        )))
        .unwrap();
    let support = support(root, std::slice::from_ref(&source));
    let mut store = GuardStore::new(inner);
    store.offer(&source);

    let snapshot = block_on(store.ensure_exact(first, &equation_signer(), &support)).unwrap();

    assert_eq!(store.acquired, vec![data(&source)]);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    let (observed, cover) = attach_collection_exact(&snapshot, first, &support).unwrap();
    assert_eq!(observed, support);
    assert_eq!(cover.len(), 1);
}

#[test]
fn exact_ensure_fetches_a_known_derive_output_without_recomputing() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let source_commit = publish_root(&mut inner, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));
    let output = FirstEncoding::map(&(), &source, &inner.snapshot().unwrap()).unwrap();
    let output_data = data(&output);
    let pending = CollectionRecord::Derive(CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        (
            data(&source),
            CollectionRecord::Commit(source_commit).fingerprint(),
        ),
        output_data,
    ));
    inner.insert(pending).unwrap();

    let mut store = GuardStore::new(inner);
    store.offer(&output);
    reset_mapping_calls();
    let snapshot = block_on(store.ensure_exact(first, &equation_signer(), &support)).unwrap();

    assert_eq!(store.acquired, vec![output_data]);
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert!(
        store.events.is_empty(),
        "acquisition must not publish algebra"
    );
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    let observed = snapshot.collection_exact(first, &support).unwrap();
    assert_eq!(observed.support().unwrap(), &support);
    assert_eq!(
        observed.cover().data_members().collect::<Vec<_>>(),
        vec![output_data],
    );
}

#[test]
fn exact_ensure_reendorses_a_resident_image_from_a_different_support_without_mapping() {
    let (mut inner, root, first, _second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let a_commit = publish_root(&mut inner, root, &a, 31);
    let b_commit = publish_root(&mut inner, root, &b, 31);
    // The same payload b has two genuine witnesses: its own COMMIT [B], and
    // join(a, b) = b [A, B]. No mapping result is invented for this fixture.
    assert_eq!(
        data(&crate::collection::simplearchive_union::join(&a, &b).unwrap()),
        data(&b),
    );
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), a_commit.fingerprint()),
        (data(&b), b_commit.fingerprint()),
        data(&b),
    );
    inner.insert(CollectionRecord::Merge(ab)).unwrap();
    let output = FirstEncoding::map(&(), &b, &inner.snapshot().unwrap()).unwrap();
    inner.put::<FirstEncoding, _>(output.clone()).unwrap();
    let previous = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&b), ab.fingerprint()),
        data(&output),
    );
    inner.insert(CollectionRecord::Derive(previous)).unwrap();
    let requested = support(root, std::slice::from_ref(&b));
    let before = inner.snapshot().unwrap();
    assert_eq!(
        before.collection(first).unwrap().support().unwrap(),
        &support(root, &[a, b.clone()]),
    );
    assert!(matches!(
        before.collection_exact(first, &requested),
        Err(CollectionRealizationError::IncompleteCover { .. })
    ));
    drop(before);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let after = block_on(store.ensure_exact(first, &signer, &requested)).unwrap();

    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    let selected = after.collection_exact(first, &requested).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    assert_eq!(
        selected.cover().data_members().collect::<Vec<_>>(),
        vec![data(&output)],
    );
    let published: Vec<_> = store
        .events
        .iter()
        .filter_map(|event| match event {
            WriteEvent::Insert(record) => Some(*record),
            WriteEvent::Put(_) => None,
        })
        .collect();
    let expected = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&b), b_commit.fingerprint()),
        data(&output),
    );
    assert_eq!(published, vec![CollectionRecord::Derive(expected)]);
    assert_eq!(
        after.record(previous.fingerprint()).unwrap(),
        Some(CollectionRecord::Derive(previous)),
    );
}

#[test]
fn exact_ensure_rejects_conflicting_images_before_reusing_a_pruned_support() {
    let (mut inner, root, first, _second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let a_commit = publish_root(&mut inner, root, &a, 31);
    let b_commit = publish_root(&mut inner, root, &b, 31);
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), a_commit.fingerprint()),
        (data(&b), b_commit.fingerprint()),
        data(&b),
    );
    inner.insert(CollectionRecord::Merge(ab)).unwrap();
    let right = FirstEncoding::map(&(), &b, &inner.snapshot().unwrap()).unwrap();
    let wrong = FirstEncoding::map(&(), &a, &inner.snapshot().unwrap()).unwrap();
    assert_ne!(data(&right), data(&wrong));
    for output in [&right, &wrong] {
        inner.put::<FirstEncoding, _>(output.clone()).unwrap();
        inner
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &signer,
                first.handle(),
                (data(&b), ab.fingerprint()),
                data(output),
            )))
            .unwrap();
    }
    let requested = support(root, std::slice::from_ref(&b));
    // Neither conflicting target claim has support [B]; both are [A, B].
    // The exact snapshot excludes them, but maintenance may otherwise reuse
    // their resident images under b's COMMIT witness.
    assert!(matches!(
        inner
            .snapshot()
            .unwrap()
            .collection_exact(first, &requested),
        Err(CollectionRealizationError::IncompleteCover { .. })
    ));
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    let error = match block_on(store.ensure_exact(first, &signer, &requested)) {
        Err(error) => error,
        Ok(_) => panic!("conflicting certified images must not be reused"),
    };

    assert!(matches!(
        error,
        CollectionRealizationError::Resolution(reason) if reason.contains("conflicting outputs")
    ));
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    assert!(store.events.is_empty(), "a conflict must publish nothing");
}

#[test]
fn exact_ensure_rejects_a_cold_conflicting_image_before_fetch_or_publication() {
    let (mut inner, root, first, _second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let a_commit = publish_root(&mut inner, root, &a, 31);
    let b_commit = publish_root(&mut inner, root, &b, 31);
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), a_commit.fingerprint()),
        (data(&b), b_commit.fingerprint()),
        data(&b),
    );
    inner.insert(CollectionRecord::Merge(ab)).unwrap();
    let right = FirstEncoding::map(&(), &b, &inner.snapshot().unwrap()).unwrap();
    let wrong = FirstEncoding::map(&(), &a, &inner.snapshot().unwrap()).unwrap();
    assert_ne!(data(&right), data(&wrong));
    // The existing [B] claim's image is cold; only the incompatible [A, B]
    // image is resident. Residency cannot make that image safe to re-endorse.
    inner.put::<FirstEncoding, _>(wrong.clone()).unwrap();
    for (witness, output) in [(b_commit.fingerprint(), &right), (ab.fingerprint(), &wrong)] {
        inner
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &signer,
                first.handle(),
                (data(&b), witness),
                data(output),
            )))
            .unwrap();
    }
    let requested = support(root, std::slice::from_ref(&b));
    let before = inner.snapshot().unwrap();
    assert!(!before.contains_blob(right.get_handle()).unwrap());
    assert!(before.contains_blob(wrong.get_handle()).unwrap());
    assert!(matches!(
        before.collection_exact(first, &requested),
        Err(CollectionRealizationError::IncompleteCover { .. })
    ));
    drop(before);
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    let error = match block_on(store.ensure_exact(first, &signer, &requested)) {
        Err(error) => error,
        Ok(_) => panic!("cold conflicting images must not be replaced by resident ones"),
    };

    assert!(matches!(
        error,
        CollectionRealizationError::Resolution(reason) if reason.contains("conflicting outputs")
    ));
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    assert!(store.events.is_empty(), "a conflict must publish nothing");
}

#[test]
fn passive_derived_snapshot_keeps_dangling_output_as_raw_evidence_only() {
    let (mut inner, root, first, _second) = collections();
    let source = archive(1, 1);
    let source_commit = publish_root(&mut inner, root, &source, 42);
    let support = support(root, std::slice::from_ref(&source));
    let output = FirstEncoding::map(&(), &source, &inner.snapshot().unwrap()).unwrap();
    let pending = CollectionRecord::Derive(CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        (
            data(&source),
            CollectionRecord::Commit(source_commit).fingerprint(),
        ),
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
    assert!(matches!(
        snapshot.collection_exact(first, &support),
        Err(CollectionRealizationError::IncompleteCover { .. })
    ));
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
    let source_commit = publish_root(&mut inner, root, &source, 31);
    let support = support(root, std::slice::from_ref(&source));
    let snapshot = inner.snapshot().unwrap();
    let output = FirstEncoding::map(&(), &source, &snapshot).unwrap();
    drop(snapshot);
    let output_data = data(&output);
    let pending = CollectionDerive::sign(
        &equation_signer(),
        first.handle(),
        (
            data(&source),
            CollectionRecord::Commit(source_commit).fingerprint(),
        ),
        output_data,
    );
    inner.insert(CollectionRecord::Derive(pending)).unwrap();
    drop(output);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let snapshot = block_on(store.maintain_exact(first, &equation_signer(), &support)).unwrap();

    assert_eq!(store.acquired, vec![output_data]);
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
    assert!(snapshot
        .metadata(Handle::<FirstEncoding>::from_hash(output_data))
        .unwrap()
        .is_some());
    let (observed, cover) = attach_collection_exact(&snapshot, first, &support).unwrap();
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
fn ordinary_derived_ensure_leaves_cold_source_records_for_explicit_root_acquisition() {
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

    let snapshot = block_on(store.ensure(first, &equation_signer())).unwrap();

    assert!(store.acquired.is_empty());
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    let observed = snapshot.collection(first).unwrap();
    assert!(observed.support().unwrap().is_empty());
    assert!(observed.cover().is_empty());
    drop(observed);
    drop(snapshot);

    // Acquisition belongs to the root. The subsequent downstream operation
    // observes its own immediate-source snapshot, including the concurrently
    // published member now that both inputs are resident and admitted.
    drop(block_on(store.ensure(root, &equation_signer())).unwrap());
    assert_eq!(store.acquired, vec![data(&source)]);
    assert!(store.inject_record_on_acquire.is_none());
    let snapshot = block_on(store.ensure(first, &equation_signer())).unwrap();
    let observed = snapshot.collection(first).unwrap();
    assert_eq!(
        observed.support().unwrap(),
        &support(root, &[source, concurrent])
    );
    assert_eq!(observed.cover().len(), 2);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
}

#[test]
fn root_ensure_hydrates_admitted_payloads_and_defers_concurrent_authority() {
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
    assert_eq!(store.acquired, vec![data(&descriptor), data(&first_source)]);
    assert_eq!(
        first_snapshot.collection(root).unwrap().support().unwrap(),
        &support(root, std::slice::from_ref(&first_source)),
        "a grant arriving during descriptor acquisition must not initiate more acquisition",
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
        &support(root, &[first_source, concurrent_source.clone()]),
    );
    assert_eq!(&store.acquired[2..], &[data(&concurrent_source)],);
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
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &equation_signer(),
            root.handle(),
            (data(&left), a.fingerprint()),
            (data(&right), b.fingerprint()),
            data(&joined),
        )))
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
fn root_ensure_exact_fetches_selected_payload_without_commits() {
    let (inner, root, _, _) = collections();
    let source = archive(35, 35);
    let requested = support(root, std::slice::from_ref(&source));
    let mut store = GuardStore::new(inner);
    store.offer(&source);

    let snapshot = block_on(store.ensure_exact(root, &equation_signer(), &requested)).unwrap();
    let selected = snapshot.collection_exact(root, &requested).unwrap();
    assert_eq!(selected.view::<TribleSet>().unwrap().len(), 1);
    assert!(snapshot.collection(root).unwrap().cover().is_empty());
    assert_eq!(store.acquired, vec![data(&source)]);
    assert!(snapshot.records().unwrap().next().is_none());
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    assert!(store.events.is_empty());
}

#[test]
fn root_maintenance_only_merges_and_warm_ensure_is_write_free() {
    let (mut inner, root, _, _) = collections();
    let left = archive(36, 36);
    let right = archive(37, 37);
    let requested = support(root, &[left.clone(), right.clone()]);
    publish_root(&mut inner, root, &left, 31);
    publish_root(&mut inner, root, &right, 31);
    let mut store = GuardStore::new(inner);

    let maintained = block_on(store.maintain_exact(root, &equation_signer(), &requested)).unwrap();
    assert_eq!(
        maintained
            .collection_exact(root, &requested)
            .unwrap()
            .cover()
            .len(),
        1
    );
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
    let ensured = block_on(store.ensure_exact(root, &equation_signer(), &requested)).unwrap();
    assert_eq!(
        ensured
            .collection_exact(root, &requested)
            .unwrap()
            .view::<TribleSet>()
            .unwrap()
            .len(),
        2
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

#[test]
fn maintenance_drops_every_residency_snapshot_and_stores_the_blob_before_merge() {
    let (mut inner, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut inner, root, blob, 31);
    }
    let support = support(root, &[left, right]);
    ensure_exact_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer(), &support)
        .unwrap();
    ensure_exact_resident::<_, SecondEncoding>(&mut inner, second, &equation_signer(), &support)
        .unwrap();
    let mut store = GuardStore::new(inner);

    maintain_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();

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
fn target_maintenance_reprobes_once_per_tier_not_per_carry() {
    const MEMBERS: usize = 8;

    let (mut inner, root, first, second) = collections();
    let members: Vec<_> = (0..MEMBERS)
        .map(|member| archive(member as u8 + 1, member as u8 + 1))
        .collect();
    for member in &members {
        publish_root(&mut inner, root, member, 31);
    }
    let support = support(root, &members);
    ensure_exact_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer(), &support)
        .unwrap();
    ensure_exact_resident::<_, SecondEncoding>(&mut inner, second, &equation_signer(), &support)
        .unwrap();

    let mut store = GuardStore::new(inner);
    maintain_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();

    let merges = store
        .events
        .iter()
        .filter(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Merge(_))))
        .count();
    assert_eq!(merges, MEMBERS - 1);
    assert_eq!(
        store.semantic_probes.load(Ordering::SeqCst),
        6,
        "one ensure probe, one source-guidance probe, and one target-resolution probe for each dyadic tier round",
    );

    let snapshot = store.inner.snapshot().unwrap();
    let (_, cover) = attach_collection_exact(&snapshot, second, &support).unwrap();
    assert_eq!(cover.len(), 1);
}

#[test]
fn failed_target_batch_preserves_every_published_prefix_carry() {
    for fail_insert in [false, true] {
        let (mut inner, root, first, second) = collections();
        let members: Vec<_> = (1..=4).map(|member| archive(member, member)).collect();
        for member in &members {
            publish_root(&mut inner, root, member, 31);
        }
        let support = support(root, &members);
        ensure_exact_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer(), &support)
            .unwrap();
        ensure_exact_resident::<_, SecondEncoding>(
            &mut inner,
            second,
            &equation_signer(),
            &support,
        )
        .unwrap();

        let mut store = GuardStore::new(inner);
        if fail_insert {
            store.reject_insert_at = Some(2);
        } else {
            store.reject_put_at = Some(2);
        }

        assert!(matches!(
            maintain_exact_resident::<_, SecondEncoding>(
                &mut store,
                second,
                &equation_signer(),
                &support
            ),
            Err(CollectionRealizationError::Storage { .. })
        ));
        assert_eq!(store.live.load(Ordering::SeqCst), 0);
        let merges = records(&mut store.inner)
            .into_iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Merge(merge) if merge.collection() == second.handle())
            })
            .count();
        assert_eq!(merges, 1, "the first target carry remains visible");
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
        let support = support(root, &[left, right]);
        let mut store = GuardStore::new(inner);
        if fail_insert {
            store.reject_insert_at = Some(2);
        } else {
            store.reject_put_at = Some(2);
        }

        assert!(matches!(
            ensure_exact_resident::<_, FirstEncoding>(
                &mut store,
                first,
                &equation_signer(),
                &support
            ),
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
    let support = support(root, &[source]);
    let before = store.snapshot().unwrap();
    FIRST_MAP_MISSING.set(true);

    let result =
        ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support);
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
    let left_witness = witnessed_input(&before, root.handle(), data(&left));
    let right_witness = witnessed_input(&before, root.handle(), data(&right));
    drop(before);
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &equation_signer(),
            root.handle(),
            left_witness,
            right_witness,
            data(&joined),
        )))
        .unwrap();
    let support = support(root, &[left.clone(), right.clone()]);
    reset_mapping_calls();
    FIRST_MAP_CAPACITY.replace(Some(data(&joined)));

    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    FIRST_MAP_CAPACITY.replace(None);

    assert_eq!(FIRST_MAP_CALLS.get(), 3);
    let inputs: std::collections::BTreeSet<_> = records(&mut store)
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) if derive.collection() == first.handle() => {
                Some(derive.input())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        inputs,
        std::collections::BTreeSet::from([data(&left), data(&right)])
    );
}

#[test]
fn warm_exact_ensure_is_a_zero_write_zero_algebra_observation() {
    let (mut store, root, first, _second) = collections();
    let source = archive(1, 1);
    publish_root(&mut store, root, &source, 31);
    let support = support(root, &[source]);
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();

    reset_mapping_calls();
    let before = store.snapshot().unwrap();
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    let after = store.snapshot().unwrap();
    assert!(after.changes_since(&before).is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
}

/// Produce a genuine two-hop endorsement, then replicate only the records and
/// bytes needed at the chosen boundary. The first-hop grant remains in the
/// replica but its definition does not; the root writer's proof is absent.
fn cold_source_authority_fixture(
    target_ready: bool,
) -> (
    GuardStore,
    Collection<SimpleArchive>,
    Collection<FirstEncoding>,
    Collection<SecondEncoding>,
    Support,
    Blob<SimpleArchive>,
) {
    let authority = SigningKey::from_bytes(&[90; 32]);
    let root_writer = SigningKey::from_bytes(&[91; 32]);
    let first_writer = SigningKey::from_bytes(&[92; 32]);
    let owner = equation_signer();
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
    staging
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(root.handle()),
            &authority,
            write_capability(),
            root_writer.verifying_key(),
        ))
        .unwrap();
    let first_proof = CapabilityProof::new(
        CapabilityResource::from(first.handle()),
        &authority,
        definition.get_handle(),
        first_writer.verifying_key(),
    );
    staging.insert_proof(first_proof.clone()).unwrap();
    let source = archive(44, 44);
    let commit = publish_root(&mut staging, root, &source, 91);
    let selected = support(root, std::slice::from_ref(&source));
    drop(block_on(staging.ensure_exact(first, &first_writer, &selected)).unwrap());
    drop(block_on(staging.ensure_exact(target, &owner, &selected)).unwrap());
    let realized = staging.snapshot().unwrap();
    let first_data = realized
        .collection(first)
        .unwrap()
        .cover()
        .data_members()
        .next()
        .unwrap();
    let target_data = realized
        .collection(target)
        .unwrap()
        .cover()
        .data_members()
        .next()
        .unwrap();
    let omitted = BTreeSet::from([
        commit.data(),
        Handle::<SimpleArchive>::to_hash(commit.metadata()),
        data(&definition),
        if target_ready {
            first_data
        } else {
            target_data
        },
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
        let record = record.unwrap();
        if target_ready || record.collection() != target.handle() {
            inner.insert(record).unwrap();
        }
    }
    inner.insert_proof(first_proof).unwrap();
    let observed = inner.snapshot().unwrap();
    assert!(!root
        .writer_is_admitted(&observed, root_writer.verifying_key())
        .unwrap());
    assert!(!first
        .writer_is_admitted(&observed, first_writer.verifying_key())
        .unwrap());
    assert_eq!(
        observed.collection(target).unwrap().support().unwrap(),
        &if target_ready {
            selected.clone()
        } else {
            root.cover([])
        },
    );
    assert!(!observed.contains_blob(source.get_handle()).unwrap());
    assert!(!observed.contains_blob(commit.metadata()).unwrap());
    assert!(!observed.contains_blob(definition.get_handle()).unwrap());
    (
        GuardStore::new(inner),
        root,
        first,
        target,
        selected,
        definition,
    )
}

#[test]
fn exact_warm_target_reuse_does_not_acquire_or_admit_its_source() {
    for maintain in [false, true] {
        for key in [equation_signer(), SigningKey::from_bytes(&[93; 32])] {
            let (mut store, _root, _first, target, selected, definition) =
                cold_source_authority_fixture(true);
            // If authority preparation crosses into the source, this available
            // definition makes that unnecessary acquisition observable.
            store.offer(&definition);
            reset_mapping_calls();
            let after = if maintain {
                block_on(store.maintain_exact(target, &key, &selected))
            } else {
                block_on(store.ensure_exact(target, &key, &selected))
            }
            .unwrap();
            if !maintain {
                assert_eq!(
                    *store.selected_collections.lock().unwrap(),
                    vec![BTreeSet::from([CollectionRecordSelector::Collection(
                        target.handle(),
                    )])],
                    "reuse authenticates the target, not its ancestral producers",
                );
            }
            assert_eq!(
                after.collection(target).unwrap().support().unwrap(),
                &selected
            );
            assert_eq!(after.wants().unwrap().count(), 0);
            assert!(store.acquired.is_empty());
            assert!(store.events.is_empty());
            assert_eq!(FIRST_MAP_CALLS.get(), 0);
            assert_eq!(SECOND_MAP_CALLS.get(), 0);
            assert_eq!(SECOND_JOIN_CALLS.get(), 0);
        }
    }
}

#[test]
fn exact_new_work_still_requires_the_immediate_source_grant_definition() {
    for available_definition in [false, true] {
        let (mut store, _root, _first, target, selected, definition) =
            cold_source_authority_fixture(false);
        if available_definition {
            store.offer(&definition);
        }
        reset_mapping_calls();
        let result = block_on(store.ensure_exact(target, &equation_signer(), &selected));
        assert_eq!(store.acquired, vec![data(&definition)]);
        assert_eq!(FIRST_MAP_CALLS.get(), 0, "never rebuild the source");
        if available_definition {
            let after = result.unwrap();
            assert_eq!(
                after.collection(target).unwrap().support().unwrap(),
                &selected
            );
            assert_eq!(SECOND_MAP_CALLS.get(), 1);
        } else {
            assert!(matches!(
                result,
                Err(CollectionRealizationError::IncompleteCover { .. })
            ));
            assert!(store.events.is_empty());
            assert_eq!(SECOND_MAP_CALLS.get(), 0);
        }
    }
}

#[test]
fn warm_exact_reuse_keeps_foundation_representation_and_mapping_checks() {
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
        let (mut store, _root, _first, target, selected, definition) =
            cold_source_authority_fixture(true);
        let unrelated = store
            .inner
            .collection("unrelated-support-foundation", policy())
            .unwrap();
        let foreign_support = unrelated.cover(
            selected
                .data_members()
                .map(Handle::<SimpleArchive>::from_hash),
        );
        store.offer(&definition);
        reset_mapping_calls();
        let wrong_foundation = if maintain {
            block_on(store.maintain_exact(target, &equation_signer(), &foreign_support))
        } else {
            block_on(store.ensure_exact(target, &equation_signer(), &foreign_support))
        };
        assert!(matches!(
            wrong_foundation,
            Err(CollectionRealizationError::InvalidCover(_)),
        ));

        let wrong_type = Collection::<FirstEncoding>::from_handle(target.handle());
        let wrong_representation = if maintain {
            block_on(store.maintain_exact(wrong_type, &equation_signer(), &selected))
        } else {
            block_on(store.ensure_exact(wrong_type, &equation_signer(), &selected))
        };
        assert!(matches!(
            wrong_representation,
            Err(CollectionRealizationError::Resolution(reason))
                if reason.contains("target descriptor has the wrong representation"),
        ));

        let wrong_mapping = if maintain {
            block_on(store.maintain_exact_with::<WrongSecondMapping>(
                target,
                &equation_signer(),
                &selected,
            ))
        } else {
            block_on(store.ensure_exact_with::<WrongSecondMapping>(
                target,
                &equation_signer(),
                &selected,
            ))
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
    publish_root(&mut inner, root, &source, 31);
    let support = support(root, &[source]);
    block_on(inner.ensure_exact(target, &owner, &support)).unwrap();
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    for maintain in [false, true] {
        let snapshot = if maintain {
            block_on(store.maintain_exact(target, &reader, &support))
        } else {
            block_on(store.ensure_exact(target, &reader, &support))
        }
        .unwrap();
        assert_eq!(
            snapshot
                .collection_exact(target, &support)
                .unwrap()
                .cover()
                .len(),
            1
        );
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
    publish_root(&mut inner, root, &source, 31);
    let support = support(root, &[source]);
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    for maintain in [false, true] {
        let result = if maintain {
            block_on(store.maintain_exact(target, &reader, &support))
        } else {
            block_on(store.ensure_exact(target, &reader, &support))
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
    for member in [&left, &right] {
        publish_root(&mut inner, root, member, 31);
    }
    let support = support(root, &[left.clone(), right.clone()]);
    block_on(inner.ensure_exact(first, &owner, &support)).unwrap();
    block_on(inner.ensure_exact(second, &owner, &support)).unwrap();
    let upper = crate::collection::simplearchive_union::join(&left, &right).unwrap();
    inner.put::<SimpleArchive, _>(upper.clone()).unwrap();
    let before = inner.snapshot().unwrap();
    let left_witness = witnessed_input(&before, root.handle(), data(&left));
    let right_witness = witnessed_input(&before, root.handle(), data(&right));
    drop(before);
    inner
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            root.handle(),
            left_witness,
            right_witness,
            data(&upper),
        )))
        .unwrap();
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    let snapshot = block_on(store.maintain_exact(first, &reader, &support)).unwrap();
    assert_eq!(
        snapshot
            .collection_exact(first, &support)
            .unwrap()
            .cover()
            .len(),
        2
    );
    drop(snapshot);
    assert!(store.events.is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);

    // The authorized source producer can pay for its upper image. A downstream
    // reader still must not join or republish it under an unauthorized key.
    drop(block_on(store.maintain_exact(first, &owner, &support)).unwrap());
    store.events.clear();
    reset_mapping_calls();
    let snapshot = block_on(store.maintain_exact(second, &reader, &support)).unwrap();
    assert_eq!(
        snapshot
            .collection_exact(second, &support)
            .unwrap()
            .cover()
            .len(),
        2
    );
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
}

#[test]
fn existing_target_support_is_not_mapped_again_when_support_grows() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let left_support = support(root, std::slice::from_ref(&left));
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &left_support)
        .unwrap();

    reset_mapping_calls();
    let full_support = support(root, &[left, right]);
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &full_support)
        .unwrap();
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
}

#[test]
fn resident_source_upper_is_mapped_instead_of_its_finer_children() {
    let (mut store, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let support = support(root, &[left, right]);
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let (_, first_cover) = attach_collection_exact(&snapshot, first, &support).unwrap();
    let mut children = first_cover.members().map(|handle| {
        snapshot
            .get::<Blob<FirstEncoding>, FirstEncoding>(handle)
            .unwrap()
    });
    let low = children.next().unwrap();
    let high = children.next().unwrap();
    let low_witness = witnessed_input(&snapshot, first.handle(), data(&low));
    let high_witness = witnessed_input(&snapshot, first.handle(), data(&high));
    drop(snapshot);
    let upper = join_first(&low, &high).unwrap();
    store.put::<FirstEncoding, _>(upper.clone()).unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &equation_signer(),
            first.handle(),
            low_witness,
            high_witness,
            data(&upper),
        )))
        .unwrap();

    reset_mapping_calls();
    ensure_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();
    assert_eq!(SECOND_MAP_CALLS.get(), 1);
    assert!(records(&mut store).iter().any(|record| matches!(
        record,
        CollectionRecord::Derive(derive)
            if derive.collection() == second.handle() && derive.input() == data(&upper)
    )));
}

#[test]
fn optional_target_dependency_keeps_the_finer_cover() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let support = support(root, &[left, right]);

    maintain_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let (_, cover) = attach_collection_exact(&snapshot, first, &support).unwrap();
    assert_eq!(cover.len(), 2);
    drop(snapshot);
    let first_result = store.snapshot().unwrap();
    maintain_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
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
fn source_guidance_maps_only_the_resident_coarsest_upper_and_repeats_without_work() {
    let (mut inner, root, first, _second) = collections();
    let members = [archive(1, 1), archive(2, 2), archive(3, 3)];
    for member in &members {
        publish_root(&mut inner, root, member, 31);
    }
    let support = support(root, &members);
    ensure_exact_resident::<_, FirstEncoding>(&mut inner, first, &equation_signer(), &support)
        .unwrap();
    let mut store = GuardStore::new(inner);

    reset_mapping_calls();
    block_on(store.maintain_exact(first, &equation_signer(), &support)).unwrap();
    assert!(
        store.events.is_empty(),
        "missing source unions stay missing"
    );
    assert!(
        store.acquired.is_empty(),
        "optional source coarsening never fetches"
    );
    assert_eq!(FIRST_MAP_CALLS.get(), 0);

    let intermediate =
        crate::collection::simplearchive_union::join(&members[0], &members[1]).unwrap();
    let upper = crate::collection::simplearchive_union::join(&intermediate, &members[2]).unwrap();
    // A resident upper outside the requested foundational support must not
    // become a coarsening candidate merely because its bytes and record exist.
    let outside = archive(4, 4);
    publish_root(&mut store.inner, root, &outside, 31);
    let overreach = crate::collection::simplearchive_union::join(&upper, &outside).unwrap();
    for member in [&intermediate, &upper, &outside, &overreach] {
        store.inner.put::<SimpleArchive, _>(member.clone()).unwrap();
    }
    for (low, high, result) in [
        (&members[0], &members[1], &intermediate),
        (&intermediate, &members[2], &upper),
        (&upper, &outside, &overreach),
    ] {
        let before = store.inner.snapshot().unwrap();
        let low_witness = witnessed_input(&before, root.handle(), data(low));
        let high_witness = witnessed_input(&before, root.handle(), data(high));
        drop(before);
        store
            .inner
            .insert(CollectionRecord::Merge(CollectionMerge::sign(
                &equation_signer(),
                root.handle(),
                low_witness,
                high_witness,
                data(result),
            )))
            .unwrap();
    }

    let after = block_on(store.maintain_exact(first, &equation_signer(), &support)).unwrap();
    assert_eq!(
        after
            .collection_exact(first, &support)
            .unwrap()
            .cover()
            .len(),
        1
    );
    drop(after);
    assert_eq!(
        FIRST_MAP_CALLS.get(),
        1,
        "skip the historical intermediate image"
    );
    assert_eq!(
        store.events.len(),
        2,
        "one target blob and one target DERIVE only"
    );
    assert!(matches!(store.events[0], WriteEvent::Put(_)));
    assert!(
        matches!(store.events[1], WriteEvent::Insert(CollectionRecord::Derive(derive))
        if derive.collection() == first.handle() && derive.input() == data(&upper))
    );
    assert!(store.acquired.is_empty());

    store.events.clear();
    reset_mapping_calls();
    block_on(store.maintain_exact(first, &equation_signer(), &support)).unwrap();
    assert!(store.events.is_empty());
    assert_eq!(
        FIRST_MAP_CALLS.get(),
        0,
        "the already resident upper image is reused"
    );
}

#[test]
fn target_maintenance_publishes_only_horizontal_target_merges() {
    let (mut store, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let support = support(root, &[left, right]);
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    maintain_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let (_, cover) = attach_collection_exact(&snapshot, second, &support).unwrap();
    assert_eq!(cover.len(), 1);
    let all = records(&mut store);
    assert!(all.iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge) if merge.collection() == second.handle()
    )));
    assert!(!all.iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge) if merge.collection() == root.handle()
    )));
}

#[test]
fn target_maintenance_reendorses_a_resident_upper_without_joining_again() {
    let (mut inner, root, first, second) = collections();
    let signer = equation_signer();
    let a = archive(1, 1);
    let b = crate::collection::simplearchive_union::join(&a, &archive(2, 2)).unwrap();
    let c = archive(3, 3);
    let a_commit = publish_root(&mut inner, root, &a, 31);
    let b_commit = publish_root(&mut inner, root, &b, 31);
    let c_commit = publish_root(&mut inner, root, &c, 31);
    let ab = CollectionMerge::sign(
        &signer,
        root.handle(),
        (data(&a), a_commit.fingerprint()),
        (data(&b), b_commit.fingerprint()),
        data(&b),
    );
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
        (data(&b), b_commit.fingerprint()),
        data(&first_b),
    );
    let first_ab_record = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&b), ab.fingerprint()),
        data(&first_b),
    );
    let first_c_record = CollectionDerive::sign(
        &signer,
        first.handle(),
        (data(&c), c_commit.fingerprint()),
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
        (data(&first_b), first_b_record.fingerprint()),
        data(&x),
    );
    let x_ab = CollectionDerive::sign(
        &signer,
        second.handle(),
        (data(&first_b), first_ab_record.fingerprint()),
        data(&x),
    );
    let y_c = CollectionDerive::sign(
        &signer,
        second.handle(),
        (data(&first_c), first_c_record.fingerprint()),
        data(&y),
    );
    for record in [x_b, x_ab, y_c] {
        inner.insert(CollectionRecord::Derive(record)).unwrap();
    }
    let z_bc = CollectionMerge::sign(
        &signer,
        second.handle(),
        (data(&x), x_b.fingerprint()),
        (data(&y), y_c.fingerprint()),
        data(&z),
    );
    inner.insert(CollectionRecord::Merge(z_bc)).unwrap();
    // x carries [A, B] as well as [B], while this particular z certificate
    // carries only [B, C]. Both resident blobs must remain selected until the
    // producer endorses join(x[A, B], z[B, C]) = z [A, B, C]. Their payload
    // order already proves that equality, so no new join is needed.
    let requested = support(root, &[a, b, c]);
    assert_eq!(x.bytes.len().ilog2(), z.bytes.len().ilog2());
    let before = inner.snapshot().unwrap();
    let selected = before.collection_exact(second, &requested).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(&x), data(&z)]),
    );
    drop(selected);
    drop(before);

    let mut store = GuardStore::new(inner);
    reset_mapping_calls();
    let after = block_on(store.maintain_exact(second, &signer, &requested)).unwrap();

    assert_eq!(FIRST_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    assert_eq!(SECOND_JOIN_CALLS.get(), 0);
    assert!(store.acquired.is_empty());
    let selected = after.collection_exact(second, &requested).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
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
    let [CollectionRecord::Merge(endorsement)] = published.as_slice() else {
        panic!("maintenance must publish exactly one target MERGE: {published:?}");
    };
    assert_eq!(endorsement.collection(), second.handle());
    assert_eq!(endorsement.result(), data(&z));
    let (low_witness, high_witness) = endorsement.input_witnesses();
    assert_eq!(
        BTreeSet::from([low_witness, high_witness]),
        BTreeSet::from([x_ab.fingerprint(), z_bc.fingerprint()]),
    );
    assert_eq!(
        after.record(z_bc.fingerprint()).unwrap(),
        Some(CollectionRecord::Merge(z_bc)),
    );
}

#[test]
fn target_maintenance_is_deterministic_and_repeatedly_idempotent() {
    let (mut store, root, first, second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let support = support(root, &[left, right]);
    ensure_exact_resident::<_, FirstEncoding>(&mut store, first, &equation_signer(), &support)
        .unwrap();
    maintain_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();
    let first_result = store.snapshot().unwrap();

    maintain_exact_resident::<_, SecondEncoding>(&mut store, second, &equation_signer(), &support)
        .unwrap();
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
            .insert(CollectionRecord::Merge(CollectionMerge::sign(
                &equation_signer(),
                collection.handle(),
                (commits[low].data(), commits[low].fingerprint()),
                (commits[high].data(), commits[high].fingerprint()),
                data(output),
            )))
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
    let [a, b, z, _] = &blobs;
    let requested = support(collection, &blobs);
    let snapshot = store.snapshot().unwrap();
    let selected = snapshot.collection_exact(collection, &requested).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    // Starting with Z [b,z], a forward support-repair walk adds A [a], then
    // B [a,b,d] for d. B makes A redundant without enlarging the support.
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(b), data(z)]),
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
    let after = block_on(store.maintain_exact(collection, &equation_signer(), &requested)).unwrap();
    let selected = after.collection_exact(collection, &requested).unwrap();
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
    let after = block_on(store.maintain_exact(collection, &equation_signer(), &requested)).unwrap();
    assert_eq!(
        after
            .collection_exact(collection, &requested)
            .unwrap()
            .support()
            .unwrap(),
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
fn support_repair_does_not_clip_a_wider_certificate_to_the_requested_support() {
    let (mut store, collection, blobs) = redundant_support_fixture();
    let [a, b, z, _] = &blobs;
    let requested = support(collection, &[a.clone(), b.clone(), z.clone()]);
    let snapshot = store.snapshot().unwrap();
    let selected = snapshot.collection_exact(collection, &requested).unwrap();
    assert_eq!(selected.support().unwrap(), &requested);
    // B's [a,d] certificate is not a [a] certificate when d is unselected.
    // Reusing B [b] and Z [b,z] therefore cannot justify removing A [a].
    assert_eq!(
        selected.cover().data_members().collect::<BTreeSet<_>>(),
        BTreeSet::from([data(a), data(z)]),
    );
    assert_eq!(
        selected.view::<TribleSet>().unwrap(),
        TribleSet::try_from_blob(z.clone()).unwrap(),
    );
}

#[test]
fn equal_payload_commit_does_not_restart_completed_target_maintenance() {
    let (mut store, collection, blobs) = redundant_support_fixture();
    let requested = support(collection, &blobs);
    drop(block_on(store.maintain_exact(collection, &equation_signer(), &requested)).unwrap());
    // A different signer attests B, not a new foundational payload. This must
    // not make the old fine member or its redundant carries reappear.
    publish_root(&mut store, collection, &blobs[1], 32);
    let before = records(&mut store);
    let mut store = GuardStore::new(store);
    let after = block_on(store.maintain_exact(collection, &equation_signer(), &requested)).unwrap();
    assert_eq!(
        after
            .collection_exact(collection, &requested)
            .unwrap()
            .support()
            .unwrap(),
        &requested
    );
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    drop(after);
    assert_eq!(records(&mut store.inner), before);
}
