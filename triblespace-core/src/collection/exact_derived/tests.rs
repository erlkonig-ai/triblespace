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
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        FIRST_JOIN_CALLS.set(FIRST_JOIN_CALLS.get() + 1);
        if FIRST_JOIN_MISSING.get() {
            // A missing optional target-join dependency must leave the exact
            // fine cover intact, not cause construction back in SimpleArchive.
            return Err(CollectionOperationError::MissingDependency(
                crate::inline::Inline::new([0xDD; 32]),
            ));
        }
        join_first(low, high)
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
    static FIRST_JOIN_CALLS: Cell<usize> = const { Cell::new(0) };
    static SECOND_MAP_CALLS: Cell<usize> = const { Cell::new(0) };
    static SECOND_JOIN_CALLS: Cell<usize> = const { Cell::new(0) };
    static FIRST_MAP_MISSING: Cell<bool> = const { Cell::new(false) };
    static FIRST_JOIN_MISSING: Cell<bool> = const { Cell::new(false) };
    /// A nonzero salt makes the first mapping add one fact of its own to
    /// every image: a derivation that does not reproduce bit for bit.
    static FIRST_SALT: Cell<u8> = const { Cell::new(0) };
    /// Whether every mapping call takes the next salt: a derivation that
    /// never reproduces.
    static FIRST_SALT_ROTATES: Cell<bool> = const { Cell::new(false) };
    static FIRST_MAP_CAPACITY: RefCell<Option<CollectionData>> = const { RefCell::new(None) };
    static FIRST_MAP_FATAL: RefCell<Option<CollectionData>> = const { RefCell::new(None) };
    /// Sources the first mapping refuses, like `FIRST_MAP_FATAL`, for
    /// tests that need several.
    static FIRST_MAP_REFUSED: RefCell<BTreeSet<CollectionData>> = const { RefCell::new(BTreeSet::new()) };
    /// A blob the first mapping needs for a source: that source maps only
    /// once the blob's bytes are here, and asks for it until then.
    static FIRST_MAP_NEEDS: RefCell<BTreeMap<CollectionData, CollectionData>> = const { RefCell::new(BTreeMap::new()) };
    /// Whether this host is outside the class a pinned test mapping is
    /// computed on.
    static FIRST_PINNED_ELSEWHERE: Cell<bool> = const { Cell::new(false) };
    /// Every source the first mapping was called on, in order.
    static FIRST_MAP_LOG: RefCell<Vec<CollectionData>> = const { RefCell::new(Vec::new()) };
}

fn reset_mapping_calls() {
    FIRST_MAP_CALLS.set(0);
    FIRST_JOIN_CALLS.set(0);
    SECOND_MAP_CALLS.set(0);
    SECOND_JOIN_CALLS.set(0);
    FIRST_MAP_MISSING.set(false);
    FIRST_JOIN_MISSING.set(false);
    FIRST_SALT.set(0);
    FIRST_SALT_ROTATES.set(false);
    FIRST_MAP_CAPACITY.replace(None);
    FIRST_MAP_FATAL.replace(None);
    FIRST_MAP_REFUSED.replace(BTreeSet::new());
    FIRST_MAP_NEEDS.replace(BTreeMap::new());
    FIRST_PINNED_ELSEWHERE.set(false);
    FIRST_MAP_LOG.replace(Vec::new());
}

/// The first mapping's image of `source` under `salt`: its facts, and one
/// more when the salt is not zero, followed by `0xA5`.
fn salted_image(source: &Blob<SimpleArchive>, salt: u8) -> Blob<FirstEncoding> {
    let mut archive = source.clone();
    if salt != 0 {
        let mut facts = TribleSet::try_from_blob(source.clone()).unwrap();
        facts.insert(&row(200, salt));
        archive = facts.to_blob();
    }
    let mut bytes = archive.bytes.as_ref().to_vec();
    bytes.push(0xA5);
    Blob::new(bytes.into())
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
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        FIRST_MAP_CALLS.set(FIRST_MAP_CALLS.get() + 1);
        FIRST_MAP_LOG.with_borrow_mut(|log| log.push(data(source)));
        if FIRST_MAP_MISSING.get() {
            return Err(CollectionOperationError::MissingDependency(
                crate::inline::Inline::new([0xEE; 32]),
            ));
        }
        if let Some(needed) = FIRST_MAP_NEEDS.with_borrow(|needs| needs.get(&data(source)).copied())
        {
            let here = reader
                .metadata(Handle::<UnknownBlob>::from_hash(needed))
                .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
                .is_some();
            if !here {
                return Err(CollectionOperationError::MissingDependency(needed));
            }
        }
        if FIRST_MAP_CAPACITY.with_borrow(|blocked| *blocked == Some(data(source))) {
            return Err(CollectionOperationError::Capacity(
                "injected source capacity".to_owned(),
            ));
        }
        if FIRST_MAP_FATAL.with_borrow(|refused| *refused == Some(data(source)))
            || FIRST_MAP_REFUSED.with_borrow(|refused| refused.contains(&data(source)))
        {
            return Err(CollectionOperationError::Fatal(
                "injected source refusal".to_owned(),
            ));
        }
        let salt = FIRST_SALT.get();
        if FIRST_SALT_ROTATES.get() {
            FIRST_SALT.set(salt + 1);
        }
        Ok(salted_image(source, salt))
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

/// A root and two chained views in a store hosted by [`equation_signer`],
/// the key these tests maintain with: its merges are the ones the store
/// believes.
fn collections() -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<FirstEncoding>,
    Collection<SecondEncoding>,
) {
    collections_as(&equation_signer())
}

/// The same fixture in a store hosted by `host`.
fn collections_as(
    host: &SigningKey,
) -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<FirstEncoding>,
    Collection<SecondEncoding>,
) {
    let mut store = MemoryRepo::for_host(host.verifying_key());
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
    /// Blobs whose bytes are here and do not read, as damaged bytes a
    /// pile's index still lists: resident, with no metadata.
    damaged: Arc<Mutex<BTreeSet<CollectionData>>>,
}

impl Clone for GuardSnapshot {
    fn clone(&self) -> Self {
        self.live.fetch_add(1, Ordering::SeqCst);
        Self {
            inner: self.inner.clone(),
            live: Arc::clone(&self.live),
            semantic_probes: Arc::clone(&self.semantic_probes),
            selected_collections: Arc::clone(&self.selected_collections),
            damaged: Arc::clone(&self.damaged),
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
        let member = Handle::<S>::to_hash(handle);
        if self.damaged.lock().unwrap().contains(&member) {
            return Ok(None);
        }
        self.inner.metadata(handle)
    }

    /// The index lists a damaged blob: it is resident without reading.
    fn resident(
        &self,
        handles: &crate::patch::PATCH<32, crate::patch::IdentitySchema, ()>,
    ) -> Result<crate::patch::PATCH<32, crate::patch::IdentitySchema, ()>, Self::MetaError> {
        self.inner.resident(handles)
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
    /// Blobs whose fetch fails outright, as a peer endpoint that cannot
    /// start, or a fetched blob that cannot be kept, would.
    acquire_fails: BTreeSet<CollectionData>,
    acquired: Vec<CollectionData>,
    /// Blobs whose bytes here do not read ([`GuardSnapshot`]); fetching one
    /// a holder has restores it.
    damaged: Arc<Mutex<BTreeSet<CollectionData>>>,
    /// How many writes `events` held when each acquisition was made.
    acquired_at: Vec<usize>,
    inject_record_on_acquire: Option<CollectionRecord>,
    inject_proof_on_acquire: Option<CapabilityProof>,
    /// What another writer publishes right after this store's first DERIVE:
    /// records, and the bytes to store beside them, as a host deriving the
    /// same collection at the same time would.
    concurrent: Vec<(CollectionRecord, Option<Bytes>)>,
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
            acquire_fails: BTreeSet::new(),
            acquired: Vec::new(),
            damaged: Arc::new(Mutex::new(BTreeSet::new())),
            acquired_at: Vec::new(),
            inject_record_on_acquire: None,
            inject_proof_on_acquire: None,
            concurrent: Vec::new(),
        }
    }

    fn offer<E: BlobEncoding>(&mut self, blob: &Blob<E>)
    where
        Handle<E>: InlineEncoding,
    {
        self.acquirable.insert(data(blob), blob.bytes.clone());
    }

    /// Damage a resident blob: its bytes stay listed and no longer read.
    fn damage<E: BlobEncoding>(&mut self, blob: &Blob<E>)
    where
        Handle<E>: InlineEncoding,
    {
        self.damaged.lock().unwrap().insert(data(blob));
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
        self.acquired_at.push(self.events.len());
        if self.acquire_fails.contains(&member) {
            return std::future::ready(Err(GuardStoreError::Injected("acquire")));
        }
        let result = match self.acquirable.get(&member).cloned() {
            Some(bytes) => {
                self.damaged.lock().unwrap().remove(&member);
                self.inner
                    .put::<UnknownBlob, _>(bytes.clone())
                    .map_err(|error| GuardStoreError::Backend(error.to_string()))
                    .map(|_| Some(bytes))
            }
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

    /// It stands for a store that asks other holders: what it was offered.
    fn acquires_remotely(&self) -> bool {
        true
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
            damaged: Arc::clone(&self.damaged),
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
            .map_err(|error| GuardStoreError::Backend(error.to_string()))?;
        if matches!(record, CollectionRecord::Derive(_)) {
            for (record, bytes) in std::mem::take(&mut self.concurrent) {
                if let Some(bytes) = bytes {
                    self.inner
                        .put::<UnknownBlob, _>(bytes)
                        .map_err(|error| GuardStoreError::Backend(error.to_string()))?;
                }
                self.inner
                    .insert(record)
                    .map_err(|error| GuardStoreError::Backend(error.to_string()))?;
            }
        }
        Ok(())
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
/// carried in the first view, and derived as leaves in the second: all a
/// maintenance of the second view has left to do is carry its own leaves.
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
    assert_eq!(merges, 1, "the second view's eight leaves, carried");
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
        // Two groups of eight leaves: maintaining the second view carries
        // them into two MERGEs, one blob and one MERGE each, and the second
        // write of either kind fails.
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
        assert_eq!(merges, 1, "the first carried MERGE remains visible");
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

/// A derived collection maps foundations only. The root's MERGE of two
/// commits is never mapped -- a capacity refusal armed on the joined node is
/// never reached -- and two leaves are below the fan-in, so the view stands
/// on its two leaves.
#[test]
fn a_derived_collection_never_maps_its_sources_merge() {
    let (mut store, root, first, _second) = collections();
    let left = archive(1, 1);
    let right = archive(2, 2);
    for blob in [&left, &right] {
        publish_root(&mut store, root, blob, 31);
    }
    let joined = crate::collection::simplearchive_union::join(&left, &right).unwrap();
    store.put::<SimpleArchive, _>(joined.clone()).unwrap();
    store
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
    reset_mapping_calls();
    FIRST_MAP_CAPACITY.replace(Some(data(&joined)));

    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    FIRST_MAP_CAPACITY.replace(None);

    assert_eq!(FIRST_MAP_CALLS.get(), 2, "the two leaves alone are mapped");
    assert_eq!(FIRST_JOIN_CALLS.get(), 0, "two leaves are below the fan-in");
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

    impl DeriveMapping for WrongSecondMapping {
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

/// Only a key the target admits derives, and neither path computes or
/// publishes anything for one it does not: the per-write `ensure` says the
/// key owes a leaf it may not publish, and `maintain` -- whose work for such
/// a key is the carry, here with nothing to carry -- reports nothing.
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

    let result = block_on(store.ensure(target, &reader));
    assert!(matches!(result,
        Err(CollectionRealizationError::UnauthorizedProducer { collection })
            if collection == target.handle()
    ));
    drop(block_on(store.maintain(target, &reader)).unwrap());
    assert!(store.events.is_empty());
    assert!(store.acquired.is_empty());
    assert_eq!(FIRST_MAP_CALLS.get(), 0);
}

/// A merge needs the host's key and no WRITE; only a new leaf needs WRITE.
/// The reader hosts this store but may write neither view: it derives
/// nothing and still carries both views' leaves into its own merges, and
/// once WRITE on the first view is granted it derives there too.
#[test]
fn a_host_without_write_carries_a_derived_collection_and_derives_nothing() {
    let owner = equation_signer();
    let reader = SigningKey::from_bytes(&[32; 32]);
    let private_write = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    // The reader is this store's host: its merges are the ones believed.
    let mut inner = MemoryRepo::for_host(reader.verifying_key());
    let root = inner.collection("read-only-maintenance", policy()).unwrap();
    let first = inner
        .derive::<FirstEncoding>(root, (), private_write.clone())
        .unwrap();
    let second = inner
        .derive::<SecondEncoding>(first, (), private_write)
        .unwrap();
    // The owner wrote eight members and derived both views' leaves.
    let members: Vec<_> = (1..=crate::collection::MERGE_FAN_IN as u8)
        .map(|member| archive(member, member))
        .collect();
    for member in &members {
        publish_root(&mut inner, root, member, 31);
    }
    block_on(inner.ensure(first, &owner)).unwrap();
    block_on(inner.ensure(second, &owner)).unwrap();
    // One more, the reader's own, with no leaf in either view.
    let own = archive(20, 20);
    publish_root(&mut inner, root, &own, 32);
    let mut store = GuardStore::new(inner);
    reset_mapping_calls();

    // Maintaining carries the owner's eight leaves into one MERGE of its
    // own and is done: the reader's own foundation is the per-write
    // ensure's to report, not maintenance's.
    drop(block_on(store.maintain(first, &reader)).unwrap());
    assert!(matches!(
        block_on(store.ensure(first, &reader)),
        Err(CollectionRealizationError::UnauthorizedProducer { collection })
            if collection == first.handle()
    ));
    assert_eq!(FIRST_MAP_CALLS.get(), 0, "nothing is derived without WRITE");
    assert!(store.acquired.is_empty());
    let carried: Vec<CollectionMerge> = records(&mut store.inner)
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) if merge.collection() == first.handle() => Some(merge),
            _ => None,
        })
        .collect();
    assert_eq!(carried.len(), 1);
    assert_eq!(
        carried[0].public_key().raw,
        reader.verifying_key().to_bytes()
    );
    assert_eq!(
        carried[0].inputs().iter().copied().collect::<BTreeSet<_>>(),
        members.iter().map(first_image).collect()
    );
    assert!(!store
        .events
        .iter()
        .any(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Derive(_)))));
    let snapshot = store.inner.snapshot().unwrap();
    assert_eq!(snapshot.collection(first).unwrap().cover().len(), 1);
    drop(snapshot);

    // The second view owes the reader nothing of its own: it is carried
    // with no error at all.
    drop(block_on(store.maintain(second, &reader)).unwrap());
    assert_eq!(SECOND_MAP_CALLS.get(), 0);
    let snapshot = store.inner.snapshot().unwrap();
    assert_eq!(snapshot.collection(second).unwrap().cover().len(), 1);
    drop(snapshot);

    // WRITE on `first` is the only thing that held its leaf back.
    store
        .inner
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(first.handle()),
            &owner,
            write_capability(),
            reader.verifying_key(),
        ))
        .unwrap();
    drop(block_on(store.maintain(first, &reader)).unwrap());
    assert_eq!(FIRST_MAP_CALLS.get(), 1);
    assert!(records(&mut store.inner).iter().any(|record| matches!(
        record,
        CollectionRecord::Derive(derive)
            if derive.collection() == first.handle()
                && derive.input() == crate::collection::SourceLocator::of(data(&own).raw)
    )));
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
fn optional_target_dependency_keeps_the_finer_cover() {
    let (mut store, root, first, _second) = collections();
    for member in 1..=crate::collection::MERGE_FAN_IN as u8 {
        publish_root(&mut store, root, &archive(member, member), 31);
    }
    reset_mapping_calls();
    // The first view's join names a dependency nobody holds: the eight
    // leaves stay the view's cover, and nothing is built back in the root.
    FIRST_JOIN_MISSING.set(true);

    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    assert_eq!(FIRST_JOIN_CALLS.get(), 1, "the join was tried once");
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        snapshot.collection(first).unwrap().cover().len(),
        crate::collection::MERGE_FAN_IN
    );
    drop(snapshot);
    let first_result = store.snapshot().unwrap();
    maintain_resident::<_, FirstEncoding>(&mut store, first, &equation_signer()).unwrap();
    FIRST_JOIN_MISSING.set(false);
    assert!(store
        .snapshot()
        .unwrap()
        .changes_since(&first_result)
        .is_empty());
    assert!(!records(&mut store).iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(merge)
            if merge.collection() == root.handle() || merge.collection() == first.handle()
    )));
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
    // Carrying the second view publishes into the second view only: nothing
    // is written into its source or the root on the way.
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
    // second view's own MERGE already consumed them, so there is nothing to
    // carry. It is not re-joined, and a is left to whoever derives it into
    // the first view.
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
    let mut store = MemoryRepo::for_host(equation_signer().verifying_key());
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

/// Host carries, leaves scheduled by leaf, derived collections carrying
/// their own lattices, and freshness.
mod lattice_v2 {
    use super::*;

    use crate::collection::test_support::{TestImage, TestImageTwo};
    use crate::collection::{
        maintain_downstream, simplearchive_union, CollectionHandle, CoverageRead, SourceLocator,
        MERGE_FAN_IN,
    };

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// The parent fixture hosted by key 41, the maintainer most of these
    /// tests carry with.
    fn collections() -> (
        MemoryRepo,
        Collection<SimpleArchive>,
        Collection<FirstEncoding>,
        Collection<SecondEncoding>,
    ) {
        collections_as(&key(41))
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
    fn one_host_merges_every_held_commit_and_absent_payloads_sit_out() {
        let (mut store, root, _, _) = collections();
        let host = key(41);
        let mut own: BTreeSet<_> = (0..4)
            .map(|entity| own_commit(&mut store, root, 41, entity))
            .collect();
        // 42's payloads are elsewhere: the carry neither reads nor waits for
        // them.
        let mut absent: BTreeSet<_> = (0..4)
            .map(|entity| foreign_commit(&mut store, root, 42, entity))
            .collect();
        // Eight nodes share tier 0, but only four are held.
        block_on(store.maintain(root, &host)).unwrap();
        assert!(merges_in(&mut store, root.handle()).is_empty());

        own.extend((4..8).map(|entity| own_commit(&mut store, root, 41, entity)));
        block_on(store.maintain(root, &host)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].public_key(), public(41));
        assert_eq!(inputs(&merges[0]), own);
        let first_tree = merges[0].result();
        assert_eq!(
            frontier(&mut store, root.handle()),
            absent.iter().copied().chain([first_tree]).collect()
        );

        // 42's payloads land and 42 writes four more: the host merges 42's
        // eight held commits as readily as its own, into its own tree.
        for entity in 0..4 {
            store.put::<SimpleArchive, _>(payload(42, entity)).unwrap();
        }
        absent.extend((4..8).map(|entity| own_commit(&mut store, root, 42, entity)));
        block_on(store.maintain(root, &host)).unwrap();
        let merges = merges_in(&mut store, root.handle());
        assert_eq!(merges.len(), 2);
        assert!(merges.iter().all(|merge| merge.public_key() == public(41)));
        let second_tree = merges
            .iter()
            .find(|merge| merge.result() != first_tree)
            .expect("the host carried 42's commits");
        assert_eq!(inputs(second_tree), absent);
        assert_eq!(
            frontier(&mut store, root.handle()),
            BTreeSet::from([first_tree, second_tree.result()])
        );

        // Two tier-1 nodes: a fixed point, and a key that is not the host
        // has nothing to publish here either.
        let before = records(&mut store).len();
        block_on(store.maintain(root, &host)).unwrap();
        block_on(store.maintain(root, &key(42))).unwrap();
        assert_eq!(records(&mut store).len(), before);
    }

    #[test]
    fn a_held_node_inside_another_is_absorbed_and_a_foreign_merge_is_no_node() {
        let (mut store, root, _, _) = collections();
        let owner = key(41);
        let commits: Vec<_> = (0..8)
            .map(|entity| own_commit(&mut store, root, 41, entity))
            .collect();
        block_on(store.maintain(root, &owner)).unwrap();
        let wide = merges_in(&mut store, root.handle())[0].result();

        // The host grouped two members again elsewhere: a node inside the
        // wide one.
        let narrow = simplearchive_union::join(&payload(41, 0), &payload(41, 1)).unwrap();
        let narrow =
            Handle::<SimpleArchive>::to_hash(store.put::<SimpleArchive, _>(narrow).unwrap());
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&owner, root.handle(), [commits[0], commits[1]], narrow)
                    .unwrap(),
            ))
            .unwrap();
        // Another key's merge of two more members, its bytes resident: not
        // folded, so it is on nobody's frontier and nothing absorbs it.
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
            BTreeSet::from([wide, narrow])
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
        assert_eq!(frontier(&mut store, root.handle()), BTreeSet::from([wide]));
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
    fn a_view_publishes_the_image_of_an_empty_commit_as_a_leaf() {
        let owner = key(41);
        let mut store = MemoryRepo::for_host(owner.verifying_key());
        let root = store.collection("receipts", policy()).unwrap();
        let images = store.derive::<TestImage>(root, (), policy()).unwrap();
        store
            .commit(
                root,
                &owner,
                crate::macros::entity! { crate::metadata::name: "something" },
            )
            .unwrap();
        let empty = store.commit(root, &owner, Fragment::empty()).unwrap();
        block_on(store.ensure(images, &owner)).unwrap();

        let leaves = derives_in(&mut store, images.handle());
        assert_eq!(leaves.len(), 2);
        let snapshot = store.snapshot().unwrap();
        let image = TestImage::image(&TribleSet::new().to_blob());
        let leaf = leaves
            .iter()
            .find(|leaf| leaf.input() == SourceLocator::of(empty.data().raw))
            .expect("the empty commit has its leaf");
        assert_eq!(leaf.output(), data(&image));
        let view = snapshot.collection(images).unwrap();
        let source = snapshot.collection(root).unwrap();
        assert!(view.missing_from(&source).unwrap().is_empty());
        assert_eq!(view.support().unwrap().len(), 2);
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
    fn a_derived_collection_carries_its_own_leaves_exactly_once_across_passes() {
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
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].public_key(), public(41));
        assert_eq!(
            inputs(&carried[0]),
            leaves.iter().map(|leaf| leaf.output()).collect()
        );
        // The join of the eight images, not a mapping of the root's merged
        // node; by homomorphism the two are the same bytes.
        let snapshot = store.snapshot().unwrap();
        let merged_blob: Blob<SimpleArchive> = snapshot
            .get(Handle::<SimpleArchive>::from_hash(merged))
            .unwrap();
        drop(snapshot);
        assert_eq!(carried[0].result(), first_image(&merged_blob));
        assert_eq!(FIRST_MAP_CALLS.get(), 8, "the leaves alone are mapped");
        assert_eq!(FIRST_JOIN_CALLS.get(), 7, "one eight-way join");
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([carried[0].result()])
        );

        reset_mapping_calls();
        let before = records(&mut store).len();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(FIRST_JOIN_CALLS.get(), 0);
    }

    /// The derived carry tiers exactly as a root's does, over leaves alone:
    /// the source is never carried here. A join that names a dependency
    /// nobody holds leaves every group's finer cover standing; once the join
    /// can be made, the next pass carries 64 leaves through two tiers.
    #[test]
    fn the_derived_carry_tiers_its_leaves_and_a_declined_join_keeps_the_finer_cover() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        let owner = key(41);
        for entity in 0..64 {
            own_commit(&mut store, root, 41, entity);
        }
        FIRST_JOIN_MISSING.set(true);
        block_on(store.maintain(first, &owner)).unwrap();
        FIRST_JOIN_MISSING.set(false);
        assert_eq!(derives_in(&mut store, first.handle()).len(), 64);
        assert!(merges_in(&mut store, first.handle()).is_empty());
        assert_eq!(frontier(&mut store, first.handle()).len(), 64);
        assert!(merges_in(&mut store, root.handle()).is_empty());

        reset_mapping_calls();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 9, "eight merges of eight, then one of those");
        assert!(carried
            .iter()
            .all(|merge| merge.inputs().len() == MERGE_FAN_IN));
        let top = frontier(&mut store, first.handle());
        assert_eq!(top.len(), 1);
        let snapshot = store.snapshot().unwrap();
        let coverage =
            CoverageRead::coverage(&snapshot, &BTreeSet::from([first.handle()])).unwrap();
        let top = *top.iter().next().unwrap();
        assert_eq!(coverage.of(first.handle(), top).unwrap().len(), 64);
        assert!(merges_in(&mut store, root.handle()).is_empty());
    }

    /// Realizes the test images through their canonical mappings.
    struct TestRealizer;

    impl<S> crate::collection::RealizeDerived<S> for TestRealizer
    where
        S: crate::repo::Store + crate::repo::async_store::AsyncBlobStoreAcquire + Send,
    {
        async fn realize(
            &mut self,
            store: &mut S,
            derived: &crate::collection::Derived,
            signer: &SigningKey,
            upkeep: crate::collection::Upkeep,
        ) -> Result<crate::collection::Realized, CollectionRealizationError> {
            if derived.representation == <TestImage as MetaDescribe>::id() {
                crate::collection::realize_as::<S, TestImage>(store, derived, signer, upkeep).await
            } else if derived.representation == <TestImageTwo as MetaDescribe>::id() {
                crate::collection::realize_as::<S, TestImageTwo>(store, derived, signer, upkeep)
                    .await
            } else {
                Ok(crate::collection::Realized::Unknown)
            }
        }

        async fn realize_attached(
            &mut self,
            _store: &mut S,
            _attached: &crate::collection::Attached,
            _signer: &SigningKey,
            _upkeep: crate::collection::Upkeep,
        ) -> Result<crate::collection::Realized, CollectionRealizationError> {
            Ok(crate::collection::Realized::Unknown)
        }
    }

    #[test]
    fn a_chain_is_maintained_upstream_first_in_one_pass() {
        let owner = key(41);
        let mut store = MemoryRepo::for_host(owner.verifying_key());
        let root = store.collection("facts", policy()).unwrap();
        let raw = store.derive::<TestImage>(root, (), policy()).unwrap();
        let accelerated = store.derive::<TestImageTwo>(raw, (), policy()).unwrap();
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
            &mut TestRealizer,
        ))
        .unwrap();
        assert_eq!(report.realized, vec![raw.handle(), accelerated.handle()]);

        // The second hop's leaves name the first hop's own foundations, and
        // each hop carries its own eight leaves into one merge of its own.
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
        let raw_carried = merges_in(&mut store, raw.handle());
        let accelerated_carried = merges_in(&mut store, accelerated.handle());
        assert_eq!(raw_carried.len(), 1);
        assert_eq!(accelerated_carried.len(), 1);
        assert_eq!(
            inputs(&accelerated_carried[0]),
            accelerated_leaves
                .iter()
                .map(|leaf| leaf.output())
                .collect()
        );
        assert_eq!(
            frontier(&mut store, accelerated.handle()),
            BTreeSet::from([accelerated_carried[0].result()])
        );

        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(accelerated).unwrap();
        let facts: TribleSet = view.view().unwrap();
        let expected: TribleSet = (0..8).map(|entity| row(entity + 1, 41)).collect();
        assert_eq!(facts, expected);
        let raw_view = snapshot.collection(raw).unwrap();
        let source = snapshot.collection(root).unwrap();
        assert!(raw_view.missing_from(&source).unwrap().is_empty());
        assert!(view.missing_from(&raw_view).unwrap().is_empty());
    }
    /// Any key the view admits may derive, but only the store's host
    /// carries: another key's carry would publish merges nothing here
    /// believes, and another key's MERGE claims about the view's leaves are
    /// never folded.
    #[test]
    fn a_derived_carry_is_the_hosts_alone() {
        let owner = key(41);
        let mut store = MemoryRepo::for_host(owner.verifying_key());
        // The owner roots the root's WRITE and grants it to 42; 43 is
        // admitted nowhere. The view admits every writer.
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
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        own_commit(&mut store, root, 42, 0);
        let images: Vec<CollectionData> = (0..8)
            .map(|entity| first_image(&payload(41, entity)))
            .collect();
        let leaves: BTreeSet<CollectionData> = images
            .iter()
            .copied()
            .chain([first_image(&payload(42, 0))])
            .collect();

        // 42 derives every foundation without a usable leaf, not only its
        // own, and is refused before it publishes a merge.
        let result = block_on(store.maintain(first, &key(42)));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::HostMismatch { host: Some(host), signer })
                    if host == public(41) && signer == public(42)
            ),
            "{:?}",
            result.err()
        );
        let derived = derives_in(&mut store, first.handle());
        assert_eq!(derived.len(), 9);
        assert!(derived.iter().all(|leaf| leaf.public_key() == public(42)));
        assert!(merges_in(&mut store, first.handle()).is_empty());

        // Claims about the view's leaves the host never made: that one leaf
        // absorbed another, and that two join into a third. Neither key is
        // the store's host, so none is folded.
        for signer in [43, 42] {
            for (pair, result) in [
                ([images[0], images[1]], images[0]),
                ([images[2], images[3]], images[4]),
            ] {
                store
                    .insert(CollectionRecord::Merge(
                        CollectionMerge::sign(&key(signer), first.handle(), pair, result).unwrap(),
                    ))
                    .unwrap();
            }
        }
        assert_eq!(frontier(&mut store, first.handle()), leaves);

        // The host carries the nine leaves itself, whoever derived them: the
        // eight lowest into one MERGE of its own.
        block_on(store.maintain(first, &owner)).unwrap();
        let carried: Vec<CollectionMerge> = merges_in(&mut store, first.handle())
            .into_iter()
            .filter(|merge| merge.public_key() == public(41))
            .collect();
        assert_eq!(carried.len(), 1);
        let lowest: BTreeSet<CollectionData> = leaves.iter().copied().take(MERGE_FAN_IN).collect();
        assert_eq!(inputs(&carried[0]), lowest);
        let rest = *leaves.iter().last().unwrap();
        assert_eq!(
            frontier(&mut store, first.handle()),
            BTreeSet::from([carried[0].result(), rest])
        );
    }

    #[test]
    fn a_derived_collection_in_a_roots_encoding_carries_only_through_its_mapping() {
        struct Identity;

        impl DeriveMapping for Identity {
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
        // Eight own leaves in one tier. The root's carry, which binds no
        // mapping, refuses the view rather than join it by a join its
        // mapping may not name.
        let before = records(&mut store);
        let result = block_on(store.maintain(copy, &owner));
        assert!(
            matches!(result, Err(CollectionRealizationError::InvalidCover(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(records(&mut store), before);

        // Through its mapping the view carries its eight leaves into one
        // merge of its own.
        block_on(store.maintain_with::<Identity>(copy, &owner)).unwrap();
        let carried = merges_in(&mut store, copy.handle());
        assert_eq!(carried.len(), 1);
        let payloads: Vec<_> = (0..8).map(|entity| payload(41, entity)).collect();
        let union = simplearchive_union::join_all(&payloads).unwrap();
        assert_eq!(carried[0].result(), data(&union));
        assert_eq!(
            frontier(&mut store, copy.handle()),
            BTreeSet::from([data(&union)])
        );
    }

    /// A derived join may return one of its inputs' bytes: the eighth leaf
    /// holds everything the other seven do. That merge consumes the seven and
    /// keeps the eighth, with no mapping beyond the leaves.
    #[test]
    fn a_derived_join_that_returns_one_of_its_leaves_consumes_the_rest() {
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
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].result(), first_image(&wide));
        assert_eq!(
            inputs(&carried[0]),
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

    /// The derived carry reads the view's own lattice and nothing else.
    /// Here the source's payloads are all elsewhere, and so are the results
    /// of the host's two merges over them (R = A+B = C+D shaped): another
    /// key derived the eight leaves and replication delivered them. The host
    /// carries them with no fetch and no mapping, and leaves the source as
    /// it is.
    #[test]
    fn the_derived_carry_never_reads_the_source() {
        reset_mapping_calls();
        let host = key(41);
        let (mut inner, root, first, _) = collections();
        let commits: Vec<CollectionData> = (0..8)
            .map(|entity| foreign_commit(&mut inner, root, 42, entity))
            .collect();
        for (pair, result) in [
            ([commits[0], commits[1]], data(&archive(210, 1))),
            ([commits[2], commits[3]], data(&archive(210, 1))),
        ] {
            inner
                .insert(CollectionRecord::Merge(
                    CollectionMerge::sign(&host, root.handle(), pair, result).unwrap(),
                ))
                .unwrap();
        }
        let mut images = BTreeSet::new();
        for entity in 0..8 {
            let source = payload(42, entity);
            let image = salted_image(&source, 0);
            images.insert(data(&image));
            inner.put::<FirstEncoding, _>(image.clone()).unwrap();
            inner
                .insert(CollectionRecord::Derive(CollectionDerive::sign(
                    &key(42),
                    first.handle(),
                    SourceLocator::of(data(&source).raw),
                    data(&image),
                )))
                .unwrap();
        }
        let source_before = frontier(&mut inner, root.handle());
        let mut store = GuardStore::new(inner);

        drop(block_on(store.maintain(first, &host)).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        let carried = merges_in(&mut store.inner, first.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(inputs(&carried[0]), images);
        assert!(store.events.iter().all(|event| match event {
            WriteEvent::Insert(record) => record.collection() == first.handle(),
            WriteEvent::Put(_) => true,
        }));
        assert_eq!(frontier(&mut store.inner, root.handle()), source_before);
        let snapshot = store.inner.snapshot().unwrap();
        for commit in &commits {
            assert!(!snapshot
                .contains_blob(Handle::<SimpleArchive>::from_hash(*commit))
                .unwrap());
        }
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
    fn two_hosts_racing_on_an_absent_owners_foundations_converge_on_one_support() {
        // A bounded race: 41 and 42 each maintain their own replica of one
        // state while 43 is away, then the replicas are united, as `cat`
        // does. 43 holds eight nodes, so each host merges them into its own
        // tree: join is idempotent, commutative and associative, so the two
        // trees stand for the same set and neither needs the other's.
        let replica = |host: u8| {
            let (mut store, root, first, _) = collections_as(&key(host));
            own_commit(&mut store, root, 41, 0);
            own_commit(&mut store, root, 42, 0);
            for entity in 0..8 {
                own_commit(&mut store, root, 43, entity);
            }
            (store, root, first)
        };
        let (mut left, root, first) = replica(41);
        let (mut right, right_root, right_first) = replica(42);
        assert_eq!(
            (right_root.handle(), right_first.handle()),
            (root.handle(), first.handle())
        );
        for (store, racer) in [(&mut left, 41), (&mut right, 42)] {
            block_on(store.maintain(root, &key(racer))).unwrap();
            block_on(store.maintain(first, &key(racer))).unwrap();
            // Each host merged eight of the ten held commits, 43's included,
            // derived all ten leaves and carried eight of them in the view.
            let merges = merges_in(store, root.handle());
            assert_eq!(merges.len(), 1);
            assert_eq!(merges[0].public_key(), public(racer));
            assert_eq!(merges[0].inputs().len(), MERGE_FAN_IN);
            let carried = merges_in(store, first.handle());
            assert_eq!(carried.len(), 1);
            assert_eq!(carried[0].public_key(), public(racer));
        }
        let alone = frontier(&mut left, root.handle());
        assert_eq!(alone.len(), 3);
        // The same eight inputs join to the same bytes whoever signs.
        assert_eq!(frontier(&mut right, root.handle()), alone);
        let left_view = frontier(&mut left, first.handle());

        let (from_left, from_right) = (records(&mut left), records(&mut right));
        for record in from_right {
            left.insert(record).unwrap();
        }
        for record in from_left {
            right.insert(record).unwrap();
        }

        // Each host still believes only its own merges: the other's are in
        // the store and fold into nothing, so each frontier is its own.
        assert_eq!(merges_in(&mut left, root.handle()).len(), 2);
        assert_eq!(frontier(&mut left, root.handle()), alone);
        assert_eq!(frontier(&mut right, root.handle()), alone);
        assert_eq!(frontier(&mut left, first.handle()), left_view);
        // Every foundation has a leaf from each racer, and both leaves name
        // the same image: a derive is a function.
        let leaves = derives_in(&mut left, first.handle());
        assert_eq!(leaves.len(), 20);
        let mut outputs = std::collections::BTreeMap::<_, BTreeSet<_>>::new();
        for leaf in &leaves {
            outputs
                .entry(leaf.input())
                .or_default()
                .insert(leaf.output());
        }
        assert_eq!(outputs.len(), 10);
        assert!(outputs.values().all(|images| images.len() == 1));
        for store in [&mut left, &mut right] {
            let snapshot = store.snapshot().unwrap();
            assert!(snapshot
                .collection(first)
                .unwrap()
                .missing_from(&snapshot.collection(root).unwrap())
                .unwrap()
                .is_empty());
        }

        // Converged: another pass by either host publishes nothing, and
        // neither stalls on the other's merges.
        let before = (records(&mut left).len(), records(&mut right).len());
        for (store, racer) in [(&mut left, 41), (&mut right, 42)] {
            block_on(store.maintain(root, &key(racer))).unwrap();
            block_on(store.maintain(first, &key(racer))).unwrap();
        }
        assert_eq!(
            (records(&mut left).len(), records(&mut right).len()),
            before
        );
    }

    #[test]
    fn a_foreign_foundation_the_mapping_refuses_is_its_owners_lag_not_this_keys_failure() {
        // Review finding, 2026-09-26: a Fatal or capacity refusal on another
        // owner's foundation must not fail this key's pass, nor be reported
        // as this key's lag. Until derived collections carried their own
        // leaves, the host's merge holding a refused foundation could not be
        // mirrored and the view's leaves stayed unjoined; the view now joins
        // them whichever source merge holds the refusals -- inside the
        // host's one merge of eight, or beside it -- and reads the same.
        let mut views = Vec::new();
        for inside in [true, false] {
            reset_mapping_calls();
            let (mut store, root, first, _) = collections();
            for entity in 0..8 {
                own_commit(&mut store, root, 41, entity);
            }
            if !inside {
                block_on(store.maintain(root, &key(41))).unwrap();
            }
            let refused = own_commit(&mut store, root, 42, 1);
            let too_big = own_commit(&mut store, root, 42, 2);
            let fine = own_commit(&mut store, root, 42, 3);
            FIRST_MAP_FATAL.replace(Some(refused));
            FIRST_MAP_CAPACITY.replace(Some(too_big));

            block_on(store.maintain(root, &key(41))).unwrap();
            block_on(store.maintain(first, &key(41))).unwrap();

            // The pass succeeds, and every foundation but the two the
            // mapping refused has a leaf: the refusals are 42's lag.
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
            let root_merges = merges_in(&mut store, root.handle());
            assert_eq!(root_merges.len(), 1);
            let merged = inputs(&root_merges[0]);
            if inside {
                assert!(merged.contains(&refused) || merged.contains(&too_big));
            } else {
                assert!(!merged.contains(&refused) && !merged.contains(&too_big));
            }

            // The view joins its nine leaves: the eight lowest in one MERGE.
            let leaves: BTreeSet<CollectionData> = (0..8)
                .map(|entity| first_image(&payload(41, entity)))
                .chain([first_image(&payload(42, 3))])
                .collect();
            let carried = merges_in(&mut store, first.handle());
            assert_eq!(carried.len(), 1);
            assert_eq!(
                inputs(&carried[0]),
                leaves.iter().copied().take(MERGE_FAN_IN).collect()
            );
            let view = frontier(&mut store, first.handle());
            assert_eq!(
                view,
                BTreeSet::from([carried[0].result(), *leaves.iter().last().unwrap()])
            );

            // Another pass is quiet and still succeeds.
            let before = records(&mut store).len();
            block_on(store.maintain(first, &key(41))).unwrap();
            assert_eq!(records(&mut store).len(), before);
            views.push(view);
        }
        assert_eq!(
            views[0], views[1],
            "the source's merges do not shape the view"
        );
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

    /// The host may not write the collection -- WRITE is 40's, granted to
    /// 42 and 43 -- and still merges the eight held commits those three
    /// keys signed into one MERGE of its own: a merge needs the host's key,
    /// not WRITE. Two more commits whose payloads are elsewhere sit out at
    /// no cost: nothing is acquired for them.
    #[test]
    fn the_carry_merges_eight_held_foundations_of_mixed_signers_into_one_merge() {
        let host = key(41);
        let mut inner = MemoryRepo::for_host(host.verifying_key());
        let root = inner
            .collection(
                "mixed-signers",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(key(40).verifying_key()),
                ),
            )
            .unwrap();
        for grantee in [42, 43] {
            inner
                .insert_proof(CapabilityProof::new(
                    CapabilityResource::from(root.handle()),
                    &key(40),
                    write_capability(),
                    key(grantee).verifying_key(),
                ))
                .unwrap();
        }
        let held: BTreeSet<CollectionData> = [
            (40, 0),
            (40, 1),
            (40, 2),
            (42, 0),
            (42, 1),
            (42, 2),
            (43, 0),
            (43, 1),
        ]
        .into_iter()
        .map(|(signer, entity)| own_commit(&mut inner, root, signer, entity))
        .collect();
        let absent: BTreeSet<CollectionData> = (3..5)
            .map(|entity| foreign_commit(&mut inner, root, 43, entity))
            .collect();
        let snapshot = inner.snapshot().unwrap();
        assert!(!root
            .writer_is_admitted(&snapshot, host.verifying_key())
            .unwrap());
        drop(snapshot);
        assert_eq!(frontier(&mut inner, root.handle()).len(), 10);

        let mut store = GuardStore::new(inner);
        drop(block_on(store.maintain(root, &host)).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        let merges = merges_in(&mut store.inner, root.handle());
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].public_key(), public(41));
        assert_eq!(inputs(&merges[0]), held);
        assert_eq!(
            frontier(&mut store.inner, root.handle()),
            absent.iter().copied().chain([merges[0].result()]).collect()
        );
        // The frontier still stands for every believed commit.
        let snapshot = store.inner.snapshot().unwrap();
        let coverage = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()])).unwrap();
        let (support, _) = coverage.frontier_support(root.handle());
        let support: BTreeSet<CollectionData> = support
            .iter_ordered()
            .map(|raw| Inline::new(*raw))
            .collect();
        assert_eq!(support, held.union(&absent).copied().collect());
    }

    /// A frontier node whose bytes are not here is skipped by the carry
    /// itself: the operation finishes without naming it missing, which is
    /// the only thing that would make the acquiring loop fetch and run the
    /// operation again. So a host holding commit records without their
    /// payloads -- another key's, or its own whose payload is elsewhere --
    /// makes no acquisition and no restart.
    #[test]
    fn a_frontier_node_whose_bytes_are_elsewhere_costs_no_acquisition_and_no_restart() {
        let host = key(41);
        let (mut inner, root, _, _) = collections();
        for entity in 0..8 {
            own_commit(&mut inner, root, 41, entity);
        }
        let absent = foreign_commit(&mut inner, root, 42, 0);
        // The host's own commit, its payload elsewhere: the carry used to ask
        // for exactly this one.
        let own_absent = foreign_commit(&mut inner, root, 41, 9);
        let mut store = GuardStore::new(inner);

        let result = {
            let mut operation = OperationFrontier::new(store.snapshot().unwrap());
            crate::collection::maintenance::carry_root(&mut store, root, &host, &mut operation)
        };
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        let merges = merges_in(&mut store.inner, root.handle());
        assert_eq!(merges.len(), 1);
        assert!(!merges[0].inputs().contains(&absent));
        assert!(!merges[0].inputs().contains(&own_absent));

        // Through the acquiring loop, on this pass and the next.
        drop(block_on(store.maintain(root, &host)).unwrap());
        drop(block_on(store.maintain(root, &host)).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        assert_eq!(merges_in(&mut store.inner, root.handle()).len(), 1);
        let after = frontier(&mut store.inner, root.handle());
        assert!(after.contains(&absent));
        assert!(after.contains(&own_absent));
    }

    /// A carry signing with a key whose merges the store does not fold would
    /// publish merges nothing believes, see the frontier unmoved, and report
    /// a stall. It is refused, naming both keys, before anything is
    /// published. With nothing to merge, the key does not matter.
    #[test]
    fn a_carry_signing_with_a_key_that_is_not_the_host_is_an_error_not_a_stall() {
        let (mut inner, root, _, _) = collections();
        for entity in 0..8 {
            own_commit(&mut inner, root, 42, entity);
        }
        let mut store = GuardStore::new(inner);
        let error = block_on(store.maintain(root, &key(42)))
            .err()
            .expect("another key's carry is refused");
        assert!(
            matches!(
                error,
                CollectionRealizationError::HostMismatch { host: Some(host), signer }
                    if host == public(41) && signer == public(42)
            ),
            "{error}"
        );
        assert!(store.events.is_empty());
        assert!(merges_in(&mut store.inner, root.handle()).is_empty());

        // A store with no host believes no merge; carrying into it is the
        // same error.
        let mut keyless = MemoryRepo::default();
        let root = keyless.collection("root", policy()).unwrap();
        for entity in 0..8 {
            own_commit(&mut keyless, root, 41, entity);
        }
        let error = block_on(keyless.maintain(root, &key(41)))
            .err()
            .expect("a carry into a store without a host is refused");
        assert!(
            matches!(
                error,
                CollectionRealizationError::HostMismatch { host: None, signer }
                    if signer == public(41)
            ),
            "{error}"
        );
        assert!(merges_in(&mut keyless, root.handle()).is_empty());

        // Seven held nodes: no merge to publish, so no host is needed.
        let mut quiet = MemoryRepo::default();
        let root = quiet.collection("root", policy()).unwrap();
        for entity in 0..7 {
            own_commit(&mut quiet, root, 41, entity);
        }
        drop(block_on(quiet.maintain(root, &key(41))).unwrap());
        assert!(merges_in(&mut quiet, root.handle()).is_empty());
    }

    /// A host merge result whose bytes are gone -- here, bytes this store
    /// never held -- is never joined and never fetched. Its inputs are
    /// consumed, so it stays on the frontier, and a reader descends it to
    /// those inputs. A held node with the same support absorbs it without
    /// reading its bytes, and the frontier narrows to the held node.
    #[test]
    fn a_host_merge_result_whose_bytes_are_gone_is_descended_until_a_held_node_absorbs_it() {
        let host = key(41);
        let (mut inner, root, _, _) = collections();
        let commits: Vec<CollectionData> = (0..8)
            .map(|entity| own_commit(&mut inner, root, 41, entity))
            .collect();
        let gone = data(&archive(200, 41));
        inner
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&host, root.handle(), commits.iter().copied(), gone).unwrap(),
            ))
            .unwrap();
        let mut store = GuardStore::new(inner);
        assert_eq!(
            frontier(&mut store.inner, root.handle()),
            BTreeSet::from([gone])
        );

        drop(block_on(store.maintain(root, &host)).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        assert!(store.events.is_empty());
        assert_eq!(
            frontier(&mut store.inner, root.handle()),
            BTreeSet::from([gone])
        );
        let snapshot = store.inner.snapshot().unwrap();
        let attached = snapshot.collection(root).unwrap();
        assert_eq!(attached.cover().len(), MERGE_FAN_IN);
        assert_eq!(attached.view::<TribleSet>().unwrap().len(), MERGE_FAN_IN);
        drop(attached);
        drop(snapshot);

        // The same eight joined again, with the joined bytes here: two
        // frontier nodes with one support, one of them held.
        let payloads: Vec<_> = (0..8).map(|entity| payload(41, entity)).collect();
        let union = simplearchive_union::join_all(&payloads).unwrap();
        let held = data(&union);
        store.inner.put::<SimpleArchive, _>(union).unwrap();
        store
            .inner
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&host, root.handle(), commits.iter().copied(), held).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            frontier(&mut store.inner, root.handle()),
            BTreeSet::from([gone, held])
        );

        drop(block_on(store.maintain(root, &host)).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        let absorptions: Vec<_> = merges_in(&mut store.inner, root.handle())
            .into_iter()
            .filter(|merge| merge.result() == held && merge.inputs().len() == 2)
            .collect();
        assert_eq!(absorptions.len(), 1);
        assert_eq!(inputs(&absorptions[0]), BTreeSet::from([gone, held]));
        assert_eq!(
            frontier(&mut store.inner, root.handle()),
            BTreeSet::from([held])
        );
    }

    /// The first view's mapping, pinned to a class of host: elsewhere it
    /// cannot be computed, and must never be run.
    struct PinnedFirst(CanonicalDerivation<FirstEncoding>);

    impl DeriveMapping for PinnedFirst {
        type Source = SimpleArchive;
        type Target = FirstEncoding;

        fn fragment(&self) -> Fragment {
            self.0.fragment()
        }

        fn bind(source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
            CanonicalDerivation::<FirstEncoding>::bind(source, target).map(Self)
        }

        fn computable_here(&self) -> bool {
            !FIRST_PINNED_ELSEWHERE.get()
        }

        fn map<R>(
            &self,
            source: &Blob<Self::Source>,
            reader: &R,
        ) -> Result<Blob<Self::Target>, CollectionOperationError>
        where
            R: StoreRead,
        {
            assert!(
                self.computable_here(),
                "a pinned mapping is never run off its class"
            );
            self.0.map(source, reader)
        }
    }

    /// A host outside the class a mapping is pinned to derives nothing
    /// through it, raises no error for it, and still carries the view: the
    /// leaves a host of the class derived arrive by replication.
    #[test]
    fn a_host_that_cannot_compute_a_pinned_mapping_derives_nothing_and_still_carries() {
        reset_mapping_calls();
        let host = key(41);
        let (mut store, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut store, root, 42, entity);
        }
        block_on(store.ensure_with::<PinnedFirst>(first, &key(42))).unwrap();
        let own = own_commit(&mut store, root, 41, 0);
        reset_mapping_calls();
        FIRST_PINNED_ELSEWHERE.set(true);

        block_on(store.ensure_with::<PinnedFirst>(first, &host)).unwrap();
        block_on(store.maintain_with::<PinnedFirst>(first, &host)).unwrap();
        FIRST_PINNED_ELSEWHERE.set(false);
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert!(derives_in(&mut store, first.handle())
            .iter()
            .all(|leaf| leaf.public_key() == public(42)));
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].public_key(), public(41));
        assert_eq!(
            inputs(&carried[0]),
            (0..8)
                .map(|entity| first_image(&payload(42, entity)))
                .collect()
        );
        let missing = |store: &mut MemoryRepo| -> BTreeSet<CollectionData> {
            let snapshot = store.snapshot().unwrap();
            let view = snapshot.collection(first).unwrap();
            let source = snapshot.collection(root).unwrap();
            view.missing_from(&source).unwrap().data_members().collect()
        };
        assert_eq!(missing(&mut store), BTreeSet::from([own]));

        // On a host of the class the next pass derives the rest.
        block_on(store.maintain_with::<PinnedFirst>(first, &host)).unwrap();
        assert_eq!(FIRST_MAP_CALLS.get(), 1);
        assert!(missing(&mut store).is_empty());
    }

    /// A DERIVE is a relation: two leaves for one locator, from runs that
    /// disagree, are both believed, both on the frontier, both named by
    /// `leaf_outputs`; freshness answers their foundation, and the carry
    /// joins them with the rest.
    #[test]
    fn two_leaves_of_one_locator_are_both_believed_and_joined() {
        reset_mapping_calls();
        let host = key(41);
        let (mut store, root, first, _) = collections();
        for entity in 0..7 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.ensure(first, &host)).unwrap();
        let twice = payload(41, 6);
        let locator = SourceLocator::of(data(&twice).raw);
        let other = salted_image(&twice, 9);
        store.put::<FirstEncoding, _>(other.clone()).unwrap();
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &key(42),
                first.handle(),
                locator,
                data(&other),
            )))
            .unwrap();
        let both = BTreeSet::from([first_image(&twice), data(&other)]);

        let snapshot = store.snapshot().unwrap();
        let coverage =
            CoverageRead::coverage(&snapshot, &BTreeSet::from([first.handle()])).unwrap();
        assert_eq!(
            coverage
                .leaf_outputs(first.handle(), locator)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            both
        );
        let view = snapshot.collection(first).unwrap();
        assert_eq!(view.support().unwrap().len(), 8);
        assert!(view
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
        drop((view, coverage, snapshot));
        assert!(both.is_subset(&frontier(&mut store, first.handle())));
        assert_eq!(frontier(&mut store, first.handle()).len(), MERGE_FAN_IN);

        // Eight leaves, two of them one foundation's: one MERGE joins them,
        // and nothing is derived again.
        reset_mapping_calls();
        block_on(store.maintain(first, &host)).unwrap();
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(derives_in(&mut store, first.handle()).len(), 8);
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 1);
        assert!(both.is_subset(&inputs(&carried[0])));
        let snapshot = store.snapshot().unwrap();
        let view = snapshot.collection(first).unwrap();
        assert_eq!(
            view.cover().data_members().collect::<Vec<_>>(),
            vec![carried[0].result()]
        );
        assert!(view
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
        let joined: Blob<FirstEncoding> = snapshot
            .get(Handle::<FirstEncoding>::from_hash(carried[0].result()))
            .unwrap();
        let facts = TribleSet::try_from_blob(decode_first(&joined).unwrap()).unwrap();
        assert!(facts.contains(&row(200, 9)), "the join keeps both runs");
    }

    /// Any admitted leaf suffices, whoever signed it: an own foundation
    /// another key derived, and another owner's foundation this key derived,
    /// are not derived again, and a leaf whose output is not here but can be
    /// fetched is fetched rather than recomputed.
    #[test]
    fn an_admitted_leaf_own_or_foreign_prevents_a_second_derivation() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let a = own_commit(&mut inner, root, 41, 0);
        let b = own_commit(&mut inner, root, 42, 1);
        let c = own_commit(&mut inner, root, 41, 2);
        let leaf =
            |store: &mut MemoryRepo, signer: u8, source: &Blob<SimpleArchive>, here: bool| {
                let image = salted_image(source, 0);
                if here {
                    store.put::<FirstEncoding, _>(image.clone()).unwrap();
                }
                store
                    .insert(CollectionRecord::Derive(CollectionDerive::sign(
                        &key(signer),
                        first.handle(),
                        SourceLocator::of(data(source).raw),
                        data(&image),
                    )))
                    .unwrap();
                image
            };
        leaf(&mut inner, 42, &payload(41, 0), true);
        leaf(&mut inner, 41, &payload(42, 1), true);
        let elsewhere = leaf(&mut inner, 42, &payload(41, 2), false);
        let mut store = GuardStore::new(inner);
        store.offer(&elsewhere);

        for signer in [41, 42] {
            drop(block_on(store.maintain(first, &key(signer))).unwrap());
        }
        assert_eq!(FIRST_MAP_CALLS.get(), 0, "nothing is derived twice");
        assert_eq!(store.acquired, vec![data(&elsewhere)], "fetched once");
        assert!(!store
            .events
            .iter()
            .any(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Derive(_)))));
        let snapshot = store.inner.snapshot().unwrap();
        let view = snapshot.collection(first).unwrap();
        assert!(view
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
        assert_eq!(view.support().unwrap().len(), 3);
        let _ = (a, b, c);
    }

    /// A leaf whose output cannot be had does not count. The fetch is
    /// tried once; it failing means the output is not here now, not that it
    /// is lost. The foundation is mapped again: equal bytes restore the leaf
    /// and publish nothing; different bytes are a second leaf. When the
    /// original output arrives later it stands beside the second, and
    /// nothing further is derived or fetched.
    #[test]
    fn a_leaf_whose_output_cannot_be_had_is_derived_again_and_the_original_coexists() {
        for salt in [3, 5] {
            reset_mapping_calls();
            let (mut inner, root, first, _) = collections();
            own_commit(&mut inner, root, 42, 0);
            let source = payload(42, 0);
            let locator = SourceLocator::of(data(&source).raw);
            let original = salted_image(&source, 3);
            inner
                .insert(CollectionRecord::Derive(CollectionDerive::sign(
                    &key(42),
                    first.handle(),
                    locator,
                    data(&original),
                )))
                .unwrap();
            let mut store = GuardStore::new(inner);

            FIRST_SALT.set(salt);
            drop(block_on(store.maintain(first, &key(41))).unwrap());
            assert_eq!(store.acquired, vec![data(&original)]);
            assert_eq!(FIRST_MAP_CALLS.get(), 1);
            let leaves = derives_in(&mut store.inner, first.handle());
            let snapshot = store.inner.snapshot().unwrap();
            let view = snapshot.collection(first).unwrap();
            assert!(view
                .missing_from(&snapshot.collection(root).unwrap())
                .unwrap()
                .is_empty());
            drop((view, snapshot));
            if salt == 3 {
                // The same bytes: the believed leaf is restored as it stands.
                assert_eq!(leaves.len(), 1);
                continue;
            }
            let replacement = salted_image(&source, salt);
            assert_eq!(leaves.len(), 2, "a second leaf, the first kept");
            assert!(
                leaves
                    .iter()
                    .any(|leaf| leaf.public_key() == public(41)
                        && leaf.output() == data(&replacement))
            );

            // With the second leaf here, a pass fetches and maps nothing.
            reset_mapping_calls();
            drop(block_on(store.maintain(first, &key(41))).unwrap());
            assert_eq!(store.acquired, vec![data(&original)]);
            assert_eq!(FIRST_MAP_CALLS.get(), 0);

            // The original arrives: both leaves stand, and nothing follows.
            store
                .inner
                .put::<FirstEncoding, _>(original.clone())
                .unwrap();
            let before = records(&mut store.inner).len();
            drop(block_on(store.maintain(first, &key(41))).unwrap());
            assert_eq!(records(&mut store.inner).len(), before);
            assert_eq!(FIRST_MAP_CALLS.get(), 0);
            assert_eq!(store.acquired, vec![data(&original)]);
            assert_eq!(
                frontier(&mut store.inner, first.handle()),
                BTreeSet::from([data(&original), data(&replacement)])
            );
        }
    }

    /// A leaf known to be bad is supplemented only on request: re-deriving
    /// adds a second leaf beside it and replaces none; asking again with the
    /// same result adds nothing. The request names believed foundations of
    /// the view's own source, and needs a key the view admits.
    #[test]
    fn an_explicit_rederive_adds_a_second_leaf_and_replaces_none() {
        reset_mapping_calls();
        let owner = key(41);
        let (mut store, root, first, _) = collections();
        own_commit(&mut store, root, 41, 0);
        block_on(store.ensure(first, &owner)).unwrap();
        let source = payload(41, 0);
        let locator = SourceLocator::of(data(&source).raw);
        let named = root.cover([source.get_handle()]);

        FIRST_SALT.set(4);
        block_on(store.rederive(first, &named, &owner)).unwrap();
        let leaves = derives_in(&mut store, first.handle());
        assert_eq!(leaves.len(), 2);
        let outputs: BTreeSet<CollectionData> = leaves.iter().map(|leaf| leaf.output()).collect();
        assert_eq!(
            outputs,
            BTreeSet::from([first_image(&source), data(&salted_image(&source, 4))])
        );
        assert!(leaves.iter().all(|leaf| leaf.input() == locator));
        assert_eq!(
            frontier(&mut store, first.handle()),
            outputs,
            "the first leaf still stands"
        );

        // The same result again adds nothing, and maintenance derives
        // nothing: both leaves are usable.
        let before = records(&mut store).len();
        block_on(store.rederive(first, &named, &owner)).unwrap();
        block_on(store.maintain(first, &owner)).unwrap();
        assert_eq!(records(&mut store).len(), before);
        FIRST_SALT.set(0);

        // Only believed foundations of the view's own source, and only a
        // key the view admits.
        let stranger = root.cover([archive(99, 99).get_handle()]);
        assert!(matches!(
            block_on(store.rederive(first, &stranger, &owner)),
            Err(CollectionRealizationError::InvalidCover(_))
        ));
        let other = store.collection("other", policy()).unwrap();
        assert!(matches!(
            block_on(store.rederive(first, &other.cover([source.get_handle()]), &owner)),
            Err(CollectionRealizationError::InvalidCover(_))
        ));
        let guarded = store
            .derive::<FirstEncoding>(
                root,
                (),
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(owner.verifying_key()),
                ),
            )
            .unwrap();
        assert!(matches!(
            block_on(store.rederive(guarded, &named, &key(43))),
            Err(CollectionRealizationError::UnauthorizedProducer { collection })
                if collection == guarded.handle()
        ));
        assert!(derives_in(&mut store, guarded.handle()).is_empty());
    }

    /// A re-derivation runs again after every fetch, so it asks for every
    /// payload before it maps anything and never maps a foundation twice:
    /// with a mapping that never reproduces, each named foundation gains
    /// exactly one leaf.
    #[test]
    fn a_rederive_that_fetches_adds_one_leaf_per_foundation() {
        reset_mapping_calls();
        let owner = key(41);
        let (mut inner, root, first, _) = collections();
        let (p0, p1) = (payload(41, 0), payload(41, 1));
        // The payload later in the pass's order is the one elsewhere, so a
        // pass that mapped as it went would map the other before fetching.
        let (here, elsewhere) = if data(&p0) < data(&p1) {
            (p0, p1)
        } else {
            (p1, p0)
        };
        publish_root(&mut inner, root, &here, 41);
        let metadata = inner
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        inner
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &owner,
                root.handle(),
                data(&elsewhere),
                metadata,
            )))
            .unwrap();
        for source in [&here, &elsewhere] {
            let image = salted_image(source, 0);
            inner.put::<FirstEncoding, _>(image.clone()).unwrap();
            inner
                .insert(CollectionRecord::Derive(CollectionDerive::sign(
                    &owner,
                    first.handle(),
                    SourceLocator::of(data(source).raw),
                    data(&image),
                )))
                .unwrap();
        }
        let mut store = GuardStore::new(inner);
        store.offer(&elsewhere);

        FIRST_SALT.set(10);
        FIRST_SALT_ROTATES.set(true);
        let named = root.cover([here.get_handle(), elsewhere.get_handle()]);
        block_on(store.rederive(first, &named, &owner)).unwrap();
        FIRST_SALT_ROTATES.set(false);
        assert_eq!(store.acquired, vec![data(&elsewhere)]);
        assert_eq!(FIRST_MAP_CALLS.get(), 2, "each foundation is mapped once");
        for source in [&here, &elsewhere] {
            let leaves: Vec<_> = derives_in(&mut store.inner, first.handle())
                .into_iter()
                .filter(|leaf| leaf.input() == SourceLocator::of(data(source).raw))
                .collect();
            assert_eq!(leaves.len(), 2, "the first leaf and one more");
        }
    }

    /// Only a new leaf needs WRITE. A realizer maintaining a view its signer
    /// may not write derives nothing there, answers `Unadmitted`, and still
    /// carries the view's leaves into the host's merge; under `Ensure` it
    /// publishes nothing at all.
    #[test]
    fn a_realizer_carries_a_view_its_signer_may_not_write() {
        let host = key(41);
        let writer = key(40);
        let mut store = MemoryRepo::for_host(host.verifying_key());
        let root = store.collection("facts", policy()).unwrap();
        let view = store
            .derive::<TestImage>(
                root,
                (),
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(writer.verifying_key()),
                ),
            )
            .unwrap();
        for entity in 0..8 {
            own_commit(&mut store, root, 40, entity);
        }
        block_on(store.ensure(view, &writer)).unwrap();
        own_commit(&mut store, root, 41, 0);

        let before = records(&mut store);
        let report = block_on(crate::collection::ensure_downstream(
            &mut store,
            root.handle(),
            &host,
            &mut TestRealizer,
        ))
        .unwrap();
        assert_eq!(report.unadmitted, vec![view.handle()]);
        assert_eq!(records(&mut store), before);

        let report = block_on(maintain_downstream(
            &mut store,
            root.handle(),
            &host,
            &mut TestRealizer,
        ))
        .unwrap();
        assert_eq!(report.unadmitted, vec![view.handle()]);
        assert!(report.realized.is_empty());
        assert_eq!(derives_in(&mut store, view.handle()).len(), 8);
        let carried = merges_in(&mut store, view.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].public_key(), public(41));
    }

    /// `signer`'s leaf for `source` in the first view, under `salt`, as a
    /// record and its output's bytes.
    fn leaf_of(
        first: Collection<FirstEncoding>,
        signer: u8,
        source: &Blob<SimpleArchive>,
        salt: u8,
    ) -> (CollectionRecord, Blob<FirstEncoding>) {
        let image = salted_image(source, salt);
        let record = CollectionRecord::Derive(CollectionDerive::sign(
            &key(signer),
            first.handle(),
            SourceLocator::of(data(source).raw),
            data(&image),
        ));
        (record, image)
    }

    fn leaves_by(
        store: &mut MemoryRepo,
        first: Collection<FirstEncoding>,
        signer: u8,
    ) -> Vec<CollectionDerive> {
        derives_in(store, first.handle())
            .into_iter()
            .filter(|leaf| leaf.public_key() == public(signer))
            .collect()
    }

    /// Review finding, 2026-09-28: two hosts rebuilding one index at once
    /// each fixed what they owed from their own control snapshot, so each
    /// mapped every foundation. A leaf another writer publishes while the
    /// pass runs is now seen before the next foundation is mapped, and its
    /// foundation is left to it.
    #[test]
    fn a_leaf_published_while_the_pass_runs_is_not_derived_again() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let sources: Vec<_> = (0..4).map(|entity| payload(42, entity)).collect();
        for entity in 0..4 {
            own_commit(&mut inner, root, 42, entity);
        }
        let mut store = GuardStore::new(inner);
        // 42, deriving the same view elsewhere, publishes its four leaves as
        // soon as 41 has published its first.
        store.concurrent = sources
            .iter()
            .map(|source| {
                let (record, image) = leaf_of(first, 42, source, 7);
                (record, Some(image.bytes))
            })
            .collect();

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(FIRST_MAP_CALLS.get(), 1, "only the first was mapped");
        assert_eq!(leaves_by(&mut store.inner, first, 41).len(), 1);
        assert_eq!(leaves_by(&mut store.inner, first, 42).len(), 4);
        assert!(store.acquired.is_empty());
        let snapshot = store.inner.snapshot().unwrap();
        assert!(snapshot
            .collection(first)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
        drop(snapshot);

        // The next pass finds every foundation done.
        reset_mapping_calls();
        let before = records(&mut store.inner).len();
        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(records(&mut store.inner).len(), before);
    }

    /// A leaf that arrives while the pass runs without its output is left
    /// alone too; the next pass asks for every such output once, after the
    /// work that needed no fetch, and maps again only the foundation whose
    /// output could not be had.
    #[test]
    fn a_leaf_that_arrives_without_its_output_waits_for_the_next_pass() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let sources: Vec<_> = (0..4).map(|entity| payload(42, entity)).collect();
        for entity in 0..4 {
            own_commit(&mut inner, root, 42, entity);
        }
        let mut store = GuardStore::new(inner);
        let elsewhere: Vec<_> = sources
            .iter()
            .map(|source| leaf_of(first, 42, source, 7))
            .collect();
        store.concurrent = elsewhere
            .iter()
            .map(|(record, _)| (*record, None))
            .collect();

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(FIRST_MAP_CALLS.get(), 1);
        assert!(store.acquired.is_empty(), "nothing was known to fetch");
        let mapped = FIRST_MAP_LOG.with_borrow(|log| log[0]);

        // Three outputs are wanted now; two can be had.
        let waiting: Vec<_> = elsewhere
            .iter()
            .filter(|(record, _)| match record {
                CollectionRecord::Derive(leaf) => leaf.input() != SourceLocator::of(mapped.raw),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(waiting.len(), 3);
        for (_, image) in &waiting[..2] {
            store.offer(image);
        }
        let lost = data(&waiting[2].1);
        let events = store.events.len();
        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(
            store.acquired.iter().copied().collect::<BTreeSet<_>>(),
            waiting.iter().map(|(_, image)| data(image)).collect(),
        );
        assert_eq!(store.acquired.len(), 3, "each asked for once");
        assert!(store.acquired_at.iter().all(|at| *at == events));
        assert_eq!(FIRST_MAP_CALLS.get(), 2, "only the lost one mapped again");
        let lost_source = sources
            .iter()
            .find(|source| leaf_of(first, 42, source, 7).1.get_handle().raw == lost.raw)
            .unwrap();
        assert_eq!(FIRST_MAP_LOG.with_borrow(|log| log[1]), data(lost_source));
        let snapshot = store.inner.snapshot().unwrap();
        assert!(snapshot
            .collection(first)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
    }

    /// Review finding, 2026-09-28: every missing output cost one restart of
    /// the operation, all of them before anything was mapped or carried, and
    /// nothing bounded the time failed fetches could take. Now the work that
    /// needs no fetch and the carry come first, the outputs are asked for
    /// together afterwards, each once, and a call stops asking after eight
    /// have failed; the rest wait for the next call.
    #[test]
    fn outputs_are_asked_for_after_the_work_and_a_call_stops_after_eight_failures() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut inner, root, 41, entity);
        }
        block_on(inner.ensure(first, &key(41))).unwrap();
        let foreign: Vec<_> = (0..10).map(|entity| payload(42, entity)).collect();
        for entity in 0..10 {
            own_commit(&mut inner, root, 42, entity);
        }
        let mut outputs = BTreeSet::new();
        for source in &foreign {
            let (record, image) = leaf_of(first, 42, source, 7);
            inner.insert(record).unwrap();
            outputs.insert(data(&image));
        }
        // One more own foundation, with no leaf at all.
        let fresh = own_commit(&mut inner, root, 41, 9);
        let mut store = GuardStore::new(inner);
        reset_mapping_calls();

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(store.acquired.len(), 8);
        assert_eq!(
            store.acquired.iter().collect::<BTreeSet<_>>().len(),
            8,
            "each asked for once"
        );
        assert!(store.acquired.iter().all(|output| outputs.contains(output)));
        // Before the first fetch: the fresh foundation's leaf and the carry
        // of the eight own leaves.
        let first_fetch = store.acquired_at[0];
        let before_fetch = &store.events[..first_fetch];
        assert!(before_fetch.iter().any(|event| matches!(
            event,
            WriteEvent::Insert(CollectionRecord::Derive(leaf))
                if leaf.input() == SourceLocator::of(fresh.raw)
        )));
        assert!(before_fetch
            .iter()
            .any(|event| matches!(event, WriteEvent::Insert(CollectionRecord::Merge(_)))));
        assert!(!before_fetch.iter().any(|event| matches!(
            event,
            WriteEvent::Insert(CollectionRecord::Derive(leaf))
                if leaf.input() != SourceLocator::of(fresh.raw)
        )));
        // Mapped again: the fresh one and the eight whose outputs failed.
        assert_eq!(FIRST_MAP_CALLS.get(), 9);

        // The next call asks for the last two.
        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(store.acquired.len(), 10);
        assert_eq!(
            store.acquired.iter().copied().collect::<BTreeSet<_>>(),
            outputs
        );
        assert_eq!(FIRST_MAP_CALLS.get(), 11);
        let snapshot = store.inner.snapshot().unwrap();
        assert!(snapshot
            .collection(first)
            .unwrap()
            .missing_from(&snapshot.collection(root).unwrap())
            .unwrap()
            .is_empty());
    }

    /// Review finding, 2026-09-28: a refusal of one own foundation ended the
    /// pass where it stood, before the foundations after it and before the
    /// carry. Now the rest is derived and the view carried, and the refusal
    /// is reported after.
    #[test]
    fn a_refused_own_foundation_holds_back_neither_the_rest_nor_the_carry() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        let refused = own_commit(&mut store, root, 41, 8);
        FIRST_MAP_FATAL.replace(Some(refused));

        let result = block_on(store.maintain(first, &key(41)));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::Derive { input, .. }) if input == refused
            ),
            "{:?}",
            result.err()
        );
        assert_eq!(FIRST_MAP_CALLS.get(), 9, "every foundation was tried");
        let leaves: BTreeSet<CollectionData> = derives_in(&mut store, first.handle())
            .iter()
            .map(|leaf| leaf.output())
            .collect();
        assert_eq!(
            leaves,
            (0..8)
                .map(|entity| first_image(&payload(41, entity)))
                .collect()
        );
        let carried = merges_in(&mut store, first.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(inputs(&carried[0]), leaves);
    }

    /// Review finding, 2026-09-28: a store that answers only from its own
    /// blobs -- a plain pile -- "failed" every fetch at once, so a leaf whose
    /// record arrived before its output was derived again at once. From such
    /// a store a miss says nothing about elsewhere: the foundation waits for
    /// the output, and nothing is derived when it arrives.
    #[test]
    fn a_store_that_cannot_fetch_waits_for_a_leafs_output() {
        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        own_commit(&mut store, root, 42, 0);
        let source = payload(42, 0);
        let (record, image) = leaf_of(first, 42, &source, 7);
        store.insert(record).unwrap();
        let missing = |store: &mut MemoryRepo| -> BTreeSet<CollectionData> {
            let snapshot = store.snapshot().unwrap();
            let view = snapshot.collection(first).unwrap();
            let source = snapshot.collection(root).unwrap();
            view.missing_from(&source).unwrap().data_members().collect()
        };

        for signer in [41, 42] {
            block_on(store.maintain(first, &key(signer))).unwrap();
        }
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(derives_in(&mut store, first.handle()).len(), 1);
        assert_eq!(missing(&mut store), BTreeSet::from([data(&source)]));

        store.put::<FirstEncoding, _>(image).unwrap();
        block_on(store.maintain(first, &key(41))).unwrap();
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
        assert_eq!(derives_in(&mut store, first.handle()).len(), 1);
        assert!(missing(&mut store).is_empty());
    }

    /// Review finding, 2026-09-28 (test gap): another owner's foundation
    /// whose payload is not here costs nothing, not even a fetch of an output
    /// its leaf names.
    #[test]
    fn another_owners_foundation_that_is_not_here_asks_for_nothing() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        foreign_commit(&mut inner, root, 42, 0);
        let (record, image) = leaf_of(first, 42, &payload(42, 0), 7);
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        store.offer(&image);

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert!(store.acquired.is_empty(), "{:?}", store.acquired);
        assert_eq!(FIRST_MAP_CALLS.get(), 0);
    }

    /// Each key derives in an order of its own, the same on every pass: two
    /// hosts deriving one collection at once do not walk it in step. A key's
    /// own foundations come first.
    #[test]
    fn two_keys_derive_the_same_foundations_in_orders_of_their_own() {
        let order = |host: u8, own: u8| {
            reset_mapping_calls();
            let (mut store, root, first, _) = collections_as(&key(host));
            for entity in 0..own {
                own_commit(&mut store, root, host, entity);
            }
            for entity in 0..12 {
                own_commit(&mut store, root, 43, entity);
            }
            block_on(store.maintain(first, &key(host))).unwrap();
            FIRST_MAP_LOG.with_borrow(|log| log.clone())
        };
        let left = order(41, 0);
        let again = order(41, 0);
        let right = order(42, 0);
        assert_eq!(left.len(), 12);
        assert_eq!(left, again, "the same order on every pass");
        assert_ne!(left, right);
        assert_eq!(
            left.iter().collect::<BTreeSet<_>>(),
            right.iter().collect::<BTreeSet<_>>()
        );

        let mixed = order(41, 3);
        let own: BTreeSet<CollectionData> =
            (0..3).map(|entity| data(&payload(41, entity))).collect();
        assert_eq!(mixed.len(), 15);
        assert_eq!(mixed[..3].iter().copied().collect::<BTreeSet<_>>(), own);
    }

    /// The order a pass by `signer` derives `foundation` in, computed as
    /// maintenance computes it, so a test can place one foundation after
    /// others in it.
    fn derive_rank(signer: u8, foundation: CollectionData) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"triblespace/derive-order");
        hash.update(key(signer).verifying_key().as_bytes());
        hash.update(&foundation.raw);
        *hash.finalize().as_bytes()
    }

    /// Review finding, 2026-09-28: a refused own foundation ended the call
    /// before it asked for the outputs it had gone on without. While one
    /// foundation stayed refused, an output that could be fetched never was,
    /// and one that could not be had never let its foundation be derived
    /// again. The call now asks for them, derives and carries what that
    /// makes possible, and reports the refusal after.
    #[test]
    fn a_refused_own_foundation_does_not_stop_the_outputs_the_rest_wants() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let refused = own_commit(&mut inner, root, 41, 0);
        FIRST_MAP_FATAL.replace(Some(refused));
        let fetched = payload(42, 1);
        let rederived = payload(42, 2);
        own_commit(&mut inner, root, 42, 1);
        own_commit(&mut inner, root, 42, 2);
        let (record, obtainable) = leaf_of(first, 42, &fetched, 7);
        inner.insert(record).unwrap();
        let (record, lost) = leaf_of(first, 42, &rederived, 7);
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        store.offer(&obtainable);

        for pass in 0..2 {
            let result = block_on(store.maintain(first, &key(41)));
            assert!(
                matches!(
                    result,
                    Err(CollectionRealizationError::Derive { input, .. }) if input == refused
                ),
                "pass {pass}: {:?}",
                result.err()
            );
        }
        assert_eq!(
            store.acquired.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([data(&obtainable), data(&lost)])
        );
        assert_eq!(store.acquired.len(), 2, "each asked for once");
        let mapped = FIRST_MAP_LOG.with_borrow(|log| log.clone());
        assert!(!mapped.contains(&data(&fetched)), "a fetched output counts");
        assert_eq!(
            mapped
                .iter()
                .filter(|source| **source == data(&rederived))
                .count(),
            1,
            "derived again once"
        );
        let own = leaves_by(&mut store.inner, first, 41);
        assert_eq!(
            own.iter().map(|leaf| leaf.input()).collect::<Vec<_>>(),
            vec![SourceLocator::of(data(&rederived).raw)]
        );
    }

    /// Review finding, 2026-09-28: the first own foundation the mapping
    /// refused was the one thing a pass reported, so a payload another own
    /// foundation after it in the key's order needed was never fetched
    /// while the refusal stood.
    #[test]
    fn a_refused_own_foundation_does_not_hide_a_payload_another_needs() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let refused = own_commit(&mut inner, root, 41, 0);
        FIRST_MAP_FATAL.replace(Some(refused));
        let entity = (1..64)
            .find(|entity| derive_rank(41, data(&payload(41, *entity))) > derive_rank(41, refused))
            .unwrap();
        let elsewhere = payload(41, entity);
        foreign_commit(&mut inner, root, 41, entity);
        let mut store = GuardStore::new(inner);
        store.offer(&elsewhere);

        let result = block_on(store.maintain(first, &key(41)));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::Derive { input, .. }) if input == refused
            ),
            "{:?}",
            result.err()
        );
        assert_eq!(store.acquired, vec![data(&elsewhere)]);
        assert_eq!(
            leaves_by(&mut store.inner, first, 41)
                .iter()
                .map(|leaf| leaf.input())
                .collect::<Vec<_>>(),
            vec![SourceLocator::of(data(&elsewhere).raw)]
        );
    }

    /// Review finding, 2026-09-28: a call stopped asking after eight failed
    /// fetches, in the same order on every call, so a foundation whose
    /// ninth leaf's output could be had never had it asked for. A call now
    /// asks for every output of a foundation it starts until one arrives or
    /// all have failed.
    #[test]
    fn a_foundations_ninth_output_is_asked_for_after_eight_fail() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let source = payload(42, 0);
        own_commit(&mut inner, root, 42, 0);
        let mut leaves: Vec<_> = (1..=9)
            .map(|salt| leaf_of(first, 42, &source, salt))
            .collect();
        leaves.sort_by_key(|(_, image)| data(image).raw);
        for (record, _) in &leaves {
            inner.insert(*record).unwrap();
        }
        let obtainable = leaves[8].1.clone();
        let mut store = GuardStore::new(inner);
        store.offer(&obtainable);

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert!(
            store.acquired.contains(&data(&obtainable)),
            "{} asked, the last not among them",
            store.acquired.len()
        );
        assert_eq!(store.acquired.len(), 9);
        assert_eq!(FIRST_MAP_CALLS.get(), 0, "the fetched output counts");
        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(store.acquired.len(), 9, "nothing is asked again");
    }

    /// Review finding, 2026-09-28: with eight foundations whose outputs
    /// never arrive and whose mapping is refused here, every call spent its
    /// eight failed fetches on them, in the same order, and a ninth after
    /// them was never asked about nor derived. Each call now starts the
    /// foundations in an order of its own, so no fixed prefix starves the
    /// rest: the ninth is reached in a call unless it is drawn last, one
    /// chance in nine, and every output is eventually asked for.
    #[test]
    fn foundations_that_always_fail_first_starve_no_other() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let mut sources: Vec<_> = (0..9).map(|entity| payload(42, entity)).collect();
        for entity in 0..9 {
            own_commit(&mut inner, root, 42, entity);
        }
        sources.sort_by_key(|source| derive_rank(41, data(source)));
        let mappable = sources.pop().unwrap();
        FIRST_MAP_REFUSED.with_borrow_mut(|refused| refused.extend(sources.iter().map(data)));
        let mut outputs = BTreeSet::new();
        for source in sources.iter().chain([&mappable]) {
            let (record, image) = leaf_of(first, 42, source, 7);
            inner.insert(record).unwrap();
            outputs.insert(data(&image));
        }
        let mappable_output = data(&leaf_of(first, 42, &mappable, 7).1);
        let mut store = GuardStore::new(inner);

        let mut calls = 0;
        while leaves_by(&mut store.inner, first, 41).is_empty() {
            assert!(
                calls < 32,
                "starved: {calls} calls asked only {:?}",
                store.acquired.iter().collect::<BTreeSet<_>>().len()
            );
            drop(block_on(store.maintain(first, &key(41))).unwrap());
            calls += 1;
        }
        assert!(store.acquired.contains(&mappable_output));
        assert_eq!(
            leaves_by(&mut store.inner, first, 41)
                .iter()
                .map(|leaf| leaf.input())
                .collect::<Vec<_>>(),
            vec![SourceLocator::of(data(&mappable).raw)]
        );
        while store.acquired.iter().copied().collect::<BTreeSet<_>>() != outputs {
            assert!(calls < 64, "an output was never asked for");
            drop(block_on(store.maintain(first, &key(41))).unwrap());
            calls += 1;
        }
    }

    /// Review finding, 2026-09-28: a refused own foundation was reported in
    /// place of the carry's own failure, so a store that could not write the
    /// carry's MERGE said only that one foundation was refused.
    #[test]
    fn a_failed_carry_is_reported_before_a_refused_foundation() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut inner, root, 41, entity);
        }
        let refused = own_commit(&mut inner, root, 41, 8);
        FIRST_MAP_FATAL.replace(Some(refused));
        let mut store = GuardStore::new(inner);
        // Eight leaves go in; the carry's MERGE is the ninth insert.
        store.reject_insert_at = Some(9);

        let result = block_on(store.maintain(first, &key(41)));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::Storage { operation, .. })
                    if operation == "publish root carry MERGE"
            ),
            "{:?}",
            result.err()
        );
        assert_eq!(leaves_by(&mut store.inner, first, 41).len(), 8);
    }

    /// Review finding, 2026-09-28: a fetch that failed outright -- a peer
    /// endpoint that cannot start, or a fetched blob that cannot be kept --
    /// ended the whole call at that output. The rest is now asked for, and
    /// the failure is reported once the work is done.
    ///
    /// Review finding, 2026-09-29: that failure was then counted as the
    /// blob being unavailable, so a foundation whose leaf's output a holder
    /// did have was derived again, and a second leaf published beside one
    /// that could be had. A fetch that fails outright is a fault here, not
    /// an answer about elsewhere: the foundation waits, every call reports
    /// the fault, and once it clears the output is fetched and counts. An
    /// own payload that cannot be fetched either way leaves its foundation
    /// underived for the call.
    #[test]
    fn a_fetch_that_fails_outright_is_reported_and_derives_nothing_in_its_place() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let fresh = own_commit(&mut inner, root, 41, 0);
        // An own foundation whose payload is elsewhere, and cannot be had.
        foreign_commit(&mut inner, root, 41, 3);
        let unreachable = payload(41, 3);
        let faulted_source = payload(42, 1);
        let fetched_source = payload(42, 2);
        own_commit(&mut inner, root, 42, 1);
        own_commit(&mut inner, root, 42, 2);
        let (record, faulted) = leaf_of(first, 42, &faulted_source, 7);
        inner.insert(record).unwrap();
        let (record, obtainable) = leaf_of(first, 42, &fetched_source, 7);
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        // A holder has both outputs; keeping the first fails here.
        store.offer(&faulted);
        store.offer(&obtainable);
        store.acquire_fails.insert(data(&faulted));
        store.acquire_fails.insert(data(&unreachable));

        for pass in 0..2 {
            let result = block_on(store.maintain(first, &key(41)));
            let reported = format!("{:?}", result.as_ref().err());
            assert!(
                matches!(result, Err(CollectionRealizationError::Storage { .. })),
                "pass {pass}: {reported}"
            );
            assert!(
                reported.contains(r#"Injected("acquire")"#),
                "pass {pass}: {reported}"
            );
        }
        let mapped = FIRST_MAP_LOG.with_borrow(|log| log.clone());
        assert!(
            !mapped.contains(&data(&faulted_source)),
            "a fault is no reason to derive again"
        );
        assert!(
            !mapped.contains(&data(&fetched_source)),
            "a fetched output counts"
        );
        assert_eq!(
            leaves_by(&mut store.inner, first, 41)
                .iter()
                .map(|leaf| leaf.input())
                .collect::<Vec<_>>(),
            vec![SourceLocator::of(fresh.raw)]
        );
        // Each call asks once for what it lacks: the first all three, the
        // second the two that failed.
        assert_eq!(
            store.acquired.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([data(&faulted), data(&obtainable), data(&unreachable)])
        );
        assert_eq!(store.acquired.len(), 5, "{:?}", store.acquired);

        // The fault clears: the output is fetched and counts.
        store.acquire_fails.remove(&data(&faulted));
        let result = block_on(store.maintain(first, &key(41)));
        assert!(
            matches!(result, Err(CollectionRealizationError::Storage { .. })),
            "the own payload still fails: {:?}",
            result.err()
        );
        assert_eq!(store.acquired.len(), 7, "{:?}", store.acquired);
        assert!(store
            .inner
            .snapshot()
            .unwrap()
            .metadata(Handle::<FirstEncoding>::from_hash(data(&faulted)))
            .unwrap()
            .is_some());
        assert!(!FIRST_MAP_LOG.with_borrow(|log| log.contains(&data(&faulted_source))));
        assert_eq!(leaves_by(&mut store.inner, first, 41).len(), 1);
    }

    /// Review finding, 2026-09-29: a blob an own foundation needs was
    /// counted unavailable when fetching it failed outright, and one blob
    /// can also be the output another foundation's leaf names. That
    /// foundation was then derived again, beside a leaf a holder could hand
    /// over. A fetch that fails outright counts a blob unavailable in
    /// neither role: the foundation that needs it waits, the one whose leaf
    /// names it waits, and the fault is reported once the work is done.
    #[test]
    fn a_needed_blob_whose_fetch_fails_outright_is_no_unavailable_leaf_output() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        // Another owner's foundation, here, whose admitted leaf names the
        // blob as its output.
        let leafed = payload(42, 1);
        own_commit(&mut inner, root, 42, 1);
        let (record, shared) = leaf_of(first, 42, &leafed, 7);
        inner.insert(record).unwrap();
        // An own foundation, here, that maps only once that blob is here.
        let needing = own_commit(&mut inner, root, 41, 0);
        FIRST_MAP_NEEDS.with_borrow_mut(|needs| needs.insert(needing, data(&shared)));
        let mut store = GuardStore::new(inner);
        // A holder has the blob; keeping it fails here.
        store.offer(&shared);
        store.acquire_fails.insert(data(&shared));

        let result = block_on(store.maintain(first, &key(41)));
        let reported = format!("{:?}", result.as_ref().err());
        assert!(
            matches!(result, Err(CollectionRealizationError::Storage { .. }))
                && reported.contains(r#"Injected("acquire")"#),
            "{reported}"
        );
        assert_eq!(store.acquired, vec![data(&shared)], "asked for once");
        assert!(
            !FIRST_MAP_LOG.with_borrow(|log| log.contains(&data(&leafed))),
            "a fault is no reason to derive again"
        );
        assert!(leaves_by(&mut store.inner, first, 41).is_empty());

        // The fault clears: the blob is fetched, the own foundation maps,
        // and the other's leaf counts.
        store.acquire_fails.remove(&data(&shared));
        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(store.acquired, vec![data(&shared), data(&shared)]);
        assert!(!FIRST_MAP_LOG.with_borrow(|log| log.contains(&data(&leafed))));
        assert_eq!(
            leaves_by(&mut store.inner, first, 41)
                .iter()
                .map(|leaf| leaf.input())
                .collect::<Vec<_>>(),
            vec![SourceLocator::of(needing.raw)]
        );
    }

    /// The same fault met the other way round: a leaf's output whose fetch
    /// failed outright was still asked for again as a blob an own
    /// foundation needs, and that request, standing first, hid the payload
    /// another own foundation after it needed. A blob whose fetch failed is
    /// not here for the rest of the call, in either role: the foundation
    /// that needs it waits and the payload is fetched.
    #[test]
    fn a_leaf_output_whose_fetch_fails_outright_hides_no_payload_another_needs() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        // Another owner's foundation, here, whose leaf names the blob.
        let leafed = payload(42, 1);
        own_commit(&mut inner, root, 42, 1);
        let (record, shared) = leaf_of(first, 42, &leafed, 7);
        inner.insert(record).unwrap();
        // Two own foundations, each with a leaf whose output nobody has: the
        // first is here and needs the blob, the second, after it in the
        // key's order, has its payload elsewhere.
        let needing = own_commit(&mut inner, root, 41, 0);
        FIRST_MAP_NEEDS.with_borrow_mut(|needs| needs.insert(needing, data(&shared)));
        let entity = (1..64)
            .find(|entity| derive_rank(41, data(&payload(41, *entity))) > derive_rank(41, needing))
            .unwrap();
        let elsewhere = payload(41, entity);
        foreign_commit(&mut inner, root, 41, entity);
        let (record, _) = leaf_of(first, 42, &payload(41, 0), 7);
        inner.insert(record).unwrap();
        let (record, _) = leaf_of(first, 42, &elsewhere, 7);
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        store.offer(&shared);
        store.offer(&elsewhere);
        store.acquire_fails.insert(data(&shared));

        let result = block_on(store.maintain(first, &key(41)));
        let reported = format!("{:?}", result.as_ref().err());
        assert!(
            matches!(result, Err(CollectionRealizationError::Storage { .. }))
                && reported.contains(r#"Injected("acquire")"#),
            "{reported}"
        );
        assert!(
            store.acquired.contains(&data(&elsewhere)),
            "the payload was hidden: asked {:?}",
            store.acquired
        );
        assert_eq!(
            store
                .acquired
                .iter()
                .filter(|member| **member == data(&shared))
                .count(),
            1,
            "asked for once"
        );
        assert!(!FIRST_MAP_LOG.with_borrow(|log| log.contains(&data(&leafed))));
        assert_eq!(
            leaves_by(&mut store.inner, first, 41)
                .iter()
                .map(|leaf| leaf.input())
                .collect::<Vec<_>>(),
            vec![SourceLocator::of(data(&elsewhere).raw)]
        );
    }

    /// Damage one byte of `blob` where a pile file holds it, the last
    /// occurrence of its bytes in the file.
    fn damage_in_file<E: BlobEncoding>(path: &std::path::Path, blob: &Blob<E>) {
        let mut bytes = std::fs::read(path).unwrap();
        let at = bytes
            .windows(blob.bytes.len())
            .rposition(|window| window == blob.bytes.as_ref())
            .unwrap();
        bytes[at + 8] ^= 0x40;
        std::fs::write(path, &bytes).unwrap();
    }

    /// Review finding, 2026-09-28: whether a leaf was usable was asked of
    /// the pile's index, which says a blob is present without reading it.
    /// A leaf whose output bytes are damaged therefore counted, and every
    /// carry that grouped it failed to read it. A leaf now counts only when
    /// its output reads, and the carry joins only nodes whose bytes read.
    ///
    /// Review finding, 2026-09-29: the damaged output then counted as
    /// unavailable at once, and its foundation was derived again -- by a
    /// store that asks nobody else, which waits for an absent output. A
    /// damaged output is now waited for or asked for exactly like an absent
    /// one: through a plain pile, nothing is derived in its place, and the
    /// carry reads around it.
    #[test]
    fn a_plain_pile_waits_for_a_damaged_output_and_the_carry_reads_around_it() {
        use crate::repo::pile::Pile;

        reset_mapping_calls();
        let file = tempfile::NamedTempFile::new().unwrap();
        let host = key(41);
        let mut pile = Pile::open_as(file.path(), host.verifying_key()).unwrap();
        let root = pile.collection("root", policy()).unwrap();
        let first = pile.derive::<FirstEncoding>(root, (), policy()).unwrap();
        let sources: Vec<_> = (0..9).map(|entity| payload(41, entity)).collect();
        for source in &sources {
            pile.put::<SimpleArchive, _>(source.clone()).unwrap();
            let metadata = pile
                .put::<SimpleArchive, _>(TribleSet::new().to_blob())
                .unwrap();
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                &host,
                root.handle(),
                data(source),
                metadata,
            )))
            .unwrap();
        }
        drop(block_on(pile.ensure(first, &host)).unwrap());
        pile.close().unwrap();
        let image = salted_image(&sources[0], 0);
        let damaged = data(&image);
        damage_in_file(file.path(), &image);

        let mut pile = Pile::open_as(file.path(), host.verifying_key()).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let handle = Handle::<FirstEncoding>::from_hash(damaged);
        assert!(snapshot.contains_blob(handle).unwrap(), "present");
        assert!(snapshot.metadata(handle).unwrap().is_none(), "unreadable");
        drop(snapshot);

        let mapped = FIRST_MAP_CALLS.get();
        let result = block_on(pile.maintain(first, &host));
        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(
            FIRST_MAP_CALLS.get(),
            mapped,
            "nothing is derived in its place"
        );
        let records: Vec<CollectionRecord> = pile
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let leaves = records
            .iter()
            .filter(|record| {
                matches!(record, CollectionRecord::Derive(leaf) if leaf.collection() == first.handle())
            })
            .count();
        let merges: Vec<CollectionMerge> = records
            .iter()
            .filter_map(|record| match record {
                CollectionRecord::Merge(merge) if merge.collection() == first.handle() => {
                    Some(*merge)
                }
                _ => None,
            })
            .collect();
        assert_eq!(leaves, 9);
        assert_eq!(merges.len(), 1);
        let carried: BTreeSet<CollectionData> = sources[1..]
            .iter()
            .map(|source| data(&salted_image(source, 0)))
            .collect();
        assert_eq!(inputs(&merges[0]), carried);
        pile.close().unwrap();
    }

    /// Review finding, 2026-09-29: a leaf output that is here but does not
    /// read counted as unavailable at once, so its foundation was derived
    /// again even when a holder could hand the bytes over: a second leaf
    /// published automatically beside one that could be had. Through a
    /// store that asks other holders a damaged output is now asked for like
    /// an absent one, and only when nobody hands it over is its foundation
    /// derived again.
    #[test]
    fn a_damaged_output_is_asked_for_before_its_foundation_is_derived_again() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        let restored_source = payload(42, 1);
        let lost_source = payload(42, 2);
        own_commit(&mut inner, root, 42, 1);
        own_commit(&mut inner, root, 42, 2);
        let (record, restored) = leaf_of(first, 42, &restored_source, 7);
        inner.put::<FirstEncoding, _>(restored.clone()).unwrap();
        inner.insert(record).unwrap();
        let (record, lost) = leaf_of(first, 42, &lost_source, 7);
        inner.put::<FirstEncoding, _>(lost.clone()).unwrap();
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        store.damage(&restored);
        store.damage(&lost);
        store.offer(&restored);

        drop(block_on(store.maintain(first, &key(41))).unwrap());
        assert_eq!(
            store.acquired.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([data(&restored), data(&lost)])
        );
        assert_eq!(
            FIRST_MAP_LOG.with_borrow(|log| log.clone()),
            vec![data(&lost_source)],
            "only the output nobody handed over is derived again"
        );
        assert!(store
            .snapshot()
            .unwrap()
            .metadata(Handle::<FirstEncoding>::from_hash(data(&restored)))
            .unwrap()
            .is_some());
    }

    /// Review finding, 2026-09-29: the carry holds only frontier nodes whose
    /// bytes read, so on a root it reads around a damaged commit, publishes
    /// nothing about it, and maintenance succeeds. The damage is not hidden
    /// by that: attaching a cover validates no byte, so a reader takes the
    /// node, and reading it fails naming it.
    #[test]
    fn a_root_carry_reads_around_a_damaged_commit_and_a_read_names_it() {
        use crate::repo::pile::Pile;

        let file = tempfile::NamedTempFile::new().unwrap();
        let host = key(41);
        let mut pile = Pile::open_as(file.path(), host.verifying_key()).unwrap();
        let root = pile.collection("root", policy()).unwrap();
        let sources: Vec<_> = (0..9).map(|entity| payload(41, entity)).collect();
        for source in &sources {
            pile.put::<SimpleArchive, _>(source.clone()).unwrap();
            let metadata = pile
                .put::<SimpleArchive, _>(TribleSet::new().to_blob())
                .unwrap();
            pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
                &host,
                root.handle(),
                data(source),
                metadata,
            )))
            .unwrap();
        }
        pile.close().unwrap();
        let damaged = data(&sources[0]);
        damage_in_file(file.path(), &sources[0]);

        let mut pile = Pile::open_as(file.path(), host.verifying_key()).unwrap();
        let result = block_on(pile.maintain(root, &host));
        assert!(result.is_ok(), "{:?}", result.err());
        let snapshot = pile.snapshot().unwrap();
        let merges: Vec<CollectionMerge> = snapshot
            .records()
            .unwrap()
            .map(Result::unwrap)
            .filter_map(|record| match record {
                CollectionRecord::Merge(merge) if merge.collection() == root.handle() => {
                    Some(merge)
                }
                _ => None,
            })
            .collect();
        assert_eq!(merges.len(), 1);
        let good: BTreeSet<CollectionData> = sources[1..].iter().map(data).collect();
        assert_eq!(inputs(&merges[0]), good);

        let observed = snapshot.collection(root).unwrap();
        assert!(observed.cover().data_members().any(|node| node == damaged));
        match observed.view::<TribleSet>() {
            Err(crate::collection::TryFromCoverError::MemberGet { member, .. }) => {
                assert_eq!(member, damaged)
            }
            other => panic!("the read names the damaged commit: {:?}", other.err()),
        }
        drop(observed);
        drop(snapshot);
        pile.close().unwrap();
    }

    /// Review finding, 2026-09-29: a fetch that failed outright was reported
    /// in place of whatever the operation reported, so a signer that is not
    /// the store's host -- which stops a whole upkeep pass -- read as a
    /// storage failure, and the pass went on.
    #[test]
    fn a_signer_that_is_not_the_host_is_reported_before_a_failed_fetch() {
        reset_mapping_calls();
        let (mut inner, root, first, _) = collections();
        for entity in 0..8 {
            let source = payload(42, entity);
            own_commit(&mut inner, root, 42, entity);
            let (record, image) = leaf_of(first, 42, &source, 0);
            inner.put::<FirstEncoding, _>(image).unwrap();
            inner.insert(record).unwrap();
        }
        let waiting = payload(42, 8);
        own_commit(&mut inner, root, 42, 8);
        let (record, output) = leaf_of(first, 42, &waiting, 7);
        inner.insert(record).unwrap();
        let mut store = GuardStore::new(inner);
        store.acquire_fails.insert(data(&output));

        let result = block_on(store.maintain(first, &key(42)));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::HostMismatch { host: Some(host), signer })
                    if host == public(41) && signer == public(42)
            ),
            "{:?}",
            result.err()
        );
        assert_eq!(store.acquired, vec![data(&output)], "the fetch was made");
    }

    /// Review finding, 2026-09-28: one derived collection failing stopped
    /// the pass at it, before every derived collection after it and every
    /// attached one. It is now that collection's lag, named with why, like
    /// a failing attached collection.
    #[test]
    fn one_derived_collection_failing_leaves_the_others_upkept() {
        use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
        use crate::collection::{
            derived_from, ensure_downstream, Attached, CoreRealizer, Derived, RealizeDerived,
            Realized, Upkeep,
        };

        /// The test realizer, except that one derived collection fails,
        /// with the error the flag picks: a resolution or a storage one.
        struct FailsOne(CollectionHandle, bool);
        impl<S> RealizeDerived<S> for FailsOne
        where
            S: crate::repo::Store + crate::repo::async_store::AsyncBlobStoreAcquire + Send,
        {
            async fn realize(
                &mut self,
                store: &mut S,
                derived: &Derived,
                signer: &SigningKey,
                upkeep: Upkeep,
            ) -> Result<Realized, CollectionRealizationError> {
                if derived.handle == self.0 {
                    return Err(if self.1 {
                        CollectionRealizationError::storage(
                            "take this one up",
                            GuardStoreError::Backend("this one cannot be taken up".to_owned()),
                        )
                    } else {
                        CollectionRealizationError::Resolution(
                            "this one cannot be taken up".to_owned(),
                        )
                    });
                }
                if derived.representation == <FirstEncoding as MetaDescribe>::id() {
                    return crate::collection::realize_as::<S, FirstEncoding>(
                        store, derived, signer, upkeep,
                    )
                    .await;
                }
                TestRealizer.realize(store, derived, signer, upkeep).await
            }

            async fn realize_attached(
                &mut self,
                store: &mut S,
                attached: &Attached,
                signer: &SigningKey,
                upkeep: Upkeep,
            ) -> Result<Realized, CollectionRealizationError> {
                CoreRealizer
                    .realize_attached(store, attached, signer, upkeep)
                    .await
            }
        }

        let owner = key(41);
        let mut store = MemoryRepo::for_host(owner.verifying_key());
        let root = store.collection("facts", policy()).unwrap();
        let raw = store.derive::<TestImage>(root, (), policy()).unwrap();
        let first = store.derive::<FirstEncoding>(root, (), policy()).unwrap();
        let succinct = store.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
        own_commit(&mut store, root, 41, 0);
        block_on(store.ensure(raw, &owner)).unwrap();
        block_on(store.ensure(first, &owner)).unwrap();
        block_on(store.ensure_attached(succinct, &owner)).unwrap();
        let listed: Vec<CollectionHandle> = derived_from(&store.snapshot().unwrap(), root.handle())
            .unwrap()
            .into_iter()
            .map(|derived| derived.handle)
            .collect();
        assert_eq!(listed.len(), 2);
        let (failing, other) = (listed[0], listed[1]);

        for (entity, upkeep, storage) in [
            (1, Upkeep::Ensure, false),
            (2, Upkeep::Maintain, false),
            (3, Upkeep::Ensure, true),
            (4, Upkeep::Maintain, true),
        ] {
            own_commit(&mut store, root, 41, entity);
            let mut realizer = FailsOne(failing, storage);
            let report = block_on(async {
                match upkeep {
                    Upkeep::Ensure => {
                        ensure_downstream(&mut store, root.handle(), &owner, &mut realizer).await
                    }
                    Upkeep::Maintain => {
                        maintain_downstream(&mut store, root.handle(), &owner, &mut realizer).await
                    }
                }
            })
            .unwrap();
            assert_eq!(report.realized, vec![other, succinct.handle()]);
            assert_eq!(
                report
                    .failed
                    .iter()
                    .map(|(derived, reason)| (
                        derived.handle,
                        reason.contains("cannot be taken up")
                    ))
                    .collect::<Vec<_>>(),
                vec![(failing, true)]
            );
            assert!(report.failed_attached.is_empty());
        }
    }

    /// Review finding, 2026-09-29 (test gap): a signer that is not the
    /// store's host stops the pass at a derived collection, as at an
    /// attached one -- no collection would believe its merges -- where any
    /// other failure of a derived collection is that collection's lag.
    #[test]
    fn a_signer_that_is_not_the_host_stops_the_pass_at_a_derived_collection() {
        use crate::collection::{Attached, Derived, RealizeDerived, Realized, Upkeep};

        /// Realizes the first test view and knows nothing else.
        struct OnlyFirst;
        impl<S> RealizeDerived<S> for OnlyFirst
        where
            S: crate::repo::Store + crate::repo::async_store::AsyncBlobStoreAcquire + Send,
        {
            async fn realize(
                &mut self,
                store: &mut S,
                derived: &Derived,
                signer: &SigningKey,
                upkeep: Upkeep,
            ) -> Result<Realized, CollectionRealizationError> {
                if derived.representation == <FirstEncoding as MetaDescribe>::id() {
                    return crate::collection::realize_as::<S, FirstEncoding>(
                        store, derived, signer, upkeep,
                    )
                    .await;
                }
                Ok(Realized::Unknown)
            }

            async fn realize_attached(
                &mut self,
                _store: &mut S,
                _attached: &Attached,
                _signer: &SigningKey,
                _upkeep: Upkeep,
            ) -> Result<Realized, CollectionRealizationError> {
                Ok(Realized::Unknown)
            }
        }

        reset_mapping_calls();
        let (mut store, root, first, _) = collections();
        for entity in 0..8 {
            own_commit(&mut store, root, 42, entity);
        }
        // Its leaves list the derived collection; `ensure` merges nothing.
        drop(block_on(store.ensure(first, &key(42))).unwrap());
        let result = block_on(maintain_downstream(
            &mut store,
            root.handle(),
            &key(42),
            &mut OnlyFirst,
        ));
        assert!(
            matches!(
                result,
                Err(CollectionRealizationError::HostMismatch { host: Some(host), signer })
                    if host == public(41) && signer == public(42)
            ),
            "{:?}",
            result
        );
        assert!(merges_in(&mut store, first.handle()).is_empty());
    }

    /// The carry binds a derived collection's mapping, which reads the
    /// descriptors of its whole source chain. They are in the derived
    /// collection's held set -- its descriptor names its source's, and so on
    /// to the root -- so a host that receives that set and the collection's
    /// leaves carries it, with none of its sources' records or payloads.
    #[test]
    fn a_derived_collections_held_set_holds_the_descriptors_its_carry_binds() {
        use crate::collection::{HeldRead, HeldStore};

        reset_mapping_calls();
        let (mut store, root, first, second) = collections();
        for entity in 0..8 {
            own_commit(&mut store, root, 41, entity);
        }
        block_on(store.ensure(first, &key(41))).unwrap();
        block_on(store.ensure(second, &key(41))).unwrap();
        store.track_held([second.handle()]);
        let snapshot = store.snapshot().unwrap();
        let held: BTreeSet<[u8; 32]> = snapshot
            .held(second.handle())
            .unwrap()
            .iter_ordered()
            .copied()
            .collect();
        for descriptor in [second.handle(), first.handle(), root.handle()] {
            assert!(held.contains(&descriptor.raw));
        }

        let mut carrier = MemoryRepo::for_host(key(43).verifying_key());
        for blob in &held {
            let bytes: Bytes = snapshot
                .get::<Bytes, UnknownBlob>(Inline::new(*blob))
                .unwrap();
            carrier.put::<UnknownBlob, _>(bytes).unwrap();
        }
        drop(snapshot);
        for leaf in derives_in(&mut store, second.handle()) {
            carrier.insert(CollectionRecord::Derive(leaf)).unwrap();
        }
        let mapped = (FIRST_MAP_CALLS.get(), SECOND_MAP_CALLS.get());
        drop(block_on(carrier.maintain(second, &key(43))).unwrap());
        let carried = merges_in(&mut carrier, second.handle());
        assert_eq!(carried.len(), 1);
        assert_eq!(inputs(&carried[0]).len(), 8);
        assert_eq!(
            (FIRST_MAP_CALLS.get(), SECOND_MAP_CALLS.get()),
            mapped,
            "the carrier maps nothing"
        );
    }
}
