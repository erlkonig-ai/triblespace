use super::*;
use crate::blob::encodings::entity_id_set::{EntityIdSet, EntityIdSetBlob};
use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use crate::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
use crate::collection::{
    succinctarchive_union, AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt,
};
use crate::id::Id;
use crate::inline::{Inline, IntoInline};
use crate::metadata;
use crate::repo::async_store::AsyncBlobStoreGet;
use crate::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use crate::repo::{BlobStorePut, CapabilityProofStore, ReadFailure, SnapshotSource, StoreRead};
use crate::trible::{Trible, TribleSet};
use std::error::Error;
use std::sync::Mutex;

#[derive(Clone)]
struct ColdSnapshot<S> {
    frozen: S,
    source: S,
    fail: Option<[u8; 32]>,
    requested: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl<S: StoreRead> AsyncBlobStoreGet for ColdSnapshot<S> {
    type GetError<E: Error + Send + Sync + 'static> = ReadFailure;
    fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> impl std::future::Future<Output = Result<T, ReadFailure>> + Send
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        let raw = handle.raw;
        async move {
            if self.fail == Some(raw) {
                return Err(ReadFailure::new(std::io::Error::other(
                    "injected storage failure",
                )));
            }
            let handle = Inline::<Handle<E>>::new(raw);
            if self
                .frozen
                .contains_blob(handle)
                .map_err(ReadFailure::new)?
            {
                return self.frozen.get(handle).map_err(ReadFailure::new);
            }
            self.requested.lock().unwrap().push(raw);
            self.source.get(handle).map_err(ReadFailure::new)
        }
    }
}

fn host() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[91; 32])
}
fn facts(byte: u8) -> TribleSet {
    let entity = Id::new([byte; 16]).unwrap();
    let tag = Id::new([byte + 1; 16]).unwrap();
    [Trible::force::<crate::inline::encodings::genid::GenId>(
        &entity,
        &metadata::tag.id(),
        &tag.to_inline(),
    )]
    .into_iter()
    .collect()
}
fn fixture() -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<SuccinctArchiveBlob>,
) {
    let key = host();
    let mut source = MemoryRepo::for_host(key.verifying_key());
    let root = source
        .collection(
            "cold read",
            CollectionPolicy::new(
                AdmissionPolicy::direct(key.verifying_key()),
                AdmissionPolicy::direct(key.verifying_key()),
            ),
        )
        .unwrap();
    let attached = source.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
    (source, root, attached)
}
fn cold(source: &mut MemoryRepo, omit: [u8; 32]) -> ColdSnapshot<MemoryRepoSnapshot> {
    let source = source.snapshot().unwrap();
    let mut local = MemoryRepo::for_host(host().verifying_key());
    for info in source.blobs() {
        let handle = info.unwrap().handle;
        if handle.raw != omit {
            local
                .put::<UnknownBlob, _>(source.get::<anybytes::Bytes, _>(handle).unwrap())
                .unwrap();
        }
    }
    for record in source.records().unwrap() {
        local.insert(record.unwrap()).unwrap();
    }
    for proof in source.proofs().unwrap() {
        local.insert_proof(proof.unwrap()).unwrap();
    }
    ColdSnapshot {
        frozen: local.snapshot().unwrap(),
        source,
        fail: None,
        requested: Default::default(),
    }
}
fn reader(
    snapshot: ColdSnapshot<MemoryRepoSnapshot>,
) -> AcquiringReader<ColdSnapshot<MemoryRepoSnapshot>> {
    AcquiringReader::new(snapshot, Arc::new(tokio::runtime::Runtime::new().unwrap()))
}

#[test]
fn acquiring_residual_keeps_fixed_support_and_passive_reads_do_not_fetch() {
    let (mut source, root, attached) = fixture();
    let ids = source
        .attach::<EntityIdSetBlob>(root, metadata::tag.id())
        .unwrap();
    let first = facts(11);
    let payload = IntoBlob::<SimpleArchive>::to_blob(first.clone())
        .get_handle()
        .raw;
    source.commit(root, &host(), first.clone().into()).unwrap();
    let mut frozen = cold(&mut source, payload);
    source.commit(root, &host(), facts(21).into()).unwrap();
    frozen.source = source.snapshot().unwrap(); // a provider can know newer records
    let requests = frozen.requested.clone();
    let reader = reader(frozen);
    let selected = reader.attached(attached).unwrap();
    assert_eq!(selected.residual().len(), 1);
    assert!(succinctarchive_union::read_attached(&selected)
        .unwrap()
        .value()
        .iter()
        .next()
        .is_none());
    assert!(requests.lock().unwrap().is_empty());
    let acquired = succinctarchive_union::read_attached_acquiring(&selected).unwrap();
    assert_eq!(acquired.value().iter().collect::<TribleSet>(), first);
    assert!(acquired.unread().is_empty());
    assert_eq!(selected.residual().len(), 1);
    assert!(!reader
        .contains_blob(Inline::<Handle<SimpleArchive>>::new(payload))
        .unwrap());
    assert!(requests.lock().unwrap().iter().all(|raw| *raw == payload));
    let projected = reader
        .attached(ids)
        .unwrap()
        .read_acquiring::<EntityIdSet>()
        .unwrap();
    assert_eq!(
        projected.value().iter().collect::<Vec<_>>(),
        vec![Id::new([12; 16]).unwrap()]
    );
    assert!(projected.unread().is_empty());
    let selected_root = reader.collection_acquiring(root).unwrap();
    assert_eq!(selected_root.support().unwrap().len(), 1);
    assert_eq!(selected_root.view::<TribleSet>().unwrap(), first);
}

#[test]
fn acquiring_unavailable_is_unread_but_faults_are_errors() {
    let (mut source, root, attached) = fixture();
    let first = facts(31);
    let payload = IntoBlob::<SimpleArchive>::to_blob(first.clone())
        .get_handle()
        .raw;
    source.commit(root, &host(), first.into()).unwrap();
    let mut snapshot = cold(&mut source, payload);
    snapshot.source = snapshot.frozen.clone(); // no provider
    let reader = reader(snapshot.clone());
    let selected = reader.attached(attached).unwrap();
    let read = succinctarchive_union::read_attached_acquiring(&selected).unwrap();
    assert_eq!(read.unread().len(), 1);
    assert!(reader
        .collection_acquiring(root)
        .unwrap()
        .view::<TribleSet>()
        .is_err());
    snapshot.fail = Some(payload);
    let failed_reader =
        super::AcquiringReader::new(snapshot, Arc::new(tokio::runtime::Runtime::new().unwrap()));
    let error =
        succinctarchive_union::read_attached_acquiring(&failed_reader.attached(attached).unwrap())
            .err()
            .expect("backend fault must not become unread");
    assert!(error.to_string().contains("injected storage failure"));
}

#[test]
fn acquiring_attached_selection_gets_missing_lineage_descriptors() {
    let (mut source, root, attached) = fixture();
    let expected = facts(51);
    source
        .commit(root, &host(), expected.clone().into())
        .unwrap();
    for missing in [root.handle().raw, attached.handle().raw] {
        let snapshot = cold(&mut source, missing);
        let requests = snapshot.requested.clone();
        let acquiring = reader(snapshot.clone());
        assert!(acquiring.attached(attached).is_err());
        assert!(
            requests.lock().unwrap().is_empty(),
            "passive selection must not fetch"
        );
        let selected = acquiring.attached_acquiring(attached).unwrap();
        let read = succinctarchive_union::read_attached_acquiring(&selected).unwrap();
        assert_eq!(read.value().iter().collect::<TribleSet>(), expected);
        assert!(read.unread().is_empty());
        assert!(requests.lock().unwrap().contains(&missing));
        assert!(!acquiring
            .contains_blob(Inline::<Handle<SimpleArchive>>::new(missing))
            .unwrap());

        let mut unavailable = snapshot.clone();
        unavailable.source = unavailable.frozen.clone();
        assert!(matches!(
            reader(unavailable).attached_acquiring(attached),
            Err(crate::collection::CollectionRealizationError::MissingDependency { .. })
        ));
        let mut failed = snapshot;
        failed.fail = Some(missing);
        let error = reader(failed).attached_acquiring(attached).err().unwrap();
        assert!(error.to_string().contains("injected storage failure"));
    }
}

#[test]
fn acquiring_missing_write_definition_retries_only_frozen_parked_records() {
    let (mut source, root, attached) = fixture();
    let first = facts(41);
    source.commit(root, &host(), first.clone().into()).unwrap();
    let definition = crate::collection::write_capability();
    let snapshot = cold(&mut source, definition.raw);
    assert!(snapshot
        .frozen
        .attached(attached)
        .unwrap()
        .residual()
        .is_empty());
    let reader = reader(snapshot.clone());
    let selected = reader.attached(attached).unwrap();
    let read = succinctarchive_union::read_attached_acquiring(&selected).unwrap();
    assert_eq!(read.value().iter().collect::<TribleSet>(), first);
    let selected_support = selected.support().clone();
    let retained = selected.into_frozen();
    assert_eq!(retained.support(), &selected_support);
    assert_eq!(retained.residual().len(), 1);
    assert!(retained
        .snapshot()
        .frozen
        .attached(attached)
        .unwrap()
        .residual()
        .is_empty());
    let mut failed = snapshot;
    failed.fail = Some(definition.raw);
    let reader =
        super::AcquiringReader::new(failed, Arc::new(tokio::runtime::Runtime::new().unwrap()));
    assert!(reader.attached(attached).is_err());
    let error = root
        .writer_is_admitted_acquiring(&reader, host().verifying_key())
        .unwrap_err();
    assert!(error.to_string().contains("injected storage failure"));
}

impl<S: crate::repo::StoreSnapshot> crate::repo::StoreSnapshot for ColdSnapshot<S> {
    fn changes_since(&self, previous: &Self) -> crate::repo::StoreChanges {
        self.frozen.changes_since(&previous.frozen)
    }

    fn changes_for(
        &self,
        previous: &Self,
        dependencies: &crate::repo::StoreDependencies,
    ) -> crate::repo::StoreChanges {
        self.frozen.changes_for(&previous.frozen, dependencies)
    }
}

impl<S: CapabilityProofRead> CapabilityProofRead for ColdSnapshot<S> {
    type ProofsError = S::ProofsError;
    type ProofIter<'a>
        = S::ProofIter<'a>
    where
        Self: 'a;

    fn proofs(&self) -> Result<Self::ProofIter<'_>, Self::ProofsError> {
        self.frozen.proofs()
    }

    fn proof(
        &self,
        id: crate::capability::CapabilityProofId,
    ) -> Result<Option<crate::capability::CapabilityProof>, Self::ProofsError> {
        self.frozen.proof(id)
    }
}

impl<S: BlobStoreList> BlobStoreList for ColdSnapshot<S> {
    type Err = S::Err;
    type Iter<'a>
        = S::Iter<'a>
    where
        Self: 'a;

    fn blobs(&self) -> Self::Iter<'_> {
        self.frozen.blobs()
    }

    fn contains_blob<E>(&self, handle: crate::inline::Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: crate::blob::BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.contains_blob(handle)
    }
}

impl<S: crate::repo::BlobStoreMeta> crate::repo::BlobStoreMeta for ColdSnapshot<S> {
    type MetaError = S::MetaError;

    fn metadata<E>(
        &self,
        handle: crate::inline::Inline<Handle<E>>,
    ) -> Result<Option<crate::repo::BlobMetadata>, Self::MetaError>
    where
        E: crate::blob::BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.metadata(handle)
    }
}

impl<S: CollectionRead> CollectionRead for ColdSnapshot<S> {
    type RecordsError = S::RecordsError;
    type RecordIter<'a>
        = S::RecordIter<'a>
    where
        Self: 'a;

    fn records(&self) -> Result<Self::RecordIter<'_>, Self::RecordsError> {
        self.frozen.records()
    }

    fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
        self.frozen.collections()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.frozen.select_records(selectors)
    }
}

impl<S: crate::collection::CoverageRead> crate::collection::CoverageRead for ColdSnapshot<S> {
    fn index(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<crate::collection::coverage::CoverageIndex, Self::RecordsError> {
        self.frozen.index(lineage)
    }
}

impl<S: crate::repo::WantRead> crate::repo::WantRead for ColdSnapshot<S> {
    type WantsError = S::WantsError;
    type WantIter<'a>
        = S::WantIter<'a>
    where
        Self: 'a;

    fn wants(&self) -> Result<Self::WantIter<'_>, Self::WantsError> {
        self.frozen.wants()
    }
}
