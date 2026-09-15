//! Direct collection lifecycle tests for regular-path summaries.

#![cfg(test)]

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, BlobEncoding, Bytes, IntoBlob, TryFromBlob};
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::collection::simplearchive_union;
use triblespace_core::collection::{
    write_capability, Collection, CollectionCommit, CollectionDerive, CollectionEncoding,
    CollectionMerge, CollectionPolicy, CollectionRead, CollectionRealizationError,
    CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt, Support,
};
use triblespace_core::id::ExclusiveId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{InlineEncoding, RawInline};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{BlobStoreGet, BlobStorePut, CapabilityProofStore, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use crate::path_summary_union;
use crate::{Automaton, PathIndex, PathSummaryBlob, Step, Transition};

#[derive(Default)]
struct CollectionOnly(MemoryRepo);

impl BlobStorePut for CollectionOnly {
    type PutError = <MemoryRepo as BlobStorePut>::PutError;

    fn put<E, T>(
        &mut self,
        item: T,
    ) -> Result<triblespace_core::inline::Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: triblespace_core::blob::IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.0.put(item)
    }
}

impl SnapshotSource for CollectionOnly {
    type Snapshot = <MemoryRepo as SnapshotSource>::Snapshot;
    type SnapshotError = <MemoryRepo as SnapshotSource>::SnapshotError;

    fn snapshot_at(
        &mut self,
        instant: hifitime::Epoch,
    ) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.0.snapshot_at(instant)
    }
}

impl AsyncBlobStoreAcquire for CollectionOnly {
    type AcquireError = <MemoryRepo as AsyncBlobStoreAcquire>::AcquireError;

    fn acquire(
        &mut self,
        handle: triblespace_core::inline::Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        self.0.acquire(handle)
    }
}

impl CollectionStore for CollectionOnly {
    type InsertError = <MemoryRepo as CollectionStore>::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.0.insert(record)
    }
}

impl CapabilityProofStore for CollectionOnly {
    type InsertError = <MemoryRepo as CapabilityProofStore>::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.0.insert_proof(proof)
    }
}

fn id(byte: u8) -> triblespace_core::id::Id {
    triblespace_core::id::Id::new([byte; 16]).unwrap()
}

fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn authority() -> VerifyingKey {
    authority_key().verifying_key()
}

fn policy(authority: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        triblespace_core::collection::AdmissionPolicy::direct(authority),
        triblespace_core::collection::AdmissionPolicy::direct(authority),
    )
}

fn test_paths(
    store: &mut CollectionOnly,
    name: &str,
    automaton: Automaton,
) -> (Collection<SimpleArchive>, Collection<PathSummaryBlob>) {
    let source = store.collection(name, policy(authority())).unwrap();
    let target = store
        .derive::<PathSummaryBlob>(source, automaton, policy(authority()))
        .unwrap();
    (source, target)
}

fn plus() -> Automaton {
    Automaton::new(
        2,
        [0],
        [1],
        [
            Transition::new(0, 1, Step::Forward(metadata::tag.id().into())),
            Transition::new(1, 1, Step::Forward(metadata::tag.id().into())),
        ],
    )
    .unwrap()
}

fn edge(source: u8, target: u8) -> TribleSet {
    let source = id(source);
    entity! { ExclusiveId::force_ref(&source) @ metadata::tag: id(target) }.into_facts()
}

fn put_data(store: &mut CollectionOnly, facts: &TribleSet) -> Blob<SimpleArchive> {
    let blob = facts.to_blob();
    store.put::<SimpleArchive, _>(blob.clone()).unwrap();
    blob
}

fn signed_commit(
    store: &mut CollectionOnly,
    collection: Collection<SimpleArchive>,
    key: u8,
    data: &Blob<SimpleArchive>,
) -> CollectionCommit {
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    CollectionCommit::sign(
        &SigningKey::from_bytes(&[key; 32]),
        collection.handle(),
        Handle::<SimpleArchive>::to_hash(data.get_handle()),
        metadata,
    )
}

fn publish(store: &mut CollectionOnly, commit: CollectionCommit) {
    store.insert(CollectionRecord::Commit(commit)).unwrap();
}

fn support(
    store: &mut CollectionOnly,
    collection: Collection<SimpleArchive>,
    commits: impl IntoIterator<Item = CollectionCommit>,
) -> Support {
    let root = authority_key();
    let mut writers: Vec<_> = commits
        .into_iter()
        .map(|commit| VerifyingKey::from_bytes(&commit.public_key().raw).unwrap())
        .filter(|writer| *writer != root.verifying_key())
        .collect();
    writers.sort_unstable_by_key(VerifyingKey::to_bytes);
    writers.dedup();
    for writer in writers {
        let proof = CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            write_capability(),
            writer,
        );
        store.insert_proof(proof).unwrap();
    }
    collection.admitted(&store.snapshot().unwrap()).unwrap()
}

fn records(store: &mut CollectionOnly) -> Vec<CollectionRecord> {
    store
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn descriptor_for<L>(store: &mut CollectionOnly, collection: Collection<L>) -> Fragment
where
    L: CollectionEncoding,
{
    let snapshot = store.snapshot().unwrap();
    let blob: Blob<SimpleArchive> = snapshot.get(collection.handle()).unwrap();
    Fragment::from(TribleSet::try_from_blob(blob).unwrap())
}

fn index(
    snapshot: &MemoryRepoSnapshot,
    target: Collection<PathSummaryBlob>,
    support: &Support,
) -> Arc<PathIndex> {
    snapshot
        .collection_exact(target, support)
        .unwrap()
        .view()
        .unwrap()
}

fn assert_cross_fragment_path(index: &PathIndex) {
    assert!(index.contains(&RawInline::from(id(1)), &RawInline::from(id(3))));
}

#[test]
fn source_and_target_policies_are_independent() {
    let mut store = CollectionOnly::default();
    let source = store.collection("paths", policy(authority())).unwrap();
    let target = store
        .derive::<PathSummaryBlob>(
            source,
            plus(),
            policy(SigningKey::from_bytes(&[2; 32]).verifying_key()),
        )
        .unwrap();
    let other_source = store
        .collection(
            "paths",
            policy(SigningKey::from_bytes(&[3; 32]).verifying_key()),
        )
        .unwrap();
    let other_target = store
        .derive::<PathSummaryBlob>(
            other_source,
            plus(),
            policy(SigningKey::from_bytes(&[2; 32]).verifying_key()),
        )
        .unwrap();

    assert_ne!(source, other_source);
    assert_ne!(target, other_target);
}

#[test]
fn malformed_fixed_representation_capacity_is_fatal() {
    let automaton = Automaton::new(u32::MAX, [0], [0], []).unwrap();
    let mut store = CollectionOnly::default();
    let (_, target) = test_paths(&mut store, "paths", automaton.clone());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&crate::automaton_fingerprint(&automaton).raw);
    bytes.extend_from_slice(&automaton.state_count().to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[2; 32]);
    let persisted = Blob::<PathSummaryBlob>::new(bytes.into());
    let descriptor = descriptor_for(&mut store, target);
    let reader = store.snapshot().unwrap();
    assert!(matches!(
        <PathSummaryBlob as CollectionEncoding>::validate_member(&descriptor, &persisted, &reader,),
        Err(triblespace_core::collection::CollectionOperationError::Fatal(_))
    ));
}

#[test]
fn empty_support_is_local_bottom_and_writes_nothing() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let blobs = store.0.blobs.len();
    let record_count = records(&mut store).len();
    let support = support(&mut store, source, []);
    let snapshot = block_on(store.maintain_exact(target, &authority_key(), &support)).unwrap();
    assert_eq!(index(&snapshot, target, &support).accepted_pair_count(), 0);
    assert_eq!(store.0.blobs.len(), blobs);
    assert_eq!(records(&mut store).len(), record_count);
}

#[test]
fn missing_then_maintain_closes_cross_fragment_path() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 2, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let support = support(&mut store, source, [first, second]);
    let before = store.snapshot().unwrap();
    assert!(matches!(
        before.collection_exact(target, &support),
        Err(CollectionRealizationError::IncompleteCover {
            unsupported_members,
            ..
        }) if unsupported_members.len() == 2
    ));

    let after = block_on(store.maintain_exact(target, &authority_key(), &support)).unwrap();
    assert_cross_fragment_path(&index(&after, target, &support));
}

#[test]
fn exact_old_support_ignores_a_later_commit_and_equation() {
    let mut store = CollectionOnly::default();
    let automaton = plus();
    let (source, target) = test_paths(&mut store, "paths", automaton.clone());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 2, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let old_support = support(&mut store, source, [first, second]);
    block_on(store.maintain_exact(target, &authority_key(), &old_support)).unwrap();

    let later = put_data(&mut store, &edge(3, 4));
    let third = signed_commit(&mut store, source, 3, &later);
    publish(&mut store, third);
    let later_summary = path_summary_union::derive_element(&later, &automaton).unwrap();
    store
        .put::<PathSummaryBlob, _>(later_summary.clone())
        .unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &authority_key(),
            target.handle(),
            (third.data(), third.fingerprint()),
            Handle::<PathSummaryBlob>::to_hash(later_summary.get_handle()),
        )))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let old = index(&snapshot, target, &old_support);
    assert!(!old.contains(&RawInline::from(id(1)), &RawInline::from(id(4))));
}

#[test]
fn duplicate_payload_provenance_shares_one_derive() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let data = put_data(&mut store, &edge(1, 2));
    let first = signed_commit(&mut store, source, 1, &data);
    let second = signed_commit(&mut store, source, 2, &data);
    publish(&mut store, first);
    publish(&mut store, second);
    let support = support(&mut store, source, [first, first, second]);
    block_on(store.ensure_exact(target, &authority_key(), &support)).unwrap();
    let derives = records(&mut store)
        .into_iter()
        .filter(|record| {
            matches!(record, CollectionRecord::Derive(claim)
                if claim.collection() == target.handle())
        })
        .count();
    assert_eq!(derives, 1);
}

#[test]
fn resident_source_merge_is_lowered_once() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 2, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let joined = simplearchive_union::join(&left, &right).unwrap();
    store.put::<SimpleArchive, _>(joined.clone()).unwrap();
    let joined_data = Handle::<SimpleArchive>::to_hash(joined.get_handle());
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &authority_key(),
            source.handle(),
            (first.data(), first.fingerprint()),
            (second.data(), second.fingerprint()),
            joined_data,
        )))
        .unwrap();
    let support = support(&mut store, source, [first, second]);

    let snapshot = block_on(store.maintain_exact(target, &authority_key(), &support)).unwrap();
    assert_cross_fragment_path(&index(&snapshot, target, &support));
    let inputs: Vec<_> = records(&mut store)
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(claim) if claim.collection() == target.handle() => {
                Some(claim.input())
            }
            _ => None,
        })
        .collect();
    assert_eq!(inputs, vec![joined_data]);
}

#[test]
fn existing_target_merge_is_selected_as_one_physical_member() {
    let mut store = CollectionOnly::default();
    let automaton = plus();
    let (source, target) = test_paths(&mut store, "paths", automaton.clone());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 2, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let left_summary = path_summary_union::derive_element(&left, &automaton).unwrap();
    let right_summary = path_summary_union::derive_element(&right, &automaton).unwrap();
    let derives = [(first, &left_summary), (second, &right_summary)].map(|(input, output)| {
        store.put::<PathSummaryBlob, _>(output.clone()).unwrap();
        let record = CollectionDerive::sign(
            &authority_key(),
            target.handle(),
            (input.data(), input.fingerprint()),
            Handle::<PathSummaryBlob>::to_hash(output.get_handle()),
        );
        store.insert(CollectionRecord::Derive(record)).unwrap();
        record
    });
    let joined = PathSummaryBlob::join(&left_summary, &right_summary, &automaton).unwrap();
    store.put::<PathSummaryBlob, _>(joined.clone()).unwrap();
    let joined_data = Handle::<PathSummaryBlob>::to_hash(joined.get_handle());
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &authority_key(),
            target.handle(),
            (derives[0].output(), derives[0].fingerprint()),
            (derives[1].output(), derives[1].fingerprint()),
            joined_data,
        )))
        .unwrap();
    let support = support(&mut store, source, [first, second]);
    let snapshot = store.snapshot().unwrap();
    let observation = snapshot.collection_exact(target, &support).unwrap();
    assert_eq!(observation.cover().len(), 1);
    assert_eq!(
        observation.cover().members().next().unwrap(),
        joined.get_handle()
    );
    assert_cross_fragment_path(&observation.view::<Arc<PathIndex>>().unwrap());
}

#[test]
fn absent_source_bytes_delay_residency_but_not_record_admission() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let absent = edge(1, 2).to_blob();
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    let commit = CollectionCommit::sign(
        &SigningKey::from_bytes(&[5; 32]),
        source.handle(),
        Handle::<SimpleArchive>::to_hash(absent.get_handle()),
        metadata,
    );
    publish(&mut store, commit);
    let support = support(&mut store, source, [commit]);
    assert_eq!(support.len(), 1);
    assert!(support.contains(absent.get_handle()));
    let before_records = records(&mut store);
    let before = store.snapshot().unwrap();
    assert!(before.collection(source).unwrap().cover().is_empty());
    assert!(before.collection(target).unwrap().cover().is_empty());
    assert!(matches!(
        before.collection_exact(source, &support),
        Err(CollectionRealizationError::IncompleteCover {
            unsupported_members,
            ..
        }) if unsupported_members == vec![commit.data()]
    ));
    assert!(matches!(
        before.collection_exact(target, &support),
        Err(CollectionRealizationError::IncompleteCover {
            unsupported_members,
            ..
        }) if unsupported_members == vec![commit.data()]
    ));

    store.put::<SimpleArchive, _>(absent.clone()).unwrap();
    let after = store.snapshot().unwrap();
    assert_eq!(source.admitted(&after).unwrap(), support);
    let source_view = after.collection_exact(source, &support).unwrap();
    assert_eq!(source_view.view::<TribleSet>().unwrap(), edge(1, 2));
    assert_eq!(records(&mut store), before_records);
    assert!(before.collection(source).unwrap().cover().is_empty());
    // Arriving source bytes need no new COMMIT, but do not manufacture a
    // target DERIVE: the same exact request is still incomplete there.
    assert!(matches!(
        after.collection_exact(target, &support),
        Err(CollectionRealizationError::IncompleteCover {
            unsupported_members,
            ..
        }) if unsupported_members == vec![commit.data()]
    ));
}
