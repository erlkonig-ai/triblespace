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
    CollectionMerge, CollectionPolicy, CollectionRead, CollectionRecord, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt, Support,
};
use triblespace_core::id::ExclusiveId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{InlineEncoding, RawInline};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, BlobStorePut, CapabilityProofStore, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use crate::path_summary_union;
use crate::{Automaton, PathIndex, PathSummaryBlob, Step, Transition};

/// The root commits a view stands for, following each root foundation up
/// the view's descriptor chain through the leaves of every hop. Lattice v2
/// supports are collection-local, so this is the only way a test can still
/// say "this view stands for these commits".
fn stood_for<R, E>(
    view: &triblespace_core::collection::CollectionSnapshot<R, E>,
) -> triblespace_core::collection::Support
where
    R: triblespace_core::repo::StoreRead,
    E: triblespace_core::collection::CollectionEncoding,
{
    use triblespace_core::collection::{descriptor, Collection, SourceLocator};
    use triblespace_core::inline::encodings::hash::Handle;
    let snapshot = view.snapshot();
    let mut chain = vec![view.cover().collection().handle()];
    loop {
        let facts: triblespace_core::trible::TribleSet =
            snapshot.get(*chain.last().unwrap()).unwrap();
        match descriptor::source(&facts).unwrap() {
            Some(source) => chain.push(source),
            None => break,
        }
    }
    let root: Collection<triblespace_core::blob::encodings::simplearchive::SimpleArchive> =
        Collection::open(snapshot, *chain.last().unwrap()).unwrap();
    let scope: std::collections::BTreeSet<_> = chain.iter().copied().collect();
    let coverage = snapshot.coverage(&scope).unwrap();
    let top: std::collections::BTreeSet<[u8; 32]> = view
        .support()
        .unwrap()
        .members()
        .map(|member| member.raw)
        .collect();
    let (foundations, _) = coverage.frontier_support(root.handle());
    root.cover(
        foundations
            .iter_ordered()
            .filter(|raw| {
                let mut images = std::collections::BTreeSet::from([**raw]);
                for hop in chain.iter().rev().skip(1) {
                    images = images
                        .iter()
                        .flat_map(|image| coverage.leaf_outputs(*hop, SourceLocator::of(*image)))
                        .map(|output| output.raw)
                        .collect();
                }
                images.iter().any(|image| top.contains(image))
            })
            .map(|raw| Handle::from_hash(triblespace_core::inline::Inline::new(*raw)))
            .collect::<Vec<_>>(),
    )
}

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

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.0.snapshot()
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
    assert!(support.is_empty());
    let snapshot = block_on(store.maintain(target, &authority_key())).unwrap();
    let observed = snapshot.collection(target).unwrap();
    assert_eq!(stood_for(&observed), support);
    let index: Arc<PathIndex> = observed.view().unwrap();
    assert_eq!(index.accepted_pair_count(), 0);
    assert_eq!(store.0.blobs.len(), blobs);
    assert_eq!(records(&mut store).len(), record_count);
}

#[test]
fn missing_then_maintain_closes_cross_fragment_path() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    // The maintaining key wrote both fragments, so both are its to derive.
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 1, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let support = support(&mut store, source, [first, second]);
    // Admitted but not yet derived data is absent from a read: until it is
    // maintained, the target stands on nothing.
    let before = store.snapshot().unwrap();
    let unrealized = before.collection(target).unwrap();
    assert!(unrealized.cover().is_empty());
    assert!(unrealized.support().unwrap().is_empty());
    assert_eq!(
        unrealized
            .missing_from(&before.collection(source).unwrap())
            .unwrap(),
        support
    );

    let after = block_on(store.maintain(target, &authority_key())).unwrap();
    let observed = after.collection(target).unwrap();
    assert_eq!(stood_for(&observed), support);
    assert!(observed
        .missing_from(&after.collection(source).unwrap())
        .unwrap()
        .is_empty());
    assert_cross_fragment_path(&observed.view::<Arc<PathIndex>>().unwrap());
}

#[test]
fn another_writers_fragment_is_its_writers_to_derive() {
    let mut store = CollectionOnly::default();
    let (source, target) = test_paths(&mut store, "paths", plus());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 2, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    support(&mut store, source, [first, second]);

    // The maintaining key derives what it wrote; the other writer's
    // fragment is that writer's lag, and freshness names exactly it.
    let after = block_on(store.maintain(target, &authority_key())).unwrap();
    let observed = after.collection(target).unwrap();
    assert_eq!(stood_for(&observed).len(), 1);
    let missing = observed
        .missing_from(&after.collection(source).unwrap())
        .unwrap();
    assert_eq!(
        missing.members().collect::<Vec<_>>(),
        vec![right.get_handle()]
    );
    let index: Arc<PathIndex> = observed.view().unwrap();
    assert!(!index.contains(&RawInline::from(id(1)), &RawInline::from(id(3))));
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
    assert_eq!(support.len(), 1);
    block_on(store.ensure(target, &authority_key())).unwrap();
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
    let automaton = plus();
    let (source, target) = test_paths(&mut store, "paths", automaton.clone());
    let left = put_data(&mut store, &edge(1, 2));
    let right = put_data(&mut store, &edge(2, 3));
    let first = signed_commit(&mut store, source, 1, &left);
    let second = signed_commit(&mut store, source, 1, &right);
    publish(&mut store, first);
    publish(&mut store, second);
    let joined = simplearchive_union::join(&left, &right).unwrap();
    store.put::<SimpleArchive, _>(joined.clone()).unwrap();
    let joined_data = Handle::<SimpleArchive>::to_hash(joined.get_handle());
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &authority_key(),
                source.handle(),
                [first.data(), second.data()],
                joined_data,
            )
            .unwrap(),
        ))
        .unwrap();
    let support = support(&mut store, source, [first, second]);

    let snapshot = block_on(store.maintain(target, &authority_key())).unwrap();
    let observed = snapshot.collection(target).unwrap();
    assert_eq!(stood_for(&observed), support);
    assert_cross_fragment_path(&observed.view::<Arc<PathIndex>>().unwrap());
    // One leaf per source foundation, never one for the merged node, and
    // the source MERGE lowered once: a target MERGE of the two leaf images
    // whose result is the merged node's own bytes mapped.
    let published = records(&mut store);
    let mut leaves: Vec<_> = published
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(claim) if claim.collection() == target.handle() => {
                Some(claim.input())
            }
            _ => None,
        })
        .collect();
    leaves.sort();
    let mut expected = vec![
        triblespace_core::collection::SourceLocator::of(first.data().raw),
        triblespace_core::collection::SourceLocator::of(second.data().raw),
    ];
    expected.sort();
    assert_eq!(leaves, expected);
    let mirrors: Vec<_> = published
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) if merge.collection() == target.handle() => Some(*merge),
            _ => None,
        })
        .collect();
    assert_eq!(mirrors.len(), 1);
    let image = |blob: &Blob<SimpleArchive>| {
        Handle::<PathSummaryBlob>::to_hash(
            path_summary_union::derive_element(blob, &automaton)
                .unwrap()
                .get_handle(),
        )
    };
    let mut images = vec![image(&left), image(&right)];
    images.sort_by(|a, b| a.raw.cmp(&b.raw));
    assert_eq!(mirrors[0].inputs(), images.as_slice());
    assert_eq!(mirrors[0].result(), image(&joined));
    assert_eq!(observed.cover().len(), 1);

    // Lowered once: a second pass publishes nothing.
    drop(observed);
    drop(snapshot);
    block_on(store.maintain(target, &authority_key())).unwrap();
    assert_eq!(records(&mut store), published);
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
            triblespace_core::collection::SourceLocator::of(input.data().raw),
            Handle::<PathSummaryBlob>::to_hash(output.get_handle()),
        );
        store.insert(CollectionRecord::Derive(record)).unwrap();
        record
    });
    let joined = PathSummaryBlob::join(&left_summary, &right_summary, &automaton).unwrap();
    store.put::<PathSummaryBlob, _>(joined.clone()).unwrap();
    let joined_data = Handle::<PathSummaryBlob>::to_hash(joined.get_handle());
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &authority_key(),
                target.handle(),
                [derives[0].output(), derives[1].output()],
                joined_data,
            )
            .unwrap(),
        ))
        .unwrap();
    let support = support(&mut store, source, [first, second]);
    let snapshot = store.snapshot().unwrap();
    let observation = snapshot.collection(target).unwrap();
    assert_eq!(observation.cover().len(), 1);
    assert_eq!(
        observation.cover().members().next().unwrap(),
        joined.get_handle()
    );
    assert_eq!(stood_for(&observation), support);
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
    // The commit is admitted, but its bytes are not here: neither the source
    // nor the target has a resident member to stand on.
    assert!(before.collection(source).unwrap().cover().is_empty());
    assert!(before.collection(target).unwrap().cover().is_empty());

    store.put::<SimpleArchive, _>(absent.clone()).unwrap();
    let after = store.snapshot().unwrap();
    assert_eq!(source.admitted(&after).unwrap(), support);
    let source_view = after.collection(source).unwrap();
    assert_eq!(source_view.support().unwrap(), &support);
    assert_eq!(source_view.view::<TribleSet>().unwrap(), edge(1, 2));
    assert_eq!(records(&mut store), before_records);
    assert!(before.collection(source).unwrap().cover().is_empty());
    // Arriving source bytes need no new COMMIT, but do not manufacture a
    // target DERIVE: the target still stands on nothing.
    let target_view = after.collection(target).unwrap();
    assert!(target_view.cover().is_empty());
    assert!(target_view.support().unwrap().is_empty());
}
