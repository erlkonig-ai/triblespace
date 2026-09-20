//! The collections derived from a source are found from their descriptors
//! and taken up as a group: ensured after a write so the write is readable
//! through every view, maintained by a daemon to their fixed points.

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace_core::collection::{
    derived_from, ensure_derived, maintain_derived, AdmissionPolicy, Collection,
    CollectionPolicy, CollectionRead, CollectionRecord, CollectionSnapshotExt,
    CollectionStoreExt, CoreRealizer, Derived, RealizeDerived, Realized, Upkeep,
};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace_core::repo::{SnapshotSource, Store};
use triblespace_core::trible::Fragment;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn open_for(root: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(root.verifying_key()),
    )
}

fn fragment(name: &'static str) -> Fragment {
    entity! { metadata::name: name }
}

struct Chain {
    source: Collection<SimpleArchive>,
    succinct: Collection<SuccinctArchiveBlob>,
    rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
}

fn chain(store: &mut MemoryRepo, name: &str, owner: &SigningKey) -> Chain {
    let policy = open_for(owner);
    let source = store.collection(name, policy.clone()).unwrap();
    let succinct = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let rank9 = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .unwrap();
    Chain {
        source,
        succinct,
        rank9,
    }
}

fn record_kinds(store: &mut MemoryRepo) -> (usize, usize, usize) {
    let snapshot = store.snapshot().unwrap();
    let mut counts = (0, 0, 0);
    for record in snapshot.records().unwrap() {
        match record.unwrap() {
            CollectionRecord::Commit(_) => counts.0 += 1,
            CollectionRecord::Merge(_) => counts.1 += 1,
            CollectionRecord::Derive(_) => counts.2 += 1,
        }
    }
    counts
}

#[test]
fn derived_collections_are_found_from_their_descriptors_in_dependency_order() {
    let owner = key(1);
    let mut store = MemoryRepo::default();
    let chain = chain(&mut store, "found", &owner);
    let other = chain_named_unrelated(&mut store, &owner);
    // A derived collection joins the listing with its first record, which
    // realizing it once, as registration does, leaves behind.
    store
        .commit(chain.source, &owner, fragment("first"))
        .unwrap();
    store.commit(other, &owner, fragment("elsewhere")).unwrap();
    block_on(store.ensure(chain.succinct, &owner)).unwrap();
    block_on(store.ensure(chain.rank9, &owner)).unwrap();
    let snapshot = store.snapshot().unwrap();
    let derived: Vec<_> = derived_from(&snapshot, chain.source.handle())
        .unwrap()
        .into_iter()
        .map(|derived| (derived.handle, derived.source))
        .collect();
    assert_eq!(
        derived,
        [
            (chain.succinct.handle(), chain.source.handle()),
            (chain.rank9.handle(), chain.succinct.handle()),
        ]
    );
    assert!(derived_from(&snapshot, other.handle()).unwrap().is_empty());
}

fn chain_named_unrelated(store: &mut MemoryRepo, owner: &SigningKey) -> Collection<SimpleArchive> {
    store.collection("unrelated", open_for(owner)).unwrap()
}

#[test]
fn ensure_derived_makes_a_commit_readable_through_every_view_and_publishes_no_merge() {
    let owner = key(2);
    let mut store = MemoryRepo::default();
    let chain = chain(&mut store, "ensured", &owner);
    // The first commit and the registration-time realization put the chain
    // into the listing; every later write finds it there.
    store
        .commit(chain.source, &owner, fragment("one"))
        .unwrap();
    block_on(store.ensure(chain.succinct, &owner)).unwrap();
    block_on(store.ensure(chain.rank9, &owner)).unwrap();

    store
        .commit(chain.source, &owner, fragment("two"))
        .unwrap();
    let report = block_on(ensure_derived(
        &mut store,
        chain.source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert_eq!(
        report.realized,
        [chain.succinct.handle(), chain.rank9.handle()]
    );
    assert!(report.unadmitted.is_empty());
    assert!(report.unknown.is_empty());

    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.collection(chain.rank9).unwrap();
    assert_eq!(observed.support().unwrap().len(), 2);
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.segment_count(), 2, "two leaf images, nothing merged");
    drop(snapshot);
    let (commits, merges, derives) = record_kinds(&mut store);
    assert_eq!((commits, merges), (2, 0));
    assert_eq!(derives, 4, "each commit's image in each lattice");

    // Maintenance carries what ensure left as leaves.
    let report = block_on(maintain_derived(
        &mut store,
        chain.source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert_eq!(
        report.realized,
        [chain.succinct.handle(), chain.rank9.handle()]
    );
    let (_, merges, _) = record_kinds(&mut store);
    assert!(merges > 0, "maintenance merged the two leaves");
    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.collection(chain.rank9).unwrap();
    assert_eq!(observed.support().unwrap().len(), 2);
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.segment_count(), 1);
}

#[test]
fn a_signer_the_target_does_not_admit_and_an_unknown_representation_are_named_not_guessed() {
    let owner = key(3);
    let stranger = key(4);
    let mut store = MemoryRepo::default();
    let chain = chain(&mut store, "guarded", &owner);
    store
        .commit(chain.source, &owner, fragment("guarded"))
        .unwrap();
    block_on(store.ensure(chain.succinct, &owner)).unwrap();
    block_on(store.ensure(chain.rank9, &owner)).unwrap();

    let report = block_on(ensure_derived(
        &mut store,
        chain.source.handle(),
        &stranger,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert!(report.realized.is_empty());
    assert_eq!(
        report.unadmitted,
        [chain.succinct.handle(), chain.rank9.handle()]
    );

    struct KnowsNothing;
    impl<S: Store + AsyncBlobStoreAcquire + Send> RealizeDerived<S> for KnowsNothing {
        async fn realize(
            &mut self,
            _store: &mut S,
            _derived: &Derived,
            _signer: &SigningKey,
            _upkeep: Upkeep,
        ) -> Result<Realized, triblespace_core::collection::CollectionRealizationError> {
            Ok(Realized::Unknown)
        }
    }
    let report = block_on(ensure_derived(
        &mut store,
        chain.source.handle(),
        &owner,
        &mut KnowsNothing,
    ))
    .unwrap();
    assert_eq!(
        report
            .unknown
            .iter()
            .map(|derived| derived.handle)
            .collect::<Vec<_>>(),
        [chain.succinct.handle(), chain.rank9.handle()]
    );
}

#[test]
fn a_descriptor_naming_another_mapping_is_left_to_whoever_registered_it() {
    use triblespace_core::blob::Blob;
    use triblespace_core::collection::{CollectionMapping, CollectionOperationError};
    use triblespace_core::repo::StoreRead;

    /// Succinct images built by a mapping that is not the canonical one: same
    /// target encoding, another algorithm in the descriptor.
    struct OtherWay;
    impl CollectionMapping for OtherWay {
        type Source = SimpleArchive;
        type Target = SuccinctArchiveBlob;
        fn fragment(&self) -> Fragment {
            use triblespace_core::collection::{mapping_algorithm, KIND_COLLECTION_MAPPING};
            let algorithm = triblespace_core::id::rngid();
            entity! {
                metadata::tag: KIND_COLLECTION_MAPPING,
                mapping_algorithm*: entity! {
                    &algorithm @
                        metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
                        metadata::name: "another way to a succinct image",
                },
            }
        }
        fn bind(_: &Fragment, _: &Fragment) -> Result<Self, CollectionOperationError> {
            Ok(OtherWay)
        }
        fn map<R: StoreRead>(
            &self,
            source: &Blob<SimpleArchive>,
            reader: &R,
        ) -> Result<Blob<SuccinctArchiveBlob>, CollectionOperationError> {
            <SuccinctArchiveBlob as triblespace_core::collection::CollectionDerivation>::map(
                &(),
                source,
                reader,
            )
        }
    }

    let owner = key(5);
    let mut store = MemoryRepo::default();
    let policy = open_for(&owner);
    let source = store.collection("mapped", policy.clone()).unwrap();
    let other = store.derive_with(source, OtherWay, policy).unwrap();
    store.commit(source, &owner, fragment("mapped")).unwrap();
    block_on(store.ensure_with::<OtherWay>(other, &owner)).unwrap();

    let report = block_on(ensure_derived(
        &mut store,
        source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert!(report.realized.is_empty());
    assert_eq!(
        report
            .unknown
            .iter()
            .map(|derived| derived.handle)
            .collect::<Vec<_>>(),
        [other.handle()],
        "the canonical realizer names it instead of mapping it its own way"
    );
}
