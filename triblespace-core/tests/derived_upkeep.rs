//! The collections attached to a root are found from their descriptors and
//! taken up as a group: ensured after a write so the write is readable
//! through every attachment, maintained by a daemon after the root's carry.

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace_core::collection::{
    attached_to, ensure_downstream, maintain_downstream, AdmissionPolicy, Attached, Collection,
    CollectionPolicy, CollectionRead, CollectionRealizationError, CollectionRecord,
    CollectionSnapshotExt, CollectionStoreExt, CoreRealizer, Derived, RealizeDerived, Realized,
    Upkeep, MERGE_FAN_IN,
};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace_core::repo::memoryrepo::MemoryRepo;
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

struct Pair {
    source: Collection<SimpleArchive>,
    succinct: Collection<SuccinctArchiveBlob>,
    rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
}

fn pair(store: &mut MemoryRepo, name: &str, owner: &SigningKey) -> Pair {
    let source = store.collection(name, open_for(owner)).unwrap();
    let succinct = store.attach::<SuccinctArchiveBlob>(source, ()).unwrap();
    let rank9 = store
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(source, succinct)
        .unwrap();
    Pair {
        source,
        succinct,
        rank9,
    }
}

/// Commits, merges, derives and maps in the store.
fn record_kinds(store: &mut MemoryRepo) -> (usize, usize, usize, usize) {
    let snapshot = store.snapshot().unwrap();
    let mut counts = (0, 0, 0, 0);
    for record in snapshot.records().unwrap() {
        match record.unwrap() {
            CollectionRecord::Commit(_) => counts.0 += 1,
            CollectionRecord::Merge(_) => counts.1 += 1,
            CollectionRecord::Derive(_) => counts.2 += 1,
            CollectionRecord::Map(_) => counts.3 += 1,
        }
    }
    counts
}

/// Registering the pair and attaching it once puts it into the listing.
fn seed(store: &mut MemoryRepo, pair: &Pair, owner: &SigningKey) {
    block_on(store.ensure_attached(pair.succinct, owner)).unwrap();
    block_on(store.ensure_attached(pair.rank9, owner)).unwrap();
}

#[test]
fn attached_collections_are_found_from_their_descriptors_siblings_first() {
    let owner = key(1);
    let mut store = MemoryRepo::for_host(owner.verifying_key());
    let pair = pair(&mut store, "found", &owner);
    let other = store.collection("unrelated", open_for(&owner)).unwrap();
    store
        .commit(pair.source, &owner, fragment("first"))
        .unwrap();
    store.commit(other, &owner, fragment("elsewhere")).unwrap();
    seed(&mut store, &pair, &owner);
    let snapshot = store.snapshot().unwrap();
    let attached: Vec<_> = attached_to(&snapshot, pair.source.handle())
        .unwrap()
        .into_iter()
        .map(|attached| (attached.handle, attached.parent, attached.siblings))
        .collect();
    assert_eq!(
        attached,
        [
            (pair.succinct.handle(), pair.source.handle(), vec![]),
            (
                pair.rank9.handle(),
                pair.source.handle(),
                vec![pair.succinct.handle()]
            ),
        ]
    );
    assert!(attached_to(&snapshot, other.handle()).unwrap().is_empty());
}

#[test]
fn ensure_downstream_makes_a_commit_readable_through_every_attachment_and_publishes_no_merge() {
    let owner = key(2);
    // The owner carries the root and signs the MAPs, so the store is its host.
    let mut store = MemoryRepo::for_host(owner.verifying_key());
    let pair = pair(&mut store, "ensured", &owner);
    store.commit(pair.source, &owner, fragment("one")).unwrap();
    seed(&mut store, &pair, &owner);

    store.commit(pair.source, &owner, fragment("two")).unwrap();
    let report = block_on(ensure_downstream(
        &mut store,
        pair.source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert_eq!(
        report.realized,
        [pair.succinct.handle(), pair.rank9.handle()]
    );
    assert!(report.unadmitted.is_empty());
    assert!(report.unknown_attached.is_empty());

    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.attached(pair.rank9).unwrap();
    assert_eq!(observed.support().len(), 2);
    assert!(observed.residual().is_empty());
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.segment_count(), 2, "two commits, nothing merged");
    drop(snapshot);
    assert_eq!(
        record_kinds(&mut store),
        (2, 0, 0, 4),
        "each commit attached in each collection, and no merge"
    );

    // Maintenance carries the root and attaches what the carry leaves: two
    // commits sit below the fan-in, so there is nothing to carry.
    block_on(maintain_downstream(
        &mut store,
        pair.source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert_eq!(record_kinds(&mut store), (2, 0, 0, 4));

    // A full tier is carried into one MERGE, and only the merged node is
    // attached, in each collection.
    let more = ["three", "four", "five", "six", "seven", "eight"];
    assert_eq!(2 + more.len(), MERGE_FAN_IN);
    for name in more {
        store.commit(pair.source, &owner, fragment(name)).unwrap();
    }
    let report = block_on(maintain_downstream(
        &mut store,
        pair.source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert_eq!(
        report.realized,
        [pair.succinct.handle(), pair.rank9.handle()]
    );
    assert_eq!(
        record_kinds(&mut store),
        (MERGE_FAN_IN, 1, 0, 6),
        "one carry, and the merged node attached in both collections"
    );
    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.attached(pair.rank9).unwrap();
    assert_eq!(observed.support().len(), MERGE_FAN_IN);
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.segment_count(), 1);
}

#[test]
fn a_key_that_is_not_the_host_fails_and_an_unknown_representation_is_named_not_guessed() {
    let owner = key(3);
    let stranger = key(4);
    let mut store = MemoryRepo::for_host(owner.verifying_key());
    let pair = pair(&mut store, "guarded", &owner);
    store
        .commit(pair.source, &owner, fragment("guarded"))
        .unwrap();
    seed(&mut store, &pair, &owner);
    store
        .commit(pair.source, &owner, fragment("guarded again"))
        .unwrap();

    // Only the host's MAPs are believed: another key has nothing to sign.
    assert!(matches!(
        block_on(ensure_downstream(
            &mut store,
            pair.source.handle(),
            &stranger,
            &mut CoreRealizer,
        )),
        Err(CollectionRealizationError::HostMismatch { .. })
    ));

    struct KnowsNothing;
    impl<S: Store + AsyncBlobStoreAcquire + Send> RealizeDerived<S> for KnowsNothing {
        async fn realize(
            &mut self,
            _store: &mut S,
            _derived: &Derived,
            _signer: &SigningKey,
            _upkeep: Upkeep,
        ) -> Result<Realized, CollectionRealizationError> {
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
    let report = block_on(ensure_downstream(
        &mut store,
        pair.source.handle(),
        &owner,
        &mut KnowsNothing,
    ))
    .unwrap();
    assert_eq!(
        report
            .unknown_attached
            .iter()
            .map(|attached| attached.handle)
            .collect::<Vec<_>>(),
        [pair.succinct.handle(), pair.rank9.handle()]
    );
}

/// One attached collection failing is that collection's lag, not the
/// pass's: it is named with why, every other collection attached to the
/// source is still taken as far as asked, and the write stays readable
/// through them.
#[test]
fn one_attached_collection_failing_leaves_the_others_upkept() {
    use triblespace_core::blob::encodings::entity_id_set::EntityIdSetBlob;
    use triblespace_core::collection::CollectionHandle;

    /// The core realizer, except that one attached collection fails.
    struct FailsOne(CollectionHandle);
    impl<S: Store + AsyncBlobStoreAcquire + Send> RealizeDerived<S> for FailsOne {
        async fn realize(
            &mut self,
            store: &mut S,
            derived: &Derived,
            signer: &SigningKey,
            upkeep: Upkeep,
        ) -> Result<Realized, CollectionRealizationError> {
            CoreRealizer.realize(store, derived, signer, upkeep).await
        }

        async fn realize_attached(
            &mut self,
            store: &mut S,
            attached: &Attached,
            signer: &SigningKey,
            upkeep: Upkeep,
        ) -> Result<Realized, CollectionRealizationError> {
            if attached.handle == self.0 {
                return Err(CollectionRealizationError::Resolution(
                    "this one cannot be taken up".to_owned(),
                ));
            }
            CoreRealizer
                .realize_attached(store, attached, signer, upkeep)
                .await
        }
    }

    let owner = key(6);
    let mut store = MemoryRepo::for_host(owner.verifying_key());
    let pair = pair(&mut store, "isolated", &owner);
    let named = store
        .attach::<EntityIdSetBlob>(pair.source, metadata::name.id())
        .unwrap();
    store
        .commit(pair.source, &owner, fragment("first"))
        .unwrap();
    seed(&mut store, &pair, &owner);
    block_on(store.ensure_attached(named, &owner)).unwrap();
    // The failing collection is visited before the Rank9 collection, which
    // reads the Succinct one.
    let order: Vec<_> = attached_to(&store.snapshot().unwrap(), pair.source.handle())
        .unwrap()
        .into_iter()
        .map(|attached| attached.handle)
        .collect();
    let position = |handle| order.iter().position(|listed| *listed == handle).unwrap();
    assert!(position(named.handle()) < position(pair.rank9.handle()));

    store
        .commit(pair.source, &owner, fragment("second"))
        .unwrap();
    for upkeep in [Upkeep::Ensure, Upkeep::Maintain] {
        let mut realizer = FailsOne(named.handle());
        let report = block_on(async {
            match upkeep {
                Upkeep::Ensure => {
                    ensure_downstream(&mut store, pair.source.handle(), &owner, &mut realizer).await
                }
                Upkeep::Maintain => {
                    maintain_downstream(&mut store, pair.source.handle(), &owner, &mut realizer)
                        .await
                }
            }
        })
        .unwrap();
        assert_eq!(
            report.realized,
            [pair.succinct.handle(), pair.rank9.handle()]
        );
        assert_eq!(
            report
                .failed_attached
                .iter()
                .map(|(attached, reason)| (attached.handle, reason.contains("cannot be taken up")))
                .collect::<Vec<_>>(),
            [(named.handle(), true)]
        );
    }
    let snapshot = store.snapshot().unwrap();
    let observed = snapshot.attached(pair.rank9).unwrap();
    assert_eq!(observed.support().len(), 2);
    assert!(observed.residual().is_empty());
}

#[test]
fn a_descriptor_naming_another_mapping_is_left_to_whoever_registered_it() {
    use triblespace_core::blob::Blob;
    use triblespace_core::collection::{
        CollectionAttachment, CollectionData, CollectionOperationError, MapMapping,
    };
    use triblespace_core::repo::StoreRead;

    /// Succinct attachments built by a mapping that is not the canonical
    /// one: same encoding, another algorithm in the descriptor.
    struct OtherWay;
    impl MapMapping for OtherWay {
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
            node: &Blob<SimpleArchive>,
            siblings: &[CollectionData],
            reader: &R,
        ) -> Result<Blob<SuccinctArchiveBlob>, CollectionOperationError> {
            <SuccinctArchiveBlob as CollectionAttachment>::map(&(), node, siblings, reader)
        }
    }

    let owner = key(5);
    let mut store = MemoryRepo::for_host(owner.verifying_key());
    let source = store.collection("mapped", open_for(&owner)).unwrap();
    let other = store.attach_with(source, OtherWay).unwrap();
    store.commit(source, &owner, fragment("mapped")).unwrap();
    block_on(store.ensure_attached_with::<OtherWay>(other, &owner)).unwrap();

    let report = block_on(ensure_downstream(
        &mut store,
        source.handle(),
        &owner,
        &mut CoreRealizer,
    ))
    .unwrap();
    assert!(report.realized.is_empty());
    assert_eq!(
        report
            .unknown_attached
            .iter()
            .map(|attached| attached.handle)
            .collect::<Vec<_>>(),
        [other.handle()],
        "the canonical realizer names it instead of mapping it its own way"
    );
}
