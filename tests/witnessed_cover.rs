//! Physical payload order cannot stand in for the exact support endorsed by
//! a record. A non-injective mapping can give one blob several different
//! signed histories, and a larger blob need not endorse all of them.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, utf8string::UTF8String};
use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace::core::collection::{
    descriptor, mapping_algorithm, simplearchive_union, AdmissionPolicy, Collection,
    CollectionData, CollectionDerive, CollectionMapping, CollectionMerge, CollectionOperationError,
    CollectionPolicy, CollectionRealizationError, CollectionRecord, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt, KIND_COLLECTION_MAPPING,
};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::metadata;
use triblespace::core::repo::memoryrepo::MemoryRepo;
use triblespace::core::repo::{BlobStoreList, BlobStorePut, SnapshotSource, StoreRead};
use triblespace::prelude::{entity, find, pattern, rngid, Fragment, Id, Inline, Trible, TribleSet};

/// An actual non-injective join homomorphism, not invented mismatching
/// payload hashes: retain name facts, dropping description facts. The
/// algorithm ID is fresh test data, never a stable production identifier.
#[derive(Clone, Copy)]
struct NamesOnly {
    algorithm: Id,
}

impl CollectionMapping for NamesOnly {
    type Source = SimpleArchive;
    type Target = SimpleArchive;

    fn fragment(&self) -> Fragment {
        entity! {
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm: self.algorithm,
        }
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        let algorithm = descriptor::mapping_algorithm(target.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .ok_or_else(|| CollectionOperationError::Fatal("missing test mapping".to_owned()))?;
        Ok(Self { algorithm })
    }

    fn map<R>(
        &self,
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<SimpleArchive>, CollectionOperationError>
    where
        R: StoreRead,
    {
        let facts = TribleSet::try_from_blob(source.clone())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let names: TribleSet = find!(
            (entity: Id, name: Inline<Handle<UTF8String>>),
            pattern!(&facts, [{ ?entity @ metadata::name: ?name }])
        )
        .map(|(entity, name)| Trible::force(&entity, &metadata::name.id(), &name))
        .collect();
        Ok(names.to_blob())
    }
}

struct Fixture {
    store: MemoryRepo,
    source: Collection<SimpleArchive>,
    target: Collection<SimpleArchive>,
    source_data: [CollectionData; 3],
    x: Inline<Handle<SimpleArchive>>,
    z: Inline<Handle<SimpleArchive>>,
    expected: TribleSet,
}

fn remove_blob(store: &mut MemoryRepo, victim: Inline<Handle<SimpleArchive>>) {
    let keep: Vec<_> = store
        .blobs
        .snapshot()
        .unwrap()
        .iter()
        .map(|(handle, _)| handle)
        .filter(|handle| handle.raw != victim.raw)
        .collect();
    // Model representation eviction in this synthetic repository, without
    // deleting any COMMIT, DERIVE, MERGE or capability evidence.
    store.blobs.keep(keep);
}

fn fixture() -> Fixture {
    let owner = SigningKey::from_bytes(&[86; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(owner.verifying_key()),
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("witnessed-cover", policy.clone()).unwrap();
    let mapping = NamesOnly {
        algorithm: rngid().id,
    };
    let target = store.derive_with(source, mapping, policy).unwrap();

    let same_entity = rngid();
    let other_entity = rngid();
    let a = entity! { &same_entity @
        metadata::name: "shared name",
        metadata::description: "a",
    };
    let b = entity! { &same_entity @
        metadata::name: "shared name",
        metadata::description: "b",
    };
    let c = entity! { &other_entity @
        metadata::name: "other name",
        metadata::description: "c",
    };
    let inputs: [Blob<SimpleArchive>; 3] = [
        a.facts().clone().to_blob(),
        b.facts().clone().to_blob(),
        c.facts().clone().to_blob(),
    ];
    let commits = [
        store.commit(source, &owner, a).unwrap(),
        store.commit(source, &owner, b).unwrap(),
        store.commit(source, &owner, c).unwrap(),
    ];
    let snapshot = store.snapshot().unwrap();
    let images = inputs.map(|input| mapping.map(&input, &snapshot).unwrap());
    assert_ne!(commits[0].data(), commits[1].data());
    assert_eq!(images[0].get_handle(), images[1].get_handle());
    let z_blob = simplearchive_union::join(&images[1], &images[2]).unwrap();
    let expected = TribleSet::try_from_blob(z_blob.clone()).unwrap();
    let x = store.put::<SimpleArchive, _>(images[0].clone()).unwrap();
    let y = store.put::<SimpleArchive, _>(images[2].clone()).unwrap();
    let z = store.put::<SimpleArchive, _>(z_blob).unwrap();
    assert_ne!(x, z);
    assert_ne!(y, z);

    let derives = std::array::from_fn::<_, 3, _>(|index| {
        CollectionRecord::Derive(CollectionDerive::sign(
            &owner,
            target.handle(),
            (
                commits[index].data(),
                CollectionRecord::Commit(commits[index]).fingerprint(),
            ),
            Handle::<SimpleArchive>::to_hash(images[index].get_handle()),
        ))
    });
    for record in derives {
        store.insert(record).unwrap();
    }
    // a -> x [A], b -> x [B], c -> y [C]. M explicitly endorses B and C,
    // not A, although their ordinary payload order proves x <= z.
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            target.handle(),
            (
                Handle::<SimpleArchive>::to_hash(x),
                derives[1].fingerprint(),
            ),
            (
                Handle::<SimpleArchive>::to_hash(y),
                derives[2].fingerprint(),
            ),
            Handle::<SimpleArchive>::to_hash(z),
        )))
        .unwrap();
    remove_blob(&mut store, y);
    Fixture {
        store,
        source,
        target,
        source_data: commits.map(|commit| commit.data()),
        x,
        z,
        expected,
    }
}

#[test]
fn a_resident_payload_subsumer_cannot_erase_another_witnesses_support() {
    let mut fixture = fixture();
    let snapshot = fixture.store.snapshot().unwrap();
    let view = snapshot.collection(fixture.target).unwrap();

    // Payload-only antichain selection would choose just z. Its only exact
    // certificate has {b,c}; preserving a requires retaining x alongside z.
    assert_eq!(
        view.cover().members().collect::<BTreeSet<_>>(),
        BTreeSet::from([fixture.x, fixture.z]),
    );
    assert_eq!(
        view.support()
            .unwrap()
            .members()
            .map(Handle::<SimpleArchive>::to_hash)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(fixture.source_data),
    );
    assert_eq!(view.view::<TribleSet>().unwrap(), fixture.expected);

    let requested = fixture
        .source
        .cover(fixture.source_data.map(Handle::<SimpleArchive>::from_hash));
    let exact = snapshot
        .collection_exact(fixture.target, &requested)
        .unwrap();
    assert_eq!(exact.support().unwrap(), &requested);
    assert_eq!(exact.cover(), view.cover());
}

#[test]
fn a_missing_alias_is_not_recovered_by_unioning_another_records_provenance() {
    let mut fixture = fixture();
    let before_eviction = fixture.store.snapshot().unwrap();
    remove_blob(&mut fixture.store, fixture.x);
    let after_eviction = fixture.store.snapshot().unwrap();
    assert!(!after_eviction.contains_blob(fixture.x).unwrap());
    assert!(after_eviction.contains_blob(fixture.z).unwrap());

    let view = after_eviction.collection(fixture.target).unwrap();
    assert_eq!(view.cover().members().collect::<Vec<_>>(), vec![fixture.z]);
    assert_eq!(
        view.support()
            .unwrap()
            .members()
            .map(Handle::<SimpleArchive>::to_hash)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([fixture.source_data[1], fixture.source_data[2]]),
        "z's witness names B and C; equal x payloads cannot import A's route",
    );
    assert_eq!(view.view::<TribleSet>().unwrap(), fixture.expected);

    let requested = fixture
        .source
        .cover(fixture.source_data.map(Handle::<SimpleArchive>::from_hash));
    match after_eviction.collection_exact(fixture.target, &requested) {
        Err(CollectionRealizationError::IncompleteCover {
            unsupported_members,
            ..
        }) => {
            assert_eq!(unsupported_members, vec![fixture.source_data[0]]);
        }
        Err(error) => panic!("expected missing support, got {error}"),
        Ok(_) => panic!("payload aliasing must not discharge a missing certificate's support"),
    }

    // The older immutable snapshot still has x, even though the mutable
    // store's later residency cannot realize the same complete support.
    let before = before_eviction.collection(fixture.target).unwrap();
    assert_eq!(before.support().unwrap(), &requested);
    assert_eq!(
        before.cover().members().collect::<BTreeSet<_>>(),
        BTreeSet::from([fixture.x, fixture.z])
    );
}
