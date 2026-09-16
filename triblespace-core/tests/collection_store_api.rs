use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::executor::block_on;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchiveBlob, UnionArchive,
};
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{BlobEncoding, IntoBlob};
use triblespace_core::capability::policy::{capability_handle, resource_policy};
use triblespace_core::capability::{
    capability_action, capability_delegate_action, CapabilityProof, CapabilityProofError,
    CapabilityResource,
};
use triblespace_core::collection::descriptor;
use triblespace_core::collection::records::{
    admission_invoke_threshold, admission_policy_root, collection_mapping, collection_name,
    collection_representation, collection_source, mapping_algorithm, KIND_COLLECTION_DESCRIPTOR,
    KIND_COLLECTION_MAPPING,
};
use triblespace_core::collection::succinctarchive_union::SIMPLE_TO_SUCCINCT_MAPPING_V1;
use triblespace_core::collection::{
    collection_action_audience, collection_read_audience, grant_collection_capability,
    grant_collection_read, grant_collection_write, read_capability, write_capability,
    AdmissionPolicy, Collection, CollectionOpenError, CollectionPolicy, CollectionRead,
    CollectionReadAudience, CollectionReadGrantError, CollectionRecord,
    CollectionRegistrationError, CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
    CollectionTypeError, CollectionWriteGrantError, PreparedCollectionCommit, ACTION_READ,
    ACTION_WRITE, KIND_ADMISSION_POLICY_QUORUM,
};
use triblespace_core::id::rngid;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreGet, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_core::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreEvent {
    Put([u8; 32]),
    Insert(triblespace_core::collection::CollectionRecordFingerprint),
    Proof([u8; 32]),
}

#[derive(Default)]
struct CountingRepo {
    inner: MemoryRepo,
    puts: BTreeMap<[u8; 32], usize>,
    events: Vec<StoreEvent>,
}

impl CountingRepo {
    fn puts_for<S>(&self, handle: Inline<Handle<S>>) -> usize
    where
        S: BlobEncoding,
        Handle<S>: InlineEncoding,
    {
        self.puts.get(&handle.raw).copied().unwrap_or_default()
    }
}

impl BlobStorePut for CountingRepo {
    type PutError = <MemoryRepo as BlobStorePut>::PutError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: triblespace_core::blob::IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let handle = self.inner.put(item)?;
        *self.puts.entry(handle.raw).or_default() += 1;
        self.events.push(StoreEvent::Put(handle.raw));
        Ok(handle)
    }
}

impl CollectionStore for CountingRepo {
    type InsertError = <MemoryRepo as CollectionStore>::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.events.push(StoreEvent::Insert(record.fingerprint()));
        self.inner.insert(record)
    }
}

impl SnapshotSource for CountingRepo {
    type Snapshot = <MemoryRepo as SnapshotSource>::Snapshot;
    type SnapshotError = <MemoryRepo as SnapshotSource>::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.inner.snapshot()
    }
}

impl CapabilityProofStore for CountingRepo {
    type InsertError = <MemoryRepo as CapabilityProofStore>::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.events.push(StoreEvent::Proof(proof.id().raw));
        self.inner.insert_proof(proof)
    }
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn policy(root: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::delegable(root),
        AdmissionPolicy::direct(root),
    )
}

fn fragment(entity: u8) -> Fragment {
    let mut row = [entity; TRIBLE_LEN];
    row[16..32].fill(entity.wrapping_add(1));
    row[32..].fill(entity.wrapping_add(2));
    let mut facts = TribleSet::new();
    facts.insert(&Trible::force_raw(row).unwrap());
    Fragment::from(facts)
}

#[test]
fn root_creation_registers_a_self_contained_descriptor() {
    let root = key(1);
    let expected_policy = policy(root.verifying_key());
    let mut store = MemoryRepo::default();

    let collection = store
        .collection("collection-store-api", expected_policy.clone())
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let descriptor_blob = snapshot
        .get::<TribleSet, SimpleArchive>(collection.handle())
        .unwrap();

    assert_eq!(descriptor::policy(&descriptor_blob), Ok(expected_policy));
    let name = descriptor::name(&descriptor_blob).unwrap().unwrap();
    let name: anybytes::View<str> = snapshot.get::<_, UTF8String>(name).unwrap();
    assert_eq!(&*name, "collection-store-api");
}

#[test]
fn typed_collection_open_accepts_the_registered_encoding() {
    let root = key(20);
    let mut store = MemoryRepo::default();
    let registered = store
        .collection("typed-open", policy(root.verifying_key()))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let opened = Collection::<SimpleArchive>::open(&snapshot, registered.handle()).unwrap();

    assert_eq!(opened, registered);
}

#[test]
fn typed_collection_names_an_exact_coordinate_without_store_access() {
    let root = key(21);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection("durable-exact-cover", policy(root.verifying_key()))
        .unwrap();
    let low = Inline::<Handle<SimpleArchive>>::new([0x31; 32]);
    let high = Inline::<Handle<SimpleArchive>>::new([0x42; 32]);

    let cover = collection.cover([high, low, high]);

    assert_eq!(cover.collection(), collection);
    assert_eq!(cover.members().collect::<Vec<_>>(), vec![low, high]);
}

#[test]
fn typed_collection_reads_its_descriptor_local_policy() {
    let source_root = key(22);
    let target_root = key(23);
    let source_policy = policy(source_root.verifying_key());
    let target_policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(target_root.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("policy-source", source_policy).unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), target_policy.clone())
        .unwrap();

    let snapshot = store.snapshot().unwrap();

    assert_eq!(target.policy(&snapshot).unwrap(), target_policy);
}

#[test]
fn typed_collection_open_rejects_the_wrong_encoding() {
    let root = key(21);
    let mut store = MemoryRepo::default();
    let source = store
        .collection("source", policy(root.verifying_key()))
        .unwrap();
    let registered = store
        .derive::<SuccinctArchiveBlob>(source, (), policy(root.verifying_key()))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let error = Collection::<SimpleArchive>::open(&snapshot, registered.handle()).unwrap_err();

    assert!(matches!(
        error,
        CollectionOpenError::WrongType(CollectionTypeError::WrongEncoding { .. })
    ));
}

#[test]
fn typed_collection_open_reports_no_matching_encoding() {
    let mut store = MemoryRepo::default();
    let invalid = store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();

    let snapshot = store.snapshot().unwrap();
    let error = Collection::<SimpleArchive>::open(&snapshot, invalid).unwrap_err();

    assert!(matches!(
        error,
        CollectionOpenError::WrongType(CollectionTypeError::WrongEncoding { .. })
    ));
}

#[test]
fn encoding_recognition_is_existential_and_entity_scoped() {
    let mut store = CountingRepo::default();
    let unrelated_encoding = rngid();
    let mut facts = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation: &unrelated_encoding,
    };
    // The requested representation on an untagged entity cannot complete a
    // descriptor interpretation on its neighbor.
    facts += entity! {
        collection_representation: SimpleArchive::id(),
    };
    assert!(matches!(
        store.register_collection::<SimpleArchive>(facts.clone()),
        Err(CollectionRegistrationError::WrongType(
            CollectionTypeError::WrongEncoding { .. }
        ))
    ));
    assert!(store.events.is_empty());

    // Registration asks only whether the requested encoding is represented;
    // admission separately queries same-entity encoding and policy links.
    facts += entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation*: [SimpleArchive::id(), unrelated_encoding.id],
    };
    store.register_collection::<SimpleArchive>(facts).unwrap();
}

#[test]
fn annotations_and_opaque_ids_preserve_ordinary_maintenance() {
    let authority = key(40);
    let expected_policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let subject = rngid();
    let read = rngid();
    let write = rngid();
    let unknown_encoding = rngid();
    let mut descriptor = entity! { &subject @
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name*: ["annotated-source", "a second descriptive name"],
        collection_representation*: [SimpleArchive::id(), unknown_encoding.id],
        resource_policy*: entity! { &read @
            capability_handle: read_capability(),
            metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
            admission_policy_root: authority.verifying_key(),
            admission_invoke_threshold: 1_u32,
        },
        resource_policy*: entity! { &write @
            capability_handle: write_capability(),
            metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
            admission_policy_root: authority.verifying_key(),
            admission_invoke_threshold: 1_u32,
        },
    };
    // This exact retired attribute was minted on 2026-08-07. It is ordinary
    // unknown data to the current reader, not a whole-archive rejection marker.
    let retired_recipe = triblespace_core::id_hex!("5D338C58D897B969BE1AE0956CCFE301");
    descriptor.facts_mut().insert(&Trible::force(
        &subject.id,
        &retired_recipe,
        &Inline::<GenId>::new([0xFF; 32]),
    ));
    // Embedded descriptions may use attributes the collection also uses.
    descriptor += entity! {
        resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
        resource_policy*: AdmissionPolicy::Open.binding(write_capability()),
    };
    descriptor.put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone());
    descriptor.put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone());
    let mut store = MemoryRepo::default();
    let source = store
        .register_collection::<SimpleArchive>(descriptor)
        .unwrap();
    let target_subject = rngid();
    let mapping_subject = rngid();
    let target = store
        .register_collection::<SuccinctArchiveBlob>(entity! { &target_subject @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: source.handle(),
            // A name annotates this derivation; it does not turn it into a root.
            collection_name: "annotated-derivation",
            collection_representation: SuccinctArchiveBlob::id(),
            resource_policy*: expected_policy.read().binding(read_capability()),
            resource_policy*: expected_policy.write().binding(write_capability()),
            collection_mapping*: entity! { &mapping_subject @
                metadata::tag: KIND_COLLECTION_MAPPING,
                mapping_algorithm: SIMPLE_TO_SUCCINCT_MAPPING_V1,
                metadata::name: "opaque mapping entity",
            },
        })
        .unwrap();
    let first = fragment(41);
    let second = fragment(42);
    let expected = first.facts().clone() + second.facts().clone();
    store.commit(source, &authority, first).unwrap();
    store.commit(source, &authority, second).unwrap();

    let maintained = block_on(store.maintain(target, &authority)).unwrap();
    let observed_policy = source.policy(&maintained).unwrap();
    assert_eq!(observed_policy.read(), expected_policy.read());
    assert_eq!(observed_policy.write(), expected_policy.write());
    assert_eq!(
        Collection::<SimpleArchive>::open(&maintained, source.handle()).unwrap(),
        source
    );
    assert_eq!(
        Collection::<SuccinctArchiveBlob>::open(&maintained, target.handle()).unwrap(),
        target
    );
    let observed = maintained.collection(target).unwrap();
    assert_eq!(observed.support().unwrap().len(), 2);
    assert_eq!(
        observed
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        expected,
    );
    let before = maintained
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let after = block_on(store.maintain(target, &authority)).unwrap();
    assert_eq!(
        after
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        before
    );
}

#[test]
fn unrecognized_policy_is_invisible_without_poisoning_other_collections() {
    let authority = key(43);
    let expected = fragment(44);
    let expected_facts = expected.facts().clone();
    let unknown_kind = rngid();
    let mut store = MemoryRepo::default();
    let unknown = store
        .register_collection::<SimpleArchive>(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: SimpleArchive::id(),
            resource_policy*: entity! { capability_handle: read_capability(), metadata::tag: &unknown_kind },
            resource_policy*: entity! { capability_handle: write_capability(), metadata::tag: &unknown_kind },
        })
        .unwrap();
    let healthy = store
        .collection("healthy", policy(authority.verifying_key()))
        .unwrap();
    store.commit(unknown, &authority, expected.clone()).unwrap();
    store.commit(healthy, &authority, expected).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        Collection::<SimpleArchive>::open(&snapshot, unknown.handle()).unwrap(),
        unknown
    );
    assert!(!unknown
        .reader_is_admitted(&snapshot, authority.verifying_key())
        .unwrap());
    assert!(!unknown
        .writer_is_admitted(&snapshot, authority.verifying_key())
        .unwrap());
    assert!(!unknown
        .reader_is_admitted_by(&snapshot, authority.verifying_key(), &[])
        .unwrap());
    assert!(unknown.admitted(&snapshot).unwrap().is_empty());
    assert!(unknown.read::<TribleSet, _>(&snapshot).unwrap().is_empty());
    assert_eq!(
        collection_read_audience(&snapshot, unknown.handle()).unwrap(),
        CollectionReadAudience::Restricted(Vec::new())
    );
    // Explicit scalar inspection remains diagnostic, not an admission gate.
    assert!(unknown.policy(&snapshot).is_err());
    assert_eq!(
        healthy.read::<TribleSet, _>(&snapshot).unwrap(),
        expected_facts
    );
}

#[test]
fn missing_read_policy_does_not_hide_supported_write_admission() {
    let writer = key(45);
    let mut store = MemoryRepo::default();
    store
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
        .unwrap();
    let collection = store
        .register_collection::<SimpleArchive>(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: SimpleArchive::id(),
            resource_policy*: AdmissionPolicy::direct(writer.verifying_key()).binding(write_capability()),
        })
        .unwrap();
    let expected = fragment(46);
    store.commit(collection, &writer, expected.clone()).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!collection
        .reader_is_admitted(&snapshot, writer.verifying_key())
        .unwrap());
    assert!(collection
        .writer_is_admitted(&snapshot, writer.verifying_key())
        .unwrap());
    assert_eq!(
        collection.read::<TribleSet, _>(&snapshot).unwrap(),
        *expected.facts()
    );
    assert!(collection.policy(&snapshot).is_err());
}

#[test]
fn multiple_policy_alternatives_union_admission_without_combining_quorum_shares() {
    let a = key(47);
    let b = key(48);
    let c = key(49);
    let d = key(50);
    let writer = key(51);
    let mut store = MemoryRepo::default();
    let mut alternatives = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation: SimpleArchive::id(),
        resource_policy*: AdmissionPolicy::direct(a.verifying_key()).binding(read_capability())
            + AdmissionPolicy::direct(c.verifying_key()).binding(read_capability()),
        resource_policy*: AdmissionPolicy::quorum([a.verifying_key(), b.verifying_key()], 2, None).unwrap().binding(write_capability())
            + AdmissionPolicy::quorum([c.verifying_key(), d.verifying_key()], 2, None).unwrap().binding(write_capability()),
    };
    alternatives
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone());
    alternatives
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone());
    let collection = store
        .register_collection::<SimpleArchive>(alternatives)
        .unwrap();
    let expected = fragment(52);
    store.commit(collection, &writer, expected.clone()).unwrap();
    for root in [&a, &c] {
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(collection.handle()),
                root,
                write_capability(),
                writer.verifying_key(),
            ))
            .unwrap();
    }
    let before = store.snapshot().unwrap();
    // One share from each alternative is not a two-root proof of either.
    assert!(!collection
        .writer_is_admitted(&before, writer.verifying_key())
        .unwrap());
    assert!(collection.admitted(&before).unwrap().is_empty());
    assert!(collection
        .reader_is_admitted(&before, a.verifying_key())
        .unwrap());
    assert!(collection
        .reader_is_admitted_by(&before, c.verifying_key(), &[])
        .unwrap());
    let mut audience = vec![a.verifying_key(), c.verifying_key()];
    audience.sort_unstable_by_key(VerifyingKey::to_bytes);
    assert_eq!(
        collection_read_audience(&before, collection.handle()).unwrap(),
        CollectionReadAudience::Restricted(audience)
    );
    assert!(collection.policy(&before).is_err());

    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &b,
            write_capability(),
            writer.verifying_key(),
        ))
        .unwrap();
    let after = store.snapshot().unwrap();
    assert!(collection
        .writer_is_admitted(&after, writer.verifying_key())
        .unwrap());
    assert_eq!(
        collection.read::<TribleSet, _>(&after).unwrap(),
        *expected.facts()
    );
    assert!(collection.admitted(&before).unwrap().is_empty());
}

#[test]
fn typed_admission_cannot_borrow_policy_from_another_descriptor_entity() {
    let authority = key(53);
    let unrelated_encoding = rngid();
    let mut facts = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation: SimpleArchive::id(),
    };
    facts += entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation: &unrelated_encoding,
        resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
        resource_policy*: AdmissionPolicy::Open.binding(write_capability()),
    };
    facts.put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone());
    facts.put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone());
    let mut store = MemoryRepo::default();
    let collection = store.register_collection::<SimpleArchive>(facts).unwrap();
    store.commit(collection, &authority, fragment(54)).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!collection
        .reader_is_admitted(&snapshot, authority.verifying_key())
        .unwrap());
    assert!(!collection
        .reader_is_admitted_by(&snapshot, authority.verifying_key(), &[])
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, authority.verifying_key())
        .unwrap());
    assert!(collection.admitted(&snapshot).unwrap().is_empty());
}

#[test]
fn custom_capability_grants_and_audiences_do_not_borrow_read_or_write_authority() {
    let transport_root = key(55);
    let delivery_root = key(56);
    let transport_reader = key(57);
    let recipient = key(58);
    let delivery_action = rngid();
    let definition = entity! {
        capability_action: &delivery_action,
        metadata::name: "key delivery fixture",
    };
    let capability = IntoBlob::<SimpleArchive>::to_blob(definition.facts().clone()).get_handle();
    let policy = policy(transport_root.verifying_key()).with_capability(
        definition.clone(),
        AdmissionPolicy::direct(delivery_root.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store
        .collection("separate-capability-audiences", policy)
        .unwrap();
    grant_collection_read(
        &mut store,
        source.handle(),
        &transport_root,
        transport_reader.verifying_key(),
    )
    .unwrap();

    assert!(matches!(
        grant_collection_capability(
            &mut store,
            source.handle(),
            capability,
            &transport_root,
            recipient.verifying_key()
        ),
        Err(triblespace_core::collection::CollectionGrantError::RootNotAuthorized { .. })
    ));
    let before = store.snapshot().unwrap();
    assert_eq!(
        collection_action_audience(&before, source.handle(), delivery_action.id).unwrap(),
        CollectionReadAudience::Restricted(vec![delivery_root.verifying_key()])
    );
    let proof = grant_collection_capability(
        &mut store,
        source.handle(),
        capability,
        &delivery_root,
        recipient.verifying_key(),
    )
    .unwrap();
    assert!(proof.capabilities().all(|handle| handle == capability));
    let after = store.snapshot().unwrap();
    let CollectionReadAudience::Restricted(delivery) =
        collection_action_audience(&after, source.handle(), delivery_action.id).unwrap()
    else {
        panic!("key delivery is restricted")
    };
    assert!(delivery.contains(&recipient.verifying_key()));
    assert!(!delivery.contains(&transport_reader.verifying_key()));
    let CollectionReadAudience::Restricted(readers) =
        collection_read_audience(&after, source.handle()).unwrap()
    else {
        panic!("replication is restricted")
    };
    assert!(readers.contains(&transport_reader.verifying_key()));
    assert!(!readers.contains(&recipient.verifying_key()));
    assert!(!source
        .writer_is_admitted(&after, recipient.verifying_key())
        .unwrap());
    assert_eq!(
        after.get::<TribleSet, SimpleArchive>(capability).unwrap(),
        *definition.facts()
    );

    // Explicit policy inspection/derivation retains the custom binding; the
    // source proof still cannot authorize the distinct derived resource.
    let copied_policy = source.policy(&after).unwrap();
    let derived = store
        .derive::<SuccinctArchiveBlob>(source, (), copied_policy)
        .unwrap();
    let derived_snapshot = store.snapshot().unwrap();
    assert_eq!(
        collection_action_audience(&derived_snapshot, derived.handle(), delivery_action.id)
            .unwrap(),
        CollectionReadAudience::Restricted(vec![delivery_root.verifying_key()])
    );
    assert_eq!(
        collection_action_audience(&before, source.handle(), delivery_action.id).unwrap(),
        CollectionReadAudience::Restricted(vec![delivery_root.verifying_key()])
    );
}

#[test]
fn compound_policy_definitions_select_roots_per_action_not_grant_handle() {
    let root = key(61);
    let reader = key(62);
    let mut store = MemoryRepo::default();
    let compound = store
        .put::<SimpleArchive, _>(
            entity! {
                capability_action*: [ACTION_READ, ACTION_WRITE],
            }
            .facts()
            .clone(),
        )
        .unwrap();
    store
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
        .unwrap();
    let collection = store
        .register_collection::<SimpleArchive>(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: SimpleArchive::id(),
            resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(compound),
        })
        .unwrap();
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            read_capability(),
            reader.verifying_key(),
        ))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_ne!(compound, read_capability());
    assert!(collection
        .reader_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    assert!(collection
        .writer_is_admitted(&snapshot, root.verifying_key())
        .unwrap());
}

#[test]
fn a_compound_grant_cannot_borrow_another_actions_root() {
    let read_root = key(63);
    let write_root = key(64);
    let subject = key(65);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "action-local-roots",
            CollectionPolicy::new(
                AdmissionPolicy::direct(read_root.verifying_key()),
                AdmissionPolicy::direct(write_root.verifying_key()),
            ),
        )
        .unwrap();
    let grant = store
        .put::<SimpleArchive, _>(
            entity! {
                capability_action*: [ACTION_READ, ACTION_WRITE],
            }
            .facts()
            .clone(),
        )
        .unwrap();
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &read_root,
            grant,
            subject.verifying_key(),
        ))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(collection
        .reader_is_admitted(&snapshot, subject.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, subject.verifying_key())
        .unwrap());
}

#[test]
fn unbound_custom_action_does_not_inherit_open_standard_policies() {
    let mut store = MemoryRepo::default();
    let source = store
        .collection(
            "open-but-not-key-delivery",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap();
    let unknown_action = rngid();
    let unknown = store
        .put::<SimpleArchive, _>(
            entity! { capability_action: &unknown_action }
                .facts()
                .clone(),
        )
        .unwrap();
    assert_eq!(
        collection_action_audience(
            &store.snapshot().unwrap(),
            source.handle(),
            unknown_action.id
        )
        .unwrap(),
        CollectionReadAudience::Restricted(Vec::new())
    );
    assert!(matches!(
        grant_collection_capability(
            &mut store,
            source.handle(),
            unknown,
            &key(59),
            key(60).verifying_key()
        ),
        Err(triblespace_core::collection::CollectionGrantError::RootNotAuthorized { .. })
    ));
}

#[test]
fn missing_policies_leave_ordinary_root_maintenance_inert() {
    let authority = key(55);
    let mut store = MemoryRepo::default();
    let collection = store
        .register_collection::<SimpleArchive>(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: SimpleArchive::id(),
        })
        .unwrap();
    store.commit(collection, &authority, fragment(56)).unwrap();
    let before = store.snapshot().unwrap();
    let records = before
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let after = block_on(store.maintain(collection, &authority)).unwrap();
    assert_eq!(
        after
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        records
    );
    let observed = after.collection(collection).unwrap();
    assert!(observed.support().unwrap().is_empty());
    assert!(observed.cover().is_empty());
    assert!(observed.view::<TribleSet>().unwrap().is_empty());
}

#[test]
fn read_grant_is_root_checked_and_replay_deterministic() {
    let root = key(25);
    let reader = key(26);
    let mut store = CountingRepo::default();
    let collection = store
        .collection("root-granted-read", policy(root.verifying_key()))
        .unwrap();
    store.events.clear();

    let first = grant_collection_read(
        &mut store,
        collection.handle(),
        &root,
        reader.verifying_key(),
    )
    .unwrap();
    assert_eq!(store.events, vec![StoreEvent::Proof(first.id().raw)]);

    assert_eq!(
        first.resource(),
        CapabilityResource::from(collection.handle())
    );
    assert_eq!(first.root_key(), root.verifying_key());
    assert_eq!(
        first.capabilities().collect::<Vec<_>>(),
        vec![read_capability()]
    );
    assert_eq!(first.leaf_key(), reader.verifying_key());

    store.events.clear();
    let replay = grant_collection_read(
        &mut store,
        collection.handle(),
        &root,
        reader.verifying_key(),
    )
    .unwrap();
    assert_eq!(replay, first);
    assert_eq!(store.events, vec![StoreEvent::Proof(first.id().raw)]);

    let snapshot = store.snapshot().unwrap();
    let proofs = snapshot
        .proofs()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(proofs, vec![first]);
    assert!(collection
        .reader_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
}

#[test]
fn write_grant_is_root_checked_and_activates_recipient_commits() {
    let root = key(34);
    let writer = key(35);
    let mut store = CountingRepo::default();
    let collection = store
        .collection(
            "root-granted-write",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    let commit = store.commit(collection, &writer, fragment(36)).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(collection.admitted(&snapshot).unwrap().is_empty());
    drop(snapshot);
    store.events.clear();

    let proof = grant_collection_write(
        &mut store,
        collection.handle(),
        &root,
        writer.verifying_key(),
    )
    .unwrap();
    assert_eq!(store.events, vec![StoreEvent::Proof(proof.id().raw)]);

    assert_eq!(
        proof.resource(),
        CapabilityResource::from(collection.handle())
    );
    assert_eq!(proof.root_key(), root.verifying_key());
    assert_eq!(
        proof.capabilities().collect::<Vec<_>>(),
        vec![write_capability()]
    );
    assert_eq!(proof.leaf_key(), writer.verifying_key());

    let snapshot = store.snapshot().unwrap();
    assert!(collection
        .writer_is_admitted(&snapshot, writer.verifying_key())
        .unwrap());
    let admitted = collection.admitted(&snapshot).unwrap();
    assert_eq!(admitted.len(), 1);
    assert!(admitted.contains(Handle::<SimpleArchive>::from_hash(commit.data())));
}

#[test]
fn read_grant_rejects_non_root_without_writing() {
    let root = key(27);
    let stranger = key(28);
    let reader = key(29);
    let mut store = CountingRepo::default();
    let collection = store
        .collection("root-checked-read", policy(root.verifying_key()))
        .unwrap();
    store.events.clear();

    let error = grant_collection_read(
        &mut store,
        collection.handle(),
        &stranger,
        reader.verifying_key(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CollectionReadGrantError::RootNotAuthorized {
            capability: rejected_capability,
            collection: rejected,
            root: rejected_root,
        } if rejected_capability == read_capability() && rejected == collection.handle() && rejected_root == stranger.verifying_key()
    ));
    assert!(store.events.is_empty());
}

#[test]
fn read_grant_rejects_an_absent_binding_without_writing() {
    let root = key(32);
    let reader = key(33);
    let mut store = CountingRepo::default();
    store
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
        .unwrap();
    let invalid = store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
    store.events.clear();

    let error =
        grant_collection_read(&mut store, invalid, &root, reader.verifying_key()).unwrap_err();

    assert!(matches!(
        error,
        CollectionReadGrantError::RootNotAuthorized {
            collection, capability, ..
        } if collection == invalid && capability == read_capability()
    ));
    assert!(store.events.is_empty());
}

#[test]
fn read_grant_rejects_redundant_open_policy_without_writing() {
    let root = key(30);
    let reader = key(31);
    let mut store = CountingRepo::default();
    let collection = store
        .collection(
            "already-open-read",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    store.events.clear();

    let error = grant_collection_read(
        &mut store,
        collection.handle(),
        &root,
        reader.verifying_key(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CollectionReadGrantError::OpenPolicy {
            capability: rejected_capability,
            collection: rejected,
        }
            if rejected_capability == read_capability() && rejected == collection.handle()
    ));
    assert!(store.events.is_empty());
}

#[test]
fn write_grant_checks_write_roots_not_read_roots() {
    let read_root = key(37);
    let write_root = key(38);
    let writer = key(39);
    let mut store = CountingRepo::default();
    let collection = store
        .collection(
            "distinct-write-root",
            CollectionPolicy::new(
                AdmissionPolicy::direct(read_root.verifying_key()),
                AdmissionPolicy::direct(write_root.verifying_key()),
            ),
        )
        .unwrap();
    store.events.clear();

    let error = grant_collection_write(
        &mut store,
        collection.handle(),
        &read_root,
        writer.verifying_key(),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CollectionWriteGrantError::RootNotAuthorized {
            capability: rejected_capability,
            collection: rejected,
            root: rejected_root,
        } if rejected_capability == write_capability() && rejected == collection.handle() && rejected_root == read_root.verifying_key()
    ));
    assert!(store.events.is_empty());
}

#[test]
fn commit_is_local_and_correct_by_construction() {
    let root = key(2);
    let mut store = CountingRepo::default();
    let collection = store
        .collection("registered", policy(root.verifying_key()))
        .unwrap();
    let descriptor_puts = store.puts_for(collection.handle());
    store.events.clear();

    let expected_data = fragment(7).facts().clone().to_blob().get_handle();
    let commit = store.commit(collection, &root, fragment(7)).unwrap();

    assert_eq!(
        Handle::<SimpleArchive>::from_hash(commit.data()),
        expected_data
    );
    assert_eq!(descriptor_puts, 1);
    assert_eq!(store.puts_for(collection.handle()), descriptor_puts);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::Insert(
            CollectionRecord::Commit(commit).fingerprint()
        ))
    );
}

#[test]
fn prepared_fragment_preserves_data_and_metadata_identity_until_commit_last() {
    let root = key(22);
    let mut store = CountingRepo::default();
    let collection = store
        .collection("prepared", policy(root.verifying_key()))
        .unwrap();
    store.events.clear();

    let mut candidate = fragment(23);
    candidate.describe_with(fragment(24));
    let expected_data = candidate.facts().clone().to_blob().get_handle();
    let expected_metadata = candidate.metafacts().clone().to_blob().get_handle();

    let prepared = PreparedCollectionCommit::from_fragment(candidate);
    let mut staged = prepared.stage_for(&mut store, collection, &root).unwrap();
    let withheld = *staged.commit();

    assert_eq!(
        Handle::<SimpleArchive>::from_hash(withheld.data()),
        expected_data
    );
    assert_eq!(withheld.metadata(), expected_metadata);
    assert!(staged
        .store_mut()
        .events
        .iter()
        .all(|event| matches!(event, StoreEvent::Put(_))));

    let committed = staged.finalize().unwrap();
    assert_eq!(committed, withheld);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::Insert(
            CollectionRecord::Commit(withheld).fingerprint()
        ))
    );
}

#[test]
fn read_and_write_policies_are_independent() {
    let root = key(3);
    let stranger = key(4);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "independent-actions",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    let authorized = store.commit(collection, &root, fragment(1)).unwrap();
    let unauthorized = store.commit(collection, &stranger, fragment(2)).unwrap();
    let attestation = store.commit(collection, &stranger, fragment(1)).unwrap();

    let snapshot = store.snapshot().unwrap();
    assert!(collection
        .reader_is_admitted(&snapshot, stranger.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, stranger.verifying_key())
        .unwrap());
    let cover = collection.admitted(&snapshot).unwrap();
    assert_eq!(cover.len(), 1);
    assert!(cover.contains(Handle::<SimpleArchive>::from_hash(authorized.data())));

    // Provenance is every valid signature over the selected payload, not the
    // set of authorized membership claims that admitted that payload.
    let commits = cover.commits(&snapshot).unwrap();
    assert_eq!(commits.len(), 2);
    assert!(commits.contains(&authorized));
    assert!(commits.contains(&attestation));
    assert!(!commits.contains(&unauthorized));
}

#[test]
fn invoke_only_root_proof_admits_recipient_but_blocks_redelegation() {
    let root = key(5);
    let intermediary = key(6);
    let leaf = key(7);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "direct-only",
            CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    let parent_proof = CapabilityProof::new(
        CapabilityResource::from(collection.handle()),
        &root,
        write_capability(),
        intermediary.verifying_key(),
    );
    let child_proof = parent_proof
        .delegate(&intermediary, write_capability(), leaf.verifying_key())
        .unwrap();
    // Signing an extension does not confer authority. The child is outside
    // the parent's delegated action set, but the earlier grant remains valid.
    store.insert_proof(child_proof.clone()).unwrap();

    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        child_proof.validate_delegation(&snapshot),
        Err(CapabilityProofError::UndelegatedAction {
            step: 1,
            action: ACTION_WRITE
        }),
    );
    assert!(collection
        .writer_is_admitted(&snapshot, intermediary.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, leaf.verifying_key())
        .unwrap());
}

#[test]
fn read_grants_use_the_distinct_read_action() {
    let root = key(8);
    let reader = key(9);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "read-action",
            CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .unwrap();
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            read_capability(),
            reader.verifying_key(),
        ))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    assert!(collection
        .reader_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
}

#[test]
fn read_audience_includes_valid_proof_prefixes() {
    let root = key(83);
    let intermediary = key(84);
    let leaf = key(85);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "read-audience",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(root.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let delegable_read = store
        .put::<SimpleArchive, _>(
            entity! {
                capability_action: ACTION_READ,
                capability_delegate_action: ACTION_READ,
            }
            .facts()
            .clone(),
        )
        .unwrap();
    let parent_proof = CapabilityProof::new(
        CapabilityResource::from(collection.handle()),
        &root,
        delegable_read,
        intermediary.verifying_key(),
    );
    let child_proof = parent_proof
        .delegate(&intermediary, read_capability(), leaf.verifying_key())
        .unwrap();
    store.insert_proof(child_proof).unwrap();

    let snapshot = store.snapshot().unwrap();
    let CollectionReadAudience::Restricted(readers) =
        collection_read_audience(&snapshot, collection.handle()).unwrap()
    else {
        panic!("delegable READ policy must have a finite audience");
    };
    assert!(readers.contains(&root.verifying_key()));
    assert!(readers.contains(&intermediary.verifying_key()));
    assert!(readers.contains(&leaf.verifying_key()));
}

#[test]
fn collection_quorum_needs_support_from_distinct_roots() {
    let first_root = key(10);
    let second_root = key(11);
    let writer = key(12);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "two-root-write-quorum",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::quorum(
                    [first_root.verifying_key(), second_root.verifying_key()],
                    2,
                    None,
                )
                .unwrap(),
            ),
        )
        .unwrap();

    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &first_root,
            write_capability(),
            writer.verifying_key(),
        ))
        .unwrap();
    assert!(!collection
        .writer_is_admitted(&store.snapshot().unwrap(), writer.verifying_key())
        .unwrap());

    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &second_root,
            write_capability(),
            writer.verifying_key(),
        ))
        .unwrap();
    assert!(collection
        .writer_is_admitted(&store.snapshot().unwrap(), writer.verifying_key())
        .unwrap());
}
