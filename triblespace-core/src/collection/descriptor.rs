//! Reading collection descriptor facts.
//!
//! A descriptor is an ordinary [`TribleSet`]: facts constructed with
//! [`entity!`](crate::macros::entity), stored as a
//! [`SimpleArchive`](crate::blob::encodings::simplearchive::SimpleArchive)
//! blob whose handle is the collection identity. The descriptor names its
//! encoding directly, and reading one is an ordinary query over ordinary
//! facts.
//!
//! A root carries [`collection_name`] while a derived collection carries
//! [`collection_source`] and one concrete [`collection_mapping`]
//! instance instead. Mapping parameters hang from that mapping entity, not
//! from the collection descriptor, so the conversion remains independently
//! identifiable and queryable. Both kinds carry independent, self-contained
//! capability policy bindings. Each capability is either open or governed by
//! a quorum over its own canonical root set; there is no privileged collection
//! owner or shared anchor. Policy is never inferred by walking the source
//! chain. Readers query the facts they need; unrelated fields and retired
//! attributes are not a reason to reject the archive. The singular accessors
//! below are explicit diagnostics requiring one descriptor entity and
//! unambiguous field values. Ordinary admission uses [`admission_policies`]
//! and accepts any supported alternative. Executable lineage still requires
//! an unambiguous source and mapping; plural lineage is not defined here.

use itertools::Itertools;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::capability::policy::{capability_handle, resource_policies, resource_policy};
use crate::capability::CapabilityHandle;
use crate::id::Id;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::UnknownInline;
use crate::inline::{Inline, IntoInline, RawInline};
use crate::metadata::{self, MetaDescribe};
use crate::prelude::{and, entity, exists, find, or, pattern};
use crate::query::TriblePattern;
use crate::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use crate::trible::{Fragment, TribleSet};

use super::policy::{
    AdmissionPolicy, CollectionPolicy, KIND_ADMISSION_POLICY_OPEN, KIND_ADMISSION_POLICY_QUORUM,
};
use super::records::{
    admission_delegate_threshold, admission_invoke_threshold, admission_policy_root,
    collection_mapping, collection_name, collection_representation, collection_source,
    mapping_algorithm as mapping_algorithm_attribute, CollectionHandle, RecordDecodeError,
    KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING,
};
use super::{read_capability, write_capability, CollectionEncoding, CollectionMapping};

/// Store one descriptor archive and every blob carried by its self-contained
/// Fragment, returning the canonical descriptor handle.
///
/// The descriptor identity covers only its fact archive. Names and embedded
/// self-descriptions may reference separate blobs, so publishing facts alone
/// would leave a descriptor whose facts are readable but whose descriptions
/// cannot be read. Registration therefore stores the complete closure before
/// publishing any later record which names the descriptor handle.
pub(crate) fn put_closure<S>(
    store: &mut S,
    descriptor: &Fragment,
) -> Result<CollectionHandle, S::PutError>
where
    S: BlobStorePut,
{
    let mut blobs = descriptor.blobs().clone();
    let mut embedded: Vec<Blob<UnknownBlob>> = blobs
        .snapshot()
        .expect("MemoryBlobStore::snapshot is infallible")
        .into_iter()
        .map(|(_, blob)| blob)
        .collect();
    embedded.sort_unstable_by_key(|blob| blob.get_handle().raw);
    for blob in embedded {
        store.put::<UnknownBlob, _>(blob)?;
    }
    store.put::<SimpleArchive, _>(descriptor.facts().clone())
}

/// Content identity of one fixed root descriptor, pinned so that re-minting
/// every collection cannot happen quietly.
///
/// A collection *is* the handle of its descriptor blob. So every fact
/// [`naming`] emits — the name, the representation, and the whole encoded
/// admission policy — is part of that identity, and changing any of their
/// shapes gives the same logical collection a different handle. Callers do not
/// see this. A faculty asks for the name it always used, receives the new
/// generation, finds it empty, and carries on while the old generation's
/// records sit unreferenced in the pile.
///
/// That has already happened four times in nine days. The records survived
/// each time; what was lost was the fact that anything had moved.
///
/// `root_descriptor_identity_is_pinned` recomputes this from a fixed name, a
/// fixed representation and a fixed key, so a policy-schema edit fails the test
/// with the new value instead of silently re-minting every collection in every
/// pile. **Never repin this to make the test pass.** A new value means existing
/// collections have new identities and their records need a migration forward;
/// the constant is the last thing to change, after that migration exists.
pub const PINNED_ROOT_DESCRIPTOR_IDENTITY: RawInline =
    hex_literal::hex!("8A63C584C7A645DAA1DA959631E55299181869B7FFC5A567A535D71924367D68");

/// Build a root descriptor that names its encoding without describing it.
///
/// A collection encoding normally writes its own descriptor as a visible
/// `entity!`; see
/// [`simplearchive_union::descriptor`](crate::collection::simplearchive_union::descriptor),
/// which additionally embeds the encoding's self-description so a stranger
/// holding the one blob can say what the collection is. This is the bare
/// generic form, for callers holding only ids.
///
/// Policy is mandatory and contributes to collection identity. Actual
/// delegated principals remain external capability proofs so invitations can
/// grow without renaming the collection.
pub(crate) fn naming<E>(name: &str, policy: CollectionPolicy) -> Fragment
where
    E: CollectionEncoding,
{
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: name.to_owned(),
        resource_policy*: policy.fragment(),
        collection_representation*: <E as MetaDescribe>::describe(),
    }
}

/// The handle a named root collection *would* have, for a reader that must
/// find it without writing to the pile.
///
/// This is [`naming`] plus the content address, with no store involved. It
/// mirrors [`CollectionStorage::collection`] deliberately non-generically, so
/// the two cannot drift: that method is fixed to `SimpleArchive`, and a derived
/// handle is only useful if it equals the one registration returns.
///
/// # Why this is narrow, and why [`identity_for_tests`] stays test-only
///
/// The reason that constructor is not public is recorded and still stands:
/// production code takes its handle from what `put` hands back, because a
/// handle computed *beside* a store rather than *by* it can name a descriptor
/// that was never written, leaving records that reference something nothing can
/// decode.
///
/// That hazard belongs to **writers**. A reader deriving this handle and finding
/// no descriptor simply reads an absent collection, which is the honest
/// open-world answer and the correct fallback for a host not yet configured. So
/// use this to OPEN a collection someone else registered; never to name one in a
/// record you are about to write. For that, register it and take the handle.
///
/// The motivating case is a pile's own configuration: a collection admitting
/// only the pile's signing key, whose handle is therefore a function of a key
/// the process already holds. Nothing external has to remember it, which is the
/// point -- an external note of a handle is one more copy that can go stale.
///
/// Identity is a function of the name, the policy and the encoding;
/// [`PINNED_ROOT_DESCRIPTOR_IDENTITY`] is what keeps that from moving silently.
pub fn root_handle_to_read(name: &str, policy: CollectionPolicy) -> CollectionHandle {
    crate::blob::IntoBlob::<crate::blob::encodings::simplearchive::SimpleArchive>::to_blob(
        naming::<crate::blob::encodings::simplearchive::SimpleArchive>(name, policy)
            .facts()
            .clone(),
    )
    .get_handle()
}

/// Build a derived descriptor around one explicit mapping value.
///
/// The mapping Fragment is spread into the same descriptor archive. Its root
/// is linked from the descriptor and all algorithm descriptions, parameters,
/// and attachments therefore travel with the collection identity. This
/// lower-level form also serves downstream mappings between encodings whose
/// crates cannot implement the target-owned
/// [`CollectionDerivation`](super::CollectionDerivation) trait because of
/// Rust's orphan rule.
pub(crate) fn deriving_with<M>(
    source: CollectionHandle,
    mapping: &M,
    policy: CollectionPolicy,
) -> Fragment
where
    M: CollectionMapping,
{
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_source: source,
        resource_policy*: policy.fragment(),
        collection_representation*: <M::Target as MetaDescribe>::describe(),
        collection_mapping*: mapping.fragment(),
    }
}

/// The entity the descriptor's own attributes hang off.
///
/// A descriptor archive holds more than one entity: the descriptor, plus the
/// embedded self-descriptions of its encoding and mapping. The
/// descriptor is the one tagged [`KIND_COLLECTION_DESCRIPTOR`].
///
/// This is not the collection identity. That is the handle of the stored
/// descriptor blob.
///
/// For the decoded path only: a descriptor read back out of a blob is a bare
/// `TribleSet`, so finding its root means looking for the tag. A caller that
/// *built* the descriptor already holds the root and should use
/// [`Fragment::root`](crate::trible::Fragment::root) rather than pay this scan
/// to recover something it never lost.
pub fn entity(facts: &TribleSet) -> Result<Id, RecordDecodeError> {
    exactly_one(
        find!(
            (e: Id),
            pattern!(facts, [{ ?e @ metadata::tag: KIND_COLLECTION_DESCRIPTOR }])
        )
        .map(|(e,)| e),
        "metadata::tag",
    )
}

/// Blob representation carried by the elements of this collection.
pub fn representation(facts: &TribleSet) -> Result<Id, RecordDecodeError> {
    let descriptor = entity(facts)?;
    exactly_one(
        find!(
            (v: Id?),
            pattern!(facts, [{ descriptor @ collection_representation: ?v }])
        )
        .map(|(v,)| v),
        "collection_representation",
    )?
    .map_err(|_| RecordDecodeError::InvalidId("collection_representation"))
}

/// Concrete mapping instance carried by a derived collection.
///
/// Root collections answer `None`. A derived collection names exactly one
/// mapping entity. Canonical builders normally derive its id from its concrete
/// parameters, but readers accept the equivalent extrinsic-id substitution.
pub fn mapping(facts: &TribleSet) -> Result<Option<Id>, RecordDecodeError> {
    let descriptor = entity(facts)?;
    at_most_one(
        find!(
            (v: Id?),
            pattern!(facts, [{ descriptor @ collection_mapping: ?v }])
        )
        .map(|(v,)| v),
        "collection_mapping",
    )?
    .map(|value| value.map_err(|_| RecordDecodeError::InvalidId("collection_mapping")))
    .transpose()
}

/// Algorithm named by the concrete mapping instance, if this is derived.
pub fn mapping_algorithm(facts: &TribleSet) -> Result<Option<Id>, RecordDecodeError> {
    let Some(mapping) = mapping(facts)? else {
        return Ok(None);
    };
    exactly_one(
        find!(
            v: Id,
            pattern!(facts, [{ mapping @
                metadata::tag: KIND_COLLECTION_MAPPING,
                mapping_algorithm_attribute: ?v,
            }])
        ),
        "mapping_algorithm",
    )
    .map(Some)
}

/// The collection this one derives from, if it derives from one.
///
/// A root has no source and answers `None`; that is not a failure, it is what
/// being a root means.
pub fn source(facts: &TribleSet) -> Result<Option<CollectionHandle>, RecordDecodeError> {
    let descriptor = entity(facts)?;
    at_most_one(
        find!(
            (v: CollectionHandle),
            pattern!(facts, [{ descriptor @ collection_source: ?v }])
        )
        .map(|(v,)| v),
        "collection_source",
    )
}

/// Handle of the UTF-8 name carried by a root collection.
///
/// A derived collection has no name of its own and answers `None`: its anchor
/// is its source, and its name is whatever that source is called.
pub fn name(facts: &TribleSet) -> Result<Option<Inline<Handle<UTF8String>>>, RecordDecodeError> {
    let descriptor = entity(facts)?;
    at_most_one(
        find!(
            (v: Inline<Handle<UTF8String>>),
            pattern!(facts, [{ descriptor @ collection_name: ?v }])
        )
        .map(|(v,)| v),
        "collection_name",
    )
}

/// Explicit scalar READ/WRITE policy inspection, retaining all binding facts.
///
/// Ordinary admission does not reconstruct this producer. This diagnostic
/// requires one descriptor and one binding for each standard capability; its
/// generic binding Fragment also retains custom and unknown policy facts.
pub fn policy(facts: &TribleSet) -> Result<CollectionPolicy, RecordDecodeError> {
    let descriptor = entity(facts)?;
    let read = exactly_one(
        find!(
            binding: Id,
            pattern!(facts, [
                { descriptor @ resource_policy: ?binding },
                { ?binding @ capability_handle: read_capability() },
            ])
        ),
        "collection READ capability policy",
    )?;
    let write = exactly_one(
        find!(
            binding: Id,
            pattern!(facts, [
                { descriptor @ resource_policy: ?binding },
                { ?binding @ capability_handle: write_capability() },
            ])
        ),
        "collection WRITE capability policy",
    )?;
    let exports: Vec<_> = find!(
        binding: Id,
        pattern!(facts, [{ descriptor @ resource_policy: ?binding }])
    )
    .collect();
    let binding_facts: TribleSet = find!(
        (binding: Id, attribute: Id, value: Inline<UnknownInline>),
        pattern!(facts, [
            { descriptor @ resource_policy: ?binding },
            { ?binding @ ?attribute: ?value },
        ])
    )
    .map(|(binding, attribute, value)| crate::trible::Trible::force(&binding, &attribute, &value))
    .collect();
    Ok(CollectionPolicy::from_bindings(
        decode_admission_policy(facts, read)?,
        decode_admission_policy(facts, write)?,
        Fragment::new(exports, binding_facts),
    ))
}

/// Query every supported capability-policy interpretation of a descriptor.
///
/// A typed consumer supplies its representation; that encoding and the
/// resource-policy link must belong to the same tagged descriptor entity.
/// Representation-neutral consumers supply `None`. Definitions are not
/// fetched or interpreted here: each exact handle remains an opaque key.
pub fn capability_policies<'a>(
    facts: &'a TribleSet,
    representation: Option<Id>,
) -> impl Iterator<Item = (CapabilityHandle, AdmissionPolicy)> + 'a {
    descriptor_entities(facts, representation)
        .flat_map(move |descriptor| resource_policies(facts, descriptor, None))
}

/// Query supported policies for an action declared by a bound capability.
///
/// Every recognized alternative contributes independently. Unknown kinds,
/// undecodable values, and unsupported thresholds supply no row; absence
/// never supplies Open. A binding names a reusable definition, not the exact
/// handle a delegated grant must repeat. Unknown or unavailable definitions
/// contribute no authority; unrelated facts do not invalidate a definition.
pub fn admission_policies<'a, R: BlobStoreGet>(
    reader: &'a R,
    facts: &'a TribleSet,
    action: Id,
    representation: Option<Id>,
) -> impl Iterator<Item = AdmissionPolicy> + 'a {
    capability_policies(facts, representation).filter_map(move |(handle, policy)| {
        let definition: TribleSet = reader.get(handle).ok()?;
        exists!(
            pattern!(&definition, [{ _?definition @ crate::capability::capability_action: action }])
        )
        .then_some(policy)
    })
}

/// The supported policies for an action whose definitions are resident, and
/// the handles of the definitions that are not.
///
/// A policy whose definition blob is elsewhere is not silently absent: the
/// fold parks on that blob and is woken when it lands, the way it waits for
/// a descriptor.
pub(crate) fn admission_policies_with_missing<R: BlobStoreGet>(
    reader: &R,
    facts: &TribleSet,
    action: Id,
    representation: Option<Id>,
) -> (Vec<AdmissionPolicy>, Vec<CapabilityHandle>) {
    let mut policies = Vec::new();
    let mut missing = Vec::new();
    for (handle, policy) in capability_policies(facts, representation) {
        let Ok(definition) = reader.get::<TribleSet, _>(handle) else {
            missing.push(handle);
            continue;
        };
        if exists!(pattern!(&definition, [{ _?definition @ crate::capability::capability_action: action }])) {
            policies.push(policy);
        }
    }
    (policies, missing)
}

/// The one descriptor entity of a descriptor blob, or `None` when the blob
/// carries none or several. A blob with two descriptor entities does not say
/// which one a collection handle names, and no policy may be borrowed from a
/// sibling entity, so an untyped reader admits nobody through it.
pub(crate) fn sole_descriptor_entity(facts: &TribleSet) -> Option<Id> {
    let mut entities = descriptor_entities(facts, None);
    let first = entities.next()?;
    entities.next().is_none().then_some(first)
}

fn descriptor_entities<'a>(
    facts: &'a TribleSet,
    representation: Option<Id>,
) -> Box<dyn Iterator<Item = Id> + 'a> {
    match representation {
        Some(representation) => Box::new(find!(
            descriptor: Id,
            pattern!(facts, [{ ?descriptor @
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_representation: representation,
            }])
        )),
        None => Box::new(find!(
            descriptor: Id,
            pattern!(facts, [{ ?descriptor @
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            }])
        )),
    }
}

fn decode_admission_policy(
    facts: &TribleSet,
    policy: Id,
) -> Result<AdmissionPolicy, RecordDecodeError> {
    let kind = exactly_one(
        find!(
            kind: Id,
            and!(
                pattern!(facts, [{ policy @ metadata::tag: ?kind }]),
                or!(
                    kind.is(KIND_ADMISSION_POLICY_OPEN.to_inline()),
                    kind.is(KIND_ADMISSION_POLICY_QUORUM.to_inline()),
                ),
            )
        ),
        "admission policy metadata::tag",
    )?;

    if kind == KIND_ADMISSION_POLICY_OPEN {
        return Ok(AdmissionPolicy::Open);
    }

    let roots = find!(
        root: ed25519_dalek::VerifyingKey,
        pattern!(facts, [{ policy @ admission_policy_root: ?root }])
    );
    let invoke = exactly_one(
        find!(
            invoke: u32,
            pattern!(facts, [{ policy @ admission_invoke_threshold: ?invoke }])
        ),
        "admission_invoke_threshold",
    )?;
    let delegate = at_most_one(
        find!(
            delegate: u32,
            pattern!(facts, [{ policy @ admission_delegate_threshold: ?delegate }])
        ),
        "admission_delegate_threshold",
    )?;
    AdmissionPolicy::quorum(roots, invoke, delegate)
        .map_err(|_| RecordDecodeError::InvalidId("admission policy quorum"))
}

/// Look up one descriptor argument by attribute.
///
/// Source-to-target parameters normally use [`mapping_argument`]. This lower
/// level helper remains available for encoding-specific descriptor facts.
pub fn argument(facts: &TribleSet, attribute: Id) -> Result<Option<RawInline>, RecordDecodeError> {
    argument_on(facts, entity(facts)?, attribute, "descriptor argument")
}

/// Look up one concrete mapping parameter by attribute.
pub fn mapping_argument(
    facts: &TribleSet,
    attribute: Id,
) -> Result<Option<RawInline>, RecordDecodeError> {
    let Some(mapping) = mapping(facts)? else {
        return Ok(None);
    };
    argument_on(facts, mapping, attribute, "mapping argument")
}

fn argument_on(
    facts: &TribleSet,
    subject: Id,
    attribute: Id,
    field: &'static str,
) -> Result<Option<RawInline>, RecordDecodeError> {
    let subject: Inline<GenId> = subject.to_inline();
    let attribute: Inline<GenId> = attribute.to_inline();
    at_most_one(
        find!(
            (v: Inline<GenId>),
            facts.pattern::<GenId>(subject, attribute, v)
        )
        .map(|(v,)| v.raw),
        field,
    )
}

/// `Itertools::exactly_one`, saying which field the rows came from.
///
/// The question is the same one the rest of the crate asks by that name; only
/// the answer differs, because a decoder has to name the attribute it was
/// reading. `ExactlyOneError` carries the leftover iterator, which is empty
/// exactly when there was no first row at all -- that is how the two failures
/// are told apart here.
fn exactly_one<T>(
    rows: impl Iterator<Item = T>,
    field: &'static str,
) -> Result<T, RecordDecodeError> {
    rows.exactly_one().map_err(|mut leftover| {
        if leftover.next().is_some() {
            RecordDecodeError::RepeatedField(field)
        } else {
            RecordDecodeError::MissingField(field)
        }
    })
}

/// Decode an optional single-valued field without accepting an arbitrary
/// first match from malformed input.
fn at_most_one<T>(
    mut rows: impl Iterator<Item = T>,
    field: &'static str,
) -> Result<Option<T>, RecordDecodeError> {
    let Some(first) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(RecordDecodeError::RepeatedField(field));
    }
    Ok(Some(first))
}

/// A root descriptor under one fixed test authority, named by `name`.
///
/// Tests overwhelmingly want "some collection, distinct from that other one".
/// Spelling that as a name under a fixed authority keeps the distinction
/// readable in the test itself.
#[cfg(test)]
pub(crate) fn named_for_tests(name: &str, representation: Id) -> Fragment {
    let root = ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]).verifying_key();
    // Some record-algebra tests deliberately use synthetic encoding ids, so
    // retain the one bare low-level test constructor beside the typed public
    // builders.
    entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_name: name.to_owned(),
        resource_policy*: CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root)).fragment(),
        collection_representation: representation,
    }
}

/// Content identity of a descriptor, for tests that have no store.
///
/// The record algebra -- which payloads a cover admits, which merges compose,
/// what a derive equates -- is a property of records alone, and its tests
/// build them without a pile. There is no `put` to take a handle from, so
/// there is nothing to forget to write and no phantom to create: the
/// descriptor is an input to the algebra rather than a thing in a store.
///
/// This is why it is `cfg(test)` rather than public. Production code always
/// has somewhere to put the descriptor, and takes the handle from what `put`
/// hands back -- because a handle computed beside a store instead of by it can
/// name a collection whose descriptor was never written, leaving records that
/// reference something nothing can decode.
#[cfg(test)]
pub(crate) fn identity_for_tests(descriptor: &Fragment) -> CollectionHandle {
    crate::blob::IntoBlob::<crate::blob::encodings::simplearchive::SimpleArchive>::to_blob(
        descriptor.facts().clone(),
    )
    .get_handle()
}

#[cfg(test)]
mod policy_tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::collection::policy::{AdmissionPolicy, CollectionPolicy};
    use crate::inline::encodings::genid::GenId;
    use crate::inline::{Inline, IntoInline};
    use crate::metadata;
    use crate::trible::Trible;

    fn key(byte: u8) -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[byte; 32]).verifying_key()
    }

    fn root(name: &str, expected: CollectionPolicy) -> Fragment {
        naming::<SimpleArchive>(name, expected)
    }

    /// The canonical root descriptor still hashes to its pinned identity.
    ///
    /// This is the guard the four 2026-08/09 re-mints did not have. It fails
    /// loudly with the computed value so that changing the descriptor's shape
    /// is a deliberate act carrying a migration, rather than an invisible one.
    /// Restore the previous descriptor shape, or land the migration and repin
    /// in the same change; never repin alone.
    #[test]
    fn root_descriptor_identity_is_pinned() {
        let authority = key(0x2A);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(authority),
            AdmissionPolicy::direct(authority),
        );
        let computed = identity_for_tests(&naming::<SimpleArchive>("pinned-root", policy)).raw;
        assert_eq!(
            computed,
            PINNED_ROOT_DESCRIPTOR_IDENTITY,
            "the canonical root descriptor now hashes to {} instead of {}; every collection this \
             build registers has a new identity and the records of the previous generation are \
             unreachable by name. Restore the descriptor shape, or land a migration that carries \
             those records forward and repin in the same change.",
            hex::encode(computed),
            hex::encode(PINNED_ROOT_DESCRIPTOR_IDENTITY),
        );
    }

    #[test]
    fn policy_round_trips_independent_quorums() {
        let expected = CollectionPolicy::new(
            AdmissionPolicy::quorum([key(4), key(5)], 2, Some(2)).unwrap(),
            AdmissionPolicy::direct(key(4)),
        );
        assert_eq!(
            policy(root("ledger", expected.clone()).facts()),
            Ok(expected)
        );
    }

    #[test]
    fn policy_participates_in_collection_identity() {
        let closed = root(
            "ledger",
            CollectionPolicy::new(
                AdmissionPolicy::direct(key(5)),
                AdmissionPolicy::direct(key(5)),
            ),
        );
        let open_read = root(
            "ledger",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::direct(key(5))),
        );
        assert_ne!(identity_for_tests(&closed), identity_for_tests(&open_read));
    }

    #[test]
    fn missing_policy_link_fails_closed() {
        let fragment = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(key(6)).binding(write_capability()),
        };
        assert_eq!(
            policy(fragment.facts()),
            Err(RecordDecodeError::MissingField(
                "collection READ capability policy"
            ))
        );
    }

    #[test]
    fn unknown_policy_kind_fails_closed() {
        let unknown = entity! {
            capability_handle: read_capability(),
            metadata::tag: crate::id::id_hex!("44444444444444444444444444444444"),
        };
        let fragment = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: unknown,
            resource_policy*: AdmissionPolicy::direct(key(7)).binding(write_capability()),
        };
        assert_eq!(
            policy(fragment.facts()),
            Err(RecordDecodeError::MissingField(
                "admission policy metadata::tag"
            ))
        );
    }

    #[test]
    fn repeated_policy_link_fails_closed() {
        let mut fragment = root(
            "ledger",
            CollectionPolicy::new(
                AdmissionPolicy::direct(key(8)),
                AdmissionPolicy::direct(key(8)),
            ),
        );
        let descriptor = fragment.root().expect("descriptor root");
        let second_binding = AdmissionPolicy::Open.binding(read_capability());
        let second: Inline<GenId> = second_binding.root().expect("open policy root").to_inline();
        fragment += second_binding;
        fragment
            .facts_mut()
            .insert(&Trible::force(&descriptor, &resource_policy.id(), &second));
        assert_eq!(
            policy(fragment.facts()),
            Err(RecordDecodeError::RepeatedField(
                "collection READ capability policy"
            ))
        );
    }

    #[test]
    fn policy_ignores_annotations_and_fields_on_other_entities() {
        let read = crate::id::rngid();
        let write = crate::id::rngid();
        let subject = crate::id::rngid();
        let mut fragment = entity! { &subject @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: entity! { &read @
                capability_handle: read_capability(),
                metadata::tag*: [KIND_ADMISSION_POLICY_OPEN, metadata::KIND_BLOB_ENCODING],
                admission_policy_root: key(9),
                admission_invoke_threshold: 0_u32,
            },
            resource_policy*: entity! { &write @
                capability_handle: write_capability(),
                metadata::tag*: [KIND_ADMISSION_POLICY_QUORUM, metadata::KIND_BLOB_ENCODING],
                admission_policy_root: key(9),
                admission_invoke_threshold: 1_u32,
            },
        };
        // An embedded description may use the same attributes. It is not a
        // second policy link on this descriptor.
        fragment += entity! {
            resource_policy*: AdmissionPolicy::direct(key(10)).binding(read_capability()),
            resource_policy*: AdmissionPolicy::Open.binding(write_capability()),
        };
        let decoded = policy(fragment.facts()).unwrap();
        assert_eq!(decoded.read(), &AdmissionPolicy::Open);
        assert_eq!(decoded.write(), &AdmissionPolicy::direct(key(9)));
        let root_inline: Inline<crate::inline::encodings::ed25519::ED25519PublicKey> =
            key(9).to_inline();
        assert!(decoded.fragment().facts().contains(&Trible::force(
            &read.id,
            &admission_policy_root.id(),
            &root_inline
        )));
    }

    #[test]
    fn policy_does_not_borrow_a_missing_link_from_another_entity() {
        let mut fragment = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(key(9)).binding(write_capability()),
        };
        fragment += entity! {
            resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
        };
        assert_eq!(
            policy(fragment.facts()),
            Err(RecordDecodeError::MissingField(
                "collection READ capability policy"
            ))
        );
    }

    #[test]
    fn typed_policy_queries_ignore_undecodable_values() {
        let expected =
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::direct(key(9)));
        let mut fragment = root("typed-policy-values", expected.clone());
        let subject = fragment.root().unwrap();
        let write = find!(
            write: Id,
            pattern!(fragment.facts(), [
                { subject @ resource_policy: ?write },
                { ?write @ capability_handle: write_capability() },
            ])
        )
        .next()
        .unwrap();
        fragment.facts_mut().insert(&Trible::force(
            &subject,
            &resource_policy.id(),
            &Inline::<GenId>::new([0xFF; 32]),
        ));
        fragment.facts_mut().insert(&Trible::force(
            &write,
            &admission_invoke_threshold.id(),
            &Inline::<crate::inline::encodings::iu256::U256>::new([0xFF; 32]),
        ));
        let decoded = policy(fragment.facts()).unwrap();
        assert_eq!(decoded.read(), expected.read());
        assert_eq!(decoded.write(), expected.write());

        // Filtering is not a fallback to Open when no threshold decodes.
        let unreadable = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
            resource_policy*: entity! {
                capability_handle: write_capability(),
                metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
                admission_policy_root: key(9),
                admission_invoke_threshold:
                    Inline::<crate::inline::encodings::iu256::U256>::new([0xFF; 32]),
            },
        };
        assert_eq!(
            policy(unreadable.facts()),
            Err(RecordDecodeError::MissingField(
                "admission_invoke_threshold"
            ))
        );
    }

    /// The whole value of a derived handle is that it equals the registered one.
    ///
    /// If registration ever stops going through `naming::<SimpleArchive>`, or
    /// `put_closure` stops returning the descriptor blob's own handle, a reader
    /// deriving its configuration collection would silently open nothing and
    /// read "unconfigured" on a configured host. That is the failure this test
    /// exists to make loud.
    #[test]
    fn a_derived_root_handle_equals_the_one_registration_returns() {
        use crate::collection::CollectionStoreExt;
        use crate::repo::memoryrepo::MemoryRepo;

        let key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key),
            AdmissionPolicy::direct(key),
        );

        let mut store = MemoryRepo::default();
        let registered = store
            .collection("self-config", policy.clone())
            .expect("register")
            .handle();

        assert_eq!(
            super::root_handle_to_read("self-config", policy),
            registered,
            "a derived handle must name the collection registration created"
        );
    }

    /// The control: the key is part of the identity, so one pile's
    /// configuration is not another's. Without this, every host would derive
    /// the same handle and a "local" collection would be colony-wide.
    #[test]
    fn a_derived_root_handle_differs_with_the_key_and_with_the_name() {
        let one = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let two = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        let policy_of = |key| CollectionPolicy::new(
            AdmissionPolicy::direct(key),
            AdmissionPolicy::direct(key),
        );

        let a = super::root_handle_to_read("self-config", policy_of(one));
        let b = super::root_handle_to_read("self-config", policy_of(two));
        let c = super::root_handle_to_read("other-config", policy_of(one));

        assert_ne!(a, b, "a different signing key must give a different collection");
        assert_ne!(a, c, "a different name must give a different collection");
    }

    #[test]
    fn admission_queries_skip_unsupported_values_without_losing_valid_alternatives() {
        let subject = crate::id::rngid();
        let policy = crate::id::rngid();
        let unknown = crate::id::rngid();
        let representation = <SimpleArchive as MetaDescribe>::id();
        let mut fragment = entity! { &subject @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: representation,
            resource_policy*: entity! { &policy @
                capability_handle: write_capability(),
                metadata::tag*: [KIND_ADMISSION_POLICY_QUORUM, unknown.id],
                admission_policy_root: key(13),
                admission_invoke_threshold*: [0_u32, 1_u32, 2_u32],
                // This retired field cannot alter proof-path delegation.
                admission_delegate_threshold*: [0_u32, 2_u32],
            },
        };
        let invalid = Inline::<GenId>::new([0xFF; 32]);
        for attribute in [resource_policy.id(), collection_representation.id()] {
            fragment
                .facts_mut()
                .insert(&Trible::force(&subject.id, &attribute, &invalid));
        }
        fragment.facts_mut().insert(&Trible::force(
            &policy.id,
            &admission_invoke_threshold.id(),
            &invalid,
        ));
        fragment.facts_mut().insert(&Trible::force(
            &policy.id,
            &admission_policy_root.id(),
            &Inline::<GenId>::new([0; 32]),
        ));
        fragment.put::<SimpleArchive, _>(super::super::policy::write_definition().facts().clone());
        let reader = crate::repo::SnapshotSource::snapshot(&mut fragment.blobs().clone()).unwrap();
        let policies: Vec<_> = admission_policies(
            &reader,
            fragment.facts(),
            super::super::ACTION_WRITE,
            Some(representation),
        )
        .collect();
        assert_eq!(policies, vec![AdmissionPolicy::direct(key(13))]);
    }

    #[test]
    fn admission_queries_preserve_both_recognized_kinds() {
        let mut fragment = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_representation: <SimpleArchive as MetaDescribe>::id(),
            resource_policy*: entity! {
                capability_handle: read_capability(),
                metadata::tag*: [KIND_ADMISSION_POLICY_OPEN, KIND_ADMISSION_POLICY_QUORUM],
                admission_policy_root: key(14),
                admission_invoke_threshold: 1_u32,
            },
        };
        fragment.put::<SimpleArchive, _>(super::super::policy::read_definition().facts().clone());
        let reader = crate::repo::SnapshotSource::snapshot(&mut fragment.blobs().clone()).unwrap();
        let policies: Vec<_> =
            admission_policies(&reader, fragment.facts(), super::super::ACTION_READ, None)
                .collect();
        assert_eq!(policies.len(), 2);
        assert!(policies.contains(&AdmissionPolicy::Open));
        assert!(policies.contains(&AdmissionPolicy::direct(key(14))));
    }
}
