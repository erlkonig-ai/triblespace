//! The collections derived from a source or attached to it, found from
//! their descriptors, and kept up as a group.
//!
//! An attached collection names its parent instead of a source; every write's
//! [`ensure_downstream`] attaches the parent's current frontier into it, and
//! [`maintain_downstream`] carries the parent first and attaches what the
//! carry left. The prose below is about derived collections.
//!
//! Every derived collection's descriptor names its immediate source, and every
//! store can list the collections its records name. So "what derives from
//! `X`" needs no list kept per faculty: one pass over the store's collections,
//! one small blob read each, and the chain comes out in dependency order --
//! source, its images, their images. A derived collection joins that list
//! with its first record: a store lists the collections its records name,
//! and a descriptor alone is a blob like any other. So whoever registers a
//! derived collection realizes it once, then, when the source has something
//! to image; from then on every write's [`ensure_downstream`] finds it.
//!
//! Upkeep on a write is "derive what you wrote". [`ensure_downstream`] gives
//! every derived collection a leaf for each source foundation the signer
//! owns and the collection has none for yet, and publishes no merge; a
//! write that calls it after its commit leaves the commit readable through
//! every view, at the cost of one locator per own foundation and that
//! commit's own images. [`maintain_downstream`] also derives every
//! foundation left without a usable leaf, whoever owns it, and carries each
//! derived collection's own lattice of leaf images into the signer's merges,
//! as the daemon does; nothing reads a source's merges. Both visit a
//! collection after its source, so a leaf image of the source is here
//! before the collection above it maps it. Neither decides what is cheap:
//! the first call on a cold store may take as long as the backlog is, and
//! says so by taking it. A representation this binary cannot map, or a
//! descriptor naming a mapping other than the representation's canonical
//! one, is named in the report rather than guessed at; a signer the target's
//! policy does not admit is named too, after its collection is carried.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;

use ed25519_dalek::SigningKey;

use crate::blob::encodings::entity_id_set::EntityIdSetBlob;
use crate::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use crate::id::Id;
use crate::inline::encodings::hash::Handle;
use crate::inline::InlineEncoding;
use crate::metadata::MetaDescribe;
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{Store, StoreRead};
use crate::trible::TribleSet;

use super::api::{load_collection_descriptor, CollectionStoreExt};
use super::encoding::{CollectionAttachment, CollectionDerivation};
use super::exact_derived::CollectionRealizationError;
use super::latest::LatestBlob;
use super::lww_register::LwwRegisterBlob;
use super::Collection;
use super::{descriptor, CollectionHandle};

/// One collection derived, directly or through other derived collections,
/// from the source asked about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Derived {
    /// The derived collection.
    pub handle: CollectionHandle,
    /// Its immediate source, which is the source asked about or another
    /// entry earlier in the same list.
    pub source: CollectionHandle,
    /// The blob representation its descriptor names.
    pub representation: Id,
    /// The mapping algorithm its descriptor names, if any.
    pub algorithm: Option<Id>,
}

/// Every collection derived from `source`, transitively, each one after the
/// collection it derives from.
///
/// Read from the store's collection listing and each candidate's descriptor;
/// no record is enumerated. A collection whose descriptor is not resident or
/// does not decode is left out: nothing here could maintain it, and its
/// own source is unknown.
pub fn derived_from<S>(
    snapshot: &S,
    source: CollectionHandle,
) -> Result<Vec<Derived>, S::RecordsError>
where
    S: StoreRead,
{
    let mut by_source: BTreeMap<CollectionHandle, Vec<Derived>> = BTreeMap::new();
    for collection in snapshot.collections()? {
        if collection == source {
            continue;
        }
        let Ok(facts) = snapshot.get::<TribleSet, _>(collection) else {
            continue;
        };
        let (Ok(Some(parent)), Ok(representation), Ok(algorithm)) = (
            descriptor::source(&facts),
            descriptor::representation(&facts),
            descriptor::mapping_algorithm(&facts),
        ) else {
            continue;
        };
        by_source.entry(parent).or_default().push(Derived {
            handle: collection,
            source: parent,
            representation,
            algorithm,
        });
    }
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::from([source]);
    let mut queue = VecDeque::from([source]);
    while let Some(parent) = queue.pop_front() {
        let Some(children) = by_source.get(&parent) else {
            continue;
        };
        for child in children {
            if seen.insert(child.handle) {
                ordered.push(*child);
                queue.push_back(child.handle);
            }
        }
    }
    Ok(ordered)
}

/// One collection attached to the parent asked about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attached {
    /// The attached collection.
    pub handle: CollectionHandle,
    /// The collection whose nodes it indexes.
    pub parent: CollectionHandle,
    /// The blob representation its descriptor names.
    pub representation: Id,
    /// The mapping algorithm its descriptor names, if any.
    pub algorithm: Option<Id>,
    /// The sibling attached collections its mapping reads, each earlier in
    /// the same list when it is attached to the same parent.
    pub siblings: Vec<CollectionHandle>,
}

/// Every collection attached to `parent` alone, each after the siblings its
/// mapping reads.
///
/// Read from the store's collection listing and each candidate's
/// descriptor, like [`derived_from`]; an attached collection is listed once
/// a record names it. A descriptor naming a second parent is not listed:
/// an attached read walks one parent's lattice, so nothing here serves it.
/// A sibling cycle, which no mapping should name, is broken by listing what
/// remains in handle order.
pub fn attached_to<S>(
    snapshot: &S,
    parent: CollectionHandle,
) -> Result<Vec<Attached>, S::RecordsError>
where
    S: StoreRead,
{
    let mut pending: BTreeMap<CollectionHandle, Attached> = BTreeMap::new();
    for collection in snapshot.collections()? {
        let Ok(facts) = snapshot.get::<TribleSet, _>(collection) else {
            continue;
        };
        let (Ok(named), Ok(representation), Ok(algorithm), Ok(siblings)) = (
            descriptor::parents(&facts),
            descriptor::representation(&facts),
            descriptor::mapping_algorithm(&facts),
            descriptor::reads_attached(&facts),
        ) else {
            continue;
        };
        if named.as_slice() != [parent] {
            continue;
        }
        pending.insert(
            collection,
            Attached {
                handle: collection,
                parent,
                representation,
                algorithm,
                siblings,
            },
        );
    }
    let mut ordered = Vec::new();
    while !pending.is_empty() {
        let ready: Vec<CollectionHandle> = pending
            .values()
            .filter(|attached| {
                attached
                    .siblings
                    .iter()
                    .all(|sibling| !pending.contains_key(sibling))
            })
            .map(|attached| attached.handle)
            .collect();
        let next = if ready.is_empty() {
            vec![*pending.keys().next().expect("pending is not empty")]
        } else {
            ready
        };
        for handle in next {
            ordered.push(
                pending
                    .remove(&handle)
                    .expect("a pending attached collection"),
            );
        }
    }
    Ok(ordered)
}

/// How far to take a derived or attached collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Upkeep {
    /// Derive the signer's own missing leaves, or attach the parent's
    /// current frontier; publish no merge.
    Ensure,
    /// Derive every foundation left without a usable leaf and carry the
    /// derived collection's own lattice; for an attached collection, carry
    /// its parent first and attach the frontier after.
    Maintain,
}

/// What one realizer did with one derived or attached collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Realized {
    /// The target was taken as far as asked.
    Done,
    /// The signer may not write the target, so no leaf was derived. Under
    /// [`Upkeep::Maintain`] the target's own lattice was still carried: a
    /// merge needs no WRITE.
    Unadmitted,
    /// This realizer knows neither the target's representation nor the
    /// mapping its descriptor names, so nothing was published.
    Unknown,
}

/// Takes one derived or attached collection as far as asked, for the
/// representations it knows. [`CoreRealizer`] knows this crate's; a binary
/// that carries more encodings wraps it and answers for those first.
pub trait RealizeDerived<S>
where
    S: Store + AsyncBlobStoreAcquire + Send,
{
    /// Realize `derived` under `upkeep`, signing what is published with
    /// `signer`, or say why nothing was.
    fn realize(
        &mut self,
        store: &mut S,
        derived: &Derived,
        signer: &SigningKey,
        upkeep: Upkeep,
    ) -> impl Future<Output = Result<Realized, CollectionRealizationError>> + Send;

    /// Realize one attached collection under `upkeep`, signing its MAPs with
    /// `signer`, which must be the store's host, or say that this realizer
    /// does not know it.
    fn realize_attached(
        &mut self,
        store: &mut S,
        attached: &Attached,
        signer: &SigningKey,
        upkeep: Upkeep,
    ) -> impl Future<Output = Result<Realized, CollectionRealizationError>> + Send;
}

/// Take one collection of a known encoding as far as asked through its
/// canonical mapping, or say why it was not: the descriptor names another
/// mapping than `T`'s canonical one, or the signer may not write it.
///
/// A descriptor registered through an explicit mapping value carries that
/// mapping's algorithm, and `T`'s canonical mapping refuses to bind to it.
/// That refusal is the answer, not an error: whoever registered the mapping
/// realizes it, and a realizer that knows the mapping answers for it first.
///
/// Only a new leaf needs WRITE. A signer the target does not admit derives
/// nothing and answers [`Realized::Unadmitted`]; under
/// [`Upkeep::Maintain`] it still carries the target's own lattice, because
/// a merge needs only the store's host key.
pub async fn realize_as<S, T>(
    store: &mut S,
    derived: &Derived,
    signer: &SigningKey,
    upkeep: Upkeep,
) -> Result<Realized, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire + Send,
    T: CollectionDerivation + MetaDescribe,
    Handle<T>: InlineEncoding,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("observe derived collection", error)
    })?;
    let collection: Collection<T> = Collection::open(&snapshot, derived.handle)
        .map_err(|error| CollectionRealizationError::storage("open derived descriptor", error))?;
    let target = load_collection_descriptor(&snapshot, derived.handle)
        .map_err(|error| CollectionRealizationError::storage("read derived descriptor", error))?;
    let source = load_collection_descriptor(&snapshot, derived.source)
        .map_err(|error| CollectionRealizationError::storage("read source descriptor", error))?;
    if T::bind(&source.fragment, &target.fragment).is_err() {
        return Ok(Realized::Unknown);
    }
    let admitted = collection
        .writer_is_admitted(&snapshot, signer.verifying_key())
        .map_err(|error| CollectionRealizationError::storage("admit derived writer", error))?;
    drop(snapshot);
    match (upkeep, admitted) {
        (Upkeep::Ensure, false) => return Ok(Realized::Unadmitted),
        (Upkeep::Ensure, true) => drop(store.ensure(collection, signer).await?),
        // A key the target does not admit derives nothing and carries.
        (Upkeep::Maintain, _) => drop(store.maintain(collection, signer).await?),
    }
    Ok(if admitted {
        Realized::Done
    } else {
        Realized::Unadmitted
    })
}

/// Take one attached collection of a known encoding as far as asked through
/// its canonical mapping, or answer [`Realized::Unknown`] when its
/// descriptor names another mapping. There is no WRITE check: an attached
/// collection has no policy, and its MAPs are believed on the host's key.
pub async fn realize_attached_as<S, T>(
    store: &mut S,
    attached: &Attached,
    signer: &SigningKey,
    upkeep: Upkeep,
) -> Result<Realized, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire + Send,
    T: CollectionAttachment + MetaDescribe,
    Handle<T>: InlineEncoding,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("observe attached collection", error)
    })?;
    let collection: Collection<T> = Collection::open(&snapshot, attached.handle)
        .map_err(|error| CollectionRealizationError::storage("open attached descriptor", error))?;
    let descriptor = load_collection_descriptor(&snapshot, attached.handle)
        .map_err(|error| CollectionRealizationError::storage("read attached descriptor", error))?;
    let parent = load_collection_descriptor(&snapshot, attached.parent)
        .map_err(|error| CollectionRealizationError::storage("read parent descriptor", error))?;
    drop(snapshot);
    if T::bind(&parent.fragment, &descriptor.fragment).is_err() {
        return Ok(Realized::Unknown);
    }
    match upkeep {
        Upkeep::Ensure => drop(store.ensure_attached(collection, signer).await?),
        Upkeep::Maintain => drop(store.maintain_attached(collection, signer).await?),
    }
    Ok(Realized::Done)
}

/// The realizer for this crate's own encodings. It knows no derived
/// collection: every index this crate defines -- Succinct and Rank9
/// archives, entity-id sets, latest indexes and last-writer-wins registers --
/// is attached to its parent instead.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreRealizer;

impl<S> RealizeDerived<S> for CoreRealizer
where
    S: Store + AsyncBlobStoreAcquire + Send,
{
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
        store: &mut S,
        attached: &Attached,
        signer: &SigningKey,
        upkeep: Upkeep,
    ) -> Result<Realized, CollectionRealizationError> {
        let representation = attached.representation;
        if representation == <SuccinctArchiveBlob as MetaDescribe>::id() {
            realize_attached_as::<S, SuccinctArchiveBlob>(store, attached, signer, upkeep).await
        } else if representation == <Rank9AcceleratedSuccinctArchiveBlob as MetaDescribe>::id() {
            realize_attached_as::<S, Rank9AcceleratedSuccinctArchiveBlob>(
                store, attached, signer, upkeep,
            )
            .await
        } else if representation == <EntityIdSetBlob as MetaDescribe>::id() {
            realize_attached_as::<S, EntityIdSetBlob>(store, attached, signer, upkeep).await
        } else if representation == <LatestBlob as MetaDescribe>::id() {
            realize_attached_as::<S, LatestBlob>(store, attached, signer, upkeep).await
        } else if representation == <LwwRegisterBlob as MetaDescribe>::id() {
            realize_attached_as::<S, LwwRegisterBlob>(store, attached, signer, upkeep).await
        } else {
            Ok(Realized::Unknown)
        }
    }
}

/// What a pass over a source's derived and attached collections did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpkeepReport {
    /// Taken as far as asked, in the order they were visited: derived
    /// collections first, then attached ones.
    pub realized: Vec<CollectionHandle>,
    /// Derived collections given no leaf because the signer may not write
    /// them; under maintenance each was still carried.
    pub unadmitted: Vec<CollectionHandle>,
    /// Derived collections left alone because no realizer knows their
    /// representation or the mapping their descriptor names; each carries
    /// both.
    pub unknown: Vec<Derived>,
    /// Attached collections left alone for the same reason.
    pub unknown_attached: Vec<Attached>,
    /// Derived collections whose upkeep failed, each with why; the pass went
    /// on to the rest. What one leaves underived or uncarried is its lag,
    /// and what it did publish stands.
    pub failed: Vec<(Derived, String)>,
    /// Attached collections whose upkeep failed, each with why; the pass
    /// went on to the rest. What one leaves unattached is its readers'
    /// residual, read from its bytes or named unread.
    pub failed_attached: Vec<(Attached, String)>,
}

/// Visit every collection derived from `source`, each after its own source,
/// then every collection attached to `source`, each after the siblings it
/// reads, and take each as far as `upkeep` asks with `realizer`.
///
/// One derived or attached collection failing is that collection's lag, not
/// the pass's: it is named in [`UpkeepReport::failed`] or
/// [`UpkeepReport::failed_attached`], and the rest are still taken up, a
/// collection derived from a failed one too, from what the failed one does
/// hold. Only a signer that is not the store's host stops the pass, because
/// no collection believes its MERGEs or MAPs.
pub async fn upkeep_downstream<S, R>(
    store: &mut S,
    source: CollectionHandle,
    signer: &SigningKey,
    upkeep: Upkeep,
    realizer: &mut R,
) -> Result<UpkeepReport, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire + Send,
    R: RealizeDerived<S>,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("observe derived collections", error)
    })?;
    let derived = derived_from(&snapshot, source)
        .map_err(|error| CollectionRealizationError::storage("list derived collections", error))?;
    let attached = attached_to(&snapshot, source)
        .map_err(|error| CollectionRealizationError::storage("list attached collections", error))?;
    drop(snapshot);
    let mut report = UpkeepReport::default();
    for target in derived {
        match realizer.realize(store, &target, signer, upkeep).await {
            Ok(Realized::Done) => report.realized.push(target.handle),
            Ok(Realized::Unadmitted) => report.unadmitted.push(target.handle),
            Ok(Realized::Unknown) => report.unknown.push(target),
            Err(error @ CollectionRealizationError::HostMismatch { .. }) => return Err(error),
            Err(error) => report.failed.push((target, error.to_string())),
        }
    }
    for target in attached {
        match realizer
            .realize_attached(store, &target, signer, upkeep)
            .await
        {
            Ok(Realized::Done) => report.realized.push(target.handle),
            Ok(Realized::Unadmitted) => report.unadmitted.push(target.handle),
            Ok(Realized::Unknown) => report.unknown_attached.push(target),
            Err(error @ CollectionRealizationError::HostMismatch { .. }) => return Err(error),
            Err(error) => report.failed_attached.push((target, error.to_string())),
        }
    }
    Ok(report)
}

/// Derive the signer's own missing leaves into every collection derived from
/// `source`, each after its own source, and attach `source`'s current
/// frontier into every collection attached to it, so that what the signer
/// wrote is readable through each of them; publish no merge. A write calls
/// this after its commit.
pub async fn ensure_downstream<S, R>(
    store: &mut S,
    source: CollectionHandle,
    signer: &SigningKey,
    realizer: &mut R,
) -> Result<UpkeepReport, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire + Send,
    R: RealizeDerived<S>,
{
    upkeep_downstream(store, source, signer, Upkeep::Ensure, realizer).await
}

/// Derive every foundation left without a usable leaf into every collection
/// derived from `source` and carry each one's own lattice, each after its
/// own source; then carry `source` and attach its new frontier into every
/// collection attached to it. What the daemon does for its configured
/// sources.
pub async fn maintain_downstream<S, R>(
    store: &mut S,
    source: CollectionHandle,
    signer: &SigningKey,
    realizer: &mut R,
) -> Result<UpkeepReport, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire + Send,
    R: RealizeDerived<S>,
{
    upkeep_downstream(store, source, signer, Upkeep::Maintain, realizer).await
}
