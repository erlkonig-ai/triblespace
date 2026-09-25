//! The collections derived from a source, found from their descriptors, and
//! kept up as a group.
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
//! Maintenance is "derive what you wrote". [`ensure_downstream`] gives every
//! derived collection a leaf for each source foundation the signer owns and
//! the collection has none for yet, and publishes no merge; a write that
//! calls it after its commit leaves the commit readable through every view,
//! at the cost of one locator per own foundation and that commit's own
//! images. [`maintain_downstream`] also mirrors the signer's own source
//! merges into each of them, as the daemon does; a derived collection has no
//! carry of its own. Both visit a collection after its source, which is what
//! makes a source's mirrored merge result resident before the collection
//! above it maps it. Neither decides what is cheap: the first call on a cold
//! store may take as long as the backlog is, and says so by taking it.
//! A representation this binary cannot map, or a descriptor naming a mapping
//! other than the representation's canonical one, is named in the report
//! rather than guessed at; a signer the target's policy does not admit is
//! named too.

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
use super::encoding::CollectionDerivation;
use super::exact_derived::CollectionRealizationError;
use super::latest::LatestBlob;
use super::lww_register::LwwRegisterBlob;
use super::reference_summary::ReferenceSummaryBlob;
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

/// How far to take a derived collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Upkeep {
    /// Derive the signer's own missing leaves; publish no merge.
    Ensure,
    /// Ensure, then mirror the signer's own source merges.
    Maintain,
}

/// What one realizer did with one derived collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Realized {
    /// The target was taken as far as asked.
    Done,
    /// The signer may not write the target, so nothing was published.
    Unadmitted,
    /// This realizer knows neither the target's representation nor the
    /// mapping its descriptor names, so nothing was published.
    Unknown,
}

/// Takes one derived collection as far as asked, for the representations it
/// knows. [`CoreRealizer`] knows this crate's; a binary that carries more
/// encodings wraps it and answers for those first.
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
}

/// Take one collection of a known encoding as far as asked through its
/// canonical mapping, or say why nothing was published: the descriptor names
/// another mapping than `T`'s canonical one, or the signer may not write it.
///
/// A descriptor registered through an explicit mapping value carries that
/// mapping's algorithm, and `T`'s canonical mapping refuses to bind to it.
/// That refusal is the answer, not an error: whoever registered the mapping
/// realizes it, and a realizer that knows the mapping answers for it first.
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
    if !admitted {
        return Ok(Realized::Unadmitted);
    }
    match upkeep {
        Upkeep::Ensure => drop(store.ensure(collection, signer).await?),
        Upkeep::Maintain => drop(store.maintain(collection, signer).await?),
    }
    Ok(Realized::Done)
}

/// The realizer for this crate's own derived encodings: Succinct and Rank9
/// archives, entity-id sets, latest indexes, last-writer-wins registers and
/// reference summaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreRealizer;

impl<S> RealizeDerived<S> for CoreRealizer
where
    S: Store + AsyncBlobStoreAcquire + Send,
{
    async fn realize(
        &mut self,
        store: &mut S,
        derived: &Derived,
        signer: &SigningKey,
        upkeep: Upkeep,
    ) -> Result<Realized, CollectionRealizationError> {
        let representation = derived.representation;
        if representation == <SuccinctArchiveBlob as MetaDescribe>::id() {
            realize_as::<S, SuccinctArchiveBlob>(store, derived, signer, upkeep).await
        } else if representation == <Rank9AcceleratedSuccinctArchiveBlob as MetaDescribe>::id() {
            realize_as::<S, Rank9AcceleratedSuccinctArchiveBlob>(store, derived, signer, upkeep)
                .await
        } else if representation == <EntityIdSetBlob as MetaDescribe>::id() {
            realize_as::<S, EntityIdSetBlob>(store, derived, signer, upkeep).await
        } else if representation == <LatestBlob as MetaDescribe>::id() {
            realize_as::<S, LatestBlob>(store, derived, signer, upkeep).await
        } else if representation == <LwwRegisterBlob as MetaDescribe>::id() {
            realize_as::<S, LwwRegisterBlob>(store, derived, signer, upkeep).await
        } else if representation == <ReferenceSummaryBlob as MetaDescribe>::id() {
            realize_as::<S, ReferenceSummaryBlob>(store, derived, signer, upkeep).await
        } else {
            Ok(Realized::Unknown)
        }
    }
}

/// What a pass over a source's derived collections did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpkeepReport {
    /// Taken as far as asked, in the order they were visited.
    pub realized: Vec<CollectionHandle>,
    /// Left alone because the signer may not write them.
    pub unadmitted: Vec<CollectionHandle>,
    /// Left alone because no realizer knows their representation or the
    /// mapping their descriptor names; each carries both.
    pub unknown: Vec<Derived>,
}

/// Visit every collection derived from `source`, each after its own source,
/// and take it as far as `upkeep` asks with `realizer`.
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
    drop(snapshot);
    let mut report = UpkeepReport::default();
    for target in derived {
        match realizer.realize(store, &target, signer, upkeep).await? {
            Realized::Done => report.realized.push(target.handle),
            Realized::Unadmitted => report.unadmitted.push(target.handle),
            Realized::Unknown => report.unknown.push(target),
        }
    }
    Ok(report)
}

/// Derive the signer's own missing leaves into every collection derived from
/// `source`, each after its own source, so that what the signer wrote is
/// readable through each of them; publish no merge. A write calls this after
/// its commit.
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

/// Derive the signer's own leaves into every collection derived from
/// `source` and mirror its own source merges there, each after its own
/// source. What the daemon does for its configured sources.
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
