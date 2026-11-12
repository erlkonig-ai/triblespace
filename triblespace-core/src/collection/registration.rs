//! Mappings registered by the algorithm id their descriptors name.
//!
//! A maintainer that finds collections by their descriptors can only run
//! the mappings it was built with. For each representation this crate
//! defines one canonical mapping; a crate that defines another (the
//! Archive's BM25 over text payloads is a `PortableBM25Blob` under its own
//! algorithm, a WeMM index derives NVFP4 rows with a model) hands it to a
//! maintainer as a registration ([`Mappings`]): an [`AttachedMapping`], a
//! [`DerivedMapping`], its own implementation, or a pair of registrations.
//! There is no global registry; a maintainer runs what it is given.
//!
//! [`registered_targets`] lists the collections a store's records name whose
//! algorithm a registration runs. A collection is named by a record once it
//! has one: an attached collection from its first `MAP` (the first read that
//! keeps its images, [`super::CollectionStoreExt::keep_attached`], declares
//! it), a derived one from its first leaf.
//!
//! A mapping may need what only some hosts have, a bound model say; its
//! registration owns that (when it binds, what it keeps bound, when it tries
//! again, [`Mappings::due`]). This module knows nothing about it.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::time::Instant;

use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::id::Id;
use crate::inline::encodings::hash::Handle;
use crate::inline::InlineEncoding;
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{BlobStoreGet, SnapshotSource, Store, StoreRead};
use crate::trible::TribleSet;

use super::{
    descriptor, Collection, CollectionHandle, CollectionRead, CollectionRealizationError,
    CollectionSnapshotExt, CollectionStoreExt, DeriveMapping, MapMapping,
};

/// The future one registered mapping maintains a collection with.
pub type Maintenance<'a, S> = Pin<
    Box<
        dyn Future<Output = Result<<S as SnapshotSource>::Snapshot, CollectionRealizationError>>
            + Send
            + 'a,
    >,
>;

/// Registered mappings, each run for the collections whose descriptors name
/// its algorithm.
///
/// A maintainer calls [`Self::begin_pass`] once at the start of each pass,
/// then, for each target, [`Self::pending`] and, when it is not zero,
/// [`Self::maintain`]; it passes again at [`Self::due`] even when the store
/// has not grown.
pub trait Mappings: Send + Sync {
    /// Whether one of these mappings runs `algorithm`.
    fn runs(&self, algorithm: Id) -> bool;

    /// A pass over `snapshot` begins: a registration may look at everything
    /// it will be asked about before the first [`Self::maintain`].
    fn begin_pass<R: StoreRead>(&self, _snapshot: &R) {}

    /// How much of collection `handle`'s input it does not answer for in
    /// `snapshot`, for an `algorithm` one of these runs: the parent
    /// foundations no attachment reaches, or the source foundations with no
    /// leaf. Zero means nothing to do here.
    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, CollectionRealizationError>;

    /// Maintain collection `handle`, whose descriptor names `algorithm`, one
    /// these run ([`CollectionStoreExt::maintain_attached_with`],
    /// [`CollectionStoreExt::maintain_with`]).
    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send;

    /// When work these deferred (a bind that failed, a model that waits for
    /// the next pass) is due again, if any: a maintainer passes then even if
    /// the store has not changed.
    fn due(&self) -> Option<Instant> {
        None
    }
}

fn unregistered(algorithm: Id) -> CollectionRealizationError {
    CollectionRealizationError::Resolution(format!(
        "mapping algorithm {algorithm:X} is not registered here"
    ))
}

fn resolution(what: &str, error: impl std::fmt::Display) -> CollectionRealizationError {
    CollectionRealizationError::Resolution(format!("{what}: {error}"))
}

/// No registered mappings.
impl Mappings for () {
    fn runs(&self, _algorithm: Id) -> bool {
        false
    }

    fn pending<R: StoreRead>(
        &self,
        _snapshot: &R,
        _handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        Err(unregistered(algorithm))
    }

    fn maintain<'a, S>(
        &'a self,
        _pile: &'a mut S,
        _snapshot: &S::Snapshot,
        _handle: CollectionHandle,
        algorithm: Id,
        _signer: &'a SigningKey,
    ) -> Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        Box::pin(async move { Err(unregistered(algorithm)) })
    }
}

/// Two registrations: the first that runs an algorithm runs it.
impl<A: Mappings, B: Mappings> Mappings for (A, B) {
    fn runs(&self, algorithm: Id) -> bool {
        self.0.runs(algorithm) || self.1.runs(algorithm)
    }

    fn begin_pass<R: StoreRead>(&self, snapshot: &R) {
        self.0.begin_pass(snapshot);
        self.1.begin_pass(snapshot);
    }

    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        if self.0.runs(algorithm) {
            self.0.pending(snapshot, handle, algorithm)
        } else {
            self.1.pending(snapshot, handle, algorithm)
        }
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        if self.0.runs(algorithm) {
            self.0.maintain(pile, snapshot, handle, algorithm, signer)
        } else {
            self.1.maintain(pile, snapshot, handle, algorithm, signer)
        }
    }

    fn due(&self) -> Option<Instant> {
        match (self.0.due(), self.1.due()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// One attached mapping `M`, registered for the descriptors naming
/// `algorithm` (the id `M::bind` accepts).
pub struct AttachedMapping<M> {
    algorithm: Id,
    mapping: PhantomData<fn() -> M>,
}

/// One derived mapping `M` that every host can compute, registered for the
/// descriptors naming `algorithm` (the id `M::bind` accepts).
pub struct DerivedMapping<M> {
    algorithm: Id,
    mapping: PhantomData<fn() -> M>,
}

impl<M> AttachedMapping<M> {
    pub const fn new(algorithm: Id) -> Self {
        Self {
            algorithm,
            mapping: PhantomData,
        }
    }

    /// The algorithm this registration runs.
    pub const fn algorithm(&self) -> Id {
        self.algorithm
    }
}

impl<M> DerivedMapping<M> {
    pub const fn new(algorithm: Id) -> Self {
        Self {
            algorithm,
            mapping: PhantomData,
        }
    }

    /// The algorithm this registration runs.
    pub const fn algorithm(&self) -> Id {
        self.algorithm
    }
}

impl<M> Mappings for AttachedMapping<M>
where
    M: MapMapping + 'static,
    Handle<M::Target>: InlineEncoding,
{
    fn runs(&self, algorithm: Id) -> bool {
        algorithm == self.algorithm
    }

    /// The parent foundations no usable attachment reaches (the residual).
    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        _algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        let attached = Collection::<M::Target>::open(snapshot, handle)
            .map_err(|error| resolution("open attached collection descriptor", error))?;
        Ok(snapshot.attached(attached)?.residual().len())
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        _algorithm: Id,
        signer: &'a SigningKey,
    ) -> Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        let attached = Collection::<M::Target>::open(snapshot, handle)
            .map_err(|error| resolution("open attached collection descriptor", error));
        Box::pin(async move { pile.maintain_attached_with::<M>(attached?, signer).await })
    }
}

/// The derived collection `handle` and its source, typed.
pub fn open_derived<M, R>(
    snapshot: &R,
    handle: CollectionHandle,
) -> Result<(Collection<M::Source>, Collection<M::Target>), CollectionRealizationError>
where
    M: DeriveMapping,
    R: BlobStoreGet,
{
    let target = Collection::<M::Target>::open(snapshot, handle)
        .map_err(|error| resolution("open derived collection descriptor", error))?;
    let facts: TribleSet = snapshot
        .get(handle)
        .map_err(|error| resolution("read derived collection descriptor", error))?;
    let source = descriptor::source(&facts)
        .map_err(|error| resolution("read derived collection source", error))?
        .ok_or_else(|| resolution("derived collection descriptor", "names no source"))?;
    let source = Collection::<M::Source>::open(snapshot, source)
        .map_err(|error| resolution("open derived collection source", error))?;
    Ok((source, target))
}

impl<M> Mappings for DerivedMapping<M>
where
    M: DeriveMapping + 'static,
    Handle<M::Source>: InlineEncoding,
    Handle<M::Target>: InlineEncoding,
{
    fn runs(&self, algorithm: Id) -> bool {
        algorithm == self.algorithm
    }

    /// The source foundations with no usable leaf (the backlog).
    fn pending<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        _algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        let (source, target) = open_derived::<M, R>(snapshot, handle)?;
        let source = snapshot.collection::<M::Source>(source)?;
        let target = snapshot.collection::<M::Target>(target)?;
        Ok(target.missing_from(&source)?.len())
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        _algorithm: Id,
        signer: &'a SigningKey,
    ) -> Maintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        let opened = open_derived::<M, S::Snapshot>(snapshot, handle);
        Box::pin(async move { pile.maintain_with::<M>(opened?.1, signer).await })
    }
}

/// The collections `snapshot`'s records name whose descriptor names an
/// algorithm `mappings` runs, each with that algorithm: attached
/// collections (a descriptor with a parent) and derived ones (a source).
///
/// Descriptors are read only from what `snapshot` holds: one that is not
/// here or does not decode is passed over, and so is a mapping nothing
/// registered. The answer is one observation's, recomputed by each caller.
pub fn registered_targets<R, M>(
    snapshot: &R,
    mappings: &M,
) -> Result<Vec<(CollectionHandle, Id)>, R::RecordsError>
where
    R: CollectionRead + BlobStoreGet,
    M: Mappings,
{
    let mut targets = Vec::new();
    for handle in snapshot.collections()? {
        let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(handle) else {
            continue;
        };
        let Ok(Some(algorithm)) = descriptor::mapping_algorithm(&facts) else {
            continue;
        };
        let attached = descriptor::parents(&facts).is_ok_and(|parents| !parents.is_empty());
        let derived = matches!(descriptor::source(&facts), Ok(Some(_)));
        if (attached || derived) && mappings.runs(algorithm) {
            targets.push((handle, algorithm));
        }
    }
    Ok(targets)
}
