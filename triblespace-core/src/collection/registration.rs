//! Attached mappings registered by the algorithm id their descriptors name.
//!
//! A maintainer that finds attached collections by their descriptors can
//! only run the mappings it was built with. For each representation this
//! crate defines one canonical mapping ([`super::CollectionAttachment`]); a
//! crate that defines another mapping onto a known representation (the
//! Archive's BM25 over text payloads is a `PortableBM25Blob` under its own
//! algorithm) hands it to a maintainer as an [`AttachedMappings`]
//! registration: one [`AttachedMapping`], or a pair of registrations. There
//! is no global registry; a maintainer runs what it is given.
//!
//! [`registered_targets`] lists the attached collections a store's records
//! name whose algorithm a registration runs. An attached collection is named
//! by a record once it has a `MAP`: the first read that keeps its images
//! ([`super::CollectionStoreExt::keep_attached`]) declares it.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

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
    CollectionSnapshotExt, CollectionStoreExt, MapMapping,
};

/// The future one registered mapping maintains an attached collection with.
pub type AttachedMaintenance<'a, S> = Pin<
    Box<
        dyn Future<Output = Result<<S as SnapshotSource>::Snapshot, CollectionRealizationError>>
            + Send
            + 'a,
    >,
>;

/// Attached mappings, each run for the attached collections whose
/// descriptors name its algorithm.
pub trait AttachedMappings: Send + Sync {
    /// Whether one of these mappings runs `algorithm`.
    fn runs(&self, algorithm: Id) -> bool;

    /// How many foundations of the attached collection `handle`'s parent no
    /// usable attachment reaches in `snapshot` (its residual), for an
    /// `algorithm` one of these runs.
    fn residual<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, CollectionRealizationError>;

    /// Maintain the attached collection `handle`, whose descriptor names
    /// `algorithm`, one these run: carry its parent and attach the frontier
    /// ([`CollectionStoreExt::maintain_attached_with`]).
    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> AttachedMaintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send;
}

fn unregistered(algorithm: Id) -> CollectionRealizationError {
    CollectionRealizationError::Resolution(format!(
        "attached mapping algorithm {algorithm:X} is not registered here"
    ))
}

/// No registered mappings.
impl AttachedMappings for () {
    fn runs(&self, _algorithm: Id) -> bool {
        false
    }

    fn residual<R: StoreRead>(
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
    ) -> AttachedMaintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        Box::pin(async move { Err(unregistered(algorithm)) })
    }
}

/// Two registrations: the first that runs an algorithm runs it.
impl<A: AttachedMappings, B: AttachedMappings> AttachedMappings for (A, B) {
    fn runs(&self, algorithm: Id) -> bool {
        self.0.runs(algorithm) || self.1.runs(algorithm)
    }

    fn residual<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        if self.0.runs(algorithm) {
            self.0.residual(snapshot, handle, algorithm)
        } else {
            self.1.residual(snapshot, handle, algorithm)
        }
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        algorithm: Id,
        signer: &'a SigningKey,
    ) -> AttachedMaintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        if self.0.runs(algorithm) {
            self.0.maintain(pile, snapshot, handle, algorithm, signer)
        } else {
            self.1.maintain(pile, snapshot, handle, algorithm, signer)
        }
    }
}

/// One attached mapping `M`, registered for the descriptors naming
/// `algorithm` (the id `M::bind` accepts).
pub struct AttachedMapping<M> {
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

fn open<M, R>(
    snapshot: &R,
    handle: CollectionHandle,
) -> Result<Collection<M::Target>, CollectionRealizationError>
where
    M: MapMapping,
    R: BlobStoreGet,
{
    Collection::<M::Target>::open(snapshot, handle).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "open attached collection descriptor: {error}"
        ))
    })
}

impl<M> AttachedMappings for AttachedMapping<M>
where
    M: MapMapping + 'static,
    Handle<M::Target>: InlineEncoding,
{
    fn runs(&self, algorithm: Id) -> bool {
        algorithm == self.algorithm
    }

    fn residual<R: StoreRead>(
        &self,
        snapshot: &R,
        handle: CollectionHandle,
        _algorithm: Id,
    ) -> Result<usize, CollectionRealizationError> {
        Ok(snapshot
            .attached(open::<M, R>(snapshot, handle)?)?
            .residual()
            .len())
    }

    fn maintain<'a, S>(
        &'a self,
        pile: &'a mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        _algorithm: Id,
        signer: &'a SigningKey,
    ) -> AttachedMaintenance<'a, S>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        let collection = open::<M, S::Snapshot>(snapshot, handle);
        Box::pin(async move { pile.maintain_attached_with::<M>(collection?, signer).await })
    }
}

/// The attached collections `snapshot`'s records name whose descriptor
/// names an algorithm `mappings` runs, each with that algorithm.
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
    M: AttachedMappings,
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
        if attached && mappings.runs(algorithm) {
            targets.push((handle, algorithm));
        }
    }
    Ok(targets)
}
