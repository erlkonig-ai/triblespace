//! Exact-byte acquisition over a frozen store observation.
//!
//! Exact gets perform I/O. Record/proof reads, residency and change detection
//! delegate to the original snapshot. First selection can retry that snapshot's
//! parked records using acquired definitions, never newer records or proofs.
//! Call synchronous reads outside an async task;
//! an async application can run a fixed observation in spawn_blocking while
//! its owning runtime continues to drive network I/O.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use futures::future::{AbortHandle, Abortable, Either, Pending, Shared};
use futures::FutureExt;

use crate::collection::{
    CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector,
};
use crate::inline::encodings::hash::Handle;
use crate::inline::InlineEncoding;
use crate::repo::{BlobStoreGet, BlobStoreList, CapabilityProofRead, ReadFailure};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod control_tests;

/// Cooperative control for one frozen acquisition call and all its reader clones.
///
/// A deadline is absolute, not renewed for each blob. Cancellation is sticky and
/// wakes every pending exact get. Neither can preempt synchronous work inside a
/// future's poll or between gets; a caller using `spawn_blocking` must retain and
/// join that task before reporting it settled. `check` also supports cooperative
/// boundaries in such callers, without creating another reader or store.
#[derive(Clone, Debug)]
pub struct AcquiringReadControl {
    abort: AbortHandle,
    cancelled: Shared<Abortable<Pending<()>>>,
    deadline: Option<Instant>,
}

/// Interruption is an operation error, never unavailable bytes (`MissingBlob`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquiringReadInterrupted {
    Cancelled,
    DeadlineExceeded,
}

impl fmt::Display for AcquiringReadInterrupted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "exact acquisition cancelled",
            Self::DeadlineExceeded => "exact acquisition deadline exceeded",
        })
    }
}

impl Error for AcquiringReadInterrupted {}

impl AcquiringReadControl {
    pub fn new(deadline: Option<Instant>) -> Self {
        let (abort, registration) = AbortHandle::new_pair();
        Self {
            abort,
            // Shared fans out notification: Abortable alone has one waker.
            cancelled: Abortable::new(futures::future::pending(), registration).shared(),
            deadline,
        }
    }

    pub fn cancel(&self) {
        self.abort.abort();
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Removes this clone's acquisition deadline while sharing cancellation.
    ///
    /// Use after a complete result is prepared when subsequent receipt work
    /// must remain cancellable but is no longer bounded by selection's deadline.
    /// Existing clones keep their deadlines; cancellation is never reset.
    pub fn without_deadline(&self) -> Self {
        Self {
            deadline: None,
            ..self.clone()
        }
    }

    /// Cancellation wins when both interruption conditions are already true.
    pub fn check(&self) -> Result<(), AcquiringReadInterrupted> {
        if self.abort.is_aborted() {
            Err(AcquiringReadInterrupted::Cancelled)
        } else if self.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            Err(AcquiringReadInterrupted::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    /// Wait for explicit cancellation; the absolute deadline is separate.
    pub fn cancelled(&self) -> impl Future<Output = ()> + Send {
        let cancelled = self.cancelled.clone();
        async move {
            let _ = cancelled.await;
        }
    }

    async fn interrupted(&self) -> AcquiringReadInterrupted {
        if let Err(error) = self.check() {
            return error;
        }
        match self.deadline {
            Some(deadline) => {
                let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                match futures::future::select(Box::pin(self.cancelled()), Box::pin(timer)).await {
                    Either::Left(_) => AcquiringReadInterrupted::Cancelled,
                    Either::Right(_) => self
                        .check()
                        .err()
                        .unwrap_or(AcquiringReadInterrupted::DeadlineExceeded),
                }
            }
            None => {
                self.cancelled().await;
                AcquiringReadInterrupted::Cancelled
            }
        }
    }
}

async fn controlled_get<F, T, E>(
    future: F,
    control: Option<AcquiringReadControl>,
) -> Result<T, ReadFailure>
where
    F: Future<Output = Result<T, E>> + Send,
    E: Error + Send + Sync + 'static,
{
    let Some(control) = control else {
        return future.await.map_err(ReadFailure::new);
    };
    control.check().map_err(ReadFailure::new)?;
    let result =
        match futures::future::select(Box::pin(future), Box::pin(control.interrupted())).await {
            Either::Left((result, _)) => {
                let value = result.map_err(ReadFailure::new)?;
                // A completed poll may have done synchronous work past the deadline.
                // Reject its result, without claiming to undo any cache insertion.
                control.check().map_err(ReadFailure::new)?;
                Ok(value)
            }
            Either::Right((interrupted, pending_get)) => {
                drop(pending_get);
                Err(ReadFailure::new(interrupted))
            }
        };
    result
}

/// A synchronous command-boundary reader with exact-byte acquisition, but
/// frozen proof evidence and residency. Use outside a running async task.
/// Acquiring a descriptor or capability definition never replaces the evidence
/// which admits it, nor an application view selected before this reader.
#[derive(Clone)]
pub struct AcquiringReader<S> {
    frozen: S,
    runtime: RuntimeDriver,
    control: Option<AcquiringReadControl>,
}

#[derive(Clone)]
enum RuntimeDriver {
    Owned(Arc<tokio::runtime::Runtime>),
    Borrowed(tokio::runtime::Handle),
}

impl RuntimeDriver {
    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        match self {
            Self::Owned(runtime) => runtime.block_on(future),
            Self::Borrowed(runtime) => runtime.block_on(future),
        }
    }
}

impl<S> AcquiringReader<S> {
    /// Recover this exact frozen reader, without observing the store again.
    pub fn into_frozen(self) -> S {
        self.frozen
    }

    /// Use a runtime kept alive by the command's storage owner.
    pub fn with_handle(snapshot: S, runtime: tokio::runtime::Handle) -> Self {
        Self {
            frozen: snapshot,
            runtime: RuntimeDriver::Borrowed(runtime),
            control: None,
        }
    }

    /// Retain the command's runtime for synchronous exact-byte reads.
    pub fn new(snapshot: S, runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self {
            frozen: snapshot,
            runtime: RuntimeDriver::Owned(runtime),
            control: None,
        }
    }

    /// Apply one call's cooperative limits without changing its frozen observation.
    pub fn with_control(mut self, control: AcquiringReadControl) -> Self {
        self.control = Some(control);
        self
    }
}

impl<S: crate::repo::StoreSnapshot> crate::repo::StoreSnapshot for AcquiringReader<S> {
    fn changes_since(&self, previous: &Self) -> crate::repo::StoreChanges {
        self.frozen.changes_since(&previous.frozen)
    }

    fn changes_for(
        &self,
        previous: &Self,
        dependencies: &crate::repo::StoreDependencies,
    ) -> crate::repo::StoreChanges {
        self.frozen.changes_for(&previous.frozen, dependencies)
    }
}

impl<S: crate::repo::async_store::AsyncBlobStoreGet> BlobStoreGet for AcquiringReader<S> {
    type GetError<E: std::error::Error + Send + Sync + 'static> = ReadFailure;

    fn get<T, E>(
        &self,
        handle: crate::inline::Inline<Handle<E>>,
    ) -> Result<T, Self::GetError<T::Error>>
    where
        E: crate::blob::BlobEncoding + 'static,
        T: crate::blob::TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.runtime
            .block_on(controlled_get(self.frozen.get(handle), self.control.clone()))
    }
}

impl<S: crate::repo::async_store::AsyncBlobStoreGet> crate::repo::async_store::AsyncBlobStoreGet
    for AcquiringReader<S>
{
    type GetError<E: std::error::Error + Send + Sync + 'static> = ReadFailure;

    fn get<T, E>(
        &self,
        handle: crate::inline::Inline<Handle<E>>,
    ) -> impl std::future::Future<Output = Result<T, Self::GetError<T::Error>>> + Send
    where
        E: crate::blob::BlobEncoding + 'static,
        T: crate::blob::TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        controlled_get(self.frozen.get(handle), self.control.clone())
    }
}

impl<S: CapabilityProofRead> CapabilityProofRead for AcquiringReader<S> {
    type ProofsError = S::ProofsError;
    type ProofIter<'a>
        = S::ProofIter<'a>
    where
        Self: 'a;

    fn proofs(&self) -> Result<Self::ProofIter<'_>, Self::ProofsError> {
        self.frozen.proofs()
    }

    fn proof(
        &self,
        id: crate::capability::CapabilityProofId,
    ) -> Result<Option<crate::capability::CapabilityProof>, Self::ProofsError> {
        self.frozen.proof(id)
    }
}

impl<S: BlobStoreList> BlobStoreList for AcquiringReader<S> {
    type Err = S::Err;
    type Iter<'a>
        = S::Iter<'a>
    where
        Self: 'a;

    fn blobs(&self) -> Self::Iter<'_> {
        self.frozen.blobs()
    }

    fn contains_blob<E>(&self, handle: crate::inline::Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: crate::blob::BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.contains_blob(handle)
    }
}

impl<S: crate::repo::BlobStoreMeta> crate::repo::BlobStoreMeta for AcquiringReader<S> {
    type MetaError = S::MetaError;

    fn metadata<E>(
        &self,
        handle: crate::inline::Inline<Handle<E>>,
    ) -> Result<Option<crate::repo::BlobMetadata>, Self::MetaError>
    where
        E: crate::blob::BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.metadata(handle)
    }
}

impl<S: CollectionRead> CollectionRead for AcquiringReader<S> {
    type RecordsError = crate::repo::ReadFailure;
    type RecordIter<'a>
        = Box<dyn Iterator<Item = Result<CollectionRecord, Self::RecordsError>> + 'a>
    where
        Self: 'a;

    fn records(&self) -> Result<Self::RecordIter<'_>, Self::RecordsError> {
        self.frozen
            .records()
            .map(|records| {
                Box::new(records.map(|record| record.map_err(crate::repo::ReadFailure::new)))
                    as Self::RecordIter<'_>
            })
            .map_err(crate::repo::ReadFailure::new)
    }

    fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
        self.frozen
            .collections()
            .map_err(crate::repo::ReadFailure::new)
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.frozen
            .select_records(selectors)
            .map_err(crate::repo::ReadFailure::new)
    }

    fn select_record_views(
        &self, selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<crate::collection::CollectionRecordView>, Self::RecordsError> {
        self.frozen.select_record_views(selectors).map_err(crate::repo::ReadFailure::new)
    }

    fn select_record_view_changes(
        &self, previous: &Self, selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<crate::collection::RecordViewChanges, Self::RecordsError> {
        self.frozen.select_record_view_changes(&previous.frozen, selectors).map_err(crate::repo::ReadFailure::new)
    }
}

impl<S> crate::collection::CoverageRead for AcquiringReader<S>
where
    S: crate::collection::CoverageRead
        + CapabilityProofRead
        + crate::repo::async_store::AsyncBlobStoreGet,
{
    fn index(
        &self,
        lineage: &BTreeSet<CollectionHandle>,
    ) -> Result<crate::collection::coverage::CoverageIndex, Self::RecordsError> {
        let mut index = self
            .frozen
            .index(lineage)
            .map_err(crate::repo::ReadFailure::new)?;
        let attempt = crate::repo::read_attempt::ReadAttempt::new(self);
        index.retry_collections(
            &crate::collection::coverage::StoreWriters::new(&attempt),
            lineage,
        );
        attempt.finish()?;
        Ok(index)
    }
}

impl<S: crate::repo::WantRead> crate::repo::WantRead for AcquiringReader<S> {
    type WantsError = S::WantsError;
    type WantIter<'a>
        = S::WantIter<'a>
    where
        Self: 'a;

    fn wants(&self) -> Result<Self::WantIter<'_>, Self::WantsError> {
        self.frozen.wants()
    }
}
