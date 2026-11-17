//! A polling driver for one [`CollectionEnvironment`].
//!
//! Stores have no change notification. A store only compares two of its own
//! snapshots ([`StoreSnapshot::changes_for`]), so the driver is polled. Each
//! step reads through an [`ObservedStore`] and keeps the raw read-set: the root's
//! records and every blob consulted, including a blob that was missing. A later
//! poll re-steps only when that read-set may have changed, so new facts and
//! late content (a blob arriving without any new fact) both wake it.
//!
//! This is not a scheduler, an effect worker or a notification owner. Firings
//! are not receipts: a restart observes the complete durable frame and may fire
//! again; conclusions already held add no publication. Conclusions are the
//! evaluator's own authored COMMITs (see [`CollectionEnvironment::publish`]).

use std::error::Error as StdError;
use std::fmt;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use crate::collection::observed_store::ObservedStore;
use crate::collection::{Collection, CollectionCommit, CollectionStore};
use crate::prelude::*;
use crate::query::register::Resolution;
use crate::repo::{
    BlobStorePut, SnapshotSource, StorageFlush, StoreDependencies, StoreRead, StoreSnapshot,
};

use super::collection::{AdvanceError, CollectionEnvironment, ObserveError, PublishError};
use super::Progress;

type Cause = Box<dyn StdError + Send + Sync>;

/// Explicit per-step limits. `firings` and `time` are checked between advance
/// calls of at most `chunk` firings; one call's query search is not interrupted,
/// so a step can overrun `time` by one chunk's search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub firings: usize,
    pub chunk: usize,
    pub time: Duration,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            firings: 1024,
            chunk: 64,
            time: Duration::from_secs(1),
        }
    }
}

/// Which bound stopped a step before quiescence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    Firings,
    Time,
}

/// How a poll ended. Only `Bounded` asks for another poll regardless of change.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing the last step read may have changed; no work was done.
    Unchanged,
    /// Every selected rule was checked; nothing unfired remains.
    Quiescent,
    /// A bound stopped the step; work may remain.
    Bounded(Bound),
    /// The reading is Empty or a Fork; nothing is advanced until it changes.
    Unresolved(Resolution),
    /// Observation or evaluation failed, typically on missing content. Facts
    /// concluded before the failure were published. Retried when the step's
    /// read-set changes, including when the missing blob arrives.
    Blocked(Cause),
}

#[derive(Debug)]
pub struct Step {
    pub outcome: Outcome,
    /// Firings of chunks that returned; a failed chunk's earlier firings are
    /// published but not counted.
    pub firings: usize,
    pub commits: Vec<CollectionCommit>,
}

/// Failures the driver does not retry by itself.
#[derive(Debug)]
pub enum DriverError {
    Snapshot(Cause),
    /// The batch stays in the environment and is retried first on the next poll.
    Publish(PublishError),
    /// Support shrank; construct a new driver to reopen deliberately.
    Reset(ObserveError),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(e) => write!(f, "snapshot: {e}"),
            Self::Publish(e) => write!(f, "publish: {e}"),
            Self::Reset(e) => write!(f, "observe: {e}"),
        }
    }
}

impl StdError for DriverError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Snapshot(e) => Some(e.as_ref()),
            Self::Publish(e) => Some(e),
            Self::Reset(e) => Some(e),
        }
    }
}

/// One environment, its signer, and the read-set of its last settled step.
/// Disposable: dropping it loses nothing that the store does not already hold.
pub struct CollectionDriver<T> {
    environment: CollectionEnvironment,
    signer: SigningKey,
    bounds: Bounds,
    /// The last step's snapshot and read-set, kept only once it settled.
    settled: Option<(T, StoreDependencies)>,
}

impl<T: StoreSnapshot> CollectionDriver<T> {
    pub fn new(
        root: Collection<blobencodings::SimpleArchive>,
        anchor: Id,
        signer: SigningKey,
        bounds: Bounds,
    ) -> Self {
        Self {
            environment: CollectionEnvironment::new(root, anchor),
            signer,
            bounds,
            settled: None,
        }
    }

    pub fn environment(&self) -> &CollectionEnvironment {
        &self.environment
    }

    /// The raw read-set of the last settled step, including missing blobs.
    /// `None` until a step settles, and after a bounded step.
    pub fn read_set(&self) -> Option<&StoreDependencies> {
        self.settled.as_ref().map(|(_, read)| read)
    }

    /// Settle any earlier batch, then step if the last read-set may have changed.
    pub fn poll<S>(&mut self, store: &mut S) -> Result<Step, DriverError>
    where
        S: SnapshotSource<Snapshot = T> + BlobStorePut + CollectionStore + StorageFlush,
        T: StoreRead,
        AdvanceError<
            <ObservedStore<T> as BlobStoreGet>::GetError<
                <View<str> as TryFromBlob<blobencodings::UTF8String>>::Error,
            >,
        >: StdError + Send + Sync + 'static,
    {
        let mut step = Step {
            outcome: Outcome::Unchanged,
            firings: 0,
            commits: Vec::new(),
        };
        self.publish(store, &mut step)?;
        let snapshot = store
            .snapshot()
            .map_err(|e| DriverError::Snapshot(Box::new(e)))?;
        if let Some((previous, read)) = &self.settled {
            if step.commits.is_empty() && snapshot.changes_for(previous, read).is_empty() {
                return Ok(step);
            }
        }
        self.settled = None;
        let observed = ObservedStore::new(snapshot.clone());
        step.outcome = match self.environment.observe(&observed) {
            Err(e @ ObserveError::ResetRequired(_)) => return Err(DriverError::Reset(e)),
            Err(e) => Outcome::Blocked(Box::new(e)),
            Ok(Resolution::Sole(_)) => self.advance(store, &observed, &mut step)?,
            Ok(other) => Outcome::Unresolved(other),
        };
        if !matches!(step.outcome, Outcome::Bounded(_)) {
            self.settled = Some((snapshot, observed.dependencies()));
        }
        Ok(step)
    }

    fn advance<S>(
        &mut self,
        store: &mut S,
        reader: &ObservedStore<T>,
        step: &mut Step,
    ) -> Result<Outcome, DriverError>
    where
        S: SnapshotSource<Snapshot = T> + BlobStorePut + CollectionStore + StorageFlush,
        T: StoreRead,
        AdvanceError<
            <ObservedStore<T> as BlobStoreGet>::GetError<
                <View<str> as TryFromBlob<blobencodings::UTF8String>>::Error,
            >,
        >: StdError + Send + Sync + 'static,
    {
        let deadline = Instant::now() + self.bounds.time;
        loop {
            if step.firings >= self.bounds.firings {
                return Ok(Outcome::Bounded(Bound::Firings));
            }
            if Instant::now() >= deadline {
                return Ok(Outcome::Bounded(Bound::Time));
            }
            let budget = self
                .bounds
                .chunk
                .max(1)
                .min(self.bounds.firings - step.firings);
            let computation = self.environment.advance(budget, reader);
            // Conclusions preceding an evaluation failure are published too.
            self.publish(store, step)?;
            match computation {
                Ok(advance) => {
                    step.firings += advance.firings.len();
                    if advance.progress == Progress::Quiescent {
                        return Ok(Outcome::Quiescent);
                    }
                }
                Err(e) => return Ok(Outcome::Blocked(Box::new(e))),
            }
        }
    }

    fn publish<S>(&mut self, store: &mut S, step: &mut Step) -> Result<(), DriverError>
    where
        S: SnapshotSource<Snapshot = T> + BlobStorePut + CollectionStore + StorageFlush,
        T: StoreRead,
    {
        if let Some(commit) = self
            .environment
            .publish(store, &self.signer)
            .map_err(DriverError::Publish)?
        {
            step.commits.push(commit);
        }
        Ok(())
    }
}
