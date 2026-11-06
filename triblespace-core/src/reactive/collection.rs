//! A synchronous collection boundary for the additive rule environment.
//!
//! Observations, immutable programs, readings and consequences share one root
//! fact collection. A reading explicitly names its selected revisions. Retirement
//! stops future applications; published consequences remain ordinary inputs.
//! This is not a daemon, a retracting view, or an exactly-once effect processor.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::collection::{
    Collection, CollectionCommit, CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
    CoverAdvanceError, Support,
};
use crate::metadata;
use crate::prelude::*;
use crate::query::register::{sole, ObservationOrder, Resolution};
use crate::repo::{BlobStorePut, SnapshotSource, StorageFlush, StoreRead};

use super::{Advance, Environment, ReadAdvanceError};

/// Immutable execution readings. Anchors minted with `trible genid` on 2026-11-06.
pub mod schema {
    use crate::prelude::*;
    attributes! {
        /// The environment whose execution reading this entity states.
        "AFE6B6ADD9F84B84AB755EADF5B629E6" as pub reading_of: inlineencodings::GenId;
        /// An exact rule revision selected by this reading; repeated means composition.
        "FA71748D012660724553D6D0AD5E3A60" as pub selects: inlineencodings::GenId;
    }
}

type Cause = Box<dyn StdError + Send + Sync>;

/// Failure to adopt one complete immutable observation. Held facts are retained.
#[derive(Debug)]
pub enum ObserveError {
    PublicationPending,
    Collection(Cause),
    View(Cause),
    ResetRequired(CoverAdvanceError),
}

/// Publication stages stay distinct, including uncertain commit/flush failures.
#[derive(Debug)]
pub enum PublishError {
    Snapshot(Cause),
    Admission(Cause),
    Unadmitted,
    /// A retry must use the signer with which this exact batch was first attempted.
    DifferentSigner,
    Commit(Cause),
    Flush(Cause),
}

macro_rules! storage_error {
    ($ty:ident, $($variant:ident),+) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl StdError for $ty {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                match self {
                    $(Self::$variant(source) => Some(source.as_ref()),)+
                    _ => None,
                }
            }
        }
    };
}
storage_error!(PublishError, Snapshot, Admission, Commit, Flush);

impl fmt::Display for ObserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl StdError for ObserveError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Collection(source) | Self::View(source) => Some(source.as_ref()),
            Self::ResetRequired(source) => Some(source),
            Self::PublicationPending => None,
        }
    }
}

/// The caller must observe an explicit Sole reading and settle each output batch.
#[derive(Debug)]
pub enum AdvanceError<E> {
    PublicationPending,
    ObservationRequired,
    UnresolvedReading(Resolution),
    Evaluation(ReadAdvanceError<E>),
}

impl<E: fmt::Display> fmt::Display for AdvanceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicationPending => f.write_str("publish the pending batch before advancing"),
            Self::ObservationRequired => f.write_str("a complete observation is required"),
            Self::UnresolvedReading(reading) => {
                write!(f, "unresolved execution reading: {reading:?}")
            }
            Self::Evaluation(source) => source.fmt(f),
        }
    }
}

impl<E: StdError + 'static> StdError for AdvanceError<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Evaluation(source) => Some(source),
            _ => None,
        }
    }
}

/// Disposable continuation state over one durable root fact collection.
///
/// On restart construct a new adapter and observe the current complete frame.
/// Published consequences seed recomputation; firing memos and support cursors
/// are not receipts. Uncommitted work under an earlier reading is not replayed
/// after that reading has changed. No checkpoint certifies an extinct frame.
pub struct CollectionEnvironment {
    root: Collection<blobencodings::SimpleArchive>,
    anchor: Id,
    environment: Environment,
    support: Option<Support>,
    reading: Option<Resolution>,
    selected: BTreeSet<Id>,
    pending: Fragment,
    signer: Option<VerifyingKey>,
}

impl CollectionEnvironment {
    pub fn new(root: Collection<blobencodings::SimpleArchive>, anchor: Id) -> Self {
        Self {
            root,
            anchor,
            environment: Environment::new(),
            support: None,
            reading: None,
            selected: BTreeSet::new(),
            pending: Fragment::empty(),
            signer: None,
        }
    }

    pub fn facts(&self) -> &TribleSet {
        self.environment.facts()
    }

    pub fn unpublished(&self) -> &Fragment {
        &self.pending
    }

    pub fn support(&self) -> Option<&Support> {
        self.support.as_ref()
    }

    pub fn reading(&self) -> Option<&Resolution> {
        self.reading.as_ref()
    }

    pub fn selected(&self) -> &BTreeSet<Id> {
        &self.selected
    }

    /// Adopt a complete view and resolve its reading with the existing DAG order.
    /// No unpublished fact chooses control state. Empty and Fork disable advance;
    /// Sole with no `selects` facts explicitly retires execution.
    ///
    /// Known but unavailable foundation bytes fail the view. Physical cover
    /// replacement is harmless; shrinking logical support requires deliberate
    /// reopening, without erasing any facts held by this adapter.
    pub fn observe<R: StoreRead>(&mut self, snapshot: &R) -> Result<Resolution, ObserveError> {
        if !self.pending.is_empty() {
            return Err(ObserveError::PublicationPending);
        }
        self.reading = None;
        self.selected.clear();
        let observed = snapshot
            .collection_acquiring(self.root)
            .map_err(|e| ObserveError::Collection(Box::new(e)))?;
        let support = observed
            .support()
            .map_err(|e| ObserveError::Collection(Box::new(e)))?;
        if let Some(previous) = &self.support {
            support
                .additions_since(previous)
                .map_err(ObserveError::ResetRequired)?;
        }
        let facts: TribleSet = observed
            .view()
            .map_err(|e| ObserveError::View(Box::new(e)))?;
        let candidates = find!(reading: Id, pattern!(&facts, [
            { ?reading @ schema::reading_of: self.anchor }
        ]));
        let reading = sole(
            &ObservationOrder::new(&facts, metadata::supersedes.id()),
            candidates,
        );
        if let Resolution::Sole(id) = &reading {
            self.selected = find!(revision: Id, pattern!(&facts, [
                { *id @ schema::selects: ?revision }
            ]))
            .collect();
        }
        self.environment.extend(&facts);
        self.environment.select(self.selected.iter().copied());
        self.support = Some(support.clone());
        self.reading = Some(reading.clone());
        Ok(reading)
    }

    /// Advance pure rules with an explicit content reader. Even on error, earlier
    /// successful new facts enter `unpublished`; call `publish` after either
    /// outcome. The budget bounds firings only, not search time or termination.
    pub fn advance<R: BlobStoreGet>(
        &mut self,
        budget: usize,
        reader: &R,
    ) -> Result<
        Advance,
        AdvanceError<R::GetError<<View<str> as TryFromBlob<blobencodings::UTF8String>>::Error>>,
    > {
        if !self.pending.is_empty() {
            return Err(AdvanceError::PublicationPending);
        }
        match &self.reading {
            None => return Err(AdvanceError::ObservationRequired),
            Some(Resolution::Sole(_)) => {}
            Some(other) => return Err(AdvanceError::UnresolvedReading(other.clone())),
        }
        let before = self.environment.facts().clone();
        let result = self.environment.advance_with_reader(budget, reader);
        self.pending = self.environment.facts().difference(&before).into();
        result.map_err(AdvanceError::Evaluation)
    }

    /// Admit the writer, insert the exact batch, and explicitly flush. Keep the
    /// same fragment and signer after either commit or flush failure. Visibility
    /// in a later snapshot is not evidence that an uncertain flush succeeded.
    pub fn publish<S>(
        &mut self,
        store: &mut S,
        signer: &SigningKey,
    ) -> Result<Option<CollectionCommit>, PublishError>
    where
        S: SnapshotSource + BlobStorePut + CollectionStore + StorageFlush,
        S::Snapshot: StoreRead,
    {
        if self.pending.is_empty() {
            return Ok(None);
        }
        let subject = signer.verifying_key();
        if self.signer.is_some_and(|previous| previous != subject) {
            return Err(PublishError::DifferentSigner);
        }
        let snapshot = store
            .snapshot()
            .map_err(|e| PublishError::Snapshot(Box::new(e)))?;
        if !self
            .root
            .writer_is_admitted(&snapshot, subject)
            .map_err(|e| PublishError::Admission(Box::new(e)))?
        {
            return Err(PublishError::Unadmitted);
        }
        self.signer = Some(subject);
        let commit = store
            .commit(self.root, signer, self.pending.clone())
            .map_err(|e| PublishError::Commit(Box::new(e)))?;
        store
            .flush()
            .map_err(|e| PublishError::Flush(Box::new(e)))?;
        self.pending = Fragment::empty();
        self.signer = None;
        Ok(Some(commit))
    }
}
