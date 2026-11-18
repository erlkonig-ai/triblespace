//! The sync producer: aggregate samples at a sync loop's existing boundaries.
//!
//! One [`Publisher`] per sync worker. The caller chooses the destination
//! collection, the signing key and the worker label, feeds each returned
//! reconcile tick to [`Publisher::reconciled`] and calls
//! [`Publisher::publish`] at its own cadence (custody uses
//! [`crate::health_record::REPORT_EVERY`]). No inventory, acquisition, new
//! subscription, timer or implicit flush lives here.
//!
//! Five subjects distinguish the measurements: `hydration`, `serve`,
//! `repair`, `publication` and `process`. Their meanings are in the book's
//! "Sync producer" section.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use triblespace_core::collection::{Collection, CollectionHandle, CollectionStoreExt, descriptor};
use triblespace_core::metadata;
use triblespace_core::prelude::*;
use triblespace_core::repo::{BlobStoreGet, Store};

use super::{KIND_SAMPLE, attrs, process_cpu_ns};
use crate::health::HealthSnapshot;
use crate::health_record as h;
use crate::reconcile::ReconcileStats;

/// Why a sync producer could not open or publish.
///
/// The variants carry no backend cause: an error may otherwise include a read
/// capability or a private path, and neither belongs in telemetry reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The worker label is empty or contains control characters.
    WorkerLabel,
    /// The store could not be observed.
    Observation,
    /// The destination is not a readable SimpleArchive collection.
    Unreadable,
    /// The destination's descriptor blob is unavailable.
    Descriptor,
    /// The destination's lineage could not be read.
    Lineage,
    /// The destination is derived; its reader ignores root COMMITs.
    Derived,
    /// Whether the signer may write could not be observed.
    Admission,
    /// The destination does not admit the signer.
    NotAdmitted,
    /// The sample timestamp could not be encoded.
    Timestamp,
    /// The signed append failed.
    Append,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WorkerLabel => "telemetry worker label must be nonempty printable text",
            Self::Observation => "telemetry destination observation failed",
            Self::Unreadable => "telemetry destination is not a readable source collection",
            Self::Descriptor => "telemetry destination descriptor is unavailable",
            Self::Lineage => "telemetry destination lineage is not readable",
            Self::Derived => "telemetry destination must be a source collection",
            Self::Admission => "telemetry writer admission could not be observed",
            Self::NotAdmitted => "telemetry reporting key is not admitted by the destination",
            Self::Timestamp => "telemetry sample timestamp cannot be encoded",
            Self::Append => "telemetry append failed",
        })
    }
}

impl std::error::Error for Error {}

/// Signed aggregate work samples of one sync worker, appended to one existing
/// source collection.
pub struct Publisher {
    collection: Collection<blobencodings::SimpleArchive>,
    signer: SigningKey,
    session: ExclusiveId,
    started: Instant,
    subjects: [Fragment; 5],
    landed: u128,
    received_bytes: u128,
    reconcile_work_ns: u128,
    pending_blobs: Option<u64>,
}

impl Publisher {
    /// Open a producer for `worker`, signing with `signer` into `destination`.
    ///
    /// Opening is a read: the destination must already be a resident
    /// SimpleArchive source collection that admits the signer. There is
    /// deliberately no collection(), derive(), grant or maintain fallback, so
    /// a failed open appends nothing. The signer's public key is the samples'
    /// endpoint; the worker label distinguishes processes on that endpoint.
    pub fn open<S: Store>(
        store: &mut S,
        signer: &SigningKey,
        destination: CollectionHandle,
        worker: &str,
    ) -> Result<Self, Error> {
        let node = signer.verifying_key();
        if worker.is_empty() || worker.chars().any(char::is_control) {
            return Err(Error::WorkerLabel);
        }
        let snapshot = store.snapshot().map_err(|_| Error::Observation)?;
        let collection = Collection::<blobencodings::SimpleArchive>::open(&snapshot, destination)
            .map_err(|_| Error::Unreadable)?;
        let facts: TribleSet = snapshot.get(destination).map_err(|_| Error::Descriptor)?;
        if descriptor::source(&facts)
            .map_err(|_| Error::Lineage)?
            .is_some()
        {
            return Err(Error::Derived);
        }
        if !collection
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .map_err(|_| Error::Admission)?
        {
            return Err(Error::NotAdmitted);
        }
        Ok(Self {
            collection,
            signer: signer.clone(),
            session: ufoid(),
            started: Instant::now(),
            subjects: ["hydration", "serve", "repair", "publication", "process"].map(|role| {
                entity! {
                    h::attrs::endpoint: node,
                    attrs::worker: worker,
                    attrs::role: role,
                }
            }),
            landed: 0,
            received_bytes: 0,
            reconcile_work_ns: 0,
            pending_blobs: None,
        })
    }

    /// Account one returned reconcile tick and its wall duration.
    pub fn reconciled(&mut self, stats: &ReconcileStats, elapsed: Duration) {
        self.landed += stats.landed as u128;
        self.received_bytes += u128::from(stats.received_bytes);
        self.reconcile_work_ns += elapsed.as_nanos();
        self.pending_blobs = stats.pending_blobs.map(|count| count as u64);
    }

    fn sample(
        &self,
        health: &HealthSnapshot,
        now: hifitime::Epoch,
        elapsed: Duration,
        cpu_ns: Option<u128>,
    ) -> Result<Fragment, Error> {
        let created: Inline<inlineencodings::NsTAIInterval> =
            (now, now).try_to_inline().map_err(|_| Error::Timestamp)?;
        let elapsed_ns = elapsed.as_nanos();
        let live = health.is_fresh(triblespace_core::clock::mono_now(), h::HOST_MAX_AGE);
        let serving = &health.blob_serving;
        let publication = &health.publication;
        let mut facts = entity! {
            metadata::tag: &KIND_SAMPLE,
            attrs::subject*: self.subjects[0].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            attrs::elapsed_ns: elapsed_ns,
            attrs::completed: self.landed,
            attrs::received_bytes: self.received_bytes,
            attrs::work_ns: self.reconcile_work_ns,
            attrs::queued?: self.pending_blobs,
        };
        // No hydration active/failed estimate: sampling does not run inside an
        // awaited tick, and an unavailable speculative word is not a known
        // failed blob. Capacity and attempts are not those measurements.
        facts += entity! {
            metadata::tag: &KIND_SAMPLE,
            attrs::subject*: self.subjects[1].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            attrs::elapsed_ns: elapsed_ns,
            attrs::active?: live.then_some(serving.in_flight),
            attrs::completed?: live.then_some(serving.completed),
            attrs::failed?: live.then_some(serving.failed),
            attrs::sent_bytes?: live.then_some(serving.sent_bytes),
            attrs::work_ns?: live.then_some(serving.work_ns),
        };
        facts += entity! {
            metadata::tag: &KIND_SAMPLE,
            attrs::subject*: self.subjects[2].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            attrs::elapsed_ns: elapsed_ns,
            // Host health records the ends of pushes and receives, not the
            // ones in flight, so the repair subject's active count stays
            // absent rather than estimated.
            attrs::active?: None::<u64>,
        };
        facts += entity! {
            metadata::tag: &KIND_SAMPLE,
            attrs::subject*: self.subjects[3].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            attrs::elapsed_ns: elapsed_ns,
            attrs::active?: live.then_some(publication.in_flight as u64),
            attrs::completed?: live.then_some(publication.acknowledged),
            attrs::failed?: live.then_some(publication.rejected.saturating_add(publication.unavailable)),
        };
        facts += entity! {
            metadata::tag: &KIND_SAMPLE,
            attrs::subject*: self.subjects[4].clone(),
            h::attrs::session: &self.session,
            metadata::created_at: created,
            attrs::elapsed_ns: elapsed_ns,
            attrs::cpu_ns?: cpu_ns,
            attrs::parallel_compiled: triblespace_core::PARALLEL_COMPILED,
        };
        Ok(facts)
    }

    /// Append one sample of every subject, observed now from `health`, this
    /// session's reconcile counters and the process CPU time.
    ///
    /// A failed observation never becomes an empty or healthy replacement
    /// sample; the caller leaves older samples to age. Nothing is flushed:
    /// the store owner's close remains its persistence boundary.
    pub fn publish<S: CollectionStoreExt>(
        &self,
        store: &mut S,
        health: &HealthSnapshot,
    ) -> Result<(), Error> {
        let facts = self.sample(
            health,
            triblespace_core::clock::epoch_now(),
            self.started.elapsed(),
            process_cpu_ns(),
        )?;
        // Discard backend cause chains at this reporting boundary. An error
        // may include a read capability or a private path, never telemetry.
        store
            .commit(self.collection, &self.signer, facts)
            .map_err(|_| Error::Append)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
