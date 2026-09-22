//! Opt-in observations at existing maintenance boundaries, not another planner.
//!
//! Equation counters count successful local insert calls, including idempotent
//! insertions and multiple witness equations for one output. They do not count
//! unique bytes, physical appends, or mapping/kernel invocations. Failed passes
//! retain successful publications. No-publication passes may still do substantial
//! certification work. Long synchronous hops can outlive the sampling cadence;
//! their last observation must then become stale, not pretend to be a heartbeat.
//!
//! Appending here does not advance or filter the maintenance baseline. Exact
//! disjoint interests ignore these records; broad name/all-record interests can
//! wake after an emission. One rate limit covers every loop/hop boundary,
//! including failed publication attempts, so that feedback cannot emit per pass.

use super::*;
use triblespace_core::blob::{encodings::UnknownBlob, BlobEncoding};
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::CollectionStore;
use triblespace_core::inline::InlineEncoding;
use triblespace_core::prelude::{entity, genid, inlineencodings, ExclusiveId, TryToInline};
use triblespace_core::repo::{BlobStorePut, CapabilityProofStore};
use triblespace_net::{health_record, telemetry};

#[derive(Clone, Debug, Default, clap::Args)]
pub(crate) struct Options {
    /// Existing telemetry collection; the maintenance key identifies and signs this worker.
    /// Never creates a descriptor or grant.
    #[arg(long, requires = "telemetry_worker")]
    pub telemetry_collection: Option<String>,
    /// Stable worker label, at most 32 UTF-8 bytes
    #[arg(long, requires = "telemetry_collection")]
    pub telemetry_worker: Option<String>,
    /// Minimum seconds between telemetry attempts (default 60); final close adds one sample
    #[arg(long, requires = "telemetry_collection", value_parser = clap::value_parser!(u64).range(1..))]
    pub telemetry_interval_secs: Option<u64>,
}

pub(super) struct Config {
    collection: CollectionHandle,
    worker: String,
    interval: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Parameters,
    Snapshot,
    Descriptor,
    DerivedDestination,
    Authority,
    Publication,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Parameters => "invalid maintenance telemetry parameters",
            Self::Snapshot => "cannot observe maintenance telemetry store",
            Self::Descriptor => "maintenance telemetry descriptor unavailable or invalid",
            Self::DerivedDestination => {
                "maintenance telemetry destination must be a source collection"
            }
            Self::Authority => "maintenance telemetry writer authority unavailable or denied",
            Self::Publication => "cannot publish maintenance telemetry",
        })
    }
}

impl std::error::Error for Failure {}

impl Options {
    pub(super) fn config(self) -> std::result::Result<Option<Config>, Failure> {
        let Some(handle) = self.telemetry_collection else {
            return if self.telemetry_worker.is_none() && self.telemetry_interval_secs.is_none() {
                Ok(None)
            } else {
                Err(Failure::Parameters)
            };
        };
        let collection = parse_collection_handle(&handle).map_err(|_| Failure::Parameters)?;
        let worker = self.telemetry_worker.ok_or(Failure::Parameters)?;
        let _: Inline<inlineencodings::ShortString> = worker
            .as_str()
            .try_to_inline()
            .map_err(|_| Failure::Parameters)?;
        if worker.is_empty() || self.telemetry_interval_secs == Some(0) {
            return Err(Failure::Parameters);
        }
        Ok(Some(Config {
            collection,
            worker,
            interval: Duration::from_secs(self.telemetry_interval_secs.unwrap_or(60)),
        }))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Publications {
    pub merges: u128,
    pub derives: u128,
}

/// Only the mutating surface is wrapped; the exact underlying snapshot type,
/// errors, proof insertion, and acquisition future are preserved.
pub(super) struct CountedStore<'a, S> {
    pub inner: &'a mut S,
    pub counts: &'a mut Publications,
}

impl<S: SnapshotSource> SnapshotSource for CountedStore<'_, S> {
    type Snapshot = S::Snapshot;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> std::result::Result<Self::Snapshot, Self::SnapshotError> {
        self.inner.snapshot()
    }
}

impl<S: BlobStorePut> BlobStorePut for CountedStore<'_, S> {
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> std::result::Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.inner.put(item)
    }
}

impl<S: CollectionStore> CollectionStore for CountedStore<'_, S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> std::result::Result<(), Self::InsertError> {
        self.inner.insert(record)?;
        match record {
            CollectionRecord::Merge(_) => {
                self.counts.merges = self.counts.merges.saturating_add(1);
            }
            CollectionRecord::Derive(_) => {
                self.counts.derives = self.counts.derives.saturating_add(1);
            }
            CollectionRecord::Commit(_) => {}
        }
        Ok(())
    }
}

impl<S: CapabilityProofStore> CapabilityProofStore for CountedStore<'_, S> {
    type InsertError = S::InsertError;

    fn insert_proof(
        &mut self,
        proof: CapabilityProof,
    ) -> std::result::Result<(), Self::InsertError> {
        self.inner.insert_proof(proof)
    }
}

impl<S: AsyncBlobStoreAcquire> AsyncBlobStoreAcquire for CountedStore<'_, S> {
    type AcquireError = S::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<
        Output = std::result::Result<Option<anybytes::Bytes>, Self::AcquireError>,
    > + Send {
        self.inner.acquire(handle)
    }
}

#[derive(Default)]
struct Work {
    active: bool,
    completed: u128,
    failed: u128,
    wall_ns: u128,
}

impl Work {
    fn finish(&mut self, success: bool, elapsed: Duration) {
        self.active = false;
        self.wall_ns = self.wall_ns.saturating_add(elapsed.as_nanos());
        if success {
            self.completed = self.completed.saturating_add(1);
        } else {
            self.failed = self.failed.saturating_add(1);
        }
    }
}

pub(super) struct Telemetry {
    config: Config,
    collection: Collection<SimpleArchive>,
    signer: SigningKey,
    session: ExclusiveId,
    subjects: Fragment,
    process: Id,
    hop: Id,
    pass: Id,
    no_publication_pass: Id,
    started: Instant,
    last_attempt: Option<Instant>,
    running: bool,
    hops: Work,
    passes: Work,
    no_publication_passes: u128,
    pub publications: Publications,
}

impl Telemetry {
    pub(super) fn open<S: Store>(
        store: &mut S,
        config: Config,
        signer: &SigningKey,
    ) -> std::result::Result<Self, Failure> {
        let signer = signer.clone();
        let node = signer.verifying_key();
        let snapshot = store.snapshot().map_err(|_| Failure::Snapshot)?;
        let collection = Collection::<SimpleArchive>::open(&snapshot, config.collection)
            .map_err(|_| Failure::Descriptor)?;
        let facts: TribleSet = snapshot
            .get(config.collection)
            .map_err(|_| Failure::Descriptor)?;
        if descriptor::source(&facts)
            .map_err(|_| Failure::Descriptor)?
            .is_some()
        {
            // A derived SimpleArchive can admit this writer but its reader
            // does not consume root COMMITs. Reject before any sample append.
            return Err(Failure::DerivedDestination);
        }
        if !collection
            .writer_is_admitted(&snapshot, signer.verifying_key())
            .map_err(|_| Failure::Authority)?
        {
            return Err(Failure::Authority);
        }
        // Identity gives emission idempotence only: readers query these facts,
        // never recompute the IDs. A restart changes the session, not the worker.
        let process = entity! {
            health_record::attrs::endpoint: node,
            telemetry::attrs::worker: config.worker.as_str(),
            telemetry::attrs::role: "process",
        };
        let hop = entity! {
            health_record::attrs::endpoint: node,
            telemetry::attrs::worker: config.worker.as_str(),
            telemetry::attrs::role: "maintenance",
            telemetry::attrs::stage: "maintenance-hop",
        };
        let pass = entity! {
            health_record::attrs::endpoint: node,
            telemetry::attrs::worker: config.worker.as_str(),
            telemetry::attrs::role: "maintenance",
            telemetry::attrs::stage: "pass",
        };
        let no_publication_pass = entity! {
            health_record::attrs::endpoint: node,
            telemetry::attrs::worker: config.worker.as_str(),
            telemetry::attrs::role: "maintenance",
            telemetry::attrs::stage: "no-publication-pass",
        };
        let process_id = process.root().expect("one subject entity");
        let hop_id = hop.root().expect("one subject entity");
        let pass_id = pass.root().expect("one subject entity");
        let no_publication_pass_id = no_publication_pass.root().expect("one subject entity");
        let subjects = process + hop + pass + no_publication_pass;
        Ok(Self {
            config,
            collection,
            signer,
            session: genid(),
            subjects,
            process: process_id,
            hop: hop_id,
            pass: pass_id,
            no_publication_pass: no_publication_pass_id,
            started: Instant::now(),
            last_attempt: None,
            running: true,
            hops: Work::default(),
            passes: Work::default(),
            no_publication_passes: 0,
            publications: Publications::default(),
        })
    }

    pub(super) fn begin_pass(&mut self) -> (Instant, Publications) {
        self.passes.active = true;
        (Instant::now(), self.publications)
    }

    pub(super) fn finish_pass(&mut self, before: (Instant, Publications), success: bool) {
        self.passes.finish(success, before.0.elapsed());
        if success && before.1 == self.publications {
            self.no_publication_passes = self.no_publication_passes.saturating_add(1);
        }
    }

    pub(super) fn begin_hop(&mut self) -> Instant {
        self.hops.active = true;
        Instant::now()
    }

    pub(super) fn finish_hop(&mut self, started: Instant, success: bool) {
        self.hops.finish(success, started.elapsed());
    }

    pub(super) fn emit_due<S: Store>(&mut self, store: &mut S) {
        let now = Instant::now();
        if self
            .last_attempt
            .is_some_and(|last| now.duration_since(last) < self.config.interval)
        {
            return;
        }
        // Throttle failures too; observer errors must not create a hot retry loop.
        self.last_attempt = Some(now);
        if let Err(error) = self.publish(store) {
            eprintln!("maintenance telemetry: {error}");
        }
    }

    pub(super) fn finish<S: Store>(&mut self, store: &mut S) {
        self.running = false;
        self.hops.active = false;
        self.passes.active = false;
        if let Err(error) = self.publish(store) {
            eprintln!("maintenance telemetry: {error}");
        }
    }

    fn publish<S: Store>(&self, store: &mut S) -> std::result::Result<(), Failure> {
        let snapshot = store.snapshot().map_err(|_| Failure::Snapshot)?;
        if !self
            .collection
            .writer_is_admitted(&snapshot, self.signer.verifying_key())
            .map_err(|_| Failure::Authority)?
        {
            return Err(Failure::Authority);
        }
        drop(snapshot);
        let at = triblespace_core::clock::epoch_now();
        let created: Inline<inlineencodings::NsTAIInterval> = (at, at).try_to_inline().unwrap();
        let elapsed_ns = self.started.elapsed().as_nanos();
        let mut facts = self.subjects.clone();
        let sample = genid();
        facts += entity! { &sample @
            metadata::tag: &telemetry::KIND_SAMPLE,
            telemetry::attrs::subject: &self.process,
            health_record::attrs::session: &self.session,
            metadata::created_at: created,
            telemetry::attrs::elapsed_ns: elapsed_ns,
            telemetry::attrs::active: u128::from(self.running),
            telemetry::attrs::cpu_ns?: crate::cli::util::process_cpu_ns(),
        };
        for (subject, stage, work) in [
            (&self.hop, "maintenance-hop", &self.hops),
            (&self.pass, "pass", &self.passes),
        ] {
            let sample = genid();
            facts += entity! { &sample @
                metadata::tag: &telemetry::KIND_SAMPLE,
                telemetry::attrs::subject: subject,
                health_record::attrs::session: &self.session,
                metadata::created_at: created,
                telemetry::attrs::elapsed_ns: elapsed_ns,
                telemetry::attrs::active: u128::from(work.active),
                telemetry::attrs::completed: work.completed,
                telemetry::attrs::failed: work.failed,
                telemetry::attrs::work_ns: work.wall_ns,
            };
            if stage == "maintenance-hop" {
                facts += entity! { &sample @
                    telemetry::attrs::parallelism: 1_u128,
                    telemetry::attrs::parallel_compiled: triblespace_core::PARALLEL_COMPILED,
                    telemetry::attrs::completed_merges: self.publications.merges,
                    telemetry::attrs::completed_derives: self.publications.derives,
                };
            }
        }
        let sample = genid();
        facts += entity! { &sample @
            metadata::tag: &telemetry::KIND_SAMPLE,
            telemetry::attrs::subject: &self.no_publication_pass,
            health_record::attrs::session: &self.session,
            metadata::created_at: created,
            telemetry::attrs::elapsed_ns: elapsed_ns,
            telemetry::attrs::completed: self.no_publication_passes,
        };
        store
            .commit(self.collection, &self.signer, facts)
            .map_err(|_| Failure::Publication)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
