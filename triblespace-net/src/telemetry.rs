//! Colony work observations, carried by ordinary explicitly selected collections.
//!
//! This is not the facade's high-volume tracing-span sink. Producers append
//! periodic aggregate facts at their existing work boundaries. Readers never
//! enumerate blobs, infer work from record census, or start networking here.
//! A collection's policy and replication selection belong to its operator;
//! neither is created or broadened by this module.
//!
//! A subject describes one worker scope: endpoint, worker name and role, plus
//! optional target/peer. A sample refers to that opaque subject and includes
//! process session, wall observation time and elapsed monotonic nanoseconds.
//! Counters accumulate within that session. Missing fields mean unobserved,
//! not zero. Do not emit a zero-filled sample after a failed observation.
//! Backlogs describe only the producer's observed selection, not unknown
//! descendants or every node in a globally enumerable colony.
//!
//! Producers use `entity!` directly; there is no catalogue or parallel writer
//! state machine. All IDs below were minted with `trible genid` on 2026-09-16.

use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use triblespace_core::attribute::Attribute;
use triblespace_core::macros::{attributes, find, id_hex, pattern};
use triblespace_core::metadata;
use triblespace_core::prelude::*;

use crate::dashboard::{CountMetric, Freshness};
use crate::health_record;

pub const KIND_SAMPLE: Id = id_hex!("61F510C330767E791E733239D432D861");

pub mod attrs {
    use super::*;
    attributes! {
        /// Sample -> worker scope. An opaque reference, not an ID to recompute.
        "2CC00BB2F43008D102DEB6A928C10A68" as subject: inlineencodings::GenId;
        /// Operator's stable process/worker label within this endpoint.
        "5E3F4C5973047A386688FCFB5C29B03E" as worker: inlineencodings::ShortString;
        /// E.g. custody, maintenance, link or process. Unknown roles coexist.
        "6E88D61051CCB56FC7AECEF335CEEDB2" as role: inlineencodings::ShortString;
        "FE8D1A886EC649FE79F2D98AE106C00D" as elapsed_ns: inlineencodings::U256BE;
        /// Actual executing backend, not one merely compiled into the binary.
        "258054295893A9C2B9677EA6611EB4B3" as backend: inlineencodings::ShortString;
        /// Subject stage, e.g. selection, certification, mapping or joining.
        /// Separate stage subjects avoid attributing a whole pass to a kernel.
        "EFF8F4225EE43DDCE38F01433166EC50" as stage: inlineencodings::ShortString;
        /// Sum of completed operation wall durations for this scope/session,
        /// not process CPU time. Parallel operation durations may overlap.
        "8F269C3A72BA2A2BD3AF72C9033CED7A" as work_ns: inlineencodings::U256BE;
        /// Observed connection path (e.g. direct/relay); not routing candidates.
        "3610AA8DE6C85D0816DB04E08B82E823" as path: inlineencodings::ShortString;
        /// Known queued work in this subject's scope; never an inventory guess.
        "6414ACDA4FF1CF3605A98A96E06E7207" as queued: inlineencodings::U256BE;
        /// Actual current in-flight work, not configured concurrency.
        "8B18ADBA1444BCEF24E27555D85B3F55" as active: inlineencodings::U256BE;
        /// Successfully completed work in this session (not unique coverage).
        "F52FEFE0107D7ECB2DDEA021055BB3D8" as completed: inlineencodings::U256BE;
        "FD6360476613A6DBFE0BFEE34022DBFC" as failed: inlineencodings::U256BE;
        /// Verified payload bytes successfully received, not transport overhead.
        "26AABE7C5DA7C5D0E6D74C96E07B85B6" as received_bytes: inlineencodings::U256BE;
        /// Payload bytes successfully sent, not transport overhead.
        "5C18405833350BC64CA92D6BAA671F1F" as sent_bytes: inlineencodings::U256BE;
        /// Process CPU time across threads. Report once in a process scope,
        /// never duplicate it across every target/job and then sum it.
        "97C66376361F300BD55BB8954109D5AC" as cpu_ns: inlineencodings::U256BE;
        /// Configured worker parallelism; explicitly NOT measured CPU effort.
        "D5DBEABB081EEE77C564A9FC6CDF7363" as parallelism: inlineencodings::U256BE;
        /// Whether this binary contains the relevant parallel execution path.
        /// Neither pool size nor lazily-created thread count establishes this.
        "6DFCFD2ACDE2A3CF3821BABEA102C8B7" as parallel_compiled: inlineencodings::Boolean;
        /// Compiled-in backend capabilities, not runtime choice or GPU usage.
        "C23227AD4E963B210884B38B298514E1" as compiled_backend: inlineencodings::ShortString;
        /// Measured transport RTT, not an estimate from application completion.
        "CF8B3D8834B521AF09A16ABAD48305DD" as rtt_ns: inlineencodings::U256BE;
        "DF90FF3ACACCA2A75BEF4CF95E54A58A" as pending_merges: inlineencodings::U256BE;
        "A5C1E6D84624930A582EFCD992502351" as pending_derives: inlineencodings::U256BE;
        "30E10F0077BF9463BC25887C04D37925" as completed_merges: inlineencodings::U256BE;
        "5182408A8FCAC247E5AEE4EEF1937556" as completed_derives: inlineencodings::U256BE;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Metric {
    Queued,
    Active,
    Completed,
    Failed,
    ReceivedBytes,
    SentBytes,
    CpuNs,
    WorkNs,
    Parallelism,
    RttNs,
    PendingMerges,
    PendingDerives,
    CompletedMerges,
    CompletedDerives,
}

impl Metric {
    pub const ALL: [Self; 14] = [
        Self::Queued,
        Self::Active,
        Self::Completed,
        Self::Failed,
        Self::ReceivedBytes,
        Self::SentBytes,
        Self::CpuNs,
        Self::WorkNs,
        Self::Parallelism,
        Self::RttNs,
        Self::PendingMerges,
        Self::PendingDerives,
        Self::CompletedMerges,
        Self::CompletedDerives,
    ];

    pub fn attribute(self) -> &'static Attribute<inlineencodings::U256BE> {
        match self {
            Self::Queued => &attrs::queued,
            Self::Active => &attrs::active,
            Self::Completed => &attrs::completed,
            Self::Failed => &attrs::failed,
            Self::ReceivedBytes => &attrs::received_bytes,
            Self::SentBytes => &attrs::sent_bytes,
            Self::CpuNs => &attrs::cpu_ns,
            Self::WorkNs => &attrs::work_ns,
            Self::Parallelism => &attrs::parallelism,
            Self::RttNs => &attrs::rtt_ns,
            Self::PendingMerges => &attrs::pending_merges,
            Self::PendingDerives => &attrs::pending_derives,
            Self::CompletedMerges => &attrs::completed_merges,
            Self::CompletedDerives => &attrs::completed_derives,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued work",
            Self::Active => "active work",
            Self::Completed => "completed work",
            Self::Failed => "failed work",
            Self::ReceivedBytes => "verified payload received",
            Self::SentBytes => "payload sent",
            Self::CpuNs => "process CPU",
            Self::WorkNs => "completed operation wall time",
            Self::Parallelism => "configured parallelism",
            Self::RttNs => "link RTT",
            Self::PendingMerges => "pending merges",
            Self::PendingDerives => "pending derives",
            Self::CompletedMerges => "completed merges",
            Self::CompletedDerives => "completed derives",
        }
    }

    pub const fn is_counter(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::ReceivedBytes
                | Self::SentBytes
                | Self::CpuNs
                | Self::WorkNs
                | Self::CompletedMerges
                | Self::CompletedDerives
        )
    }
}

/// A display projection of one metric, not a mutable database of worker state.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricValue {
    pub metric: Metric,
    pub value: CountMetric,
    /// Units per second from two fresh, same-session observations. For CPU
    /// nanoseconds divide by 1e9 to display effective cores. No value means
    /// unmeasured/incomparable; it must not be printed as a zero rate.
    pub per_second: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WorkerReport {
    pub subject: Id,
    pub node: [u8; 32],
    pub worker: String,
    pub role: String,
    pub report: Id,
    pub session: Id,
    pub created_ns: i128,
    /// Prior observation used for rate derivation; renderers may continue to
    /// age a retained frame without promoting an old interval to current work.
    pub previous_created_ns: Option<i128>,
    pub age_seconds: Option<u64>,
    pub freshness: Freshness,
    pub backends: Vec<String>,
    pub parallel_compiled: Vec<bool>,
    pub compiled_backends: Vec<String>,
    pub stages: Vec<String>,
    pub paths: Vec<String>,
    pub peers: Vec<[u8; 32]>,
    pub targets: Vec<[u8; 32]>,
    pub metrics: Vec<MetricValue>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Observation {
    created_ns: i128,
    report: Id,
    session: Id,
    elapsed_ns: u128,
}

/// Query the latest two observations per scope directly from admitted facts.
/// Only two header witnesses per subject are retained; payload inventories and
/// historical rows are never materialized into a secondary catalogue.
/// Equal-time ties are a deterministic presentation choice, not causal order.
/// Unfamiliar/undecodable facts simply do not match the typed query.
pub fn observe(facts: &TribleSet, now_ns: i128, max_age: Duration) -> Vec<WorkerReport> {
    let mut latest = BTreeMap::<Id, Vec<Observation>>::new();
    for (report, subject, created, session, elapsed_ns) in find!(
        (report: Id, subject: Id, created: (i128, i128), session: Id, elapsed_ns: u128),
        pattern!(facts, [{
            ?report @ metadata::tag: &KIND_SAMPLE,
            attrs::subject: ?subject,
            metadata::created_at: ?created,
            health_record::attrs::session: ?session,
            attrs::elapsed_ns: ?elapsed_ns,
        }])
    ) {
        let samples = latest.entry(subject).or_default();
        samples.push(Observation {
            created_ns: created.1,
            report,
            session,
            elapsed_ns,
        });
        samples.sort_unstable_by(|a, b| b.cmp(a));
        samples.dedup();
        samples.truncate(2);
    }

    let max_age_ns = i128::try_from(max_age.as_nanos()).unwrap_or(i128::MAX);
    let mut reports = Vec::new();
    for (subject, observations) in latest {
        let current = observations[0];
        let age = now_ns.checked_sub(current.created_ns);
        let freshness = if current.created_ns > now_ns {
            Freshness::Future
        } else if age.is_some_and(|age| age < max_age_ns) {
            Freshness::Fresh
        } else {
            Freshness::Stale
        };
        let previous = observations.get(1).filter(|previous| {
            freshness == Freshness::Fresh
                && previous.report != current.report
                && previous.session == current.session
                && previous.created_ns <= current.created_ns
                && now_ns.saturating_sub(previous.created_ns) < max_age_ns
                && previous.elapsed_ns < current.elapsed_ns
        });
        let mut metrics = Vec::new();
        for metric in Metric::ALL {
            let attribute = metric.attribute();
            let report = current.report;
            let mut values: Vec<u128> = find!(value: u128,
                pattern!(facts, [{ report @ attribute: ?value }]))
            .collect();
            values.sort_unstable();
            values.dedup();
            let value = match values.as_slice() {
                [] => CountMetric::Absent,
                [value] => CountMetric::Value(*value),
                _ => CountMetric::Ambiguous(values),
            };
            let per_second = previous.and_then(|previous| {
                if !metric.is_counter() {
                    return None;
                }
                let report = previous.report;
                let mut before: Vec<u128> = find!(value: u128,
                    pattern!(facts, [{ report @ attribute: ?value }]))
                .collect();
                before.sort_unstable();
                before.dedup();
                let [before] = before.as_slice() else {
                    return None;
                };
                let delta = value.value()?.checked_sub(*before)?;
                Some(delta as f64 * 1e9 / (current.elapsed_ns - previous.elapsed_ns) as f64)
            });
            metrics.push(MetricValue {
                metric,
                value,
                per_second,
            });
        }
        let report = current.report;
        let mut backends: Vec<String> = find!(backend: String,
            pattern!(facts, [{ report @ attrs::backend: ?backend }]))
        .collect();
        let mut parallel_compiled: Vec<bool> = find!(available: bool,
            pattern!(facts, [{ report @ attrs::parallel_compiled: ?available }]))
        .collect();
        let mut compiled_backends: Vec<String> = find!(backend: String,
            pattern!(facts, [{ report @ attrs::compiled_backend: ?backend }]))
        .collect();
        let mut paths: Vec<String> = find!(path: String,
            pattern!(facts, [{ report @ attrs::path: ?path }]))
        .collect();
        let mut stages: Vec<String> = find!(stage: String,
            pattern!(facts, [{ subject @ attrs::stage: ?stage }]))
        .collect();
        let mut peers: Vec<[u8; 32]> = find!(peer: VerifyingKey,
            pattern!(facts, [{ subject @ health_record::attrs::peer: ?peer }]))
        .map(|peer| peer.to_bytes())
        .collect();
        let mut targets: Vec<[u8; 32]> =
            find!(target: triblespace_core::collection::CollectionHandle,
            pattern!(facts, [{ subject @ health_record::attrs::collection: ?target }]))
            .map(|target| target.raw)
            .collect();
        backends.sort_unstable();
        backends.dedup();
        parallel_compiled.sort_unstable();
        parallel_compiled.dedup();
        compiled_backends.sort_unstable();
        compiled_backends.dedup();
        paths.sort_unstable();
        paths.dedup();
        stages.sort_unstable();
        stages.dedup();
        peers.sort_unstable();
        peers.dedup();
        targets.sort_unstable();
        targets.dedup();
        // Reduce whole subject witnesses, never independent field bags. Extra
        // annotations and repeated labels do not invalidate admitted evidence.
        let mut subjects: Vec<_> = find!(
            (node: VerifyingKey, worker: String, role: String),
            pattern!(facts, [{ subject @
                health_record::attrs::endpoint: ?node,
                attrs::worker: ?worker,
                attrs::role: ?role,
            }])
        )
        .map(|(node, worker, role)| (node.to_bytes(), worker, role))
        .collect();
        subjects.sort_unstable();
        subjects.dedup();
        for (node, worker, role) in subjects {
            reports.push(WorkerReport {
                subject,
                node,
                worker,
                role,
                report,
                session: current.session,
                created_ns: current.created_ns,
                previous_created_ns: previous.map(|sample| sample.created_ns),
                age_seconds: age
                    .filter(|age| *age >= 0)
                    .and_then(|age| u64::try_from(age / 1_000_000_000).ok()),
                freshness,
                backends: backends.clone(),
                parallel_compiled: parallel_compiled.clone(),
                compiled_backends: compiled_backends.clone(),
                stages: stages.clone(),
                paths: paths.clone(),
                peers: peers.clone(),
                targets: targets.clone(),
                metrics: metrics.clone(),
            });
        }
    }
    reports.sort_by(|a, b| {
        (&a.node, &a.role, &a.worker, a.subject).cmp(&(&b.node, &b.role, &b.worker, b.subject))
    });
    reports
}

#[cfg(test)]
mod tests;
