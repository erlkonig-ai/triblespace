//! Read-only cluster-dashboard projections over one immutable store snapshot.
//!
//! The report deliberately keeps four kinds of evidence separate:
//! local blob residency, stored native collection equations, durable requested
//! work, and replicated observer reports. A stored equation is not proof that
//! its output blob is resident, and an absent request is never invented from a
//! missing blob. Renderers may share this value without maintaining another
//! database beside the pile.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use triblespace_core::attribute::Attribute;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::{CollectionHandle, CollectionRecord, CollectionRecordSelector};
use triblespace_core::exists;
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::iu256::U256BE;
use triblespace_core::macros::{find, pattern};
use triblespace_core::metadata;
use triblespace_core::prelude::Id;
use triblespace_core::repo::{StoreRead, WantRequest};
use triblespace_core::trible::TribleSet;

use crate::health_record::{self, Component, State};

/// Default bound for exact-handle samples shown by terminal and GUI views.
pub const DEFAULT_SAMPLE_LIMIT: usize = 20;

/// One locally resident immutable blob.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlobSample {
    pub handle: [u8; 32],
    pub bytes: u64,
}

/// Kind of native collection evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeKind {
    Commit,
    Merge,
    Derive,
}

impl NativeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Merge => "merge",
            Self::Derive => "derive",
        }
    }
}

/// Residency accounting for one kind of stored native record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeSummary {
    /// Signed records present in this immutable snapshot.
    pub stored: u64,
    /// Records for which every direct blob reference is resident.
    pub all_references_resident: u64,
    /// Records whose member/result blob is resident.
    pub result_resident: u64,
    /// Missing direct references counted per record occurrence.
    pub missing_reference_occurrences: u64,
}

/// One bounded example of a stored record's missing direct reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MissingReference {
    pub collection: [u8; 32],
    pub kind: NativeKind,
    pub handle: [u8; 32],
}

/// Stored native evidence grouped by its collection descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionEvidence {
    pub collection: [u8; 32],
    pub commits: NativeSummary,
    pub merges: NativeSummary,
    pub derives: NativeSummary,
}

/// Kind of durable request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WantKind {
    Blob,
    Merge,
    Derive,
}

impl WantKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Merge => "merge",
            Self::Derive => "derive",
        }
    }
}

/// Durable request counts, with answered requests separated from pending work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WantSummary {
    pub total: u64,
    pub answered: u64,
    pub pending: u64,
}

/// One bounded exact request that has no answer in this snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PendingWant {
    pub kind: WantKind,
    pub request: WantRequest,
}

/// Complete read-only local projection used by every dashboard renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalReport {
    pub resident_blobs: u64,
    pub resident_bytes: u128,
    pub blob_sample: Vec<BlobSample>,
    pub blob_sample_truncated: bool,
    pub stored_records: u64,
    pub commits: NativeSummary,
    pub merges: NativeSummary,
    pub derives: NativeSummary,
    pub collections: Vec<CollectionEvidence>,
    pub missing_reference_sample: Vec<MissingReference>,
    pub missing_reference_sample_truncated: bool,
    pub wants: WantSummary,
    pub blob_wants: WantSummary,
    pub merge_wants: WantSummary,
    pub derive_wants: WantSummary,
    pub pending_want_sample: Vec<PendingWant>,
    pub pending_want_sample_truncated: bool,
}

/// A repeated numeric fact remains visible instead of being collapsed through
/// an arbitrary exactly-one rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CountMetric {
    Absent,
    Value(u128),
    Ambiguous(Vec<u128>),
}

impl CountMetric {
    pub fn value(&self) -> Option<u128> {
        match self {
            Self::Value(value) => Some(*value),
            Self::Absent | Self::Ambiguous(_) => None,
        }
    }
}

/// Quantitative evidence carried by one replicated condition episode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedEvidence {
    pub resident_blobs: CountMetric,
    pub local_records: CountMetric,
    pub local_authorizations: CountMetric,
    pub remote_records: CountMetric,
    pub remote_authorizations: CountMetric,
    pub publication_keys: CountMetric,
    pub publication_startup_pending: CountMetric,
    pub publication_incremental_pending: CountMetric,
    pub publication_retry_pending: CountMetric,
    pub publication_renewal_remaining: CountMetric,
    pub publication_in_flight: CountMetric,
    pub publication_attempts: CountMetric,
    pub publication_acknowledged: CountMetric,
    pub publication_rejected: CountMetric,
    pub publication_unavailable: CountMetric,
}

/// One condition from a selected observer report. Plural fields preserve the
/// open-world result if a union contains competing annotations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCondition {
    pub id: Id,
    pub components: Vec<Component>,
    pub states: Vec<State>,
    pub collections: Vec<[u8; 32]>,
    pub peers: Vec<[u8; 32]>,
    pub alert: bool,
    pub recovered: bool,
    pub evidence: ObservedEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    Fresh,
    Stale,
    Future,
}

/// Latest report selected for one observer node by `(created_at, report id)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverReport {
    pub node: Id,
    pub report: Id,
    pub sessions: Vec<Id>,
    pub endpoints: Vec<[u8; 32]>,
    pub created_ns: i128,
    pub age_seconds: Option<u64>,
    pub freshness: Freshness,
    pub conditions: Vec<ObservedCondition>,
}

/// One frozen value shared by terminal and graphical renderers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardReport {
    pub local: LocalReport,
    pub observers: Vec<ObserverReport>,
}

#[derive(Default)]
struct MutableCollectionEvidence {
    commits: NativeSummary,
    merges: NativeSummary,
    derives: NativeSummary,
}

/// Inspect one immutable store observation without fetching, maintaining, or
/// writing anything. Samples are the lexicographically smallest exact keys,
/// so repeated views of the same snapshot are stable.
pub fn inspect_local<R>(snapshot: &R, sample_limit: usize) -> Result<LocalReport>
where
    R: StoreRead,
{
    let mut blob_sample = BTreeSet::new();
    let mut resident_blobs = 0_u64;
    let mut resident_bytes = 0_u128;
    for info in snapshot.blobs() {
        let info = info
            .map_err(anyhow::Error::new)
            .context("enumerate resident blobs")?;
        resident_blobs = resident_blobs.saturating_add(1);
        resident_bytes = resident_bytes.saturating_add(u128::from(info.length));
        retain_smallest(
            &mut blob_sample,
            BlobSample {
                handle: info.handle.raw,
                bytes: info.length,
            },
            sample_limit,
        );
    }
    let blob_sample_truncated =
        resident_blobs > u64::try_from(blob_sample.len()).unwrap_or(u64::MAX);

    // Construct only the semantic query named by the durable operation
    // requests. This avoids retaining a second inventory of every equation.
    let mut operation_selectors = BTreeSet::new();
    for request in snapshot
        .wants()
        .map_err(anyhow::Error::new)
        .context("enumerate durable wants for operation lookup")?
    {
        let request = request
            .map_err(anyhow::Error::new)
            .context("read durable want for operation lookup")?;
        if matches!(
            request,
            WantRequest::Merge { .. } | WantRequest::Derive { .. }
        ) {
            operation_selectors.insert(CollectionRecordSelector::Operation(request));
        }
    }
    let answered_operations: BTreeSet<WantRequest> = snapshot
        .select_records(&operation_selectors)
        .map_err(anyhow::Error::new)
        .context("select records answering durable operation wants")?
        .into_iter()
        .filter_map(record_answer)
        .collect();

    let mut commits = NativeSummary::default();
    let mut merges = NativeSummary::default();
    let mut derives = NativeSummary::default();
    let mut collections = BTreeMap::<[u8; 32], MutableCollectionEvidence>::new();
    let mut missing_references = BTreeSet::new();
    let mut missing_reference_count = 0_u64;
    let mut stored_records = 0_u64;

    for record in snapshot
        .records()
        .map_err(anyhow::Error::new)
        .context("enumerate native collection records")?
    {
        let record = record
            .map_err(anyhow::Error::new)
            .context("read native collection record")?;
        stored_records = stored_records.saturating_add(1);
        let collection = record.collection().raw;
        let (kind, result) = match record {
            CollectionRecord::Commit(commit) => (NativeKind::Commit, commit.data().raw),
            CollectionRecord::Merge(merge) => (NativeKind::Merge, merge.result().raw),
            CollectionRecord::Derive(derive) => (NativeKind::Derive, derive.output().raw),
        };
        let mut missing = Vec::new();
        for handle in record.blob_references() {
            if !contains_blob(
                snapshot,
                handle,
                "inspect native record reference residency",
            )? {
                missing.push(handle.raw);
            }
        }
        let result_resident = contains_blob(
            snapshot,
            Inline::<Handle<UnknownBlob>>::new(result),
            "inspect native record result residency",
        )?;

        update_native_summary(
            summary_mut(kind, &mut commits, &mut merges, &mut derives),
            &missing,
            result_resident,
        );
        let collection_summary = collections.entry(collection).or_default();
        update_native_summary(
            summary_mut(
                kind,
                &mut collection_summary.commits,
                &mut collection_summary.merges,
                &mut collection_summary.derives,
            ),
            &missing,
            result_resident,
        );
        for handle in missing {
            missing_reference_count = missing_reference_count.saturating_add(1);
            retain_smallest(
                &mut missing_references,
                MissingReference {
                    collection,
                    kind,
                    handle,
                },
                sample_limit,
            );
        }
    }
    let missing_reference_sample_truncated =
        missing_reference_count > u64::try_from(missing_references.len()).unwrap_or(u64::MAX);

    let mut wants = WantSummary::default();
    let mut blob_wants = WantSummary::default();
    let mut merge_wants = WantSummary::default();
    let mut derive_wants = WantSummary::default();
    let mut pending_wants = BTreeSet::new();
    for request in snapshot
        .wants()
        .map_err(anyhow::Error::new)
        .context("enumerate durable wants")?
    {
        let request = request
            .map_err(anyhow::Error::new)
            .context("read durable want")?;
        let (kind, answered) = match request {
            WantRequest::Blob { handle } => (
                WantKind::Blob,
                contains_blob(snapshot, handle, "inspect durable blob WANT residency")?,
            ),
            WantRequest::Merge { .. } => (WantKind::Merge, answered_operations.contains(&request)),
            WantRequest::Derive { .. } => {
                (WantKind::Derive, answered_operations.contains(&request))
            }
        };
        update_want_summary(&mut wants, answered);
        update_want_summary(
            match kind {
                WantKind::Blob => &mut blob_wants,
                WantKind::Merge => &mut merge_wants,
                WantKind::Derive => &mut derive_wants,
            },
            answered,
        );
        if !answered {
            retain_smallest(
                &mut pending_wants,
                PendingWant { kind, request },
                sample_limit,
            );
        }
    }
    let pending_want_sample_truncated =
        wants.pending > u64::try_from(pending_wants.len()).unwrap_or(u64::MAX);

    Ok(LocalReport {
        resident_blobs,
        resident_bytes,
        blob_sample: blob_sample.into_iter().collect(),
        blob_sample_truncated,
        stored_records,
        commits,
        merges,
        derives,
        collections: collections
            .into_iter()
            .map(|(collection, evidence)| CollectionEvidence {
                collection,
                commits: evidence.commits,
                merges: evidence.merges,
                derives: evidence.derives,
            })
            .collect(),
        missing_reference_sample: missing_references.into_iter().collect(),
        missing_reference_sample_truncated,
        wants,
        blob_wants,
        merge_wants,
        derive_wants,
        pending_want_sample: pending_wants.into_iter().collect(),
        pending_want_sample_truncated,
    })
}

/// Project replicated health reports without maintaining an index or assuming
/// cardinality. This chooses the latest report per observer for presentation;
/// every fact within that report stays open-world.
pub fn observe_health(facts: &TribleSet, now_ns: i128, max_age: Duration) -> Vec<ObserverReport> {
    let mut latest = BTreeMap::<Id, (i128, Id)>::new();
    for (report, node, created) in find!(
        (report: Id, node: Id, created: (i128, i128)),
        pattern!(facts, [{
            ?report @ metadata::tag: &health_record::KIND_REPORT,
            health_record::attrs::node: ?node,
            metadata::created_at: ?created,
        }])
    ) {
        let candidate = (created.1, report);
        latest
            .entry(node)
            .and_modify(|selected| {
                if candidate > *selected {
                    *selected = candidate;
                }
            })
            .or_insert(candidate);
    }

    latest
        .into_iter()
        .map(|(node, (created_ns, report))| {
            let mut sessions: Vec<Id> = find!(
                session: Id,
                pattern!(facts, [{ report @ health_record::attrs::session: ?session }])
            )
            .collect();
            sessions.sort_unstable();
            sessions.dedup();
            let mut endpoints: Vec<[u8; 32]> = find!(
                endpoint: VerifyingKey,
                pattern!(facts, [{ node @ health_record::attrs::endpoint: ?endpoint }])
            )
            .map(|endpoint| endpoint.to_bytes())
            .collect();
            endpoints.sort_unstable();
            endpoints.dedup();

            let mut condition_ids: Vec<Id> = find!(
                condition: Id,
                pattern!(facts, [{
                    report @ health_record::attrs::condition: ?condition,
                }, {
                    ?condition @ metadata::tag: &health_record::KIND_CONDITION,
                    health_record::attrs::node: &node,
                }])
            )
            .collect();
            condition_ids.sort_unstable();
            condition_ids.dedup();
            let conditions = condition_ids
                .into_iter()
                .map(|condition| observe_condition(facts, condition))
                .collect();

            let age_ns = now_ns.checked_sub(created_ns);
            let age_seconds = age_ns
                .filter(|age| *age >= 0)
                .and_then(|age| u64::try_from(age / 1_000_000_000).ok());
            let max_age_ns = i128::from(max_age.as_secs()).saturating_mul(1_000_000_000);
            let freshness = if created_ns > now_ns {
                Freshness::Future
            } else if now_ns.saturating_sub(created_ns) < max_age_ns {
                Freshness::Fresh
            } else {
                Freshness::Stale
            };
            ObserverReport {
                node,
                report,
                sessions,
                endpoints,
                created_ns,
                age_seconds,
                freshness,
                conditions,
            }
        })
        .collect()
}

/// Build the shared report after the caller has opened the health collection
/// through the same immutable snapshot. `None` means no readable report facts,
/// not an empty or healthy remote cluster.
pub fn inspect<R>(
    snapshot: &R,
    health_facts: Option<&TribleSet>,
    now_ns: i128,
    max_age: Duration,
    sample_limit: usize,
) -> Result<DashboardReport>
where
    R: StoreRead,
{
    Ok(DashboardReport {
        local: inspect_local(snapshot, sample_limit)?,
        observers: health_facts
            .map(|facts| observe_health(facts, now_ns, max_age))
            .unwrap_or_default(),
    })
}

fn observe_condition(facts: &TribleSet, condition: Id) -> ObservedCondition {
    let mut tags: Vec<Id> = find!(
        tag: Id,
        pattern!(facts, [{ condition @ metadata::tag: ?tag }])
    )
    .collect();
    tags.sort_unstable();
    tags.dedup();
    let components = [
        (health_record::HOST, Component::Host),
        (health_record::STORE, Component::Store),
        (health_record::COLLECTION, Component::Collection),
        (health_record::DHT, Component::Dht),
    ]
    .into_iter()
    .filter_map(|(tag, component)| tags.binary_search(&tag).is_ok().then_some(component))
    .collect();
    let mut state_tags: Vec<Id> = find!(
        state: Id,
        pattern!(facts, [{ condition @ health_record::attrs::state: ?state }])
    )
    .collect();
    state_tags.sort_unstable();
    state_tags.dedup();
    let states = [
        (health_record::CURRENT, State::Current),
        (health_record::PROGRESSING, State::Progressing),
        (health_record::UNKNOWN, State::Unknown),
        (health_record::STALLED, State::Stalled),
    ]
    .into_iter()
    .filter_map(|(tag, state)| state_tags.binary_search(&tag).is_ok().then_some(state))
    .collect();
    let mut collections: Vec<[u8; 32]> = find!(
        collection: CollectionHandle,
        pattern!(facts, [{ condition @ health_record::attrs::collection: ?collection }])
    )
    .map(|collection| collection.raw)
    .collect();
    collections.sort_unstable();
    collections.dedup();
    let mut peers: Vec<[u8; 32]> = find!(
        peer: VerifyingKey,
        pattern!(facts, [{ condition @ health_record::attrs::peer: ?peer }])
    )
    .map(|peer| peer.to_bytes())
    .collect();
    peers.sort_unstable();
    peers.dedup();

    ObservedCondition {
        id: condition,
        components,
        states,
        collections,
        peers,
        alert: exists!(pattern!(facts, [{
            condition @ metadata::tag: &health_record::KIND_ALERT,
        }])),
        recovered: exists!(pattern!(facts, [{
            condition @ metadata::tag: &health_record::KIND_RECOVERED,
        }])),
        evidence: ObservedEvidence {
            resident_blobs: count_metric(facts, condition, &health_record::attrs::resident_blobs),
            local_records: count_metric(facts, condition, &health_record::attrs::local_records),
            local_authorizations: count_metric(
                facts,
                condition,
                &health_record::attrs::local_authorizations,
            ),
            remote_records: count_metric(facts, condition, &health_record::attrs::remote_records),
            remote_authorizations: count_metric(
                facts,
                condition,
                &health_record::attrs::remote_authorizations,
            ),
            publication_keys: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_keys,
            ),
            publication_startup_pending: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_startup_pending,
            ),
            publication_incremental_pending: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_incremental_pending,
            ),
            publication_retry_pending: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_retry_pending,
            ),
            publication_renewal_remaining: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_renewal_remaining,
            ),
            publication_in_flight: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_in_flight,
            ),
            publication_attempts: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_attempts,
            ),
            publication_acknowledged: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_acknowledged,
            ),
            publication_rejected: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_rejected,
            ),
            publication_unavailable: count_metric(
                facts,
                condition,
                &health_record::attrs::publication_unavailable,
            ),
        },
    }
}

fn count_metric(facts: &TribleSet, entity: Id, attribute: &Attribute<U256BE>) -> CountMetric {
    let mut values: Vec<u128> = find!(
        value: u128,
        pattern!(facts, [{ entity @ attribute: ?value }])
    )
    .collect();
    values.sort_unstable();
    values.dedup();
    match values.as_slice() {
        [] => CountMetric::Absent,
        [value] => CountMetric::Value(*value),
        _ => CountMetric::Ambiguous(values),
    }
}

fn record_answer(record: CollectionRecord) -> Option<WantRequest> {
    match record {
        CollectionRecord::Commit(_) => None,
        CollectionRecord::Merge(merge) => {
            let (low, high) = merge.inputs();
            Some(WantRequest::merge(merge.collection(), low, high))
        }
        CollectionRecord::Derive(derive) => {
            Some(WantRequest::derive(derive.collection(), derive.input()))
        }
    }
}

fn contains_blob<R>(
    snapshot: &R,
    handle: Inline<Handle<UnknownBlob>>,
    operation: &'static str,
) -> Result<bool>
where
    R: StoreRead,
{
    snapshot
        .contains_blob(handle)
        .map_err(anyhow::Error::new)
        .context(operation)
}

fn retain_smallest<T>(sample: &mut BTreeSet<T>, value: T, limit: usize)
where
    T: Ord,
{
    if limit == 0 {
        return;
    }
    sample.insert(value);
    if sample.len() > limit {
        sample.pop_last();
    }
}

fn summary_mut<'a>(
    kind: NativeKind,
    commits: &'a mut NativeSummary,
    merges: &'a mut NativeSummary,
    derives: &'a mut NativeSummary,
) -> &'a mut NativeSummary {
    match kind {
        NativeKind::Commit => commits,
        NativeKind::Merge => merges,
        NativeKind::Derive => derives,
    }
}

fn update_native_summary(summary: &mut NativeSummary, missing: &[[u8; 32]], result_resident: bool) {
    summary.stored = summary.stored.saturating_add(1);
    if missing.is_empty() {
        summary.all_references_resident = summary.all_references_resident.saturating_add(1);
    }
    if result_resident {
        summary.result_resident = summary.result_resident.saturating_add(1);
    }
    summary.missing_reference_occurrences = summary
        .missing_reference_occurrences
        .saturating_add(u64::try_from(missing.len()).unwrap_or(u64::MAX));
}

fn update_want_summary(summary: &mut WantSummary, answered: bool) {
    summary.total = summary.total.saturating_add(1);
    if answered {
        summary.answered = summary.answered.saturating_add(1);
    } else {
        summary.pending = summary.pending.saturating_add(1);
    }
}

/// Format a collection handle for a compact dashboard row.
pub fn short_handle(raw: &[u8; 32]) -> String {
    hex::encode(&raw[..6])
}

/// Return the collection handle named by an operation request, if any.
pub const fn requested_collection(request: WantRequest) -> Option<CollectionHandle> {
    match request {
        WantRequest::Blob { .. } => None,
        WantRequest::Merge { collection, .. } => Some(collection),
        WantRequest::Derive { target, .. } => Some(target),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionMerge, CollectionPolicy, CollectionRecordFingerprint,
        CollectionStore, CollectionStoreExt,
    };
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource, WantStore};

    use super::*;

    #[test]
    fn report_keeps_equation_residency_and_requested_work_distinct() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let mut store = MemoryRepo::default();
        let collection = store.collection("dashboard-test", policy).unwrap();
        let input = store
            .put::<UnknownBlob, _>(anybytes::Bytes::from_source(vec![1, 2, 3]))
            .unwrap();
        let missing_result = Inline::new([9; 32]);
        let input_witness = CollectionRecordFingerprint::from_raw([6; 32]);
        store
            .insert(CollectionRecord::Merge(CollectionMerge::sign(
                &key,
                collection.handle(),
                (Inline::new(input.raw), input_witness),
                (Inline::new(input.raw), input_witness),
                missing_result,
            )))
            .unwrap();
        store
            .want(WantRequest::merge(
                collection.handle(),
                Inline::new(input.raw),
                Inline::new(input.raw),
            ))
            .unwrap();
        store.want(WantRequest::blob(input)).unwrap();
        let absent_blob =
            Inline::<triblespace_core::inline::encodings::hash::Handle<UnknownBlob>>::new([8; 32]);
        store.want(WantRequest::blob(absent_blob)).unwrap();

        let report = inspect_local(&store.snapshot().unwrap(), 1).unwrap();

        assert_eq!(report.stored_records, 1);
        assert_eq!(report.merges.stored, 1);
        assert_eq!(report.merges.result_resident, 0);
        assert_eq!(report.merges.all_references_resident, 0);
        assert_eq!(
            report.wants,
            WantSummary {
                total: 3,
                answered: 2,
                pending: 1
            }
        );
        assert_eq!(
            report.pending_want_sample[0].request,
            WantRequest::blob(absent_blob)
        );
        assert!(report.blob_sample_truncated);
    }

    #[test]
    fn observed_counts_roundtrip_and_zero_is_not_absence() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let mut recorder = health_record::Recorder::new(key.verifying_key());
        let at = hifitime::Epoch::from_unix_seconds(1_700_000_000.0);
        let fragment = recorder
            .record_measurements(
                at,
                [health_record::Measurement {
                    condition: health_record::Condition {
                        component: Component::Store,
                        collection: None,
                        peer: None,
                        state: State::Current,
                        alert: false,
                    },
                    evidence: health_record::Evidence {
                        resident_blobs: Some(0),
                        ..health_record::Evidence::default()
                    },
                }],
            )
            .unwrap();
        let now = at.to_tai_duration().total_nanoseconds() + 1_000_000_000;

        let reports = observe_health(fragment.facts(), now, Duration::from_secs(10));

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].freshness, Freshness::Fresh);
        assert_eq!(reports[0].conditions.len(), 1);
        assert_eq!(
            reports[0].conditions[0].evidence.resident_blobs,
            CountMetric::Value(0)
        );
        assert_eq!(
            reports[0].conditions[0].evidence.local_records,
            CountMetric::Absent
        );
    }
}
