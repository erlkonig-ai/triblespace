//! Exact collection realization from invariant foundational support.
//!
//! A [`Support`] is always a cover of the ultimate `SimpleArchive` root.
//! Stored `MERGE` and `DERIVE` equations close the complete descriptor lineage
//! from those roots. Crossing one mapping publishes only `DERIVE`; horizontal
//! LSM carries are the separate `maintain` operation. Neither operation ever
//! manufactures an upstream dependency as a side effect of downstream work.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::inline::encodings::hash::Handle;
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{BlobStoreGet, BlobStoreList, Store, StoreRead};
use crate::trible::Fragment;

use super::operation_snapshot::OperationFrontier;
use super::{
    descriptor, resolve_collection_semantics, Collection,
    CollectionClaimValidation, CollectionData, CollectionEncoding,
    CollectionHandle, CollectionMapping, CollectionRecord, CollectionRecordFingerprint,
    CollectionRecordSelector, CollectionResolutionError, Support,
};
#[cfg(test)]
use super::{CanonicalDerivation, CollectionDerivation};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Failure to observe, ensure, or maintain one collection realization.
#[derive(Debug)]
pub enum CollectionRealizationError {
    /// A storage operation failed.
    Storage {
        /// Operation that failed.
        operation: &'static str,
        /// Backend failure.
        source: BoxError,
    },
    /// The supplied support belongs to another foundation or cannot describe
    /// the requested target.
    InvalidCover(String),
    /// Descriptor ancestry or stored equations are contradictory.
    Resolution(String),
    /// The target does not have a complete resident realization.
    IncompleteCover {
        /// Target-frontier obligations without a resident realization.
        missing: Vec<CollectionData>,
        /// Foundational members not represented by the selected target cover.
        unsupported_members: Vec<CollectionData>,
    },
    /// Missing support requires a new equation, but the supplied producer is
    /// not admitted by the target's frozen WRITE policy.
    UnauthorizedProducer {
        /// Target whose realization needs an authorized producer.
        collection: CollectionHandle,
    },
    /// Canonical source-to-target construction failed.
    Derive {
        /// Immediate source member being mapped.
        input: CollectionData,
        /// Concrete construction failure.
        reason: String,
    },
    /// The target encoding could not join one deterministic LSM pair.
    Merge {
        /// Canonically lower input identity.
        low: CollectionData,
        /// Canonically higher input identity.
        high: CollectionData,
        /// Concrete construction failure.
        reason: String,
    },
    /// A required mapping input names an immutable blob absent from the
    /// current store snapshot.
    MissingDependency {
        /// Exact missing content identity.
        member: CollectionData,
    },
    /// The selected target is readable, but one or more exact endorsed
    /// historical record routes cannot be reconstructed in this snapshot.
    IncompleteSupport {
        /// Target endorsements with missing or mismatched witness ancestry.
        records: Vec<CollectionRecordFingerprint>,
    },
    /// No resident physical source cover remains after deterministic capacity
    /// failures exclude members which cannot be represented downstream.
    UnrepresentableCover {
        /// Capacity-terminal source members and their reasons.
        blocked: Vec<(CollectionData, String)>,
        /// Foundational obligations left uncovered by usable source members.
        missing: Vec<CollectionData>,
    },
    /// Publication made no observable progress.
    Stalled {
        /// Repeated target cover in canonical content order.
        cover: Vec<CollectionData>,
    },
}

impl CollectionRealizationError {
    pub(super) fn storage(
        operation: &'static str,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::Storage {
            operation,
            source: Box::new(source),
        }
    }
}

/// How many identities an error names before it starts counting instead.
///
/// A cover can hold tens of thousands of members, so an error is not a place to
/// dump all of them. But printing NONE of them, as these variants used to, keeps
/// the only part that tells you where to look: every one of them already holds
/// the identities and threw them away at the display boundary. A count says
/// something is wrong; an identity says what to go and read.
const NAMED_IN_ERROR: usize = 4;

/// Render up to [`NAMED_IN_ERROR`] entries, then say how many were elided.
fn name_some(entries: impl IntoIterator<Item = String>) -> String {
    let entries: Vec<_> = entries.into_iter().collect();
    let total = entries.len();
    let shown = entries
        .iter()
        .take(NAMED_IN_ERROR)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match total.saturating_sub(NAMED_IN_ERROR) {
        0 => shown,
        rest => format!("{shown}, and {rest} more"),
    }
}

impl fmt::Display for CollectionRealizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidCover(reason) => write!(formatter, "invalid exact support: {reason}"),
            Self::Resolution(reason) => write!(formatter, "resolve collection: {reason}"),
            Self::IncompleteCover {
                missing,
                unsupported_members,
            } => write!(
                formatter,
                "collection realization is incomplete ({} missing target element(s): {}; {} unsupported foundational member(s): {})",
                missing.len(),
                name_some(missing.iter().map(|m| hex::encode_upper(m.raw))),
                unsupported_members.len(),
                name_some(unsupported_members.iter().map(|m| hex::encode_upper(m.raw))),
            ),
            Self::UnauthorizedProducer { collection } => write!(
                formatter,
                "collection {} requires an admitted WRITE producer to realize missing support",
                hex::encode_upper(collection.raw),
            ),
            Self::Derive { input, reason } => write!(
                formatter,
                "derive source element {}: {reason}",
                hex::encode_upper(input.raw),
            ),
            Self::Merge { low, high, reason } => write!(
                formatter,
                "merge target elements {} and {}: {reason}",
                hex::encode_upper(low.raw),
                hex::encode_upper(high.raw),
            ),
            Self::MissingDependency { member } => write!(
                formatter,
                "mapping requires resident blob {}",
                hex::encode_upper(member.raw),
            ),
            Self::IncompleteSupport { records } => write!(
                formatter,
                "collection support is unavailable ({} incomplete endorsed record route(s): {})",
                records.len(),
                name_some(records.iter().map(|r| hex::encode_upper(r.raw()))),
            ),
            Self::UnrepresentableCover { blocked, missing } => write!(
                formatter,
                "source support is unrepresentable ({} capacity-terminal member(s): {}; {} uncovered foundational member(s): {})",
                blocked.len(),
                name_some(
                    blocked
                        .iter()
                        .map(|(member, reason)| format!("{} ({reason})", hex::encode_upper(member.raw))),
                ),
                missing.len(),
                name_some(missing.iter().map(|m| hex::encode_upper(m.raw))),
            ),
            Self::Stalled { cover } => write!(
                formatter,
                "collection operation repeated an unchanged {}-member cover",
                cover.len(),
            ),
        }
    }
}

impl Error for CollectionRealizationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

pub(super) fn producer_is_admitted<R, E>(
    snapshot: &R,
    target: Collection<E>,
    signing_key: &SigningKey,
) -> Result<bool, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    target
        .writer_is_admitted(snapshot, signing_key.verifying_key())
        .map_err(|error| {
            CollectionRealizationError::storage("check target producer WRITE authority", error)
        })
}

/// Runtime descriptor ancestry from one `SimpleArchive` foundation to a
/// typed target.
pub(super) struct Lineage {
    pub(super) foundation: Collection<SimpleArchive>,
    pub(super) descriptors: BTreeMap<CollectionHandle, Fragment>,
    pub(super) source_by_target: BTreeMap<CollectionHandle, CollectionHandle>,
}

impl Lineage {
    pub(super) fn descriptor(&self, collection: CollectionHandle) -> &Fragment {
        self.descriptors
            .get(&collection)
            .expect("loaded lineage contains every descriptor")
    }
}

pub(super) fn load_lineage<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<Lineage, CollectionRealizationError>
where
    R: BlobStoreGet + BlobStoreList,
    E: CollectionEncoding,
{
    let lineage = load_record_lineage(snapshot, target.handle())?;
    super::encoding::validate_descriptor_type::<E>(lineage.descriptor(target.handle())).map_err(
        |error| {
            CollectionRealizationError::Resolution(format!(
                "target descriptor has the wrong representation: {error}"
            ))
        },
    )?;
    Ok(lineage)
}

pub(super) fn load_record_lineage<R>(
    snapshot: &R,
    target: CollectionHandle,
) -> Result<Lineage, CollectionRealizationError>
where
    R: BlobStoreGet + BlobStoreList,
{
    let mut descriptors = BTreeMap::new();
    let mut source_by_target = BTreeMap::new();
    let mut collections = BTreeSet::new();
    let mut cursor = target;

    loop {
        if !collections.insert(cursor) {
            return Err(CollectionRealizationError::Resolution(format!(
                "collection descriptor ancestry contains a cycle at {}",
                hex::encode_upper(cursor.raw),
            )));
        }

        if !snapshot.contains_blob(cursor).map_err(|error| {
            CollectionRealizationError::storage("inspect collection descriptor residency", error)
        })? {
            return Err(CollectionRealizationError::MissingDependency {
                member: Handle::<SimpleArchive>::to_hash(cursor),
            });
        }

        let loaded = super::api::load_collection_descriptor(snapshot, cursor).map_err(|error| {
            CollectionRealizationError::Resolution(format!(
                "load collection descriptor {}: {error}",
                hex::encode_upper(cursor.raw),
            ))
        })?;
        let source = descriptor::source(loaded.fragment.facts()).map_err(|error| {
            CollectionRealizationError::Resolution(format!(
                "decode collection source for {}: {error}",
                hex::encode_upper(cursor.raw),
            ))
        })?;
        descriptors.insert(cursor, loaded.fragment);

        match source {
            Some(source) => {
                source_by_target.insert(cursor, source);
                cursor = source;
            }
            None => {
                let root = descriptors
                    .get(&cursor)
                    .expect("root descriptor was inserted before inspection");
                super::encoding::validate_descriptor_type::<SimpleArchive>(root).map_err(
                    |error| {
                        CollectionRealizationError::Resolution(format!(
                            "collection ancestry terminates in a non-SimpleArchive root: {error}"
                        ))
                    },
                )?;
                return Ok(Lineage {
                    foundation: Collection::from_handle(cursor),
                    descriptors,
                    source_by_target,
                });
            }
        }
    }
}

/// Find the ultimate canonical fact collection beneath a typed target.
#[cfg(test)]
pub(crate) fn foundation<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<Collection<SimpleArchive>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    Ok(load_lineage(snapshot, target)?.foundation)
}

pub(super) type InputWitnesses =
    BTreeMap<(CollectionHandle, CollectionData), Vec<(CollectionRecord, Support)>>;

struct CertifiedResolution {
    witnesses: InputWitnesses,
}

#[cfg(test)]
impl CertifiedResolution {
    /// The support the selected records of one collection certify: the union
    /// of their witnesses' supports. A read no longer accumulates this; the
    /// tests of the selection filter still ask for it.
    fn support_of(
        &self,
        foundation: Collection<SimpleArchive>,
        collection: CollectionHandle,
    ) -> Support {
        let mut support = Support::from_data(foundation, []);
        for ((owner, _), alternatives) in &self.witnesses {
            if *owner != collection {
                continue;
            }
            for (_, alternative) in alternatives {
                support = support.union(alternative).expect("one foundation");
            }
        }
        support
    }
}

/// Enumerate exact admitted input witnesses for explicit equation imports.
///
/// This diagnostic/migration surface preserves distinct supports of a lossy
/// mapping. It does not load member payloads, publish records, or choose among
/// ambiguous historical provenance. Endorsed descendants are usable witnesses
/// even when their original authority proof is no longer locally available.
pub fn admitted_record_witnesses<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<Vec<(CollectionRecord, Support)>, CollectionRealizationError>
where
    R: StoreRead,
{
    let lineage = load_record_lineage(snapshot, collection)?;
    let certified = resolve_endorsed_lineage(snapshot, &lineage, &BTreeSet::from([collection]))?;
    let mut records = Vec::new();
    for ((owner, _), alternatives) in certified.witnesses {
        if owner != collection {
            continue;
        }
        records.extend(alternatives);
    }
    Ok(records)
}

/// Preview equation imports against one frozen store without publishing them.
///
/// This diagnostic/migration operation overlays actual signed MERGE and DERIVE
/// records, then uses ordinary admission and witness resolution. Existing native
/// records whose missing witnesses are supplied by the preview participate too.
/// Functional and commuting-square conflicts are reported before any append;
/// payloads are neither loaded nor recomputed. The returned witnesses include
/// the complete admitted collection in this preview, not just the proposed rows.
/// COMMIT publication remains a separate operation and is not previewed here.
pub fn preview_record_witnesses<R>(
    snapshot: &R,
    collection: CollectionHandle,
    records: impl IntoIterator<Item = CollectionRecord>,
) -> Result<Vec<(CollectionRecord, Support)>, CollectionRealizationError>
where
    R: StoreRead,
{
    let mut frontier = OperationFrontier::new(snapshot.clone());
    for record in records {
        if matches!(record, CollectionRecord::Commit(_)) {
            return Err(CollectionRealizationError::InvalidCover(
                "equation preview does not publish COMMIT records".to_owned(),
            ));
        }
        frontier.include_record(record);
    }
    admitted_record_witnesses(&frontier.view(snapshot.clone()), collection)
}

/// What ONE cited record certifies, read straight out of the coverage index.
///
/// A coverage row is the denotational answer for a value: every route to it
/// unions in, because either way of building it is a way it could have been
/// built. Citing a record is narrower -- it chooses a route -- so a
/// certificate is the union over the inputs *that record* names, and the rows
/// supply those inputs' answers without a walk.
///
/// All-or-nothing, like a row: one input with no row makes the certificate
/// unknown, never a smaller set that would pass a subset test it should fail.
fn record_certificate(
    coverage: &super::coverage::Coverage,
    lineage: &Lineage,
    record: CollectionRecord,
) -> Option<super::coverage::CoverageSet> {
    use super::coverage::{Attestation, CoverageSet};
    let collection = record.collection();
    match Attestation::of(&record) {
        // A commit stands for its own payload. The row is consulted only to
        // ask whether it was admitted; the row itself may be wider, and that
        // width belongs to the value rather than to this citation.
        Attestation::Foundation { data } => {
            // A commit anywhere but the foundation is a malformed route --
            // the structural walk says the same -- and certifies nothing.
            if collection != lineage.foundation.handle() {
                return None;
            }
            coverage
                .of(collection, data)
                .map(|_| CoverageSet::from_keys(std::iter::once(data.raw)))
        }
        Attestation::Join { low, high, .. } => {
            let mut set = coverage.of(collection, low)?.clone();
            set.union(coverage.of(collection, high)?.clone());
            Some(set)
        }
        Attestation::Image { input, .. } => {
            // The input is a node in this collection's source, which the
            // lineage already names -- no descriptor read needed here.
            let source = lineage.source_by_target.get(&collection)?;
            coverage.of(*source, input).cloned()
        }
    }
}

/// The foundation payloads a record's stated inputs reduce to, walking
/// producers structurally through the produced-member index.
///
/// This is what an admitted producer vouches for when it names its inputs,
/// and it is the certificate to use when the coverage fold has no row for the
/// record -- which happens exactly when something beneath it is not admitted
/// HERE. Records below the certified one must EXIST: every payload on the way
/// down needs a producing record, and a foundation payload needs a COMMIT. A
/// missing record anywhere makes the certificate unknown (`None`), not
/// narrower. But none of them is re-admitted, and no payload is loaded: the
/// reader trusts the producer it admitted for what that producer named.
///
/// Two named tests hold the two halves apart.
/// `aggregate_support_excludes_missing_witnesses_and_unadmitted_producers`
/// keeps a derive out of the support until its input's COMMIT lands;
/// `multihop_support_uses_exact_endorsed_records_without_ancestor_authority_
/// or_payload_rechecks` follows a chain whose every ancestor is signed by a
/// key this store does not admit. The witness field satisfied both by citing
/// one exact record; naming the payload and walking every producer of it
/// satisfies both without the field, wider where routes diverge -- which the
/// lattice comparison absorbs.
///
/// [`super::witness::records_for`] walks the same graph for retention.
fn structural_certificate<R>(
    snapshot: &R,
    lineage: &Lineage,
    record: CollectionRecord,
) -> Result<Option<super::coverage::CoverageSet>, CollectionRealizationError>
where
    R: StoreRead,
{
    let foundation = lineage.foundation.handle();
    let mut certificate = super::coverage::CoverageSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![record];
    while let Some(record) = pending.pop() {
        if !visited.insert(record.fingerprint()) {
            continue;
        }
        let collection = record.collection();
        let inputs: Vec<(CollectionHandle, CollectionData)> = match record {
            CollectionRecord::Commit(commit) if collection == foundation => {
                certificate.union(super::coverage::CoverageSet::from_keys([commit.data().raw]));
                Vec::new()
            }
            // A COMMIT anywhere but the foundation is a raw membership claim
            // with no derivation behind it: its foundation provenance is not
            // empty, it is unknown.
            CollectionRecord::Commit(_) => return Ok(None),
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                vec![(collection, low), (collection, high)]
            }
            CollectionRecord::Derive(derive) => match lineage.source_by_target.get(&collection) {
                Some(source) => vec![(*source, derive.input())],
                None => return Ok(None),
            },
        };
        for (owner, payload) in inputs {
            let producers = snapshot
                .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
                    owner, payload,
                )]))
                .map_err(|error| {
                    CollectionRealizationError::storage("expand producing records", error)
                })?;
            if producers.is_empty() {
                return Ok(None);
            }
            pending.extend(producers);
        }
    }
    Ok(Some(certificate))
}

/// Admit selected producers, then follow only their immutable witness DAGs.
/// Read attachment selects only the target; maintenance additionally admits
/// immediate-source candidates it may use to publish new equations.
fn resolve_endorsed_lineage<R>(
    snapshot: &R,
    lineage: &Lineage,
    collections: &BTreeSet<CollectionHandle>,
) -> Result<CertifiedResolution, CollectionRealizationError>
where
    R: StoreRead,
{
    let mut evidence = BTreeMap::new();
    for collection in collections {
        let descriptor = lineage.descriptor(*collection);
        let writers = super::api::discover_admission_evidence(
            snapshot,
            descriptor::admission_policies(snapshot, descriptor.facts(), super::ACTION_WRITE, None),
            super::ACTION_WRITE,
            *collection,
        )
        .map_err(|error| {
            CollectionRealizationError::storage("discover equation WRITE admission", error)
        })?;
        evidence.insert(*collection, writers);
    }
    let mut admitted = BTreeMap::new();
    let selectors = collections
        .iter()
        .copied()
        .map(CollectionRecordSelector::Collection)
        .collect();
    let candidates = snapshot.select_records(&selectors).map_err(|error| {
        CollectionRealizationError::storage("select endorsed collection records", error)
    })?;
    // Support is a lookup, not a walk: every edge under a row was admitted
    // when the fold believed it, so nothing here re-derives or re-decides it.
    let coverage = snapshot
        .coverage(&lineage.descriptors.keys().copied().collect())
        .map_err(|error| CollectionRealizationError::storage("read downward coverage", error))?;
    let mut roots = BTreeSet::new();
    let mut witnesses = InputWitnesses::new();
    for record in candidates {
        let accepted = *admitted
            .entry((record.collection(), record.public_key().raw))
            .or_insert_with(|| {
                ed25519_dalek::VerifyingKey::from_bytes(&record.public_key().raw)
                    .ok()
                    .is_some_and(|subject| {
                        evidence
                            .get(&record.collection())
                            .is_some_and(|writers| writers.authorizes(snapshot, subject))
                    })
            });
        if !accepted {
            continue;
        }
        // A record certifies something when the fold has a row for it or,
        // failing that, when what its producer named reduces to commits.
        if record_certificate(&coverage, lineage, record).is_none()
            && structural_certificate(snapshot, lineage, record)?.is_none()
        {
            continue;
        }
        roots.insert(record);
    }
    // Support comes from the index now, but the RECORD set still has to be
    // expanded: `resolve_collection_semantics` needs the COMMIT records
    // underneath the selected endorsements, and record retention is exactly
    // what the coverage index forgets. Two different questions, and only one
    // of them is denotational.
    let records = super::witness::records_for(snapshot, roots, &lineage.source_by_target)
        .map_err(|error| CollectionRealizationError::storage("expand producing records", error))?;
    for record in &records {
        let record_support = Support::from_patch(
            lineage.foundation,
            match record_certificate(&coverage, lineage, *record) {
                Some(certificate) => certificate,
                None => structural_certificate(snapshot, lineage, *record)?.unwrap_or_default(),
            },
        );
        let alternatives = witnesses
            .entry((record.collection(), super::coverage::produced(*record)))
            .or_default();
        // Retain actual records, including equal-support signatures/routes.
        // Publication selects a small covering witness set when needed;
        // diagnostics and migrations must still see every persisted identity.
        alternatives.push((*record, record_support));
    }
    let discovered = super::DiscoveredCollectionRecords::from_records(records);
    let commits = discovered.commits().iter().copied().collect();
    let resolution =
        resolve_collection_semantics(&discovered, &lineage.source_by_target, &commits, |_| {
            Ok::<CollectionClaimValidation<()>, std::convert::Infallible>(
                CollectionClaimValidation::Accepted,
            )
        });

    match resolution {
        Ok(_) => Ok(CertifiedResolution { witnesses }),
        Err(CollectionResolutionError::Validation { source, .. }) => match source {},
        Err(CollectionResolutionError::Conflict(conflict)) => {
            Err(CollectionRealizationError::Resolution(conflict.to_string()))
        }
    }
}

/// Read what an immutable target's retained endorsements stand for.
///
/// Every edge these records rest on was admitted when the coverage index
/// folded it, so nothing is re-decided here and no witness is consulted: a
/// record's support is the row its result already has. A record whose result
/// has no row is reported rather than skipped, because a caller asking for
/// support needs to know when its answer is partial.
pub(crate) fn support_of_records<R, E>(
    snapshot: &R,
    target: Collection<E>,
    records: &[CollectionRecord],
) -> Result<Support, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let lineage = load_lineage(snapshot, target)?;
    let coverage = snapshot
        .coverage(&lineage.descriptors.keys().copied().collect())
        .map_err(|error| CollectionRealizationError::storage("read downward coverage", error))?;
    let (mut members, unattested) = coverage.union_over(
        target.handle(),
        records.iter().copied().map(super::coverage::produced),
    );
    // A record the fold has no row for is certified from what it named,
    // minus the admission of everything beneath it -- see
    // `structural_certificate`. Unknown stays unknown, and is reported.
    let mut incomplete = Vec::new();
    for record in records
        .iter()
        .filter(|record| unattested.contains(&super::coverage::produced(**record)))
    {
        match structural_certificate(snapshot, &lineage, *record)? {
            Some(certificate) => members.union(certificate),
            None => incomplete.push(record.fingerprint()),
        }
    }
    if incomplete.is_empty() {
        Ok(Support::from_patch(lineage.foundation, members))
    } else {
        // Name the records, not the payloads: a caller repairing this needs
        // to know which endorsements it is missing evidence for.
        Err(CollectionRealizationError::IncompleteSupport {
            records: incomplete,
        })
    }
}

/// Ensure one immediate mapping for invariant foundational support.
///
/// Existing equations throughout the ancestry are reused, but new work only
/// maps resident immediate-source members and publishes target `DERIVE`
/// records. A missing immediate-source cover is an error: downstream ensure
/// never constructs upstream blobs.
#[cfg(test)]
fn ensure_resident_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze mapping frontier", error)
    })?;
    let mut frontier = OperationFrontier::new(snapshot);
    ensure_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        &BTreeSet::new(),
        &mut frontier,
    )
}

#[cfg(test)]
fn ensure_resident<S, T>(
    store: &mut S,
    target: Collection<T>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    T: CollectionDerivation,
{
    ensure_resident_with::<S, CanonicalDerivation<T>>(store, target, signing_key)
}

fn ensure_resident_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    super::maintenance::realize_images::<S, M>(store, target, signing_key, unavailable, frontier)
}

/// Ensure one mapping and then carry its target lattice to the deterministic
/// LSM fixed point.
#[cfg(test)]
fn maintain_resident_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze maintenance frontier", error)
    })?;
    let mut frontier = OperationFrontier::new(snapshot);
    maintain_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        &BTreeSet::new(),
        &mut frontier,
    )
}

#[cfg(test)]
fn maintain_resident<S, T>(
    store: &mut S,
    target: Collection<T>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    T: CollectionDerivation,
{
    maintain_resident_with::<S, CanonicalDerivation<T>>(store, target, signing_key)
}

fn maintain_resident_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    super::maintenance::maintain_images::<S, M>(store, target, signing_key, unavailable, frontier)
}

pub(crate) async fn acquire_missing<S>(
    store: &mut S,
    attempted: &mut BTreeSet<CollectionData>,
    member: CollectionData,
) -> Result<bool, CollectionRealizationError>
where
    S: AsyncBlobStoreAcquire,
{
    if !attempted.insert(member) {
        return Ok(false);
    }
    store
        .acquire(Handle::<UnknownBlob>::from_hash(member))
        .await
        .map_err(|error| {
            CollectionRealizationError::storage("acquire exact blob dependency", error)
        })
        .map(|bytes| bytes.is_some())
}

/// Acquire the reusable authority definitions for an explicitly selected
/// lineage. Records and proofs stay frozen; only byte availability advances.
/// No member payload is followed until its producer has been admitted.
pub(crate) async fn acquire_authority<S, E>(
    store: &mut S,
    target: Collection<E>,
    frontier: &OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    E: CollectionEncoding,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe authority definitions", error)
        })?);
        let lineage = match load_lineage(&snapshot, target) {
            Ok(lineage) => lineage,
            Err(CollectionRealizationError::MissingDependency { member }) => {
                drop(snapshot);
                if acquire_missing(store, &mut attempted, member).await? {
                    continue;
                }
                return Err(CollectionRealizationError::MissingDependency { member });
            }
            Err(error) => return Err(error),
        };
        let mut definitions = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut selected = BTreeSet::from([target.handle()]);
        selected.extend(lineage.source_by_target.get(&target.handle()).copied());
        for collection in selected {
            let descriptor = lineage.descriptor(collection);
            for (definition, policy) in descriptor::capability_policies(descriptor.facts(), None) {
                definitions.insert(Handle::<SimpleArchive>::to_hash(definition));
                if let Some(keys) = policy.roots() {
                    roots.extend(keys.iter().map(|key| (collection.raw, key.to_bytes())));
                }
            }
        }
        for proof in crate::repo::CapabilityProofRead::proofs(&snapshot).map_err(|error| {
            CollectionRealizationError::storage("select authority proof definitions", error)
        })? {
            let proof = proof.map_err(|error| {
                CollectionRealizationError::storage("read authority proof definitions", error)
            })?;
            if roots.contains(&(proof.resource().into_bytes(), proof.root_key().to_bytes())) {
                definitions.extend(proof.blob_references().map(Handle::<UnknownBlob>::to_hash));
            }
        }
        let missing = definitions
            .into_iter()
            .filter_map(|member| {
                match snapshot.contains_blob(Handle::<UnknownBlob>::from_hash(member)) {
                    Ok(true) => None,
                    Ok(false) => Some(Ok(member)),
                    Err(error) => Some(Err(CollectionRealizationError::storage(
                        "inspect authority definition residency",
                        error,
                    ))),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(snapshot);
        for member in missing {
            let _ = acquire_missing(store, &mut attempted, member).await?;
        }
        return Ok(());
    }
}

/// Make one explicit root support readable, without needing provenance records
/// or publishing equations. Existing resident MERGEs may already cover it.
pub(crate) async fn ensure_root_in_frontier<S>(
    store: &mut S,
    target: Collection<SimpleArchive>,
    frontier: &OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe root realization", error)
        })?);
        let result = super::maintenance::root_acquisitions(&snapshot, target);
        drop(snapshot);
        let missing = match result {
            Ok(None) => return Ok(()),
            Ok(Some(missing)) => missing,
            Err(CollectionRealizationError::MissingDependency { member }) => vec![member],
            Err(error) => return Err(error),
        };
        let previous_attempts = attempted.len();
        for member in missing {
            let _ = acquire_missing(store, &mut attempted, member).await?;
        }
        if attempted.len() == previous_attempts {
            let snapshot = frontier.view(store.snapshot().map_err(|error| {
                CollectionRealizationError::storage("observe incomplete root realization", error)
            })?);
            return super::maintenance::root_incomplete(&snapshot, target);
        }
    }
}

/// A resident target endorsement is sufficient for reuse. Binding still checks
/// the requested encoding, mapping, and support foundation, but no immediate-
/// source producer or capability definition is needed until new work remains.
async fn prepare_mapping<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    frontier: &OperationFrontier<S::Snapshot>,
) -> Result<bool, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    let resident = {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe target before acquisition", error)
        })?);
        match super::maintenance::images_current::<_, M>(&snapshot, target) {
            Ok(exact) => exact,
            // A missing descriptor can still be acquired through the ordinary
            // active path. Semantic/type/mapping errors must not become misses.
            Err(CollectionRealizationError::MissingDependency { .. }) => false,
            Err(error) => return Err(error),
        }
    };
    if !resident {
        acquire_authority(store, target, frontier).await?;
    }
    Ok(resident)
}

pub(crate) async fn ensure_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    if prepare_mapping::<S, M>(store, target, frontier).await? {
        return Ok(());
    }
    let mut attempted = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    loop {
        match ensure_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            &unavailable,
            frontier,
        ) {
            Err(CollectionRealizationError::MissingDependency { member }) => {
                if attempted.contains(&member) {
                    return Err(CollectionRealizationError::MissingDependency { member });
                }
                if !acquire_missing(store, &mut attempted, member).await? {
                    unavailable.insert(member);
                }
            }
            result => return result,
        }
    }
}

pub(crate) async fn maintain_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    // Warm maintenance may still coarsen the target, but source-guided
    // opportunities are optional and must use only already resident evidence.
    prepare_mapping::<S, M>(store, target, frontier).await?;
    let mut attempted = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    loop {
        match maintain_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            &unavailable,
            frontier,
        ) {
            Err(CollectionRealizationError::MissingDependency { member }) => {
                if attempted.contains(&member) {
                    return Err(CollectionRealizationError::MissingDependency { member });
                }
                if !acquire_missing(store, &mut attempted, member).await? {
                    unavailable.insert(member);
                }
            }
            result => return result,
        }
    }
}

pub(super) fn data_identity<E: CollectionEncoding>(blob: &Blob<E>) -> CollectionData {
    Handle::<E>::to_hash(blob.get_handle())
}

#[cfg(test)]
mod tests;
