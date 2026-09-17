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
use crate::repo::{BlobStoreGet, BlobStoreList, BlobStoreMeta, Store, StoreRead};
use crate::trible::Fragment;

use super::encoding::{collection_member_availability, CollectionMemberAvailability};
use super::operation_snapshot::OperationFrontier;
use super::witness::WitnessMemo;
use super::{
    collection_complete_physical_cover, descriptor, resolve_collection_semantics, Collection,
    CollectionClaimValidation, CollectionData, CollectionDerive, CollectionEncoding,
    CollectionHandle, CollectionMapping, CollectionMerge, CollectionOperationError,
    CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector,
    CollectionResolutionError, CollectionSemantics, Cover, Support,
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
struct Lineage {
    foundation: Collection<SimpleArchive>,
    descriptors: BTreeMap<CollectionHandle, Fragment>,
    source_by_target: BTreeMap<CollectionHandle, CollectionHandle>,
}

impl Lineage {
    fn descriptor(&self, collection: CollectionHandle) -> &Fragment {
        self.descriptors
            .get(&collection)
            .expect("loaded lineage contains every descriptor")
    }
}

fn load_lineage<R, E>(
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

fn load_record_lineage<R>(
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

/// Select the admitted support actually realized by a mapping's immediate source.
///
/// An unbuilt or nonresident source member is not an obligation of ordinary
/// downstream maintenance. Exact requests still specify their own support.
pub(crate) fn source_support<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
) -> Result<Support, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let lineage = load_lineage(snapshot, target)?;
    let source = lineage
        .source_by_target
        .get(&target.handle())
        .copied()
        .ok_or_else(|| {
            CollectionRealizationError::Resolution(
                "maintenance requires a derived target descriptor".to_owned(),
            )
        })?;
    let (support, _) = attach_collection(snapshot, Collection::<M::Source>::from_handle(source))?;
    Ok(support)
}

fn require_support(lineage: &Lineage, support: &Support) -> Result<(), CollectionRealizationError> {
    if support.collection() == lineage.foundation {
        return Ok(());
    }
    Err(CollectionRealizationError::InvalidCover(format!(
        "support foundation {} differs from target foundation {}",
        hex::encode_upper(support.collection().handle().raw),
        hex::encode_upper(lineage.foundation.handle().raw),
    )))
}

pub(super) type InputWitnesses =
    BTreeMap<(CollectionHandle, CollectionData), Vec<(CollectionRecordFingerprint, Support)>>;

fn witness_cover(
    alternatives: &[(CollectionRecordFingerprint, Support)],
    mut represented: Support,
) -> Vec<CollectionRecordFingerprint> {
    let mut ordered: Vec<_> = alternatives.iter().collect();
    ordered.sort_by(|(left_id, left), (right_id, right)| {
        right.len().cmp(&left.len()).then(left_id.cmp(right_id))
    });
    let mut selected = Vec::new();
    for (id, support) in ordered {
        if !support.is_subset(&represented).expect("one foundation") {
            represented = represented.union(support).expect("one foundation");
            selected.push(*id);
        }
    }
    selected
}

pub(super) fn merge_witness_pairs(
    witnesses: &InputWitnesses,
    collection: CollectionHandle,
    low: CollectionData,
    high: CollectionData,
) -> Result<
    Vec<(
        (CollectionData, CollectionRecordFingerprint),
        (CollectionData, CollectionRecordFingerprint),
    )>,
    CollectionRealizationError,
> {
    let alternatives = |member| {
        witnesses
            .get(&(collection, member))
            .filter(|witnesses| !witnesses.is_empty())
            .ok_or_else(|| {
                CollectionRealizationError::InvalidCover(
                    "a published MERGE needs an endorsed record for each input".into(),
                )
            })
    };
    let low_witnesses = alternatives(low)?;
    let high_witnesses = alternatives(high)?;
    let foundation = low_witnesses[0].1.collection();
    let low_witnesses = witness_cover(low_witnesses, foundation.cover([]));
    let high_witnesses = witness_cover(high_witnesses, foundation.cover([]));
    // One joined blob, enough paired certificates to preserve every distinct
    // input support. A Cartesian product adds no denotational information.
    Ok((0..low_witnesses.len().max(high_witnesses.len()))
        .map(|index| {
            (
                (low, low_witnesses[index % low_witnesses.len()]),
                (high, high_witnesses[index % high_witnesses.len()]),
            )
        })
        .collect())
}

fn witnessed_support(
    witnesses: &InputWitnesses,
    collection: CollectionHandle,
    members: impl IntoIterator<Item = CollectionData>,
    foundation: Collection<SimpleArchive>,
) -> Support {
    let mut support = Support::from_data(foundation, []);
    for member in members {
        for (_, input_support) in witnesses.get(&(collection, member)).into_iter().flatten() {
            support = support.union(input_support).expect("one foundation");
        }
    }
    support
}

/// Payload order chooses the coarse physical shape. Exact certificates choose
/// its denotation: with a lossy mapping, x <= z does not imply that z's signed
/// witness covers every independently signed support of x.
fn witnessed_physical_cover<E, R>(
    snapshot: &R,
    semantics: &CollectionSemantics,
    witnesses: &InputWitnesses,
    collection: CollectionHandle,
    resident: &BTreeSet<CollectionData>,
    requested: &Support,
) -> Result<(super::resolution::CollectionCompletePhysicalCover, Support), CollectionRealizationError>
where
    E: CollectionEncoding,
    R: BlobStoreGet + BlobStoreMeta,
{
    let mut selected =
        collection_complete_physical_cover::<E, _>(semantics, collection, resident, snapshot);
    let mut represented = witnessed_support(
        witnesses,
        collection,
        selected.physical.cover.iter().copied(),
        requested.collection(),
    );
    let coarse_support = represented.clone();
    let mut residuals = Vec::new();
    for member in resident {
        if requested.is_subset(&represented).expect("one foundation") {
            break;
        }
        let member_support =
            witnessed_support(witnesses, collection, [*member], requested.collection());
        if member_support
            .is_subset(&represented)
            .expect("one foundation")
        {
            continue;
        }
        match collection_member_availability::<E, _>(*member, snapshot).map_err(|error| {
            CollectionRealizationError::storage("inspect residual witness realization", error)
        })? {
            CollectionMemberAvailability::Complete => {
                selected.physical.cover.insert(*member);
                represented = represented.union(&member_support).expect("one foundation");
                residuals.push((*member, member_support));
            }
            _ => {}
        }
    }
    // A later support-repair member can make an earlier one redundant even
    // though both were needed when first visited. Keep the semantic physical
    // cover, and prune only these additions before an LSM carry is planned.
    // Cached suffix unions let each candidate see every other retained support
    // without rebuilding the whole union per candidate. Compare FULL witnessed
    // support, never its intersection with the requested slice.
    if residuals.len() > 1 {
        let mut remaining = Vec::with_capacity(residuals.len() + 1);
        remaining.push(requested.collection().cover([]));
        for (_, member_support) in residuals.iter().rev() {
            remaining.push(
                remaining
                    .last()
                    .expect("suffix union starts with the empty support")
                    .union(member_support)
                    .expect("one foundation"),
            );
        }
        let mut retained_support = coarse_support;
        for (member, member_support) in residuals {
            remaining.pop();
            let others = retained_support
                .union(
                    remaining
                        .last()
                        .expect("suffix retains its empty terminator"),
                )
                .expect("one foundation");
            if member_support.is_subset(&others).expect("one foundation") {
                selected.physical.cover.remove(&member);
            } else {
                retained_support = retained_support
                    .union(&member_support)
                    .expect("one foundation");
            }
        }
        debug_assert_eq!(retained_support, represented);
    }
    if requested.is_subset(&represented).expect("one foundation") {
        selected.physical.missing.clear();
        selected.dependencies.clear();
        selected.unusable = None;
    }
    Ok((selected, represented))
}

struct CertifiedResolution {
    resolution: super::CollectionResolution<()>,
    support: Support,
    witnesses: InputWitnesses,
    images: BTreeMap<(CollectionHandle, CollectionData), BTreeSet<CollectionData>>,
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
    let certified = resolve_endorsed_lineage(
        snapshot,
        &lineage,
        &BTreeSet::from([collection]),
        None,
        &mut WitnessMemo::default(),
    )?;
    let mut records = Vec::new();
    for ((owner, _), alternatives) in certified.witnesses {
        if owner != collection {
            continue;
        }
        for (id, support) in alternatives {
            if let Some(record) = snapshot.record(id).map_err(|error| {
                CollectionRealizationError::storage("read admitted input witness", error)
            })? {
                records.push((record, support));
            }
        }
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

/// Admit selected producers, then follow only their immutable witness DAGs.
/// Read attachment selects only the target; maintenance additionally admits
/// immediate-source candidates it may use to publish new equations.
fn resolve_endorsed_lineage<R>(
    snapshot: &R,
    lineage: &Lineage,
    collections: &BTreeSet<CollectionHandle>,
    requested: Option<&Support>,
    memo: &mut WitnessMemo,
) -> Result<CertifiedResolution, CollectionRealizationError>
where
    R: StoreRead,
{
    if let Some(requested) = requested {
        require_support(lineage, requested)?;
    }
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
    let mut closure = memo.closure(lineage.foundation, &lineage.source_by_target);
    let mut roots = BTreeSet::new();
    let mut witnesses = InputWitnesses::new();
    let mut images = BTreeMap::<_, BTreeSet<_>>::new();
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
        let Some(record_support) = closure
            .support(snapshot, record)
            .map_err(|error| {
                CollectionRealizationError::storage("read endorsed input records", error)
            })?
        else {
            continue;
        };
        // Reusing a computed image is independent of which exact support the
        // caller wants to endorse today. Keep this index before that filter.
        if let CollectionRecord::Derive(derive) = record {
            images
                .entry((derive.collection(), derive.input()))
                .or_default()
                .insert(derive.output());
        }
        if requested
            .is_some_and(|requested| !record_support.is_subset(requested).expect("one foundation"))
        {
            continue;
        }
        roots.insert(record.fingerprint());
    }
    let records = closure.records_for(roots);
    for record in &records {
        if let CollectionRecord::Derive(derive) = record {
            images
                .entry((derive.collection(), derive.input()))
                .or_default()
                .insert(derive.output());
        }
        let record_support = closure
            .support(snapshot, *record)
            .map_err(|error| CollectionRealizationError::storage("read endorsed support", error))?
            .expect("accepted roots have closed witness DAGs");
        let alternatives = witnesses
            .entry((record.collection(), super::witness::output(*record)))
            .or_default();
        // Retain actual records, including equal-support signatures/routes.
        // Publication selects a small covering witness set when needed;
        // diagnostics and migrations must still see every persisted identity.
        alternatives.push((record.fingerprint(), record_support));
    }
    let discovered = super::DiscoveredCollectionRecords::from_records(records);
    // The selected closed DAG's distinct COMMIT payloads are exactly the
    // union of its accepted roots' supports. Build that PATCH once rather
    // than repeatedly unioning overlapping intermediate certificates.
    let support = Support::from_data(
        lineage.foundation,
        discovered.commits().iter().map(|commit| commit.data()),
    );
    let commits = discovered.commits().iter().copied().collect();
    let resolution =
        resolve_collection_semantics(&discovered, &lineage.source_by_target, &commits, |_| {
            Ok::<CollectionClaimValidation<()>, std::convert::Infallible>(
                CollectionClaimValidation::Accepted,
            )
        });

    match resolution {
        Ok(resolution) => Ok(CertifiedResolution {
            resolution,
            support,
            witnesses,
            images,
        }),
        Err(CollectionResolutionError::Validation { source, .. }) => match source {},
        Err(CollectionResolutionError::Conflict(conflict)) => {
            Err(CollectionRealizationError::Resolution(conflict.to_string()))
        }
    }
}

/// Fetch an existing target result before computing it, then only missing
/// immediate-source realizations. Historical foundation payloads and COMMIT
/// metadata are not dependencies of an endorsed result.
fn relevant_missing_dependency<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
    source: CollectionHandle,
    resolved: &TargetResolution<M::Target>,
    unavailable: &BTreeSet<CollectionData>,
) -> Result<Option<CollectionData>, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    for member in &resolved.dependencies {
        if !unavailable.contains(member) {
            return Ok(Some(*member));
        }
    }
    for ((collection, member), witnesses) in &resolved.witnesses {
        if *collection != target.handle() || unavailable.contains(member) {
            continue;
        }
        if witnesses.iter().all(|(_, support)| {
            support
                .is_subset(&resolved.support)
                .expect("one foundation")
        }) {
            continue;
        }
        if !snapshot
            .contains_blob(Handle::<M::Target>::from_hash(*member))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect existing target output", error)
            })?
        {
            return Ok(Some(*member));
        }
    }
    let mut resident = BTreeSet::new();
    for member in resolved.semantics.members(source).into_iter().flatten() {
        if snapshot
            .metadata(Handle::<M::Source>::from_hash(*member))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect immediate-source output", error)
            })?
            .is_some()
        {
            resident.insert(*member);
        }
    }
    let selected = collection_complete_physical_cover::<M::Source, _>(
        &resolved.semantics,
        source,
        &resident,
        snapshot,
    );
    Ok(selected
        .dependencies
        .into_iter()
        .chain(selected.physical.missing)
        .find(|member| !unavailable.contains(member)))
}

pub(super) struct TargetResolution<E: CollectionEncoding> {
    pub(super) semantics: CollectionSemantics,
    pub(super) witnesses: InputWitnesses,
    images: BTreeMap<(CollectionHandle, CollectionData), BTreeSet<CollectionData>>,
    dependencies: BTreeSet<CollectionData>,
    support: Support,
    pub(super) cover: Cover<E>,
    missing: BTreeSet<CollectionData>,
}

impl<E: CollectionEncoding> TargetResolution<E> {
    fn is_exact_for(&self, requested: &Support) -> bool {
        self.missing.is_empty() && self.support == *requested
    }

    fn incomplete_error(&self, requested: &Support) -> CollectionRealizationError {
        let represented: BTreeSet<_> = self.support.data_members().collect();
        CollectionRealizationError::IncompleteCover {
            missing: self.missing.iter().copied().collect(),
            unsupported_members: requested
                .data_members()
                .filter(|member| !represented.contains(member))
                .collect(),
        }
    }
}

fn resolve_target<R, E>(
    snapshot: &R,
    target: Collection<E>,
    lineage: &Lineage,
    requested: &Support,
    memo: &mut WitnessMemo,
) -> Result<TargetResolution<E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let certified = resolve_endorsed_lineage(
        snapshot,
        lineage,
        &BTreeSet::from([target.handle()]),
        Some(requested),
        memo,
    )?;
    resolve_certified_target(snapshot, target, lineage, requested, certified)
}

fn resolve_certified_target<R, E>(
    snapshot: &R,
    target: Collection<E>,
    lineage: &Lineage,
    requested: &Support,
    certified: CertifiedResolution,
) -> Result<TargetResolution<E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let semantics = certified.resolution.into_semantics();
    let target_handle = target.handle();
    let mut resident = BTreeSet::new();
    for member in semantics
        .members(target_handle)
        .into_iter()
        .flatten()
        .copied()
    {
        if snapshot
            .metadata(Handle::<E>::from_hash(member))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect target member residency", error)
            })?
            .is_some()
        {
            resident.insert(member);
        }
    }

    let (selected, represented) = witnessed_physical_cover::<E, _>(
        snapshot,
        &semantics,
        &certified.witnesses,
        target_handle,
        &resident,
        requested,
    )?;

    Ok(TargetResolution {
        support: Cover::from_data(
            lineage.foundation,
            requested
                .data_members()
                .filter(|member| represented.contains_data(*member)),
        ),
        cover: Cover::from_data(target, selected.physical.cover.iter().copied()),
        missing: selected.physical.missing,
        dependencies: selected.dependencies,
        witnesses: certified.witnesses,
        images: certified.images,
        semantics,
    })
}

/// Attach one target collection for exact caller-supplied support.
///
/// This fails unless all requested support is resident in the target. Authority
/// and realization are interpreted from this immutable store snapshot.
pub(crate) fn attach_collection_exact<R, E>(
    snapshot: &R,
    target: Collection<E>,
    requested: &Support,
) -> Result<(Support, Cover<E>), CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let resolved =
        attach_exact_resolution(snapshot, target, requested, &mut WitnessMemo::default())?;
    Ok((resolved.support, resolved.cover))
}

pub(super) fn attach_exact_resolution<R, E>(
    snapshot: &R,
    target: Collection<E>,
    requested: &Support,
    memo: &mut WitnessMemo,
) -> Result<TargetResolution<E>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let lineage = load_lineage(snapshot, target)?;
    let mut resolved = resolve_target(snapshot, target, &lineage, requested, memo)?;
    // An explicit root cover is also a low-level content selection: its
    // directly resident members need no COMMIT to be read. This does not
    // manufacture admission or an input witness. Ordinary collection
    // attachment and every equation publication still require real records.
    if target.handle() == lineage.foundation.handle() {
        for member in requested.data_members() {
            if !resolved.support.contains_data(member)
                && matches!(
                    collection_member_availability::<E, _>(member, snapshot).map_err(|error| {
                        CollectionRealizationError::storage("inspect explicit root member", error)
                    })?,
                    CollectionMemberAvailability::Complete
                )
            {
                resolved.support = resolved
                    .support
                    .union(&lineage.foundation.cover([Handle::from_hash(member)]))
                    .expect("one foundation");
                resolved.cover = resolved
                    .cover
                    .union(&target.cover([Handle::from_hash(member)]))
                    .expect("one target");
            }
        }
        if resolved.support == *requested {
            resolved.missing.clear();
            resolved.dependencies.clear();
        }
    }
    if !resolved.is_exact_for(requested) {
        return Err(resolved.incomplete_error(requested));
    }
    Ok(resolved)
}

/// Attach one target collection using its snapshot's proof and definition state.
///
/// The target's endorsed records define the search boundary. The result
/// contains only resident target members and the exact foundational support
/// their record witnesses establish. A static snapshot promises no future work.
pub(crate) fn attach_collection<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<(Support, Cover<E>), CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let lineage = load_lineage(snapshot, target)?;
    let certified = resolve_endorsed_lineage(
        snapshot,
        &lineage,
        &BTreeSet::from([target.handle()]),
        None,
        &mut WitnessMemo::default(),
    )?;
    let represented = certified.support.clone();
    let resolved = resolve_certified_target(snapshot, target, &lineage, &represented, certified)?;
    Ok((resolved.support, resolved.cover))
}

/// Expand only the exact endorsements retained by an immutable target read.
/// Ancestor authority and payloads remain the admitted producer's responsibility.
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
    let mut memo = WitnessMemo::default();
    let mut closure = memo.closure(lineage.foundation, &lineage.source_by_target);
    let mut support = Support::from_data(lineage.foundation, []);
    let mut incomplete = Vec::new();
    for record in records {
        match closure
            .support(snapshot, *record)
            .map_err(|error| CollectionRealizationError::storage("read support witnesses", error))?
        {
            Some(represented) => {
                support = support.union(&represented).expect("one foundation");
            }
            None => incomplete.push(record.fingerprint()),
        }
    }
    if incomplete.is_empty() {
        Ok(support)
    } else {
        Err(CollectionRealizationError::IncompleteSupport {
            records: incomplete,
        })
    }
}

struct MappingProbe<M: CollectionMapping> {
    source: Collection<M::Source>,
    mapping: M,
    target_resolution: TargetResolution<M::Target>,
}

/// Certify the target's lineage against the requested support and resolve
/// what the target already realizes. Pure: it reads the snapshot and plans no
/// acquisition. With `admit_source` the immediate source is certified beside
/// the target so its members can be selected; without it only the target's
/// own endorsement is read, the warm target-only path.
fn probe_mapping<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
    support: &Support,
    admit_source: bool,
    memo: &mut WitnessMemo,
) -> Result<MappingProbe<M>, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let lineage = load_lineage(snapshot, target)?;
    require_support(&lineage, support)?;
    let source_handle = lineage
        .source_by_target
        .get(&target.handle())
        .copied()
        .ok_or_else(|| {
            CollectionRealizationError::Resolution(
                "ensure requires a derived target descriptor".to_owned(),
            )
        })?;
    let source_descriptor = lineage.descriptor(source_handle);
    let target_descriptor = lineage.descriptor(target.handle());
    super::encoding::validate_descriptor_type::<M::Source>(source_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "mapping source descriptor has the wrong representation: {error}"
        ))
    })?;
    let mapping = M::bind(source_descriptor, target_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "target descriptor does not bind the requested mapping: {error}"
        ))
    })?;
    let mut selected = BTreeSet::from([target.handle()]);
    if admit_source {
        selected.insert(source_handle);
    }
    let certified = resolve_endorsed_lineage(snapshot, &lineage, &selected, Some(support), memo)?;
    // Image reuse crosses support witnesses, so its functional check must do
    // the same. A cold or support-pruned claim is still a certified equation;
    // residency must never decide which conflicting image we endorse next.
    // Only inputs admitted into this requested source slice are relevant.
    for input in certified
        .resolution
        .semantics()
        .members(source_handle)
        .into_iter()
        .flatten()
    {
        let mut outputs = certified
            .images
            .get(&(target.handle(), *input))
            .into_iter()
            .flatten();
        if let (Some(first), Some(second)) = (outputs.next(), outputs.next()) {
            return Err(CollectionRealizationError::Resolution(format!(
                "derivation into {} has conflicting outputs {} and {} for {}",
                hex::encode_upper(target.handle().raw),
                hex::encode_upper(first.raw),
                hex::encode_upper(second.raw),
                hex::encode_upper(input.raw),
            )));
        }
    }
    let target_resolution =
        resolve_certified_target(snapshot, target, &lineage, support, certified)?;
    Ok(MappingProbe {
        source: Collection::from_handle(source_handle),
        mapping,
        target_resolution,
    })
}

/// The acquisition step an `ensure` owes once the pure probe has shown that
/// the target is not exact for the requested support: fetch an existing
/// target result before computing it, then only missing immediate-source
/// realizations. A warm exact target needs no acquisition planning, so the
/// raw dangling equation frontier is consulted only after the semantic
/// snapshot proves that work remains; this keeps resident maintenance at one
/// indexed semantic probe per LSM round. Read-only residual selection never
/// calls this: a signed target equation whose output payload has not landed
/// yet must not stop a reader from selecting the resident source member it
/// names, which is the record-before-blob case the residual exists for.
fn demand_missing_dependency<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
    probe: &MappingProbe<M>,
    support: &Support,
    unavailable: &BTreeSet<CollectionData>,
) -> Result<(), CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    if probe.target_resolution.is_exact_for(support) {
        return Ok(());
    }
    if let Some(member) = relevant_missing_dependency::<_, M>(
        snapshot,
        target,
        probe.source.handle(),
        &probe.target_resolution,
        unavailable,
    )? {
        return Err(CollectionRealizationError::MissingDependency { member });
    }
    Ok(())
}

fn source_residual<R, M>(
    snapshot: &R,
    probe: &MappingProbe<M>,
    requested: &Support,
    blocked: &BTreeMap<CollectionData, String>,
) -> Result<
    Vec<(
        CollectionData,
        Blob<M::Source>,
        Vec<CollectionRecordFingerprint>,
    )>,
    CollectionRealizationError,
>
where
    R: BlobStoreGet + BlobStoreMeta,
    M: CollectionMapping,
{
    let semantics = &probe.target_resolution.semantics;
    let source = probe.source.handle();
    let mut resident = BTreeSet::new();
    for member in semantics.members(source).into_iter().flatten().copied() {
        if blocked.contains_key(&member) {
            continue;
        }
        if snapshot
            .metadata(Handle::<M::Source>::from_hash(member))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect source member residency", error)
            })?
            .is_some()
        {
            resident.insert(member);
        }
    }

    let needed = requested
        .difference(&probe.target_resolution.support)
        .expect("one foundation");
    let (selected, source_support) = witnessed_physical_cover::<M::Source, _>(
        snapshot,
        semantics,
        &probe.target_resolution.witnesses,
        source,
        &resident,
        &needed,
    )?;
    let missing: Vec<_> = needed
        .data_members()
        .filter(|member| !source_support.contains_data(*member))
        .collect();
    if !missing.is_empty() {
        if blocked.is_empty() {
            return Err(CollectionRealizationError::IncompleteCover {
                missing: selected.physical.missing.iter().copied().collect(),
                unsupported_members: missing,
            });
        }
        return Err(CollectionRealizationError::UnrepresentableCover {
            blocked: blocked
                .iter()
                .map(|(member, reason)| (*member, reason.clone()))
                .collect(),
            missing,
        });
    }

    let mut residual = Vec::new();
    for member in selected.physical.cover.iter().copied() {
        let alternatives = probe
            .target_resolution
            .witnesses
            .get(&(source, member))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let witnesses = witness_cover(alternatives, probe.target_resolution.support.clone());
        if witnesses.is_empty() {
            continue;
        }
        let blob = snapshot
            .get(Handle::<M::Source>::from_hash(member))
            .map_err(|error| {
                CollectionRealizationError::storage("load source member for mapping", error)
            })?;
        residual.push((member, blob, witnesses));
    }
    Ok(residual)
}

/// Ensure one immediate mapping for invariant foundational support.
///
/// Existing equations throughout the ancestry are reused, but new work only
/// maps resident immediate-source members and publishes target `DERIVE`
/// records. A missing immediate-source cover is an error: downstream ensure
/// never constructs upstream blobs.
#[cfg(test)]
fn ensure_exact_resident_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze exact mapping frontier", error)
    })?;
    let mut frontier = OperationFrontier::new(snapshot);
    ensure_exact_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        support,
        &BTreeSet::new(),
        &mut frontier,
        &mut WitnessMemo::default(),
    )
}

#[cfg(test)]
fn ensure_exact_resident<S, T>(
    store: &mut S,
    target: Collection<T>,
    signing_key: &SigningKey,
    support: &Support,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    T: CollectionDerivation,
{
    ensure_exact_resident_with::<S, CanonicalDerivation<T>>(store, target, signing_key, support)
}

fn ensure_exact_resident_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    memo: &mut WitnessMemo,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let mut blocked = BTreeMap::<CollectionData, String>::new();
    let mut published = BTreeSet::<CollectionRecordFingerprint>::new();

    loop {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("open exact mapping snapshot", error)
        })?);
        let probe = probe_mapping::<_, M>(&snapshot, target, support, true, memo)?;
        demand_missing_dependency::<_, M>(&snapshot, target, &probe, support, unavailable)?;
        if probe.target_resolution.is_exact_for(support) {
            return Ok(());
        }
        let repeated_cover = probe.target_resolution.cover.data_members().collect();
        let residual = source_residual(&snapshot, &probe, support, &blocked)?;
        let mapping = probe.mapping;
        let incomplete = probe.target_resolution.incomplete_error(support);

        if residual.is_empty() {
            return Err(incomplete);
        }
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Err(CollectionRealizationError::UnauthorizedProducer {
                collection: target.handle(),
            });
        }
        drop(snapshot);

        let mut replan = false;
        for (input_data, input, witnesses) in residual {
            if witnesses.iter().any(|witness| published.contains(witness)) {
                return Err(CollectionRealizationError::Stalled {
                    cover: repeated_cover,
                });
            }
            let snapshot = frontier.view(store.snapshot().map_err(|error| {
                CollectionRealizationError::storage("open mapping dependency snapshot", error)
            })?);
            let mut reusable = None;
            for member in probe
                .target_resolution
                .images
                .get(&(target.handle(), input_data))
                .into_iter()
                .flatten()
                .copied()
            {
                if matches!(
                    collection_member_availability::<M::Target, _>(member, &snapshot).map_err(
                        |error| CollectionRealizationError::storage(
                            "inspect existing mapping image",
                            error
                        )
                    )?,
                    CollectionMemberAvailability::Complete
                ) {
                    reusable = Some(
                        snapshot
                            .get(Handle::<M::Target>::from_hash(member))
                            .map_err(|error| {
                                CollectionRealizationError::storage(
                                    "reuse existing mapping image",
                                    error,
                                )
                            })?,
                    );
                    break;
                }
            }
            let output = match reusable {
                Some(output) => Ok(output),
                None => mapping.map(&input, &snapshot),
            };
            drop(snapshot);
            let output = match output {
                Ok(output) => output,
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Derive {
                        input: input_data,
                        reason,
                    });
                }
                Err(CollectionOperationError::Capacity(reason)) => {
                    blocked.insert(input_data, reason);
                    replan = true;
                    break;
                }
                Err(CollectionOperationError::MissingDependency(member)) => {
                    return Err(CollectionRealizationError::MissingDependency { member });
                }
            };
            let output_data = data_identity::<M::Target>(&output);
            store.put::<M::Target, _>(output).map_err(|error| {
                CollectionRealizationError::storage("store derived target member", error)
            })?;
            for witness in witnesses {
                let record = CollectionRecord::Derive(CollectionDerive::sign(
                    signing_key,
                    target.handle(),
                    (input_data, witness),
                    output_data,
                ));
                store.insert(record).map_err(|error| {
                    CollectionRealizationError::storage("publish target DERIVE", error)
                })?;
                frontier.include_record(record);
                published.insert(witness);
            }
        }
        if replan {
            continue;
        }
    }
}

/// Ensure one mapping and then carry its target lattice to the deterministic
/// LSM fixed point.
#[cfg(test)]
fn maintain_exact_resident_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze exact maintenance frontier", error)
    })?;
    let mut frontier = OperationFrontier::new(snapshot);
    maintain_exact_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        support,
        &BTreeSet::new(),
        &mut frontier,
        &mut WitnessMemo::default(),
    )
}

#[cfg(test)]
fn maintain_exact_resident<S, T>(
    store: &mut S,
    target: Collection<T>,
    signing_key: &SigningKey,
    support: &Support,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    T: CollectionDerivation,
{
    maintain_exact_resident_with::<S, CanonicalDerivation<T>>(store, target, signing_key, support)
}

fn maintain_exact_resident_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    memo: &mut WitnessMemo,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    ensure_exact_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        support,
        unavailable,
        frontier,
        memo,
    )?;
    let mapping = coarsen_from_resident_source::<S, M>(
        store,
        target,
        signing_key,
        support,
        unavailable,
        frontier,
        memo,
    )?;
    super::exact_target_compaction::maintain_target_with(
        store,
        target,
        signing_key,
        support,
        frontier,
        memo,
        |descriptor, low, high, reader| mapping.join_images(descriptor, None, low, high, reader),
    )
}

/// Reuse coarsening already paid for by the immediate source. This is optional
/// maintenance over an exact target, never coverage repair or upstream work.
/// Only the coarsest complete resident source cover is considered; unavailable
/// child images do not cause intermediate images to be constructed. Without
/// target WRITE authority, the existing exact finer realization is retained.
fn coarsen_from_resident_source<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    memo: &mut WitnessMemo,
) -> Result<M, CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("open source-guided maintenance snapshot", error)
        })?);
        let probe = probe_mapping::<_, M>(&snapshot, target, support, true, memo)?;
        demand_missing_dependency::<_, M>(&snapshot, target, &probe, support, unavailable)?;
        let semantics = &probe.target_resolution.semantics;
        let source = probe.source.handle();
        let mut resident = BTreeSet::new();
        for member in semantics.members(source).into_iter().flatten().copied() {
            if snapshot
                .metadata(Handle::<M::Source>::from_hash(member))
                .map_err(|error| {
                    CollectionRealizationError::storage(
                        "inspect source coarsening residency",
                        error,
                    )
                })?
                .is_some()
            {
                resident.insert(member);
            }
        }
        let (selected, _) = witnessed_physical_cover::<M::Source, _>(
            &snapshot,
            semantics,
            &probe.target_resolution.witnesses,
            source,
            &resident,
            support,
        )?;
        let target_cover = probe.target_resolution.cover.data_members().collect();
        let candidate = semantics
            .source_coarsenings(
                source,
                target.handle(),
                &selected.physical.cover,
                &target_cover,
            )
            .into_iter()
            .find(|(member, _)| !attempted.contains(member));
        let Some((input_data, image_pairs)) = candidate else {
            return Ok(probe.mapping);
        };
        let input_alternatives = probe
            .target_resolution
            .witnesses
            .get(&(source, input_data))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let input_witnesses = witness_cover(input_alternatives, support.collection().cover([]));
        if input_witnesses.is_empty() {
            attempted.insert(input_data);
            continue;
        }
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Ok(probe.mapping);
        }
        attempted.insert(input_data);
        let input: Blob<M::Source> = snapshot
            .get(Handle::<M::Source>::from_hash(input_data))
            .map_err(|error| {
                CollectionRealizationError::storage("load resident source coarsening", error)
            })?;
        let descriptor = super::api::load_collection_descriptor(&snapshot, target.handle())
            .map_err(|error| {
                CollectionRealizationError::Resolution(format!(
                    "load target descriptor for source-guided maintenance: {error}"
                ))
            })?
            .fragment;

        let mut joined = None;
        for (low_data, high_data) in image_pairs {
            let mut complete = true;
            for member in [low_data, high_data] {
                if !matches!(
                    collection_member_availability::<M::Target, _>(member, &snapshot).map_err(
                        |error| {
                            CollectionRealizationError::storage(
                                "inspect reusable target image",
                                error,
                            )
                        }
                    )?,
                    CollectionMemberAvailability::Complete
                ) {
                    complete = false;
                    break;
                }
            }
            if !complete {
                continue;
            }
            let low = snapshot
                .get(Handle::<M::Target>::from_hash(low_data))
                .map_err(|error| {
                    CollectionRealizationError::storage("load lower reusable target image", error)
                })?;
            let high = snapshot
                .get(Handle::<M::Target>::from_hash(high_data))
                .map_err(|error| {
                    CollectionRealizationError::storage("load higher reusable target image", error)
                })?;
            match probe
                .mapping
                .join_images(&descriptor, Some(&input), &low, &high, &snapshot)
            {
                Ok(Some(output)) => joined = Some((output, (low_data, high_data))),
                Ok(None)
                | Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => {}
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Merge {
                        low: low_data,
                        high: high_data,
                        reason,
                    });
                }
            }
            break;
        }
        let (output, pair) = match joined {
            Some((output, pair)) => (output, Some(pair)),
            None => match probe.mapping.map(&input, &snapshot) {
                Ok(output) => (output, None),
                Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => continue,
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Derive {
                        input: input_data,
                        reason,
                    });
                }
            },
        };
        let merge_witnesses = pair
            .map(|(low, high)| {
                merge_witness_pairs(
                    &probe.target_resolution.witnesses,
                    target.handle(),
                    low,
                    high,
                )
            })
            .transpose()?;
        drop(snapshot);
        let output_data = data_identity::<M::Target>(&output);
        store.put::<M::Target, _>(output).map_err(|error| {
            CollectionRealizationError::storage("store source-guided target member", error)
        })?;
        for (low, high) in merge_witnesses.into_iter().flatten() {
            let record = CollectionRecord::Merge(CollectionMerge::sign(
                signing_key,
                target.handle(),
                low,
                high,
                output_data,
            ));
            store.insert(record).map_err(|error| {
                CollectionRealizationError::storage("publish source-guided target MERGE", error)
            })?;
            frontier.include_record(record);
        }
        for witness in input_witnesses {
            let record = CollectionRecord::Derive(CollectionDerive::sign(
                signing_key,
                target.handle(),
                (input_data, witness),
                output_data,
            ));
            store.insert(record).map_err(|error| {
                CollectionRealizationError::storage("publish source-guided target DERIVE", error)
            })?;
            frontier.include_record(record);
        }
    }
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
    support: &Support,
    frontier: &OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
{
    let mut attempted = BTreeSet::new();
    let mut memo = WitnessMemo::default();
    loop {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe root realization", error)
        })?);
        let result = (|| {
            let lineage = load_lineage(&snapshot, target)?;
            if lineage.foundation != target {
                return Err(CollectionRealizationError::InvalidCover(
                    "a derived SimpleArchive target requires an explicit mapping".into(),
                ));
            }
            require_support(&lineage, support)?;
            let resolved = resolve_target(&snapshot, target, &lineage, support, &mut memo)?;
            if resolved.is_exact_for(support) {
                return Ok(());
            }
            // Explicit root covers remain useful for reading content without
            // publishing a COMMIT. New equations still require record witnesses.
            if support.available(&snapshot).map_err(|error| {
                CollectionRealizationError::storage("inspect explicit root cover", error)
            })? == *support
            {
                return Ok(());
            }
            if let Some(member) = resolved
                .dependencies
                .iter()
                .chain(&resolved.missing)
                .find(|member| !attempted.contains(*member))
                .copied()
            {
                return Err(CollectionRealizationError::MissingDependency { member });
            }
            Err(resolved.incomplete_error(support))
        })();
        drop(snapshot);
        let missing = match result {
            Ok(()) => return Ok(()),
            Err(CollectionRealizationError::MissingDependency { member }) => vec![member],
            Err(CollectionRealizationError::IncompleteCover {
                unsupported_members,
                ..
            }) => unsupported_members,
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
            return attach_collection_exact(&snapshot, target, support).map(|_| ());
        }
    }
}

/// A resident target endorsement is sufficient for reuse. Binding still checks
/// the requested encoding, mapping, and support foundation, but no immediate-
/// source producer or capability definition is needed until new work remains.
async fn prepare_exact_mapping<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    support: &Support,
    frontier: &OperationFrontier<S::Snapshot>,
    memo: &mut WitnessMemo,
) -> Result<bool, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    let resident = {
        let snapshot = frontier.view(store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe exact target before acquisition", error)
        })?);
        match probe_mapping::<_, M>(&snapshot, target, support, false, memo) {
            Ok(probe) => probe.target_resolution.is_exact_for(support),
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

pub(crate) async fn ensure_exact_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    let mut memo = WitnessMemo::default();
    if prepare_exact_mapping::<S, M>(store, target, support, frontier, &mut memo).await? {
        return Ok(());
    }
    let mut attempted = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    loop {
        match ensure_exact_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            support,
            &unavailable,
            frontier,
            &mut memo,
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

pub(crate) async fn maintain_exact_in_frontier_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    support: &Support,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    // Warm maintenance may still coarsen the target, but source-guided
    // opportunities are optional and must use only already resident evidence.
    let mut memo = WitnessMemo::default();
    prepare_exact_mapping::<S, M>(store, target, support, frontier, &mut memo).await?;
    let mut attempted = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    loop {
        match maintain_exact_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            support,
            &unavailable,
            frontier,
            &mut memo,
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
