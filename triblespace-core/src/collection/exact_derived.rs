//! Realization operations and their acquisition loop.
//!
//! A collection's support is a cover of its own foundations: commit payloads
//! in a root, leaf images in a derived collection. `ensure` on a derived
//! collection derives the maintaining key's own missing leaves; `maintain`
//! also mirrors its own source merges; `maintain` on a root carries the
//! key's own nodes. None of them manufactures an upstream dependency as a
//! side effect of downstream work, and none reads another owner's payload.

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
    descriptor, Collection, CollectionData, CollectionEncoding, CollectionHandle, CollectionMapping,
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
    /// The target encoding could not join one group of own nodes.
    Merge {
        /// The inputs of the join, ascending.
        inputs: Vec<CollectionData>,
        /// Concrete construction failure.
        reason: String,
    },
    /// A required mapping input names an immutable blob absent from the
    /// current store snapshot.
    MissingDependency {
        /// Exact missing content identity.
        member: CollectionData,
    },
    /// Own source foundations the mapping cannot represent as leaves: its
    /// capacity refused them, or their bytes or a dependency could not be
    /// acquired. Everything else was derived and mirrored.
    Unmappable {
        /// Each foundation left without a leaf, and why.
        blocked: Vec<(CollectionData, String)>,
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
            Self::Merge { inputs, reason } => write!(
                formatter,
                "join {} collection element(s) {}: {reason}",
                inputs.len(),
                name_some(inputs.iter().map(|m| hex::encode_upper(m.raw))),
            ),
            Self::MissingDependency { member } => write!(
                formatter,
                "mapping requires resident blob {}",
                hex::encode_upper(member.raw),
            ),
            Self::Unmappable { blocked } => write!(
                formatter,
                "{} own source foundation(s) have no leaf the mapping can represent: {}",
                blocked.len(),
                name_some(
                    blocked
                        .iter()
                        .map(|(member, reason)| format!("{} ({reason})", hex::encode_upper(member.raw))),
                ),
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

/// Runtime descriptor ancestry from one `SimpleArchive` root to a typed
/// target. Maintenance binds a mapping through it; nothing reads another
/// collection's coverage through it.
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

/// Derive the key's own missing leaves through one mapping, in one frozen
/// operation, without acquisition.
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
    let snapshot = store
        .snapshot()
        .map_err(|error| CollectionRealizationError::storage("freeze mapping frontier", error))?;
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
    super::maintenance::maintain_derived::<S, M>(
        store,
        target,
        signing_key,
        unavailable,
        frontier,
        false,
    )
}

/// Derive the key's own missing leaves and mirror its own source merges
/// through one mapping, in one frozen operation, without acquisition.
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
    super::maintenance::maintain_derived::<S, M>(
        store,
        target,
        signing_key,
        unavailable,
        frontier,
        true,
    )
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

/// Acquire the reusable authority definitions for a target and its immediate
/// source: descriptors, policy definitions, and the definitions the proofs
/// admitting their roots reference. This is acquisition, not an operation:
/// it reads fresh snapshots and publishes nothing. No member payload is
/// followed until its producer has been admitted.
pub(crate) async fn acquire_authority<S, E>(
    store: &mut S,
    target: Collection<E>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    E: CollectionEncoding,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe authority definitions", error)
        })?;
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

/// Make a root readable on every admitted commit, whoever wrote it,
/// acquiring what is missing: what `ensure` on a root does. This publishes
/// nothing, so it needs no operation: every look is a fresh snapshot, and a
/// commit admitted while it runs is simply seen. Maintenance never waits on
/// it: a root's carry reads only its maintainer's own nodes.
pub(crate) async fn ensure_root<S>(
    store: &mut S,
    target: Collection<SimpleArchive>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe root realization", error)
        })?;
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
            let snapshot = store.snapshot().map_err(|error| {
                CollectionRealizationError::storage("observe incomplete root realization", error)
            })?;
            return super::maintenance::root_incomplete(&snapshot, target);
        }
    }
}

/// Run one operation against a fresh control snapshot, acquiring what it
/// names as missing and running it again from a fresh snapshot after every
/// acquisition. An operation never sees bytes, records, or proofs that
/// arrived while it ran; the next one sees all of them, which is what makes
/// an acquired definition or descriptor count without re-deciding anything
/// inside the operation that asked for it.
async fn acquiring<S, F>(store: &mut S, mut operation: F) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    F: FnMut(
        &mut S,
        &BTreeSet<CollectionData>,
        &mut OperationFrontier<S::Snapshot>,
    ) -> Result<(), CollectionRealizationError>,
{
    let mut attempted = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    loop {
        let missing = {
            let mut frontier = OperationFrontier::new(store.snapshot().map_err(|error| {
                CollectionRealizationError::storage("freeze operation control snapshot", error)
            })?);
            match operation(store, &unavailable, &mut frontier) {
                Err(CollectionRealizationError::MissingDependency { member }) => member,
                result => return result,
            }
        };
        // The operation is over and its control snapshot released before
        // anything is fetched: acquisition holds no view of the store.
        if attempted.contains(&missing) {
            return Err(CollectionRealizationError::MissingDependency { member: missing });
        }
        if !acquire_missing(store, &mut attempted, missing).await? {
            unavailable.insert(missing);
        }
    }
}

pub(crate) async fn ensure_acquiring_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    acquiring(store, |store, unavailable, frontier| {
        ensure_resident_in_frontier_with::<S, M>(store, target, signing_key, unavailable, frontier)
    })
    .await
}

pub(crate) async fn maintain_acquiring_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: CollectionMapping,
{
    acquiring(store, |store, unavailable, frontier| {
        maintain_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            unavailable,
            frontier,
        )
    })
    .await
}

/// Carry the key's own nodes of one root, acquiring an own node whose bytes
/// are elsewhere. Nobody else's payload is asked for.
pub(crate) async fn maintain_root_acquiring<S, E>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    E: CollectionEncoding,
{
    acquiring(store, |store, unavailable, frontier| {
        super::maintenance::carry_root(store, target, signing_key, unavailable, frontier)
    })
    .await
}

pub(super) fn data_identity<E: CollectionEncoding>(blob: &Blob<E>) -> CollectionData {
    Handle::<E>::to_hash(blob.get_handle())
}

#[cfg(test)]
mod tests;
