//! Realization operations and their acquisition loop.
//!
//! A collection's support is a cover of its own foundations: commit payloads
//! in a root, leaf images in a derived collection. `ensure` on a derived
//! collection derives the maintaining key's own missing leaves; `maintain`
//! derives every foundation without a usable leaf this host can derive and
//! carries the collection's own leaf images into the host's merges;
//! `maintain` on a root carries every node the store holds, whoever signed
//! the foundations beneath it, into the host's own merges. None of them
//! manufactures an upstream dependency as a side effect of downstream work,
//! none reads a source's merges, and none fetches another owner's payload.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use ed25519_dalek::SigningKey;
use rand::seq::SliceRandom;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{BlobStoreGet, BlobStoreList, Store, StoreRead};
use crate::trible::Fragment;

use super::operation_snapshot::OperationFrontier;
use super::{
    descriptor, Collection, CollectionData, CollectionEncoding, CollectionHandle, DeriveMapping,
    MapMapping,
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
    /// The target encoding could not join one group of held nodes.
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
    /// capacity refused them, a dependency of the mapping could not be
    /// acquired, or the payload of a root commit could not be. Everything
    /// else was derived and carried.
    Unmappable {
        /// Each foundation left without a leaf, and why.
        blocked: Vec<(CollectionData, String)>,
    },
    /// Publication made no observable progress.
    Stalled {
        /// Repeated target cover in canonical content order.
        cover: Vec<CollectionData>,
    },
    /// A MERGE was about to be signed with a key whose MERGEs the store
    /// does not fold: the store was opened with another host, or with none.
    /// Open it as the maintaining key.
    HostMismatch {
        /// The key whose MERGEs the store folds, if any.
        host: Option<Inline<ED25519PublicKey>>,
        /// The key maintenance signs with.
        signer: Inline<ED25519PublicKey>,
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
            Self::HostMismatch { host, signer } => write!(
                formatter,
                "maintenance signs with {} but the store folds the MERGEs of {}; open the store as the signing key",
                hex::encode_upper(signer.raw),
                host.map_or_else(|| "no key".to_owned(), |host| hex::encode_upper(host.raw)),
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
        // An attached collection is no lattice: it has no carry, no leaves
        // and no merges of its own, and nothing derives from it.
        if !descriptor::parents(loaded.fragment.facts())
            .map_err(|error| {
                CollectionRealizationError::Resolution(format!(
                    "decode collection parent for {}: {error}",
                    hex::encode_upper(cursor.raw),
                ))
            })?
            .is_empty()
        {
            return Err(CollectionRealizationError::InvalidCover(format!(
                "collection {} is an attached collection; maintain it through its mapping",
                hex::encode_upper(cursor.raw),
            )));
        }
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
    M: DeriveMapping,
{
    let snapshot = store
        .snapshot()
        .map_err(|error| CollectionRealizationError::storage("freeze mapping frontier", error))?;
    let mut frontier = OperationFrontier::new(snapshot);
    ensure_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        &Unfetched::default(),
        &mut Vec::new(),
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
    unfetched: &Unfetched,
    wanted: &mut Vec<Vec<CollectionData>>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    super::maintenance::maintain_derived::<S, M>(
        store,
        target,
        signing_key,
        unfetched,
        wanted,
        frontier,
        false,
    )
}

/// Derive every foundation without a usable leaf and carry the target's own
/// lattice through one mapping, in one frozen operation, without
/// acquisition: a foundation whose leaves' outputs are not here waits.
#[cfg(test)]
fn maintain_resident_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    let snapshot = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze maintenance frontier", error)
    })?;
    let mut frontier = OperationFrontier::new(snapshot);
    maintain_resident_in_frontier_with::<S, M>(
        store,
        target,
        signing_key,
        &Unfetched::default(),
        &mut Vec::new(),
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
    unfetched: &Unfetched,
    wanted: &mut Vec<Vec<CollectionData>>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    super::maintenance::maintain_derived::<S, M>(
        store,
        target,
        signing_key,
        unfetched,
        wanted,
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
/// commit admitted while it runs is simply seen. A host merge standing for
/// several missing payloads is fetched before them; another key's merge is
/// not believed here, so commits no host merge covers are fetched one by
/// one. Maintenance never waits on it: a root's carry merges what is held
/// and fetches nothing.
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

/// How many optional fetches one call lets fail before it starts on no
/// further group of them.
///
/// Through a store that asks other holders a failed fetch can wait out a
/// network deadline -- `triblespace-net` gives an interactive fetch ten
/// seconds -- so this bounds what one call spends on blobs nobody hands over,
/// and on fetches that fail outright. A fetch that succeeds is not counted.
/// What an operation went on without comes in groups, each of which one blob
/// completes -- for derive scheduling, the outputs of one foundation's
/// leaves, any one of which is a usable leaf -- and a group once started is
/// asked to the end: until one of its blobs arrives or every one has failed,
/// so a foundation with more unavailable outputs than this is still decided
/// in one call. One call therefore lets fewer than eight fetches fail before
/// the last group it starts, plus that group's own.
///
/// Each call starts the groups in an order drawn afresh. A call keeps no
/// memory of the last one -- a faculty's store lives for one command -- and
/// with nothing new arriving two calls would otherwise make the same
/// choices, spending every call's failures on the same leading groups and
/// never reaching the rest. With a fresh order a group is started whenever
/// fewer than eight fetches failed in the groups drawn before it: at least
/// when it is drawn first, and, when every group holds one blob (one leaf
/// per foundation), whenever it is among the first eight. So of `n` groups
/// waiting, a given one is reached in a call with probability at least
/// `1/n`, and at least `min(8, n)/n` when every group holds one blob: within
/// `n` calls in expectation, or `n/8` in the one-blob case.
const OPTIONAL_FETCH_FAILURES: usize = 8;

/// The blobs one call asked for and did not get.
#[derive(Default)]
pub(super) struct Unfetched {
    /// No holder handed these over: an answer about elsewhere, so a leaf
    /// naming one of them as its output does not count.
    pub(super) unavailable: BTreeSet<CollectionData>,
    /// Fetching these failed outright -- the store could not ask other
    /// holders, or could not keep what it got. That is a fault here and says
    /// nothing about any holder, so a leaf naming one of them is not given
    /// up on: its foundation waits.
    pub(super) failed: BTreeSet<CollectionData>,
}

impl Unfetched {
    /// Whether `member` was asked for and is not here, for either reason:
    /// for this call, what needs it waits.
    pub(super) fn contains(&self, member: &CollectionData) -> bool {
        self.unavailable.contains(member) || self.failed.contains(member)
    }
}

/// Run one operation against a fresh control snapshot, acquiring what it
/// names as missing and running it again from a fresh snapshot after every
/// acquisition. An operation never sees bytes, records, or proofs that
/// arrived while it ran; the next one sees all of them, which is what makes
/// an acquired definition or descriptor count without re-deciding anything
/// inside the operation that asked for it.
///
/// A blob the operation needs ends it with
/// [`CollectionRealizationError::MissingDependency`], one at a time. Blobs it
/// could use but went on without -- the outputs of leaves that are not here
/// -- it names in `wanted`, grouped so that any one blob of a group
/// completes it, and finishes its work; those are asked for together
/// afterwards, each once per call and within [`OPTIONAL_FETCH_FAILURES`], and
/// the operation runs once more if any was. They are asked for only through
/// a store that can reach other holders
/// ([`AsyncBlobStoreAcquire::acquires_remotely`]): from one that cannot, a
/// miss says nothing about elsewhere, so what it names waits.
///
/// An operation that reports something after its work -- a foundation its
/// mapping refused, a carry that failed -- has its `wanted` asked for, and
/// runs again, before that report is returned: nothing it reports holds back
/// a fetch. Only a storage error ends the call at once.
///
/// Every blob asked for and not got is [`Unfetched`] for the rest of the
/// call, and the operation is told which and why. A fetch that fails
/// outright is a fault here, not an answer about elsewhere, whichever role
/// the blob plays -- needed by one foundation, the output of another's leaf,
/// or both: it is never counted unavailable. What needs the blob waits, as
/// for any blob it cannot have; nothing is done in its place -- no
/// foundation is derived again for a leaf whose output a fault kept out --
/// and the next call asks for it again. Only a blob no holder handed over is
/// unavailable. The first such error is reported once the work is done, in
/// preference to what the operation reported, except a signer that is not
/// the store's host ([`CollectionRealizationError::HostMismatch`]): that
/// stops a whole upkeep pass, so it is reported first. A storage error the
/// operation itself raises ends the call at once and is the one reported.
async fn acquiring<S, F>(store: &mut S, mut operation: F) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    F: FnMut(
        &mut S,
        &Unfetched,
        &mut Vec<Vec<CollectionData>>,
        &mut OperationFrontier<S::Snapshot>,
    ) -> Result<(), CollectionRealizationError>,
{
    let mut attempted = BTreeSet::new();
    let mut unfetched = Unfetched::default();
    let mut failures = 0;
    let mut broken = None;
    loop {
        let mut wanted = Vec::new();
        let result = {
            let mut frontier = OperationFrontier::new(store.snapshot().map_err(|error| {
                CollectionRealizationError::storage("freeze operation control snapshot", error)
            })?);
            operation(store, &unfetched, &mut wanted, &mut frontier)
        };
        // The operation is over and its control snapshot released before
        // anything is fetched: acquisition holds no view of the store.
        let reported = match result {
            Ok(()) => None,
            Err(error @ CollectionRealizationError::Storage { .. }) => return Err(error),
            Err(CollectionRealizationError::MissingDependency { member })
                if !attempted.contains(&member) =>
            {
                ask(store, &mut attempted, &mut unfetched, &mut broken, member).await;
                continue;
            }
            Err(error) => Some(error),
        };
        if store.acquires_remotely() && failures < OPTIONAL_FETCH_FAILURES {
            wanted.shuffle(&mut rand::thread_rng());
            let mut asked = false;
            for group in wanted {
                if failures >= OPTIONAL_FETCH_FAILURES {
                    break;
                }
                for member in group {
                    if attempted.contains(&member) {
                        continue;
                    }
                    asked = true;
                    if ask(store, &mut attempted, &mut unfetched, &mut broken, member).await {
                        break;
                    }
                    failures += 1;
                }
            }
            if asked {
                continue;
            }
        }
        return match (broken, reported) {
            (_, Some(error @ CollectionRealizationError::HostMismatch { .. })) => Err(error),
            (Some(error), _) | (None, Some(error)) => Err(error),
            (None, None) => Ok(()),
        };
    }
}

/// Ask for one blob this call has not asked for: whether its bytes are here
/// now. One no holder handed over is recorded `unavailable`; one whose fetch
/// failed outright is recorded `failed`, and the first such error is kept in
/// `broken`, to be reported once the work is done.
async fn ask<S>(
    store: &mut S,
    attempted: &mut BTreeSet<CollectionData>,
    unfetched: &mut Unfetched,
    broken: &mut Option<CollectionRealizationError>,
    member: CollectionData,
) -> bool
where
    S: AsyncBlobStoreAcquire,
{
    match acquire_missing(store, attempted, member).await {
        Ok(true) => true,
        Ok(false) => {
            unfetched.unavailable.insert(member);
            false
        }
        Err(error) => {
            unfetched.failed.insert(member);
            broken.get_or_insert(error);
            false
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
    M: DeriveMapping,
{
    acquiring(store, |store, unfetched, wanted, frontier| {
        ensure_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            unfetched,
            wanted,
            frontier,
        )
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
    M: DeriveMapping,
{
    acquiring(store, |store, unfetched, wanted, frontier| {
        maintain_resident_in_frontier_with::<S, M>(
            store,
            target,
            signing_key,
            unfetched,
            wanted,
            frontier,
        )
    })
    .await
}

/// Map the named source foundations again through one mapping, adding a
/// leaf wherever the result is not already a leaf's output, acquiring each
/// payload that is not here.
pub(crate) async fn rederive_acquiring_with<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    source: CollectionHandle,
    foundations: &BTreeSet<CollectionData>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: DeriveMapping,
{
    let mut done = BTreeSet::new();
    acquiring(store, |store, unfetched, _wanted, frontier| {
        super::maintenance::rederive::<S, M>(
            store,
            target,
            source,
            foundations,
            &mut done,
            signing_key,
            unfetched,
            frontier,
        )
    })
    .await
}

/// Carry every held node of one root into the host's merges. No frontier
/// node is fetched: one whose bytes are not here sits out, so the loop
/// acquires only what the root's lineage names (its descriptor) and never
/// restarts for a payload.
pub(crate) async fn maintain_root_acquiring<S, E>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    E: CollectionEncoding,
{
    acquiring(store, |store, _unfetched, _wanted, frontier| {
        super::maintenance::carry_root(store, target, signing_key, frontier)
    })
    .await
}

/// Acquire an attached collection's descriptor and its parent's: all an
/// attachment needs to be bound. Neither carries a policy the attachment
/// answers to, so nothing else is fetched.
pub(crate) async fn acquire_attached_lineage<S, E>(
    store: &mut S,
    attached: Collection<E>,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    E: CollectionEncoding,
{
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = store.snapshot().map_err(|error| {
            CollectionRealizationError::storage("observe attached lineage", error)
        })?;
        let result = super::maintenance::attached_lineage(&snapshot, attached);
        drop(snapshot);
        match result {
            Ok(_) => return Ok(()),
            Err(CollectionRealizationError::MissingDependency { member }) => {
                if acquire_missing(store, &mut attempted, member).await? {
                    continue;
                }
                return Err(CollectionRealizationError::MissingDependency { member });
            }
            Err(error) => return Err(error),
        }
    }
}

/// Give the parent's frontier nodes their missing attachments through one
/// mapping, acquiring what the mapping names as missing and running again.
pub(crate) async fn attach_acquiring_with<S, M>(
    store: &mut S,
    attached: Collection<M::Target>,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
    M: MapMapping,
{
    acquiring(store, |store, unfetched, _wanted, frontier| {
        super::maintenance::attach_frontier::<S, M>(
            store,
            attached,
            signing_key,
            unfetched,
            frontier,
        )
    })
    .await
}

pub(super) fn data_identity<E: CollectionEncoding>(blob: &Blob<E>) -> CollectionData {
    Handle::<E>::to_hash(blob.get_handle())
}

#[cfg(test)]
mod tests;
