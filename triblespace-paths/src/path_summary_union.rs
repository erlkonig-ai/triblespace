//! Canonical path-summary union and its derivation from `SimpleArchive`.
//!
//! One collection is fixed by an extrinsic dataset scope and one canonical
//! path automaton. Its elements retain only the graph domain and direct
//! product arcs required by that automaton; their join is exact set union.
//! Lowering graph facts into those direct arcs is therefore a join
//! homomorphism:
//!
//! ```text
//! paths(a ∪ b) = paths(a) ⊔ paths(b)
//! ```
//!
//! Transitive closure is deliberately absent from the collection law. It is
//! performed once when a [`PathIndex`](crate::PathIndex) is materialized, so
//! paths whose edges live in different source fragments remain discoverable.
//!
//! Reading is split in three steps with different trust. Attaching a
//! [`PathSummaryView`] is typed and structural: it keeps the resident members
//! and the automaton they name and checks nothing but the 32-byte handle each
//! member carries against the collection's. [`PathSummaryView::prepare`] is
//! the query computation: it decodes the members structurally, merges the
//! decoded summaries once and closes the union, so cross-member paths stay
//! discoverable without encoding any intermediate join. The canonical audit
//! is explicit: [`CollectionEncoding::validate_member`] and the producer's
//! [`join_members`](CollectionEncoding::join_members) re-prove the bytes;
//! a warm read never re-encodes or hashes to believe a stored equation.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use triblespace_core::prelude::entity;

use triblespace_core::attribute::Attribute;
use triblespace_core::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use triblespace_core::blob::Blob;
use triblespace_core::collection::descriptor;
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::simplearchive_union;
use triblespace_core::collection::{
    CollectionData, CollectionDerivation, CollectionEncoding, CollectionOperationError, Cover,
    TryFromCover, TryFromCoverError,
};
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::id_hex;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace_core::inline::encodings::iu256::U256BE;
use triblespace_core::inline::{Inline, TryFromInline};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

use crate::persistence::{
    path_automaton_accepting_state, path_automaton_fingerprint, path_automaton_initial_state,
    path_automaton_state_count, path_automaton_transition, path_transition_from,
    path_transition_kind, path_transition_label, path_transition_to, PathAutomatonBlob,
    PathAutomatonBlobError,
};
use crate::{
    Automaton, GraphEdge, PathError, PathIndex, PathSummary, PathSummaryBlob, PathSummaryBlobError,
    Step, Transition,
};

/// Failure to lower one canonical source member through the regular-path mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegularPathMappingError {
    /// The source is not a canonical `SimpleArchive`.
    Source(UnarchiveError),
    /// Path-summary encoding failed.
    Summary(PathSummaryBlobError),
}

impl fmt::Display for RegularPathMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(source) => write!(formatter, "invalid SimpleArchive source: {source}"),
            Self::Summary(source) => write!(formatter, "invalid path-summary element: {source}"),
        }
    }
}

impl Error for RegularPathMappingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(source) => Some(source),
            Self::Summary(source) => Some(source),
        }
    }
}

/// Stable identity of the canonical regular-path mapping algorithm.
///
/// Minted with `trible genid` on 2026-08-29.
pub const REGULAR_PATH_MAPPING_V1: Id = id_hex!("EB6B81A38B71AC1B7EA0806A9A48DAB5");

/// Self-description of the canonical `SimpleArchive -> PathSummaryBlob` mapping.
pub struct RegularPathMappingV1;

impl MetaDescribe for RegularPathMappingV1 {
    fn describe() -> Fragment {
        let id = REGULAR_PATH_MAPPING_V1;
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "regular-path-mapping-v1",
                metadata::description: "Canonical join-preserving conversion from a SimpleArchive trible set to the direct-product summary of one concrete epsilon-free regular-path automaton. The content-derived mapping instance carries the complete automaton and its checked fingerprint.",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

fn mapping_fragment(automaton: &Automaton) -> Fragment {
    let automaton_blob = PathAutomatonBlob::encode(automaton);
    let fingerprint = Inline::new(automaton_blob.get_handle().raw);
    let mut fragment = mapping_fragment_with_fingerprint(automaton, fingerprint);
    let attached = fragment.put::<PathAutomatonBlob, _>(automaton_blob);
    debug_assert_eq!(attached.raw, fingerprint.raw);
    fragment
}

fn mapping_fragment_with_fingerprint(
    automaton: &Automaton,
    fingerprint: Inline<Hash<Blake3>>,
) -> Fragment {
    let transitions = automaton
        .transitions()
        .iter()
        .map(transition_fragment)
        .fold(Fragment::empty(), |mut transitions, transition| {
            transitions += transition;
            transitions
        });
    entity! { _ @
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <RegularPathMappingV1 as MetaDescribe>::describe(),
        path_automaton_fingerprint: fingerprint,
        path_automaton_state_count: automaton.state_count(),
        path_automaton_initial_state*: automaton.initial_states(),
        path_automaton_accepting_state*: automaton.accepting_states(),
        path_automaton_transition*: transitions,
    }
}

fn transition_fragment(transition: &Transition) -> Fragment {
    let (kind, labels): (u32, &[triblespace_core::id::RawId]) = match &transition.step {
        Step::Forward(label) => (0, std::slice::from_ref(label)),
        Step::Reverse(label) => (1, std::slice::from_ref(label)),
        Step::ForwardExcept(labels) => (2, labels),
        Step::ReverseExcept(labels) => (3, labels),
    };
    let labels = labels
        .iter()
        .copied()
        .map(u128::from_be_bytes)
        .collect::<Vec<_>>();
    entity! { _ @
        path_transition_from: transition.from,
        path_transition_to: transition.to,
        path_transition_kind: kind,
        path_transition_label*: labels,
    }
}

fn descriptor_automaton_handle(
    descriptor_fragment: &Fragment,
) -> Result<Inline<Handle<PathAutomatonBlob>>, CollectionOperationError> {
    let raw =
        descriptor::mapping_argument(descriptor_fragment.facts(), path_automaton_fingerprint.id())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal(
                    "regular-path mapping is missing path_automaton_fingerprint".to_owned(),
                )
            })?;
    Ok(Inline::new(raw))
}

fn require_member_automaton(
    descriptor: &Fragment,
    member: &Blob<PathSummaryBlob>,
) -> Result<Inline<Handle<PathAutomatonBlob>>, CollectionOperationError> {
    let expected = descriptor_automaton_handle(descriptor)?;
    let actual = PathSummaryBlob::automaton_handle(member)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    if actual != expected {
        return Err(CollectionOperationError::Fatal(
            "path-summary member names an automaton outside its collection".to_owned(),
        ));
    }
    Ok(actual)
}

fn resident_automaton<R>(
    handle: Inline<Handle<PathAutomatonBlob>>,
    reader: &R,
) -> Result<Automaton, CollectionOperationError>
where
    R: triblespace_core::repo::BlobStoreGet + triblespace_core::repo::BlobStoreMeta,
{
    let resident = reader
        .metadata(handle)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
        .is_some();
    if !resident {
        return Err(CollectionOperationError::MissingDependency(Handle::<
            PathAutomatonBlob,
        >::to_hash(
            handle
        )));
    }
    let blob: Blob<PathAutomatonBlob> = reader
        .get(handle)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    PathAutomatonBlob::audit(&blob)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
}

/// Bind the canonical path-summary collection to the automaton named by its
/// mapping while loading representation semantics from each member's exact
/// immutable automaton child.
impl CollectionEncoding for PathSummaryBlob {
    fn validate_descriptor(descriptor: &Fragment) -> Result<(), CollectionOperationError> {
        let source = descriptor::source(descriptor.facts())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        if source.is_none() {
            return Err(CollectionOperationError::Fatal(
                "path-summary descriptor is missing its source collection".to_owned(),
            ));
        }
        automaton_from_descriptor(descriptor).map(|_| ())
    }

    fn validate_member<R>(
        descriptor: &Fragment,
        member: &Blob<Self>,
        reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: triblespace_core::repo::BlobStoreGet + triblespace_core::repo::BlobStoreMeta,
    {
        let handle = require_member_automaton(descriptor, member)?;
        let automaton = resident_automaton(handle, reader)?;
        PathSummaryBlob::audit(member.clone(), &automaton)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        Ok(())
    }

    fn missing_representation_dependencies<R>(
        member: CollectionData,
        reader: &R,
    ) -> Result<Vec<CollectionData>, CollectionOperationError>
    where
        R: triblespace_core::repo::BlobStoreGet + triblespace_core::repo::BlobStoreMeta,
    {
        let root = reader
            .get::<Blob<Self>, Self>(Handle::<Self>::from_hash(member))
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        let automaton = PathSummaryBlob::automaton_handle(&root)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        let resident = reader
            .metadata(automaton)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .is_some();
        Ok(if resident {
            Vec::new()
        } else {
            vec![Handle::<PathAutomatonBlob>::to_hash(automaton)]
        })
    }

    fn join_members<R>(
        descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: triblespace_core::repo::BlobStoreGet + triblespace_core::repo::BlobStoreMeta,
    {
        let low_automaton = require_member_automaton(descriptor, low)?;
        let high_automaton = require_member_automaton(descriptor, high)?;
        if low_automaton != high_automaton {
            return Err(CollectionOperationError::Fatal(
                "cannot join path summaries for different automata".to_owned(),
            ));
        }
        let automaton = resident_automaton(low_automaton, reader)?;
        PathSummaryBlob::join(low, high, &automaton).map_err(summary_operation_error)
    }
}

impl CollectionDerivation for PathSummaryBlob {
    type Source = SimpleArchive;
    type Argument = Automaton;

    fn fragment(automaton: &Self::Argument) -> Fragment {
        mapping_fragment(automaton)
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        require_regular_path_mapping(target)?;
        automaton_from_descriptor(target)
    }

    fn map<R>(
        automaton: &Self::Argument,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: triblespace_core::repo::BlobStoreGet + triblespace_core::repo::BlobStoreMeta,
    {
        let automaton_handle = PathAutomatonBlob::encode(automaton).get_handle();
        let resident = reader
            .metadata(automaton_handle)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .is_some();
        if !resident {
            return Err(CollectionOperationError::MissingDependency(Handle::<
                PathAutomatonBlob,
            >::to_hash(
                automaton_handle,
            )));
        }
        derive_element(source, automaton).map_err(|source| match source {
            RegularPathMappingError::Summary(PathSummaryBlobError::CapacityOverflow) => {
                CollectionOperationError::Capacity(source.to_string())
            }
            RegularPathMappingError::Source(_) | RegularPathMappingError::Summary(_) => {
                CollectionOperationError::Fatal(source.to_string())
            }
        })
    }
}

fn summary_operation_error(source: PathSummaryBlobError) -> CollectionOperationError {
    match source {
        PathSummaryBlobError::CapacityOverflow => {
            CollectionOperationError::Capacity(source.to_string())
        }
        _ => CollectionOperationError::Fatal(source.to_string()),
    }
}

/// A lazy logical path-summary value retaining its exact physical members.
///
/// Attaching one is typed and structural: the resident members are kept as
/// stored, each checked only for naming the collection's automaton by the
/// 32-byte handle it carries, and that automaton is decoded once from its
/// content-addressed blob. Closure is intentionally not part of the
/// collection law; [`prepare`](Self::prepare) computes it when a query needs
/// the [`PathIndex`].
pub struct PathSummaryView {
    cover: Cover<PathSummaryBlob>,
    segments: Vec<(Inline<Handle<PathSummaryBlob>>, Blob<PathSummaryBlob>)>,
    automaton_handle: Inline<Handle<PathAutomatonBlob>>,
    automaton: Automaton,
}

impl PathSummaryView {
    /// Exact typed physical cover represented by this view.
    pub fn cover(&self) -> &Cover<PathSummaryBlob> {
        &self.cover
    }

    /// The canonical automaton every member of this view is a summary for.
    pub fn automaton(&self) -> &Automaton {
        &self.automaton
    }

    /// Content handle of the automaton blob the members and descriptor name.
    pub fn automaton_handle(&self) -> Inline<Handle<PathAutomatonBlob>> {
        self.automaton_handle
    }

    /// Compute the exact endpoint relation over every member: the query
    /// computation, kept out of attachment.
    ///
    /// Each member is decoded structurally, the decoded summaries are merged
    /// once as sets, and the union is closed. Paths that take their edges from
    /// several members are found because closure follows the join; nothing is
    /// re-encoded on the way. An empty view closes the automaton's bottom.
    pub fn prepare(&self) -> Result<PathIndex, PathIndexViewError> {
        let mut summaries = Vec::with_capacity(self.segments.len());
        for (_, blob) in &self.segments {
            summaries.push(
                PathSummaryBlob::decode(blob.clone(), &self.automaton)
                    .map_err(PathIndexViewError::Summary)?,
            );
        }
        let summary = if summaries.is_empty() {
            PathSummary::from_edges(self.automaton.clone(), std::iter::empty::<GraphEdge>())
        } else {
            PathSummary::merge_all(&summaries).map_err(PathIndexViewError::Index)?
        };
        PathIndex::from_summary(summary).map_err(PathIndexViewError::Index)
    }

    /// Number of physical path-summary members retained by this view.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Whether this view is the empty-cover bottom.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Borrow the ordered resident physical summary members.
    ///
    /// Stored collection equations are trusted materialized work, so this
    /// lazy view does not replay summary decoding merely to expose its shards.
    /// Consumers which interpret path semantics validate while constructing
    /// that interpretation, as the collection's path-index construction does.
    pub fn segments(&self) -> &[(Inline<Handle<PathSummaryBlob>>, Blob<PathSummaryBlob>)] {
        &self.segments
    }

    /// Consume the view into its ordered resident physical members.
    pub fn into_segments(self) -> Vec<(Inline<Handle<PathSummaryBlob>>, Blob<PathSummaryBlob>)> {
        self.segments
    }

    /// Consume just the physical summary blobs without forcing their union.
    pub fn into_blobs(self) -> impl ExactSizeIterator<Item = Blob<PathSummaryBlob>> {
        self.segments.into_iter().map(|(_, blob)| blob)
    }
}

impl TryFromCover<PathSummaryBlob> for PathSummaryView {
    type Error = PathIndexViewError;

    fn try_from_cover<R>(
        cover: &Cover<PathSummaryBlob>,
        descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: triblespace_core::repo::BlobStoreGet,
    {
        // The descriptor is the collection's admission expectation and names
        // the automaton every member must be a summary for; a member's own
        // header carries the same handle, compared as bytes, never rehashed.
        let automaton_handle = descriptor_automaton_handle(descriptor)
            .map_err(PathIndexViewError::Descriptor)
            .map_err(TryFromCoverError::View)?;
        let mut segments = Vec::with_capacity(cover.len());
        for handle in cover.members() {
            let member = Handle::<PathSummaryBlob>::to_hash(handle);
            let blob = snapshot
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let named = PathSummaryBlob::automaton_handle(&blob)
                .map_err(PathIndexViewError::Summary)
                .map_err(TryFromCoverError::View)?;
            if named != automaton_handle {
                return Err(TryFromCoverError::View(PathIndexViewError::Descriptor(
                    CollectionOperationError::Fatal(
                        "path-summary member names an automaton outside its collection".to_owned(),
                    ),
                )));
            }
            segments.push((handle, blob));
        }
        // The automaton blob is a content-addressed representation dependency
        // retained in the descriptor closure, so the empty cover has it too.
        let automaton_member = Handle::<PathAutomatonBlob>::to_hash(automaton_handle);
        let automaton_blob =
            snapshot
                .get(automaton_handle)
                .map_err(|source| TryFromCoverError::MemberGet {
                    member: automaton_member,
                    source,
                })?;
        let automaton = PathAutomatonBlob::decode(&automaton_blob)
            .map_err(PathIndexViewError::Automaton)
            .map_err(TryFromCoverError::View)?;
        Ok(Self {
            cover: cover.clone(),
            segments,
            automaton_handle,
            automaton,
        })
    }
}

/// Failure to close one realized path-summary cover into its endpoint index.
#[derive(Debug)]
pub enum PathIndexViewError {
    /// The target descriptor did not name one regular-path automaton.
    Descriptor(CollectionOperationError),
    /// The named automaton blob was not canonically encoded.
    Automaton(PathAutomatonBlobError),
    /// A selected summary did not decode under its named automaton.
    Summary(PathSummaryBlobError),
    /// Closing the joined summary into the accepted endpoint relation failed.
    Index(PathError),
}

impl fmt::Display for PathIndexViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(source) => source.fmt(formatter),
            Self::Automaton(source) => source.fmt(formatter),
            Self::Summary(source) => source.fmt(formatter),
            Self::Index(source) => source.fmt(formatter),
        }
    }
}

impl Error for PathIndexViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(source) => Some(source),
            Self::Automaton(source) => Some(source),
            Self::Summary(source) => Some(source),
            Self::Index(source) => Some(source),
        }
    }
}

impl TryFromCover<PathSummaryBlob> for Arc<PathIndex> {
    type Error = PathIndexViewError;

    /// The structural attach of a [`PathSummaryView`] followed by its
    /// [`prepare`](PathSummaryView::prepare), for callers that want the
    /// closed relation in one step.
    fn try_from_cover<R>(
        cover: &Cover<PathSummaryBlob>,
        descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: triblespace_core::repo::BlobStoreGet,
    {
        let view = PathSummaryView::try_from_cover(cover, descriptor, snapshot)?;
        view.prepare()
            .map(Arc::new)
            .map_err(TryFromCoverError::View)
    }
}

fn automaton_from_descriptor(
    descriptor_fragment: &Fragment,
) -> Result<Automaton, CollectionOperationError> {
    let facts = descriptor_fragment.facts();
    let mapping = descriptor::mapping(facts)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
        .ok_or_else(|| {
            CollectionOperationError::Fatal(
                "path-summary descriptor is missing its regular-path mapping".to_owned(),
            )
        })?;
    let state_count = exactly_one_u32(
        facts,
        mapping,
        &path_automaton_state_count,
        "path_automaton_state_count",
    )?;
    let initial = u32_values(facts, mapping, &path_automaton_initial_state)?;
    let accepting = u32_values(facts, mapping, &path_automaton_accepting_state)?;
    let transition_ids = id_values(facts, mapping, &path_automaton_transition)?;
    let mut transitions = Vec::with_capacity(transition_ids.len());
    for transition in transition_ids {
        let from = exactly_one_u32(
            facts,
            transition,
            &path_transition_from,
            "path_transition_from",
        )?;
        let to = exactly_one_u32(facts, transition, &path_transition_to, "path_transition_to")?;
        let kind = exactly_one_u32(
            facts,
            transition,
            &path_transition_kind,
            "path_transition_kind",
        )?;
        let labels = u128_values(facts, transition, &path_transition_label)?
            .into_iter()
            .map(u128::to_be_bytes)
            .collect::<Vec<_>>();
        let step = match (kind, labels.as_slice()) {
            (0, [label]) => Step::Forward(*label),
            (1, [label]) => Step::Reverse(*label),
            (2, labels) => Step::ForwardExcept(labels.to_vec()),
            (3, labels) => Step::ReverseExcept(labels.to_vec()),
            (0 | 1, _) => {
                return Err(CollectionOperationError::Fatal(
                    "exact path transition requires exactly one label".to_owned(),
                ));
            }
            _ => {
                return Err(CollectionOperationError::Fatal(format!(
                    "unknown path transition kind {kind}"
                )));
            }
        };
        transitions.push(Transition::new(from, to, step));
    }
    let automaton = Automaton::new(state_count, initial, accepting, transitions)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    let expected = PathAutomatonBlob::encode(&automaton).get_handle();
    let actual = descriptor_automaton_handle(descriptor_fragment)?;
    if actual != expected {
        return Err(CollectionOperationError::Fatal(
            "regular-path mapping automaton facts do not match its fingerprint".to_owned(),
        ));
    }
    Ok(automaton)
}

fn require_regular_path_mapping(target: &Fragment) -> Result<(), CollectionOperationError> {
    let algorithm = descriptor::mapping_algorithm(target.facts())
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    if algorithm == Some(REGULAR_PATH_MAPPING_V1) {
        return Ok(());
    }
    Err(CollectionOperationError::Fatal(format!(
        "path-summary mapping algorithm {:?} does not match regular-path mapping {REGULAR_PATH_MAPPING_V1:X}",
        algorithm.map(|id| format!("{id:X}")),
    )))
}

fn exactly_one_u32(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<U256BE>,
    field: &'static str,
) -> Result<u32, CollectionOperationError> {
    let mut values = u32_values(facts, entity, attribute)?.into_iter();
    let value = values.next().ok_or_else(|| {
        CollectionOperationError::Fatal(format!("regular-path mapping is missing {field}"))
    })?;
    if values.next().is_some() {
        return Err(CollectionOperationError::Fatal(format!(
            "regular-path mapping repeats {field}"
        )));
    }
    Ok(value)
}

fn u32_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<U256BE>,
) -> Result<Vec<u32>, CollectionOperationError> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| {
            u32::try_from_inline(fact.v::<U256BE>()).map_err(|source| {
                CollectionOperationError::Fatal(format!(
                    "regular-path mapping integer does not fit u32: {source:?}"
                ))
            })
        })
        .collect()
}

fn u128_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<U256BE>,
) -> Result<Vec<u128>, CollectionOperationError> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| {
            u128::try_from_inline(fact.v::<U256BE>()).map_err(|source| {
                CollectionOperationError::Fatal(format!(
                    "regular-path mapping label does not fit u128: {source:?}"
                ))
            })
        })
        .collect()
}

fn id_values(
    facts: &TribleSet,
    entity: Id,
    attribute: &Attribute<GenId>,
) -> Result<Vec<Id>, CollectionOperationError> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| {
            Id::try_from_inline(fact.v::<GenId>()).map_err(|source| {
                CollectionOperationError::Fatal(format!(
                    "regular-path mapping transition has an invalid id: {source:?}"
                ))
            })
        })
        .collect()
}

/// Canonically derive one path-summary element from a `SimpleArchive`.
pub fn derive_element(
    source: &Blob<SimpleArchive>,
    automaton: &Automaton,
) -> Result<Blob<PathSummaryBlob>, RegularPathMappingError> {
    simplearchive_union::validate_element(source).map_err(RegularPathMappingError::Source)?;
    let edges = source.bytes.as_ref().chunks_exact(TRIBLE_LEN).map(|chunk| {
        let raw: &[u8; TRIBLE_LEN] = chunk
            .try_into()
            .expect("validated SimpleArchive chunks have fixed trible length");
        let trible = Trible::as_transmute_force_raw(raw)
            .expect("validated SimpleArchive contains valid tribles");
        GraphEdge::from(trible)
    });
    let summary = PathSummary::from_edges(automaton.clone(), edges);
    PathSummaryBlob::encode(&summary).map_err(RegularPathMappingError::Summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::VerifyingKey;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::collection::records::{
        collection_mapping, collection_name, collection_representation, collection_source,
        CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
    };
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};
    use triblespace_core::id::ExclusiveId;
    use triblespace_core::inline::RawInline;
    use triblespace_core::metadata;
    use triblespace_core::prelude::entity;
    use triblespace_core::repo::{BlobStoreGet, SnapshotSource};
    use triblespace_core::trible::Fragment;
    use triblespace_core::trible::TribleSet;

    use crate::{PathIndex, Step, Transition};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    /// Authority shared by these test collections.
    fn authority() -> VerifyingKey {
        SigningKey::from_bytes(&[1; 32]).verifying_key()
    }

    fn policy() -> CollectionPolicy {
        CollectionPolicy::new(
            AdmissionPolicy::direct(authority()),
            AdmissionPolicy::direct(authority()),
        )
    }

    /// The source collection these tests summarise.
    fn source_collection() -> Fragment {
        source_descriptor("edges", policy())
    }

    /// These tests only need identities to bind claims to; nothing stores the
    /// descriptors they come from.
    fn collection_of(descriptor: &Fragment) -> CollectionHandle {
        IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle()
    }

    fn source_descriptor(name: &str, policy: CollectionPolicy) -> Fragment {
        entity! { _ @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_name: name.to_owned(),
            resource_policy*: policy.fragment(),
            collection_representation*: <SimpleArchive as MetaDescribe>::describe(),
        }
    }

    fn summary_descriptor(source: CollectionHandle, automaton: &Automaton) -> Fragment {
        let policy = policy();
        entity! { _ @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: source,
            resource_policy*: policy.fragment(),
            collection_representation*: <PathSummaryBlob as MetaDescribe>::describe(),
            collection_mapping*: mapping_fragment(automaton),
        }
    }

    fn summary_descriptor_with_fingerprint(
        source: CollectionHandle,
        automaton: &Automaton,
        fingerprint: Inline<Hash<Blake3>>,
    ) -> Fragment {
        let policy = policy();
        entity! { _ @
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: source,
            resource_policy*: policy.fragment(),
            collection_representation*: <PathSummaryBlob as MetaDescribe>::describe(),
            collection_mapping*: mapping_fragment_with_fingerprint(automaton, fingerprint),
        }
    }

    fn label(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn plus(attribute: [u8; 16]) -> Automaton {
        Automaton::new(
            2,
            [0],
            [1],
            [
                Transition::new(0, 1, Step::Forward(attribute)),
                Transition::new(1, 1, Step::Forward(attribute)),
            ],
        )
        .unwrap()
    }

    fn edge_facts(source_byte: u8, target_byte: u8) -> TribleSet {
        let source = id(source_byte);
        let target = id(target_byte);
        entity! { ExclusiveId::force_ref(&source) @ metadata::tag: target }.into_facts()
    }

    fn archive(facts: &TribleSet) -> Blob<SimpleArchive> {
        facts.to_blob()
    }

    #[test]
    fn descriptor_identity_includes_source_representation_and_automaton() {
        let first_automaton = plus(label(7));
        let second_automaton = plus(label(8));
        let source = source_collection();
        let first = summary_descriptor(collection_of(&source), &first_automaton);
        let repeated = summary_descriptor(collection_of(&source), &first_automaton);
        let second = summary_descriptor(collection_of(&source), &second_automaton);

        assert_eq!(first, repeated);
        // A summary names the collection it summarises, and carries no anchor
        // of its own.
        assert_eq!(
            descriptor::source(first.facts()),
            Ok(Some(collection_of(&source)))
        );
        assert!(
            descriptor::name(first.facts()).unwrap().is_none(),
            "a derivation needs no anchor"
        );
        assert_eq!(descriptor::policy(first.facts()), Ok(policy()));
        let other_source = summary_descriptor(
            collection_of(&source_descriptor("other-edges", policy())),
            &first_automaton,
        );
        // Source scope changes the collection but not the reusable mapping.
        assert_ne!(collection_of(&first), collection_of(&other_source));
        assert_eq!(
            descriptor::mapping(first.facts()),
            descriptor::mapping(other_source.facts())
        );
        assert_eq!(
            descriptor::representation(first.facts()).unwrap(),
            <PathSummaryBlob as MetaDescribe>::id()
        );
        assert_ne!(
            descriptor::representation(first.facts()),
            descriptor::representation(source.facts())
        );
        assert_eq!(descriptor::mapping(source.facts()), Ok(None));
        assert_eq!(
            descriptor::mapping_algorithm(first.facts()),
            Ok(Some(REGULAR_PATH_MAPPING_V1))
        );
        // The constructor gives different automata different content-derived
        // mapping instances of the same algorithm.
        assert_ne!(
            descriptor::mapping(first.facts()),
            descriptor::mapping(second.facts())
        );
        assert_ne!(
            descriptor::mapping_argument(first.facts(), path_automaton_fingerprint.id()),
            descriptor::mapping_argument(second.facts(), path_automaton_fingerprint.id())
        );
        assert_eq!(
            descriptor::argument(first.facts(), path_automaton_fingerprint.id()),
            Ok(None),
            "automaton parameters belong to the mapping, not the descriptor root",
        );
        assert_ne!(collection_of(&first), collection_of(&second));
    }

    #[test]
    fn descriptor_round_trips_automaton_and_rejects_fingerprint_mismatch() {
        let automaton = Automaton::new(
            3,
            [0, 1],
            [1, 2],
            [
                Transition::new(0, 1, Step::Forward(label(7))),
                Transition::new(1, 2, Step::ReverseExcept(vec![label(8), label(9)])),
            ],
        )
        .unwrap();
        let source = collection_of(&source_collection());
        let descriptor = summary_descriptor(source, &automaton);

        let expected_automaton = PathAutomatonBlob::encode(&automaton);
        let expected_handle = expected_automaton.get_handle();
        let historical_mapping =
            mapping_fragment_with_fingerprint(&automaton, Inline::new(expected_handle.raw));
        let attached_mapping = <PathSummaryBlob as CollectionDerivation>::fragment(&automaton);
        assert_eq!(attached_mapping.facts(), historical_mapping.facts());
        assert_eq!(attached_mapping.root(), historical_mapping.root());

        let mut attachments = descriptor.blobs().clone();
        let attachment_snapshot = attachments.snapshot().unwrap();
        let attached: Blob<PathAutomatonBlob> = attachment_snapshot.get(expected_handle).unwrap();
        assert_eq!(attached.bytes, expected_automaton.bytes);

        assert_eq!(
            descriptor::mapping(descriptor.facts()),
            Ok(mapping_fragment(&automaton).root()),
            "the canonical constructor links its concrete mapping subtree",
        );
        assert_eq!(automaton_from_descriptor(&descriptor).unwrap(), automaton);
        <PathSummaryBlob as CollectionEncoding>::validate_descriptor(&descriptor).unwrap();

        let mut annotated = descriptor.clone();
        let mapping = descriptor::mapping(annotated.facts())
            .unwrap()
            .expect("derived descriptor has a mapping");
        let predecessor: Inline<GenId> =
            triblespace_core::inline::IntoInline::to_inline(REGULAR_PATH_MAPPING_V1);
        annotated.facts_mut().insert(&Trible::force(
            &mapping,
            &metadata::supersedes.id(),
            &predecessor,
        ));
        assert_eq!(
            automaton_from_descriptor(&annotated).unwrap(),
            automaton,
            "annotations do not change a mapping's operational meaning",
        );

        let mismatched =
            summary_descriptor_with_fingerprint(source, &automaton, Inline::new([0xA5; 32]));
        assert!(matches!(
            <PathSummaryBlob as CollectionEncoding>::validate_descriptor(&mismatched),
            Err(CollectionOperationError::Fatal(reason))
                if reason.contains("do not match its fingerprint")
        ));
    }

    #[test]
    fn canonical_empty_is_total_derived_bottom_and_join_identity() {
        let automaton = plus(label(7));
        let source_empty = archive(&TribleSet::new());
        let canonical_empty = PathSummaryBlob::empty(&automaton);

        assert_eq!(canonical_empty.bytes.len(), 48);
        let mut expected_empty = Vec::with_capacity(48);
        expected_empty.extend_from_slice(&crate::automaton_fingerprint(&automaton).raw);
        expected_empty.extend_from_slice(&automaton.state_count().to_le_bytes());
        expected_empty.extend_from_slice(&0u32.to_le_bytes());
        expected_empty.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(canonical_empty.bytes.as_ref(), expected_empty);
        assert_eq!(
            canonical_empty.get_handle(),
            PathSummaryBlob::empty(&automaton).get_handle()
        );
        let decoded = PathSummaryBlob::decode(canonical_empty.clone(), &automaton).unwrap();
        assert!(decoded.vertices().is_empty());
        assert_eq!(decoded.direct_arc_count(), 0);

        let derived_empty = derive_element(&source_empty, &automaton).unwrap();
        assert_eq!(derived_empty.bytes, canonical_empty.bytes);

        // `metadata::tag` does not match the fixed label(7) transition.
        let unmatched_source = archive(&edge_facts(2, 3));
        let derived_unmatched = derive_element(&unmatched_source, &automaton).unwrap();
        assert_eq!(derived_unmatched.bytes, canonical_empty.bytes);

        let matching_automaton = plus(metadata::tag.id().into());
        let matching = derive_element(&archive(&edge_facts(4, 5)), &matching_automaton).unwrap();
        let matching_empty = PathSummaryBlob::empty(&matching_automaton);
        let left_identity =
            PathSummaryBlob::join(&matching_empty, &matching, &matching_automaton).unwrap();
        let right_identity =
            PathSummaryBlob::join(&matching, &matching_empty, &matching_automaton).unwrap();
        let idempotent = PathSummaryBlob::join(&matching, &matching, &matching_automaton).unwrap();
        for joined in [left_identity, right_identity, idempotent] {
            assert_eq!(joined.bytes, matching.bytes);
            assert_eq!(joined.get_handle(), matching.get_handle());
        }
    }

    #[test]
    fn derive_and_merge_commute_and_close_cross_fragment_paths() {
        let automaton = plus(metadata::tag.id().into());
        let left = archive(&edge_facts(1, 2));
        let right = archive(&edge_facts(2, 3));

        let source_union = simplearchive_union::join(&left, &right).unwrap();
        let derive_after_source_join = derive_element(&source_union, &automaton).unwrap();
        let derived_left = derive_element(&left, &automaton).unwrap();
        let derived_right = derive_element(&right, &automaton).unwrap();
        let join_after_derive =
            PathSummaryBlob::join(&derived_left, &derived_right, &automaton).unwrap();

        assert_eq!(derive_after_source_join.bytes, join_after_derive.bytes);
        assert_eq!(
            derive_after_source_join.get_handle(),
            join_after_derive.get_handle()
        );

        let summary = PathSummaryBlob::decode(join_after_derive, &automaton).unwrap();
        let index = PathIndex::from_summary(summary).unwrap();
        assert!(index.contains(&RawInline::from(id(1)), &RawInline::from(id(3)),));
    }

    #[test]
    fn nullable_unmatched_domain_obeys_the_same_mapping_law() {
        let automaton = Automaton::new(1, [0], [0], []).unwrap();
        let left = archive(&edge_facts(1, 2));
        let right = archive(&edge_facts(2, 3));
        let source_union = simplearchive_union::join(&left, &right).unwrap();

        let derive_after_source_join = derive_element(&source_union, &automaton).unwrap();
        let derived_left = derive_element(&left, &automaton).unwrap();
        let derived_right = derive_element(&right, &automaton).unwrap();
        let join_after_derive =
            PathSummaryBlob::join(&derived_left, &derived_right, &automaton).unwrap();

        assert_eq!(derive_after_source_join.bytes, join_after_derive.bytes);
        let summary = PathSummaryBlob::decode(join_after_derive, &automaton).unwrap();
        assert_eq!(summary.vertices().len(), 3);
        assert_eq!(summary.direct_arc_count(), 0);
        let index = PathIndex::from_summary(summary).unwrap();
        assert_eq!(index.accepted_pair_count(), 3);

        let joined_with_empty = PathSummaryBlob::join(
            &PathSummaryBlob::empty(&automaton),
            &derived_left,
            &automaton,
        )
        .unwrap();
        assert_eq!(joined_with_empty.bytes, derived_left.bytes);
    }
}
