//! Maintained latest states with historical supersession evidence.
//!
//! An element is `(H, D)`: the known live states and every superseded target
//! ever observed, including targets whose own facts have not arrived. Its join is
//!
//! ```text
//! (H1, D1) join (H2, D2) = ((H1 union H2) minus (D1 union D2), D1 union D2)
//! ```
//!
//! Derivation projects all source entity subjects into `S`, and all well-formed
//! id values under the configured observation attribute into `D`, then stores
//! `H = S minus D`. Both projections preserve union, even when an entity's
//! fields arrive in different source commits. A multi-fact shape query would
//! not have that property: its missing halves could only meet after merging.
//!
//! Live heads alone are neither monotone nor antitone under inclusion. The
//! maintained pair is monotone in its own join order. Retaining `D` is essential:
//! after `b -> a, c -> b` leaves only `c` live, a later arrival of `a` must not
//! resurrect it. No ancestor walk, id derivation, or DAG constraint is needed.
//! Cycles simply retire their members, independently of arrival order.
//!
//! [`LatestIndex`] exposes `H` through ordinary positive `.has(state)`
//! membership: it proposes every known live state, uses stored section counts
//! as a planning bound, and confirms membership by binary search. Unknown
//! candidates do not survive.
//! The index belongs to the frozen collection observation which produced it;
//! queries never acquire bytes or advance maintenance. Other fact views may
//! have advanced independently, so positive membership is not a same-support
//! requirement or a global-current guarantee.

use anybytes::{Bytes, View};
use itertools::{Either, Itertools};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::{Blob, BlobEncoding};
use crate::id::{ExclusiveId, Id};
use crate::id_hex;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::macros::entity;
use crate::metadata::{self, MetaDescribe};
use crate::query::{
    Binding, Candidates, Constraint, ContainsConstraint, Frontier, ProposalBuffer, Variable,
    VariableId, VariableSet,
};
use crate::repo::BlobStoreGet;
use crate::trible::{Fragment, Trible, A_START, E_START, TRIBLE_LEN};

use super::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use super::{
    CollectionDerivation, CollectionEncoding, CollectionOperationError, TryFromCover,
    TryFromCoverError,
};

const ID_LEN: usize = 16;
const HEADER_LEN: usize = 16;

crate::macros::attributes! {
    /// The observation attribute read by a maintained latest-state mapping.
    ///
    /// Reuses the same edge-parameter identity minted with `trible genid` on
    /// 2026-08-19; only the target encoding and mapping algorithm have changed.
    "E61092974C734142217EC718CC184673" as pub register_observes: GenId;
}

/// Canonical `(H, D)` latest-state lattice element.
///
/// The header is two big-endian `u64` counts, live ids then superseded ids.
/// Each following section is a strictly increasing sequence of nonnil 16-byte
/// ids, and the sections are disjoint. Empty is a 16-byte all-zero header.
/// These bytes have a new encoding identity; the retired observed-only encoding
/// is never reinterpreted as this lattice.
pub struct LatestBlob;

impl BlobEncoding for LatestBlob {}

impl MetaDescribe for LatestBlob {
    fn describe() -> Fragment {
        // Minted with installed `trible genid` on 2026-09-05.
        let id: Id = id_hex!("35304D6FF3421A1F9C0DCF4F8C45D392");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "latest-states-v1",
            metadata::description: "Canonical latest-state lattice (H,D). Two big-endian u64 counts precede disjoint strictly sorted nonnil 16-byte live-state and historical superseded-target id sets. Join unions the historical targets and removes them from the union of live states. Empty is a sixteen-byte zero header.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Failure to decode, derive, or join one canonical latest-state element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LatestError {
    /// The source is not a canonical `SimpleArchive`.
    InvalidSource(UnarchiveError),
    /// The payload length does not match its two declared id counts.
    BadLength(usize),
    /// Header arithmetic exceeds the platform's addressable size.
    CountOverflow,
    /// One id section is not strictly increasing.
    NotStrictlyIncreasing,
    /// One section contains the nil id.
    NilId,
    /// A state is both live and superseded.
    OverlappingSections,
}

impl fmt::Display for LatestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(source) => write!(formatter, "invalid source archive: {source}"),
            Self::BadLength(len) => {
                write!(formatter, "latest-state counts do not match {len} bytes")
            }
            Self::CountOverflow => {
                formatter.write_str("latest-state counts overflow address space")
            }
            Self::NotStrictlyIncreasing => {
                formatter.write_str("latest-state ids are not strictly increasing")
            }
            Self::NilId => formatter.write_str("latest-state element contains a nil id"),
            Self::OverlappingSections => {
                formatter.write_str("latest-state live and superseded sections overlap")
            }
        }
    }
}

impl Error for LatestError {}

fn sections(blob: &Blob<LatestBlob>) -> Result<(&[u8], &[u8]), LatestError> {
    let bytes = blob.bytes.as_ref();
    if bytes.len() < HEADER_LEN {
        return Err(LatestError::BadLength(bytes.len()));
    }
    let count = |header: &[u8]| {
        usize::try_from(u64::from_be_bytes(
            header.try_into().expect("eight-byte count"),
        ))
        .ok()
        .and_then(|n| n.checked_mul(ID_LEN))
        .ok_or(LatestError::CountOverflow)
    };
    let live_len = count(&bytes[..8])?;
    let retired_len = count(&bytes[8..HEADER_LEN])?;
    let split = HEADER_LEN
        .checked_add(live_len)
        .ok_or(LatestError::CountOverflow)?;
    let total = split
        .checked_add(retired_len)
        .ok_or(LatestError::CountOverflow)?;
    if bytes.len() != total {
        return Err(LatestError::BadLength(bytes.len()));
    }
    Ok((&bytes[HEADER_LEN..split], &bytes[split..]))
}

/// Validate the canonical byte layout, including `H intersect D = empty`.
pub fn validate_element(blob: &Blob<LatestBlob>) -> Result<(), LatestError> {
    let (live, retired) = sections(blob)?;
    for section in [live, retired] {
        let mut previous = None;
        for id in section.chunks_exact(ID_LEN) {
            if id == [0; ID_LEN] {
                return Err(LatestError::NilId);
            }
            if previous.is_some_and(|prior| prior >= id) {
                return Err(LatestError::NotStrictlyIncreasing);
            }
            previous = Some(id);
        }
    }
    let mut retired = retired.chunks_exact(ID_LEN).peekable();
    for id in live.chunks_exact(ID_LEN) {
        while retired.peek().is_some_and(|other| *other < id) {
            retired.next();
        }
        if retired.peek().is_some_and(|other| *other == id) {
            return Err(LatestError::OverlappingSections);
        }
    }
    Ok(())
}

fn encode(live: &[u8], retired: &[u8]) -> Blob<LatestBlob> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + live.len() + retired.len());
    bytes.extend_from_slice(&((live.len() / ID_LEN) as u64).to_be_bytes());
    bytes.extend_from_slice(&((retired.len() / ID_LEN) as u64).to_be_bytes());
    bytes.extend_from_slice(live);
    bytes.extend_from_slice(retired);
    Blob::new(Bytes::from_source(bytes))
}

/// The canonical bottom element `(empty, empty)`.
pub fn empty() -> Blob<LatestBlob> {
    encode(&[], &[])
}

fn difference(live: &[u8], retired: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(live.len());
    let mut retired = retired.chunks_exact(ID_LEN).peekable();
    for id in live.chunks_exact(ID_LEN) {
        while retired.peek().is_some_and(|other| *other < id) {
            retired.next();
        }
        if !retired.peek().is_some_and(|other| *other == id) {
            result.extend_from_slice(id);
        }
    }
    result
}

/// Project subjects and configured-edge targets from one canonical archive.
///
/// Every subject is known, regardless of its other fields. Target values which
/// do not decode as nonnil `GenId`s are simply not supersession evidence.
pub fn derive_element(
    source: &Blob<SimpleArchive>,
    observes: Id,
) -> Result<Blob<LatestBlob>, LatestError> {
    let bytes = source.bytes.as_ref();
    if bytes.len() % TRIBLE_LEN != 0 {
        return Err(LatestError::InvalidSource(UnarchiveError::BadArchive));
    }
    let mut subjects: Vec<[u8; ID_LEN]> = Vec::new();
    let mut retired: Vec<[u8; ID_LEN]> = Vec::new();
    let mut previous = None;
    for row in bytes.chunks_exact(TRIBLE_LEN) {
        let row: &[u8; TRIBLE_LEN] = row.try_into().expect("64-byte archive row");
        let trible = Trible::as_transmute_force_raw(row)
            .ok_or(LatestError::InvalidSource(UnarchiveError::BadTrible))?;
        if let Some(previous) = previous {
            if previous == row {
                return Err(LatestError::InvalidSource(
                    UnarchiveError::BadCanonicalizationRedundancy,
                ));
            }
            if previous > row {
                return Err(LatestError::InvalidSource(
                    UnarchiveError::BadCanonicalizationOrdering,
                ));
            }
        }
        previous = Some(row);
        let subject = row[E_START..E_START + ID_LEN]
            .try_into()
            .expect("16-byte subject");
        if subjects.last() != Some(&subject) {
            subjects.push(subject);
        }
        if row[A_START..A_START + ID_LEN] == observes[..] {
            if let Ok(id) = trible.v::<GenId>().try_from_inline::<Id>() {
                retired.push(id[..].try_into().expect("16-byte id"));
            }
        }
    }
    retired.sort_unstable();
    retired.dedup();
    let retired = retired.concat();
    Ok(encode(&difference(&subjects.concat(), &retired), &retired))
}

fn union(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        let a = &left[i..i + ID_LEN];
        let b = &right[j..j + ID_LEN];
        match a.cmp(b) {
            std::cmp::Ordering::Less => {
                merged.extend_from_slice(a);
                i += ID_LEN;
            }
            std::cmp::Ordering::Greater => {
                merged.extend_from_slice(b);
                j += ID_LEN;
            }
            std::cmp::Ordering::Equal => {
                merged.extend_from_slice(a);
                i += ID_LEN;
                j += ID_LEN;
            }
        }
    }
    merged.extend_from_slice(&left[i..]);
    merged.extend_from_slice(&right[j..]);
    merged
}

/// The canonical latest-state join; historical targets are never discarded.
pub fn join(
    low: &Blob<LatestBlob>,
    high: &Blob<LatestBlob>,
) -> Result<Blob<LatestBlob>, LatestError> {
    validate_element(low)?;
    validate_element(high)?;
    let (low_live, low_retired) = sections(low)?;
    let (high_live, high_retired) = sections(high)?;
    let retired = union(low_retired, high_retired);
    let live = difference(&union(low_live, high_live), &retired);
    Ok(encode(&live, &retired))
}

/// Canonical subject/supersession projection algorithm, version 1.
///
/// Minted with installed `trible genid` on 2026-09-05.
pub const LATEST_STATES_MAPPING_V1: Id = id_hex!("2D3DFB807700200A43FD841406B46D77");

/// Self-description of the canonical latest-state projection algorithm.
pub struct LatestStatesMappingV1;

impl MetaDescribe for LatestStatesMappingV1 {
    fn describe() -> Fragment {
        let id = LATEST_STATES_MAPPING_V1;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "latest-states-mapping-v1",
            metadata::description: "Project every SimpleArchive subject into S and every well-formed GenId target under register_observes into D, retaining (S minus D,D) in LatestBlob. Both projections preserve union, including split entity fields and unseen superseded targets.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

impl CollectionEncoding for LatestBlob {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        validate_element(member)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        join(low, high).map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

impl CollectionDerivation for LatestBlob {
    type Source = SimpleArchive;
    type Argument = Id;

    fn fragment(observes: &Id) -> Fragment {
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <LatestStatesMappingV1 as MetaDescribe>::describe(),
            register_observes: observes,
        }
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Id, CollectionOperationError> {
        let raw = super::descriptor::mapping_argument(target.facts(), register_observes.id())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal(
                    "latest-state mapping is missing register_observes".to_owned(),
                )
            })?;
        let observes = Inline::<GenId>::new(raw)
            .try_from_inline::<Id>()
            .map_err(|source| {
                CollectionOperationError::Fatal(format!("invalid register_observes: {source:?}"))
            })?;
        let actual = super::descriptor::mapping_algorithm(target.facts())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        if actual != Some(LATEST_STATES_MAPPING_V1) {
            return Err(CollectionOperationError::Fatal(format!(
                "latest-state mapping algorithm does not match {LATEST_STATES_MAPPING_V1:X}"
            )));
        }
        Ok(observes)
    }

    fn map<R>(
        observes: &Id,
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        derive_element(source, *observes)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

/// Positive known-live membership attached to one frozen latest-state cover.
#[derive(Clone, Debug, Default)]
pub struct LatestIndex {
    members: Vec<LatestRows>,
}

#[derive(Clone, Debug)]
struct LatestRows {
    live: View<[[u8; ID_LEN]]>,
    retired: View<[[u8; ID_LEN]]>,
}

impl LatestRows {
    fn decode(blob: &Blob<LatestBlob>) -> Result<Self, LatestError> {
        let (live, _) = sections(blob)?;
        let split = HEADER_LEN + live.len();
        // The framing check establishes exact multiples of byte-aligned rows.
        // Canonical ordering and lattice validity belong to validate_element.
        Ok(Self {
            live: blob
                .bytes
                .slice(HEADER_LEN..split)
                .view()
                .map_err(|_| LatestError::BadLength(blob.bytes.len()))?,
            retired: blob
                .bytes
                .slice(split..)
                .view()
                .map_err(|_| LatestError::BadLength(blob.bytes.len()))?,
        })
    }
}

impl LatestIndex {
    /// View a typed element, checking its framing without revalidating it.
    ///
    /// Both row sections retain the blob's shared backing. Use
    /// [`validate_element`] to audit canonical ordering and lattice validity.
    pub fn decode(blob: &Blob<LatestBlob>) -> Result<Self, LatestError> {
        let member = LatestRows::decode(blob)?;
        Ok(Self {
            members: vec![member],
        })
    }

    fn raw_states(&self) -> impl Iterator<Item = [u8; ID_LEN]> + '_ {
        if let [member] = self.members.as_slice() {
            return Either::Left(member.live.iter().copied());
        }
        let mut retired = self
            .members
            .iter()
            .map(|member| member.retired.iter().copied())
            .kmerge()
            .dedup()
            .peekable();
        Either::Right(
            self.members
                .iter()
                .map(|member| member.live.iter().copied())
                .kmerge()
                .dedup()
                .filter(move |state| {
                    while retired.peek().is_some_and(|other| other < state) {
                        retired.next();
                    }
                    retired.peek() != Some(state)
                }),
        )
    }

    /// The exact number of known live states.
    ///
    /// A single member uses its header count. A multi-member cover is merged
    /// lazily when this count is requested, not when its rows are attached.
    pub fn len(&self) -> usize {
        match self.members.as_slice() {
            [] => 0,
            [member] => member.live.len(),
            _ => self.raw_states().count(),
        }
    }

    /// Whether this observation has no known live states.
    pub fn is_empty(&self) -> bool {
        self.raw_states().next().is_none()
    }

    /// The strictly sorted known live states.
    pub fn states(&self) -> impl Iterator<Item = Id> + '_ {
        self.raw_states().filter_map(Id::new)
    }

    /// Positive membership; unknown and superseded states both return false.
    pub fn contains(&self, state: Id) -> bool {
        let raw = state.raw();
        !self
            .members
            .iter()
            .any(|member| member.retired.binary_search(&raw).is_ok())
            && self
                .members
                .iter()
                .any(|member| member.live.binary_search(&raw).is_ok())
    }
}

impl PartialEq for LatestIndex {
    fn eq(&self, other: &Self) -> bool {
        self.raw_states().eq(other.raw_states())
    }
}

impl Eq for LatestIndex {}

/// Positive known-live membership over the frozen cover's stored row sets.
pub struct LatestConstraint<'a> {
    variable: Variable<GenId>,
    index: &'a LatestIndex,
}

impl<'a> ContainsConstraint<'a, GenId> for &'a LatestIndex {
    type Constraint = LatestConstraint<'a>;

    fn has(self, variable: Variable<GenId>) -> Self::Constraint {
        LatestConstraint {
            variable,
            index: self,
        }
    }
}

impl<'a> Constraint<'a> for LatestConstraint<'a> {
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.variable.index)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        // Estimates guide planning, not correctness. Stored section lengths
        // are a cheap upper bound; do not enumerate a cover union merely to
        // decide which constraint should propose candidates.
        (self.variable.index == variable).then(|| {
            self.index.members.iter().fold(0usize, |total, member| {
                total.saturating_add(member.live.len())
            })
        })
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        use crate::inline::IntoInline;
        if self.variable.index == variable {
            for row in 0..frontier.len() {
                proposals.open(row as u32);
                proposals.extend(self.index.raw_states().map(|state| {
                    let value: Inline<GenId> = state.to_inline();
                    value.raw
                }));
            }
        }
    }

    fn confirm(
        &self,
        variable: VariableId,
        _frontier: &Frontier<'_>,
        candidates: &mut Candidates<'_>,
    ) {
        if self.variable.index == variable {
            for i in 0..candidates.len() {
                if !candidates.is_live(i) {
                    continue;
                }
                let keep = Inline::<GenId>::as_transmute_raw(&candidates.values()[i])
                    .try_from_inline::<Id>()
                    .is_ok_and(|state| self.index.contains(state));
                if !keep {
                    candidates.kill(i);
                }
            }
        }
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        binding.get(self.variable.index).is_none_or(|raw| {
            Inline::<GenId>::as_transmute_raw(raw)
                .try_from_inline::<Id>()
                .is_ok_and(|state| self.index.contains(state))
        })
    }
}

impl TryFromCover<LatestBlob> for LatestIndex {
    type Error = LatestError;

    fn try_from_cover<R>(
        cover: &super::Cover<LatestBlob>,
        _descriptor: &Fragment,
        reader: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut members = Vec::new();
        for handle in cover.members() {
            let member = Handle::<LatestBlob>::to_hash(handle);
            let segment = reader
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            members.push(LatestRows::decode(&segment).map_err(TryFromCoverError::View)?);
        }
        Ok(Self { members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::query::register::{resolve, ObservationOrder};
    use crate::trible::V_START;
    use futures::executor::block_on;
    use std::collections::BTreeSet;

    fn edge(successor: &ExclusiveId, predecessor: &ExclusiveId) -> TribleSet {
        entity! { successor @ metadata::supersedes: predecessor }.into()
    }

    fn state(id: &ExclusiveId) -> TribleSet {
        entity! { id @ metadata::tag: metadata::KIND_MULTI }.into()
    }

    fn project(facts: &TribleSet) -> Blob<LatestBlob> {
        derive_element(&facts.clone().to_blob(), metadata::supersedes.id()).unwrap()
    }

    fn heads(blob: &Blob<LatestBlob>) -> BTreeSet<Id> {
        let index = LatestIndex::decode(blob).unwrap();
        find!(state: Id, index.has(state)).collect()
    }

    fn policy(key: ed25519_dalek::VerifyingKey) -> super::super::CollectionPolicy {
        super::super::CollectionPolicy::new(
            super::super::AdmissionPolicy::direct(key),
            super::super::AdmissionPolicy::direct(key),
        )
    }

    fn attach(members: &[Blob<LatestBlob>]) -> LatestIndex {
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let mut store = MemoryRepo::default();
        let source = store
            .collection("latest-row-view", policy(key.verifying_key()))
            .unwrap();
        let target = store
            .derive::<LatestBlob>(
                source,
                metadata::supersedes.id(),
                policy(key.verifying_key()),
            )
            .unwrap();
        let handles = members
            .iter()
            .cloned()
            .map(|member| store.put(member).unwrap())
            .collect::<Vec<_>>();
        let snapshot = store.snapshot().unwrap();
        LatestIndex::try_from_cover(&target.cover(handles), &Fragment::empty(), &snapshot).unwrap()
    }

    #[test]
    fn typed_attachment_keeps_shared_rows_and_defers_canonical_audit() {
        let old = ufoid();
        let live = ufoid();
        let blob = project(&edge(&live, &old));
        let live_ptr = blob.bytes[HEADER_LEN..].as_ptr();
        let retired_ptr = blob.bytes[HEADER_LEN + ID_LEN..].as_ptr();
        let index = attach(&[blob.clone()]);
        assert_eq!(index.members[0].live.as_ptr().cast::<u8>(), live_ptr);
        assert_eq!(index.members[0].retired.as_ptr().cast::<u8>(), retired_ptr);
        let retained = index.clone();
        drop(blob);
        drop(index);
        assert_eq!(retained.states().collect::<Vec<_>>(), [*live]);
        assert!(!retained.contains(*old));

        // The typed read boundary checks shape, not semantic canonicality.
        // Explicit audit still identifies each malformed element.
        for (blob, error) in [
            (
                encode(&live[..], &live[..]),
                LatestError::OverlappingSections,
            ),
            (encode(&[0; ID_LEN], &[]), LatestError::NilId),
            (
                encode(&[&live[..], &live[..]].concat(), &[]),
                LatestError::NotStrictlyIncreasing,
            ),
        ] {
            assert!(LatestIndex::decode(&blob).is_ok());
            assert_eq!(validate_element(&blob), Err(error));
        }
        let nil = LatestIndex::decode(&encode(&[0; ID_LEN], &[])).unwrap();
        assert_eq!(nil.states().next(), None);
        assert_eq!(find!(state: Id, nil.has(state)).next(), None);
        for bytes in [
            vec![0; HEADER_LEN - 1],
            vec![0; HEADER_LEN + 1],
            vec![255; HEADER_LEN],
        ] {
            let blob = Blob::new(Bytes::from_source(bytes));
            assert_eq!(
                LatestIndex::decode(&blob).unwrap_err(),
                validate_element(&blob).unwrap_err()
            );
        }
    }

    #[test]
    fn cover_queries_merge_shared_rows_without_serializing_prefixes() {
        let a = ufoid();
        let b = ufoid();
        let c = ufoid();
        let d = ufoid();
        let members = [
            project(&edge(&b, &a)),
            project(&edge(&c, &b)),
            project(&state(&a)),
            project(&state(&d)),
            project(&(state(&c) + state(&d))),
        ];
        let index = attach(&members);
        assert_eq!(index.members.len(), members.len());
        for member in &members {
            let ptr = member.bytes[HEADER_LEN..].as_ptr();
            assert!(index
                .members
                .iter()
                .any(|rows| rows.live.as_ptr().cast::<u8>() == ptr));
        }
        let joined = members
            .iter()
            .fold(empty(), |joined, member| join(&joined, member).unwrap());
        let expected = LatestIndex::decode(&joined).unwrap();
        assert_eq!(index, expected);
        assert_eq!(index.len(), 2);
        let state = Variable::<GenId>::new(0);
        let constraint = index.has(state);
        assert_eq!(
            constraint.estimate(state.index, &Binding::default()),
            Some(6)
        );
        assert_eq!(constraint.estimate(1, &Binding::default()), None);
        assert_eq!(
            index.states().collect::<BTreeSet<_>>(),
            BTreeSet::from([*c, *d])
        );
        assert_eq!(
            find!(state: Id, index.has(state)).collect::<BTreeSet<_>>(),
            BTreeSet::from([*c, *d])
        );
        for candidate in [*a, *b, *c, *d] {
            assert_eq!(index.contains(candidate), expected.contains(candidate));
        }
        let reversed = members.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(attach(&reversed), expected);
        assert!(attach(&[]).is_empty());
    }

    #[test]
    fn empty_has_no_candidates_and_is_the_canonical_bottom() {
        assert_eq!(empty().bytes.as_ref(), &[0; HEADER_LEN]);
        assert_eq!(project(&TribleSet::new()), empty());
        let index = LatestIndex::decode(&empty()).unwrap();
        assert!(index.is_empty());
        assert!(heads(&empty()).is_empty());
        let unknown = ufoid();
        assert!(!index.contains(*unknown));
        assert!(!exists!((state: Id), and!(state.is((&unknown).to_inline()), index.has(state))));
    }

    #[test]
    fn forks_remain_positive_until_a_merge_observes_both() {
        let base = ufoid();
        let left = ufoid();
        let right = ufoid();
        let merge = ufoid();
        let mut facts = state(&base);
        facts += edge(&left, &base);
        facts += edge(&right, &base);
        let fork = project(&facts);
        assert_eq!(heads(&fork), BTreeSet::from([*left, *right]));
        let mut merge_facts = edge(&merge, &left);
        merge_facts += edge(&merge, &right);
        let merged = join(&fork, &project(&merge_facts)).unwrap();
        assert_eq!(heads(&merged), BTreeSet::from([*merge]));
        facts += merge_facts;
        assert_eq!(merged, project(&facts));
        assert_eq!(
            heads(&merged),
            resolve(
                &ObservationOrder::new(&facts, metadata::supersedes.id()),
                [*base, *left, *right, *merge]
            )
        );
    }

    #[test]
    fn successor_before_predecessor_does_not_resurrect_the_predecessor() {
        let predecessor = ufoid();
        let successor = ufoid();
        let early = project(&edge(&successor, &predecessor));
        assert_eq!(heads(&early), BTreeSet::from([*successor]));
        let late = project(&state(&predecessor));
        assert_eq!(join(&early, &late).unwrap(), early);
        assert_eq!(join(&late, &early).unwrap(), early);
    }

    #[test]
    fn discarded_ancestry_still_retires_a_later_old_state() {
        let a = ufoid();
        let b = ufoid();
        let c = ufoid();
        let with_ancestry = join(&project(&edge(&b, &a)), &project(&edge(&c, &b))).unwrap();
        let without_ancestry = project(&edge(&c, &b));
        assert_eq!(heads(&with_ancestry), heads(&without_ancestry));
        assert_ne!(with_ancestry, without_ancestry);
        let old_a = project(&state(&a));
        assert_eq!(
            heads(&join(&with_ancestry, &old_a).unwrap()),
            BTreeSet::from([*c])
        );
        assert_eq!(
            heads(&join(&without_ancestry, &old_a).unwrap()),
            BTreeSet::from([*a, *c])
        );
    }

    #[test]
    fn cyclic_and_self_observations_are_deterministic() {
        let a = ufoid();
        let b = ufoid();
        let ab = project(&edge(&a, &b));
        let ba = project(&edge(&b, &a));
        let cycle = join(&ab, &ba).unwrap();
        assert_eq!(cycle, join(&ba, &ab).unwrap());
        assert!(heads(&cycle).is_empty());
        assert_eq!(join(&cycle, &project(&state(&a))).unwrap(), cycle);
        let self_edge = project(&edge(&a, &a));
        assert!(heads(&self_edge).is_empty());
        validate_element(&cycle).unwrap();
        validate_element(&self_edge).unwrap();
    }

    #[test]
    fn substituting_random_ids_preserves_known_live_visibility() {
        let intrinsic = entity! { metadata::tag: metadata::KIND_MULTI };
        let intrinsic_id = intrinsic.root().unwrap();
        let random = rngid();
        let successor = rngid();
        for (id, mut facts) in [
            (intrinsic_id, intrinsic.into_facts()),
            (*random, state(&random)),
        ] {
            assert_eq!(heads(&project(&facts)), BTreeSet::from([id]));
            facts += entity! { &successor @ metadata::supersedes: id };
            assert_eq!(heads(&project(&facts)), BTreeSet::from([*successor]));
        }
    }

    #[test]
    fn every_split_field_partition_distributes_over_union_with_canonical_join_laws() {
        // The tag and name halves describe one state but need not arrive
        // together. Every subject contributes immediately, before shape joins.
        let a = ufoid();
        let b = ufoid();
        let c = ufoid();
        let facts = [
            state(&a),
            entity! { &a @ metadata::name: "split" }.into(),
            edge(&b, &a),
            state(&b),
            edge(&c, &b),
        ];
        let mut all = TribleSet::new();
        for fact in &facts {
            all += fact.clone();
        }
        let expected = project(&all);
        for assignment in 0..3usize.pow(facts.len() as u32) {
            let mut partitions = [TribleSet::new(), TribleSet::new(), TribleSet::new()];
            let mut choices = assignment;
            for fact in &facts {
                partitions[choices % 3] += fact.clone();
                choices /= 3;
            }
            let [x, y, z] = partitions.map(|facts| project(&facts));
            let xy = join(&x, &y).unwrap();
            assert_eq!(
                xy,
                join(&y, &x).unwrap(),
                "commutative partition {assignment}"
            );
            assert_eq!(
                join(&xy, &z).unwrap(),
                expected,
                "distributive partition {assignment}"
            );
            assert_eq!(
                join(&x, &join(&y, &z).unwrap()).unwrap(),
                expected,
                "associative partition {assignment}"
            );
            assert_eq!(
                join(&xy, &xy).unwrap(),
                xy,
                "idempotent partition {assignment}"
            );
            assert_eq!(
                join(&empty(), &xy).unwrap(),
                xy,
                "bottom partition {assignment}"
            );
            validate_element(&xy).unwrap();
        }
        assert_eq!(heads(&project(&facts[0])), BTreeSet::from([*a]));
        assert_eq!(heads(&project(&facts[1])), BTreeSet::from([*a]));
    }

    #[test]
    fn standalone_and_join_queries_enumerate_or_confirm_only_known_live_states() {
        let old = ufoid();
        let live = ufoid();
        let other = ufoid();
        let unknown = ufoid();
        let mut facts = state(&old);
        facts += state(&live);
        facts += state(&other);
        facts += edge(&live, &old);
        let index = LatestIndex::decode(&project(&facts)).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(
            index.states().collect::<BTreeSet<_>>(),
            BTreeSet::from([*live, *other])
        );
        // Advance the facts alone: this id is deliberately unknown to latest.
        facts += state(&unknown);
        let standalone: BTreeSet<_> = find!(state: Id, index.has(state)).collect();
        let conjunction: BTreeSet<_> = find!(state: Id, and!(
            pattern!(&facts, [{ ?state @ metadata::tag: metadata::KIND_MULTI }]),
            index.has(state),
        ))
        .collect();
        assert_eq!(standalone, conjunction);
        for candidate in [*old, *live, *other, *unknown] {
            // The constant is the tighter proposer; latest confirms it.
            let accepted =
                exists!((state: Id), and!(state.is(candidate.to_inline()), index.has(state)));
            assert_eq!(accepted, standalone.contains(&candidate));
        }
    }

    #[test]
    fn configured_edge_is_part_of_mapping_identity_and_does_not_limit_subjects() {
        use super::super::{descriptor, CanonicalDerivation};
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut store = MemoryRepo::default();
        let source = store
            .collection("latest-identity", policy(key.verifying_key()))
            .unwrap();
        let a = CanonicalDerivation::<LatestBlob>::new(metadata::supersedes.id());
        let b = CanonicalDerivation::<LatestBlob>::new(metadata::tag.id());
        let first = descriptor::deriving_with(source.handle(), &a, policy(key.verifying_key()));
        let second = descriptor::deriving_with(source.handle(), &b, policy(key.verifying_key()));
        assert_ne!(first, second);
        assert_eq!(
            descriptor::mapping_algorithm(first.facts()),
            Ok(Some(LATEST_STATES_MAPPING_V1))
        );
        let observes: Inline<GenId> = metadata::supersedes.id().to_inline();
        assert_eq!(
            descriptor::mapping_argument(first.facts(), register_observes.id()),
            Ok(Some(observes.raw))
        );
        let predecessor = ufoid();
        let successor = ufoid();
        let archive: Blob<SimpleArchive> = edge(&successor, &predecessor).to_blob();
        let other_edge = derive_element(&archive, metadata::tag.id()).unwrap();
        assert_eq!(heads(&other_edge), BTreeSet::from([*successor]));
        assert!(sections(&other_edge).unwrap().1.is_empty());
    }

    #[test]
    fn ordinary_collection_maintenance_keeps_frozen_latest_views_and_historical_targets() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let mut store = MemoryRepo::default();
        let source = store
            .collection("maintained-latest", policy(key.verifying_key()))
            .unwrap();
        let target = store
            .derive::<LatestBlob>(
                source,
                metadata::supersedes.id(),
                policy(key.verifying_key()),
            )
            .unwrap();
        let a = ufoid();
        let b = ufoid();
        let c = ufoid();
        store
            .commit(source, &key, Fragment::from(edge(&b, &a)))
            .unwrap();
        let early = block_on(store.maintain(target, &key))
            .unwrap()
            .collection(target)
            .unwrap();
        assert_eq!(
            early
                .view::<LatestIndex>()
                .unwrap()
                .states()
                .collect::<Vec<_>>(),
            [*b]
        );
        store
            .commit(source, &key, Fragment::from(edge(&c, &b)))
            .unwrap();
        let after = block_on(store.maintain(target, &key)).unwrap();
        let frozen = after.collection(target).unwrap();
        assert_eq!(
            frozen
                .view::<LatestIndex>()
                .unwrap()
                .states()
                .collect::<Vec<_>>(),
            [*c]
        );
        store
            .commit(source, &key, Fragment::from(state(&a)))
            .unwrap();
        let caught_up = block_on(store.maintain(target, &key)).unwrap();
        let live: LatestIndex = caught_up.collection(target).unwrap().view().unwrap();
        assert_eq!(live.states().collect::<Vec<_>>(), [*c]);
        assert_eq!(
            early
                .view::<LatestIndex>()
                .unwrap()
                .states()
                .collect::<Vec<_>>(),
            [*b]
        );
        assert_eq!(
            frozen
                .view::<LatestIndex>()
                .unwrap()
                .states()
                .collect::<Vec<_>>(),
            [*c]
        );
        assert_eq!(frozen.support().unwrap().len(), 2);
        assert_eq!(
            caught_up
                .collection(target)
                .unwrap()
                .support()
                .unwrap()
                .len(),
            3
        );
        assert!(caught_up.records().unwrap().any(|record| matches!(record.unwrap(), super::super::CollectionRecord::Merge(merge) if merge.collection() == target.handle())));
    }

    #[test]
    fn malformed_observation_values_are_skipped_without_hiding_the_subject() {
        let a = ufoid();
        let b = ufoid();
        let archive: Blob<SimpleArchive> = edge(&b, &a).to_blob();
        for invalid in [[0; 32], [1; 32]] {
            let mut bytes = archive.bytes.as_ref().to_vec();
            bytes[V_START..V_START + 32].copy_from_slice(&invalid);
            let source = Blob::new(Bytes::from_source(bytes));
            let derived = derive_element(&source, metadata::supersedes.id()).unwrap();
            assert_eq!(heads(&derived), BTreeSet::from([*b]));
            assert!(sections(&derived).unwrap().1.is_empty());
        }
    }

    #[test]
    fn noncanonical_sources_and_lattice_elements_are_rejected() {
        let a = ufoid();
        let b = ufoid();
        let archive: Blob<SimpleArchive> = edge(&b, &a).to_blob();
        let row = archive.bytes.as_ref();
        let duplicate = Blob::new(Bytes::from_source([row, row].concat()));
        assert_eq!(
            derive_element(&duplicate, metadata::supersedes.id()),
            Err(LatestError::InvalidSource(
                UnarchiveError::BadCanonicalizationRedundancy
            ))
        );
        let invalid = Blob::new(Bytes::from_source(vec![0u8; TRIBLE_LEN]));
        assert_eq!(
            derive_element(&invalid, metadata::supersedes.id()),
            Err(LatestError::InvalidSource(UnarchiveError::BadTrible))
        );
        let ragged = Blob::new(Bytes::from_source(vec![0u8; HEADER_LEN - 1]));
        assert_eq!(
            validate_element(&ragged),
            Err(LatestError::BadLength(HEADER_LEN - 1))
        );
        assert_eq!(
            validate_element(&encode(&a[..], &a[..])),
            Err(LatestError::OverlappingSections)
        );
        assert_eq!(
            validate_element(&encode(&[0; ID_LEN], &[])),
            Err(LatestError::NilId)
        );
        assert_eq!(
            validate_element(&encode(&[&a[..], &a[..]].concat(), &[])),
            Err(LatestError::NotStrictlyIncreasing)
        );
        let overflow = Blob::new(Bytes::from_source(vec![255u8; HEADER_LEN]));
        assert_eq!(validate_element(&overflow), Err(LatestError::CountOverflow));
    }
}
