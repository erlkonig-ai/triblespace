//! Maintained last-write-wins registers over stated identity and order facts.
//!
//! [`StatedOrder`](crate::query::register::StatedOrder) resolves a register
//! directly from a fact source. That is the right zero-setup path, but every
//! read repeats the joins from a state to its identity and order value. This
//! module projects exactly those two columns into an exact derived collection
//! and attaches its stored rows as an [`LwwIndex`] without copying them. A
//! reader prepares [`LwwQuery`] when it needs the winners.
//!
//! # Why the maintained element contains both fact halves
//!
//! A state's identity and order facts need not be in the same source commit.
//! Deriving only complete coordinates from each commit would therefore not be
//! a join homomorphism:
//!
//! ```text
//! derive({ state --identity--> register }) = empty
//! derive({ state --order-----> key      }) = empty
//! derive(their union)                    = one coordinate
//! ```
//!
//! The target element instead contains two canonical sorted row sets, one of
//! state/register pairs and one of state/raw-order pairs. Its join is set
//! union. Pairing the halves and selecting the greatest `(key, state-id)`
//! happens when a query is prepared over the exact target cover. Consequently:
//!
//! ```text
//! project(C1 union C2) = project(C1) join project(C2)
//! ```
//!
//! even when every coordinate is partitioned across commits. The maintained
//! bytes are still smaller than the source projection (80 bytes for a complete
//! state rather than two 64-byte tribles), and unrelated facts disappear.
//!
//! # Data contract
//!
//! Within one exact source cover, a state which asserts both halves may assert
//! at most one well-formed identity and at most one order value under the
//! mapping's two attributes. Repeating the same fact is harmless set
//! idempotence. Distinct values are retained by the union law and rejected when
//! query preparation discovers that the state has become a complete coordinate.
//! Multiplicity on an incomplete state is harmless open-world data: it remains
//! retained and incomparable unless the missing half later arrives. Missing
//! halves therefore match
//! [`StatedOrder`](crate::query::register::StatedOrder). Malformed `GenId`
//! identity values are ignored, also matching the live query's typed
//! projection.
//!
//! LWW is total among complete states: keys compare as raw inline bytes and
//! equal keys are broken by state id. The order attribute must therefore use
//! an order-preserving encoding, the same contract as
//! [`StatedOrder::tiebreak_by_id`](crate::query::register::StatedOrder::tiebreak_by_id).
//!
//! [`LwwQuery`]'s `.has(state)` is ordinary positive query membership over its
//! known complete winners. It proposes those ids with their exact cardinality
//! and confirms only them, excluding unknown and incomplete states. The pure
//! [`RegisterOrder`] utility remains available separately; it does not promise
//! positive membership for candidates it has never observed.

use std::collections::{BTreeMap, BTreeSet};
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
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::query::register::{register_identity, register_orders, RegisterOrder};
use crate::query::{
    Binding, Candidates, Constraint, ContainsConstraint, Frontier, ProposalBuffer, Variable,
    VariableId, VariableSet,
};
use crate::repo::BlobStoreGet;
use crate::trible::{Fragment, Trible, A_START, E_START, TRIBLE_LEN, V_START};
use anybytes::{Bytes, View};
use itertools::Itertools;

#[cfg(test)]
use super::records::CollectionHandle;
use super::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
#[cfg(test)]
use super::simplearchive_union;
#[cfg(test)]
use super::CollectionPolicy;
use super::{
    CollectionDerivation, CollectionEncoding, CollectionOperationError, TryFromCover,
    TryFromCoverError,
};

const ID_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 16;
const IDENTITY_ROW_LEN: usize = ID_LEN * 2;
const ORDER_ROW_LEN: usize = ID_LEN + KEY_LEN;

type RawId = [u8; ID_LEN];
type RawKey = [u8; KEY_LEN];

/// Canonical projection of the two fact halves needed by a stated LWW register.
///
/// The first 16 bytes are two big-endian `u64` counts: identity rows followed
/// by order rows. Identity rows are `state[16] || register[16]`; order rows are
/// `state[16] || key[32]`. Each section is strictly increasing by its complete
/// row. Repeating a state with a distinct value is retained so target join is
/// total and remains a plain set union; query preparation enforces uniqueness
/// only when both halves make that state a coordinate.
pub struct LwwRegisterBlob;

impl BlobEncoding for LwwRegisterBlob {}

impl MetaDescribe for LwwRegisterBlob {
    fn describe() -> Fragment {
        // Minted with `trible genid` on 2026-08-28.
        let id: Id = id_hex!("AE6E7C26F39480D80E0162A362F80085");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "lww-register-projection-v1",
            metadata::description: "Canonical projection for maintained stated last-write-wins registers. The payload is two strictly sorted row sets: state with register identity, then state with raw order key. Keeping both halves independently makes projection commute with source union even when a state's facts are split across commits. Readers pair unique complete coordinates and choose the greatest (key, state-id) per register.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Failure to decode, derive, or join a canonical LWW register projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LwwRegisterError {
    /// The source is not a canonical `SimpleArchive`.
    InvalidSource(UnarchiveError),
    /// A payload's declared row counts do not match its byte length.
    BadLength {
        /// Expected length computed from the header.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// Header arithmetic exceeded the platform's addressable size.
    CountOverflow,
    /// An identity section is not strictly increasing by complete row.
    IdentityOrder,
    /// An order-key section is not strictly increasing by complete row.
    KeyOrder,
    /// A target row names the nil state id.
    NilState,
    /// An identity row names the nil register id.
    NilRegister,
    /// One state asserts two distinct register identities.
    ConflictingIdentity(RawId),
    /// One state asserts two distinct order values.
    ConflictingOrder(RawId),
}

impl fmt::Display for LwwRegisterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(source) => write!(formatter, "invalid source archive: {source}"),
            Self::BadLength { expected, actual } => write!(
                formatter,
                "LWW register projection declares {expected} bytes but contains {actual}"
            ),
            Self::CountOverflow => {
                formatter.write_str("LWW register projection row counts overflow address space")
            }
            Self::IdentityOrder => {
                formatter.write_str("LWW register identity rows are not strictly sorted")
            }
            Self::KeyOrder => {
                formatter.write_str("LWW register order rows are not strictly sorted")
            }
            Self::NilState => formatter.write_str("LWW register projection contains a nil state"),
            Self::NilRegister => {
                formatter.write_str("LWW register projection contains a nil register identity")
            }
            Self::ConflictingIdentity(state) => write!(
                formatter,
                "state {} asserts distinct LWW register identities",
                hex::encode_upper(state)
            ),
            Self::ConflictingOrder(state) => write!(
                formatter,
                "state {} asserts distinct LWW order values",
                hex::encode_upper(state)
            ),
        }
    }
}

impl Error for LwwRegisterError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Projection {
    identities: BTreeSet<(RawId, RawId)>,
    orders: BTreeSet<(RawId, RawKey)>,
}

impl Projection {
    fn union(mut self, other: Self) -> Self {
        self.identities.extend(other.identities);
        self.orders.extend(other.orders);
        self
    }

    fn encode(self) -> Blob<LwwRegisterBlob> {
        let identity_count =
            u64::try_from(self.identities.len()).expect("usize identity count fits in u64");
        let order_count = u64::try_from(self.orders.len()).expect("usize order count fits in u64");
        let mut bytes = Vec::with_capacity(
            HEADER_LEN
                + self.identities.len() * IDENTITY_ROW_LEN
                + self.orders.len() * ORDER_ROW_LEN,
        );
        bytes.extend_from_slice(&identity_count.to_be_bytes());
        bytes.extend_from_slice(&order_count.to_be_bytes());
        for (state, register) in self.identities {
            bytes.extend_from_slice(&state);
            bytes.extend_from_slice(&register);
        }
        for (state, key) in self.orders {
            bytes.extend_from_slice(&state);
            bytes.extend_from_slice(&key);
        }
        Blob::new(Bytes::from_source(bytes))
    }
}

fn checked_payload_len(identity_count: usize, order_count: usize) -> Option<usize> {
    HEADER_LEN
        .checked_add(identity_count.checked_mul(IDENTITY_ROW_LEN)?)?
        .checked_add(order_count.checked_mul(ORDER_ROW_LEN)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectionRows {
    identities: View<[[u8; IDENTITY_ROW_LEN]]>,
    orders: View<[[u8; ORDER_ROW_LEN]]>,
}

impl ProjectionRows {
    fn decode(blob: &Blob<LwwRegisterBlob>) -> Result<Self, LwwRegisterError> {
        let bytes = blob.bytes.as_ref();
        if bytes.len() < HEADER_LEN {
            return Err(LwwRegisterError::BadLength {
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let identity_count = usize::try_from(u64::from_be_bytes(
            bytes[0..8].try_into().expect("eight-byte identity count"),
        ))
        .map_err(|_| LwwRegisterError::CountOverflow)?;
        let order_count = usize::try_from(u64::from_be_bytes(
            bytes[8..16].try_into().expect("eight-byte order count"),
        ))
        .map_err(|_| LwwRegisterError::CountOverflow)?;
        let expected = checked_payload_len(identity_count, order_count)
            .ok_or(LwwRegisterError::CountOverflow)?;
        if bytes.len() != expected {
            return Err(LwwRegisterError::BadLength {
                expected,
                actual: bytes.len(),
            });
        }

        let identity_end = HEADER_LEN + identity_count * IDENTITY_ROW_LEN;
        // Framing establishes exact multiples of byte-aligned rows. Retain the
        // original backing; canonical ordering and identifiers are audited by
        // validate_element rather than scanned at ordinary attachment.
        let bad_length = |_| LwwRegisterError::BadLength {
            expected,
            actual: bytes.len(),
        };
        Ok(Self {
            identities: blob
                .bytes
                .slice(HEADER_LEN..identity_end)
                .view()
                .map_err(bad_length)?,
            orders: blob
                .bytes
                .slice(identity_end..)
                .view()
                .map_err(bad_length)?,
        })
    }
}

fn decode_projection(blob: &Blob<LwwRegisterBlob>) -> Result<Projection, LwwRegisterError> {
    let rows = ProjectionRows::decode(blob)?;
    let mut projection = Projection::default();
    let mut previous_identity = None;
    for row in rows.identities.iter() {
        let state: RawId = row[0..ID_LEN].try_into().expect("16-byte state id");
        let register: RawId = row[ID_LEN..IDENTITY_ROW_LEN]
            .try_into()
            .expect("16-byte register id");
        if state == [0; ID_LEN] {
            return Err(LwwRegisterError::NilState);
        }
        if register == [0; ID_LEN] {
            return Err(LwwRegisterError::NilRegister);
        }
        let current = (state, register);
        if previous_identity.is_some_and(|prior| prior >= current) {
            return Err(LwwRegisterError::IdentityOrder);
        }
        previous_identity = Some(current);
        projection.identities.insert(current);
    }

    let mut previous_order = None;
    for row in rows.orders.iter() {
        let state: RawId = row[0..ID_LEN].try_into().expect("16-byte state id");
        let key: RawKey = row[ID_LEN..ORDER_ROW_LEN]
            .try_into()
            .expect("32-byte order key");
        if state == [0; ID_LEN] {
            return Err(LwwRegisterError::NilState);
        }
        let current = (state, key);
        if previous_order.is_some_and(|prior| prior >= current) {
            return Err(LwwRegisterError::KeyOrder);
        }
        previous_order = Some(current);
        projection.orders.insert(current);
    }
    Ok(projection)
}

/// Validate one canonical maintained LWW register element.
pub fn validate_element(blob: &Blob<LwwRegisterBlob>) -> Result<(), LwwRegisterError> {
    decode_projection(blob).map(|_| ())
}

/// The canonical empty maintained LWW register element.
pub fn empty() -> Blob<LwwRegisterBlob> {
    Projection::default().encode()
}

fn genid_value(raw: &[u8]) -> Option<RawId> {
    if raw[0..ID_LEN] != [0; ID_LEN] {
        return None;
    }
    let id: RawId = raw[ID_LEN..KEY_LEN].try_into().expect("16-byte GenId tail");
    (id != [0; ID_LEN]).then_some(id)
}

/// Project one source archive into the two canonical stated-register row sets.
///
/// Well-formed identities and raw order values are collected independently;
/// no atomic-entity assumption is made. Distinct values remain distinct target
/// rows so derivation commutes with arbitrary source partitioning. Attachment
/// rejects them only if both halves make that state a complete coordinate.
pub fn derive_element(
    source: &Blob<SimpleArchive>,
    identity: Id,
    orders: Id,
) -> Result<Blob<LwwRegisterBlob>, LwwRegisterError> {
    let bytes = source.bytes.as_ref();
    if bytes.len() % TRIBLE_LEN != 0 {
        return Err(LwwRegisterError::InvalidSource(UnarchiveError::BadArchive));
    }
    let mut projection = Projection::default();
    let mut previous = None;
    for trible in bytes.chunks_exact(TRIBLE_LEN) {
        let row: &[u8; TRIBLE_LEN] = trible.try_into().expect("64-byte archive row");
        if Trible::as_transmute_force_raw(row).is_none() {
            return Err(LwwRegisterError::InvalidSource(UnarchiveError::BadTrible));
        }
        if let Some(previous) = previous {
            if previous == row {
                return Err(LwwRegisterError::InvalidSource(
                    UnarchiveError::BadCanonicalizationRedundancy,
                ));
            }
            if previous > row {
                return Err(LwwRegisterError::InvalidSource(
                    UnarchiveError::BadCanonicalizationOrdering,
                ));
            }
        }
        previous = Some(row);
        let state: RawId = trible[E_START..E_START + ID_LEN]
            .try_into()
            .expect("16-byte entity id");
        let attribute = &trible[A_START..A_START + ID_LEN];
        let value = &trible[V_START..V_START + KEY_LEN];
        if attribute == &identity[..] {
            if let Some(register) = genid_value(value) {
                projection.identities.insert((state, register));
            }
        }
        if attribute == &orders[..] {
            projection
                .orders
                .insert((state, value.try_into().expect("32-byte inline order value")));
        }
    }
    Ok(projection.encode())
}

/// Canonical join of two maintained LWW register elements.
pub fn join(
    low: &Blob<LwwRegisterBlob>,
    high: &Blob<LwwRegisterBlob>,
) -> Result<Blob<LwwRegisterBlob>, LwwRegisterError> {
    Ok(decode_projection(low)?
        .union(decode_projection(high)?)
        .encode())
}

/// Construct the maintained LWW register descriptor for one source collection.
///
/// The target's independent READ and WRITE policies are explicit rather than
/// inherited from its source.
#[cfg(test)]
pub(crate) fn descriptor(
    source: CollectionHandle,
    identity: Id,
    orders: Id,
    policy: CollectionPolicy,
) -> Fragment {
    let mapping =
        crate::collection::CanonicalDerivation::<LwwRegisterBlob>::new((identity, orders));
    crate::collection::descriptor::deriving_with(source, &mapping, policy)
}

/// Canonical stated-register coordinate projection algorithm, version 1.
///
/// Minted with `trible genid` on 2026-08-29.
pub const REGISTER_COORDINATES_MAPPING_V1: Id = id_hex!("A013A3EE9E5F439BF77F6393058B5BD8");

/// Self-description of the canonical register-coordinate projection.
pub struct RegisterCoordinatesMappingV1;

impl MetaDescribe for RegisterCoordinatesMappingV1 {
    fn describe() -> Fragment {
        let id: Id = REGISTER_COORDINATES_MAPPING_V1;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "register-coordinates-v1",
            metadata::description: "Canonical projection from a SimpleArchive fact set to the two sorted row sets needed by a stated last-write-wins register: state-to-identity and state-to-raw-order. The mapping preserves set union even when the two facts are split across source members; its concrete mapping entity carries `register_identity` and `register_orders`.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

fn mapping_fragment(identity: Id, orders: Id) -> Fragment {
    let identity = crate::inline::IntoInline::to_inline(identity);
    let orders = crate::inline::IntoInline::to_inline(orders);
    entity! { _ @
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <RegisterCoordinatesMappingV1 as MetaDescribe>::describe(),
        register_identity: identity,
        register_orders: orders,
    }
}

fn register_attributes(descriptor: &Fragment) -> Result<(Id, Id), CollectionOperationError> {
    let parse = |attribute, name| {
        let raw = crate::collection::descriptor::mapping_argument(descriptor.facts(), attribute)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal(format!("LWW register mapping is missing {name}"))
            })?;
        Inline::<GenId>::new(raw)
            .try_from_inline::<Id>()
            .map_err(|source| {
                CollectionOperationError::Fatal(format!(
                    "LWW register descriptor has an invalid {name}: {source:?}"
                ))
            })
    };
    Ok((
        parse(register_identity.id(), "register_identity")?,
        parse(register_orders.id(), "register_orders")?,
    ))
}

impl CollectionEncoding for LwwRegisterBlob {
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

impl CollectionDerivation for LwwRegisterBlob {
    type Source = SimpleArchive;
    type Argument = (Id, Id);

    fn fragment(&(identity, orders): &Self::Argument) -> Fragment {
        mapping_fragment(identity, orders)
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        let (identity, orders) = register_attributes(target)?;
        let actual = crate::collection::descriptor::mapping_algorithm(target.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        if actual != Some(REGISTER_COORDINATES_MAPPING_V1) {
            return Err(CollectionOperationError::Fatal(format!(
                "LWW register mapping algorithm {:?} does not match register-coordinates algorithm {REGISTER_COORDINATES_MAPPING_V1:X}",
                actual.map(|id| format!("{id:X}")),
            )));
        }
        Ok((identity, orders))
    }

    fn map<R>(
        &(identity, orders): &Self::Argument,
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<LwwRegisterBlob>, CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        derive_element(source, identity, orders)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

/// Shared persisted rows attached to one frozen last-write-wins cover.
///
/// Attachment checks framing only. [`Self::query`] pairs the stored rows and
/// selects winners when a query actually needs that work.
#[derive(Clone, Debug, Default)]
pub struct LwwIndex {
    members: Vec<ProjectionRows>,
}

impl LwwIndex {
    /// View one typed projection without revalidating its canonical contents.
    pub fn decode(blob: &Blob<LwwRegisterBlob>) -> Result<Self, LwwRegisterError> {
        Ok(Self {
            members: vec![ProjectionRows::decode(blob)?],
        })
    }

    fn identity_rows(&self) -> impl Iterator<Item = &[u8; IDENTITY_ROW_LEN]> {
        self.members
            .iter()
            .map(|member| member.identities.iter())
            .kmerge()
            .dedup()
    }

    fn order_rows(&self) -> impl Iterator<Item = &[u8; ORDER_ROW_LEN]> {
        self.members
            .iter()
            .map(|member| member.orders.iter())
            .kmerge()
            .dedup()
    }

    fn coordinate(&self, state: &RawId) -> Option<(RawId, RawKey)> {
        let register = self.members.iter().find_map(|member| {
            let position = member
                .identities
                .partition_point(|row| row[..ID_LEN] < state[..]);
            member.identities.get(position).and_then(|row| {
                (row[..ID_LEN] == state[..])
                    .then(|| row[ID_LEN..].try_into().expect("16-byte register id"))
            })
        })?;
        let key = self.members.iter().find_map(|member| {
            let position = member
                .orders
                .partition_point(|row| row[..ID_LEN] < state[..]);
            member.orders.get(position).and_then(|row| {
                (row[..ID_LEN] == state[..])
                    .then(|| row[ID_LEN..].try_into().expect("32-byte order key"))
            })
        })?;
        Some((register, key))
    }

    /// Pair complete coordinates and prepare their per-register winners.
    ///
    /// This is the fallible query boundary: distinct identities or order keys
    /// on a complete state remain conflicts. Missing halves remain unresolved.
    /// The prepared query retains shared rows and only the actual winner map;
    /// it does not copy the projected facts into another owned relation.
    pub fn query(&self) -> Result<LwwQuery, LwwRegisterError> {
        let mut identities = self.identity_rows().peekable();
        let mut orders = self.order_rows().peekable();
        let mut winners = BTreeMap::<RawId, (RawKey, RawId)>::new();
        let mut complete = 0;
        let mut unresolved = 0;
        loop {
            let identity_state = identities.peek().map(|row| &row[..ID_LEN]);
            let order_state = orders.peek().map(|row| &row[..ID_LEN]);
            let state: RawId = match (identity_state, order_state) {
                (None, None) => break,
                (Some(state), None) | (None, Some(state)) => state,
                (Some(left), Some(right)) => left.min(right),
            }
            .try_into()
            .expect("16-byte state id");
            if state == [0; ID_LEN] {
                return Err(LwwRegisterError::NilState);
            }

            let mut register = None;
            let mut identity_conflict = false;
            while identities.peek().is_some_and(|row| row[..ID_LEN] == state) {
                let row = identities.next().expect("peeked identity row");
                let value: RawId = row[ID_LEN..].try_into().expect("16-byte register id");
                if value == [0; ID_LEN] {
                    return Err(LwwRegisterError::NilRegister);
                }
                identity_conflict |= register.is_some_and(|prior| prior != value);
                register = Some(value);
            }
            let mut key = None;
            let mut order_conflict = false;
            while orders.peek().is_some_and(|row| row[..ID_LEN] == state) {
                let row = orders.next().expect("peeked order row");
                let value: RawKey = row[ID_LEN..].try_into().expect("32-byte order key");
                order_conflict |= key.is_some_and(|prior| prior != value);
                key = Some(value);
            }
            let (Some(register), Some(key)) = (register, key) else {
                unresolved += 1;
                continue;
            };
            if identity_conflict {
                return Err(LwwRegisterError::ConflictingIdentity(state));
            }
            if order_conflict {
                return Err(LwwRegisterError::ConflictingOrder(state));
            }
            complete += 1;
            let candidate = (key, state);
            winners
                .entry(register)
                .and_modify(|winner| *winner = (*winner).max(candidate))
                .or_insert(candidate);
        }
        Ok(LwwQuery {
            index: self.clone(),
            winners,
            complete,
            unresolved,
        })
    }
}

impl PartialEq for LwwIndex {
    fn eq(&self, other: &Self) -> bool {
        self.identity_rows().eq(other.identity_rows()) && self.order_rows().eq(other.order_rows())
    }
}

impl Eq for LwwIndex {}

/// A prepared last-write-wins query over one frozen projection.
#[derive(Clone, Debug, Default)]
pub struct LwwQuery {
    index: LwwIndex,
    winners: BTreeMap<RawId, (RawKey, RawId)>,
    complete: usize,
    unresolved: usize,
}

impl LwwQuery {
    /// Number of complete state coordinates in the index.
    pub fn len(&self) -> usize {
        self.complete
    }

    /// Whether the index has no complete state coordinates.
    pub fn is_empty(&self) -> bool {
        self.complete == 0
    }

    /// Number of registers with at least one complete state.
    pub fn register_count(&self) -> usize {
        self.winners.len()
    }

    /// Number of projected states missing either identity or order.
    pub fn unresolved_count(&self) -> usize {
        self.unresolved
    }

    /// The total-order winner for `register`, if it has a complete state.
    pub fn winner(&self, register: Id) -> Option<Id> {
        let raw: RawId = register[..].try_into().expect("id is 16 bytes");
        self.winners
            .get(&raw)
            .map(|(_, state)| Id::new(*state).expect("indexed states are non-nil"))
    }

    /// Whether this state is a known complete winner in this observation.
    /// Unknown states and states missing either coordinate half are excluded.
    pub fn contains(&self, state: Id) -> bool {
        let raw: RawId = state[..].try_into().expect("id is 16 bytes");
        self.index.coordinate(&raw).is_some_and(|(register, _)| {
            self.winners
                .get(&register)
                .is_some_and(|(_, winner)| *winner == raw)
        })
    }

    fn coordinates(&self) -> impl Iterator<Item = (RawId, RawId, RawKey)> + '_ {
        self.index
            .identity_rows()
            .map(|row| row[..ID_LEN].try_into().expect("16-byte state id"))
            .dedup()
            .filter_map(|state| {
                self.index
                    .coordinate(&state)
                    .map(|(register, key)| (state, register, key))
            })
    }
}

impl PartialEq for LwwQuery {
    fn eq(&self, other: &Self) -> bool {
        self.complete == other.complete
            && self.unresolved == other.unresolved
            && self.winners == other.winners
            && self.coordinates().eq(other.coordinates())
    }
}

impl Eq for LwwQuery {}

/// Positive membership in an attached index's known complete winning states.
pub struct LwwConstraint<'a> {
    variable: Variable<GenId>,
    index: &'a LwwQuery,
}

impl<'a> ContainsConstraint<'a, GenId> for &'a LwwQuery {
    type Constraint = LwwConstraint<'a>;

    fn has(self, variable: Variable<GenId>) -> Self::Constraint {
        LwwConstraint {
            variable,
            index: self,
        }
    }
}

impl<'a> Constraint<'a> for LwwConstraint<'a> {
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.variable.index)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        (self.variable.index == variable).then_some(self.index.register_count())
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
                proposals.extend(self.index.winners.values().map(|(_, state)| {
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

impl RegisterOrder for LwwQuery {
    fn dominated(&self, state: Id) -> bool {
        let raw: RawId = state[..].try_into().expect("id is 16 bytes");
        let Some((register, _)) = self.index.coordinate(&raw) else {
            return false;
        };
        self.winners
            .get(&register)
            .is_some_and(|(_, winner)| *winner != raw)
    }
}

impl TryFromCover<LwwRegisterBlob> for LwwIndex {
    type Error = LwwRegisterError;

    fn try_from_cover<R>(
        cover: &super::Cover<LwwRegisterBlob>,
        _descriptor: &Fragment,
        reader: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut members = Vec::new();
        for handle in cover.members() {
            let member = Handle::<LwwRegisterBlob>::to_hash(handle);
            let segment = reader
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            members.push(ProjectionRows::decode(&segment).map_err(TryFromCoverError::View)?);
        }
        Ok(Self { members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    fn direct_policy(root: ed25519_dalek::VerifyingKey) -> CollectionPolicy {
        CollectionPolicy::new(
            crate::collection::AdmissionPolicy::direct(root),
            crate::collection::AdmissionPolicy::direct(root),
        )
    }
    use crate::inline::encodings::time::{i128_to_ordered_be, NsTAIInterval};
    use crate::inline::Inline;
    use crate::prelude::*;
    use crate::query::register::{resolve, StatedOrder};
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::trible::TribleSet;
    use std::collections::BTreeSet;

    attributes! {
        "46D95EBAB8D5D0E9103148B35731065C" as state_of: crate::inline::encodings::genid::GenId;
        "3B7AD155842AE30B164A311858D4D9A6" as written_at: NsTAIInterval;
    }

    fn at(nanos: i128) -> Inline<NsTAIInterval> {
        let bound = i128_to_ordered_be(nanos);
        let mut raw = [0u8; KEY_LEN];
        raw[0..16].copy_from_slice(&bound);
        raw[16..32].copy_from_slice(&bound);
        Inline::new(raw)
    }

    fn identity(state: &ExclusiveId, register: &ExclusiveId) -> TribleSet {
        entity! { state @ state_of: register }.into()
    }

    fn order(state: &ExclusiveId, nanos: i128) -> TribleSet {
        entity! { state @ written_at: at(nanos) }.into()
    }

    fn coordinate(state: &ExclusiveId, register: &ExclusiveId, nanos: i128) -> TribleSet {
        let mut facts = identity(state, register);
        facts += order(state, nanos);
        facts
    }

    fn archive(facts: &TribleSet) -> Blob<SimpleArchive> {
        facts.clone().to_blob()
    }

    fn project(facts: &TribleSet) -> Blob<LwwRegisterBlob> {
        derive_element(&archive(facts), state_of.id(), written_at.id()).expect("valid projection")
    }

    fn attach(members: &[Blob<LwwRegisterBlob>]) -> LwwIndex {
        let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let mut store = MemoryRepo::default();
        let source = store
            .collection("lww-row-view", direct_policy(key.verifying_key()))
            .unwrap();
        let target = store
            .derive::<LwwRegisterBlob>(
                source,
                (state_of.id(), written_at.id()),
                direct_policy(key.verifying_key()),
            )
            .unwrap();
        let handles = members
            .iter()
            .cloned()
            .map(|member| store.put(member).unwrap())
            .collect::<Vec<_>>();
        LwwIndex::try_from_cover(&target.cover(handles), &Fragment::empty(), &store).unwrap()
    }

    #[test]
    fn typed_attachment_keeps_shared_rows_and_query_prepares_winners() {
        let register = ufoid();
        let state = ufoid();
        let blob = project(&coordinate(&state, &register, 1));
        let identity_ptr = blob.bytes[HEADER_LEN..].as_ptr();
        let order_ptr = blob.bytes[HEADER_LEN + IDENTITY_ROW_LEN..].as_ptr();
        let index = attach(&[blob.clone()]);
        assert_eq!(
            index.members[0].identities.as_ptr().cast::<u8>(),
            identity_ptr
        );
        assert_eq!(index.members[0].orders.as_ptr().cast::<u8>(), order_ptr);
        let query = index.query().unwrap();
        assert_eq!(
            query.index.members[0].identities.as_ptr().cast::<u8>(),
            identity_ptr
        );
        drop(blob);
        drop(index);
        assert_eq!(query.winner(*register), Some(*state));
        assert!(query.contains(*state));
    }

    #[test]
    fn attachment_checks_framing_while_full_validation_audits_rows() {
        let nil = Projection {
            identities: BTreeSet::from([([0; ID_LEN], [1; ID_LEN])]),
            orders: BTreeSet::new(),
        }
        .encode();
        assert!(LwwIndex::decode(&nil).is_ok());
        assert_eq!(validate_element(&nil), Err(LwwRegisterError::NilState));
        assert_eq!(
            LwwIndex::decode(&nil).unwrap().query(),
            Err(LwwRegisterError::NilState)
        );

        let canonical = Projection {
            identities: BTreeSet::from([([1; ID_LEN], [3; ID_LEN]), ([2; ID_LEN], [3; ID_LEN])]),
            orders: BTreeSet::new(),
        }
        .encode();
        let mut bytes = canonical.bytes.as_ref().to_vec();
        bytes[HEADER_LEN..HEADER_LEN + ID_LEN].fill(3);
        let noncanonical = Blob::new(Bytes::from_source(bytes));
        assert!(LwwIndex::decode(&noncanonical).is_ok());
        assert_eq!(
            validate_element(&noncanonical),
            Err(LwwRegisterError::IdentityOrder)
        );

        for bytes in [
            vec![0; HEADER_LEN - 1],
            vec![0; HEADER_LEN + 1],
            vec![255; HEADER_LEN],
        ] {
            let blob = Blob::new(Bytes::from_source(bytes));
            assert_eq!(
                LwwIndex::decode(&blob).unwrap_err(),
                validate_element(&blob).unwrap_err()
            );
        }
    }

    #[test]
    fn cover_query_pairs_split_rows_without_owning_the_projection() {
        let register = ufoid();
        let other = ufoid();
        let old = ufoid();
        let winner = ufoid();
        let tied = ufoid();
        let other_winner = ufoid();
        let incomplete = ufoid();
        let members = [
            project(&(identity(&old, &register) + identity(&winner, &register))),
            project(&(order(&old, 1) + order(&winner, 2))),
            project(&coordinate(&tied, &register, 2)),
            project(&coordinate(&other_winner, &other, 3)),
            project(&(coordinate(&old, &register, 1) + identity(&incomplete, &register))),
        ];
        let index = attach(&members);
        for member in &members {
            let ptr = member.bytes[HEADER_LEN..].as_ptr();
            assert!(index
                .members
                .iter()
                .any(|rows| rows.identities.as_ptr().cast::<u8>() == ptr));
        }
        let query = index.query().unwrap();
        let joined = members
            .iter()
            .fold(empty(), |joined, member| join(&joined, member).unwrap());
        let expected = LwwIndex::decode(&joined).unwrap().query().unwrap();
        assert_eq!(query, expected);
        assert_eq!(query.len(), 4);
        assert_eq!(query.unresolved_count(), 1);
        assert_eq!(query.register_count(), 2);
        assert_eq!(query.winner(*register), Some((*winner).max(*tied)));
        assert_eq!(query.winner(*other), Some(*other_winner));
        assert!(!query.dominated(*incomplete));
        let winners = BTreeSet::from([(*winner).max(*tied), *other_winner]);
        assert_eq!(
            find!(state: Id, query.has(state)).collect::<BTreeSet<_>>(),
            winners
        );
        for state in [*old, *winner, *tied, *other_winner, *incomplete] {
            assert_eq!(query.contains(state), expected.contains(state));
            assert_eq!(query.dominated(state), expected.dominated(state));
        }
        let reversed = members.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(attach(&reversed).query().unwrap(), expected);
    }

    #[test]
    fn split_coordinate_conflicts_are_reported_only_when_a_query_is_prepared() {
        let state = ufoid();
        let one = ufoid();
        let two = ufoid();
        let identities = [
            project(&identity(&state, &one)),
            project(&identity(&state, &two)),
        ];
        let unresolved = attach(&identities);
        assert_eq!(unresolved.query().unwrap().unresolved_count(), 1);
        let mut complete = identities.to_vec();
        complete.push(project(&order(&state, 1)));
        let attached = attach(&complete);
        assert_eq!(
            attached.query(),
            Err(LwwRegisterError::ConflictingIdentity(state.raw()))
        );

        let conflicting_orders = attach(&[
            project(&identity(&state, &one)),
            project(&order(&state, 1)),
            project(&order(&state, 2)),
        ]);
        assert_eq!(
            conflicting_orders.query(),
            Err(LwwRegisterError::ConflictingOrder(state.raw()))
        );
    }

    #[test]
    fn positive_membership_proposes_known_winners_and_confirms_without_unknowns() {
        let register = ufoid();
        let other_register = ufoid();
        let old = ufoid();
        let winner = ufoid();
        let other_winner = ufoid();
        let incomplete = ufoid();
        let unknown = ufoid();
        let mut facts = coordinate(&old, &register, 1);
        facts += coordinate(&winner, &register, 2);
        facts += coordinate(&other_winner, &other_register, 1);
        facts += identity(&incomplete, &register);
        let index = LwwIndex::decode(&project(&facts)).unwrap().query().unwrap();
        let standalone: BTreeSet<_> = find!(state: Id, index.has(state)).collect();
        assert_eq!(standalone, BTreeSet::from([*winner, *other_winner]));
        facts += coordinate(&unknown, &register, 3);
        let joined: BTreeSet<_> = find!(state: Id, and!(
            pattern!(&facts, [{ ?state @ state_of: _?register }]),
            index.has(state),
        ))
        .collect();
        assert_eq!(joined, standalone);
        for candidate in [*old, *winner, *other_winner, *incomplete, *unknown] {
            let accepted =
                exists!((state: Id), and!(state.is(candidate.to_inline()), index.has(state)));
            assert_eq!(accepted, standalone.contains(&candidate));
        }
        let empty = LwwIndex::default().query().unwrap();
        assert_eq!(find!(state: Id, empty.has(state)).count(), 0);
    }

    #[test]
    fn split_identity_and_order_facts_form_a_coordinate_only_after_join() {
        let register = ufoid();
        let state = ufoid();
        let identities = identity(&state, &register);
        let orders = order(&state, 42);

        let left = project(&identities);
        let right = project(&orders);
        assert_eq!(LwwIndex::decode(&left).unwrap().query().unwrap().len(), 0);
        assert_eq!(LwwIndex::decode(&right).unwrap().query().unwrap().len(), 0);

        let combined = join(&left, &right).expect("projection row sets join");
        let index = LwwIndex::decode(&combined)
            .expect("joined index decodes")
            .query()
            .unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index.winner(*register), Some(*state));

        let mut union = identities;
        union += orders;
        assert_eq!(combined.bytes.as_ref(), project(&union).bytes.as_ref());
    }

    #[test]
    fn every_three_way_partition_has_the_same_byte_exact_projection() {
        let register = ufoid();
        let other_register = ufoid();
        let first = ufoid();
        let second = ufoid();
        let elsewhere = ufoid();
        let facts = [
            identity(&first, &register),
            order(&first, 1),
            identity(&second, &register),
            order(&second, 2),
            identity(&elsewhere, &other_register),
            order(&elsewhere, 3),
        ];
        let mut complete = TribleSet::new();
        for fact in &facts {
            complete += fact.clone();
        }
        let direct = project(&complete);

        // 3^6 partitions include every way of separating each state's two
        // halves while keeping every source fact in exactly one shard.
        for mut assignment in 0usize..3usize.pow(facts.len() as u32) {
            let mut shards = [TribleSet::new(), TribleSet::new(), TribleSet::new()];
            for fact in &facts {
                let shard = assignment % 3;
                assignment /= 3;
                shards[shard] += fact.clone();
            }
            let joined = join(
                &join(&project(&shards[0]), &project(&shards[1])).unwrap(),
                &project(&shards[2]),
            )
            .unwrap();
            assert_eq!(joined.bytes.as_ref(), direct.bytes.as_ref());
        }
    }

    #[test]
    fn target_join_is_associative_commutative_idempotent_with_empty_unit() {
        let register = ufoid();
        let a = ufoid();
        let b = ufoid();
        let c = ufoid();
        let pa = project(&identity(&a, &register));
        let pb = project(&order(&a, 1));
        let pc = project(&coordinate(&b, &register, 2));
        let duplicate = project(&coordinate(&c, &register, 3));

        let ab = join(&pa, &pb).unwrap();
        assert_eq!(
            join(&pa, &pb).unwrap().bytes.as_ref(),
            join(&pb, &pa).unwrap().bytes.as_ref(),
            "commutative"
        );
        assert_eq!(
            join(&ab, &ab).unwrap().bytes.as_ref(),
            ab.bytes.as_ref(),
            "idempotent"
        );
        assert_eq!(
            join(&ab, &empty()).unwrap().bytes.as_ref(),
            ab.bytes.as_ref(),
            "empty unit"
        );
        let left = join(&join(&ab, &pc).unwrap(), &duplicate).unwrap();
        let right = join(&ab, &join(&pc, &duplicate).unwrap()).unwrap();
        assert_eq!(left.bytes.as_ref(), right.bytes.as_ref(), "associative");
    }

    #[test]
    fn attached_order_matches_live_stated_order_on_valid_data() {
        let register = ufoid();
        let other_register = ufoid();
        let early = ufoid();
        let tied_low = ufoid();
        let tied_high = ufoid();
        let elsewhere = ufoid();
        let identity_only = ufoid();
        let order_only = ufoid();
        let mut facts = TribleSet::new();
        facts += coordinate(&early, &register, 1);
        facts += coordinate(&tied_low, &register, 9);
        facts += coordinate(&tied_high, &register, 9);
        facts += coordinate(&elsewhere, &other_register, 50);
        facts += identity(&identity_only, &register);
        facts += order(&order_only, 99);
        let candidates = [
            *early,
            *tied_low,
            *tied_high,
            *elsewhere,
            *identity_only,
            *order_only,
        ];

        let index = LwwIndex::decode(&project(&facts)).unwrap().query().unwrap();
        let live = StatedOrder::<_, NsTAIInterval>::new(&facts, state_of.id(), written_at.id())
            .tiebreak_by_id();
        assert_eq!(resolve(&index, candidates), resolve(&live, candidates));
        assert_eq!(
            index.winner(*register),
            Some((*tied_low).max(*tied_high)),
            "equal keys break toward the greatest state id"
        );
        assert_eq!(index.winner(*other_register), Some(*elsewhere));
        assert_eq!(index.unresolved_count(), 2);
        assert_eq!(
            resolve(&index, [*identity_only, *order_only]),
            [*identity_only, *order_only]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            "missing coordinates remain incomparable"
        );
    }

    #[test]
    fn malformed_genid_identity_is_ignored_like_the_live_typed_order() {
        let state = ufoid();
        let mut raw = [0u8; TRIBLE_LEN];
        raw[E_START..E_START + ID_LEN].copy_from_slice(&state[..]);
        raw[A_START..A_START + ID_LEN].copy_from_slice(&state_of.id()[..]);
        raw[V_START..V_START + KEY_LEN].fill(0x7f);
        let malformed = Trible::force_raw(raw).expect("entity and attribute are non-nil");
        let mut facts = TribleSet::new();
        facts.insert(&malformed);
        facts += order(&state, 99);

        let index = LwwIndex::decode(&project(&facts)).unwrap().query().unwrap();
        let live = StatedOrder::<_, NsTAIInterval>::new(&facts, state_of.id(), written_at.id())
            .tiebreak_by_id();
        assert_eq!(resolve(&index, [*state]), resolve(&live, [*state]));
        assert_eq!(index.unresolved_count(), 1);
    }

    #[test]
    fn derive_rejects_a_non_trible_source_row_while_scanning_it() {
        let register = ufoid();
        let mut row = [0u8; TRIBLE_LEN];
        row[A_START..A_START + ID_LEN].copy_from_slice(&state_of.id()[..]);
        row[V_START + ID_LEN..V_START + KEY_LEN].copy_from_slice(&register[..]);
        let source: Blob<SimpleArchive> = Blob::new(Bytes::from_source(row.to_vec()));

        assert_eq!(
            derive_element(&source, state_of.id(), written_at.id()),
            Err(LwwRegisterError::InvalidSource(UnarchiveError::BadTrible))
        );
    }

    #[test]
    fn conflicts_are_retained_until_a_state_has_both_halves() {
        let one = ufoid();
        let two = ufoid();
        let state = ufoid();
        let left = project(&identity(&state, &one));
        let right = project(&identity(&state, &two));
        let identities = join(&left, &right).unwrap();
        assert_eq!(
            identities.bytes.as_ref(),
            join(&right, &left).unwrap().bytes.as_ref()
        );
        let mut identity_union = identity(&state, &one);
        identity_union += identity(&state, &two);
        assert_eq!(
            identities.bytes.as_ref(),
            project(&identity_union).bytes.as_ref()
        );
        assert_eq!(
            LwwIndex::decode(&identities)
                .unwrap()
                .query()
                .unwrap()
                .unresolved_count(),
            1,
            "identity-only multiplicity is unrelated open-world data"
        );
        let complete = join(&identities, &project(&order(&state, 1))).unwrap();
        assert_eq!(
            LwwIndex::decode(&complete).unwrap().query(),
            Err(LwwRegisterError::ConflictingIdentity(
                (*state)[..].try_into().unwrap()
            ))
        );

        let first = project(&order(&state, 1));
        let second = project(&order(&state, 2));
        let orders = join(&first, &second).unwrap();
        let mut order_union = order(&state, 1);
        order_union += order(&state, 2);
        assert_eq!(orders.bytes.as_ref(), project(&order_union).bytes.as_ref());
        assert_eq!(
            LwwIndex::decode(&orders)
                .unwrap()
                .query()
                .unwrap()
                .unresolved_count(),
            1,
            "order-only multiplicity is unrelated open-world data"
        );
        let complete = join(&project(&identity(&state, &one)), &orders).unwrap();
        assert_eq!(
            LwwIndex::decode(&complete).unwrap().query(),
            Err(LwwRegisterError::ConflictingOrder(
                (*state)[..].try_into().unwrap()
            ))
        );
    }

    #[test]
    fn descriptor_carries_canonical_register_mapping() {
        use crate::collection::descriptor as descriptor_facts;

        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let policy = || direct_policy(key);
        let source = crate::blob::IntoBlob::<SimpleArchive>::to_blob(
            simplearchive_union::descriptor("source", policy()).into_facts(),
        )
        .get_handle();
        let stated = descriptor(source, state_of.id(), written_at.id(), policy());
        assert_eq!(
            descriptor_facts::mapping_argument(stated.facts(), register_identity.id()),
            Ok(Some(
                <Id as crate::inline::IntoInline<crate::inline::encodings::genid::GenId>>::to_inline(
                    state_of.id(),
                )
                .raw,
            ))
        );
        assert_eq!(
            descriptor_facts::mapping_argument(stated.facts(), register_orders.id()),
            Ok(Some(
                <Id as crate::inline::IntoInline<crate::inline::encodings::genid::GenId>>::to_inline(
                    written_at.id(),
                )
                .raw,
            ))
        );
        assert_ne!(
            stated,
            descriptor(source, metadata::tag.id(), written_at.id(), policy(),)
        );
        assert_eq!(
            descriptor_facts::mapping_algorithm(stated.facts()),
            Ok(Some(REGISTER_COORDINATES_MAPPING_V1))
        );
    }

    #[test]
    fn source_and_derived_descriptors_carry_independent_policies() {
        use crate::collection::descriptor as descriptor_facts;

        let source_root = ed25519_dalek::SigningKey::from_bytes(&[8; 32]).verifying_key();
        let target_root = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        let name = "lww-source".to_owned();
        let source_policy = direct_policy(source_root);
        let target_policy = direct_policy(target_root);
        let mut store = MemoryRepo::default();
        let source = store.collection(&name, source_policy.clone()).unwrap();
        let target = store
            .derive::<LwwRegisterBlob>(
                source,
                (state_of.id(), written_at.id()),
                target_policy.clone(),
            )
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let source_descriptor =
            crate::collection::api::load_collection_descriptor(&snapshot, source.handle())
                .unwrap()
                .fragment;
        let target_descriptor =
            crate::collection::api::load_collection_descriptor(&snapshot, target.handle())
                .unwrap()
                .fragment;

        assert_eq!(
            descriptor_facts::policy(source_descriptor.facts()),
            Ok(source_policy)
        );
        assert_eq!(
            descriptor_facts::policy(target_descriptor.facts()),
            Ok(target_policy)
        );
    }

    #[test]
    fn exact_collection_lifecycle_joins_fact_halves_from_distinct_commits() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let team = signing_key.verifying_key();
        let mut store = MemoryRepo::default();
        let source = store
            .collection("maintained-lww", direct_policy(team))
            .unwrap();
        let target = store
            .derive::<LwwRegisterBlob>(
                source,
                (state_of.id(), written_at.id()),
                direct_policy(team),
            )
            .unwrap();
        let register = ufoid();
        let state = ufoid();
        let identity_commit = store
            .commit(
                source,
                &signing_key,
                Fragment::from(identity(&state, &register)),
            )
            .unwrap();
        let order_commit = store
            .commit(source, &signing_key, Fragment::from(order(&state, 42)))
            .unwrap();
        let support = Support::from_data(source, [identity_commit.data(), order_commit.data()]);

        let snapshot = block_on(store.maintain_exact(target, &signing_key, &support)).unwrap();
        let ensured: LwwIndex = snapshot
            .collection_exact(target, &support)
            .unwrap()
            .view()
            .unwrap();
        assert_eq!(ensured.query().unwrap().winner(*register), Some(*state));
        let attached: LwwIndex = store
            .snapshot()
            .unwrap()
            .collection_exact(target, &support)
            .unwrap()
            .view()
            .unwrap();
        assert_eq!(attached.query().unwrap().winner(*register), Some(*state));
    }

    #[test]
    fn malformed_target_bytes_are_rejected() {
        let ragged = Blob::<LwwRegisterBlob>::new(Bytes::from_source(vec![0u8; HEADER_LEN - 1]));
        assert_eq!(
            validate_element(&ragged),
            Err(LwwRegisterError::BadLength {
                expected: HEADER_LEN,
                actual: HEADER_LEN - 1,
            })
        );

        let state = ufoid();
        let register = ufoid();
        let canonical = project(&identity(&state, &register));
        let mut bytes = canonical.bytes.as_ref().to_vec();
        bytes.extend_from_slice(&[0]);
        let extended = Blob::<LwwRegisterBlob>::new(Bytes::from_source(bytes));
        assert!(matches!(
            validate_element(&extended),
            Err(LwwRegisterError::BadLength { .. })
        ));

        let nil_state = Projection {
            identities: BTreeSet::from([([0; ID_LEN], [1; ID_LEN])]),
            orders: BTreeSet::new(),
        }
        .encode();
        assert_eq!(
            validate_element(&nil_state),
            Err(LwwRegisterError::NilState)
        );

        let nil_register = Projection {
            identities: BTreeSet::from([([1; ID_LEN], [0; ID_LEN])]),
            orders: BTreeSet::new(),
        }
        .encode();
        assert_eq!(
            validate_element(&nil_register),
            Err(LwwRegisterError::NilRegister)
        );

        let mut descending = Vec::new();
        descending.extend_from_slice(&2u64.to_be_bytes());
        descending.extend_from_slice(&0u64.to_be_bytes());
        descending.extend_from_slice(&[2; ID_LEN]);
        descending.extend_from_slice(&[3; ID_LEN]);
        descending.extend_from_slice(&[1; ID_LEN]);
        descending.extend_from_slice(&[3; ID_LEN]);
        let descending = Blob::<LwwRegisterBlob>::new(Bytes::from_source(descending));
        assert_eq!(
            validate_element(&descending),
            Err(LwwRegisterError::IdentityOrder)
        );

        let overflowing = Blob::<LwwRegisterBlob>::new(Bytes::from_source(vec![0xff; HEADER_LEN]));
        assert_eq!(
            validate_element(&overflowing),
            Err(LwwRegisterError::CountOverflow)
        );
    }
}
