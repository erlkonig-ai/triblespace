//! Maintained last-write-wins registers over stated identity and order facts.
//!
//! [`StatedOrder`](crate::query::register::StatedOrder) resolves a register
//! directly from a fact source. That is the right zero-setup path, but every
//! read repeats the joins from a state to its identity and order value. This
//! module projects exactly those two columns into an exact derived collection
//! and builds an [`LwwIndex`](crate::collection::lww_register::LwwIndex) when a
//! reader attaches a cover.
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
//! happens only after the exact target cover has been joined. Consequently:
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
//! attachment discovers that the state has become a complete coordinate.
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
//! [`LwwIndex`]'s `.has(state)` is ordinary positive query membership over its
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
use anybytes::Bytes;

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
/// total and remains a plain set union; attachment enforces uniqueness only
/// when both halves make that state a coordinate.
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

fn decode_projection(blob: &Blob<LwwRegisterBlob>) -> Result<Projection, LwwRegisterError> {
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
    let expected =
        checked_payload_len(identity_count, order_count).ok_or(LwwRegisterError::CountOverflow)?;
    if bytes.len() != expected {
        return Err(LwwRegisterError::BadLength {
            expected,
            actual: bytes.len(),
        });
    }

    let identity_end = HEADER_LEN + identity_count * IDENTITY_ROW_LEN;
    let mut projection = Projection::default();
    let mut previous_identity = None;
    for row in bytes[HEADER_LEN..identity_end].chunks_exact(IDENTITY_ROW_LEN) {
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
    for row in bytes[identity_end..].chunks_exact(ORDER_ROW_LEN) {
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

/// An attached last-write-wins index over one exact source cover.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LwwIndex {
    coordinates: BTreeMap<RawId, (RawId, RawKey)>,
    winners: BTreeMap<RawId, (RawKey, RawId)>,
    unresolved: usize,
}

impl LwwIndex {
    /// Decode one complete canonical projection and select each register's winner.
    pub fn decode(blob: &Blob<LwwRegisterBlob>) -> Result<Self, LwwRegisterError> {
        let projection = decode_projection(blob)?;
        Self::from_projection(projection)
    }

    fn from_projection(projection: Projection) -> Result<Self, LwwRegisterError> {
        let mut identities = BTreeMap::<RawId, Vec<RawId>>::new();
        for (state, register) in projection.identities {
            identities.entry(state).or_default().push(register);
        }
        let mut orders = BTreeMap::<RawId, Vec<RawKey>>::new();
        for (state, key) in projection.orders {
            orders.entry(state).or_default().push(key);
        }
        let states: BTreeSet<RawId> = identities.keys().chain(orders.keys()).copied().collect();
        let mut index = Self::default();
        for state in states {
            let Some(registers) = identities.get(&state) else {
                index.unresolved += 1;
                continue;
            };
            let Some(keys) = orders.get(&state) else {
                index.unresolved += 1;
                continue;
            };
            if registers.len() != 1 {
                return Err(LwwRegisterError::ConflictingIdentity(state));
            }
            if keys.len() != 1 {
                return Err(LwwRegisterError::ConflictingOrder(state));
            }
            let register = registers[0];
            let key = keys[0];
            index.coordinates.insert(state, (register, key));
            let candidate = (key, state);
            index
                .winners
                .entry(register)
                .and_modify(|winner| {
                    if candidate > *winner {
                        *winner = candidate;
                    }
                })
                .or_insert(candidate);
        }
        Ok(index)
    }

    /// Number of complete state coordinates in the index.
    pub fn len(&self) -> usize {
        self.coordinates.len()
    }

    /// Whether the index has no complete state coordinates.
    pub fn is_empty(&self) -> bool {
        self.coordinates.is_empty()
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
        self.coordinates.get(&raw).is_some_and(|(register, _)| {
            self.winners
                .get(register)
                .is_some_and(|(_, winner)| *winner == raw)
        })
    }
}

/// Positive membership in an attached index's known complete winning states.
pub struct LwwConstraint<'a> {
    variable: Variable<GenId>,
    index: &'a LwwIndex,
}

impl<'a> ContainsConstraint<'a, GenId> for &'a LwwIndex {
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

impl RegisterOrder for LwwIndex {
    fn dominated(&self, state: Id) -> bool {
        let raw: RawId = state[..].try_into().expect("id is 16 bytes");
        let Some((register, _)) = self.coordinates.get(&raw) else {
            return false;
        };
        self.winners
            .get(register)
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
        let mut combined = Projection::default();
        for handle in cover.members() {
            let member = Handle::<LwwRegisterBlob>::to_hash(handle);
            let segment = reader
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            combined =
                combined.union(decode_projection(&segment).map_err(TryFromCoverError::View)?);
        }
        Self::from_projection(combined).map_err(TryFromCoverError::View)
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
        let index = LwwIndex::decode(&project(&facts)).unwrap();
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
        let empty = LwwIndex::default();
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
        assert_eq!(LwwIndex::decode(&left).unwrap().len(), 0);
        assert_eq!(LwwIndex::decode(&right).unwrap().len(), 0);

        let combined = join(&left, &right).expect("projection row sets join");
        let index = LwwIndex::decode(&combined).expect("joined index decodes");
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

        let index = LwwIndex::decode(&project(&facts)).unwrap();
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

        let index = LwwIndex::decode(&project(&facts)).unwrap();
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
            LwwIndex::decode(&identities).unwrap().unresolved_count(),
            1,
            "identity-only multiplicity is unrelated open-world data"
        );
        let complete = join(&identities, &project(&order(&state, 1))).unwrap();
        assert_eq!(
            LwwIndex::decode(&complete),
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
            LwwIndex::decode(&orders).unwrap().unresolved_count(),
            1,
            "order-only multiplicity is unrelated open-world data"
        );
        let complete = join(&project(&identity(&state, &one)), &orders).unwrap();
        assert_eq!(
            LwwIndex::decode(&complete),
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
        assert_eq!(ensured.winner(*register), Some(*state));
        let attached: LwwIndex = store
            .snapshot()
            .unwrap()
            .collection_exact(target, &support)
            .unwrap()
            .view()
            .unwrap();
        assert_eq!(attached.winner(*register), Some(*state));
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
