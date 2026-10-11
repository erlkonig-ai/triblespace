//! Identifier utilities and ownership mechanisms for Trible Space.
//!
//! For a deeper discussion see the [Identifiers](../book/src/deep-dive/identifiers.md) chapter of the Tribles Book.

/// Fast Unsafe Compressible ID generation.
pub mod fucid;
/// Random Number Generated ID generation.
pub mod rngid;
/// Universal Forgettable Ordered ID generation.
pub mod ufoid;

use std::borrow::Borrow;
use std::cell::RefCell;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::LowerHex;
use std::fmt::UpperHex;
use std::hash::Hash;
use std::marker::PhantomData;
use std::mem;
use std::num::NonZero;
use std::ops::Deref;

use hex::FromHex;

/// Re-export of [`fucid::fucid`].
pub use fucid::fucid;
/// Re-export of [`fucid::FUCIDsource`].
pub use fucid::FUCIDsource;
/// Alias for [`rngid()`] — generates a random 128-bit identifier.
pub use rngid::rngid as genid;
/// Re-export of [`rngid::rngid`].
pub use rngid::rngid;
/// Re-export of [`ufoid::ufoid`].
pub use ufoid::ufoid;

use crate::inline::RawInline;
use crate::inline::INLINE_LEN;
use crate::patch::Entry;
use crate::patch::IdentitySchema;
use crate::patch::PATCH;
use crate::prelude::inlineencodings::GenId;
use crate::query::Constraint;
use crate::query::ContainsConstraint;
use crate::query::Variable;

thread_local!(static OWNED_IDS: IdOwner = IdOwner::new());

/// The length of a 128bit abstract identifier in bytes.
pub const ID_LEN: usize = 16;

/// Represents a 16 byte abstract identifier.
pub type RawId = [u8; ID_LEN];

/// Converts a 16 byte [RawId] reference into an 32 byte [RawInline].
pub(crate) fn id_into_value(id: &RawId) -> RawInline {
    let mut data = [0; INLINE_LEN];
    data[16..32].copy_from_slice(id);
    data
}

/// Converts a 32 byte [RawInline] reference into an 16 byte [RawId].
/// Returns `None` if the value is not in the canonical ID format,
/// i.e. the first 16 bytes are all zero.
pub(crate) fn id_from_value(id: &RawInline) -> Option<RawId> {
    if id[0..16] != [0; 16] {
        return None;
    }
    let id = id[16..32].try_into().unwrap();
    Some(id)
}

/// Represents a unique abstract 128 bit identifier.
/// As we do not allow for all zero `nil` IDs,
/// `Option<Id>` benefits from Option nieche optimizations.
///
/// Note that it has an alignment of 1, and can be referenced as a `[u8; 16]` [RawId].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed(1))]
pub struct Id {
    inner: NonZero<u128>,
}

impl Id {
    /// Creates a new [`Id`] from a [RawId] 16 byte array.
    pub const fn new(id: RawId) -> Option<Self> {
        unsafe { std::mem::transmute::<RawId, Option<Id>>(id) }
    }

    /// Parses a hexadecimal identifier string into an [`Id`].
    ///
    /// Returns `None` if the input is not valid hexadecimal or represents the
    /// nil identifier (all zero bytes).
    pub fn from_hex(hex: &str) -> Option<Self> {
        let raw = <RawId as FromHex>::from_hex(hex).ok()?;
        Id::new(raw)
    }

    /// Forces the creation of an [`Id`] from a [RawId] without checking for nil.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `id` is not the nil value of all zero bytes.
    pub const unsafe fn force(id: RawId) -> Self {
        std::mem::transmute::<RawId, Id>(id)
    }

    /// Transmutes a reference to a [RawId] into a reference to an [`Id`].
    /// Returns `None` if the referenced RawId is nil (all zero).
    pub fn as_transmute_raw(id: &RawId) -> Option<&Self> {
        if *id == [0; 16] {
            None
        } else {
            Some(unsafe { std::mem::transmute::<&RawId, &Id>(id) })
        }
    }

    /// Takes ownership of this Id from the current write context (i.e. thread).
    /// Returns `None` if this Id was not found, because it is not associated with this
    /// write context, or because it is currently acquired.
    pub fn acquire(&self) -> Option<ExclusiveId> {
        OWNED_IDS.with(|owner| owner.take(self))
    }

    /// Returns the raw 16-byte representation of this identifier.
    ///
    /// This is `const` so schema identifiers can be composed at compile time.
    pub const fn raw(self) -> RawId {
        // SAFETY: `Id` is a transparent 16-byte wrapper around a non-zero 128-bit
        // integer. Its representation matches `RawId` by construction, as
        // `Id::new` already transmutes from `RawId` to `Option<Id>`.
        unsafe { std::mem::transmute::<Id, RawId>(self) }
    }
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let s: &RawId = self;
        let o: &RawId = other;
        Ord::cmp(s, o)
    }
}

impl Hash for Id {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let s: &RawId = self;
        Hash::hash(s, state);
    }
}

impl Deref for Id {
    type Target = RawId;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<&Id, &RawId>(self) }
    }
}

impl Borrow<RawId> for Id {
    fn borrow(&self) -> &RawId {
        self
    }
}

impl AsRef<RawId> for Id {
    fn as_ref(&self) -> &RawId {
        self
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl From<Id> for RawId {
    fn from(id: Id) -> Self {
        *id
    }
}

impl From<Id> for RawInline {
    fn from(id: Id) -> Self {
        let raw: RawId = id.into();
        id_into_value(&raw)
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Id({self:X})")
    }
}

impl LowerHex for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self[..] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl UpperHex for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self[..] {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl From<Id> for uuid::Uuid {
    fn from(id: Id) -> Self {
        let id: &RawId = &id;
        uuid::Uuid::from_slice(id).unwrap()
    }
}

/// Error returned when converting a nil (all-zero) UUID into an [`Id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NilUuidError;

impl TryFrom<uuid::Uuid> for Id {
    type Error = NilUuidError;

    fn try_from(id: uuid::Uuid) -> Result<Self, NilUuidError> {
        let bytes = id.into_bytes();
        Id::new(bytes).ok_or(NilUuidError)
    }
}

impl std::fmt::Display for NilUuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UUID conversion failed: the UUID is nil (all zero bytes)"
        )
    }
}

impl std::error::Error for NilUuidError {}

#[doc(hidden)]
pub use hex_literal::hex as _hex_literal_hex;

/// Creates an [`Id`] from a hex string literal.
///
/// # Example
/// ```
/// use triblespace_core::id::id_hex;
/// let id = id_hex!("7D06820D69947D76E7177E5DEA4EA773");
/// ```
#[macro_export]
macro_rules! id_hex {
    ( $data:expr ) => {
        $crate::id::Id::new($crate::id::_hex_literal_hex!($data)).unwrap()
    };
}

/// Re-export of the [`id_hex!`] macro for use in other modules.
pub use id_hex;

/// Represents an ID that can only be used by a single writer at a time.
///
/// [`ExclusiveId`]s are associated with one owning context (typically a thread) at a time.
/// Because they are `Send` and `!Sync`, they can be passed between contexts, but not used concurrently.
/// This makes use of Rust's borrow checker to enforce a weaker form of software transactional memory (STM) without rollbacks - as these are not an issue with the heavy use of copy-on-write data structures.
///
/// They are automatically associated with the thread they are dropped from, which can be used in queries via the [local_ids] constraint.
/// You can also make use of explicit [`IdOwner`] containers to store them when not actively used in a transaction.
///
/// Most methods defined on [`ExclusiveId`] are low-level primitives meant to be used for the implementation of new ownership management strategies,
/// such as a transactional database that tracks checked out IDs for ownership, or distributed ledgers like blockchains.
///
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ExclusiveId {
    /// The underlying identifier.
    pub id: Id,
    // Make sure that the type can't be syntactically initialized.
    // Also make sure that we don't get auto impl of Send and Sync
    _private: PhantomData<*const ()>,
}

unsafe impl Send for ExclusiveId {}

impl ExclusiveId {
    /// Forces a regular (read-only) [`Id`] to become a writable [`ExclusiveId`].
    ///
    /// This is a low-level primitive that is meant to be used for the implementation of new ownership management strategies,
    /// such as a transactional database that tracks checked out IDs for ownership, or distributed ledgers like blockchains.
    ///
    /// This should be done with care, as it allows scenarios where multiple writers can create conflicting information for the same ID.
    /// Similar caution should be applied when using the `force_ref` and `forget` methods.
    ///
    /// # Arguments
    ///
    /// * `id` - The [`Id`] to be forced into an [`ExclusiveId`].
    pub fn force(id: Id) -> Self {
        Self {
            id,
            _private: PhantomData,
        }
    }

    /// Safely transmutes a reference to an [`Id`] into a reference to an [`ExclusiveId`].
    ///
    /// Similar caution should be applied when using the `force` method.
    ///
    /// # Arguments
    ///
    /// * `id` - A reference to the [`Id`] to be transmuted.
    pub fn force_ref(id: &Id) -> &Self {
        unsafe { std::mem::transmute(id) }
    }

    /// Releases the [`ExclusiveId`], returning the underlying [`Id`].
    ///
    /// # Returns
    ///
    /// The underlying [`Id`].
    pub fn release(self) -> Id {
        let id = self.id;
        mem::drop(self);
        id
    }

    /// Forgets the [`ExclusiveId`], leaking ownership of the underlying [`Id`], while returning it.
    ///
    /// This is not as potentially problematic as [force](ExclusiveId::force), because it prevents further writes with the [`ExclusiveId`], thus avoiding potential conflicts.
    ///
    /// # Returns
    ///
    /// The underlying [`Id`].
    pub fn forget(self) -> Id {
        let id = self.id;
        mem::forget(self);
        id
    }
}

impl Drop for ExclusiveId {
    fn drop(&mut self) {
        OWNED_IDS.with(|ids| {
            ids.force_insert(self);
        });
    }
}

impl Deref for ExclusiveId {
    type Target = Id;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl Borrow<RawId> for ExclusiveId {
    fn borrow(&self) -> &RawId {
        self
    }
}

impl Borrow<Id> for ExclusiveId {
    fn borrow(&self) -> &Id {
        self
    }
}

impl AsRef<Id> for ExclusiveId {
    fn as_ref(&self) -> &Id {
        self
    }
}

impl AsRef<ExclusiveId> for ExclusiveId {
    fn as_ref(&self) -> &ExclusiveId {
        self
    }
}

impl AsRef<RawId> for ExclusiveId {
    fn as_ref(&self) -> &RawId {
        self
    }
}

impl AsRef<[u8]> for ExclusiveId {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl Display for ExclusiveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id: &Id = self;
        write!(f, "ExclusiveId({id:X})")
    }
}

/// A constraint that checks if a variable is an [`ExclusiveId`] associated with the current write context (i.e. thread).
pub fn local_ids(v: Variable<GenId>) -> impl Constraint<'static> {
    OWNED_IDS.with(|owner| owner.has(v))
}

/// A container for [`ExclusiveId`]s, allowing for explicit ownership management.
/// There is an implicit [`IdOwner`] for each thread, to which [`ExclusiveId`]s are associated when they are dropped,
/// and which can be queried via the [local_ids] constraint.
///
/// # Example
///
/// ```
/// use triblespace_core::id::{IdOwner, ExclusiveId, fucid};
/// let mut owner = IdOwner::new();
/// let exclusive_id = fucid();
/// let id = owner.insert(exclusive_id);
///
/// assert!(owner.owns(&id));
/// assert_eq!(owner.take(&id), Some(ExclusiveId::force(id)));
/// assert!(!owner.owns(&id));
/// ```
///
pub struct IdOwner {
    owned_ids: RefCell<PATCH<ID_LEN, IdentitySchema, ()>>,
}

/// An [`ExclusiveId`] that is associated with an [`IdOwner`].
/// It is automatically returned to the [`IdOwner`] when dropped.
pub struct OwnedId<'a> {
    /// The underlying identifier.
    pub id: Id,
    owner: &'a IdOwner,
}

impl Default for IdOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl IdOwner {
    /// Creates a new [`IdOwner`].
    ///
    /// This is typically not necessary, as each thread has an implicit [`IdOwner`] associated with it.
    ///
    /// # Returns
    ///
    /// A new [`IdOwner`].
    pub fn new() -> Self {
        Self {
            owned_ids: RefCell::new(PATCH::<ID_LEN, IdentitySchema, ()>::new()),
        }
    }

    /// Inserts an [`ExclusiveId`] into the [`IdOwner`], returning the underlying [`Id`].
    ///
    /// # Arguments
    ///
    /// * `id` - The [`ExclusiveId`] to be inserted.
    ///
    /// # Returns
    ///
    /// The underlying [`Id`].
    pub fn insert(&mut self, id: ExclusiveId) -> Id {
        self.force_insert(&id);
        id.forget()
    }

    /// Defers inserting an [`ExclusiveId`] into the [`IdOwner`], returning an [`OwnedId`].
    /// The [`OwnedId`] will return the [`ExclusiveId`] to the [`IdOwner`] when dropped.
    /// This is useful if you generated an [`ExclusiveId`] that you want to use temporarily,
    /// but want to make sure it is returned to the [`IdOwner`] when you are done.
    ///
    /// # Arguments
    ///
    /// * `id` - The [`ExclusiveId`] to be inserted.
    ///
    /// # Returns
    ///
    /// An [`OwnedId`] that will return the [`ExclusiveId`] to the [`IdOwner`] when dropped.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::U256BE;
    /// use triblespace_core::id_hex;
    ///
    /// let mut owner = IdOwner::new();
    /// let owned_id = owner.defer_insert(fucid());
    /// let trible = Trible::new(&owned_id, &id_hex!("7830D7B3C2DCD44EB3FA68C93D06B973"), &U256BE::inline_from(42u64));
    /// ```
    pub fn defer_insert(&self, id: ExclusiveId) -> OwnedId<'_> {
        OwnedId {
            id: id.forget(),
            owner: self,
        }
    }

    /// Forces an [`Id`] into the [`IdOwner`] as an [`ExclusiveId`].
    ///
    /// # Arguments
    ///
    /// * `id` - The [`Id`] to be forced into an [`ExclusiveId`].
    pub fn force_insert(&self, id: &Id) {
        let entry = Entry::new(id);
        self.owned_ids.borrow_mut().insert(&entry);
    }

    /// Takes an [`Id`] from the [`IdOwner`], returning it as an [`ExclusiveId`].
    ///
    /// # Arguments
    ///
    /// * `id` - The [`Id`] to be taken.
    ///
    /// # Returns
    ///
    /// An [`ExclusiveId`] if the [`Id`] was found, otherwise `None`.
    pub fn take(&self, id: &Id) -> Option<ExclusiveId> {
        if self.owned_ids.borrow().has_prefix(id) {
            self.owned_ids.borrow_mut().remove(id);
            Some(ExclusiveId::force(*id))
        } else {
            None
        }
    }

    /// Get an [`OwnedId`] from the [`IdOwner`].
    /// The [`OwnedId`] will return the [`ExclusiveId`] to the [`IdOwner`] when dropped.
    /// This is useful for temporary exclusive access to an [`Id`].
    /// If you want to keep the [`Id`] for longer, you can use the `take` method,
    /// but you will have to manually return it to the [`IdOwner`] when you are done.
    ///
    /// # Arguments
    ///
    /// * `id` - The [`Id`] to be taken.
    ///
    /// # Returns
    ///
    /// An [`OwnedId`] if the [`Id`] was found, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::id::{IdOwner, ExclusiveId, fucid};
    /// let mut owner = IdOwner::new();
    /// let exclusive_id = fucid();
    /// let id = owner.insert(exclusive_id);
    ///  {
    ///     let mut owned_id = owner.borrow(&id).unwrap();
    ///
    ///     assert_eq!(owned_id.id, id);
    ///     assert!(!owner.owns(&id));
    ///  }
    /// assert!(owner.owns(&id));
    /// ```
    pub fn borrow<'a>(&'a self, id: &Id) -> Option<OwnedId<'a>> {
        self.take(id).map(move |id| OwnedId {
            id: id.forget(),
            owner: self,
        })
    }

    /// Checks if the [`IdOwner`] owns an [`Id`].
    ///
    /// # Arguments
    ///
    /// * `id` - The [`Id`] to be checked.
    ///
    /// # Returns
    ///
    /// `true` if the [`Id`] is owned by the [`IdOwner`], otherwise `false`.
    pub fn owns(&self, id: &Id) -> bool {
        self.owned_ids.borrow().has_prefix(id)
    }
}

impl Deref for OwnedId<'_> {
    type Target = ExclusiveId;

    fn deref(&self) -> &Self::Target {
        ExclusiveId::force_ref(&self.id)
    }
}

impl Borrow<RawId> for OwnedId<'_> {
    fn borrow(&self) -> &RawId {
        self
    }
}

impl Borrow<Id> for OwnedId<'_> {
    fn borrow(&self) -> &Id {
        self
    }
}

impl Borrow<ExclusiveId> for OwnedId<'_> {
    fn borrow(&self) -> &ExclusiveId {
        self
    }
}

impl AsRef<ExclusiveId> for OwnedId<'_> {
    fn as_ref(&self) -> &ExclusiveId {
        self
    }
}

impl AsRef<Id> for OwnedId<'_> {
    fn as_ref(&self) -> &Id {
        self
    }
}

impl AsRef<RawId> for OwnedId<'_> {
    fn as_ref(&self) -> &RawId {
        self
    }
}

impl AsRef<[u8]> for OwnedId<'_> {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl Display for OwnedId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id: &Id = self;
        write!(f, "OwnedId({id:X})")
    }
}

impl<'a> Drop for OwnedId<'a> {
    fn drop(&mut self) {
        self.owner.force_insert(&(self.id));
    }
}

impl ContainsConstraint<'static, GenId> for &IdOwner {
    type Constraint =
        <PATCH<ID_LEN, IdentitySchema, ()> as ContainsConstraint<'static, GenId>>::Constraint;

    fn has(self, v: Variable<GenId>) -> Self::Constraint {
        self.owned_ids.borrow().clone().has(v)
    }
}

#[cfg(test)]
mod tests {
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::examples::literature;
    use crate::id::ExclusiveId;
    use crate::inline::encodings::genid::GenId;
    use crate::inline::encodings::hash::Handle;
    use crate::prelude::*;
    use crate::query::Query;
    use crate::query::VariableContext;

    #[test]
    fn id_formatting() {
        let id: Id = id_hex!("7D06820D69947D76E7177E5DEA4EA773");
        assert_eq!(format!("{id:x}"), "7d06820d69947d76e7177e5dea4ea773");
        assert_eq!(format!("{id:X}"), "7D06820D69947D76E7177E5DEA4EA773");
    }

    #[test]
    fn ns_local_ids() {
        let mut kb = TribleSet::new();

        {
            let isaac = ufoid();
            let jules = ufoid();
            kb += entity! { &jules @
               literature::firstname: "Jules",
               literature::lastname: "Verne"
            };
            kb += entity! { &isaac @
               literature::firstname: "Isaac",
               literature::lastname: "Asimov"
            };
        }

        let mut r: Vec<_> = find!(
            (author: ExclusiveId, name: Inline<Handle<UTF8String>>),
            and!(
                local_ids(author),
                pattern!(&kb, [
                    {?author @
                        literature::firstname: ?name
                    }])
            )
        )
        .map(|(_, n)| n)
        .collect();
        r.sort_by_key(|name| name.raw);
        let mut expected: Vec<Inline<Handle<UTF8String>>> =
            vec!["Isaac".to_inline(), "Jules".to_inline()];
        expected.sort_by_key(|name| name.raw);

        assert_eq!(expected, r);
    }

    #[test]
    fn ns_local_ids_bad_estimates_remain_complete() {
        let mut kb = TribleSet::new();

        {
            let isaac = ufoid();
            let jules = ufoid();
            kb += entity! { &jules @
               literature::firstname: "Jules",
               literature::lastname: "Verne"
            };
            kb += entity! { &isaac @
               literature::firstname: "Isaac",
               literature::lastname: "Asimov"
            };
        }

        let mut ctx = VariableContext::new();
        macro_rules! __local_find_context {
            () => {
                &mut ctx
            };
        }
        let author = ctx.next_variable::<GenId>();
        let name = ctx.next_variable::<Handle<UTF8String>>();

        let base = and!(
            local_ids(author),
            pattern!(&kb, [{ ?author @ literature::firstname: ?name }])
        );

        let mut wrapper = crate::debug::query::EstimateOverrideConstraint::new(base);
        wrapper.set_estimate(author.index, 100);
        wrapper.set_estimate(name.index, 1);

        let q: Query<_, _, _> = Query::new(wrapper, |binding| Some(*name.extract(binding)));
        // Query scheduling may change result order; this regression is about
        // completeness under deliberately misleading estimates.
        let mut r: Vec<Inline<Handle<UTF8String>>> = q.collect();
        r.sort_by_key(|name| name.raw);
        let mut expected: Vec<Inline<Handle<UTF8String>>> =
            vec!["Isaac".to_inline(), "Jules".to_inline()];
        expected.sort_by_key(|name| name.raw);
        assert_eq!(r, expected);
    }
}
