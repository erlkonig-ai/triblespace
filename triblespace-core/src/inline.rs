//! `Inline<S>` (32-byte stored payload), `Encoded<V>` (the
//! Inline-or-Blob sum that `entity!{}` builds), and the conversion
//! traits between them. For a deeper look at portability goals,
//! common formats, and schema design, refer to the "Portability &
//! Common Formats" chapter in the project book.
//!
//! # Example
//!
//! ```
//! use triblespace_core::inline::{Inline, InlineEncoding, IntoInline, TryFromInline};
//! use triblespace_core::metadata::{self, MetaDescribe};
//! use triblespace_core::trible::Fragment;
//! use triblespace_core::id::{ExclusiveId, Id};
//! use triblespace_core::macros::{id_hex, entity};
//! use std::convert::{TryInto, Infallible};
//!
//! // Define a new schema type.
//! // We're going to define an unsigned integer type that is stored as a little-endian 32-byte array.
//! // Note that makes our example easier, as we don't have to worry about sign-extension or padding bytes.
//! pub struct MyNumber;
//!
//! // The schema's identity hex lives inline in its describe body — that's
//! // the only place it appears; callers reach the id via MyNumber::id().
//! // `entity!{ &id @ ... }` returns a Fragment already rooted at `id` with
//! // the listed facts; auto-puts any blob-source values into its local
//! // store. The `metadata::tag` annotation lets schema registries discover
//! // this entity as an inline encoding.
//! impl MetaDescribe for MyNumber {
//!    fn describe() -> Fragment {
//!        let id: Id = id_hex!("345EAC0C5B5D7D034C87777280B88AE2");
//!        entity! { ExclusiveId::force_ref(&id) @
//!            metadata::name: "my_number",
//!            metadata::tag:  metadata::KIND_INLINE_ENCODING,
//!        }
//!    }
//! }
//! impl InlineEncoding for MyNumber {
//!    type ValidationError = ();
//!    type Encoding = Self;
//!    // Every bit pattern is valid for this schema.
//! }
//!
//! // Implement conversion functions for the schema type.
//! // Use `Error = Infallible` when the conversion cannot fail.
//! impl TryFromInline<'_, MyNumber> for u32 {
//!    type Error = Infallible;
//!    fn try_from_inline(v: &Inline<MyNumber>) -> Result<Self, Infallible> {
//!      Ok(u32::from_le_bytes(v.raw[0..4].try_into().unwrap()))
//!    }
//! }
//!
//! impl triblespace_core::inline::IntoEncoded<MyNumber> for u32 {
//!   type Output = Inline<MyNumber>;
//!   fn into_encoded(self) -> Inline<MyNumber> {
//!      // Convert the Rust type to the schema type, i.e. a 32-byte array.
//!      let mut bytes = [0; 32];
//!      bytes[0..4].copy_from_slice(&self.to_le_bytes());
//!      Inline::new(bytes)
//!   }
//! }
//!
//! // Use the schema type to store and retrieve a Rust type.
//! let value: Inline<MyNumber> = MyNumber::inline_from(42u32);
//! let i: u32 = value.from_inline();
//! assert_eq!(i, 42);
//!
//! // You can also implement conversion functions for other Rust types.
//! impl TryFromInline<'_, MyNumber> for u64 {
//!   type Error = Infallible;
//!   fn try_from_inline(v: &Inline<MyNumber>) -> Result<Self, Infallible> {
//!    Ok(u64::from_le_bytes(v.raw[0..8].try_into().unwrap()))
//!   }
//! }
//!
//! impl triblespace_core::inline::IntoEncoded<MyNumber> for u64 {
//!  type Output = Inline<MyNumber>;
//!  fn into_encoded(self) -> Inline<MyNumber> {
//!   let mut bytes = [0; 32];
//!   bytes[0..8].copy_from_slice(&self.to_le_bytes());
//!   Inline::new(bytes)
//!   }
//! }
//!
//! let value: Inline<MyNumber> = MyNumber::inline_from(42u64);
//! let i: u64 = value.from_inline();
//! assert_eq!(i, 42);
//!
//! // And use a value round-trip to convert between Rust types.
//! let value: Inline<MyNumber> = MyNumber::inline_from(42u32);
//! let i: u64 = value.from_inline();
//! assert_eq!(i, 42);
//! ```

/// Built-in inline encoding types and their conversion implementations.
pub mod encodings;

use crate::metadata::MetaDescribe;

use core::fmt;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;

use hex::ToHex;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

/// The length of a value in bytes.
pub const INLINE_LEN: usize = 32;

/// A raw value is simply a 32-byte array.
pub type RawInline = [u8; INLINE_LEN];

/// A value is a 32-byte array that can be (de)serialized as a Rust type.
/// The schema type parameter is an abstract type that represents the meaning
/// and valid bit patterns of the bytes.
///
/// # Example
///
/// ```
/// use triblespace_core::prelude::*;
/// use inlineencodings::R256;
/// use num_rational::Ratio;
///
/// let ratio = Ratio::new(1, 2);
/// let value: Inline<R256> = R256::inline_from(ratio);
/// let ratio2: Ratio<i128> = value.try_from_inline().unwrap();
/// assert_eq!(ratio, ratio2);
/// ```
// Every 32-byte pattern is an `Inline` (schema validity is checked separately
// by `validate`), so it is `FromBytes`, which also derives `TryFromBytes` and
// `FromZeros`.
#[derive(FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct Inline<T: InlineEncoding> {
    /// The 32-byte representation of this value.
    pub raw: RawInline,
    _schema: PhantomData<T>,
}

impl<S: InlineEncoding> Inline<S> {
    /// Create a new value from a 32-byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::inline::{Inline, InlineEncoding};
    /// use triblespace_core::inline::encodings::UnknownInline;
    ///
    /// let bytes = [0; 32];
    /// let value = Inline::<UnknownInline>::new(bytes);
    /// ```
    pub fn new(value: RawInline) -> Self {
        Self {
            raw: value,
            _schema: PhantomData,
        }
    }

    /// Validate this value using its schema.
    pub fn validate(self) -> Result<Self, S::ValidationError> {
        S::validate(self)
    }

    /// Check if this value conforms to its schema.
    pub fn is_valid(&self) -> bool {
        S::validate(*self).is_ok()
    }

    /// Transmute a value from one schema type to another.
    /// This is a safe operation, as the bytes are not changed.
    /// The schema type is only changed in the type system.
    /// This is a zero-cost operation.
    /// This is useful when you have a value with an abstract schema type,
    /// but you know the concrete schema type.
    pub fn transmute<O>(self) -> Inline<O>
    where
        O: InlineEncoding,
    {
        Inline::new(self.raw)
    }

    /// Transmute a value reference from one schema type to another.
    /// This is a safe operation, as the bytes are not changed.
    /// The schema type is only changed in the type system.
    /// This is a zero-cost operation.
    /// This is useful when you have a value reference with an abstract schema type,
    /// but you know the concrete schema type.
    pub fn as_transmute<O>(&self) -> &Inline<O>
    where
        O: InlineEncoding,
    {
        zerocopy::transmute_ref!(self)
    }

    /// Transmute a raw value reference to a value reference.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::inline::{Inline, InlineEncoding};
    /// use triblespace_core::inline::encodings::UnknownInline;
    /// use std::borrow::Borrow;
    ///
    /// let bytes = [0; 32];
    /// let value: Inline<UnknownInline> = Inline::new(bytes);
    /// let value_ref: &Inline<UnknownInline> = &value;
    /// let raw_value_ref: &[u8; 32] = value_ref.borrow();
    /// let value_ref2: &Inline<UnknownInline> = Inline::as_transmute_raw(raw_value_ref);
    /// assert_eq!(&value, value_ref2);
    /// ```
    pub fn as_transmute_raw(value: &RawInline) -> &Self {
        zerocopy::transmute_ref!(value)
    }

    /// Deserialize a value with an abstract schema type to a concrete Rust type.
    ///
    /// This method only works for infallible conversions (where `Error = Infallible`).
    /// For fallible conversions, use the [Inline::try_from_inline] method.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::F64;
    ///
    /// let value: Inline<F64> = (3.14f64).to_inline();
    /// let concrete: f64 = value.from_inline();
    /// ```
    pub fn from_inline<'a, T>(&'a self) -> T
    where
        T: TryFromInline<'a, S, Error = std::convert::Infallible>,
    {
        match <T as TryFromInline<'a, S>>::try_from_inline(self) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Deserialize a value with an abstract schema type to a concrete Rust type.
    ///
    /// This method returns an error if the conversion is not possible.
    /// This might happen if the bytes are not valid for the schema type or if the
    /// rust type can't represent the specific value of the schema type,
    /// e.g. if the schema type is a fractional number and the rust type is an integer.
    ///
    /// For infallible conversions, use the [Inline::from_inline] method.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::R256;
    /// use num_rational::Ratio;
    ///
    /// let value: Inline<R256> = R256::inline_from(Ratio::new(1, 2));
    /// let concrete: Result<Ratio<i128>, _> = value.try_from_inline();
    /// ```
    ///
    pub fn try_from_inline<'a, T>(&'a self) -> Result<T, <T as TryFromInline<'a, S>>::Error>
    where
        T: TryFromInline<'a, S>,
    {
        <T as TryFromInline<'a, S>>::try_from_inline(self)
    }
}

impl<T: InlineEncoding> Copy for Inline<T> {}

impl<T: InlineEncoding> Clone for Inline<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: InlineEncoding> PartialEq for Inline<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<T: InlineEncoding> Eq for Inline<T> {}

impl<T: InlineEncoding> Hash for Inline<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<T: InlineEncoding> Ord for Inline<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<T: InlineEncoding> PartialOrd for Inline<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: InlineEncoding> Borrow<RawInline> for Inline<S> {
    fn borrow(&self) -> &RawInline {
        &self.raw
    }
}

impl<T: InlineEncoding> Debug for Inline<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Inline<{}>({})",
            std::any::type_name::<T>(),
            ToHex::encode_hex::<String>(&self.raw)
        )
    }
}

/// A trait that represents an abstract schema type that can be (de)serialized as a [Inline].
///
/// This trait is usually implemented on a type-level empty struct,
/// but may contain additional information about the schema type as associated constants or types.
/// The [Handle](crate::inline::encodings::hash::Handle) type for example contains type information about the hash algorithm,
/// and the schema of the referenced blob.
///
/// See the [inline](crate::inline) module for more information.
/// See the [BlobEncoding](crate::blob::BlobEncoding) trait for the counterpart trait for blobs.
pub trait InlineEncoding: MetaDescribe + Sized + 'static {
    /// The error type returned by [`validate`](InlineEncoding::validate).
    /// Use `()` or [`Infallible`](std::convert::Infallible) when every bit pattern is valid.
    type ValidationError;

    /// The trait parameter to dispatch via for `entity!{}` field
    /// conversion. For *inline* schemas (32-byte data lives in the
    /// trible), set `Encoding = Self` — sources convert via
    /// `IntoEncoded<Self> { Output = Inline<Self> }`. For
    /// [`Handle<T>`](crate::inline::encodings::hash::Handle), set
    /// `Encoding = T` — sources convert via `IntoEncoded<T> { Output =
    /// Blob<T> }`. The BlobEncoding `T` sitting directly at trait
    /// position 0 is what lets downstream impl `IntoEncoded<MyBlob>
    /// for MyType` without bumping into the orphan rule.
    type Encoding;

    /// Check if the given value conforms to this schema.
    fn validate(value: Inline<Self>) -> Result<Inline<Self>, Self::ValidationError> {
        Ok(value)
    }

    /// Create a new value from a concrete Rust type via [`IntoInline`].
    /// Panics if the underlying conversion panics.
    fn inline_from<T: IntoInline<Self>>(t: T) -> Inline<Self> {
        t.to_inline()
    }

    /// Create a new value from a concrete Rust type via [`TryToInline`].
    /// Returns an error if the conversion fails.
    fn inline_try_from<T: TryToInline<Self>>(
        t: T,
    ) -> Result<Inline<Self>, <T as TryToInline<Self>>::Error> {
        t.try_to_inline()
    }

    /// Lift an already-encoded `Inline<Self>` into the [`Encoded`] sum
    /// `entity!{}` consumes — yields `Encoded::Inline(form)`, no
    /// side-blob.
    ///
    /// Overridable if a schema has unusual storage semantics. The
    /// blob-path counterpart lives on
    /// [`BlobEncoding::to_encoded`](crate::blob::BlobEncoding::to_encoded).
    fn to_encoded(form: Inline<Self>) -> Encoded<Self> {
        Encoded::Inline(form)
    }
}

/// Fallible variant of value conversion — `T → Result<Inline<S>, Error>`.
///
/// Kept as a standalone trait (not folded into [`IntoEncoded`])
/// because the error type is part of the per-source/per-target contract.
/// Used for parses that can fail (e.g. `&str → Hash<Blake3>` via
/// hex-decoding).
pub trait TryToInline<S: InlineEncoding> {
    /// The error type returned when the conversion fails.
    type Error;
    /// Convert the Rust type to a [Inline] with a specific schema type.
    fn try_to_inline(self) -> Result<Inline<S>, Self::Error>;
}

/// User-implemented schema-side encoding trait, in the `From`
/// direction: **the schema is the impl target**, the source is the
/// trait parameter.
///
/// ```ignore
/// impl Encodes<&str> for UTF8String {
///     type Output = Blob<UTF8String>;
///     fn encode(s: &str) -> Blob<UTF8String> { Blob::new(s.into()) }
/// }
/// ```
///
/// This is the canonical orphan-rule shape (mirroring `From<T>` in
/// std): downstream that defines a local `MyBlobEncoding` writes
/// `impl Encodes<ForeignType> for MyBlobEncoding` — the local encoding
/// sits at the impl-target position so Rust's orphan checker
/// trivially accepts the impl, no matter how foreign the source
/// type is.
///
/// The user-facing source-side ergonomic — `source.into_encoded()` /
/// `source.to_inline()` / `source.to_blob()` — is blanket-derived
/// from this trait via [`IntoEncoded`].
pub trait Encodes<Source> {
    /// The concrete form this source produces when encoded for this
    /// schema. `Inline<Self>` for inline encodings, `Blob<Self>` for
    /// blob encodings, or `Inline<Handle<Self>>` for the
    /// precomputed-handle case where `Self: BlobEncoding`.
    type Output;
    /// Run the encoding.
    fn encode(source: Source) -> Self::Output;
}

/// Source-side ergonomic counterpart of [`Encodes`], in the `Into`
/// direction: methods like `42u32.to_inline()` resolve here.
///
/// Blanket-derived from every `Encodes` impl — users never implement
/// `IntoEncoded` directly. The split mirrors std's `From`/`Into`:
/// implement `From`, get `Into` for free.
pub trait IntoEncoded<S> {
    /// The concrete form this source produces.
    type Output;
    /// Run the conversion.
    fn into_encoded(self) -> Self::Output;
}

impl<S, T> IntoEncoded<S> for T
where
    S: Encodes<T>,
{
    type Output = <S as Encodes<T>>::Output;
    fn into_encoded(self) -> Self::Output {
        <S as Encodes<T>>::encode(self)
    }
}

/// Shorthand bound for `IntoEncoded<S, Output = Inline<S>>` — "this
/// source produces a directly-encoded `Inline<S>`, no side-blob."
///
/// `IntoInline` is a supertrait alias over [`IntoEncoded`]: any type
/// that implements `IntoEncoded<S>` with `Output = Inline<S>`
/// automatically becomes `IntoInline<S>`, and gains the
/// `to_inline(self) -> Inline<S>` convenience method.
pub trait IntoInline<S: InlineEncoding>: IntoEncoded<S, Output = Inline<S>> {
    /// Convert directly to `Inline<S>`.
    fn to_inline(self) -> Inline<S>
    where
        Self: Sized,
    {
        self.into_encoded()
    }
}
impl<S, T> IntoInline<S> for T
where
    S: InlineEncoding,
    T: IntoEncoded<S, Output = Inline<S>>,
{
}

/// The two-shape sum an attribute's value can take when an
/// `entity!{}` field is encoded: either a 32-byte [`Inline<V>`]
/// payload that lives directly in the trible, or a [`Blob`](crate::blob::Blob) holding
/// the heavy content with a derivable handle.
///
/// Replaces the older `(Inline<V>, Option<Blob>)` pair that carried
/// an implicit "Option is Some iff V is a Handle schema" invariant.
/// Encoding the split as a sum makes the invariant structural — a
/// `Encoded::Inline` never has a stored blob; a `Encoded::Blob` always
/// does — and drops the redundant handle that used to be carried
/// alongside its own blob.
#[derive(Debug, Clone)]
pub enum Encoded<V: InlineEncoding> {
    /// 32-byte payload stored directly in the trible.
    Inline(Inline<V>),
    /// Bytes resolvable via a content-addressed handle. The handle
    /// is `blob.get_handle().transmute::<V>()` — the same 32 bytes,
    /// just re-phantomed back to the attribute's schema.
    Blob(crate::blob::Blob<crate::blob::encodings::UnknownBlob>),
}

impl<V: InlineEncoding> Encoded<V> {
    /// The 32-byte form that goes into the trible. For
    /// [`Encoded::Blob`], this rederives the handle from the cached
    /// hash in the blob (no rehash) and recasts the phantom.
    pub fn inline(&self) -> Inline<V> {
        match self {
            Encoded::Inline(i) => *i,
            Encoded::Blob(b) => b.get_handle().transmute(),
        }
    }

    /// Yield the inline form alongside the side-blob (if any). This
    /// is the macro consumer's destructuring entry point — it gets
    /// both pieces in one call without losing the structural
    /// guarantee from [`Encoded`].
    pub fn into_parts(
        self,
    ) -> (
        Inline<V>,
        Option<crate::blob::Blob<crate::blob::encodings::UnknownBlob>>,
    ) {
        match self {
            Encoded::Inline(i) => (i, None),
            Encoded::Blob(b) => {
                let h = b.get_handle().transmute();
                (h, Some(b))
            }
        }
    }
}

/// Lift an [`IntoEncoded::Output`] into the [`Encoded`] sum the
/// `entity!{}` macro folds into a Fragment.
///
/// `V` is the *attribute's* inline encoding. Two impls cover everything:
/// - `Inline<V>` delegates to [`InlineEncoding::to_encoded`] — inline
///   path, yields `Encoded::Inline(form)`.
/// - `Blob<T>` targeting `Handle<T>` delegates to
///   [`BlobEncoding::to_encoded`](crate::blob::BlobEncoding::to_encoded) —
///   handle path, yields `Encoded::Blob(form.transmute())`.
///
/// This trait is the **dispatch shim** for the macro layer; the
/// actual logic lives on the schema traits so users (and overriding
/// schemas) can call it directly without going through the trait.
/// `to_encoded` matches the `to_inline`/`to_blob` style of the
/// supertrait aliases.
pub trait ToEncoded<V: InlineEncoding> {
    /// Produce the [`Encoded`] the macro absorbs.
    fn to_encoded(self) -> Encoded<V>;
}

impl<V: InlineEncoding> ToEncoded<V> for Inline<V> {
    fn to_encoded(self) -> Encoded<V> {
        <V as InlineEncoding>::to_encoded(self)
    }
}

/// A trait for converting a [Inline] with a specific schema type to a Rust type.
/// This trait is implemented on the concrete Rust type.
///
/// Values are 32-byte arrays that represent data at a deserialization boundary.
/// Conversions may fail depending on the schema and target type. Use
/// `Error = Infallible` for conversions that genuinely cannot fail (e.g.
/// `ethnum::U256` from `U256BE`), and a real error type for narrowing
/// conversions (e.g. `u64` from `U256BE`).
///
/// This is the counterpart to the [TryToInline] trait.
///
/// See [TryFromBlob](crate::blob::TryFromBlob) for the counterpart trait for blobs.
pub trait TryFromInline<'a, S: InlineEncoding>: Sized {
    /// The error type returned when the conversion fails.
    type Error;
    /// Convert the [Inline] with a specific schema type to the Rust type.
    fn try_from_inline(v: &'a Inline<S>) -> Result<Self, Self::Error>;
}

impl<S: InlineEncoding> Encodes<Inline<S>> for S {
    type Output = Inline<S>;
    fn encode(source: Inline<S>) -> Inline<S> {
        source
    }
}

impl<S: InlineEncoding> Encodes<&Inline<S>> for S {
    type Output = Inline<S>;
    fn encode(source: &Inline<S>) -> Inline<S> {
        *source
    }
}

impl<'a, S: InlineEncoding> TryFromInline<'a, S> for Inline<S> {
    type Error = std::convert::Infallible;
    fn try_from_inline(v: &'a Inline<S>) -> Result<Self, std::convert::Infallible> {
        Ok(*v)
    }
}

impl<'a, S: InlineEncoding> TryFromInline<'a, S> for () {
    type Error = std::convert::Infallible;
    fn try_from_inline(_v: &'a Inline<S>) -> Result<Self, std::convert::Infallible> {
        Ok(())
    }
}
