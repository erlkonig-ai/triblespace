//! Anything that can be represented as a byte sequence.
//!
//! Blobs store larger data items outside tribles and values. For the design
//! rationale and an extended usage example see the [Blobs
//! chapter](../book/src/deep-dive/blobs.md) of the Tribles Book.

// Converting Rust types to blobs is infallible in practice, so only `IntoBlob`
// and `TryFromBlob` are used throughout the codebase.  `TryToBlob` and
// `FromBlob` were never required and have been removed for simplicity.

mod cache;
/// Built-in blob encoding types and their conversion implementations.
pub mod encodings;
/// Opaque discovery locators which do not disclose bearer blob handles.
pub mod locator;
mod memoryblobstore;

use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::metadata::MetaDescribe;

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::fmt::{self};
use std::hash::Hash;
use std::marker::PhantomData;

/// Re-export of the blob cache wrapper.
pub use cache::BlobCache;
/// Re-export of the in-memory blob store.
pub use memoryblobstore::{MemoryBlobStore, MemoryBlobStoreSnapshot, MemoryStoreGetError};

/// Re-export of `anybytes::Bytes` for blob payloads.
pub use anybytes::Bytes;

/// A content-addressed value: immutable bytes paired with their
/// Blake3 handle and a schema marker.
///
/// `Blob<S>` is the **heavy form** of a content-addressed payload —
/// it carries the bytes plus the cached
/// [`Inline<Handle<S>>`][Handle] that names them. The handle is the
/// **lightweight form**: a 32-byte reference you can store in
/// tribles, send across the network, or hand around freely without
/// dragging the bytes along. `Blob` ↔ `Handle<S>` is the same
/// "content / reference" duality as `Vec<T>` ↔ `&[T]`, except the
/// reference is hash-based rather than pointer-based and survives
/// crossing process boundaries.
///
/// The link is enforced by construction:
/// - [`Blob::new`] hashes the bytes and stores the resulting handle.
///   Subsequent `get_handle` / `as_ref` calls are O(1).
/// - [`Blob::with_handle`] is the explicit "trust me" constructor for
///   read paths where the handle is already known (a blob-store
///   reader pulling a known-keyed entry, a pile-format decoder where
///   the index has the hash). Caller asserts `handle == Blake3(bytes)`.
/// - [`Blob::transmute`] / [`Blob::as_transmute`] preserve the cached
///   handle across schema casts — the Blake3 hash is over bytes, not
///   over schema, so the digest survives the phantom change.
///
/// `Blob<S>: AsRef<Inline<Handle<S>>>` so `&blob` deref-coerces to the
/// lightweight reference for free.
///
/// The previous shape (`#[repr(transparent)]` around `Bytes`) was
/// given up deliberately: caching the handle in the struct
/// eliminates a real double-hash that surfaced at every `insert` site,
/// and the only call that relied on transparency (`as_transmute`'s
/// `mem::transmute`) still works because `Blob<S>` and `Blob<T>`
/// have identical layouts for any `S`/`T: BlobEncoding` (phantoms
/// are zero-sized, handle is `[u8; 32] + PhantomData`).
pub struct Blob<S: BlobEncoding> {
    /// The raw byte content of this blob.
    pub bytes: Bytes,
    /// Cached content-addressed handle. Computed eagerly at
    /// construction time; reused on every `get_handle` call and on
    /// `MemoryBlobStore::insert`.
    handle: Inline<Handle<S>>,
    _schema: PhantomData<S>,
}

impl<S> Blob<S>
where
    S: BlobEncoding,
    Handle<S>: InlineEncoding,
{
    /// Creates a new blob from a sequence of bytes.
    ///
    /// **Hashes eagerly**: this call runs Blake3 over `bytes` once and
    /// caches the resulting handle. Subsequent `get_handle` /
    /// `MemoryBlobStore::insert` calls reuse the cached value at O(1).
    /// For most use cases this is what callers want — `Blob::new`
    /// almost always precedes an `insert` or a `get_handle`. If you
    /// have a blob path that's *never* hashed and the eager cost
    /// matters, reach for the raw `Bytes` instead.
    pub fn new(bytes: Bytes) -> Self {
        let digest = crate::inline::encodings::hash::Blake3::digest(&bytes);
        Self {
            bytes,
            handle: Inline::new(digest),
            _schema: PhantomData,
        }
    }

    /// Constructs a blob from bytes *and* a precomputed handle,
    /// skipping the hash step.
    ///
    /// Used by blob-store snapshots (`MemoryBlobStoreSnapshot::get` and
    /// friends) and pile-format decoders that already know the
    /// handle the blob is stored under — they read the bytes out of
    /// their backing storage already keyed by hash, so recomputing
    /// it would be pure overhead.
    ///
    /// # Safety
    ///
    /// The caller asserts that `handle == Blake3(bytes)`. The cache
    /// is trusted on read paths; if these diverge,
    /// `MemoryBlobStore::insert(blob)` will store the bytes under
    /// `handle` (not the true Blake3 hash), and subsequent lookups
    /// will silently miss or return wrong data. Always pair this
    /// with a hash you got from a trusted source (the same store
    /// you're reading from, the pile header, a verified network
    /// fetch). For callers without that guarantee, use
    /// [`Blob::new`] which hashes from bytes.
    pub fn with_handle(bytes: Bytes, handle: Inline<Handle<S>>) -> Self {
        Self {
            bytes,
            handle,
            _schema: PhantomData,
        }
    }

    /// Reinterprets the contained bytes as a blob of a different schema.
    ///
    /// This is a zero-copy transformation: bytes pass through and the
    /// cached handle is recast at the phantom level. It does **not**
    /// validate that the data actually conforms to the new schema.
    pub fn transmute<T: BlobEncoding>(self) -> Blob<T>
    where
        Handle<T>: InlineEncoding,
    {
        Blob {
            bytes: self.bytes,
            handle: self.handle.transmute(),
            _schema: PhantomData,
        }
    }

    /// Transmutes the blob to a blob of a different schema.
    /// This is a zero-cost operation.
    /// If the schema types are not compatible, this will not cause undefined behavior,
    /// but it might cause unexpected results.
    ///
    /// This is primarily used to give blobs with an [UnknownBlob](crate::blob::encodings::UnknownBlob) schema a more specific schema.
    /// Use with caution.
    pub fn as_transmute<T: BlobEncoding>(&self) -> &Blob<T> {
        unsafe { std::mem::transmute(self) }
    }

    /// Returns the cached Blake3 handle. O(1) — no rehash.
    ///
    /// The handle is the *lightweight reference* form of this blob —
    /// 32 bytes you can store in a trible, share over the network, or
    /// pass around freely. The blob is the *heavy* form (bytes you
    /// can decode). Both share the same Blake3 identity.
    pub fn get_handle(&self) -> Inline<Handle<S>> {
        self.handle
    }

    /// Tries to convert the blob to a concrete Rust type.
    /// If the conversion fails, an error is returned.
    pub fn try_from_blob<T>(self) -> Result<T, <T as TryFromBlob<S>>::Error>
    where
        T: TryFromBlob<S>,
    {
        <T as TryFromBlob<S>>::try_from_blob(self)
    }
}

impl<T> Clone for Blob<T>
where
    T: BlobEncoding,
    Handle<T>: InlineEncoding,
{
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            handle: self.handle,
            _schema: PhantomData,
        }
    }
}

/// `Blob<S>` borrows as the `Inline<Handle<S>>` that references it.
///
/// Models the heavy/lightweight duality at the type system level:
/// a `Blob<S>` IS a content-addressed value, and its `Handle<S>` is
/// the 32-byte reference form. Coercing a `&Blob<S>` to a
/// `&Inline<Handle<S>>` is free — the handle is stored as a field —
/// so code that wants to pass the lightweight reference around
/// (e.g. inserting into a trible, sending over the network) can
/// just `blob.as_ref()` instead of `&blob.get_handle()`.
impl<S> AsRef<Inline<Handle<S>>> for Blob<S>
where
    S: BlobEncoding,
    Handle<S>: InlineEncoding,
{
    fn as_ref(&self) -> &Inline<Handle<S>> {
        &self.handle
    }
}

impl<T: BlobEncoding> PartialEq for Blob<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T: BlobEncoding> Eq for Blob<T> {}

impl<T: BlobEncoding> Hash for Blob<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<T: BlobEncoding> Debug for Blob<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob<{}>", std::any::type_name::<T>())
    }
}

/// A trait for defining the abstract schema type of a blob.
/// This is similar to the [`InlineEncoding`] trait in the [`inline`](crate::inline) module.
pub trait BlobEncoding: MetaDescribe + Sized + 'static {
    /// Converts a concrete Rust type to a blob with this schema via [`IntoBlob`].
    fn blob_from<T: IntoBlob<Self>>(t: T) -> Blob<Self> {
        t.to_blob()
    }

    /// Lift a `Blob<Self>` into the [`Encoded`](crate::inline::Encoded)
    /// sum `entity!{}` consumes — yields
    /// `Encoded::Blob(blob.transmute())`. The handle lives inside the
    /// blob; consumers recover it via
    /// [`Encoded::inline`](crate::inline::Encoded::inline).
    ///
    /// Overridable if a schema has unusual storage semantics. The
    /// inline-path counterpart lives on
    /// [`InlineEncoding::to_encoded`].
    fn to_encoded(blob: Blob<Self>) -> crate::inline::Encoded<Handle<Self>>
    where
        Handle<Self>: InlineEncoding,
    {
        crate::inline::Encoded::Blob(blob.transmute::<crate::blob::encodings::UnknownBlob>())
    }
}

/// Shorthand bound for `IntoEncoded<S, Output = Blob<S>>` — "this
/// source produces a `Blob<S>` for content-addressed storage."
///
/// `IntoBlob` is a supertrait alias over
/// [`IntoEncoded`](crate::inline::IntoEncoded): any type that
/// implements `IntoEncoded<S>` with `Output = Blob<S>` automatically
/// becomes `IntoBlob<S>`, and gains the `to_blob(self) -> Blob<S>`
/// convenience method.
///
/// The trait parameter is the [`BlobEncoding`] directly (not
/// `Handle<S>`) — this is what makes `impl IntoBlob<MyBlobEncoding>
/// for MyForeignType` legal for downstream crates: the local
/// `MyBlobEncoding` sits at trait position 0, satisfying Rust's
/// orphan rule.
pub trait IntoBlob<S: BlobEncoding>: crate::inline::IntoEncoded<S, Output = Blob<S>> {
    /// Convert directly to `Blob<S>`.
    fn to_blob(self) -> Blob<S>
    where
        Self: Sized,
    {
        self.into_encoded()
    }
}
impl<S, T> IntoBlob<S> for T
where
    S: BlobEncoding,
    T: crate::inline::IntoEncoded<S, Output = Blob<S>>,
{
}

/// A trait for converting a [Blob] with a specific schema to a Rust type.
/// This trait is implemented on the concrete Rust type.
///
/// This might return an error if the conversion is not possible,
/// This is the counterpart to the [`IntoBlob`] trait.
///
/// See [TryFromInline](crate::inline::TryFromInline) for the counterpart trait for values.
pub trait TryFromBlob<S: BlobEncoding>: Sized {
    /// The error type returned when the conversion fails.
    type Error: Error + Send + Sync + 'static;
    /// Attempts to convert a blob into this type.
    fn try_from_blob(b: Blob<S>) -> Result<Self, Self::Error>;
}

impl<S: BlobEncoding> TryFromBlob<S> for Blob<S> {
    type Error = Infallible;

    fn try_from_blob(b: Blob<S>) -> Result<Self, Self::Error> {
        Ok(b)
    }
}

/// `Blob<S>` is the identity source for [`IntoEncoded<S>`](crate::inline::IntoEncoded) in the
/// blob path: it converts to itself with no allocation, and the
/// cached handle inside lets every downstream step skip rehashing.
impl<S: BlobEncoding> crate::inline::Encodes<Blob<S>> for S
where
    Handle<S>: InlineEncoding,
{
    type Output = Blob<S>;
    fn encode(source: Blob<S>) -> Blob<S> {
        source
    }
}

/// `Blob<T>` is the `ToEncoded<Handle<T>>` expander: it delegates to
/// [`BlobEncoding::to_encoded`] for the actual blob-to-Encoded lift. The
/// trait is the macro-side dispatch shim; the logic lives on
/// `BlobEncoding` so users (and schemas that need custom storage
/// semantics) can call or override it directly.
impl<T> crate::inline::ToEncoded<Handle<T>> for Blob<T>
where
    T: BlobEncoding,
    Handle<T>: InlineEncoding,
{
    fn to_encoded(self) -> crate::inline::Encoded<Handle<T>> {
        <T as BlobEncoding>::to_encoded(self)
    }
}

/// Precomputed-handle case: a `Inline<Handle<T>>` can be passed as a
/// `IntoEncoded<T>` source (T is the BlobEncoding, matching the
/// `Handle<T>`-attributed field's `Encoding`). Output is the value
/// itself; no side-blob — caller asserts the bytes live somewhere
/// resolvable.
impl<T: BlobEncoding> crate::inline::Encodes<Inline<Handle<T>>> for T
where
    Handle<T>: InlineEncoding,
{
    type Output = Inline<Handle<T>>;
    fn encode(source: Inline<Handle<T>>) -> Inline<Handle<T>> {
        source
    }
}

/// Reference form of the precomputed-handle case.
impl<T: BlobEncoding> crate::inline::Encodes<&Inline<Handle<T>>> for T
where
    Handle<T>: InlineEncoding,
{
    type Output = Inline<Handle<T>>;
    fn encode(source: &Inline<Handle<T>>) -> Inline<Handle<T>> {
        *source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::encodings::UnknownBlob;
    use crate::inline::encodings::hash::Blake3;

    #[test]
    fn new_computes_and_caches_handle() {
        let b: Blob<UnknownBlob> = Blob::new(Bytes::from(b"hello".to_vec()));
        let h1 = b.get_handle();
        let h2 = b.get_handle();
        // Same handle on repeat — cache is stable.
        assert_eq!(h1, h2);
        // And matches a fresh independent Blake3 of the bytes.
        let independent = Inline::new(Blake3::digest(b"hello"));
        let h_typed: Inline<Handle<UnknownBlob>> = independent;
        assert_eq!(h1, h_typed);
    }

    #[test]
    fn with_handle_trusts_the_provided_handle() {
        // Construct a blob with a *deliberately bogus* handle. The
        // cache returns it verbatim — proving we don't recompute from
        // bytes. This is the optimization read paths exploit (they
        // already know the handle, no point re-hashing).
        let bogus: Inline<Handle<UnknownBlob>> = Inline::new([0xAA; 32]);
        let b: Blob<UnknownBlob> = Blob::with_handle(Bytes::from(b"any bytes".to_vec()), bogus);
        assert_eq!(b.get_handle(), bogus);
    }

    #[test]
    fn as_ref_borrows_the_lightweight_handle() {
        let b: Blob<UnknownBlob> = Blob::new(Bytes::from(b"borrow me".to_vec()));
        let h_owned: Inline<Handle<UnknownBlob>> = b.get_handle();
        let h_borrowed: &Inline<Handle<UnknownBlob>> = b.as_ref();
        // Same value, no allocation, no rehash.
        assert_eq!(h_owned, *h_borrowed);
    }

    #[test]
    fn transmute_carries_cached_handle() {
        let b: Blob<UnknownBlob> = Blob::new(Bytes::from(b"shared".to_vec()));
        let h_before: Inline<Handle<UnknownBlob>> = b.get_handle();
        // Schema cast — handle bytes stay identical, only the phantom
        // changes.
        let b2: Blob<crate::blob::encodings::utf8string::UTF8String> =
            b.transmute::<crate::blob::encodings::utf8string::UTF8String>();
        let h_after = b2.get_handle();
        assert_eq!(h_before.raw, h_after.raw);
    }
}
