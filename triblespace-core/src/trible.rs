//! Representation of a single knowledge graph edge.
//!
//! For layout details and edge semantics see the [Trible Structure](../book/src/deep-dive/trible-structure.md) chapter of the Tribles Book.

mod fragment;
mod spread;
mod tribleset;

use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;

use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use crate::id::ExclusiveId;
use crate::id::Id;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;

/// Re-export of [`Fragment`](fragment::Fragment).
pub use fragment::Fragment;
/// Re-export of [`Spread`](spread::Spread).
pub use spread::Spread;
#[doc(hidden)]
pub use tribleset::build_intrinsic_entity;
pub(crate) use tribleset::build_namespaced_intrinsic_entity;
#[doc(hidden)]
pub use tribleset::intrinsic_entity_id_v1;
/// Re-export of [`TribleSet`](tribleset::TribleSet).
pub use tribleset::TribleSet;
/// Re-export of [`TribleSetFingerprint`](tribleset::TribleSetFingerprint).
pub use tribleset::TribleSetFingerprint;

/// The length of a trible in bytes.
pub const TRIBLE_LEN: usize = 64;

/// The start index of the entity in a trible.
pub const E_START: usize = 0;
/// The end index of the entity in a trible (inclusive).
pub const E_END: usize = 15;

/// The start index of the attribute in a trible.
pub const A_START: usize = 16;
/// The end index of the attribute in a trible (inclusive).
pub const A_END: usize = 31;

/// The start index of the value in a trible.
pub const V_START: usize = 32;
/// The end index of the value in a trible (inclusive).
pub const V_END: usize = 63;

/// Fundamentally a trible is always a collection of 64 bytes.
pub type RawTrible = [u8; TRIBLE_LEN];

/// One 16-byte-aligned scratch row used while deriving an intrinsic entity.
///
/// The row starts as `NIL || attribute || value`. After the complete row set
/// has been canonicalized and hashed, the derived entity id is written into
/// the leading 16 bytes in place. Its exact 64-byte representation lets the
/// canonical row sequence be hashed as one contiguous byte slice, while its
/// alignment matches the entity and attribute segment width.
///
/// This is an implementation seam for the `entity!` macro rather than a
/// general serialization format. Use [`Trible`] for ordinary fact
/// construction.
#[doc(hidden)]
#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
)]
#[repr(C, align(16))]
pub struct IntrinsicEntityRow {
    data: RawTrible,
}

impl IntrinsicEntityRow {
    /// Creates a `NIL || attribute || value` scratch row.
    pub fn new(attribute: Id, value: RawInline) -> Self {
        let mut data = [0; TRIBLE_LEN];
        data[A_START..=A_END].copy_from_slice(&attribute[..]);
        data[V_START..=V_END].copy_from_slice(&value);
        Self { data }
    }

    fn fill_entity(&mut self, entity: Id) {
        self.data[E_START..=E_END].copy_from_slice(&entity[..]);
    }

    fn raw(&self) -> &RawTrible {
        &self.data
    }
}

const _: () = {
    assert!(std::mem::size_of::<IntrinsicEntityRow>() == TRIBLE_LEN);
    assert!(std::mem::align_of::<IntrinsicEntityRow>() == crate::id::ID_LEN);
};

/// Fundamental 64-byte tuple of entity, attribute and value used throughout the
/// knowledge graph.
///
/// See the [Trible Structure](../book/src/deep-dive/trible-structure.md)
/// chapter of the Tribles Book for a detailed discussion of the layout and its
/// design rationale.
///
/// The fields are laid out exactly as the 64 bytes on disk and on the wire:
/// entity, attribute, value, with no padding. The type is 16-byte aligned, so
/// a `&[Trible]` view over archive bytes refuses a misaligned base. Its
/// validity, checked by zerocopy's [`TryFromBytes`], is the row rule: neither
/// the entity nor the attribute is nil (all zero).
///
/// The derived [`Ord`] compares the fields in layout order, and each field
/// compares its raw bytes, so it is the byte-lexicographic order of
/// [`Trible::as_raw`].
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TryFromBytes, KnownLayout, Immutable, IntoBytes,
)]
#[repr(C, align(16))]
pub struct Trible {
    e: Id,
    a: Id,
    v: RawInline,
}

const _: () = {
    assert!(std::mem::size_of::<Trible>() == TRIBLE_LEN);
    assert!(std::mem::align_of::<Trible>() == crate::id::ID_LEN);
    assert!(std::mem::offset_of!(Trible, e) == E_START);
    assert!(std::mem::offset_of!(Trible, a) == A_START);
    assert!(std::mem::offset_of!(Trible, v) == V_START);
};

// Hash and Debug go through the raw bytes so both stay exactly what they were
// when the trible was a bare `[u8; 64]`.
impl Hash for Trible {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw().hash(state);
    }
}

impl fmt::Debug for Trible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trible")
            .field("data", self.as_raw())
            .finish()
    }
}

impl Trible {
    /// Creates a new trible from an entity, an attribute, and a value.
    ///
    /// # Arguments
    ///
    /// * `e` - The entity of the trible.
    /// * `a` - The attribute of the trible.
    /// * `v` - The value of the trible.
    ///
    /// # Returns
    ///
    /// A new trible.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::R256;
    ///
    /// let e = fucid();
    /// let a = fucid();
    /// let v: Inline<R256> = R256::inline_from(42);
    /// let trible = Trible::new(&e, &a, &v);
    /// ```
    pub fn new<V: InlineEncoding>(e: &ExclusiveId, a: &Id, v: &Inline<V>) -> Trible {
        Trible::force(e, a, v)
    }

    /// Creates a new trible from an entity, an attribute, and a value.
    /// This is similar to [Trible::new], but takes a plain entity id instead of an owned id.
    /// Allowing to circumvent the ownership system, which can be used to inject
    /// data into a local knowledge graph without owning the entity.
    /// This is useful for loading existing trible data, for example when loading
    /// an existing [crate::trible::TribleSet] from a blob, or when declaring
    /// a namespace.
    ///
    /// # Arguments
    ///
    /// * `e` - The entity of the trible.
    /// * `a` - The attribute of the trible.
    /// * `v` - The value of the trible.
    ///
    /// # Returns
    ///
    /// A new trible.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::R256;
    ///
    /// let e = fucid();
    /// let a = fucid();
    /// let v: Inline<R256> = R256::inline_from(42);
    /// let trible = Trible::force(&e, &a, &v);
    ///
    /// assert_eq!(trible.e(), &*e);
    /// ```
    pub fn force<V: InlineEncoding>(e: &Id, a: &Id, v: &Inline<V>) -> Trible {
        Self {
            e: *e,
            a: *a,
            v: v.raw,
        }
    }

    /// Creates a new trible from a raw trible (a 64-byte array).
    /// It circumvents the ownership system, and is useful for loading existing trible data,
    /// just like [Trible::force].
    ///
    /// # Arguments
    ///
    /// * `data` - The raw trible.
    ///
    /// # Returns
    ///
    /// A new trible if the entity and attribute are not nil
    /// (i.e. they are not all zeroes), otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    ///
    /// let data = [
    ///    // Entity
    ///    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ///    // Attribute
    ///    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ///    // Inline
    ///    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    ///    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    /// ];
    /// let trible = Trible::force_raw(data);
    /// assert!(trible.is_some());
    /// ```
    pub fn force_raw(data: RawTrible) -> Option<Trible> {
        // A by-value read copies into an aligned `Trible`, so the source
        // array's alignment does not matter; only validity can fail.
        Trible::try_read_from_bytes(&data).ok()
    }

    /// Views a raw trible reference as a trible reference.
    /// Circumvents the ownership system, and is useful for loading existing trible data,
    /// just like [Trible::force] and [Trible::force_raw].
    ///
    /// # Arguments
    ///
    /// * `data` - The raw trible reference.
    ///
    /// # Returns
    ///
    /// A trible reference if `data` is 16-byte aligned and the entity and
    /// attribute are not nil (i.e. they are not all zeroes), otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    ///
    /// // A `[u8; 64]` has alignment 1; this wrapper gives it the 16-byte
    /// // alignment a `&Trible` requires.
    /// #[repr(align(16))]
    /// struct Aligned([u8; 64]);
    ///
    /// let data = Aligned([
    ///   // Entity
    ///   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ///   // Attribute
    ///   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ///   // Inline
    ///   32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    ///   48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    /// ]);
    /// let trible = Trible::as_transmute_force_raw(&data.0);
    /// assert!(trible.is_some());
    /// ```
    pub fn as_transmute_force_raw(data: &RawTrible) -> Option<&Self> {
        Trible::try_ref_from_bytes(data).ok()
    }

    /// Returns the entity of the trible.
    ///
    /// # Returns
    ///
    /// The entity of the trible.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    ///
    /// let data = [
    ///   // Entity
    ///   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ///   // Attribute
    ///   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ///   // Inline
    ///   32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    ///   48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    /// ];
    /// let trible = Trible::force_raw(data).unwrap();
    /// let entity = trible.e();
    /// assert_eq!(entity, &Id::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap());
    /// ```
    pub fn e(&self) -> &Id {
        &self.e
    }

    /// Returns the attribute of the trible.
    ///
    /// # Returns
    ///
    /// The attribute of the trible.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    ///
    /// let data = [
    ///   // Entity
    ///   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ///   // Attribute
    ///   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ///   // Inline
    ///   32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    ///   48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    /// ];
    /// let trible = Trible::force_raw(data).unwrap();
    /// let attribute = trible.a();
    /// assert_eq!(attribute, &Id::new([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]).unwrap());
    /// ```
    pub fn a(&self) -> &Id {
        &self.a
    }

    /// Returns the value of the trible.
    ///
    /// # Returns
    ///
    /// The value of the trible.
    ///
    /// # Example
    ///
    /// ```
    /// use triblespace_core::prelude::*;
    /// use inlineencodings::R256;
    ///
    /// let data = [
    ///   // Entity
    ///   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ///   // Attribute
    ///   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ///   // Inline
    ///   32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    ///   48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    /// ];
    /// let trible = Trible::force_raw(data).unwrap();
    /// let value = trible.v::<R256>();
    /// assert_eq!(value, &Inline::new([32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    /// 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]));
    /// ```
    pub fn v<V: InlineEncoding>(&self) -> &Inline<V> {
        Inline::as_transmute_raw(&self.v)
    }

    /// Returns the raw 64-byte EAV content of this trible.
    ///
    /// This is the byte form used on disk and on the wire, and the order
    /// that [`Ord`] compares.
    pub fn as_raw(&self) -> &RawTrible {
        zerocopy::transmute_ref!(self)
    }
}

crate::key_segmentation!(
    /// Segment layout for a 64-byte trible: 16-byte entity, 16-byte attribute, 32-byte value.
    TribleSegmentation, TRIBLE_LEN, [16, 16, 32]
);

crate::key_schema!(
    /// Key schema ordering: Entity → Attribute → Inline.
    EAVOrder, TribleSegmentation, TRIBLE_LEN, [0, 1, 2]
);
crate::key_schema!(
    /// Key schema ordering: Entity → Inline → Attribute.
    EVAOrder, TribleSegmentation, TRIBLE_LEN, [0, 2, 1]
);
crate::key_schema!(
    /// Key schema ordering: Attribute → Entity → Inline.
    AEVOrder, TribleSegmentation, TRIBLE_LEN, [1, 0, 2]
);
crate::key_schema!(
    /// Key schema ordering: Attribute → Inline → Entity.
    AVEOrder, TribleSegmentation, TRIBLE_LEN, [1, 2, 0]
);
crate::key_schema!(
    /// Key schema ordering: Inline → Entity → Attribute.
    VEAOrder, TribleSegmentation, TRIBLE_LEN, [2, 0, 1]
);
crate::key_schema!(
    /// Key schema ordering: Inline → Attribute → Entity.
    VAEOrder, TribleSegmentation, TRIBLE_LEN, [2, 1, 0]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::KeySchema;

    #[rustfmt::skip]
    #[test]
    fn order_eav() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let tree_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        assert_eq!(EAVOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(EAVOrder::key_ordered(&tree_bytes), key_bytes);
    }

    #[rustfmt::skip]
    #[test]
    fn order_eva() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let tree_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        assert_eq!(EVAOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(EVAOrder::key_ordered(&tree_bytes), key_bytes);
    }

    #[rustfmt::skip]
    #[test]
    fn order_aev() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let tree_bytes = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        assert_eq!(AEVOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(AEVOrder::key_ordered(&tree_bytes), key_bytes);
    }

    #[rustfmt::skip]
    #[test]
    fn order_ave() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let tree_bytes = [
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
            60, 61, 62, 63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ];
        assert_eq!(AVEOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(AVEOrder::key_ordered(&tree_bytes), key_bytes);
    }

    #[rustfmt::skip]
    #[test]
    fn order_vea() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ]; 
        let tree_bytes = [
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ];
        assert_eq!(VEAOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(VEAOrder::key_ordered(&tree_bytes), key_bytes);
    }

    #[rustfmt::skip]
    #[test]
    fn order_vae() {
        let key_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let tree_bytes = [
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ];
        assert_eq!(VAEOrder::tree_ordered(&key_bytes), tree_bytes);
        assert_eq!(VAEOrder::key_ordered(&tree_bytes), key_bytes);
    }
}
