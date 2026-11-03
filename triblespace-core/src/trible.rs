//! Representation of a single knowledge graph edge.
//!
//! For layout details and edge semantics see the [Trible Structure](../book/src/deep-dive/trible-structure.md) chapter of the Tribles Book.

mod fragment;
mod spread;
mod tribleset;

use std::convert::TryInto;

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
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct Trible {
    /// The raw 64-byte EAV content of this trible.
    pub data: RawTrible,
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
        let mut data = [0; TRIBLE_LEN];
        data[E_START..=E_END].copy_from_slice(&e[..]);
        data[A_START..=A_END].copy_from_slice(&a[..]);
        data[V_START..=V_END].copy_from_slice(&v.raw[..]);

        Self { data }
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
        Trible::new(ExclusiveId::force_ref(e), a, v)
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
        if data[E_START..=E_END].iter().all(|&x| x == 0)
            || data[A_START..=A_END].iter().all(|&x| x == 0)
        {
            return None;
        }
        Some(Self { data })
    }

    /// Transmutes a raw trible reference into a trible reference.
    /// Circumvents the ownership system, and is useful for loading existing trible data,
    /// just like [Trible::force] and [Trible::force_raw].
    ///
    /// # Arguments
    ///
    /// * `data` - The raw trible reference.
    ///
    /// # Returns
    ///
    /// A new trible reference if the entity and attribute are not nil
    /// (i.e. they are not all zeroes), otherwise `None`.
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
    /// let trible = Trible::as_transmute_force_raw(&data);
    /// assert!(trible.is_some());
    /// ```
    pub fn as_transmute_force_raw(data: &RawTrible) -> Option<&Self> {
        if data[E_START..=E_END].iter().all(|&x| x == 0)
            || data[A_START..=A_END].iter().all(|&x| x == 0)
        {
            return None;
        }
        Some(unsafe { std::mem::transmute::<&RawTrible, &Self>(data) })
    }

    /// Transmutes a raw trible reference into a trible reference.
    /// Circumvents the ownership system, and does not check if the entity and attribute are nil.
    /// Should only be used if it it certain that the `RawTrible` is actually valid.
    pub fn as_transmute_raw_unchecked(data: &RawTrible) -> &Self {
        unsafe { std::mem::transmute::<&RawTrible, &Self>(data) }
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
        Id::as_transmute_raw(self.data[E_START..=E_END].try_into().unwrap()).unwrap()
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
        Id::as_transmute_raw(self.data[A_START..=A_END].try_into().unwrap()).unwrap()
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
        Inline::as_transmute_raw(self.data[V_START..=V_END].try_into().unwrap())
    }

    /// Returns the raw 64-byte EAV content of this trible.
    ///
    /// This is the byte form used on disk and on the wire, and the order
    /// that [`Ord`] compares.
    pub fn as_raw(&self) -> &RawTrible {
        &self.data
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
