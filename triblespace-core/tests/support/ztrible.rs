//! Standalone prototype row types for the zerocopy-validated canonical check.
//! Not the real `Trible` or `Id`; shared by the `ztrible_prototype` test and
//! the `unarchive_phase_probe` example through `#[path]`.

use core::num::NonZero;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unalign, Unaligned};

/// The shape of the real `Id`: packed, align 1, non-zero.
#[derive(TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C, packed(1))]
pub struct PackedId {
    pub inner: NonZero<u128>,
}

/// A 64-byte row whose validity is exactly the trible row invariant:
/// entity (bytes 0..16) and attribute (16..32) each not all zero.
#[derive(TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
pub struct ZTrible {
    pub e: Unalign<NonZero<u128>>,
    pub a: Unalign<NonZero<u128>>,
    pub v: [u8; 32],
}

/// `ZTrible` with the ids typed as `PackedId`, the field type the real
/// `Trible` would carry.
#[derive(TryFromBytes, KnownLayout, Immutable, IntoBytes, Unaligned)]
#[repr(C)]
pub struct ZTriblePacked {
    pub e: PackedId,
    pub a: PackedId,
    pub v: [u8; 32],
}
