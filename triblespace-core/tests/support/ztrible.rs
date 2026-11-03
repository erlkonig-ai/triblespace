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

/// `ZTriblePacked` aligned to 16 as a whole: the ids stay packed (align 1
/// wherever else they are embedded), the row demands an aligned slice.
#[derive(TryFromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(C, align(16))]
pub struct ATrible {
    pub e: PackedId,
    pub a: PackedId,
    pub v: [u8; 32],
}

/// The canonical check in blocks of `block` rows: each block is validated as
/// `[ZTrible]` and then checked strictly increasing, within itself and
/// against the previous block's last row, while its rows are still in cache.
/// A block zerocopy rejects is re-run through the per-row base check, so the
/// first error in row order is reported whichever kind it is, with its index.
#[inline(never)]
pub fn check_ztrible_blocked(
    rows: &[[u8; 64]],
    block: usize,
) -> Result<(), (usize, triblespace_core::blob::encodings::simplearchive::UnarchiveError)> {
    use triblespace_core::blob::encodings::simplearchive::{phase_probe, UnarchiveError};
    assert!(block > 0);
    let mut previous: Option<&[u8; 64]> = None;
    for (number, chunk) in rows.chunks(block).enumerate() {
        let start = number * block;
        if <[ZTrible]>::try_ref_from_bytes(chunk.as_bytes()).is_err() {
            // Rows before `start` passed, so the base check over the block,
            // preceded by the previous block's last row, finds the first error.
            let from = start.saturating_sub(1);
            let to = start + chunk.len();
            return match phase_probe::check_rows_at(&rows[from..to]) {
                Err((index, error)) => Err((from + index, error)),
                Ok(()) => unreachable!("zerocopy rejected a block the base check accepts"),
            };
        }
        for (offset, row) in chunk.iter().enumerate() {
            if let Some(previous) = previous {
                if previous == row {
                    return Err((start + offset, UnarchiveError::BadCanonicalizationRedundancy));
                }
                if previous > row {
                    return Err((start + offset, UnarchiveError::BadCanonicalizationOrdering));
                }
            }
            previous = Some(row);
        }
    }
    Ok(())
}
