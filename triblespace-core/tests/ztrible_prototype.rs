//! Byte identity and validity semantics of the prototype `ZTrible` row.
//! That the derives in `support/ztrible.rs` compile is itself the first check.

#[path = "support/ztrible.rs"]
mod ztrible;

use triblespace_core::blob::encodings::simplearchive::{phase_probe, UnarchiveError};
use ztrible::{check_ztrible_blocked, ATrible, PackedId, ZTrible, ZTriblePacked};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn valid_row(state: &mut u64) -> [u8; 64] {
    let mut row = [0u8; 64];
    for chunk in row.chunks_exact_mut(8) {
        chunk.copy_from_slice(&splitmix(state).to_le_bytes());
    }
    // Guarantee a non-zero entity and attribute without biasing the rest.
    row[(splitmix(state) % 16) as usize] |= 1;
    row[16 + (splitmix(state) % 16) as usize] |= 1;
    row
}

fn accepts(rows: &[[u8; 64]]) -> bool {
    <[ZTrible]>::try_ref_from_bytes(rows.as_bytes()).is_ok()
}

#[test]
fn ztrible_layout_is_64_bytes_align_1() {
    assert_eq!(core::mem::size_of::<ZTrible>(), 64);
    assert_eq!(core::mem::align_of::<ZTrible>(), 1);
    assert_eq!(core::mem::size_of::<PackedId>(), 16);
    assert_eq!(core::mem::align_of::<PackedId>(), 1);
}

#[test]
fn ztrible_rejects_zero_entity_or_attribute() {
    let mut state = 1;
    let good = valid_row(&mut state);
    let mut zero_e = good;
    zero_e[..16].fill(0);
    let mut zero_a = good;
    zero_a[16..32].fill(0);
    let mut zero_both = good;
    zero_both[..32].fill(0);
    assert!(accepts(&[good]));
    assert!(!accepts(&[zero_e]));
    assert!(!accepts(&[zero_a]));
    assert!(!accepts(&[zero_both]));
    // An invalid row anywhere in a slice rejects the whole slice.
    let mut many: Vec<[u8; 64]> = (0..1000).map(|_| valid_row(&mut state)).collect();
    assert!(accepts(&many));
    many[777] = zero_a;
    assert!(!accepts(&many));
}

#[test]
fn ztrible_accepts_zero_value() {
    let mut state = 2;
    let mut row = valid_row(&mut state);
    row[32..].fill(0);
    assert!(accepts(&[row]));
}

#[test]
fn ztrible_nonzero_is_exactly_not_all_zero_bytes() {
    for pos in 0..16 {
        for byte in [0x01u8, 0x80, 0xff] {
            let mut row = [0u8; 64];
            row[pos] = byte;
            row[16] = 1;
            assert!(accepts(&[row]), "entity byte {pos} = {byte:#x}");
            let mut row = [0u8; 64];
            row[0] = 1;
            row[16 + pos] = byte;
            assert!(accepts(&[row]), "attribute byte {pos} = {byte:#x}");
        }
        let mut row = [0u8; 64];
        row[pos] = 1;
        assert!(!accepts(&[row]), "attribute all zero, entity byte {pos}");
    }
    let mut id = [0u8; 16];
    assert!(PackedId::try_ref_from_bytes(&id).is_err());
    for pos in 0..16 {
        id = [0u8; 16];
        id[pos] = 1;
        assert!(PackedId::try_ref_from_bytes(&id).is_ok(), "id byte {pos}");
    }
}

#[test]
fn ztrible_view_bytes_equal_input_bytes() {
    let mut state = 3;
    let rows: Vec<[u8; 64]> = (0..100_000).map(|_| valid_row(&mut state)).collect();
    let input = rows.as_bytes();
    let view = <[ZTrible]>::try_ref_from_bytes(input).expect("valid rows");
    assert_eq!(view.len(), rows.len());
    assert_eq!(view.as_bytes(), input);
    assert_eq!(view.as_bytes().as_ptr(), input.as_ptr());
    for (z, row) in view.iter().zip(&rows) {
        assert_eq!(z.e.as_bytes(), &row[..16]);
        assert_eq!(z.a.as_bytes(), &row[16..32]);
        assert_eq!(&z.v, &row[32..]);
        assert_eq!(z.as_bytes(), &row[..]);
    }
}

#[test]
fn ztrible_anybytes_view_validates() {
    use anybytes::{Bytes, View};
    let mut state = 4;
    let mut rows: Vec<[u8; 64]> = (0..1000).map(|_| valid_row(&mut state)).collect();
    let bytes = Bytes::from(rows.clone());
    let view: View<[ZTrible]> = bytes.view().expect("valid rows view");
    assert_eq!(view.len(), 1000);
    rows[3][..16].fill(0);
    assert!(Bytes::from(rows).view::<[ZTrible]>().is_err());
}

/// One id: random, all zero, or a single non-zero byte at a random position.
fn id_case(state: &mut u64, out: &mut [u8]) {
    out.fill(0);
    match splitmix(state) % 3 {
        0 => {
            out[..8].copy_from_slice(&splitmix(state).to_le_bytes());
            out[8..].copy_from_slice(&splitmix(state).to_le_bytes());
        }
        1 => {}
        _ => out[(splitmix(state) % 16) as usize] = (splitmix(state) % 255) as u8 + 1,
    }
}

#[test]
fn ztrible_packed_id_fields_match_ztrible() {
    fn derives<T>()
    where
        T: ?Sized + TryFromBytes + KnownLayout + Immutable + IntoBytes + Unaligned,
    {
    }
    derives::<ZTrible>();
    derives::<ZTriblePacked>();
    derives::<[ZTriblePacked]>();
    assert_eq!(core::mem::size_of::<ZTriblePacked>(), 64);
    assert_eq!(core::mem::align_of::<ZTriblePacked>(), 1);
    let mut state = 5;
    let mut rows: Vec<[u8; 64]> = Vec::with_capacity(100_000);
    let (mut accepted, mut rejected) = (0, 0);
    for _ in 0..100_000 {
        let mut row = valid_row(&mut state);
        id_case(&mut state, &mut row[..16]);
        id_case(&mut state, &mut row[16..32]);
        let z = ZTrible::try_ref_from_bytes(&row).is_ok();
        let p = ZTriblePacked::try_ref_from_bytes(&row);
        assert_eq!(z, p.is_ok(), "row {row:?}");
        if let Ok(p) = p {
            assert_eq!(p.as_bytes(), &row[..]);
            assert_eq!(p.e.as_bytes(), &row[..16]);
            assert_eq!(p.a.as_bytes(), &row[16..32]);
            accepted += 1;
        } else {
            rejected += 1;
        }
        rows.push(row);
    }
    // Both outcomes are exercised: 5/9 of rows have a zero id.
    assert!(accepted > 30_000 && rejected > 40_000, "{accepted} {rejected}");
    // Slices: each type rejects a slice exactly when it holds a rejected row.
    for window in rows.chunks(7) {
        assert_eq!(
            <[ZTrible]>::try_ref_from_bytes(window.as_bytes()).is_ok(),
            <[ZTriblePacked]>::try_ref_from_bytes(window.as_bytes()).is_ok()
        );
    }
    let good: Vec<[u8; 64]> = rows
        .iter()
        .copied()
        .filter(|r| ZTrible::try_ref_from_bytes(r).is_ok())
        .collect();
    assert!(<[ZTriblePacked]>::try_ref_from_bytes(good.as_bytes()).is_ok());
}

fn sorted_rows(len: usize, seed: u64) -> Vec<[u8; 64]> {
    let mut state = seed;
    let mut rows: Vec<[u8; 64]> = (0..len).map(|_| valid_row(&mut state)).collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// The blocked check must agree with the base check on kind and index, and
/// on kind with the decoders' own check, for every block size.
fn assert_blocked_matches_base(rows: &[[u8; 64]], expected: Result<(), (usize, UnarchiveError)>) {
    assert_eq!(phase_probe::check_rows_at(rows), expected);
    assert_eq!(phase_probe::check_rows(rows), expected.map_err(|(_, e)| e));
    for block in [1, 2, 3, 7, 64, 256, 4096] {
        assert_eq!(check_ztrible_blocked(rows, block), expected, "block {block}");
    }
}

#[test]
fn ztrible_blocked_error_order_matches_base() {
    let base = sorted_rows(1000, 6);
    let n = base.len();
    assert_blocked_matches_base(&base, Ok(()));
    let firsts = [0, 1, 2, 6, 7, 63, 64, 254, 255, 256, 500, 900];
    let gaps = [2, 3, 8, 64, 300];
    let mut cases = 0;
    for &i in &firsts {
        for &gap in &gaps {
            let j = i + gap;
            if j + 1 >= n {
                continue;
            }
            for zero in [0..16, 16..32] {
                // An ordering error at i + 1, then a zero id at j.
                let mut rows = base.clone();
                rows.swap(i, i + 1);
                rows[j][zero.clone()].fill(0);
                assert_blocked_matches_base(
                    &rows,
                    Err((i + 1, UnarchiveError::BadCanonicalizationOrdering)),
                );
                // A zero id at i, then an ordering error at j + 1.
                let mut rows = base.clone();
                rows[i][zero.clone()].fill(0);
                rows.swap(j, j + 1);
                assert_blocked_matches_base(&rows, Err((i, UnarchiveError::BadTrible)));
                // A duplicate at i + 1, then a zero id at j.
                let mut rows = base.clone();
                rows[i + 1] = rows[i];
                rows[j][zero.clone()].fill(0);
                assert_blocked_matches_base(
                    &rows,
                    Err((i + 1, UnarchiveError::BadCanonicalizationRedundancy)),
                );
                cases += 3;
            }
        }
    }
    assert!(cases > 100, "{cases}");
}

/// A 16-aligned row of packed ids: 64 bytes, align 16, no padding. An
/// aligned slice of valid rows is accepted, the same bytes one off an
/// alignment boundary are refused as misaligned, and a zero entity is
/// refused as invalid.
#[test]
fn atrible_is_aligned_and_refuses_misaligned_bytes() {
    assert_eq!(core::mem::size_of::<ATrible>(), 64);
    assert_eq!(core::mem::align_of::<ATrible>(), 16);
    assert_eq!(core::mem::align_of::<PackedId>(), 1);

    // u128 storage is 16-aligned; one spare element leaves room to shift.
    let rows = 8;
    let mut storage = vec![0u128; rows * 4 + 1];
    for (i, word) in storage.iter_mut().enumerate() {
        *word = 0x0101_0101_0101_0101_0101_0101_0101_0101 ^ (i as u128 + 1);
    }
    let bytes = storage.as_bytes();
    assert_eq!(bytes.as_ptr() as usize % 16, 0);

    let aligned = &bytes[..rows * 64];
    let view = <[ATrible]>::try_ref_from_bytes(aligned).expect("aligned valid rows");
    assert_eq!(view.len(), rows);
    assert_eq!(view.as_bytes(), aligned);

    let shifted = &bytes[1..1 + rows * 64];
    assert!(matches!(
        <[ATrible]>::try_ref_from_bytes(shifted),
        Err(zerocopy::TryCastError::Alignment(_))
    ));

    let mut zeroed = storage.clone();
    zeroed[4] = 0; // row 1's entity
    assert!(matches!(
        <[ATrible]>::try_ref_from_bytes(&zeroed.as_bytes()[..rows * 64]),
        Err(zerocopy::TryCastError::Validity(_))
    ));
}
