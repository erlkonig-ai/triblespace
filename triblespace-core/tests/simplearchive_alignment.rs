//! The encoded `SimpleArchive` blob starts 16-byte aligned, and its bytes are
//! still exactly the canonical rows.
//!
//! Both encode paths (owned and borrowed set) are checked. The byte oracle is
//! independent of the encoder: the sorted, deduplicated input rows.

use triblespace_core::prelude::blobencodings::SimpleArchive;
use triblespace_core::prelude::*;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// `len` distinct valid rows (non-nil entity and attribute), unsorted.
fn rows(len: usize) -> Vec<[u8; 64]> {
    let mut state = len as u64 ^ 0x243f_6a88_85a3_08d3;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let mut row = [0u8; 64];
        for chunk in row.chunks_exact_mut(8) {
            chunk.copy_from_slice(&splitmix(&mut state).to_be_bytes());
        }
        // A distinct counter in the entity keeps rows distinct and non-nil.
        row[8..16].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        row[31] |= 1;
        out.push(row);
    }
    out
}

fn set_of(rows: &[[u8; 64]]) -> TribleSet {
    let mut set = TribleSet::new();
    for row in rows {
        set.insert(&Trible::force_raw(*row).expect("valid fixture row"));
    }
    set
}

#[test]
fn encoded_archive_is_16_aligned_and_canonical() {
    for len in [1usize, 7, 64, 10_000] {
        let input = rows(len);
        let set = set_of(&input);
        assert_eq!(set.len(), len);

        let mut expected = input.clone();
        expected.sort_unstable();
        let expected: Vec<u8> = expected.concat();

        let borrowed: Blob<SimpleArchive> = (&set).to_blob();
        let owned: Blob<SimpleArchive> = set.clone().to_blob();
        for (path, blob) in [("borrowed", &borrowed), ("owned", &owned)] {
            assert_eq!(
                blob.bytes.as_ptr() as usize % 16,
                0,
                "{path} encode of {len} rows is not 16-aligned"
            );
            assert_eq!(blob.bytes.len(), len * 64, "{path} length, {len} rows");
            assert!(
                blob.bytes.as_ref() == expected.as_slice(),
                "{path} bytes differ from canonical rows, {len} rows"
            );
        }
    }
}

#[test]
fn empty_set_encodes_to_empty_bytes() {
    let set = TribleSet::new();
    let borrowed: Blob<SimpleArchive> = (&set).to_blob();
    let owned: Blob<SimpleArchive> = set.to_blob();
    assert!(borrowed.bytes.is_empty());
    assert!(owned.bytes.is_empty());
    assert_eq!(borrowed, owned);
}
