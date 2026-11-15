//! Each test builds a pile through the ordinary writer, takes its frames
//! apart with the ordinary reader, damages the bytes between them, and
//! compares what the walk yields as frames: the byte layout of a file is not
//! the semantic resource, its records are.

use super::*;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::repo::pile::Pile;
use crate::repo::{BlobStorePut, WantRequest, WantStore};

/// The frames of a fresh pile holding one blob per payload, then one WANT,
/// in write order.
fn frames(payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile: Pile = Pile::open(&path).unwrap();
    let mut last = None;
    for payload in payloads {
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(payload.clone()));
        last = Some(pile.put::<UnknownBlob, _>(blob).unwrap());
    }
    if let Some(handle) = last {
        pile.want(WantRequest::blob(handle)).unwrap();
    }
    pile.close().unwrap();
    read_frames(&path)
}

/// Every frame the ordinary reader yields; panics on any read error.
fn read_frames(path: &Path) -> Vec<Vec<u8>> {
    let mut records = PileRecords::open(path).unwrap();
    let mut out = Vec::new();
    while let Some(record) = records.next() {
        let record = record.unwrap();
        out.push(records.bytes()[record.offset..record.offset + record.len].to_vec());
    }
    out
}

/// What a repair walk of `bytes` yields: the record frames and the skips.
fn walk(bytes: Vec<u8>) -> (Vec<Vec<u8>>, Vec<SkippedRange>) {
    let mut walk = ResyncingRecords::new(Bytes::from_source(bytes));
    let mut records = Vec::new();
    let mut skipped = Vec::new();
    while let Some(step) = walk.next() {
        match step {
            RepairStep::Record(record) => {
                records.push(walk.bytes()[record.offset..record.offset + record.len].to_vec())
            }
            RepairStep::Skipped(range) => skipped.push(range),
        }
    }
    (records, skipped)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Four blobs, the second and fourth long enough that a tear inside their
/// payload leaves the header (and so the declared span) intact, plus a WANT.
fn fixture() -> Vec<Vec<u8>> {
    frames(&[
        vec![1u8; 4],
        vec![2u8; 1000],
        vec![3u8; 600],
        vec![4u8; 1000],
    ])
}

#[test]
fn a_clean_pile_walks_to_the_same_frames_with_nothing_skipped() {
    let frames = fixture();
    assert_eq!(frames.len(), 5, "four blobs and a WANT");
    let (records, skipped) = walk(frames.concat());
    assert_eq!(records, frames);
    assert!(skipped.is_empty(), "{skipped:?}");
}

#[test]
fn a_torn_blob_in_the_middle_is_skipped_and_the_walk_resumes_at_the_next_frame() {
    let f = fixture();
    // The header of the 1000-byte blob survives, so the decoder alone accepts
    // its declared five-block span: the bytes written after the crash fill
    // it. Only the payload hash shows the record is torn.
    let torn = &f[1][..600];
    let (records, skipped) = walk(cat(&[&f[0], torn, &f[2], &f[3], &f[4]]));
    assert_eq!(
        records,
        vec![f[0].clone(), f[2].clone(), f[3].clone(), f[4].clone()]
    );
    assert_eq!(
        skipped,
        vec![SkippedRange {
            start: f[0].len(),
            end: f[0].len() + torn.len(),
            defect: RepairDefect::BlobHash,
        }]
    );
}

#[test]
fn two_separate_torn_regions_are_each_reported() {
    let f = fixture();
    let first = &f[1][..300];
    let second = &f[3][..700];
    let bytes = cat(&[&f[0], first, &f[2], second, &f[4]]);
    let (records, skipped) = walk(bytes);
    assert_eq!(records, vec![f[0].clone(), f[2].clone(), f[4].clone()]);
    let second_start = f[0].len() + first.len() + f[2].len();
    assert_eq!(
        skipped
            .iter()
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>(),
        vec![
            (f[0].len(), f[0].len() + first.len()),
            (second_start, second_start + second.len()),
        ]
    );
}

#[test]
fn a_torn_tail_repairs_to_what_amputation_keeps() {
    let f = fixture();
    let bytes = cat(&[&f[0], &f[1], &f[2], &f[3][..500]]);
    let (records, skipped) = walk(bytes.clone());
    assert_eq!(
        skipped,
        vec![SkippedRange {
            start: f[0].len() + f[1].len() + f[2].len(),
            end: bytes.len(),
            defect: RepairDefect::Corrupt,
        }]
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("torn.pile");
    std::fs::write(&path, &bytes).unwrap();
    let mut pile: Pile = Pile::open(&path).unwrap();
    pile.amputate().unwrap();
    pile.close().unwrap();
    assert_eq!(records, read_frames(&path));
    assert_eq!(records, vec![f[0].clone(), f[1].clone(), f[2].clone()]);
}

#[test]
fn garbage_between_frames_is_skipped_even_off_block_alignment() {
    let f = fixture();
    let garbage = [0xABu8; 100];
    let (records, skipped) = walk(cat(&[&f[0], &garbage, &f[1], &f[2]]));
    assert_eq!(records, vec![f[0].clone(), f[1].clone(), f[2].clone()]);
    assert_eq!(
        skipped,
        vec![SkippedRange {
            start: f[0].len(),
            end: f[0].len() + garbage.len(),
            defect: RepairDefect::Unsupported { marker: [0xAB; 16] },
        }]
    );
}

#[test]
fn a_truncated_magic_prefix_is_skipped_in_the_middle_and_at_the_tail() {
    let f = fixture();
    let prefix = &FRAME_MAGIC[..20];
    let (records, skipped) = walk(cat(&[&f[0], prefix, &f[1]]));
    assert_eq!(records, vec![f[0].clone(), f[1].clone()]);
    assert_eq!(
        skipped
            .iter()
            .map(|range| (range.start, range.len()))
            .collect::<Vec<_>>(),
        vec![(f[0].len(), prefix.len())]
    );

    let (records, skipped) = walk(cat(&[&f[0], prefix]));
    assert_eq!(records, vec![f[0].clone()]);
    assert_eq!(
        skipped,
        vec![SkippedRange {
            start: f[0].len(),
            end: f[0].len() + prefix.len(),
            defect: RepairDefect::Corrupt,
        }]
    );
}

#[test]
fn a_frame_inside_a_blob_payload_is_never_a_resynchronisation_point() {
    // The inner frame is a complete, valid blob record, hash and all: a pile
    // stored as a blob looks exactly like this.
    let inner = frames(&[vec![7u8; 300]]);
    let inner_blob = inner[0].clone();
    let mut payload = vec![0x55u8; 40];
    payload.extend_from_slice(&inner_blob);
    payload.extend_from_slice(&[0x66u8; 40]);
    let f = frames(&[vec![1u8; 4], payload, vec![3u8; 600]]);
    let (outer, after) = (&f[1], &f[2]);

    // Clean: the outer blob's extent is taken whole.
    let (records, skipped) = walk(f.concat());
    assert_eq!(records, f);
    assert!(skipped.is_empty());

    // After damage, the scan meets the outer frame first. Its framing wins,
    // so the inner frame is still only payload.
    let torn = &f[0][..100];
    let (records, skipped) = walk(cat(&[torn, outer, after, &f[3]]));
    assert_eq!(records, vec![outer.clone(), after.clone(), f[3].clone()]);
    assert_eq!(
        skipped
            .iter()
            .map(|range| (range.start, range.end))
            .collect::<Vec<_>>(),
        vec![(0, torn.len())]
    );
    assert!(!records.contains(&inner_blob));
}

#[test]
fn a_valid_frame_inside_a_damaged_blob_is_recovered_as_itself() {
    let inner = frames(&[vec![7u8; 300]]);
    let inner_blob = inner[0].clone();
    let mut payload = vec![0x55u8; 40];
    payload.extend_from_slice(&inner_blob);
    payload.extend_from_slice(&[0x66u8; 40]);
    let f = frames(&[payload, vec![3u8; 600]]);
    let mut outer = f[0].clone();
    // Flip one payload byte before the inner frame: the outer blob no longer
    // matches its hash, so its extent is not trusted, and the inner record,
    // which does validate whole, is the next record the scan finds. Content
    // addressing makes a validating blob true wherever it was found.
    outer[256 + 3] ^= 0xFF;
    let (records, skipped) = walk(cat(&[&outer, &f[1], &f[2]]));
    assert_eq!(
        records,
        vec![inner_blob.clone(), f[1].clone(), f[2].clone()]
    );
    let inner_start = 256 + 40;
    assert_eq!(
        skipped,
        vec![
            SkippedRange {
                start: 0,
                end: inner_start,
                defect: RepairDefect::BlobHash,
            },
            SkippedRange {
                start: inner_start + inner_blob.len(),
                end: outer.len(),
                defect: RepairDefect::Unsupported { marker: [0x66; 16] },
            },
        ]
    );
}

#[test]
fn an_empty_pile_yields_nothing() {
    let (records, skipped) = walk(Vec::new());
    assert!(records.is_empty());
    assert!(skipped.is_empty());
}

#[test]
fn all_garbage_is_one_skipped_range_and_no_record() {
    // Garbage that even contains the magic, followed by no valid frame.
    let mut bytes = vec![0x11u8; 1000];
    bytes[300..300 + FRAME_MAGIC_LEN].copy_from_slice(&FRAME_MAGIC);
    let (records, skipped) = walk(bytes.clone());
    assert!(records.is_empty());
    assert_eq!(
        skipped,
        vec![SkippedRange {
            start: 0,
            end: bytes.len(),
            defect: RepairDefect::Unsupported { marker: [0x11; 16] },
        }]
    );
}
