use triblespace::core::blob::encodings::succinctarchive::{
    CompressedUniverse, OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive,
    SuccinctArchiveBlob,
};
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::{Blob, Bytes, MemoryBlobStore};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::repo::{reachable, BlobStoreGet, SnapshotSource};
use triblespace::core::trible::{Trible, TribleSet};

type RawTrible = [u8; 64];

fn raw_trible(entity: [u8; 16], attribute: [u8; 16], value: [u8; 32]) -> RawTrible {
    let mut out = [0; 64];
    out[..16].copy_from_slice(&entity);
    out[16..32].copy_from_slice(&attribute);
    out[32..].copy_from_slice(&value);
    out
}

fn set(seed: u8) -> TribleSet {
    [
        raw_trible([seed; 16], [0x11; 16], [0x81; 32]),
        raw_trible([seed; 16], [0x12; 16], [0x82; 32]),
    ]
    .into_iter()
    .map(|data| Trible::force_raw(data).expect("non-nil entity and attribute"))
    .collect()
}

fn pair(
    seed: u8,
) -> (
    Blob<SuccinctArchiveBlob>,
    Blob<Rank9AcceleratedSuccinctArchiveBlob>,
) {
    let archive: SuccinctArchive<OrderedUniverse> = (&set(seed)).into();
    archive.to_accelerated_parts()
}

#[test]
fn accelerated_root_starts_with_its_source_handle_and_pair_roundtrips() {
    let expected = set(1);
    let (raw, rank9) = pair(1);
    assert_eq!(&rank9.bytes.as_ref()[..32], &raw.get_handle().raw);

    let archive = SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw, rank9).unwrap();
    assert_eq!(archive.iter().collect::<TribleSet>(), expected);
}

#[test]
fn rank9_root_discovers_and_retains_its_raw_archive() {
    let (raw, rank9) = pair(5);
    let mut store = MemoryBlobStore::new();
    let raw_handle = store.insert(raw);
    let rank9_handle = store.insert(rank9);
    let orphan_handle = store.insert(Blob::<UnknownBlob>::new(Bytes::from_source(vec![0xA5; 64])));

    let root: Inline<Handle<UnknownBlob>> = rank9_handle.transmute();
    let raw_unknown: Inline<Handle<UnknownBlob>> = raw_handle.transmute();
    let snapshot = store.snapshot().unwrap();
    let reachable_from_rank9: Vec<_> = reachable(&snapshot, [root]).collect();
    assert_eq!(reachable_from_rank9[0], root);
    assert!(reachable_from_rank9.contains(&raw_unknown));
    assert_eq!(reachable_from_rank9.len(), 2);

    store.keep(reachable(&snapshot, [root]));
    let retained = store.snapshot().unwrap();
    assert_eq!(retained.len(), 2);
    assert!(retained
        .get::<Blob<Rank9AcceleratedSuccinctArchiveBlob>, Rank9AcceleratedSuccinctArchiveBlob>(
            rank9_handle,
        )
        .is_ok());
    assert!(retained
        .get::<Blob<SuccinctArchiveBlob>, SuccinctArchiveBlob>(raw_handle)
        .is_ok());
    assert!(retained
        .get::<Blob<UnknownBlob>, UnknownBlob>(orphan_handle)
        .is_err());
}

#[test]
fn runtime_universe_choice_preserves_pair_identity_and_cross_attachment() {
    let expected = set(4);
    let (ordered_raw, ordered_rank9) =
        SuccinctArchive::<OrderedUniverse>::build_accelerated_parts(&expected);
    let (compressed_raw, compressed_rank9) =
        SuccinctArchive::<CompressedUniverse>::build_accelerated_parts(&expected);

    assert_eq!(compressed_raw.bytes, ordered_raw.bytes);
    assert_eq!(compressed_raw.get_handle(), ordered_raw.get_handle());
    assert_eq!(compressed_rank9.bytes, ordered_rank9.bytes);
    assert_eq!(compressed_rank9.get_handle(), ordered_rank9.get_handle());

    let compressed = SuccinctArchive::<CompressedUniverse>::from_accelerated_parts(
        ordered_raw.clone(),
        ordered_rank9.clone(),
    )
    .unwrap();
    let ordered = SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(
        compressed_raw,
        compressed_rank9,
    )
    .unwrap();
    assert_eq!(compressed.iter().collect::<TribleSet>(), expected);
    assert_eq!(ordered.iter().collect::<TribleSet>(), expected);
}

#[test]
fn pair_attachment_rejects_mismatched_and_corrupt_indexes() {
    let (raw_a, rank9_a) = pair(1);
    let (raw_b, rank9_b) = pair(2);

    assert!(
        SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw_a.clone(), rank9_b).is_err()
    );

    let mut corrupt = rank9_a.bytes.as_ref().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let corrupt = Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(Bytes::from_source(corrupt));
    assert!(SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw_a, corrupt).is_err());

    // Keep both variables meaningfully distinct: B's raw content is not A.
    assert_ne!(raw_b.get_handle().raw, pair(1).0.get_handle().raw);
}

#[test]
fn raw_identity_is_deterministic_and_independent_of_rank9_bytes() {
    let (raw_a, rank9_a) = pair(7);
    let (raw_b, rank9_b) = pair(7);
    assert_eq!(raw_a.get_handle(), raw_b.get_handle());
    assert_eq!(raw_a.bytes, raw_b.bytes);
    assert_eq!(rank9_a.get_handle(), rank9_b.get_handle());

    let mut alternative_index = rank9_a.bytes.as_ref().to_vec();
    alternative_index[32] ^= 1;
    let alternative_index =
        Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(Bytes::from_source(alternative_index));
    assert_ne!(alternative_index.get_handle(), rank9_b.get_handle());
    assert_eq!(raw_a.get_handle(), raw_b.get_handle());
}

#[test]
fn embedded_accelerator_is_not_a_portable_raw_succinct_archive() {
    let archive: SuccinctArchive<OrderedUniverse> = (&set(9)).into();
    let (raw, rank9) = archive.to_accelerated_parts();
    let mut embedded = Vec::with_capacity(raw.bytes.len() + rank9.bytes.len());
    embedded.extend_from_slice(raw.bytes.as_ref());
    embedded.extend_from_slice(rank9.bytes.as_ref());

    let embedded = Blob::<SuccinctArchiveBlob>::new(Bytes::from_source(embedded));
    let decoded: Result<SuccinctArchive<OrderedUniverse>, _> = embedded.try_from_blob();
    assert!(decoded.is_err());
}

#[test]
fn raw_only_decode_rebuilds_the_same_detached_index_explicitly() {
    let (raw, rank9) = pair(3);
    let rebuilt_rank9 =
        SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw.clone()).unwrap();
    let rebuilt: SuccinctArchive<OrderedUniverse> = raw.clone().try_from_blob().unwrap();
    let (rebuilt_raw, _) = rebuilt.to_accelerated_parts();
    assert_eq!(rebuilt_raw.get_handle(), raw.get_handle());
    assert_eq!(rebuilt_rank9.get_handle(), rank9.get_handle());
}
