//! `trible pile migrate SRC lattice-v3` over synthetic piles.
//!
//! The fixture registers one root and, through the CLI, one derived
//! collection of every kind the CLI can register, so the filter classifies
//! real descriptors: Succinct, Rank9, EntityIdSet, latest states, the LWW
//! register, BM25 and PathSummary become attached, and the stored-vector
//! NVFP4 set stays derived. Beside them sit hand-built descriptors the CLI
//! cannot register any more or never could: ReferenceSummary (deleted, known
//! only by its literal ids), a retired semantic-index id, an unrecognised
//! algorithm, and a plural descriptor. Records: commits, an own and a foreign
//! MERGE, one DERIVE per derived collection, a DERIVE into a collection with
//! no resident descriptor, and retired v8/v9 frames written byte for byte.

#![cfg(feature = "search")]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anybytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::collection::records::{
    collection_mapping, collection_source, mapping_algorithm, CollectionData, CollectionHandle,
    DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED, KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
    KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING, KIND_COLLECTION_MERGE_BINARY_RETIRED,
    MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
};
use triblespace_core::collection::{
    empty_metadata_handle, AdmissionPolicy, CollectionCommit, CollectionDerive, CollectionMerge,
    CollectionPolicy, CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt,
    RetiredCollectionEquation, SourceLocator,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{BlobStoreList, BlobStorePut, CapabilityProofRead, SnapshotSource};
use triblespace_core::trible::Fragment;

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";
/// Pile record kinds of the retired binary MERGE (v8) and handle DERIVE (v9).
const KIND_MERGE_V8: &str = "424E7CF62C69A76E6829DF9F71CDFCB42B2B4795143AC6CC5CFF57F410E287CA";
const KIND_DERIVE_V9: &str = "5839C091F53DFDDCC32BB1909471989E3C40F934A64E4A2F7729E610ACF0494F";
/// The deleted ReferenceSummary mapping, version 2, as the filter must still
/// recognise it.
const REFERENCE_SUMMARY_MAPPING_V2: &str = "C0F7F9B5A68660407FDBFD8CF4D6E1AD";
/// The semantic index's mapping id before f0c6157b: deployed indexes name it.
const SEMANTIC_BEFORE_F0C6157B: &str = "2B69128192930EE0782CCA03B97677F5";
/// An algorithm no table knows, minted for this test with `trible genid`.
const UNRECOGNISED: &str = "3E378C5714EE7DFCA8022855191FE864";

type Raw = [u8; 32];

fn trible() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trible"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "PILE" || name.starts_with("TRIBLESPACE_") {
            command.env_remove(key);
        }
    }
    command
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn id(text: &str) -> Id {
    Id::from_hex(text).unwrap()
}

fn put_raw(pile: &mut Pile, bytes: &[u8]) -> CollectionData {
    let handle = pile
        .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(bytes.to_vec())))
        .unwrap();
    Inline::new(handle.raw)
}

/// One retired frame, exactly as the retired writers framed it.
fn retired_frame(
    kind: &str,
    semantic_kind: Id,
    domain: &[u8],
    key: &SigningKey,
    fields: &[Raw],
) -> Vec<u8> {
    let author = key.verifying_key().to_bytes();
    let mut transcript = domain.to_vec();
    transcript.extend_from_slice(&semantic_kind.raw());
    transcript.extend_from_slice(&author);
    for field in fields {
        transcript.extend_from_slice(field);
    }
    let signature = key.sign(&transcript);
    let body: Vec<Raw> = fields
        .iter()
        .copied()
        .chain([author, *signature.r_bytes(), *signature.s_bytes()])
        .collect();
    let blocks = (64 + 32 * body.len()).div_ceil(256);
    let mut frame = vec![0u8; 256 * blocks];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&(blocks as u32).to_le_bytes());
    frame[32..64].copy_from_slice(&hex::decode(kind).unwrap());
    for (index, field) in body.iter().enumerate() {
        frame[64 + 32 * index..96 + 32 * index].copy_from_slice(field);
    }
    frame
}

fn merge_v8(
    key: &SigningKey,
    collection: CollectionHandle,
    a: Raw,
    b: Raw,
    result: Raw,
) -> Vec<u8> {
    let (low, high) = if a <= b { (a, b) } else { (b, a) };
    retired_frame(
        KIND_MERGE_V8,
        KIND_COLLECTION_MERGE_BINARY_RETIRED,
        MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
        key,
        &[collection.raw, low, high, result],
    )
}

fn derive_v9(key: &SigningKey, target: CollectionHandle, input: Raw, output: Raw) -> Vec<u8> {
    retired_frame(
        KIND_DERIVE_V9,
        KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
        DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED,
        key,
        &[target.raw, input, output],
    )
}

fn append(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

fn policy(key: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    )
}

/// A derived descriptor naming `algorithms`, built by hand: one descriptor
/// entity per algorithm, so a plural descriptor is their union.
fn hand_descriptor(
    pile: &mut Pile,
    source: CollectionHandle,
    algorithms: &[Id],
) -> CollectionHandle {
    let mut facts = Fragment::empty();
    for algorithm in algorithms {
        facts += entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: source,
            collection_mapping*: entity! {
                metadata::tag: KIND_COLLECTION_MAPPING,
                mapping_algorithm: *algorithm,
            },
        };
    }
    pile.put::<SimpleArchive, _>(facts.facts().clone()).unwrap()
}

/// Register one derived collection through the CLI and return its handle.
fn derive(
    pile: &Path,
    key: &Path,
    source: CollectionHandle,
    kind: &str,
    args: &[&str],
) -> CollectionHandle {
    let output = trible()
        .args(["pile", "collection", "derive"])
        .arg(pile)
        .arg(format!("blake3:{}", hex::encode(source.raw)))
        .arg(kind)
        .args(args)
        .arg("--key")
        .arg(key)
        .output()
        .unwrap();
    assert_success(&output);
    let text = stdout(&output);
    let hex = text.trim().strip_prefix("blake3:").unwrap();
    Inline::new(hex::decode(hex).unwrap().try_into().unwrap())
}

const ATTRIBUTE: &str = "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A1";
const ORDERS: &str = "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A2";

struct Fixture {
    dir: TempDir,
    src: PathBuf,
    root: CollectionHandle,
    /// DERIVE records the filter must leave behind, and the ones it keeps.
    dropped: Vec<CollectionRecord>,
    kept: Vec<CollectionRecord>,
    commits: Vec<CollectionRecord>,
    merges: Vec<CollectionRecord>,
    /// The result both MERGEs and the retired v8 MERGE name, and nothing else.
    joined: CollectionData,
    /// Collections the CLI registered, by kind.
    succinct: CollectionHandle,
    nvfp4: CollectionHandle,
    reference_summary: CollectionHandle,
    unrecognised: CollectionHandle,
    missing: CollectionHandle,
}

impl Fixture {
    /// `absent_payload` adds a commit whose payload is not resident.
    fn new(absent_payload: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.pile");
        std::fs::File::create(&src).unwrap();
        let key_path = dir.path().join("self.key");
        let key = triblespace_core::signing_key_file::init(&key_path).unwrap();
        let foreign = SigningKey::from_bytes(&[0x42; 32]);

        let mut pile = Pile::open(&src).unwrap();
        let root = pile.collection("facts", policy(&key)).unwrap().handle();
        pile.close().unwrap();

        let succinct = derive(&src, &key_path, root, "succinct", &[]);
        let rank9 = derive(&src, &key_path, succinct, "rank9", &[]);
        let attached = [
            succinct,
            rank9,
            derive(
                &src,
                &key_path,
                root,
                "entity-id-set",
                &["--attribute", ATTRIBUTE],
            ),
            derive(&src, &key_path, root, "latest", &["--observes", ATTRIBUTE]),
            derive(
                &src,
                &key_path,
                root,
                "lww",
                &["--identity", ATTRIBUTE, "--orders", ORDERS],
            ),
            derive(&src, &key_path, root, "bm25", &["--text", ATTRIBUTE]),
            derive(&src, &key_path, root, "path", &["--expr", ATTRIBUTE]),
        ];
        let nvfp4 = derive(
            &src,
            &key_path,
            root,
            "nvfp4",
            &["--attribute", ATTRIBUTE, "--dimension", "4"],
        );

        let mut pile = Pile::open(&src).unwrap();
        let reference_summary =
            hand_descriptor(&mut pile, root, &[id(REFERENCE_SUMMARY_MAPPING_V2)]);
        let semantic = hand_descriptor(&mut pile, root, &[id(SEMANTIC_BEFORE_F0C6157B)]);
        let unrecognised = hand_descriptor(&mut pile, root, &[id(UNRECOGNISED)]);
        // Attached and unrecognised together: not every algorithm is
        // attached, so the DERIVEs stay.
        let plural = hand_descriptor(
            &mut pile,
            root,
            &[
                triblespace_core::collection::succinctarchive_union::SIMPLE_TO_SUCCINCT_MAPPING_V1,
                id(UNRECOGNISED),
            ],
        );
        let missing: CollectionHandle = Inline::new([0x77; 32]);

        let p1 = put_raw(&mut pile, b"first payload");
        let p2 = put_raw(&mut pile, b"second payload");
        let mut commits = Vec::new();
        for data in [p1, p2] {
            commits.push(CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                root,
                data,
                empty_metadata_handle(),
            )));
        }
        if absent_payload {
            commits.push(CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                root,
                Inline::new(*blake3::hash(b"never stored here").as_bytes()),
                empty_metadata_handle(),
            )));
        }
        let joined = put_raw(&mut pile, b"joined");
        let merges = vec![
            CollectionRecord::Merge(CollectionMerge::sign(&key, root, [p1, p2], joined).unwrap()),
            CollectionRecord::Merge(
                CollectionMerge::sign(&foreign, root, [p1, p2], joined).unwrap(),
            ),
        ];
        let leaf = |pile: &mut Pile, target: CollectionHandle, tag: &str| {
            let output = put_raw(pile, format!("image in {tag}").as_bytes());
            CollectionRecord::Derive(CollectionDerive::sign(
                &key,
                target,
                SourceLocator::of(p1.raw),
                output,
            ))
        };
        let mut dropped = Vec::new();
        for (index, target) in attached.iter().enumerate() {
            dropped.push(leaf(&mut pile, *target, &format!("attached {index}")));
        }
        dropped.push(leaf(&mut pile, reference_summary, "reference summary"));
        let kept = vec![
            leaf(&mut pile, nvfp4, "nvfp4"),
            leaf(&mut pile, semantic, "semantic"),
            leaf(&mut pile, unrecognised, "unrecognised"),
            leaf(&mut pile, plural, "plural"),
            leaf(&mut pile, missing, "missing"),
        ];
        for record in commits.iter().chain(&merges).chain(&dropped).chain(&kept) {
            pile.insert(*record).unwrap();
        }
        pile.close().unwrap();

        // Retired frames: of a v8 MERGE and two v9 DERIVEs, only the DERIVE
        // into the NVFP4 set is kept.
        append(&src, &merge_v8(&key, root, p1.raw, p2.raw, joined.raw));
        append(&src, &derive_v9(&key, succinct, p2.raw, [0x32; 32]));
        append(&src, &derive_v9(&key, nvfp4, p2.raw, [0x31; 32]));

        Fixture {
            dir,
            src,
            root,
            dropped,
            kept,
            commits,
            merges,
            joined,
            succinct,
            nvfp4,
            reference_summary,
            unrecognised,
            missing,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, source: &Path, extra: &[&str]) -> Output {
        trible()
            .args(["pile", "migrate"])
            .arg(source)
            .arg("lattice-v3")
            .args(extra)
            .output()
            .unwrap()
    }

    fn filter_into(&self, name: &str, extra: &[&str]) -> (PathBuf, Output) {
        let destination = self.path(name);
        let mut args = vec!["--into", destination.to_str().unwrap()];
        args.extend_from_slice(extra);
        let output = self.run(&self.src, &args);
        (destination, output)
    }
}

fn records(path: &Path) -> BTreeSet<CollectionRecord> {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let records = snapshot
        .records()
        .unwrap()
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    drop(snapshot);
    pile.close().unwrap();
    records
}

/// Compare two piles frame by frame: every frame byte-identical, except the
/// eight bytes of each blob record's insertion timestamp, which every
/// rewrite stamps afresh by design.
fn assert_identical_but_blob_timestamps(left: &Path, right: &Path) {
    let left_bytes = std::fs::read(left).unwrap();
    let right_bytes = std::fs::read(right).unwrap();
    assert_eq!(left_bytes.len(), right_bytes.len(), "pile lengths differ");
    let spans = |path: &Path| -> Vec<(usize, usize, bool)> {
        PileRecords::open(path)
            .unwrap()
            .map(|record| {
                let record = record.unwrap();
                let blob = matches!(record.content, PileRecordContent::Blob { .. });
                (record.offset, record.len, blob)
            })
            .collect()
    };
    let left_spans = spans(left);
    assert_eq!(left_spans, spans(right), "frame layouts differ");
    let mut masked = 0;
    for (offset, len, blob) in left_spans {
        let (mut a, mut b) = (
            left_bytes[offset..offset + len].to_vec(),
            right_bytes[offset..offset + len].to_vec(),
        );
        if blob {
            a[64..72].fill(0);
            b[64..72].fill(0);
            masked += 1;
        }
        assert_eq!(a, b, "frame at {offset} differs");
    }
    assert!(masked > 0);
}

#[test]
fn the_filter_keeps_commits_and_derived_mappings_and_leaves_merges_and_attached_derives() {
    let fixture = Fixture::new(false);
    let (destination, output) = fixture.filter_into("filtered.pile", &[]);
    assert_success(&output);
    let text = stdout(&output);

    let carried = records(&destination);
    let expected: BTreeSet<_> = fixture
        .commits
        .iter()
        .chain(&fixture.kept)
        .copied()
        .collect();
    assert_eq!(carried, expected);
    for record in fixture.merges.iter().chain(&fixture.dropped) {
        assert!(!carried.contains(record));
    }

    let mut pile = Pile::open(&destination).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let retired: Vec<_> = snapshot.retired_collection_equations().collect();
    assert!(
        matches!(
            retired.as_slice(),
            [RetiredCollectionEquation::DeriveV9 { target, output, .. }]
                if *target == fixture.nvfp4 && output.raw == [0x31; 32]
        ),
        "{retired:?}"
    );
    // What kept records name stays; what only records left behind name (the
    // merge result, the images of dropped DERIVEs, the descriptors of the
    // collections that become attached) is left behind with them.
    let resident = |raw: Raw| {
        snapshot
            .contains_blob(Inline::<Handle<UnknownBlob>>::new(raw))
            .unwrap()
    };
    for record in &fixture.commits {
        let CollectionRecord::Commit(commit) = record else {
            unreachable!()
        };
        assert!(resident(commit.data().raw));
    }
    for record in &fixture.kept {
        let CollectionRecord::Derive(derive) = record else {
            unreachable!()
        };
        assert!(resident(derive.output().raw));
    }
    for record in &fixture.dropped {
        let CollectionRecord::Derive(derive) = record else {
            unreachable!()
        };
        assert!(!resident(derive.output().raw));
    }
    assert!(!resident(fixture.joined.raw));
    assert!(resident(fixture.root.raw));
    assert!(resident(fixture.nvfp4.raw));
    assert!(!resident(fixture.succinct.raw));
    assert!(!resident(fixture.reference_summary.raw));
    let mut source = Pile::open(&fixture.src).unwrap();
    let source_snapshot = source.snapshot().unwrap();
    assert_eq!(
        snapshot.proofs().unwrap().count(),
        source_snapshot.proofs().unwrap().count()
    );
    drop((snapshot, source_snapshot));
    pile.close().unwrap();
    source.close().unwrap();

    // The report: kinds, mappings, collections and readability.
    for line in [
        "  COMMIT (current): 2 / 0",
        "  MERGE (current): 0 / 2",
        "  DERIVE (current): 5 / 8",
        "  MERGE (retired v8/v9): 0 / 1",
        "  DERIVE (retired v8/v9): 1 / 1",
        "rewrite: 12 left behind by the filter, 0 superseded, 0 drained; carried 0 frames of unknown kind and 1 retired v8/v9 equations",
        "  9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached]: 0 / 2 in 1",
        "  C0F7F9B5A68660407FDBFD8CF4D6E1AD REFERENCE_SUMMARY_MAPPING_V2 [deleted]: 0 / 1 in 1",
        "  7B8668FD3857AD86B5AB24F5DD1BC1F9 EMBEDDING_ATTRIBUTE_TO_NVFP4 [derived]: 2 / 0 in 1",
        "  2B69128192930EE0782CCA03B97677F5 NOMIC_ATTRIBUTES_TO_NVFP4 (before f0c6157b) [derived]: 1 / 0 in 1",
        "  3E378C5714EE7DFCA8022855191FE864 [unrecognised]: 1 / 0 in 1",
        // Ascending by id: the plural descriptor's algorithms in order.
        "  3E378C5714EE7DFCA8022855191FE864 [unrecognised] + 9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached]: 1 / 0 in 1",
        "  (no resident descriptor): 1 / 0 in 1",
        "readability (keyless fold): 2 kept collections with believed foundations, 3 foundations, 0 not resident",
    ] {
        assert!(
            text.lines().any(|candidate| candidate == line),
            "missing line {line:?} in\n{text}"
        );
    }
    for attached in [
        "RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE [attached]: 0 / 1 in 1",
        "GENID_ATTRIBUTE_VALUES_MAPPING_V1 [attached]: 0 / 1 in 1",
        "LATEST_STATES_MAPPING_V1 [attached]: 0 / 1 in 1",
        "REGISTER_COORDINATES_MAPPING_V1 [attached]: 0 / 1 in 1",
        "TEXT_ATTRIBUTE_TO_BM25 [attached]: 0 / 1 in 1",
        "REGULAR_PATH_MAPPING_V1 [attached]: 0 / 1 in 1",
    ] {
        assert!(
            text.lines().any(|line| line.ends_with(attached)),
            "missing mapping {attached:?} in\n{text}"
        );
    }
    assert!(
        text.lines().any(|line| line.starts_with("blobs: ")),
        "{text}"
    );
}

#[test]
fn a_dry_run_writes_nothing_and_reports_what_the_real_run_does() {
    let fixture = Fixture::new(false);
    let before = std::fs::read(&fixture.src).unwrap();
    let dry = fixture.run(&fixture.src, &["--dry-run"]);
    assert_success(&dry);
    assert_eq!(std::fs::read(&fixture.src).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(fixture.dir.path()).unwrap().count(),
        2,
        "only the source and its key"
    );
    let (_, real) = fixture.filter_into("filtered.pile", &[]);
    assert_success(&real);
    let dry = stdout(&dry);
    let real = stdout(&real);
    let dry_body: Vec<_> = dry.lines().skip(1).collect();
    let real_body: Vec<_> = real.lines().skip(1).collect();
    assert!(dry.starts_with("lattice-v3 dry run of "));
    assert!(real.starts_with("lattice-v3 filter of "));
    // The real run adds one line about the destination.
    assert_eq!(real_body.len(), dry_body.len() + 1);
    assert_eq!(&real_body[..dry_body.len()], &dry_body[..]);
    assert!(real_body[dry_body.len()].starts_with("destination: "));
}

#[test]
fn running_the_filter_twice_gives_the_same_pile() {
    let fixture = Fixture::new(false);
    let (first, output) = fixture.filter_into("first.pile", &[]);
    assert_success(&output);
    let (second, output) = fixture.filter_into("second.pile", &[]);
    assert_success(&output);
    assert_identical_but_blob_timestamps(&first, &second);

    // The filtered pile is a fixpoint: filtering it again leaves nothing
    // behind and writes the same frames.
    let again = fixture.path("again.pile");
    let output = fixture.run(&first, &["--into", again.to_str().unwrap()]);
    assert_success(&output);
    let text = stdout(&output);
    assert!(
        text.lines()
            .any(|line| line.starts_with("rewrite: 0 left behind by the filter")),
        "{text}"
    );
    assert_identical_but_blob_timestamps(&first, &again);
}

#[test]
fn a_derive_into_a_collection_without_a_resident_descriptor_is_kept() {
    let fixture = Fixture::new(false);
    let (destination, output) = fixture.filter_into("filtered.pile", &[]);
    assert_success(&output);
    let into_missing: Vec<_> = records(&destination)
        .into_iter()
        .filter(|record| record.collection() == fixture.missing)
        .collect();
    assert_eq!(into_missing.len(), 1);
    assert!(matches!(into_missing[0], CollectionRecord::Derive(_)));
    let line = format!(
        "  blake3:{} (no resident descriptor): DERIVE 1 / 0",
        hex::encode_upper(fixture.missing.raw)
    );
    assert!(stdout(&output).lines().any(|candidate| candidate == line));
}

#[test]
fn reference_summary_derives_are_left_behind_by_their_literal_ids() {
    let fixture = Fixture::new(false);
    let (destination, output) = fixture.filter_into("filtered.pile", &[]);
    assert_success(&output);
    assert!(records(&destination)
        .iter()
        .all(|record| record.collection() != fixture.reference_summary));
    let line = format!(
        "  blake3:{} {REFERENCE_SUMMARY_MAPPING_V2} REFERENCE_SUMMARY_MAPPING_V2 [deleted]: DERIVE 0 / 1",
        hex::encode_upper(fixture.reference_summary.raw)
    );
    assert!(stdout(&output).lines().any(|candidate| candidate == line));
}

#[test]
fn an_unrecognised_mapping_is_kept_unless_named_attached() {
    let fixture = Fixture::new(false);
    let (destination, output) = fixture.filter_into("kept.pile", &[]);
    assert_success(&output);
    assert!(records(&destination)
        .iter()
        .any(|record| record.collection() == fixture.unrecognised));

    let (destination, output) =
        fixture.filter_into("named.pile", &["--attached-mapping", UNRECOGNISED]);
    assert_success(&output);
    let carried = records(&destination);
    assert!(carried
        .iter()
        .all(|record| record.collection() != fixture.unrecognised));
    // The plural descriptor now names only attached algorithms.
    assert_eq!(
        carried
            .iter()
            .filter(|record| matches!(record, CollectionRecord::Derive(_)))
            .count(),
        3
    );

    // A known id cannot be reclassified.
    let refused = fixture.run(
        &fixture.src,
        &[
            "--dry-run",
            "--attached-mapping",
            "7B8668FD3857AD86B5AB24F5DD1BC1F9",
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("EMBEDDING_ATTRIBUTE_TO_NVFP4"));
}

#[test]
fn a_source_another_process_holds_open_is_refused() {
    let fixture = Fixture::new(false);
    let held = std::fs::File::open(&fixture.src).unwrap();
    let (destination, output) = fixture.filter_into("filtered.pile", &[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("other process"), "{stderr}");
    assert!(stderr.contains(&std::process::id().to_string()), "{stderr}");
    assert!(!destination.exists());
    let dry = fixture.run(&fixture.src, &["--dry-run"]);
    assert!(!dry.status.success());
    drop(held);
    let (_, output) = fixture.filter_into("filtered.pile", &[]);
    assert_success(&output);
}

#[test]
fn absent_foundation_payloads_are_listed_and_refused_unless_allowed() {
    let fixture = Fixture::new(true);
    let absent = format!(
        "    absent blake3:{}",
        hex::encode_upper(blake3::hash(b"never stored here").as_bytes())
    );
    let dry = fixture.run(&fixture.src, &["--dry-run"]);
    assert!(!dry.status.success());
    let text = stdout(&dry);
    assert!(text.lines().any(|line| line == absent), "{text}");
    assert!(text.lines().any(|line| line
        == "readability (keyless fold): 2 kept collections with believed foundations, 4 foundations, 1 not resident"));

    let (destination, output) = fixture.filter_into("refused.pile", &[]);
    assert!(!output.status.success());
    assert!(stdout(&output).lines().any(|line| line == absent));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-absent"));
    assert!(!destination.exists(), "a refused result is removed");

    let (destination, output) = fixture.filter_into("accepted.pile", &["--allow-absent"]);
    assert_success(&output);
    assert!(destination.exists());
}
