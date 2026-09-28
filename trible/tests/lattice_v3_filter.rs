//! `trible pile migrate SRC lattice-v3` over synthetic piles.
//!
//! The fixture registers one root and one derived collection of every kind
//! the pre-v3 lattice derived: Succinct, Rank9, EntityIdSet, latest states,
//! the LWW register, BM25 and PathSummary become attached, and the
//! stored-vector NVFP4 set stays derived. The NVFP4 set is registered
//! through the CLI. The kinds that become attached are built by hand as the
//! derived descriptors earlier binaries wrote (a source and a mapping
//! algorithm), because this binary registers them only as attached
//! collections. Beside them sit hand-built descriptors the CLI cannot
//! register any more or never could: ReferenceSummary (deleted, known only
//! by its literal ids), a retired semantic-index id, an unrecognised
//! algorithm, a plural descriptor, one naming a mapping entity without a
//! tagged algorithm, and a blob that does not decode as a descriptor.
//! Records: commits, an own and a foreign MERGE, one DERIVE per derived
//! collection, a DERIVE into the root and one into a collection with no
//! resident descriptor, a capability proof and a WANT; and, written byte for
//! byte, retired v8/v9 equations, retired signed v2/v6/v7 frames, legacy
//! unsigned equations and legacy V3 headers. A second root collection holds
//! no record at all.

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
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
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
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
    WantRead, WantRequest, WantStore,
};
use triblespace_core::trible::Fragment;

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";
/// Pile record kinds of the retired binary MERGE (v8) and handle DERIVE (v9).
const KIND_MERGE_V8: &str = "424E7CF62C69A76E6829DF9F71CDFCB42B2B4795143AC6CC5CFF57F410E287CA";
const KIND_DERIVE_V9: &str = "5839C091F53DFDDCC32BB1909471989E3C40F934A64E4A2F7729E610ACF0494F";
/// Pile record kinds replay crosses as opaque frames, copied from
/// triblespace-core's record kinds: the retired signed MERGE v2 and v6 and
/// DERIVE v2 and v7.
const KIND_MERGE_SIGNED_V2: &str =
    "9D9B962D46FA42168AB3A11FB367AC14692D4F51B5190196F2BDB08D5BC2BA07";
const KIND_MERGE_WITNESSED_V6: &str =
    "4D2087B6C4944A404E1D0BCF4898819267E00FCAE49B146F5955522CBE935909";
const KIND_DERIVE_SIGNED_V2: &str =
    "B2EE8382C70161379E387D692B822946A60B602A909EED66B7D6DA2A62F36232";
const KIND_DERIVE_WITNESSED_V7: &str =
    "DBF641F31E772F6CE715087D954375AA44860BF411C0DE849C207B542ABDC583";
/// Pile record kinds of the retired unsigned MERGE and DERIVE.
const KIND_MERGE_UNSIGNED: &str =
    "0CEE320DE0BDA40A6A6F52221C5E4E4D2CE3B165B69C858673FD13D98F655379";
const KIND_DERIVE_UNSIGNED: &str =
    "7ACE1ED10F3EBC632627058CC461DC1CC171CD2E56C52E5DCE60EA4C8DC23C36";
/// Markers of the legacy V3 collection headers, copied from triblespace-core.
const MAGIC_DEFINITION_V3: &str = "3BE108504E4F5242FB24AA72D6D94CE1";
const MAGIC_COMMIT_V3: &str = "BB758AA6F79FBFC4D1958592A8956777";
const MAGIC_MERGE_V3: &str = "CC0108AC1DF4F335AFA856A529C42BE9";
const MAGIC_DERIVE_V3: &str = "07ECF056F6F015D94389FFF21F851480";
/// The deleted ReferenceSummary mapping, versions 2 and 1, as the filter
/// must still recognise them.
const REFERENCE_SUMMARY_MAPPING_V2: &str = "C0F7F9B5A68660407FDBFD8CF4D6E1AD";
const REFERENCE_SUMMARY_MAPPING_V1: &str = "A8C939AA55A7EC07C12FFCDA1FAA5785";
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

/// One framed record of `kind` whose body is `body`, zero padded.
fn frame(kind: &str, body: &[Raw]) -> Vec<u8> {
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
    frame(kind, &body)
}

/// One legacy V3 collection header: its 16-byte marker, then `ids` 16-byte
/// ids, then 32-byte `fields`, zero padded to 256 bytes.
fn v3_header(magic: &str, ids: &[[u8; 16]], fields: &[Raw]) -> Vec<u8> {
    let mut header = hex::decode(magic).unwrap();
    for id in ids {
        header.extend_from_slice(id);
    }
    for field in fields {
        header.extend_from_slice(field);
    }
    header.resize(256, 0);
    header
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
    reference_summary_v1: CollectionHandle,
    unrecognised: CollectionHandle,
    missing: CollectionHandle,
    /// A root collection that holds no record.
    empty: CollectionHandle,
    /// Blobs only a WANT, a legacy V3 COMMIT, a legacy V3 DERIVE and a
    /// legacy V3 MERGE name.
    wanted: Raw,
    v3_payload: Raw,
    v3_output: Raw,
    v3_result: Raw,
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
        let empty = pile.collection("empty", policy(&key)).unwrap().handle();
        pile.close().unwrap();

        // The derived descriptors the pre-v3 lattice registered for the
        // mappings that become attached; this binary attaches them instead.
        let (succinct, attached) = {
            use triblespace_core::collection::succinctarchive_union::{
                RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE, SIMPLE_TO_SUCCINCT_MAPPING_V1,
            };
            let mut pile = Pile::open(&src).unwrap();
            let succinct = hand_descriptor(&mut pile, root, &[SIMPLE_TO_SUCCINCT_MAPPING_V1]);
            let rank9 = hand_descriptor(
                &mut pile,
                succinct,
                &[RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE],
            );
            let mut attached = vec![succinct, rank9];
            for algorithm in [
                triblespace_core::blob::encodings::entity_id_set::GENID_ATTRIBUTE_VALUES_MAPPING_V1,
                triblespace_core::collection::latest::LATEST_STATES_MAPPING_V1,
                triblespace_core::collection::lww_register::REGISTER_COORDINATES_MAPPING_V1,
                triblespace_search::text_bm25::TEXT_ATTRIBUTE_TO_BM25,
                triblespace_paths::REGULAR_PATH_MAPPING_V1,
            ] {
                attached.push(hand_descriptor(&mut pile, root, &[algorithm]));
            }
            pile.close().unwrap();
            (succinct, attached)
        };
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
        let reference_summary_v1 =
            hand_descriptor(&mut pile, root, &[id(REFERENCE_SUMMARY_MAPPING_V1)]);
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
        // An attached mapping beside a mapping entity not tagged as one: the
        // second names no algorithm this reader can resolve, so the DERIVEs
        // stay.
        let untagged = {
            let mut facts = Fragment::empty();
            facts += entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_source: root,
                collection_mapping*: entity! {
                    metadata::tag: KIND_COLLECTION_MAPPING,
                    mapping_algorithm:
                        triblespace_core::collection::succinctarchive_union::SIMPLE_TO_SUCCINCT_MAPPING_V1,
                },
            };
            facts += entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_source: root,
                collection_mapping*: entity! { mapping_algorithm: id(UNRECOGNISED) },
            };
            pile.put::<SimpleArchive, _>(facts.facts().clone()).unwrap()
        };
        // A resident blob that does not decode as a descriptor.
        let undecodable: CollectionHandle =
            Inline::new(put_raw(&mut pile, b"not a descriptor").raw);
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
        dropped.push(leaf(
            &mut pile,
            reference_summary_v1,
            "reference summary v1",
        ));
        let kept = vec![
            leaf(&mut pile, nvfp4, "nvfp4"),
            leaf(&mut pile, semantic, "semantic"),
            leaf(&mut pile, unrecognised, "unrecognised"),
            leaf(&mut pile, plural, "plural"),
            leaf(&mut pile, missing, "missing"),
            leaf(&mut pile, root, "root"),
            leaf(&mut pile, untagged, "untagged"),
            leaf(&mut pile, undecodable, "undecodable"),
        ];
        for record in commits.iter().chain(&merges).chain(&dropped).chain(&kept) {
            pile.insert(*record).unwrap();
        }
        // A capability proof and a WANT naming a blob nothing else names.
        let definition = pile
            .put::<SimpleArchive, _>(triblespace_core::trible::TribleSet::new())
            .unwrap();
        pile.insert_proof(CapabilityProof::new(
            CapabilityResource::new([0x61; 32]),
            &SigningKey::from_bytes(&[0x62; 32]),
            definition,
            SigningKey::from_bytes(&[0x63; 32]).verifying_key(),
        ))
        .unwrap();
        let wanted = put_raw(&mut pile, b"named only by a WANT");
        pile.want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
            wanted.raw,
        )))
        .unwrap();
        let v3_payload = put_raw(&mut pile, b"named only by a legacy V3 COMMIT");
        let v3_output = put_raw(&mut pile, b"named only by a legacy V3 DERIVE");
        let v3_result = put_raw(&mut pile, b"named only by a legacy V3 MERGE");
        pile.close().unwrap();

        // Retired v8/v9 frames: of a v8 MERGE and two v9 DERIVEs, only the
        // DERIVE into the NVFP4 set is kept.
        append(&src, &merge_v8(&key, root, p1.raw, p2.raw, joined.raw));
        append(&src, &derive_v9(&key, succinct, p2.raw, [0x32; 32]));
        append(&src, &derive_v9(&key, nvfp4, p2.raw, [0x31; 32]));
        // Retired signed frames replay crosses as opaque: both MERGEs and the
        // DERIVE into Succinct are left behind, the DERIVE into the NVFP4 set
        // is kept.
        append(
            &src,
            &frame(
                KIND_MERGE_SIGNED_V2,
                &[root.raw, [0x41; 32], [0x42; 32], [0x43; 32]],
            ),
        );
        append(
            &src,
            &frame(
                KIND_MERGE_WITNESSED_V6,
                &[root.raw, [0x44; 32], [0x45; 32], [0x46; 32]],
            ),
        );
        append(
            &src,
            &frame(
                KIND_DERIVE_SIGNED_V2,
                &[succinct.raw, [0x47; 32], [0x48; 32]],
            ),
        );
        append(
            &src,
            &frame(
                KIND_DERIVE_WITNESSED_V7,
                &[nvfp4.raw, [0x49; 32], [0x4A; 32]],
            ),
        );
        // Legacy unsigned equations: the same fates.
        append(
            &src,
            &frame(
                KIND_MERGE_UNSIGNED,
                &[root.raw, [0x51; 32], [0x52; 32], [0x53; 32]],
            ),
        );
        append(
            &src,
            &frame(
                KIND_DERIVE_UNSIGNED,
                &[succinct.raw, [0x54; 32], [0x55; 32]],
            ),
        );
        append(
            &src,
            &frame(KIND_DERIVE_UNSIGNED, &[nvfp4.raw, [0x56; 32], [0x57; 32]]),
        );
        // Legacy V3 headers: the definition, COMMIT and DERIVE are kept with
        // the blobs they name, the MERGE is left behind with its result.
        append(
            &src,
            &v3_header(MAGIC_DEFINITION_V3, &[[1; 16], [2; 16], [3; 16]], &[]),
        );
        append(
            &src,
            &v3_header(
                MAGIC_COMMIT_V3,
                &[[4; 16]],
                &[
                    v3_payload.raw,
                    empty_metadata_handle().raw,
                    [7; 32],
                    [8; 32],
                    [9; 32],
                ],
            ),
        );
        append(
            &src,
            &v3_header(
                MAGIC_MERGE_V3,
                &[[10; 16]],
                &[[0x11; 32], [0x12; 32], v3_result.raw],
            ),
        );
        append(
            &src,
            &v3_header(
                MAGIC_DERIVE_V3,
                &[[14; 16], [15; 16]],
                &[[0x16; 32], v3_output.raw],
            ),
        );

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
            reference_summary_v1,
            unrecognised,
            missing,
            empty,
            wanted: wanted.raw,
            v3_payload: v3_payload.raw,
            v3_output: v3_output.raw,
            v3_result: v3_result.raw,
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
    // Carried legacy V3 headers keep what they name; the MERGE left behind
    // does not. A preserved WANT keeps its handle.
    assert!(resident(fixture.v3_payload));
    assert!(resident(fixture.v3_output));
    assert!(!resident(fixture.v3_result));
    assert!(resident(fixture.wanted));
    // A collection no record names keeps no descriptor without a root.
    assert!(!resident(fixture.empty.raw));
    let wants: Vec<_> = snapshot.wants().unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        wants,
        vec![WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
            fixture.wanted
        ))]
    );
    let mut source = Pile::open(&fixture.src).unwrap();
    let source_snapshot = source.snapshot().unwrap();
    let proofs: Vec<_> = snapshot
        .proofs()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let source_proofs: Vec<_> = source_snapshot
        .proofs()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(source_proofs.len(), 1);
    assert_eq!(proofs, source_proofs);
    for proof in &proofs {
        for handle in proof.blob_references() {
            assert!(resident(handle.raw), "a proof keeps its definition");
        }
    }
    drop((snapshot, source_snapshot));
    pile.close().unwrap();
    source.close().unwrap();
    let kinds: BTreeSet<_> = PileRecords::open(&destination)
        .unwrap()
        .filter_map(|record| match record.unwrap().content {
            PileRecordContent::LegacyCollectionV3 { kind } => Some(format!("{kind:?}")),
            _ => None,
        })
        .collect();
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    assert!(
        !kinds.iter().any(|kind| kind.contains("Merge")),
        "{kinds:?}"
    );

    // The report: kinds, mappings, collections and readability.
    for line in [
        "  COMMIT (current): 2 / 0",
        "  MERGE (current): 0 / 2",
        "  DERIVE (current): 8 / 9",
        "  MERGE (retired v8/v9): 0 / 1",
        "  DERIVE (retired v8/v9): 1 / 1",
        "  MERGE (retired v2/v6/v7): 0 / 2",
        "  DERIVE (retired v2/v6/v7): 1 / 1",
        "  MERGE (legacy unsigned): 0 / 1",
        "  DERIVE (legacy unsigned): 1 / 1",
        "  COMMIT (legacy V3): 1 / 0",
        "  MERGE (legacy V3): 0 / 1",
        "  DERIVE (legacy V3): 1 / 0",
        "  DEFINITION (legacy V3): 1 / 0",
        "rewrite: 19 left behind by the filter, 0 superseded, 0 drained, 0 repeated frames counted once; carried 1 frames of unknown kind and 1 retired v8/v9 equations",
        "roots: 0 named, 0 resident and kept with what they reach, 0 not resident in the source",
        "  9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached]: 0 / 4 in 1",
        "  C0F7F9B5A68660407FDBFD8CF4D6E1AD REFERENCE_SUMMARY_MAPPING_V2 [deleted]: 0 / 1 in 1",
        "  A8C939AA55A7EC07C12FFCDA1FAA5785 REFERENCE_SUMMARY_MAPPING_V1 [deleted]: 0 / 1 in 1",
        "  7B8668FD3857AD86B5AB24F5DD1BC1F9 EMBEDDING_ATTRIBUTE_TO_NVFP4 [derived]: 4 / 0 in 1",
        "  2B69128192930EE0782CCA03B97677F5 NOMIC_ATTRIBUTES_TO_NVFP4 (before f0c6157b) [derived]: 1 / 0 in 1",
        "  3E378C5714EE7DFCA8022855191FE864 [unrecognised]: 1 / 0 in 1",
        // Ascending by id: the plural descriptor's algorithms in order.
        "  3E378C5714EE7DFCA8022855191FE864 [unrecognised] + 9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached]: 1 / 0 in 1",
        "  9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached] + 1 mapping(s) without a tagged algorithm [unrecognised]: 1 / 0 in 1",
        "  (undecodable descriptor): 1 / 0 in 1",
        "  root \"facts\": 1 / 0 in 1",
        "  (legacy V3 definition ids): 1 / 0 in 1",
        "  (no resident descriptor): 1 / 0 in 1",
        "descriptors left behind: 9 (resident; only collections a frame names are examined, keep others with --root)",
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
    let left = format!(
        "  blake3:{} 9C8CFEB097B0A336E09D506E8DD361C2 SIMPLE_TO_SUCCINCT_MAPPING_V1 [attached]: its DERIVEs are left behind",
        hex::encode_upper(fixture.succinct.raw)
    );
    assert!(text.lines().any(|line| line == left), "{text}");
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
    // The real run adds two lines about the destination.
    assert_eq!(real_body.len(), dry_body.len() + 2);
    assert_eq!(&real_body[..dry_body.len()], &dry_body[..]);
    assert!(real_body[dry_body.len()].starts_with("destination: "));
    assert!(real_body[dry_body.len() + 1]
        .starts_with("destination digest (blob insertion timestamps left out): blake3:"));
}

#[test]
fn running_the_filter_twice_gives_the_same_pile() {
    let fixture = Fixture::new(false);
    let digest = |output: &Output| -> String {
        stdout(output)
            .lines()
            .find_map(|line| {
                line.strip_prefix("destination digest (blob insertion timestamps left out): ")
            })
            .unwrap()
            .to_owned()
    };
    let (first, output) = fixture.filter_into("first.pile", &[]);
    assert_success(&output);
    let first_digest = digest(&output);
    let (second, output) = fixture.filter_into("second.pile", &[]);
    assert_success(&output);
    assert_identical_but_blob_timestamps(&first, &second);
    // Two runs agree on the digest the report prints; the bytes differ only
    // in blob insertion timestamps, so a digest of the file would not.
    assert_eq!(digest(&output), first_digest);

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
    assert_eq!(digest(&output), first_digest);

    // Different content, a different digest: a root keeps one more blob.
    let root = format!("blake3:{}", hex::encode(fixture.empty.raw));
    let (_, output) = fixture.filter_into("rooted.pile", &["--root", &root]);
    assert_success(&output);
    assert_ne!(digest(&output), first_digest);
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
    assert!(records(&destination)
        .iter()
        .all(|record| record.collection() != fixture.reference_summary_v1));
    for (collection, id, name) in [
        (
            fixture.reference_summary,
            REFERENCE_SUMMARY_MAPPING_V2,
            "REFERENCE_SUMMARY_MAPPING_V2",
        ),
        (
            fixture.reference_summary_v1,
            REFERENCE_SUMMARY_MAPPING_V1,
            "REFERENCE_SUMMARY_MAPPING_V1",
        ),
    ] {
        let line = format!(
            "  blake3:{} {id} {name} [deleted]: DERIVE 0 / 1",
            hex::encode_upper(collection.raw)
        );
        assert!(stdout(&output).lines().any(|candidate| candidate == line));
    }
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
    // The plural descriptor now names only attached algorithms. The one
    // with an untagged mapping still names one this reader cannot resolve.
    assert_eq!(
        carried
            .iter()
            .filter(|record| matches!(record, CollectionRecord::Derive(_)))
            .count(),
        6
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

#[test]
fn a_collection_only_a_root_names_keeps_its_descriptor() {
    let fixture = Fixture::new(false);
    let (destination, output) = fixture.filter_into("unrooted.pile", &[]);
    assert_success(&output);
    let resident = |path: &Path, raw: Raw| {
        let mut pile = Pile::open(path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let resident = snapshot
            .contains_blob(Inline::<Handle<UnknownBlob>>::new(raw))
            .unwrap();
        drop(snapshot);
        pile.close().unwrap();
        resident
    };
    assert!(!resident(&destination, fixture.empty.raw));

    // A collection environment file, a plain handle list line and a handle
    // the source does not hold.
    let absent = [0x5A; 32];
    let roots = fixture.path("roots.env");
    std::fs::write(
        &roots,
        format!(
            "# collections something outside the pile opens\n\n\
             export TRIBLESPACE_COLLECTION_EMPTY={}\n\
             blake3:{}\n",
            hex::encode(fixture.empty.raw),
            hex::encode(absent),
        ),
    )
    .unwrap();
    let (destination, output) =
        fixture.filter_into("rooted.pile", &["--roots-from", roots.to_str().unwrap()]);
    assert_success(&output);
    assert!(resident(&destination, fixture.empty.raw));
    let text = stdout(&output);
    for line in [
        "roots: 2 named, 1 resident and kept with what they reach, 1 not resident in the source"
            .to_owned(),
        format!("  not resident blake3:{}", hex::encode_upper(absent)),
    ] {
        assert!(text.lines().any(|candidate| candidate == line), "{text}");
    }
    // The same root on the command line, and a dry run that agrees.
    let root = format!("blake3:{}", hex::encode(fixture.empty.raw));
    let dry = fixture.run(&fixture.src, &["--dry-run", "--root", &root]);
    assert_success(&dry);
    let (destination, real) = fixture.filter_into("rooted-again.pile", &["--root", &root]);
    assert_success(&real);
    assert!(resident(&destination, fixture.empty.raw));
    let dry = stdout(&dry);
    let real = stdout(&real);
    let dry_body: Vec<_> = dry.lines().skip(1).collect();
    let real_body: Vec<_> = real.lines().skip(1).collect();
    assert_eq!(&real_body[..dry_body.len()], &dry_body[..]);

    let refused = fixture.run(&fixture.src, &["--dry-run", "--root", "not-a-handle"]);
    assert!(!refused.status.success());
}

#[test]
fn a_pile_concatenated_with_itself_filters_to_the_same_pile() {
    let fixture = Fixture::new(false);
    let (single, output) = fixture.filter_into("single.pile", &[]);
    assert_success(&output);
    let single_text = stdout(&output);

    let doubled = fixture.path("doubled-source.pile");
    let bytes = std::fs::read(&fixture.src).unwrap();
    std::fs::write(&doubled, [bytes.as_slice(), bytes.as_slice()].concat()).unwrap();
    let double = fixture.path("double.pile");
    let output = fixture.run(&doubled, &["--into", double.to_str().unwrap()]);
    assert_success(&output);
    let double_text = stdout(&output);

    assert_identical_but_blob_timestamps(&single, &double);
    // The report counts records, not frames: every line but the rewrite
    // line, the header and the destination line is the same.
    let body = |text: &str| -> Vec<String> {
        text.lines()
            .skip(1)
            .filter(|line| !line.starts_with("rewrite: ") && !line.starts_with("destination: "))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(body(&double_text), body(&single_text));
    let repeated = |text: &str| -> usize {
        let line = text
            .lines()
            .find(|line| line.starts_with("rewrite: "))
            .unwrap();
        let (_, tail) = line.split_once(" drained, ").unwrap();
        tail.split_once(' ').unwrap().0.parse().unwrap()
    };
    assert_eq!(repeated(&single_text), 0);
    // Every current record and every retired signed frame, once more.
    assert_eq!(
        repeated(&double_text),
        fixture.commits.len()
            + fixture.merges.len()
            + fixture.dropped.len()
            + fixture.kept.len()
            + 4
    );
}
