//! `trible pile migrate SRC clean --into DST` over synthetic piles.
//!
//! One fixture holds every case the clean-pile migration decides: a payload
//! committed by two admitted signers, its owner's second metadata, an
//! unadmitted and an invalidly signed commit, a retired generation with a
//! payload to adopt, an unmapped retired root, current and retired MERGEs,
//! first-hop and chained v9 DERIVEs (Succinct over the root, Rank9 over
//! Succinct), a conflicting DERIVE, DERIVEs of merged nodes, WRITE grants,
//! and a WANT. Retired v8/v9 frames are written byte for byte, because no
//! current writer can produce them any more.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anybytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::records::{
    CollectionData, CollectionHandle, DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED,
    KIND_COLLECTION_DERIVE_HANDLE_RETIRED, KIND_COLLECTION_MERGE_BINARY_RETIRED,
    MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
};
use triblespace_core::collection::{
    grant_collection_write, AdmissionPolicy, CollectionCommit, CollectionMerge, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt,
    RetiredCollectionEquation, SourceLocator,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::repo::pile::{Pile, PileFile, PileRecordContent, PileRecords};
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, SnapshotSource, WantRequest, WantStore,
};

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";
/// Pile record kinds of the retired binary MERGE (v8) and handle DERIVE (v9).
const KIND_MERGE_V8: &str = "424E7CF62C69A76E6829DF9F71CDFCB42B2B4795143AC6CC5CFF57F410E287CA";
const KIND_DERIVE_V9: &str = "5839C091F53DFDDCC32BB1909471989E3C40F934A64E4A2F7729E610ACF0494F";

type Raw = [u8; 32];

fn trible() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trible"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "PILE" || name == "PERSONA" || name.starts_with("TRIBLESPACE_") {
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

fn sha256(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).unwrap()).to_vec()
}

fn data(bytes: &[u8]) -> CollectionData {
    Inline::new(*blake3::hash(bytes).as_bytes())
}

/// Put an opaque blob and name it the way a collection record would.
fn put_raw(pile: &mut Pile, bytes: &[u8]) -> CollectionData {
    let handle = pile
        .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(bytes.to_vec())))
        .unwrap();
    Inline::new(handle.raw)
}

/// One retired frame, exactly as the retired writers framed it: magic, span,
/// kind, the dense fields, the author, R, S, zero padding to whole blocks.
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
    a: CollectionData,
    b: CollectionData,
    result: CollectionData,
) -> Vec<u8> {
    let (low, high) = if a.raw <= b.raw { (a, b) } else { (b, a) };
    retired_frame(
        KIND_MERGE_V8,
        KIND_COLLECTION_MERGE_BINARY_RETIRED,
        MERGE_BINARY_TRANSCRIPT_DOMAIN_RETIRED,
        key,
        &[collection.raw, low.raw, high.raw, result.raw],
    )
}

fn derive_v9(
    key: &SigningKey,
    target: CollectionHandle,
    input: CollectionData,
    output: CollectionData,
) -> Vec<u8> {
    retired_frame(
        KIND_DERIVE_V9,
        KIND_COLLECTION_DERIVE_HANDLE_RETIRED,
        DERIVE_HANDLE_TRANSCRIPT_DOMAIN_RETIRED,
        key,
        &[target.raw, input.raw, output.raw],
    )
}

/// A current-envelope frame whose kind no binary knows.
fn unknown_frame() -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    frame[32..64].copy_from_slice(&[0x5A; 32]);
    frame
}

fn append(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

fn handle_line(handle: Raw) -> String {
    format!("blake3:{}\n", hex::encode(handle))
}

fn policy(key: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    )
}

struct Fixture {
    dir: TempDir,
    src: PathBuf,
    roots_file: PathBuf,
    key_a: PathBuf,
    key_b: PathBuf,
    key_c: PathBuf,
    a: SigningKey,
    b: SigningKey,
    root: CollectionHandle,
    succinct: CollectionHandle,
    rank9: CollectionHandle,
    retired: CollectionHandle,
    retired_view: CollectionHandle,
    other: CollectionHandle,
    /// P1 (owner A, two metadata), P2 (owner B), P3 (only C, unadmitted),
    /// P5 (A's frame corrupted first, then B), Q1 (retired only, adopted).
    p1: CollectionData,
    p1_metadata: [Raw; 2],
    p2: CollectionData,
    p3: CollectionData,
    p5: CollectionData,
    q1: CollectionData,
    q1_metadata: Raw,
    /// Leaf images: S* in Succinct, K* in Rank9.
    s1: CollectionData,
    s2: CollectionData,
    s5: CollectionData,
    k1: CollectionData,
    k2: CollectionData,
    /// The UTF-8 child blob P1's archive names in its value column.
    p1_child: Raw,
    proofs: Vec<CapabilityProof>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.pile");
        std::fs::File::create(&src).unwrap();
        let key_a = dir.path().join("a.key");
        let key_b = dir.path().join("b.key");
        let key_c = dir.path().join("c.key");
        let a = triblespace_core::signing_key_file::init(&key_a).unwrap();
        let b = triblespace_core::signing_key_file::init(&key_b).unwrap();
        let c = triblespace_core::signing_key_file::init(&key_c).unwrap();

        let mut pile = Pile::open(&src).unwrap();
        let current = policy(&a);
        let root = pile.collection("facts", current.clone()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(root, (), current.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), current.clone())
            .unwrap();
        // The previous generation of the same name: a different policy, so a
        // different descriptor.
        let old = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(a.verifying_key()),
        );
        let retired = pile.collection("facts", old.clone()).unwrap();
        let retired_view = pile
            .derive::<SuccinctArchiveBlob>(retired, (), old.clone())
            .unwrap();
        let other = pile.collection("other", current.clone()).unwrap();
        let mut proofs = Vec::new();
        for collection in [root.handle(), succinct.handle(), rank9.handle()] {
            proofs.push(
                grant_collection_write(&mut pile, collection, &a, b.verifying_key()).unwrap(),
            );
        }

        // P1: A twice (distinct metadata), then B: B is a duplicate owner.
        let first = pile
            .commit(root, &a, entity! { metadata::description: "first fact" })
            .unwrap();
        let p1 = first.data();
        let second_metadata = pile
            .put::<SimpleArchive, _>(
                entity! { metadata::tag: metadata::KIND_BLOB_ENCODING }
                    .facts()
                    .clone(),
            )
            .unwrap();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &a,
            root.handle(),
            p1,
            second_metadata,
        )))
        .unwrap();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &b,
            root.handle(),
            p1,
            first.metadata(),
        )))
        .unwrap();
        // P2: B first, then A.
        let second = pile
            .commit(root, &b, entity! { metadata::description: "second fact" })
            .unwrap();
        let p2 = second.data();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &a,
            root.handle(),
            p2,
            second.metadata(),
        )))
        .unwrap();
        // P3: only C, whom the root does not admit.
        let p3 = pile
            .commit(root, &c, entity! { metadata::description: "third fact" })
            .unwrap()
            .data();
        // P5: A's frame is corrupted below, so B's later commit owns it.
        let broken = pile
            .commit(root, &a, entity! { metadata::description: "fifth fact" })
            .unwrap();
        let p5 = broken.data();
        pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
            &b,
            root.handle(),
            p5,
            broken.metadata(),
        )))
        .unwrap();

        // The retired generation: Q1 is new, P1 is already current, Q3's
        // author was never admitted there.
        let adopted = pile
            .commit(
                retired,
                &a,
                entity! { metadata::description: "retired fact" },
            )
            .unwrap();
        let q1 = adopted.data();
        pile.commit(retired, &a, entity! { metadata::description: "first fact" })
            .unwrap();
        pile.commit(retired, &c, entity! { metadata::description: "stray fact" })
            .unwrap();
        pile.commit(other, &a, entity! { metadata::description: "unrelated" })
            .unwrap();

        // A current n-ary MERGE, dropped like every other MERGE.
        let r125 = put_raw(&mut pile, b"union of p1 p2 p5");
        pile.insert(CollectionRecord::Merge(
            CollectionMerge::sign(&a, root.handle(), [p1, p2, p5], r125).unwrap(),
        ))
        .unwrap();
        pile.want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
            r125.raw,
        )))
        .unwrap();

        let image = |pile: &mut Pile, label: &str| put_raw(pile, label.as_bytes());
        let r12 = image(&mut pile, "merged p1 p2");
        let s1 = image(&mut pile, "succinct p1");
        let s1x = image(&mut pile, "succinct p1 (disputed)");
        let s2 = image(&mut pile, "succinct p2");
        let s12 = image(&mut pile, "succinct p1 p2");
        let s3 = image(&mut pile, "succinct p3");
        let s5 = image(&mut pile, "succinct p5");
        let k1 = image(&mut pile, "rank9 p1");
        let k2 = image(&mut pile, "rank9 p2");
        let k12 = image(&mut pile, "rank9 p1 p2");
        let k1x = image(&mut pile, "rank9 disputed");
        let xq = image(&mut pile, "retired view q1");
        let rq = image(&mut pile, "retired merge");
        pile.close().unwrap();

        let (root, succinct, rank9) = (root.handle(), succinct.handle(), rank9.handle());
        let (retired, retired_view, other) =
            (retired.handle(), retired_view.handle(), other.handle());
        for frame in [
            merge_v8(&a, root, p1, p2, r12),
            // B's disputed image of P1 comes first; the owner's still wins.
            derive_v9(&b, succinct, p1, s1x),
            derive_v9(&a, succinct, p1, s1),
            derive_v9(&a, succinct, p2, s2),
            derive_v9(&a, succinct, r12, s12),
            merge_v8(&a, succinct, s1, s2, s12),
            derive_v9(&b, succinct, p5, s5),
            derive_v9(&c, succinct, p3, s3),
            derive_v9(&a, rank9, s1, k1),
            derive_v9(&a, rank9, s2, k2),
            derive_v9(&a, rank9, s12, k12),
            derive_v9(&a, rank9, s1x, k1x),
            derive_v9(&a, retired_view, q1, xq),
            merge_v8(&a, retired, q1, p1, rq),
        ] {
            append(&src, &frame);
        }

        // Corrupt the signature of A's P5 commit in place.
        let offset = PileRecords::open(&src)
            .unwrap()
            .map(Result::unwrap)
            .find(|record| {
                matches!(record.content, PileRecordContent::Collection {
                    record: CollectionRecord::Commit(commit),
                } if commit == broken)
            })
            .unwrap()
            .offset;
        let position = offset as u64 + 64 + 5 * 32 + 7;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&src)
            .unwrap();
        let mut byte = [0u8];
        file.seek(SeekFrom::Start(position)).unwrap();
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(position)).unwrap();
        file.write_all(&[byte[0] ^ 0x5A]).unwrap();
        drop(file);

        // Every retired frame decodes and verifies; the corrupted commit
        // decodes and does not.
        let mut retired_frames = 0;
        let mut invalid_commits = 0;
        for record in PileRecords::open(&src).unwrap() {
            match record.unwrap().content {
                PileRecordContent::RetiredCollectionEquation { equation } => {
                    equation.verify_strict().unwrap();
                    retired_frames += 1;
                }
                PileRecordContent::Collection { record } => {
                    invalid_commits += usize::from(record.verify_strict().is_err());
                }
                _ => {}
            }
        }
        assert_eq!(retired_frames, 14);
        assert_eq!(invalid_commits, 1);

        let roots_file = dir.path().join("roots.txt");
        std::fs::write(&roots_file, format!("# current\n{}", handle_line(root.raw))).unwrap();

        let q1_metadata = adopted.metadata().raw;
        Fixture {
            p1_child: *blake3::hash(b"first fact").as_bytes(),
            dir,
            src,
            roots_file,
            key_a,
            key_b,
            key_c,
            a,
            b,
            root,
            succinct,
            rank9,
            retired,
            retired_view,
            other,
            p1,
            p1_metadata: [first.metadata().raw, second_metadata.raw],
            p2,
            p3,
            p5,
            q1,
            q1_metadata,
            s1,
            s2,
            s5,
            k1,
            k2,
            proofs,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn clean(&self, source: &Path, into: &Path, extra: &[&str], keys: &[&Path]) -> Output {
        let report = into.with_extension("json");
        let mut command = trible();
        command
            .args(["pile", "migrate"])
            .arg(source)
            .args(["clean", "--into"])
            .arg(into)
            .arg("--roots")
            .arg(&self.roots_file)
            .arg("--report")
            .arg(&report)
            .args(extra);
        for key in keys {
            command.arg("--key").arg(key);
        }
        command.output().unwrap()
    }

    fn report(&self, into: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(into.with_extension("json")).unwrap())
            .unwrap()
    }
}

fn records(path: &Path) -> Vec<CollectionRecord> {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let records = snapshot
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(snapshot);
    pile.close().unwrap();
    records
}

fn commits_of(records: &[CollectionRecord], data: CollectionData) -> BTreeSet<(Raw, Raw)> {
    records
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Commit(commit) if commit.data() == data => {
                Some((commit.public_key().raw, commit.metadata().raw))
            }
            _ => None,
        })
        .collect()
}

/// `(target, locator, output, signer)` of every DERIVE.
fn derives(records: &[CollectionRecord]) -> BTreeSet<(Raw, Raw, Raw, Raw)> {
    records
        .iter()
        .filter_map(|record| match record {
            CollectionRecord::Derive(derive) => Some((
                derive.target().raw,
                derive.input().raw(),
                derive.output().raw,
                derive.public_key().raw,
            )),
            _ => None,
        })
        .collect()
}

fn leaf(
    target: CollectionHandle,
    foundation: CollectionData,
    output: CollectionData,
    signer: &SigningKey,
) -> (Raw, Raw, Raw, Raw) {
    (
        target.raw,
        SourceLocator::of(foundation.raw).raw(),
        output.raw,
        signer.verifying_key().to_bytes(),
    )
}

fn hex_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn find<'a>(list: &'a Value, handle: CollectionHandle) -> &'a Value {
    let handle = hex::encode(handle.raw);
    list.as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["handle"] == handle.as_str())
        .unwrap_or_else(|| panic!("{handle} not in {list}"))
}

fn owners(value: &Value) -> BTreeMap<String, u64> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, count)| (key.clone(), count.as_u64().unwrap()))
        .collect()
}

#[test]
fn clean_keeps_one_owner_adopts_and_reemits_leaves() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let before = sha256(&fixture.src);
    // The source is only ever read: a read-only file works.
    #[cfg(unix)]
    std::fs::set_permissions(&fixture.src, std::fs::Permissions::from_mode(0o400)).unwrap();
    let dst = fixture.path("clean.pile");
    let output = fixture.clean(
        &fixture.src,
        &dst,
        &["--adopt-by-name"],
        &[&fixture.key_a, &fixture.key_b],
    );
    assert_success(&output);
    assert_eq!(sha256(&fixture.src), before, "the source is unchanged");
    assert!(
        !fixture.path("clean.pile.partial").exists(),
        "the partial file is installed, not left behind"
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let written = records(&dst);
    let (a, b) = (
        fixture.a.verifying_key().to_bytes(),
        fixture.b.verifying_key().to_bytes(),
    );
    // One owner per payload; the owner's distinct metadata both survive.
    assert_eq!(
        commits_of(&written, fixture.p1),
        BTreeSet::from([(a, fixture.p1_metadata[0]), (a, fixture.p1_metadata[1])])
    );
    assert_eq!(commits_of(&written, fixture.p2).len(), 1);
    assert_eq!(commits_of(&written, fixture.p2).first().unwrap().0, b);
    assert!(commits_of(&written, fixture.p3).is_empty(), "unadmitted");
    assert_eq!(commits_of(&written, fixture.p5).len(), 1);
    assert_eq!(commits_of(&written, fixture.p5).first().unwrap().0, b);
    // Adopted: re-signed into the current root by the first key.
    assert_eq!(
        commits_of(&written, fixture.q1),
        BTreeSet::from([(a, fixture.q1_metadata)])
    );
    for record in &written {
        assert_eq!(
            record.collection() == fixture.root,
            matches!(record, CollectionRecord::Commit(_))
        );
        assert!(
            !matches!(record, CollectionRecord::Merge(_)),
            "no MERGE survives"
        );
        for dropped in [fixture.retired, fixture.retired_view, fixture.other] {
            assert_ne!(record.collection(), dropped);
        }
    }
    // Leaves: first hop by each payload's owner, and Rank9 over the kept
    // Succinct leaves, by the underlying commit's owner.
    assert_eq!(
        derives(&written),
        BTreeSet::from([
            leaf(fixture.succinct, fixture.p1, fixture.s1, &fixture.a),
            leaf(fixture.succinct, fixture.p2, fixture.s2, &fixture.b),
            leaf(fixture.succinct, fixture.p5, fixture.s5, &fixture.b),
            leaf(fixture.rank9, fixture.s1, fixture.k1, &fixture.a),
            leaf(fixture.rank9, fixture.s2, fixture.k2, &fixture.b),
        ])
    );

    // Every reference resolves; proofs and the archive child survive; the
    // coverage fold believes every leaf.
    let mut pile = Pile::open(&dst).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let resident = |raw: Raw| {
        snapshot
            .contains_blob(Inline::<Handle<UnknownBlob>>::new(raw))
            .unwrap()
    };
    for record in &written {
        for reference in record.blob_references() {
            assert!(resident(reference.raw), "{record:?} names an absent blob");
        }
    }
    let kept_proofs: Vec<CapabilityProof> = snapshot
        .proofs()
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kept_proofs.len(), fixture.proofs.len());
    for proof in &fixture.proofs {
        assert!(kept_proofs.iter().any(|kept| kept.id() == proof.id()));
        for definition in proof.blob_references() {
            assert!(resident(definition.raw));
        }
    }
    assert!(resident(fixture.p1_child), "archive children are retained");
    for blob in triblespace_core::repo::pile::description_blobs() {
        assert!(resident(blob.get_handle().raw));
    }
    // Every lineage decided for exactly this prefix.
    let coverage = snapshot.coverage();
    for (target, foundation) in [
        (fixture.succinct, fixture.p1),
        (fixture.succinct, fixture.p2),
        (fixture.succinct, fixture.p5),
        (fixture.rank9, fixture.s1),
        (fixture.rank9, fixture.s2),
    ] {
        assert!(
            coverage.has_leaf(target, SourceLocator::of(foundation.raw)),
            "the fold believes the leaf of {foundation:?} in {target:?}"
        );
    }
    assert!(!coverage.has_leaf(fixture.succinct, SourceLocator::of(fixture.p3.raw)));
    for (payload, owner) in [
        (fixture.p1, a),
        (fixture.p2, b),
        (fixture.p5, b),
        (fixture.q1, a),
    ] {
        let believed: Vec<Raw> = coverage
            .owners(fixture.root, payload)
            .iter()
            .map(|signer| signer.raw)
            .collect();
        assert_eq!(believed, vec![owner], "the fold's owner of {payload:?}");
    }
    drop(snapshot);
    pile.close().unwrap();

    // The report says what happened, collection by collection.
    let report = fixture.report(&dst);
    let root = find(&report["roots"], fixture.root);
    assert_eq!(root["kept_commits"], 4);
    assert_eq!(root["kept_payloads"], 3);
    assert_eq!(root["adopted_payloads"], 1);
    assert_eq!(root["dropped"]["duplicate_owner"], 2);
    assert_eq!(root["dropped"]["invalid_signature"], 1);
    assert_eq!(root["dropped"]["unadmitted"], 1);
    let retired = find(&report["retired"], fixture.retired);
    assert_eq!(
        retired["adopted_into"],
        hex::encode(fixture.root.raw).as_str()
    );
    assert_eq!(retired["adopted_payloads"], 1);
    assert_eq!(retired["already_present"], 1);
    assert_eq!(retired["unadmitted"], 1);
    let other = find(&report["retired"], fixture.other);
    assert!(other["adopted_into"].is_null());
    assert_eq!(other["records"], 1);
    let dropped_view = find(&report["dropped_collections"], fixture.retired_view);
    assert_eq!(dropped_view["records"], 1);

    let succinct = find(&report["derived"], fixture.succinct);
    assert_eq!(succinct["depth"], 1);
    assert_eq!(succinct["source_foundations"], 4);
    assert_eq!(succinct["foundations_with_leaf"], 3);
    assert_eq!(
        owners(&succinct["needs_rederive_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.a), 1)]),
        "the adopted payload still needs its leaf"
    );
    let frames = &succinct["derive_frames"];
    assert_eq!(frames["reemitted"], 3);
    assert_eq!(frames["conflicting_output"], 1);
    assert_eq!(frames["merged_input"], 1);
    assert_eq!(frames["unmatched_input"], 1);
    let rank9 = find(&report["derived"], fixture.rank9);
    assert_eq!(rank9["depth"], 2);
    assert_eq!(rank9["source_foundations"], 3);
    assert_eq!(rank9["foundations_with_leaf"], 2);
    assert_eq!(
        owners(&rank9["needs_rederive_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.b), 1)])
    );
    assert_eq!(rank9["derive_frames"]["reemitted"], 2);
    assert_eq!(rank9["derive_frames"]["merged_input"], 1);
    assert_eq!(rank9["derive_frames"]["unmatched_input"], 1);

    assert_eq!(report["records_written"]["commit"], 4);
    assert_eq!(report["records_written"]["adopted_commit"], 1);
    assert_eq!(report["records_written"]["derive"], 5);
    assert_eq!(report["records_written"]["capability_proof"], 3);
    assert_eq!(report["dropped_frames"]["merge_v10"], 1);
    assert_eq!(report["dropped_frames"]["merge_v8"], 3);
    assert_eq!(report["dropped_frames"]["derive_v9"], 11);
    assert_eq!(report["dropped_frames"]["want"], 1);
    assert_eq!(report["destination_audit"]["unresolved_references"], 0);
    assert_eq!(
        report["destination_bytes"], report["destination_bytes_projected"],
        "the dry-run projection is the written size"
    );
    assert_eq!(
        report["source_bytes"].as_u64().unwrap(),
        std::fs::metadata(&fixture.src).unwrap().len()
    );
    assert!(report["elapsed_seconds"].as_f64().is_some());

    // Cleaning a clean pile changes nothing.
    let again = fixture.path("again.pile");
    assert_success(&fixture.clean(&dst, &again, &[], &[&fixture.key_a, &fixture.key_b]));
    let first: BTreeSet<_> = written.iter().map(|record| record.fingerprint()).collect();
    let second: BTreeSet<_> = records(&again)
        .iter()
        .map(|record| record.fingerprint())
        .collect();
    assert_eq!(first, second, "clean is idempotent");
    let report = fixture.report(&again);
    assert_eq!(
        find(&report["derived"], fixture.succinct)["derive_frames"]["kept_current"],
        3
    );
    assert_eq!(
        find(&report["derived"], fixture.rank9)["derive_frames"]["kept_current"],
        2
    );
}

#[test]
fn without_the_owner_key_leaves_are_counted_for_the_owner() {
    let fixture = Fixture::new();
    let adopt = fixture.path("adopt.txt");
    std::fs::write(
        &adopt,
        format!(
            "{} {}  # the old generation\n",
            hex::encode(fixture.retired.raw),
            hex::encode(fixture.root.raw)
        ),
    )
    .unwrap();
    let dst = fixture.path("clean.pile");
    let output = fixture.clean(
        &fixture.src,
        &dst,
        &["--adopt", adopt.to_str().unwrap()],
        &[&fixture.key_a],
    );
    assert_success(&output);

    let written = records(&dst);
    assert_eq!(
        derives(&written),
        BTreeSet::from([
            leaf(fixture.succinct, fixture.p1, fixture.s1, &fixture.a),
            leaf(fixture.rank9, fixture.s1, fixture.k1, &fixture.a),
        ]),
        "only the leaves whose owner's key the run holds"
    );
    // B still owns its payloads; only its leaves wait.
    assert_eq!(
        commits_of(&written, fixture.p2).first().unwrap().0,
        fixture.b.verifying_key().to_bytes()
    );
    assert_eq!(
        commits_of(&written, fixture.q1).len(),
        1,
        "adopted via --adopt"
    );

    let report = fixture.report(&dst);
    let succinct = find(&report["derived"], fixture.succinct);
    assert_eq!(
        owners(&succinct["derive_frames"]["no_key_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.b), 2)])
    );
    assert_eq!(
        owners(&succinct["needs_rederive_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.a), 1), (hex_key(&fixture.b), 2)])
    );
    let rank9 = find(&report["derived"], fixture.rank9);
    assert!(
        owners(&rank9["derive_frames"]["no_key_by_owner"]).is_empty(),
        "a Rank9 leaf over an unwritten Succinct leaf waits for that leaf"
    );
    assert_eq!(
        owners(&rank9["derive_frames"]["source_leaf_not_written_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.b), 1)])
    );
    assert_eq!(
        owners(&rank9["needs_rederive_by_owner"]),
        BTreeMap::from([(hex_key(&fixture.b), 2)])
    );
    assert_eq!(report["records_written"]["derive"], 2);
}

#[test]
fn dry_run_writes_nothing_and_counts_what_a_run_writes() {
    let fixture = Fixture::new();
    let before = sha256(&fixture.src);
    let keys = [fixture.key_a.as_path(), fixture.key_b.as_path()];
    let dry = fixture.path("dry.pile");
    assert_success(&fixture.clean(&fixture.src, &dry, &["--adopt-by-name", "--dry-run"], &keys));
    assert!(!dry.exists(), "a dry run creates no destination");
    let real = fixture.path("real.pile");
    assert_success(&fixture.clean(&fixture.src, &real, &["--adopt-by-name"], &keys));
    assert_eq!(sha256(&fixture.src), before);

    let (dry, real) = (fixture.report(&dry), fixture.report(&real));
    assert_eq!(dry["dry_run"], true);
    for key in [
        "roots",
        "retired",
        "derived",
        "dropped_collections",
        "source_census",
        "records_written",
        "dropped_frames",
        "capability_proofs",
        "blobs",
        "destination_bytes_projected",
        "source_bytes",
    ] {
        assert_eq!(
            dry[key], real[key],
            "{key} differs between dry and real runs"
        );
    }
    assert!(dry["destination_bytes"].is_null());
    assert_eq!(
        real["destination_bytes"],
        real["destination_bytes_projected"]
    );
}

#[test]
fn refusals_leave_no_destination() {
    let fixture = Fixture::new();

    // The first key adopts, so it must be admitted to the current root.
    let dst = fixture.path("inadmissible.pile");
    let output = fixture.clean(&fixture.src, &dst, &["--adopt-by-name"], &[&fixture.key_c]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not admitted to WRITE"));
    assert!(!dst.exists());

    // A derived collection is not a root.
    let roots = fixture.path("derived-roots.txt");
    std::fs::write(&roots, handle_line(fixture.succinct.raw)).unwrap();
    let output = trible()
        .args(["pile", "migrate"])
        .arg(&fixture.src)
        .args(["clean", "--into"])
        .arg(&dst)
        .arg("--roots")
        .arg(&roots)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("derived collection"));
    assert!(!dst.exists());

    // Unknown kinds are refused unless explicitly dropped.
    append(&fixture.src, &unknown_frame());
    let output = fixture.clean(&fixture.src, &dst, &[], &[&fixture.key_a]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--drop-unknown"));
    assert!(!dst.exists());
    assert_success(&fixture.clean(&fixture.src, &dst, &["--drop-unknown"], &[&fixture.key_a]));
    assert_eq!(fixture.report(&dst)["dropped_frames"]["unknown_kind"], 1);

    // An existing destination is never overwritten.
    let output = fixture.clean(&fixture.src, &dst, &["--drop-unknown"], &[&fixture.key_a]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn retired_frames_decode_with_every_field() {
    // A guard on the fixture itself: the frames above are what the retired
    // writers wrote, so the migration reads real v8/v9 evidence.
    let key = SigningKey::from_bytes(&[9; 32]);
    let target = Inline::new([1; 32]);
    let frame = derive_v9(&key, target, data(b"in"), data(b"out"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frames.pile");
    std::fs::write(&path, &frame).unwrap();
    let record = PileRecords::open(&path).unwrap().next().unwrap().unwrap();
    let PileRecordContent::RetiredCollectionEquation {
        equation:
            RetiredCollectionEquation::DeriveV9 {
                target: t,
                input,
                output,
                ..
            },
    } = record.content
    else {
        panic!("not a retired DERIVE: {:?}", record.content);
    };
    assert_eq!((t, input, output), (target, data(b"in"), data(b"out")));
}

#[test]
fn a_read_only_source_handle_replays_and_cannot_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    put_raw(&mut pile, b"resident");
    pile.close().unwrap();
    let before = sha256(&path);

    let mut source = PileFile::open_read_only(&path).unwrap();
    let snapshot = source.snapshot().unwrap();
    assert_eq!(
        snapshot.prefix_len() as u64,
        std::fs::metadata(&path).unwrap().len()
    );
    assert!(snapshot
        .contains_blob(Inline::<Handle<UnknownBlob>>::new(data(b"resident").raw))
        .unwrap());
    drop(snapshot);
    assert!(
        source
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(
                b"new".to_vec()
            )))
            .is_err(),
        "a read-only handle cannot append"
    );
    source.close().unwrap();
    assert_eq!(sha256(&path), before);
}
