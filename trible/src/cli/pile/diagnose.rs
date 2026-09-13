use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};
use triblespace_core::repo::{WantRequest, WANT_REQUEST_BYTES_LEN};

// Raw-diagnostic knowledge of the short-lived retired typed-WANT format. This
// is intentionally not part of WantRequest's current public encoding surface.
const RETIRED_WANT_DERIVE_V1_TAG: u8 = 3;

fn retired_derive_v1_source(
    request: WantRequest,
    identity: &[u8; WANT_REQUEST_BYTES_LEN],
) -> Option<[u8; 32]> {
    if identity[0] != RETIRED_WANT_DERIVE_V1_TAG {
        return None;
    }
    let WantRequest::Derive { target, input } = request else {
        return None;
    };
    let historical_target: [u8; 32] = identity[33..65].try_into().ok()?;
    let historical_input: [u8; 32] = identity[65..97].try_into().ok()?;
    (historical_target == target.raw && historical_input == input.raw).then(|| {
        identity[1..33]
            .try_into()
            .expect("fixed historical WANT field")
    })
}

#[derive(Parser)]
pub enum Command {
    /// Verify pile integrity (blob hashes + legacy branch commit chains).
    Check {
        /// Path to the pile file to inspect
        pile: PathBuf,
        /// Exit non-zero at the first detected issue
        #[arg(long)]
        fail_fast: bool,
    },
    /// Locate occurrences of a blob handle in raw pile bytes.
    ///
    /// This is useful when the normal repository graph fails (e.g. a branch
    /// points at a missing blob) and you want to distinguish:
    /// - a missing blob record (0 header matches), vs
    /// - a blob referenced inside other blob payloads (payload refs)
    LocateHash {
        /// Path to the pile file to inspect
        pile: PathBuf,
        /// Handle to locate (e.g. "blake3:HEX..." or bare 64 hex)
        handle: String,
    },
    /// Decode the record beginning at one exact byte offset without modifying the pile.
    ///
    /// The command walks canonical record boundaries from the start of the
    /// pile. An offset inside a record is rejected and reports the enclosing
    /// span; an unsupported unenveloped marker is distinguished from a
    /// malformed or torn known record.
    RecordAt {
        /// Path to the pile file to inspect
        pile: PathBuf,
        /// Exact byte offset where a record header is expected
        offset: usize,
    },
    /// Count every record in a pile by kind, with the bytes each kind occupies.
    ///
    /// Opaque records are listed by their marker, so a refusal to compact can
    /// be read: which kinds are unknown here, and how much of the file they are.
    Census {
        /// Path to the pile file to inspect
        pile: PathBuf,
    },
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Check { pile, fail_fast } => check(&pile, fail_fast),
        Command::LocateHash { pile, handle } => locate_hash_in_pile(&pile, &handle),
        Command::RecordAt { pile, offset } => record_at(&pile, offset),
        Command::Census { pile } => census(&pile),
    }
}

#[derive(Default)]
struct RecordEvidence {
    opaque_count: usize,
    opaque_first: Option<usize>,
    opaque_last: Option<usize>,
    retired_derive_count: usize,
    retired_derive_first: Option<usize>,
    retired_derive_last: Option<usize>,
    retired_team_count: usize,
    retired_team_first: Option<usize>,
    retired_team_last: Option<usize>,
    retired_want_count: usize,
    retired_want_first: Option<usize>,
    retired_want_last: Option<usize>,
    legacy_collection_count: usize,
    legacy_collection_first: Option<usize>,
    legacy_collection_last: Option<usize>,
}

fn observe_offset(
    count: &mut usize,
    first: &mut Option<usize>,
    last: &mut Option<usize>,
    offset: usize,
) {
    *count += 1;
    first.get_or_insert(offset);
    *last = Some(offset);
}

fn scan_record_evidence(pile_path: &Path) -> Result<RecordEvidence> {
    use triblespace_core::repo::pile::{PileRecordContent, PileRecords};

    let mut evidence = RecordEvidence::default();
    let mut records =
        PileRecords::open(pile_path).map_err(|error| super::pile_read_error(pile_path, error))?;
    for record in &mut records {
        let record = record.map_err(|error| super::pile_read_error(pile_path, error))?;
        match record.content {
            PileRecordContent::Opaque { .. } => observe_offset(
                &mut evidence.opaque_count,
                &mut evidence.opaque_first,
                &mut evidence.opaque_last,
                record.offset,
            ),
            PileRecordContent::LegacyCollectionV3 { .. } => observe_offset(
                &mut evidence.legacy_collection_count,
                &mut evidence.legacy_collection_first,
                &mut evidence.legacy_collection_last,
                record.offset,
            ),
            PileRecordContent::RetiredCollectionDeriveV4 => observe_offset(
                &mut evidence.retired_derive_count,
                &mut evidence.retired_derive_first,
                &mut evidence.retired_derive_last,
                record.offset,
            ),
            PileRecordContent::RetiredPeerEvidenceV1 | PileRecordContent::RetiredStoreScopeV1 => {
                observe_offset(
                    &mut evidence.retired_team_count,
                    &mut evidence.retired_team_first,
                    &mut evidence.retired_team_last,
                    record.offset,
                )
            }
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => observe_offset(
                &mut evidence.retired_want_count,
                &mut evidence.retired_want_first,
                &mut evidence.retired_want_last,
                record.offset,
            ),
            _ => {}
        }
    }
    Ok(evidence)
}

fn check(pile_path: &Path, fail_fast: bool) -> Result<()> {
    use triblespace::prelude::blobencodings::{SimpleArchive, UTF8String};
    use triblespace::prelude::BlobStoreGet;

    use triblespace_core::id::id_hex;
    use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
    use triblespace_core::inline::Inline;
    use triblespace_core::macros::{find, pattern};
    use triblespace_core::repo::pile::{Pile, ReadError};
    use triblespace_core::repo::{self, BlobStoreMeta, PinSnapshotSource, SnapshotSource};
    use triblespace_core::trible::TribleSet;

    match Pile::open(pile_path) {
        Ok(mut pile) => {
            let res = (|| -> Result<(), anyhow::Error> {
                let mut any_error = false;
                let snapshot = pile
                    .snapshot()
                    .map_err(|error| super::pile_read_error(pile_path, error))?;
                let evidence = scan_record_evidence(pile_path)?;

                // Blob hash validation.
                let mut invalid = 0usize;
                let mut total = 0usize;
                for item in snapshot.iter() {
                    match item {
                        Ok((handle, blob)) => {
                            total += 1;
                            let expected: triblespace_core::inline::Inline<Hash<Blake3>> =
                                Handle::to_hash(handle);
                            let computed = Hash::<Blake3>::digest(&blob.bytes);
                            if expected != computed {
                                invalid += 1;
                            }
                        }
                        Err(_) => {
                            // Treat iterator errors (validation, missing index) as invalid blobs.
                            total += 1;
                            invalid += 1;
                        }
                    }
                }

                if invalid == 0 {
                    if evidence.opaque_count == 0 {
                        println!("Pile appears healthy");
                    } else {
                        println!(
                            "Known record projection appears healthy; skipped {} structurally framed opaque record(s) whose bodies were not semantically validated",
                            evidence.opaque_count
                        );
                    }
                } else {
                    println!("Pile corrupt: {invalid} of {total} blobs have incorrect hashes");
                    if fail_fast {
                        anyhow::bail!("invalid blob hashes detected");
                    }
                    any_error = true;
                }

                if evidence.legacy_collection_count != 0 {
                    println!(
                        "Recognized {} inert legacy V3 collection record(s) (first byte {}, last byte {}); preserved as migration evidence",
                        evidence.legacy_collection_count,
                        evidence
                            .legacy_collection_first
                            .expect("nonzero evidence has a first offset"),
                        evidence
                            .legacy_collection_last
                            .expect("nonzero evidence has a last offset"),
                    );
                }
                if evidence.retired_derive_count != 0 {
                    println!(
                        "Recognized {} retired V4 collection derive record(s) (first byte {}, last byte {}); omitted from current state",
                        evidence.retired_derive_count,
                        evidence
                            .retired_derive_first
                            .expect("nonzero evidence has a first offset"),
                        evidence
                            .retired_derive_last
                            .expect("nonzero evidence has a last offset"),
                    );
                }
                if evidence.retired_team_count != 0 {
                    println!(
                        "Recognized {} retired team-state record(s) (first byte {}, last byte {}); omitted from current state",
                        evidence.retired_team_count,
                        evidence
                            .retired_team_first
                            .expect("nonzero evidence has a first offset"),
                        evidence
                            .retired_team_last
                            .expect("nonzero evidence has a last offset"),
                    );
                }
                if evidence.retired_want_count != 0 {
                    println!(
                        "Recognized {} retired WANT log record(s) (first byte {}, last byte {}); omitted from current demand and available to explicit monotone-wants migration or reframe projection",
                        evidence.retired_want_count,
                        evidence
                            .retired_want_first
                            .expect("nonzero evidence has a first offset"),
                        evidence
                            .retired_want_last
                            .expect("nonzero evidence has a last offset"),
                    );
                }
                if evidence.opaque_count != 0 {
                    println!(
                        "Opaque record offsets: first byte {}, last byte {}",
                        evidence
                            .opaque_first
                            .expect("nonzero evidence has a first offset"),
                        evidence
                            .opaque_last
                            .expect("nonzero evidence has a last offset"),
                    );
                }

                // Branch integrity diagnostics.
                println!("\nBranches:");
                let _repo_branch_attr: triblespace_core::id::Id =
                    id_hex!("8694CC73AF96A5E1C7635C677D1B928A");
                let repo_parent_attr: triblespace_core::id::Id =
                    id_hex!("317044B612C690000D798CA660ECFD2A");
                let repo_content_attr: triblespace_core::id::Id =
                    id_hex!("4DD4DDD05CC31734B03ABB4E43188B1F");

                fn verify_chain(
                    snapshot: &triblespace_core::repo::pile::PileSnapshot,
                    start: Inline<Handle<SimpleArchive>>,
                    repo_parent_attr: triblespace_core::id::Id,
                    repo_content_attr: triblespace_core::id::Id,
                ) -> (usize, Option<String>) {
                    use std::collections::BTreeSet;
                    let mut visited: BTreeSet<String> = BTreeSet::new();
                    let mut stack: Vec<Inline<Handle<SimpleArchive>>> = vec![start];
                    let mut count = 0usize;
                    while let Some(h) = stack.pop() {
                        let hh: Inline<Hash<Blake3>> = Handle::to_hash(h);
                        let hex: String = hh.from_inline();
                        if !visited.insert(hex.clone()) {
                            continue;
                        }
                        match snapshot.metadata(h) {
                            Ok(None) => {
                                return (count, Some(format!("commit blake3:{hex} missing")));
                            }
                            Ok(Some(_)) => {}
                            Err(e) => {
                                return (
                                    count,
                                    Some(format!("commit blake3:{hex} metadata error: {e:?}")),
                                );
                            }
                        }
                        let meta: TribleSet = match snapshot.get::<TribleSet, SimpleArchive>(h) {
                            Ok(m) => m,
                            Err(e) => {
                                return (
                                    count,
                                    Some(format!("commit blake3:{hex} decode failed: {e:?}")),
                                )
                            }
                        };
                        let mut content_handle: Option<Inline<Handle<SimpleArchive>>> = None;
                        let mut parents: Vec<Inline<Handle<SimpleArchive>>> = Vec::new();
                        for t in meta.iter() {
                            if t.a() == &repo_content_attr {
                                content_handle = Some(*t.v::<Handle<SimpleArchive>>());
                            } else if t.a() == &repo_parent_attr {
                                parents.push(*t.v::<Handle<SimpleArchive>>());
                            }
                        }
                        // Some commits (for example merge-only commits) intentionally do not carry
                        // a content blob. Only verify content existence when present.
                        if let Some(c) = content_handle {
                            match snapshot.metadata(c) {
                                Ok(Some(_)) => {}
                                Ok(None) => {
                                    return (
                                        count,
                                        Some(format!("commit blake3:{hex} content blob missing")),
                                    );
                                }
                                Err(e) => {
                                    return (
                                        count,
                                        Some(format!("commit blake3:{hex} metadata error: {e:?}")),
                                    );
                                }
                            }
                        }
                        for p in parents {
                            stack.push(p);
                        }
                        count += 1;
                    }
                    (count, None)
                }

                // Legacy pins are migration evidence, not an operational
                // mutable branch API. Diagnose them through the immutable
                // snapshot surface retained for forensic reads.
                let pins = pile.snapshot_pin_heads()?;
                for raw in pins.iter_ordered() {
                    let bid = triblespace_core::id::Id::new(*raw)
                        .expect("pin snapshot cannot contain the nil id");
                    let meta_handle_opt = pins.get(raw).copied();
                    let id_hex = format!("{bid:X}");
                    match meta_handle_opt {
                        None => {
                            println!("- {id_hex}: <no branch metadata head set>");
                        }
                        Some(meta_handle) => {
                            let meta_present = snapshot.metadata(meta_handle)?.is_some();
                            let mut name_val: Option<String> = None;
                            let mut head_val: Option<Inline<Handle<SimpleArchive>>> = None;
                            let mut meta_err: Option<String> = None;
                            if meta_present {
                                match snapshot.get::<TribleSet, SimpleArchive>(meta_handle) {
                                    Ok(meta) => match repo::branch::branch_entity(&meta, bid) {
                                        Ok(branch_entity) => {
                                            let mut names = find!(
                                                name: Inline<Handle<UTF8String>>,
                                                pattern!(&meta, [{ branch_entity @ triblespace_core::metadata::name: ?name }])
                                            );
                                            if let (Some(name), None) = (names.next(), names.next())
                                            {
                                                if let Ok(view) = snapshot
                                                    .get::<triblespace::prelude::View<str>, _>(name)
                                                {
                                                    name_val = Some(view.as_ref().to_string());
                                                }
                                            }

                                            let mut heads = find!(
                                                head: Inline<Handle<SimpleArchive>>,
                                                pattern!(&meta, [{ branch_entity @ repo::head: ?head }])
                                            );
                                            match (heads.next(), heads.next()) {
                                                (Some(head), None) => head_val = Some(head),
                                                (None, None) => {}
                                                _ => {
                                                    meta_err = Some(
                                                        "multiple scoped branch heads".to_string(),
                                                    )
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            meta_err =
                                                Some(format!("branch entity malformed: {err:?}"));
                                        }
                                    },
                                    Err(e) => {
                                        meta_err = Some(format!("decode failed: {e:?}"));
                                    }
                                }
                            }
                            let meta_hash: Inline<Hash<Blake3>> = Handle::to_hash(meta_handle);
                            // `from_inline` already yields the "blake3:HEX" form — don't re-prefix.
                            let meta_ref: String = meta_hash.from_inline();
                            if let Some(n) = name_val.as_ref() {
                                println!(
                                    "- {id_hex} ({n}): meta {meta_ref} [{}]{}",
                                    if meta_present { "present" } else { "missing" },
                                    meta_err
                                        .as_deref()
                                        .map(|e| format!(" ({e})"))
                                        .unwrap_or_default()
                                );
                            } else {
                                println!(
                                    "- {id_hex}: meta {meta_ref} [{}]{}",
                                    if meta_present { "present" } else { "missing" },
                                    meta_err
                                        .as_deref()
                                        .map(|e| format!(" ({e})"))
                                        .unwrap_or_default()
                                );
                            }
                            if !meta_present {
                                if fail_fast {
                                    anyhow::bail!("branch metadata blob missing for {id_hex}");
                                }
                                any_error = true;
                                continue;
                            }
                            if meta_err.is_some() {
                                if fail_fast {
                                    anyhow::bail!("branch metadata decode failed for {id_hex}");
                                }
                                any_error = true;
                                continue;
                            }
                            if let Some(head) = head_val {
                                let (count, err) = verify_chain(
                                    &snapshot,
                                    head,
                                    repo_parent_attr,
                                    repo_content_attr,
                                );
                                if let Some(e) = err {
                                    println!("  commit chain error: {e}");
                                    if fail_fast {
                                        anyhow::bail!(e);
                                    }
                                    any_error = true;
                                } else {
                                    println!("  commit chain: {count} commits");
                                }
                            } else {
                                println!("  no head set");
                            }
                        }
                    }
                }

                if any_error {
                    anyhow::bail!("diagnostics reported issues");
                }

                Ok(())
            })();

            let close_res = pile.close().map_err(|e| anyhow::anyhow!("{e:?}"));
            res.and(close_res)?;
        }
        Err(ReadError::IoError(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("pile not found");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn record_at(pile_path: &Path, offset: usize) -> Result<()> {
    use triblespace_core::repo::pile::PileRecords;

    let mut records =
        PileRecords::open(pile_path).map_err(|error| super::pile_read_error(pile_path, error))?;
    let bytes = records.bytes().clone();
    let file_len = bytes.len();
    if offset > file_len {
        anyhow::bail!(
            "byte offset {offset} lies past the {file_len}-byte end of pile {}",
            pile_path.display()
        );
    }
    if offset == file_len {
        anyhow::bail!(
            "byte offset {offset} is the end of pile {}; no record begins there",
            pile_path.display()
        );
    }

    for decoded in &mut records {
        let record = decoded.map_err(|error| super::pile_read_error(pile_path, error))?;
        let next_offset = record
            .offset
            .checked_add(record.len)
            .expect("accepted pile record span fits usize");
        if offset == record.offset {
            print_record(&bytes, file_len, record);
            return Ok(());
        }
        if offset < next_offset {
            anyhow::bail!(
                "byte offset {offset} is inside the record spanning bytes {}..{}; exact record starts are {} and {}",
                record.offset,
                next_offset,
                record.offset,
                next_offset,
            );
        }
    }

    anyhow::bail!(
        "no record begins at byte offset {offset} in pile {}",
        pile_path.display()
    )
}

fn print_record(bytes: &[u8], file_len: usize, record: triblespace_core::repo::pile::PileRecord) {
    use triblespace_core::collection::CollectionRecord;
    use triblespace_core::repo::pile::{LegacyCollectionRecordKindV3, PileRecordContent};
    fn print_want_request(request: WantRequest) {
        match request {
            WantRequest::Blob { handle } => {
                println!("  request_kind: blob");
                println!("  handle: {}", hex::encode_upper(handle.raw));
            }
            WantRequest::Merge {
                collection,
                low,
                high,
            } => {
                println!("  request_kind: merge");
                println!("  collection: {}", hex::encode_upper(collection.raw));
                println!("  low: {}", hex::encode_upper(low.raw));
                println!("  high: {}", hex::encode_upper(high.raw));
            }
            WantRequest::Derive { target, input } => {
                println!("  request_kind: derive");
                println!("  target: {}", hex::encode_upper(target.raw));
                println!("  input: {}", hex::encode_upper(input.raw));
            }
        }
    }

    let next_offset = record
        .offset
        .checked_add(record.len)
        .expect("accepted pile record span fits usize");
    let raw = &bytes[record.offset..next_offset];
    let marker = &raw[..16];

    println!("Record at byte {}", record.offset);
    println!("  file_length: {file_len}");
    println!("  marker: {}", hex::encode_upper(marker));
    println!("  known_span_bytes: {}", record.len);
    println!("  next_offset: {next_offset}");

    match record.content {
        PileRecordContent::Blob {
            timestamp,
            hash,
            data_offset,
            data_len,
        } => {
            println!("  classification: blob");
            println!("  timestamp_ms: {timestamp}");
            println!("  payload_hash: {}", hex::encode_upper(hash.raw));
            println!("  payload_offset: {data_offset}");
            println!("  payload_length: {data_len}");
        }
        PileRecordContent::Branch { branch_id, head } => {
            println!("  classification: branch-head");
            println!("  branch_id: {branch_id:X}");
            println!("  head: {}", hex::encode_upper(head.raw));
        }
        PileRecordContent::BranchTombstone { branch_id } => {
            println!("  classification: branch-tombstone");
            println!("  branch_id: {branch_id:X}");
        }
        PileRecordContent::Want { request } => {
            println!("  classification: want (current grow-only set)");
            print_want_request(request);
        }
        PileRecordContent::RetiredWantAssert { request, identity } => {
            println!("  classification: retired want assertion (migration input)");
            print_want_request(request);
            if let Some(source) = retired_derive_v1_source(request, &identity) {
                println!("  historical_source: {}", hex::encode_upper(source));
            }
        }
        PileRecordContent::RetiredWantRetract { request, identity } => {
            println!("  classification: retired want retraction (migration input)");
            print_want_request(request);
            if let Some(source) = retired_derive_v1_source(request, &identity) {
                println!("  historical_source: {}", hex::encode_upper(source));
            }
        }
        PileRecordContent::Collection { record } => match record {
            CollectionRecord::Commit(commit) => {
                println!("  classification: collection-commit");
                println!(
                    "  collection: {}",
                    hex::encode_upper(commit.collection().raw)
                );
                println!("  data: {}", hex::encode_upper(commit.data().raw));
                println!("  metadata: {}", hex::encode_upper(commit.metadata().raw));
                println!("  author: {}", hex::encode_upper(commit.public_key().raw));
            }
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                println!("  classification: collection-merge");
                println!(
                    "  collection: {}",
                    hex::encode_upper(merge.collection().raw)
                );
                println!("  low: {}", hex::encode_upper(low.raw));
                println!("  high: {}", hex::encode_upper(high.raw));
                println!("  result: {}", hex::encode_upper(merge.result().raw));
                println!("  author: {}", hex::encode_upper(merge.public_key().raw));
            }
            CollectionRecord::Derive(derive) => {
                let (input, output) = (derive.input(), derive.output());
                println!("  classification: collection-derive");
                println!("  target: {}", hex::encode_upper(derive.collection().raw));
                println!("  input: {}", hex::encode_upper(input.raw));
                println!("  output: {}", hex::encode_upper(output.raw));
                println!("  author: {}", hex::encode_upper(derive.public_key().raw));
            }
        },
        PileRecordContent::LegacyCollectionV3 { kind } => {
            let classification = match kind {
                LegacyCollectionRecordKindV3::Definition => {
                    "legacy-v3-collection-definition (inert)"
                }
                LegacyCollectionRecordKindV3::Commit => "legacy-v3-collection-commit (inert)",
                LegacyCollectionRecordKindV3::Merge => "legacy-v3-collection-merge (inert)",
                LegacyCollectionRecordKindV3::Derive => "legacy-v3-collection-derive (inert)",
            };
            println!("  classification: {classification}");
            if kind == LegacyCollectionRecordKindV3::Definition {
                println!("  scope: {}", hex::encode_upper(&raw[16..32]));
                println!("  representation: {}", hex::encode_upper(&raw[32..48]));
                println!("  recipe: {}", hex::encode_upper(&raw[48..64]));
            }
        }
        PileRecordContent::RetiredCollectionDeriveV4 => {
            println!("  classification: retired-v4-collection-derive (inert)");
        }
        PileRecordContent::LegacyUnsignedCollectionEquation { .. } => {
            println!("  classification: legacy-unsigned-collection-equation (inert)");
        }
        PileRecordContent::RetiredPeerEvidenceV1 => {
            println!("  classification: retired-peer-evidence-v1 (inert)");
        }
        PileRecordContent::RetiredStoreScopeV1 => {
            println!("  classification: retired-store-scope-v1 (inert)");
        }
        PileRecordContent::Opaque { kind } => {
            println!("  classification: opaque (semantically skipped)");
            println!("  record_kind: {}", hex::encode_upper(kind));
        }
        _ => println!("  classification: recognized record"),
    }
}

fn locate_hash_in_pile(pile_path: &Path, handle: &str) -> Result<()> {
    use memchr::memmem::Finder;
    use triblespace_core::inline::encodings::hash::Blake3;
    use triblespace_core::inline::encodings::hash::Hash;
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::pile::{PileRecordContent, PileRecords};
    fn matching_want_fields(request: WantRequest, needle: &[u8; 32]) -> Vec<&'static str> {
        match request {
            WantRequest::Blob { handle } => (handle.raw == *needle)
                .then_some("handle")
                .into_iter()
                .collect(),
            WantRequest::Merge {
                collection,
                low,
                high,
            } => [
                ("collection", collection.raw),
                ("low", low.raw),
                ("high", high.raw),
            ]
            .into_iter()
            .filter_map(|(field, value)| (value == *needle).then_some(field))
            .collect(),
            WantRequest::Derive { target, input } => {
                { [("target", target.raw), ("input", input.raw)] }
                    .into_iter()
                    .filter_map(|(field, value)| (value == *needle).then_some(field))
                    .collect()
            }
        }
    }

    let handle = handle.trim();
    let normalized = if !handle.contains(':') && handle.len() == 64 {
        format!("blake3:{handle}")
    } else {
        handle.to_owned()
    };
    let target: Inline<Hash<Blake3>> = crate::cli::util::parse_blob_handle(&normalized)?;
    let needle = target.raw;
    let needle_str: String = target.from_inline();

    // Record-level walk shared with the pile replay path — understands every
    // record format (legacy and generic envelope), so no format constant is
    // duplicated here.
    let mut records = PileRecords::open(pile_path)?;
    let bytes = records.bytes().clone();

    let finder = Finder::new(&needle);
    let mut blob_header_matches = 0usize;
    let mut branch_header_matches = 0usize;
    let mut want_marker_matches = 0usize;
    let mut collection_record_matches = 0usize;
    let mut opaque_record_matches = 0usize;
    let mut payload_matches = 0usize;
    let mut parse_error = None;

    for record in &mut records {
        let record = match record {
            Ok(record) => record,
            Err(e) => {
                parse_error = Some(e);
                break;
            }
        };
        match record.content {
            PileRecordContent::Blob {
                hash,
                data_offset,
                data_len,
                ..
            } => {
                if hash.raw == needle {
                    blob_header_matches += 1;
                    println!("blob header match at byte {}", record.offset);
                }
                let payload = &bytes[data_offset..data_offset + data_len];
                if finder.find(payload).is_some() {
                    let container_str: String = hash.from_inline();
                    for pos in finder.find_iter(payload) {
                        payload_matches += 1;
                        let absolute = data_offset + pos;
                        println!("payload reference in {container_str} at byte {absolute}");
                    }
                }
            }
            PileRecordContent::Branch { branch_id, head } => {
                if head.raw == needle {
                    branch_header_matches += 1;
                    println!(
                        "branch head match at byte {} (branch_id {branch_id:X})",
                        record.offset
                    );
                }
            }
            PileRecordContent::BranchTombstone { .. } => {}
            PileRecordContent::Want { request } => {
                for field in matching_want_fields(request, &needle) {
                    want_marker_matches += 1;
                    println!(
                        "typed want reference at byte {} (request field {field})",
                        record.offset
                    );
                }
            }
            PileRecordContent::RetiredWantAssert { request, identity }
            | PileRecordContent::RetiredWantRetract { request, identity } => {
                for field in matching_want_fields(request, &needle) {
                    want_marker_matches += 1;
                    println!(
                        "typed want reference at byte {} (request field {field})",
                        record.offset
                    );
                }
                if retired_derive_v1_source(request, &identity) == Some(needle) {
                    want_marker_matches += 1;
                    println!(
                        "typed want reference at byte {} (request field historical_source)",
                        record.offset
                    );
                }
            }
            PileRecordContent::Collection { .. }
            | PileRecordContent::LegacyUnsignedCollectionEquation { .. }
            | PileRecordContent::LegacyCollectionV3 { .. }
            | PileRecordContent::RetiredCollectionDeriveV4 => {
                let raw = &bytes[record.offset..record.offset + record.len];
                for pos in finder.find_iter(raw) {
                    collection_record_matches += 1;
                    println!(
                        "collection-record reference at byte {}",
                        record.offset + pos
                    );
                }
            }
            PileRecordContent::Opaque { kind } => {
                let raw = &bytes[record.offset..record.offset + record.len];
                for pos in finder.find_iter(raw) {
                    opaque_record_matches += 1;
                    println!(
                        "opaque-record byte match at byte {} (kind {})",
                        record.offset + pos,
                        hex::encode_upper(kind)
                    );
                }
            }
            _ => {}
        }
    }

    println!("\nSummary for {needle_str}:");
    println!("  blob headers:   {blob_header_matches}");
    println!("  branch headers: {branch_header_matches}");
    println!("  want markers:   {want_marker_matches}");
    println!("  collection records: {collection_record_matches}");
    println!("  opaque records: {opaque_record_matches}");
    println!("  payload refs:   {payload_matches}");
    if let Some(err) = parse_error {
        println!("  parse stopped:  {err}");
        anyhow::bail!("pile contains an unreadable record: {err}");
    }
    Ok(())
}

/// Every record by kind: how many, and how many bytes of the file they are.
fn census(path: &Path) -> Result<()> {
    use std::collections::BTreeMap;
    use triblespace_core::repo::pile::{PileRecordContent, PileRecords};

    let mut records =
        PileRecords::open(path).map_err(|error| super::pile_read_error(path, error))?;
    let total = records.bytes().len() as u64;
    let mut kinds: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut opaque: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut first_opaque: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut duplicate_blobs: (u64, u64) = (0, 0);
    let mut duplicates_by_day: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    while let Some(record) = records.next() {
        let record = record.map_err(|error| super::pile_read_error(path, error))?;
        if let PileRecordContent::Blob {
            hash, timestamp, ..
        } = &record.content
        {
            if !seen.insert(hash.raw) {
                duplicate_blobs.0 += 1;
                duplicate_blobs.1 += record.len as u64;
                let day = timestamp / 86_400_000;
                let entry = duplicates_by_day.entry(day).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += record.len as u64;
            }
        }
        let (kind, is_opaque) = match &record.content {
            PileRecordContent::Blob { .. } => ("BLOB", None),
            PileRecordContent::Collection { .. } => ("COLLECTION", None),
            PileRecordContent::LegacyUnsignedCollectionEquation { .. } => {
                ("legacy UNSIGNED_COLLECTION_EQUATION", None)
            }
            PileRecordContent::CapabilityProof { .. } => ("CAPABILITY_PROOF", None),
            PileRecordContent::Want { .. } => ("WANT", None),
            PileRecordContent::Branch { .. } => ("legacy BRANCH", None),
            PileRecordContent::BranchTombstone { .. } => ("legacy BRANCH_TOMBSTONE", None),
            PileRecordContent::LegacyCollectionV3 { .. } => ("legacy COLLECTION_V3", None),
            PileRecordContent::RetiredCapabilityProof { .. } => ("retired CAPABILITY_PROOF", None),
            PileRecordContent::RetiredCollectionDeriveV4 { .. } => {
                ("retired COLLECTION_DERIVE_V4", None)
            }
            PileRecordContent::RetiredPeerEvidenceV1 => ("retired PEER_EVIDENCE_V1", None),
            PileRecordContent::RetiredStoreScopeV1 => ("retired STORE_SCOPE_V1", None),
            PileRecordContent::RetiredArtifactOfferV1 => ("retired ARTIFACT_OFFER_V1", None),
            PileRecordContent::RetiredWantAssert { .. } => ("retired WANT_ASSERT", None),
            PileRecordContent::RetiredWantRetract { .. } => ("retired WANT_RETRACT", None),
            PileRecordContent::Opaque { kind, .. } => {
                ("OPAQUE", Some(hex::encode_upper(kind.as_ref())))
            }
            _ => ("other", None),
        };
        let entry = kinds.entry(kind.to_owned()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += record.len as u64;
        if let Some(marker) = is_opaque {
            let entry = opaque.entry(marker.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += record.len as u64;
            first_opaque.entry(marker).or_insert(record.offset);
        }
    }
    println!("{} bytes in {}", total, path.display());
    println!(
        "{:<34} {:>10} {:>16} {:>7}",
        "kind", "records", "bytes", "share"
    );
    for (kind, (count, bytes)) in &kinds {
        println!(
            "{:<34} {:>10} {:>16} {:>6.1}%",
            kind,
            count,
            bytes,
            *bytes as f64 * 100.0 / total.max(1) as f64
        );
    }
    println!(
        "{:<34} {:>10} {:>16} {:>6.1}%   (a second or later record of a blob already present; distinct blobs {})",
        "  of which duplicate BLOB",
        duplicate_blobs.0,
        duplicate_blobs.1,
        duplicate_blobs.1 as f64 * 100.0 / total.max(1) as f64,
        seen.len()
    );
    if !duplicates_by_day.is_empty() {
        println!();
        println!("duplicate BLOB records by insertion day (days since 1970-01-01, UTC):");
        for (day, (count, bytes)) in &duplicates_by_day {
            println!("  day {} {:>10} {:>16}", day, count, bytes);
        }
    }
    if !opaque.is_empty() {
        println!();
        println!("opaque records by marker (first offset in brackets):");
        for (marker, (count, bytes)) in &opaque {
            println!(
                "  {} {:>10} {:>16} [{}]",
                marker, count, bytes, first_opaque[marker]
            );
        }
    }
    Ok(())
}
