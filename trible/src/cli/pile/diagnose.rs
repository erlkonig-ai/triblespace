use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};
use triblespace_core::repo::{WantRequest, WANT_REQUEST_BYTES_LEN};

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
    /// List MERGEs that disagree: one key naming two results for one input set.
    ///
    /// A MERGE names the join of its inputs, and the host that signed it
    /// takes it at its word and never recomputes the result to check it. A
    /// host believes only its own MERGEs, so one key naming two results for
    /// the same inputs is that host's computation disagreeing with itself,
    /// which this lists by collection and key and exits non-zero on.
    /// Different keys naming different results are two private lattices, and
    /// a DERIVE with several outputs for one locator is several leaves; both
    /// are counted and neither fails. Admission is not checked here.
    Conflicts {
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
        Command::Conflicts { pile } => conflicts(&pile),
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
    use triblespace_core::collection::{CollectionRecord, RetiredCollectionEquation};
    use triblespace_core::repo::pile::{LegacyCollectionRecordKindV3, PileRecordContent};
    fn print_want_request(request: WantRequest) {
        match request {
            WantRequest::Blob { handle } => {
                println!("  request_kind: blob");
                println!("  handle: {}", hex::encode_upper(handle.raw));
            }
        }
    }
    // A retired identity is raw migration input: only the blob shape still
    // decodes, and the computation shapes project to no current want.
    fn print_retired_want_identity(identity: &[u8; WANT_REQUEST_BYTES_LEN]) {
        println!("  identity: {}", hex::encode_upper(identity));
        match WantRequest::from_bytes(*identity) {
            Ok(request) => print_want_request(request),
            Err(error) => println!("  request_kind: retired, projects to no want ({error})"),
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
        PileRecordContent::RetiredWantAssert { identity } => {
            println!("  classification: retired want assertion (migration input)");
            print_retired_want_identity(&identity);
        }
        PileRecordContent::RetiredWantRetract { identity } => {
            println!("  classification: retired want retraction (migration input)");
            print_retired_want_identity(&identity);
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
                println!("  classification: collection-merge");
                println!(
                    "  collection: {}",
                    hex::encode_upper(merge.collection().raw)
                );
                for (index, input) in merge.inputs().iter().enumerate() {
                    println!("  input[{index}]: {}", hex::encode_upper(input.raw));
                }
                println!("  result: {}", hex::encode_upper(merge.result().raw));
                println!("  author: {}", hex::encode_upper(merge.public_key().raw));
            }
            CollectionRecord::Derive(derive) => {
                println!("  classification: collection-derive");
                println!("  target: {}", hex::encode_upper(derive.collection().raw));
                println!(
                    "  source_locator: {}",
                    hex::encode_upper(derive.input().raw())
                );
                println!("  output: {}", hex::encode_upper(derive.output().raw));
                println!("  author: {}", hex::encode_upper(derive.public_key().raw));
            }
        },
        PileRecordContent::RetiredCollectionEquation { equation } => match equation {
            RetiredCollectionEquation::MergeV8 {
                collection,
                low,
                high,
                result,
                public_key,
                ..
            } => {
                println!("  classification: retired-v8-collection-merge (inert)");
                println!("  collection: {}", hex::encode_upper(collection.raw));
                println!("  low: {}", hex::encode_upper(low.raw));
                println!("  high: {}", hex::encode_upper(high.raw));
                println!("  result: {}", hex::encode_upper(result.raw));
                println!("  author: {}", hex::encode_upper(public_key.raw));
            }
            RetiredCollectionEquation::DeriveV9 {
                target,
                input,
                output,
                public_key,
                ..
            } => {
                println!("  classification: retired-v9-collection-derive (inert)");
                println!("  target: {}", hex::encode_upper(target.raw));
                println!("  input: {}", hex::encode_upper(input.raw));
                println!("  output: {}", hex::encode_upper(output.raw));
                println!("  author: {}", hex::encode_upper(public_key.raw));
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
            PileRecordContent::RetiredWantAssert { identity }
            | PileRecordContent::RetiredWantRetract { identity } => {
                // A retired identity may carry a shape no current decoder
                // names, so match its fixed historical fields directly.
                for (index, field) in identity[1..].chunks_exact(32).enumerate() {
                    if field == needle {
                        want_marker_matches += 1;
                        println!(
                            "typed want reference at byte {} (retired identity field {index})",
                            record.offset
                        );
                    }
                }
            }
            PileRecordContent::Collection { .. }
            | PileRecordContent::LegacyUnsignedCollectionEquation { .. }
            | PileRecordContent::RetiredCollectionEquation { .. }
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
            PileRecordContent::RetiredCollectionEquation { .. } => {
                ("retired COLLECTION_EQUATION_V8_V9", None)
            }
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

/// One MERGE's input set as one key signed it: the collection, the signer and
/// the nodes it joins. The signer is part of the key because another key's
/// MERGE is never believed here: two keys naming different results for one
/// input set are two private lattices, not a contradiction. One key naming
/// two results is its own computation disagreeing with itself.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SignedJoin {
    collection: [u8; 32],
    signer: [u8; 32],
    inputs: Vec<[u8; 32]>,
}

/// What `conflicts` counts in one record scan: every MERGE once per signer
/// (inputs -> results) and every DERIVE once per locator (outputs). A
/// display tally, dropped after printing; nothing reads it later.
#[derive(Default)]
struct ConflictTally {
    merge_records: usize,
    derive_records: usize,
    /// Every MERGE once per signer: inputs -> results.
    merges: std::collections::BTreeMap<SignedJoin, Named>,
    /// Every DERIVE once: (target, locator) -> outputs.
    derives: std::collections::BTreeMap<([u8; 32], [u8; 32]), Named>,
}

/// The results or outputs named for one input set or locator.
type Named = std::collections::BTreeSet<[u8; 32]>;

impl ConflictTally {
    fn add(&mut self, record: &triblespace_core::collection::CollectionRecord) {
        use triblespace_core::collection::CollectionRecord;
        match record {
            CollectionRecord::Commit(_) => {}
            CollectionRecord::Merge(merge) => {
                self.merge_records += 1;
                self.merges
                    .entry(SignedJoin {
                        collection: merge.collection().raw,
                        signer: merge.public_key().raw,
                        inputs: merge.inputs().iter().map(|input| input.raw).collect(),
                    })
                    .or_default()
                    .insert(merge.result().raw);
            }
            CollectionRecord::Derive(derive) => {
                self.derive_records += 1;
                self.derives
                    .entry((derive.collection().raw, derive.input().raw()))
                    .or_default()
                    .insert(derive.output().raw);
            }
        }
    }

    /// DERIVE locators with several outputs. Legal: a DERIVE is a relation,
    /// and every output is its own leaf of the derived collection.
    fn several_outputs(&self) -> usize {
        self.derives
            .values()
            .filter(|outputs| outputs.len() > 1)
            .count()
    }

    /// Joins (collection and input set) on which different keys name
    /// different results and no key contradicts itself. Legal: each host
    /// believes only its own MERGEs, so neither side reaches the other. A join
    /// some key does contradict itself on is one of [`Self::disagreeing`]'s,
    /// and is reported there rather than counted twice.
    fn across_keys(&self) -> usize {
        use std::collections::{BTreeMap, BTreeSet};
        let mut by_join: BTreeMap<([u8; 32], &[[u8; 32]]), (BTreeSet<[u8; 32]>, bool)> =
            BTreeMap::new();
        for (merge, results) in &self.merges {
            let (named, contradicted) = by_join
                .entry((merge.collection, merge.inputs.as_slice()))
                .or_default();
            named.extend(results.iter().copied());
            *contradicted |= results.len() > 1;
        }
        by_join
            .values()
            .filter(|(named, contradicted)| named.len() > 1 && !contradicted)
            .count()
    }

    /// The conflicts: one key naming two or more results for one input set.
    fn disagreeing(&self) -> Vec<(&SignedJoin, &Named)> {
        self.merges
            .iter()
            .filter(|(_, results)| results.len() > 1)
            .collect()
    }
}

fn conflicts(path: &Path) -> Result<()> {
    use std::collections::BTreeMap;
    use triblespace_core::collection::CollectionRead;
    use triblespace_core::repo::pile::Pile;
    use triblespace_core::repo::SnapshotSource;

    // A record scan: nothing here asks the fold, so the pile is opened with
    // no host and no MERGE is believed or needs to be.
    let mut pile = Pile::open(path).map_err(|error| super::pile_read_error(path, error))?;
    let snapshot = pile
        .snapshot()
        .map_err(|error| super::pile_read_error(path, error))?;
    let mut tally = ConflictTally::default();
    for record in snapshot.records().map_err(|error| {
        anyhow::anyhow!("read collection records of {}: {error}", path.display())
    })? {
        let record = record.map_err(|error| {
            anyhow::anyhow!("read collection records of {}: {error}", path.display())
        })?;
        tally.add(&record);
    }
    println!(
        "{} MERGE record(s) over {} signed input set(s) and {} DERIVE record(s) over {} \
         locator(s) in {}",
        tally.merge_records,
        tally.merges.len(),
        tally.derive_records,
        tally.derives.len(),
        path.display()
    );

    // Counted so a reader can see them, never failed on.
    let several = tally.several_outputs();
    if several > 0 {
        println!(
            "{several} DERIVE locator(s) carry several outputs; each output is its own leaf, \
             which is not a conflict"
        );
    }
    let across_keys = tally.across_keys();
    if across_keys > 0 {
        println!(
            "{across_keys} MERGE input set(s) carry different results from different keys; \
             another key's MERGE is never believed, so these are not conflicts"
        );
    }

    let disagreeing = tally.disagreeing();
    if disagreeing.is_empty() {
        println!("No key names two results for one MERGE input set");
        return Ok(());
    }
    let mut by_collection: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for (inputs, _) in &disagreeing {
        *by_collection.entry(inputs.collection).or_default() += 1;
    }
    println!(
        "{} MERGE input set(s) carry two or more results from one key, in {} collection(s):",
        disagreeing.len(),
        by_collection.len()
    );
    for (collection, count) in &by_collection {
        println!("  {} {:>8}", hex::encode(collection), count);
    }
    println!();
    for (merge, results) in &disagreeing {
        println!(
            "MERGE in {} signed by {}",
            hex::encode(merge.collection),
            hex::encode(merge.signer)
        );
        for input in &merge.inputs {
            println!("  input {}", hex::encode(input));
        }
        for result in results.iter() {
            println!("  -> {}", hex::encode(result));
        }
    }
    anyhow::bail!(
        "{} MERGE input set(s) name two or more results under one key",
        disagreeing.len()
    )
}

#[cfg(test)]
mod conflict_tests {
    use super::{conflicts, ConflictTally};
    use ed25519_dalek::SigningKey;
    use triblespace_core::collection::{
        CollectionDerive, CollectionMerge, CollectionRecord, CollectionStore,
    };
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::pile::Pile;

    fn pile_with(records: impl IntoIterator<Item = CollectionRecord>) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("equations.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        for record in records {
            pile.insert(record).unwrap();
        }
        pile.close().unwrap();
        directory
    }

    #[test]
    fn agreeing_equations_report_nothing_and_disagreeing_ones_fail() {
        let one = SigningKey::from_bytes(&[1; 32]);
        let two = SigningKey::from_bytes(&[2; 32]);
        let collection = Inline::new([7; 32]);
        let input = Inline::new([10; 32]);
        let other = Inline::new([11; 32]);
        let agreed = pile_with([
            CollectionRecord::Derive(CollectionDerive::sign(
                &one,
                collection,
                triblespace_core::collection::SourceLocator::of(input.raw),
                Inline::new([20; 32]),
            )),
            // A second signer naming the same output agrees, and is one more
            // key behind the same equation, not a conflict.
            CollectionRecord::Derive(CollectionDerive::sign(
                &two,
                collection,
                triblespace_core::collection::SourceLocator::of(input.raw),
                Inline::new([20; 32]),
            )),
            CollectionRecord::Merge(
                CollectionMerge::sign(&one, collection, [input, other], Inline::new([30; 32]))
                    .unwrap(),
            ),
        ]);
        conflicts(&agreed.path().join("equations.pile")).unwrap();

        // One key naming two results for one join is that key disagreeing
        // with itself. The same join named in either order is one input set.
        let disagreeing = pile_with([
            CollectionRecord::Merge(
                CollectionMerge::sign(&one, collection, [input, other], Inline::new([30; 32]))
                    .unwrap(),
            ),
            CollectionRecord::Merge(
                CollectionMerge::sign(&one, collection, [other, input], Inline::new([31; 32]))
                    .unwrap(),
            ),
        ]);
        let error = conflicts(&disagreeing.path().join("equations.pile")).unwrap_err();
        assert!(
            error.to_string().contains("1 MERGE input set(s)"),
            "unexpected report: {error}"
        );
    }

    #[test]
    fn other_keys_merges_and_several_outputs_per_locator_do_not_fail() {
        let one = SigningKey::from_bytes(&[1; 32]);
        let two = SigningKey::from_bytes(&[2; 32]);
        let collection = Inline::new([7; 32]);
        let input = Inline::new([10; 32]);
        let other = Inline::new([11; 32]);
        let legal = pile_with([
            // A DERIVE is a relation: two outputs for one locator are two
            // leaves, from two keys or from one.
            CollectionRecord::Derive(CollectionDerive::sign(
                &one,
                collection,
                triblespace_core::collection::SourceLocator::of(input.raw),
                Inline::new([20; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &two,
                collection,
                triblespace_core::collection::SourceLocator::of(input.raw),
                Inline::new([21; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &one,
                collection,
                triblespace_core::collection::SourceLocator::of(other.raw),
                Inline::new([22; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &one,
                collection,
                triblespace_core::collection::SourceLocator::of(other.raw),
                Inline::new([23; 32]),
            )),
            // Two keys naming different results for one join are two private
            // lattices: a host never believes the other key's MERGE.
            CollectionRecord::Merge(
                CollectionMerge::sign(&one, collection, [input, other], Inline::new([30; 32]))
                    .unwrap(),
            ),
            CollectionRecord::Merge(
                CollectionMerge::sign(&two, collection, [input, other], Inline::new([31; 32]))
                    .unwrap(),
            ),
        ]);
        conflicts(&legal.path().join("equations.pile")).unwrap();
    }

    #[test]
    fn the_tally_counts_disagreement_across_keys_apart_from_one_key_contradicting_itself() {
        let one = SigningKey::from_bytes(&[1; 32]);
        let two = SigningKey::from_bytes(&[2; 32]);
        let collection = Inline::new([7; 32]);
        let input = Inline::new([10; 32]);
        let other = Inline::new([11; 32]);
        let third = Inline::new([12; 32]);
        let merge = |key: &SigningKey,
                     inputs: [triblespace_core::collection::CollectionData; 2],
                     result: u8| {
            CollectionRecord::Merge(
                CollectionMerge::sign(key, collection, inputs, Inline::new([result; 32])).unwrap(),
            )
        };
        let mut tally = ConflictTally::default();
        // One join two keys disagree on, each consistent with itself: counted
        // across keys, and no conflict.
        tally.add(&merge(&one, [input, other], 30));
        tally.add(&merge(&two, [input, other], 31));
        // Another join, on which key one contradicts itself while key two
        // names a third result: a conflict of key one's, reported once among
        // the conflicts and not counted again across keys.
        tally.add(&merge(&one, [input, third], 40));
        tally.add(&merge(&one, [third, input], 41));
        tally.add(&merge(&two, [input, third], 42));
        // A key repeating itself is one result, not two.
        tally.add(&merge(&two, [input, other], 31));
        // Two outputs for one locator are two leaves.
        tally.add(&CollectionRecord::Derive(CollectionDerive::sign(
            &one,
            collection,
            triblespace_core::collection::SourceLocator::of(input.raw),
            Inline::new([20; 32]),
        )));
        tally.add(&CollectionRecord::Derive(CollectionDerive::sign(
            &two,
            collection,
            triblespace_core::collection::SourceLocator::of(input.raw),
            Inline::new([21; 32]),
        )));

        assert_eq!(tally.merge_records, 6);
        assert_eq!(tally.merges.len(), 4, "signed input sets");
        assert_eq!(tally.derive_records, 2);
        assert_eq!(tally.several_outputs(), 1);
        assert_eq!(tally.across_keys(), 1);
        let disagreeing = tally.disagreeing();
        assert_eq!(disagreeing.len(), 1);
        let (join, results) = disagreeing[0];
        assert_eq!(join.signer, one.verifying_key().to_bytes());
        assert_eq!(join.inputs, vec![input.raw, third.raw]);
        assert_eq!(
            results.iter().copied().collect::<Vec<_>>(),
            vec![[40; 32], [41; 32]]
        );
    }
}
