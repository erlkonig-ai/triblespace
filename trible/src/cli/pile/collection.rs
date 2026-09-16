//! `trible pile collection …` — a collection-aware view of a pile.
//!
//! A collection is identified by the blake3 handle of its *descriptor blob*,
//! not by the entity id inside that blob. The descriptor is an ordinary
//! canonical `SimpleArchive` whose distinguished intrinsic entity carries the
//! `KIND_COLLECTION_DESCRIPTOR` tag, an anchor — `name` for a root, `source`
//! for a derivation — plus independent READ and WRITE admission policies, the
//! blob `representation`, and — for a derivation — its content-derived
//! `mapping`. Policy, encoding, mapping algorithm, and concrete mapping
//! parameters are embedded as ordinary associated entities.
//!
//! Without this module the only way to look at one was
//! `pile blob inspect <PILE> blake3:<HEX>`, which reports "256 bytes, Binary"
//! and nothing else. Here the facts are read with the same
//! [`descriptor`](triblespace_core::collection::descriptor) queries resolution
//! and retention use, so the CLI view can never drift from the semantics.
//!
//! Names are what the listing leads with. A root carries the name it is known
//! by, while its complete policy remains part of its immutable identity. That
//! name — not the 64 hex characters of its descriptor handle — is what an
//! operator came to read. Every subcommand that takes a collection therefore
//! accepts either spelling. `blake3:` and `name:` prefixes disambiguate the
//! unusual case where an arbitrary UTF-8 name itself looks like a bare handle.

use anyhow::{anyhow, Result};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use triblespace_core::blob::encodings::entity_id_set::{
    EntityIdSetBlob, GENID_ATTRIBUTE_VALUES_MAPPING_V1,
};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::Blob;
use triblespace_core::blob::IntoBlob;
use triblespace_core::blob::TryFromBlob;
use triblespace_core::collection::records::{CollectionHandle, CollectionRecord};
use triblespace_core::collection::reference_summary::{
    ReferenceSummaryBlob, ReferenceSummaryLayout, REFERENCE_SUMMARY_MAPPING_V1,
};
use triblespace_core::collection::CollectionRead;
use triblespace_core::collection::{
    descriptor, grant_collection_read, grant_collection_write, AdmissionPolicy, Collection,
    CollectionPolicy, CollectionRecordSelector, CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace_core::inline::Inline;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreMeta, ObservedStore, SnapshotSource, Store, StoreDependencies,
    StoreRead, StoreSnapshot,
};
use triblespace_core::trible::Fragment;
use triblespace_core::trible::TribleSet;

use super::open_refreshed;

#[cfg(test)]
mod maintenance_counts;
mod maintenance_telemetry;

/// Hex characters shown for a handle or key when the full value is not asked
/// for. Sixteen is far past the point where two collections in one pile
/// collide, and short enough that a row stays one terminal line.
const ABBREV: usize = 16;

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum SuccinctBackend {
    #[default]
    Cpu,
    /// CUDA wavelet packing; requires the succinct-cuda build feature and a
    /// separately reserved device/shared-memory budget. Rank9 stays on CPU.
    Cuda,
}

impl SuccinctBackend {
    fn check_available(self) -> Result<()> {
        match self {
            Self::Cpu => Ok(()),
            Self::Cuda => {
                #[cfg(feature = "succinct-cuda")]
                {
                    Ok(())
                }
                #[cfg(not(feature = "succinct-cuda"))]
                {
                    Err(anyhow!(
                        "CUDA Succinct maintenance requires the succinct-cuda build feature"
                    ))
                }
            }
        }
    }
}

#[derive(Parser)]
pub enum Command {
    /// Register one named root collection and print its exact handle.
    ///
    /// The existing signing key becomes the direct READ and WRITE root. This
    /// stores only the canonical descriptor closure: it does not create a
    /// synthetic commit, and repeating it is idempotent.
    Init {
        /// Path to the pile file to update.
        pile: PathBuf,
        /// Stable name carried by the root collection descriptor.
        name: String,
        /// Existing READ/WRITE-root signing key. Defaults to TRIBLESPACE_KEY
        /// or self.key beside the pile; a missing key is never created.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// List every collection the pile references, named ones first.
    ///
    /// A collection is "referenced" when some commit, merge, or derive record
    /// in the pile names it. Roots are listed by the name they carry, then
    /// derivations by their source, then any collection whose descriptor
    /// claims no anchor or is not in the pile at all — those are never
    /// silently dropped, because a pile that has forgotten what a collection
    /// is called still has its records.
    List {
        /// Path to the pile file to inspect.
        path: PathBuf,
        /// Only list named roots, hiding derivations and anchorless
        /// collections.
        #[arg(long)]
        named: bool,
        /// Also show the descriptor blob's size and storage timestamp.
        #[arg(long)]
        metadata: bool,
        /// Print handles and policy roots in full.
        #[arg(long)]
        long: bool,
    },
    /// Fully decode one collection descriptor.
    ///
    /// Prints the descriptor handle (the collection identity), the intrinsic
    /// entity id inside the archive, the decoded anchor / representation /
    /// mapping, every trible in the archive, and how many records in this pile
    /// reference the collection.
    Show {
        /// Path to the pile file to read.
        pile: PathBuf,
        /// Collection name, or descriptor handle. Use `name:` or `blake3:`
        /// to disambiguate a name that itself looks like a handle.
        collection: String,
    },
    /// List the commit, merge, and derive records that name one collection.
    ///
    /// This is the record stream itself, in the store's deterministic
    /// fingerprint order — not a commit chain, because a collection has no
    /// head to walk back from. Signatures are verified as they are printed.
    Log {
        /// Path to the pile file to read.
        pile: PathBuf,
        /// Collection name, or descriptor handle. Use `name:` or `blake3:`
        /// to disambiguate a name that itself looks like a handle.
        collection: String,
        /// Maximum records to print; `0` prints all of them.
        #[arg(long, default_value_t = 25)]
        limit: usize,
        /// Print handles and keys in full instead of abbreviated.
        #[arg(long)]
        long: bool,
    },
    /// Re-sign every commit of one collection into another, under this key.
    ///
    /// Concatenation is the merge: after `cat other.pile >> pile`, the other
    /// pile's collections are here physically, but under their own authority,
    /// so nothing reading this pile's collections sees them. Adopt reads each
    /// COMMIT of the source collection from one frozen snapshot, verifies its
    /// signature, and commits the exact same data and metadata archives into
    /// the target collection signed by this key. A claim-level act: no data is
    /// rewritten, no id is minted, and repeating it appends nothing new.
    Adopt {
        /// Path to the pile file to update.
        pile: PathBuf,
        /// Source collection: name, or descriptor handle (`name:` / `blake3:`).
        #[arg(long)]
        from: String,
        /// Target collection: name, or descriptor handle (`name:` / `blake3:`).
        #[arg(long)]
        into: String,
        /// Signing key for the target commits: one of the target's WRITE roots,
        /// or an author with a resident WRITE proof. Defaults to TRIBLESPACE_KEY
        /// or self.key beside the pile.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Report what would be adopted without appending anything.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Register one derived collection over a source and print its exact handle.
    ///
    /// The kind picks the encoding and its mapping. The descriptor then carries
    /// the source, the mapping and its arguments, which is everything `maintain`
    /// and every reader need; nothing has to be told twice. As for `init`, the
    /// existing signing key becomes the direct READ and WRITE root.
    Derive {
        /// Path to the pile file to update
        pile: PathBuf,
        /// Source collection: name, or descriptor handle
        source: String,
        /// What to derive. succinct and rank9 take no arguments; entity-id-set
        /// takes --attribute; latest takes --observes; lww takes --identity and
        /// --orders; nvfp4 takes --attribute and --dimension. reference-summary
        /// takes --log2-bits and --probes (defaults: 32 and 4); bm25 takes --text
        /// and --tokenizer; path takes --expr.
        #[arg(value_enum)]
        kind: DeriveKind,
        /// latest: the attribute whose GenId values name the state observed
        #[arg(long)]
        observes: Option<String>,
        /// lww: the attribute carrying the register identity
        #[arg(long)]
        identity: Option<String>,
        /// lww: the attribute carrying the register order coordinate
        #[arg(long)]
        orders: Option<String>,
        /// entity-id-set: the attribute carrying GenId values; nvfp4: the
        /// attribute carrying f32 embedding blobs
        #[arg(long)]
        attribute: Option<String>,
        /// nvfp4: the embedding dimension
        #[arg(long)]
        dimension: Option<usize>,
        /// reference-summary: fixed bit universe, expressed as its base-two log
        #[arg(long)]
        log2_bits: Option<u8>,
        /// reference-summary: fixed number of Bloom probes per locator
        #[arg(long)]
        probes: Option<u8>,
        /// bm25: the attribute carrying UTF8String text blobs
        #[arg(long)]
        text: Option<String>,
        /// bm25: how to cut the texts: word, bigram or code
        #[arg(long, default_value = "word")]
        tokenizer: String,
        /// path: the regular path expression over attribute ids. Juxtaposition
        /// is sequence, | alternation, * + ? repetition, ^ reverse, ( ) group:
        /// `A (^B | C)+ D?` with A..D as 32-hex-digit attribute ids.
        #[arg(long)]
        expr: Option<String>,
        /// Existing READ/WRITE-root signing key (default: beside the pile)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Search a maintained BM25 collection from the command line.
    ///
    /// Reads the collection's resident cover, merges its carriers, cuts the query
    /// with the tokenizer the descriptor names, and prints the best documents
    /// (entities of the source collection) with their BM25 scores. With
    /// --snippet, also prints the start of each hit's text, read from the
    /// source collection through the attribute the descriptor names. Needs
    /// the search feature.
    Search {
        /// Path to the pile file to read
        pile: PathBuf,
        /// BM25 collection: name, or descriptor handle
        collection: String,
        /// The query text
        query: String,
        /// How many hits to print
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Print the first characters of each hit's text
        #[arg(long)]
        snippet: bool,
    },
    /// Maintain selected collections, without maintaining their dependencies.
    ///
    /// Root collections roll up their admitted commits; derived collections
    /// fill missing images of available source members and roll up results.
    /// Readers can then use those merged members. Deterministic and
    /// idempotent: run again, it publishes nothing new. New equations are
    /// signed by the supplied durable key and admitted under target WRITE.
    /// Each target uses the immediate-source members already available. Use
    /// maintain-all to advance its source dependencies first. --watch keeps
    /// one pile open and retries after content or authorization changes.
    /// Target priority is stable for the author's public key, spreading first
    /// attempts across independent authors without changing the merge plan.
    /// Reference summaries require the complete producer-side blob closure.
    Maintain {
        /// Path to the pile file to modify
        pile: PathBuf,
        /// Explicit target names or descriptor handles; at least one is required
        #[arg(required = true, num_args = 1..)]
        collections: Vec<String>,
        /// Existing durable signing-key file (default: beside the pile)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Keep the pile open and maintain when its observed state changes
        #[arg(long)]
        watch: bool,
        /// Poll interval in milliseconds (positive; only used with --watch)
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
        interval_ms: u64,
        /// Raw Succinct execution backend; this does not reserve the device
        #[arg(long, value_enum, default_value_t = SuccinctBackend::Cpu)]
        succinct_backend: SuccinctBackend,
        #[command(flatten)]
        telemetry: maintenance_telemetry::Options,
    },
    /// Maintain selected targets and their source dependencies, upstream first.
    ///
    /// Shared dependencies run once per pass. Root fact collections are only
    /// ensured, unless explicitly selected as targets themselves. This is
    /// scheduling over ordinary one-edge operations; mappings and joins do not
    /// acquire recursive construction side effects. Only the requested targets
    /// and their descriptor source chains are selected, not historical indexes.
    /// The author's public key biases which selected chain runs first; each
    /// chain still runs upstream first, independently of argument order.
    MaintainAll {
        /// Path to the pile file to modify
        pile: PathBuf,
        /// Explicit target names or descriptor handles; at least one is required
        #[arg(required = true, num_args = 1..)]
        collections: Vec<String>,
        /// Existing durable signing-key file (default: beside the pile)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Keep the pile open and maintain when its observed state changes
        #[arg(long)]
        watch: bool,
        /// Poll interval in milliseconds (positive; only used with --watch)
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
        interval_ms: u64,
        /// Raw Succinct execution backend; this does not reserve the device
        #[arg(long, value_enum, default_value_t = SuccinctBackend::Cpu)]
        succinct_backend: SuccinctBackend,
        #[command(flatten)]
        telemetry: maintenance_telemetry::Options,
    },
    /// Grant one endpoint unbounded READ access to an existing collection.
    ///
    /// The signing key must be one of the collection descriptor's READ roots.
    /// One self-contained native proof record is stored, and repeating the
    /// exact command is idempotent.
    GrantRead {
        /// Path to the pile file to update.
        pile: PathBuf,
        /// Collection name, or descriptor handle. Use `name:` or `blake3:`
        /// to disambiguate a name that itself looks like a handle.
        collection: String,
        /// Recipient's Ed25519 public key (hex or z-base-32).
        recipient: String,
        /// READ-root signing key. Defaults to TRIBLESPACE_KEY or self.key
        /// beside the pile.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Grant one author unbounded WRITE access to an existing collection.
    ///
    /// The signing key must be one of the collection descriptor's WRITE roots.
    /// One self-contained native proof record is stored, and repeating the
    /// exact command is idempotent.
    GrantWrite {
        /// Path to the pile file to update.
        pile: PathBuf,
        /// Collection name, or descriptor handle. Use `name:` or `blake3:`
        /// to disambiguate a name that itself looks like a handle.
        collection: String,
        /// Recipient author's Ed25519 public key (hex or z-base-32).
        recipient: String,
        /// WRITE-root signing key. Defaults to TRIBLESPACE_KEY or self.key
        /// beside the pile.
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

/// The derivations this binary can register from the command line.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DeriveKind {
    /// SuccinctArchiveBlob over a SimpleArchive source
    Succinct,
    /// Rank9AcceleratedSuccinctArchiveBlob over a SuccinctArchiveBlob source
    Rank9,
    /// EntityIdSetBlob over one attribute's GenId values in a SimpleArchive source
    EntityIdSet,
    /// LatestBlob over a SimpleArchive source
    Latest,
    /// LwwRegisterBlob over a SimpleArchive source
    Lww,
    /// NvFp4CosineSet over f32 embeddings in a SimpleArchive source
    Nvfp4,
    /// Recursive blob-reference Bloom summary; maintain only with complete producer closure
    ReferenceSummary,
    /// PortableBM25Blob over UTF8String texts in a SimpleArchive source
    Bm25,
    /// PathSummaryBlob over a SimpleArchive source, for the regular path
    /// expression given as --expr
    Path,
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Init { pile, name, key } => run_init(pile, name, key),
        Command::List {
            path,
            named,
            metadata,
            long,
        } => run_list(path, named, metadata, long),
        Command::Show { pile, collection } => run_show(pile, collection),
        Command::Log {
            pile,
            collection,
            limit,
            long,
        } => run_log(pile, collection, limit, long),
        Command::Adopt {
            pile,
            from,
            into,
            key,
            dry_run,
        } => run_adopt(pile, from, into, key, dry_run),
        Command::Derive {
            pile,
            source,
            kind,
            observes,
            identity,
            orders,
            attribute,
            dimension,
            log2_bits,
            probes,
            text,
            tokenizer,
            expr,
            key,
        } => run_derive(
            pile,
            source,
            kind,
            DeriveArguments {
                observes,
                identity,
                orders,
                attribute,
                dimension,
                log2_bits,
                probes,
                text,
                tokenizer,
                expr,
            },
            key,
        ),
        Command::Search {
            pile,
            collection,
            query,
            top,
            snippet,
        } => run_search(pile, collection, query, top, snippet),
        Command::Maintain {
            pile,
            collections,
            key,
            watch,
            interval_ms,
            succinct_backend,
            telemetry,
        } => run_maintain(
            pile,
            collections,
            key,
            false,
            watch,
            interval_ms,
            succinct_backend,
            telemetry,
        ),
        Command::MaintainAll {
            pile,
            collections,
            key,
            watch,
            interval_ms,
            succinct_backend,
            telemetry,
        } => run_maintain(
            pile,
            collections,
            key,
            true,
            watch,
            interval_ms,
            succinct_backend,
            telemetry,
        ),
        Command::GrantRead {
            pile,
            collection,
            recipient,
            key,
        } => run_grant_read(pile, collection, recipient, key),
        Command::GrantWrite {
            pile,
            collection,
            recipient,
            key,
        } => run_grant_write(pile, collection, recipient, key),
    }
}

fn run_init(path: PathBuf, name: String, key: Option<PathBuf>) -> Result<()> {
    let key_path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &path);
    let root = triblespace_core::signing_key_file::load_existing(&key_path).map_err(|error| {
        anyhow!(
            "load collection-root signing key {}: {error}",
            key_path.display()
        )
    })?;

    let mut pile = open_refreshed(&path)?;
    let handle_res = pile
        .collection(
            &name,
            CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::direct(root.verifying_key()),
            ),
        )
        .map(|collection| collection.handle())
        .map_err(|error| anyhow!("register collection descriptor: {error}"));
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    let handle = handle_res.and_then(|handle| close_res.map(|()| handle))?;

    println!("blake3:{}", handle_hex(handle));
    Ok(())
}

/// Parse a collection handle, accepting both `blake3:HEX` and a bare `HEX`.
///
/// `pile blob inspect` rejects the bare form with `BadProtocol`. Collection
/// handles get copied out of record dumps and log lines in both shapes, so
/// this entry point normalizes rather than nitpicks.
fn parse_collection_handle(handle: &str) -> Result<CollectionHandle> {
    use triblespace::prelude::TryToInline;

    let trimmed = handle.trim();
    let owned;
    let normalized = if trimmed.contains(':') {
        trimmed
    } else {
        owned = format!("blake3:{trimmed}");
        owned.as_str()
    };
    let hash: Inline<Hash<Blake3>> = normalized.try_to_inline().map_err(|e| {
        anyhow!(
            "parse collection handle {handle:?}: {e:?} (expected `blake3:<64 hex>` or bare hex)"
        )
    })?;
    Ok(hash.into())
}

fn parse_recipient_key(value: &str) -> Result<VerifyingKey> {
    let value = value.trim();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| {
            anyhow!(
                "invalid recipient {value:?}: expected an Ed25519 public key in hex or z-base-32"
            )
        })?;
        return VerifyingKey::from_bytes(&bytes).map_err(|_| {
            anyhow!(
                "invalid recipient {value:?}: expected an Ed25519 public key in hex or z-base-32"
            )
        });
    }
    let endpoint = value.parse::<iroh_base::PublicKey>().map_err(|_| {
        anyhow!("invalid recipient {value:?}: expected an Ed25519 public key in hex or z-base-32")
    })?;
    Ok(VerifyingKey::from_bytes(endpoint.as_bytes())
        .expect("iroh public keys are validated Ed25519 points"))
}

fn handle_hex(handle: CollectionHandle) -> String {
    hex::encode(handle.raw)
}

fn abbrev(text: &str, long: bool) -> String {
    if long || text.len() <= ABBREV {
        text.to_owned()
    } else {
        format!("{}…", &text[..ABBREV])
    }
}

/// Resolve the blob-representation id against the schemas that actually
/// implement a collection kind. There is no id-keyed registry to consult, so
/// this asks each known `MetaDescribe` schema for its own id rather than
/// inventing a table of literals.
fn representation_name(id: Id) -> Option<&'static str> {
    if id == <SimpleArchive as MetaDescribe>::id() {
        Some("SimpleArchive")
    } else if id == <SuccinctArchiveBlob as MetaDescribe>::id() {
        Some("SuccinctArchiveBlob")
    } else if id == <Rank9AcceleratedSuccinctArchiveBlob as MetaDescribe>::id() {
        Some("Rank9AcceleratedSuccinctArchiveBlob")
    } else if id == <EntityIdSetBlob as MetaDescribe>::id() {
        Some("EntityIdSetBlob")
    } else if id == <triblespace_core::collection::latest::LatestBlob as MetaDescribe>::id() {
        Some("LatestBlob")
    } else if id
        == <triblespace_core::collection::lww_register::LwwRegisterBlob as MetaDescribe>::id()
    {
        Some("LwwRegisterBlob")
    } else if id == <ReferenceSummaryBlob as MetaDescribe>::id() {
        Some("ReferenceSummaryBlob")
    } else if id == <triblespace_paths::PathSummaryBlob as MetaDescribe>::id() {
        Some("PathSummaryBlob")
    } else if nvfp4_embedding_set_id().is_some_and(|nvfp4| id == nvfp4) {
        Some("NvFp4CosineSet<Embedding>")
    } else if bm25_carrier_id().is_some_and(|bm25| id == bm25) {
        Some("PortableBM25Blob")
    } else {
        None
    }
}

/// The representation id of the portable BM25 carrier, with the `search`
/// feature; `None` otherwise.
fn bm25_carrier_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(<triblespace_search::portable_bm25::PortableBM25Blob as MetaDescribe>::id())
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

/// The text-attribute-to-BM25 mapping id, under the same feature.
fn bm25_mapping_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(triblespace_search::text_bm25::TEXT_ATTRIBUTE_TO_BM25)
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

/// The representation id of the NVFP4 vector set over f32 embeddings, when
/// this binary was built with the `search` feature; `None` otherwise, so the
/// listing prints the bare id instead of a name it cannot stand behind.
fn nvfp4_embedding_set_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(<triblespace_search::nvfp4::NvFp4CosineSet<
            triblespace_search::schemas::Embedding,
        > as MetaDescribe>::id())
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

/// The NVFP4 mapping-algorithm id, under the same feature.
fn nvfp4_mapping_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(triblespace_search::nvfp4::EMBEDDING_ATTRIBUTE_TO_NVFP4)
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

/// Resolve a mapping-algorithm id against the algorithms declared in core.
fn mapping_algorithm_name(id: Id) -> Option<&'static str> {
    use triblespace_core::collection::latest::LATEST_STATES_MAPPING_V1;
    use triblespace_core::collection::lww_register::REGISTER_COORDINATES_MAPPING_V1;
    use triblespace_core::collection::succinctarchive_union::{
        RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE, RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE,
        RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE, RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE,
        SIMPLE_TO_SUCCINCT_MAPPING_V1,
    };

    if id == SIMPLE_TO_SUCCINCT_MAPPING_V1 {
        Some("SIMPLE_TO_SUCCINCT_MAPPING_V1")
    } else if id == REFERENCE_SUMMARY_MAPPING_V1 {
        Some("REFERENCE_SUMMARY_MAPPING_V1")
    } else if id == RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE {
        Some("RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE")
    } else if id == RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE {
        Some("RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE")
    } else if id == RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE {
        Some("RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE")
    } else if id == RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE {
        Some("RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE")
    } else if id == GENID_ATTRIBUTE_VALUES_MAPPING_V1 {
        Some("GENID_ATTRIBUTE_VALUES_MAPPING_V1")
    } else if id == LATEST_STATES_MAPPING_V1 {
        Some("LATEST_STATES_MAPPING_V1")
    } else if id == REGISTER_COORDINATES_MAPPING_V1 {
        Some("REGISTER_COORDINATES_MAPPING_V1")
    } else if id == triblespace_paths::REGULAR_PATH_MAPPING_V1 {
        Some("REGULAR_PATH_MAPPING_V1")
    } else if nvfp4_mapping_id().is_some_and(|nvfp4| id == nvfp4) {
        Some("EMBEDDING_ATTRIBUTE_TO_NVFP4")
    } else if semantic_mapping_id().is_some_and(|semantic| id == semantic) {
        Some("NOMIC_ATTRIBUTES_TO_NVFP4")
    } else if bm25_mapping_id().is_some_and(|bm25| id == bm25) {
        Some("TEXT_ATTRIBUTE_TO_BM25")
    } else {
        None
    }
}

fn semantic_mapping_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(triblespace_search::semantic::NOMIC_ATTRIBUTES_TO_NVFP4)
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

fn named_id(id: Id, name: Option<&'static str>) -> String {
    match name {
        Some(name) => format!("{id:X} ({name})"),
        None => format!("{id:X}"),
    }
}

/// The short column form: the schema's name if this binary implements it, and
/// the bare id if it does not. An unknown id is not an error — a descriptor
/// may name an encoding or mapping algorithm some other reader owns.
fn short_named_id(
    id: Result<Id, impl std::fmt::Debug>,
    name: fn(Id) -> Option<&'static str>,
) -> String {
    match id {
        Ok(id) => name(id)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{id:X}")),
        Err(_) => "<unreadable>".to_owned(),
    }
}

/// The short column form for an optional id. Root collections have no mapping,
/// while malformed descriptors remain visibly different from that valid
/// absence.
fn short_optional_id(id: Result<Option<Id>, impl std::fmt::Debug>, long: bool) -> String {
    match id {
        Ok(Some(id)) => abbrev(&format!("{id:X}"), long),
        Ok(None) => "-".to_owned(),
        Err(_) => "<unreadable>".to_owned(),
    }
}

/// The short column form for an optional id whose known values have names.
fn short_optional_named_id(
    id: Result<Option<Id>, impl std::fmt::Debug>,
    name: fn(Id) -> Option<&'static str>,
) -> String {
    match id {
        Ok(Some(id)) => name(id)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{id:X}")),
        Ok(None) => "-".to_owned(),
        Err(_) => "<unreadable>".to_owned(),
    }
}

/// Compact rendering of one action's immutable admission law.
fn policy_text(policy: &AdmissionPolicy, long: bool) -> String {
    match policy {
        AdmissionPolicy::Open => "open".to_owned(),
        AdmissionPolicy::Quorum(quorum) => {
            let roots = quorum
                .roots()
                .iter()
                .map(|root| abbrev(&hex::encode_upper(root.to_bytes()), long))
                .collect::<Vec<_>>()
                .join(",");
            let delegate = quorum
                .delegate_threshold()
                .map(|threshold| format!(" legacy-delegate={threshold}(ignored)"))
                .unwrap_or_default();
            format!(
                "{}/{} [{}]{delegate}",
                quorum.invoke_threshold(),
                quorum.roots().len(),
                roots,
            )
        }
    }
}

fn descriptor_policy_columns(facts: &TribleSet, long: bool) -> [String; 2] {
    match descriptor::policy(facts) {
        Ok(policy) => [
            policy_text(policy.read(), long),
            policy_text(policy.write(), long),
        ],
        Err(error) => {
            let invalid = format!("<invalid: {error}>");
            [invalid.clone(), invalid]
        }
    }
}

/// How many records of each kind name one collection.
#[derive(Default, Clone, Copy)]
struct Refs {
    commits: usize,
    merges: usize,
    /// Derives naming this collection as their source.
    derives_from: usize,
    /// Derives naming this collection as their target.
    derives_into: usize,
}

impl Refs {
    fn total(&self) -> usize {
        self.commits + self.merges + self.derives_from + self.derives_into
    }
}

/// Walk every collection record in the pile and tally which collections they
/// name. Merges and derives are included: a collection that only ever appears
/// as a derive target is still a collection this pile references.
fn referenced_collections(snapshot: &PileSnapshot) -> Result<BTreeMap<CollectionHandle, Refs>> {
    let mut refs: BTreeMap<CollectionHandle, Refs> = BTreeMap::new();
    let records = snapshot
        .records()
        .map_err(|e| anyhow!("enumerate collection records: {e:?}"))?;
    for record in records {
        let record = record.map_err(|e| anyhow!("decode collection record: {e:?}"))?;
        match record {
            CollectionRecord::Commit(commit) => {
                refs.entry(commit.collection()).or_default().commits += 1;
            }
            CollectionRecord::Merge(merge) => {
                refs.entry(merge.collection()).or_default().merges += 1;
            }
            CollectionRecord::Derive(derive) => {
                refs.entry(derive.collection()).or_default().derives_into += 1;
            }
        }
    }
    Ok(refs)
}

/// The descriptor facts, or why they could not be read.
enum Fields {
    Decoded {
        facts: TribleSet,
        name: Result<Option<String>, String>,
    },
    Missing,
    Undecodable(String),
}

impl Fields {
    fn load<R: BlobStoreGet>(reader: &R, handle: CollectionHandle) -> Self {
        let blob: Blob<SimpleArchive> = match reader.get(handle) {
            Ok(blob) => blob,
            Err(_) => return Fields::Missing,
        };
        match <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob) {
            Ok(facts) => {
                let name = match descriptor::name(&facts) {
                    Ok(Some(handle)) => reader
                        .get::<Blob<UTF8String>, UTF8String>(handle)
                        .map_err(|error| format!("read collection name attachment: {error}"))
                        .and_then(|name| {
                            std::str::from_utf8(&name.bytes)
                                .map(|name| Some(name.to_owned()))
                                .map_err(|error| {
                                    format!("decode collection name attachment: {error}")
                                })
                        }),
                    Ok(None) => Ok(None),
                    Err(error) => Err(error.to_string()),
                };
                Fields::Decoded { facts, name }
            }
            Err(e) => Fields::Undecodable(format!("{e:?}")),
        }
    }

    fn facts(&self) -> Option<&TribleSet> {
        match self {
            Fields::Decoded { facts, .. } => Some(facts),
            _ => None,
        }
    }
}

/// One collection the pile references: its identity, what its descriptor says,
/// and how many records name it.
///
/// The descriptor stays a bare `TribleSet` and is read with the same
/// `descriptor::*` queries the library uses. Nothing here caches a decoded
/// field beside it.
struct Enumerated {
    handle: CollectionHandle,
    refs: Refs,
    fields: Fields,
}

/// What a descriptor is anchored to. A root is named directly and a
/// derivation is anchored by the collection it derives from.
enum Anchor {
    Root(Result<String, String>),
    Derived(CollectionHandle),
    Unreadable(String),
}

fn anchor(fields: &Fields) -> Anchor {
    let (facts, loaded_name) = match fields {
        Fields::Decoded { facts, name } => (facts, name),
        Fields::Missing => return Anchor::Unreadable("descriptor blob not in pile".to_owned()),
        Fields::Undecodable(e) => {
            return Anchor::Unreadable(format!("descriptor undecodable: {e}"));
        }
    };
    match descriptor::source(facts) {
        Ok(Some(source)) => {
            if matches!(descriptor::name(facts), Ok(Some(_))) {
                return Anchor::Unreadable(
                    "descriptor carries both collection_name and collection_source".to_owned(),
                );
            }
            return Anchor::Derived(source);
        }
        Ok(None) => {}
        Err(error) => return Anchor::Unreadable(error.to_string()),
    }
    match loaded_name {
        Ok(Some(name)) => Anchor::Root(Ok(name.clone())),
        Ok(None) => Anchor::Unreadable(
            "descriptor carries neither collection_name nor collection_source".to_owned(),
        ),
        Err(error) => Anchor::Root(Err(error.clone())),
    }
}

/// Sort order for the listing: named roots by name, then derivations by
/// source, then everything with nothing to be called. Ties break on the
/// handle so a listing is stable across runs.
fn sort_key(row: &Enumerated) -> (u8, String, [u8; 32]) {
    match anchor(&row.fields) {
        Anchor::Root(Ok(name)) => (0, name, row.handle.raw),
        Anchor::Root(Err(_)) => (1, String::new(), row.handle.raw),
        Anchor::Derived(source) => (2, handle_hex(source), row.handle.raw),
        Anchor::Unreadable(_) => (3, String::new(), row.handle.raw),
    }
}

/// Every collection the pile references, descriptors decoded, in listing
/// order.
fn enumerate(snapshot: &PileSnapshot) -> Result<Vec<Enumerated>> {
    let refs = referenced_collections(snapshot)?;
    let mut rows: Vec<Enumerated> = refs
        .into_iter()
        .map(|(handle, refs)| Enumerated {
            handle,
            refs,
            fields: Fields::load(snapshot, handle),
        })
        .collect();
    rows.sort_by_key(sort_key);
    Ok(rows)
}

/// Resolve what an operator typed to a collection in this pile.
///
/// Explicit prefixes are authoritative. For an unprefixed reference, an exact
/// name wins unless it also parses as a different handle, in which case the
/// operator must disambiguate.
fn resolve(rows: &[Enumerated], reference: &str) -> Result<CollectionHandle> {
    let reference = reference.trim();
    if reference.starts_with("blake3:") {
        return parse_collection_handle(reference);
    }
    let (name, explicit_name) = match reference.strip_prefix("name:") {
        Some(name) => (name, true),
        None => (reference, false),
    };

    let matches: Vec<CollectionHandle> = rows
        .iter()
        .filter(|row| matches!(anchor(&row.fields), Anchor::Root(Ok(found)) if found == name))
        .map(|row| row.handle)
        .collect();

    if !explicit_name {
        if let Ok(handle) = parse_collection_handle(reference) {
            match matches.as_slice() {
                [] => return Ok(handle),
                [named] if *named == handle => return Ok(handle),
                _ => {
                    return Err(anyhow!(
                        "{reference:?} is both a collection name and a bare handle; use \
                         `name:{reference}` or `blake3:{reference}`"
                    ));
                }
            }
        }
    }

    match matches.as_slice() {
        [only] => Ok(*only),
        [] => {
            let known: Vec<String> = rows
                .iter()
                .filter_map(|row| match anchor(&row.fields) {
                    Anchor::Root(Ok(name)) => Some(name),
                    _ => None,
                })
                .collect();
            if known.is_empty() {
                Err(anyhow!(
                    "no collection named {name:?} in this pile; it references no named collections \
                     at all. `pile collection list` shows what it does reference"
                ))
            } else {
                Err(anyhow!(
                    "no collection named {name:?} in this pile; it has: {}",
                    known.join(", ")
                ))
            }
        }
        many => Err(anyhow!(
            "{} collections in this pile are named {name:?} under different policies. Pass one \
             of the handles instead:\n{}",
            many.len(),
            many.iter()
                .map(|handle| format!("  {}", handle_hex(*handle)))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

enum Align {
    Left,
    Right,
}

/// Print a table whose columns are exactly as wide as their widest cell.
fn print_table(headers: &[&str], aligns: &[Align], rows: &[Vec<String>], indent: &str) {
    if rows.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (column, cell) in row.iter().enumerate() {
            widths[column] = widths[column].max(cell.chars().count());
        }
    }
    let render = |cells: &[String]| {
        let mut line = String::from(indent);
        for (column, cell) in cells.iter().enumerate() {
            let last = column + 1 == cells.len();
            let pad = widths[column].saturating_sub(cell.chars().count());
            match aligns[column] {
                Align::Left => {
                    line.push_str(cell);
                    if !last {
                        line.push_str(&" ".repeat(pad));
                    }
                }
                Align::Right => {
                    line.push_str(&" ".repeat(pad));
                    line.push_str(cell);
                }
            }
            if !last {
                line.push_str("  ");
            }
        }
        line
    };
    let header_cells: Vec<String> = headers.iter().map(|header| header.to_string()).collect();
    println!("{}", render(&header_cells));
    for row in rows {
        println!("{}", render(row));
    }
}

fn format_timestamp(millis: u64) -> String {
    use chrono::{DateTime, Utc};
    use std::time::{Duration, UNIX_EPOCH};

    let dt = UNIX_EPOCH + Duration::from_millis(millis);
    DateTime::<Utc>::from(dt).to_rfc3339()
}

fn run_list(path: PathBuf, named_only: bool, metadata: bool, long: bool) -> Result<()> {
    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        let snapshot = pile
            .snapshot()
            .map_err(|e| anyhow!("pile snapshot: {e:?}"))?;
        let rows = enumerate(&snapshot)?;
        if rows.is_empty() {
            println!("(no collections referenced by pile {})", path.display());
            return Ok(());
        }
        // A row's trailing columns are the same question for every section, so
        // they are built once here.
        let tail = |row: &Enumerated| -> Vec<String> {
            let policies = row
                .fields
                .facts()
                .map(|facts| descriptor_policy_columns(facts, long))
                .unwrap_or_else(|| ["-".to_owned(), "-".to_owned()]);
            let mut cells = vec![
                row.refs.total().to_string(),
                abbrev(&handle_hex(row.handle), long),
                policies[0].clone(),
                policies[1].clone(),
                match row.fields.facts() {
                    Some(facts) => {
                        short_named_id(descriptor::representation(facts), representation_name)
                    }
                    None => "-".to_owned(),
                },
                match row.fields.facts() {
                    Some(facts) => short_optional_id(descriptor::mapping(facts), long),
                    None => "-".to_owned(),
                },
                match row.fields.facts() {
                    Some(facts) => short_optional_named_id(
                        descriptor::mapping_algorithm(facts),
                        mapping_algorithm_name,
                    ),
                    None => "-".to_owned(),
                },
            ];
            if metadata {
                match snapshot.metadata(row.handle) {
                    Ok(Some(meta)) => {
                        cells.push(meta.length.to_string());
                        cells.push(format_timestamp(meta.timestamp));
                    }
                    Ok(None) => {
                        cells.push("-".to_owned());
                        cells.push("absent".to_owned());
                    }
                    Err(e) => {
                        cells.push("-".to_owned());
                        cells.push(format!("metadata error ({e:?})"));
                    }
                }
            }
            cells
        };

        let mut named: Vec<Vec<String>> = Vec::new();
        let mut derived: Vec<Vec<String>> = Vec::new();
        let mut anchorless: Vec<(String, Vec<String>)> = Vec::new();
        for row in &rows {
            match anchor(&row.fields) {
                Anchor::Root(name) => {
                    let mut cells = vec![match &name {
                        Ok(name) => name.clone(),
                        Err(e) => format!("<invalid: {e}>"),
                    }];
                    cells.extend(tail(row));
                    named.push(cells);
                }
                Anchor::Derived(source) => {
                    let mut cells = vec![abbrev(&handle_hex(source), long)];
                    cells.extend(tail(row));
                    derived.push(cells);
                }
                Anchor::Unreadable(why) => {
                    anchorless.push((why, tail(row)));
                }
            }
        }

        // Name only the categories this pile actually has. "0 derived" is
        // noise in a summary whose job is to say what is here.
        let summary: Vec<String> = [
            (named.len(), "named"),
            (derived.len(), "derived"),
            (anchorless.len(), "without a readable anchor"),
        ]
        .into_iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, what)| format!("{count} {what}"))
        .collect();
        println!(
            "collections in {}: {} ({})",
            path.display(),
            rows.len(),
            summary.join(", ")
        );

        let mut tail_headers: Vec<&str> = vec![
            "RECORDS",
            "COLLECTION",
            "READ",
            "WRITE",
            "REPRESENTATION",
            "MAPPING",
            "ALGORITHM",
        ];
        let mut tail_aligns = vec![
            Align::Right,
            Align::Left,
            Align::Left,
            Align::Left,
            Align::Left,
            Align::Left,
            Align::Left,
        ];
        if metadata {
            tail_headers.extend(["BYTES", "STORED"]);
            tail_aligns.extend([Align::Right, Align::Left]);
        }

        if !named.is_empty() {
            println!();
            let mut headers = vec!["NAME"];
            headers.extend(tail_headers.iter().copied());
            let mut aligns = vec![Align::Left];
            aligns.extend(tail_aligns.iter().map(|align| match align {
                Align::Left => Align::Left,
                Align::Right => Align::Right,
            }));
            print_table(&headers, &aligns, &named, "  ");
        }

        if named_only {
            let hidden: Vec<String> = [(derived.len(), "derived"), (anchorless.len(), "unnamed")]
                .into_iter()
                .filter(|(count, _)| *count > 0)
                .map(|(count, what)| format!("{count} {what}"))
                .collect();
            if !hidden.is_empty() {
                println!();
                println!("  ({} hidden by --named)", hidden.join(", "));
            }
            return Ok(());
        }

        if !derived.is_empty() {
            println!();
            println!("derived from another collection:");
            let mut headers = vec!["SOURCE"];
            headers.extend(tail_headers.iter().copied());
            let mut aligns = vec![Align::Left];
            aligns.extend(tail_aligns.iter().map(|align| match align {
                Align::Left => Align::Left,
                Align::Right => Align::Right,
            }));
            print_table(&headers, &aligns, &derived, "  ");
        }

        if !anchorless.is_empty() {
            println!();
            println!("without a name:");
            // The note column earns its width only if some row has a note;
            // otherwise every cell would repeat the heading.
            let noted = anchorless.iter().any(|(note, _)| !note.is_empty());
            let mut headers: Vec<&str> = Vec::new();
            let mut aligns: Vec<Align> = Vec::new();
            if noted {
                headers.push("NOTE");
                aligns.push(Align::Left);
            }
            headers.extend(tail_headers.iter().copied());
            aligns.extend(tail_aligns.iter().map(|align| match align {
                Align::Left => Align::Left,
                Align::Right => Align::Right,
            }));
            let rows: Vec<Vec<String>> = anchorless
                .into_iter()
                .map(|(note, cells)| {
                    if noted {
                        std::iter::once(note).chain(cells).collect()
                    } else {
                        cells
                    }
                })
                .collect();
            print_table(&headers, &aligns, &rows, "  ");
        }

        Ok(())
    })();
    let close_res = pile.close().map_err(|e| anyhow!("pile close: {e:?}"));
    res.and(close_res)
}

fn run_grant_read(
    path: PathBuf,
    reference: String,
    recipient: String,
    key: Option<PathBuf>,
) -> Result<()> {
    run_grant(path, reference, recipient, key, GrantAction::Read)
}

fn run_grant_write(
    path: PathBuf,
    reference: String,
    recipient: String,
    key: Option<PathBuf>,
) -> Result<()> {
    run_grant(path, reference, recipient, key, GrantAction::Write)
}

#[derive(Clone, Copy)]
enum GrantAction {
    Read,
    Write,
}

impl GrantAction {
    const fn label(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

fn run_grant(
    path: PathBuf,
    reference: String,
    recipient: String,
    key: Option<PathBuf>,
    action: GrantAction,
) -> Result<()> {
    let recipient = parse_recipient_key(&recipient)?;
    let key_path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &path);
    let root = triblespace_core::signing_key_file::load_existing(&key_path).map_err(|error| {
        anyhow!(
            "load {}-root signing key {}: {error}",
            action.label(),
            key_path.display()
        )
    })?;

    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        let rows = enumerate(&snapshot)?;
        let collection = resolve(&rows, &reference)?;
        drop(snapshot);

        let proof = match action {
            GrantAction::Read => grant_collection_read(&mut pile, collection, &root, recipient),
            GrantAction::Write => grant_collection_write(&mut pile, collection, &root, recipient),
        }
        .map_err(|error| anyhow!("grant collection {}: {error}", action.label()))?;
        println!("collection: blake3:{}", handle_hex(collection));
        println!(
            "root:       {}",
            hex::encode_upper(root.verifying_key().to_bytes())
        );
        println!("recipient:  {}", hex::encode(recipient.to_bytes()));
        println!("proof:      blake3:{}", hex::encode(proof.id().raw));
        Ok(())
    })();
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close_res)
}

fn run_adopt(
    path: PathBuf,
    from: String,
    into: String,
    key: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let key_path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &path);
    let signer = triblespace_core::signing_key_file::load_existing(&key_path)
        .map_err(|error| anyhow!("load adopting signing key {}: {error}", key_path.display()))?;

    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        // One frozen view chooses both collections and every commit adopted;
        // a concurrent append cannot change what this run means.
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        let rows = enumerate(&snapshot)?;
        let source = resolve(&rows, &from)?;
        let target = resolve(&rows, &into)?;
        if source == target {
            return Err(anyhow!("source and target are the same collection"));
        }
        let target_collection: Collection<SimpleArchive> = Collection::open(&snapshot, target)
            .map_err(|error| anyhow!("open target collection descriptor: {error}"))?;

        // Prepare everything before appending anything: every source commit
        // verified, its exact data and metadata decoded. Re-wrapping canonical
        // fact sets mints nothing; `commit` serializes them back to the same
        // data and metadata handles while signing the native record.
        let empty_metadata: Blob<SimpleArchive> = TribleSet::new().to_blob();
        let mut prepared: Vec<(CollectionRecord, Fragment)> = Vec::new();
        let mut invalid = 0usize;
        let records = snapshot
            .records()
            .map_err(|error| anyhow!("enumerate collection records: {error:?}"))?;
        for record in records {
            let record = record.map_err(|error| anyhow!("decode collection record: {error:?}"))?;
            let CollectionRecord::Commit(commit) = &record else {
                continue;
            };
            if commit.collection() != source {
                continue;
            }
            if let Err(error) = commit.verify_strict() {
                eprintln!(
                    "skipping commit {:X}: invalid signature ({error})",
                    record.fingerprint()
                );
                invalid += 1;
                continue;
            }
            // A commit names its member by bare content hash; the member of a
            // SimpleArchive collection is a SimpleArchive.
            let data_handle: Inline<Handle<SimpleArchive>> = Inline::new(commit.data().raw);
            let data: Blob<SimpleArchive> = snapshot.get(data_handle).map_err(|error| {
                anyhow!(
                    "read commit data {}: {error}",
                    hex::encode(commit.data().raw)
                )
            })?;
            let metadata: Blob<SimpleArchive> = match snapshot.get(commit.metadata()) {
                Ok(blob) => blob,
                Err(error) => {
                    if commit.metadata() == empty_metadata.get_handle() {
                        empty_metadata.clone()
                    } else {
                        return Err(anyhow!(
                            "read commit metadata {}: {error}",
                            hex::encode(commit.metadata().raw)
                        ));
                    }
                }
            };
            let facts = TribleSet::try_from_blob(data)
                .map_err(|error| anyhow!("decode commit data: {error:?}"))?;
            let metafacts = TribleSet::try_from_blob(metadata)
                .map_err(|error| anyhow!("decode commit metadata: {error:?}"))?;
            prepared.push((
                record,
                Fragment::from_parts(facts, metafacts, Default::default()),
            ));
        }
        drop(snapshot);

        println!("source: blake3:{}", handle_hex(source));
        println!("target: blake3:{}", handle_hex(target));
        println!(
            "signer: {}",
            hex::encode_upper(signer.verifying_key().to_bytes())
        );
        println!(
            "commits: {} to adopt, {} skipped as invalid",
            prepared.len(),
            invalid
        );
        if dry_run {
            println!("dry run: nothing appended");
            return Ok(());
        }
        let mut adopted = std::collections::BTreeSet::new();
        for (record, fragment) in prepared {
            let commit = pile
                .commit(target_collection, &signer, fragment)
                .map_err(|error| anyhow!("adopt commit {:X}: {error}", record.fingerprint()))?;
            adopted.insert(commit.data().raw);
        }
        println!(
            "adopted: {} distinct data archive(s) now asserted in the target",
            adopted.len()
        );
        Ok(())
    })();
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close_res)
}

fn run_show(path: PathBuf, reference: String) -> Result<()> {
    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        let snapshot = pile
            .snapshot()
            .map_err(|e| anyhow!("pile snapshot: {e:?}"))?;
        let rows = enumerate(&snapshot)?;
        let handle = resolve(&rows, &reference)?;
        let blob: Blob<SimpleArchive> = snapshot
            .get(handle)
            .map_err(|e| anyhow!("read descriptor blob {}: {e:?}", handle_hex(handle)))?;

        println!("collection: blake3:{}", handle_hex(handle));
        if let Ok(Some(meta)) = snapshot.metadata(handle) {
            println!(
                "descriptor blob: {} bytes, stored {}",
                meta.length,
                format_timestamp(meta.timestamp)
            );
        } else {
            println!("descriptor blob: {} bytes", blob.bytes.len());
        }

        let descriptor = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob.clone())
            .map_err(|e| anyhow!("decode collection descriptor: {e:?}"))?;
        println!("entity id:      {:X}", descriptor::entity(&descriptor)?);
        let fields = Fields::load(&snapshot, handle);
        match anchor(&fields) {
            Anchor::Root(Ok(name)) => println!("name:           {name}"),
            Anchor::Root(Err(e)) => println!("name:           <invalid: {e}>"),
            Anchor::Derived(source) => {
                println!("source:         {}", handle_hex(source));
            }
            Anchor::Unreadable(why) => println!("anchor:         <{why}>"),
        }
        match descriptor::policy(&descriptor) {
            Ok(policy) => {
                println!("read policy:    {}", policy_text(policy.read(), true));
                println!("write policy:   {}", policy_text(policy.write(), true));
            }
            Err(error) => {
                println!("read policy:    <invalid: {error}>");
                println!("write policy:   <invalid: {error}>");
            }
        }
        println!(
            "representation: {}",
            named_id(
                descriptor::representation(&descriptor)?,
                representation_name(descriptor::representation(&descriptor)?)
            )
        );
        match descriptor::mapping(&descriptor)? {
            Some(mapping) => println!("mapping:        {mapping:X}"),
            None => println!("mapping:        <none>"),
        }
        match descriptor::mapping_algorithm(&descriptor)? {
            Some(algorithm) => println!(
                "mapping algo:   {}",
                named_id(algorithm, mapping_algorithm_name(algorithm))
            ),
            None => println!("mapping algo:   <none>"),
        }

        let facts: TribleSet = snapshot
            .get::<TribleSet, SimpleArchive>(handle)
            .map_err(|e| anyhow!("unarchive descriptor: {e:?}"))?;
        println!("tribles:        {}", facts.len());
        for trible in facts.iter() {
            println!(
                "  {:X} {:X} {}",
                trible.e(),
                trible.a(),
                hex::encode_upper(&trible.data[32..64])
            );
        }

        let counts = rows
            .iter()
            .find(|row| row.handle == handle)
            .map(|row| row.refs)
            .unwrap_or_default();
        println!(
            "records:        {} (commits={} merges={} derives-from={} derives-into={})",
            counts.total(),
            counts.commits,
            counts.merges,
            counts.derives_from,
            counts.derives_into,
        );
        Ok(())
    })();
    let close_res = pile.close().map_err(|e| anyhow!("pile close: {e:?}"));
    res.and(close_res)
}

/// Does this record name that collection?
///
/// A commit and a merge name the collection they are of; a derive names the
/// collection it produces. This is the same question `referenced_collections`
/// tallies, asked one record at a time.
fn names_collection(record: &CollectionRecord, collection: CollectionHandle) -> bool {
    match record {
        CollectionRecord::Commit(commit) => commit.collection() == collection,
        CollectionRecord::Merge(merge) => merge.collection() == collection,
        CollectionRecord::Derive(derive) => derive.collection() == collection,
    }
}

fn run_log(path: PathBuf, reference: String, limit: usize, long: bool) -> Result<()> {
    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        let snapshot = pile
            .snapshot()
            .map_err(|e| anyhow!("pile snapshot: {e:?}"))?;
        let rows = enumerate(&snapshot)?;
        let handle = resolve(&rows, &reference)?;
        let row = rows
            .iter()
            .find(|row| row.handle == handle)
            .ok_or_else(|| {
                anyhow!(
                    "no record in this pile names collection {}",
                    handle_hex(handle)
                )
            })?;

        print!("collection: blake3:{}", handle_hex(handle));
        match anchor(&row.fields) {
            Anchor::Root(Ok(name)) => print!("  ({name})"),
            Anchor::Derived(source) => print!("  (derived from {})", handle_hex(source)),
            _ => {}
        }
        println!();
        println!(
            "records: {} (commits={} merges={} derives-from={} derives-into={})",
            row.refs.total(),
            row.refs.commits,
            row.refs.merges,
            row.refs.derives_from,
            row.refs.derives_into,
        );
        println!();

        let short = |bytes: [u8; 32]| abbrev(&hex::encode(bytes), long);
        let mut printed = 0usize;
        let mut skipped = 0usize;
        let records = snapshot
            .records()
            .map_err(|e| anyhow!("enumerate collection records: {e:?}"))?;
        for record in records {
            let record = record.map_err(|e| anyhow!("decode collection record: {e:?}"))?;
            if !names_collection(&record, handle) {
                continue;
            }
            if limit != 0 && printed == limit {
                skipped += 1;
                continue;
            }
            printed += 1;
            let fingerprint = record.fingerprint();
            let signature = match record.verify_strict() {
                Ok(()) => "ok".to_owned(),
                Err(error) => format!("INVALID ({error})"),
            };
            let signer = abbrev(&hex::encode_upper(record.public_key().raw), long);
            match record {
                CollectionRecord::Commit(commit) => {
                    println!(
                        "commit  {:X}  data={}  meta={}  signer={signer}  signature={signature}",
                        fingerprint,
                        short(commit.data().raw),
                        short(commit.metadata().raw),
                    );
                }
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    let (low_witness, high_witness) = merge.input_witnesses();
                    println!(
                        "merge   {:X}  low={}  high={}  result={}  low_witness={}  high_witness={}  signer={signer}  signature={signature}",
                        fingerprint,
                        short(low.raw),
                        short(high.raw),
                        short(merge.result().raw),
                        short(low_witness.raw()),
                        short(high_witness.raw()),
                    );
                }
                CollectionRecord::Derive(derive) => {
                    let (input, output) = (derive.input(), derive.output());
                    println!(
                        "derive  {:X}  input={}  output={}  input_witness={}  signer={signer}  signature={signature}",
                        fingerprint,
                        short(input.raw),
                        short(output.raw),
                        short(derive.input_witness().raw()),
                    );
                }
            }
        }
        if skipped > 0 {
            println!();
            println!("… {skipped} more (pass --limit 0 for all of them)");
        }
        Ok(())
    })();
    let close_res = pile.close().map_err(|e| anyhow!("pile close: {e:?}"));
    res.and(close_res)
}

/// Every collection a set of records names, without the descriptor lookups.
/// Exposed for tests that want the enumeration independent of blob presence.
#[cfg(test)]
fn referenced_ids(records: &[CollectionRecord]) -> std::collections::BTreeSet<CollectionHandle> {
    let mut out = std::collections::BTreeSet::new();
    for record in records {
        match record {
            CollectionRecord::Commit(commit) => {
                out.insert(commit.collection());
            }
            CollectionRecord::Merge(merge) => {
                out.insert(merge.collection());
            }
            CollectionRecord::Derive(derive) => {
                out.insert(derive.collection());
            }
        }
    }
    out
}
#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    fn witnessed(
        signer: &ed25519_dalek::SigningKey,
        collection: triblespace_core::collection::CollectionHandle,
        data: triblespace_core::collection::CollectionData,
    ) -> (
        triblespace_core::collection::CollectionData,
        triblespace_core::collection::CollectionRecordFingerprint,
    ) {
        let record = triblespace_core::collection::CollectionCommit::sign(
            signer,
            collection,
            data,
            triblespace_core::collection::empty_metadata_handle(),
        );
        (data, record.fingerprint())
    }

    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::succinctarchive_union::SIMPLE_TO_SUCCINCT_MAPPING_V1;
    use triblespace_core::collection::{CollectionPolicy, CollectionStore, CollectionStoreExt};
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStoreList, BlobStorePut};

    #[test]
    fn maintenance_catches_arrivals_during_a_pass_without_self_sustaining_work() {
        let mut store = MemoryRepo::default();
        let before = store.snapshot().unwrap();
        let observed = ObservedStore::new(before.clone());
        let requested: Blob<UTF8String> = "arrived while maintenance ran".to_blob();
        assert!(observed
            .get::<Blob<UTF8String>, _>(requested.get_handle())
            .is_err());
        store.put::<UTF8String, _>(requested).unwrap();
        let interests = observed.dependencies();
        let after = store.snapshot().unwrap();
        let catch_up = maintenance_changed(&before, &after, &interests);
        assert!(
            catch_up,
            "post-work baseline must not swallow an in-flight append"
        );

        // The next poll has the post-work baseline, so only the retained dirty
        // bit requests its bounded catch-up pass. With no further arrivals or
        // writes that pass clears the bit instead of becoming an idle loop.
        let poll = store.snapshot().unwrap();
        assert!(!maintenance_changed(&after, &poll, &interests));
        assert!(catch_up || maintenance_changed(&after, &poll, &interests));
        let after_catch_up = store.snapshot().unwrap();
        assert!(!maintenance_changed(&poll, &after_catch_up, &interests));
    }

    #[test]
    fn maintenance_ignores_repeated_observations_without_content_changes() {
        let mut store = MemoryRepo::default();
        let previous = store.snapshot().unwrap();
        let interests = StoreDependencies {
            all_blobs: true,
            all_records: true,
            capability_proofs: true,
            ..StoreDependencies::default()
        };

        for _ in 0..3 {
            let sampled = store.snapshot().unwrap();
            assert!(!maintenance_changed(&previous, &sampled, &interests));
        }
    }

    fn observed_maintenance_pass(
        pile: &mut Pile,
        targets: &[CollectionHandle],
        signer: &SigningKey,
        calls: &mut usize,
    ) -> (usize, StoreDependencies) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let references = targets
            .iter()
            .map(|handle| format!("blake3:{}", handle_hex(*handle)))
            .collect::<Vec<_>>();
        let mut observed = ObservedStore::new(pile);
        *calls += 1;
        let failures = runtime
            .block_on(maintenance_pass(
                &mut observed,
                &references,
                signer,
                true,
                SuccinctBackend::Cpu,
                &mut MaintenanceState::default(),
            ))
            .unwrap();
        (failures, observed.dependencies())
    }

    #[test]
    fn maintenance_read_set_ignores_unrelated_arrivals_but_tracks_source_and_cold_blobs() {
        use triblespace_core::capability::{CapabilityProof, CapabilityResource};
        use triblespace_core::collection::{
            empty_metadata_handle, read_capability, CollectionCommit, CollectionSnapshotExt,
        };
        use triblespace_core::macros::entity;
        use triblespace_core::repo::{CapabilityProofStore, WantRead, WantRequest, WantStore};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scoped-maintenance.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let mut writer = Pile::open(&path).unwrap();
        let signer = SigningKey::from_bytes(&[61; 32]);
        let policy = direct_policy(signer.verifying_key());
        let source = pile.collection("scoped source", policy.clone()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let target = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy.clone())
            .unwrap();
        let other = pile.collection("unrelated source", policy).unwrap();
        for text in ["first scoped member", "second scoped member"] {
            pile.commit(source, &signer, entity! { metadata::description: text })
                .unwrap();
        }
        let selected = [target.handle()];
        let mut calls = 0;
        let before = pile.snapshot().unwrap();
        let (failures, first_interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert_eq!(failures, 0);
        let after = pile.snapshot().unwrap();
        assert!(
            maintenance_changed(&before, &after, &first_interests),
            "own publication requests one catch-up"
        );
        let (failures, interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert_eq!(failures, 0);
        let settled = pile.snapshot().unwrap();
        assert!(!maintenance_changed(&after, &settled, &interests));
        assert_eq!(calls, 2);
        assert!(
            !interests.all_records && !interests.all_blobs,
            "exact selection and census stay scoped"
        );
        for handle in [source.handle(), succinct.handle(), target.handle()] {
            assert!(interests
                .records
                .contains(&CollectionRecordSelector::Collection(handle)));
            assert!(interests
                .blobs
                .contains(&Handle::<SimpleArchive>::to_hash(handle)));
        }

        writer.put::<UTF8String, _>("unrelated payload").unwrap();
        let requested: Blob<UTF8String> = "unrelated request".to_blob();
        writer
            .want(WantRequest::blob(requested.get_handle()))
            .unwrap();
        writer
            .commit(
                other,
                &signer,
                entity! { metadata::description: "unrelated record" },
            )
            .unwrap();
        let unrelated = pile.snapshot().unwrap();
        assert!(!unrelated.changes_since(&settled).is_empty());
        if maintenance_changed(&settled, &unrelated, &interests) {
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        }
        assert_eq!(
            calls, 2,
            "no maintenance call for unrelated blob, WANT or record"
        );

        // Proof lookup is still component-wide, deliberately. A proof-only
        // arrival retries once even when it concerns a different resource.
        assert!(interests.capability_proofs);
        writer
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(other.handle()),
                &signer,
                read_capability(),
                SigningKey::from_bytes(&[65; 32]).verifying_key(),
            ))
            .unwrap();
        let proof_arrived = pile.snapshot().unwrap();
        assert!(maintenance_changed(&unrelated, &proof_arrived, &interests));
        let (failures, interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert_eq!(failures, 0);
        assert_eq!(calls, 3);
        assert!(!maintenance_changed(
            &proof_arrived,
            &pile.snapshot().unwrap(),
            &interests
        ));

        let cold: Blob<SimpleArchive> = entity! { metadata::description: "new cold source member" }
            .facts()
            .clone()
            .to_blob();
        writer
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                source.handle(),
                Handle::<SimpleArchive>::to_hash(cold.get_handle()),
                empty_metadata_handle(),
            )))
            .unwrap();
        let source_arrived = pile.snapshot().unwrap();
        assert!(maintenance_changed(
            &proof_arrived,
            &source_arrived,
            &interests
        ));
        let (failures, cold_interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert!(
            failures > 0,
            "cold foundational input is still an explicit error"
        );
        assert_eq!(calls, 4);
        assert!(cold_interests
            .blobs
            .contains(&Handle::<SimpleArchive>::to_hash(cold.get_handle())));
        let absent = pile.snapshot().unwrap();
        assert!(!absent.contains_blob(cold.get_handle()).unwrap());
        assert_eq!(
            absent.collection(target).unwrap().support().unwrap().len(),
            2
        );
        let wants_before = absent.wants().unwrap().count();
        assert_eq!(wants_before, 1, "maintenance did not manufacture a WANT");
        assert!(!maintenance_changed(
            &absent,
            &pile.snapshot().unwrap(),
            &cold_interests
        ));

        writer.put::<SimpleArchive, _>(cold).unwrap();
        let resident = pile.snapshot().unwrap();
        assert!(
            maintenance_changed(&absent, &resident, &cold_interests),
            "blob-only arrival retries the failed input"
        );
        let (failures, complete_interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert_eq!(failures, 0);
        let complete = pile.snapshot().unwrap();
        assert_eq!(
            complete
                .collection(target)
                .unwrap()
                .support()
                .unwrap()
                .len(),
            3
        );
        assert!(maintenance_changed(
            &resident,
            &complete,
            &complete_interests
        ));
        let (failures, settled_interests) =
            observed_maintenance_pass(&mut pile, &selected, &signer, &mut calls);
        assert_eq!(failures, 0);
        assert!(!maintenance_changed(
            &complete,
            &pile.snapshot().unwrap(),
            &settled_interests
        ));
        assert_eq!(calls, 6, "one retry and one bounded self-write catch-up");
        writer.close().unwrap();
        pile.close().unwrap();
    }

    #[test]
    fn maintenance_errors_keep_missing_descriptors_and_grant_definitions_as_interests() {
        use triblespace_core::capability::{
            capability_action, CapabilityProof, CapabilityResource,
        };
        use triblespace_core::collection::{CollectionSnapshotExt, ACTION_WRITE};
        use triblespace_core::macros::entity;
        use triblespace_core::repo::CapabilityProofStore;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scoped-authority.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let root = SigningKey::from_bytes(&[62; 32]);
        let signer = SigningKey::from_bytes(&[63; 32]);
        let policy = direct_policy(root.verifying_key());
        let source = pile.collection("delegated source", policy.clone()).unwrap();
        let target = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        pile.commit(
            source,
            &root,
            entity! { metadata::description: "delegated member" },
        )
        .unwrap();
        let definition: Blob<SimpleArchive> = entity! {
            capability_action: ACTION_WRITE,
            metadata::description: "scoped maintenance test grant",
        }
        .facts()
        .clone()
        .to_blob();
        pile.insert_proof(CapabilityProof::new(
            CapabilityResource::from(target.handle()),
            &root,
            definition.get_handle(),
            signer.verifying_key(),
        ))
        .unwrap();

        let mut elsewhere = MemoryRepo::default();
        let late = elsewhere
            .collection("late selected descriptor", policy)
            .unwrap();
        let late_blob: Blob<SimpleArchive> =
            elsewhere.snapshot().unwrap().get(late.handle()).unwrap();
        let targets = [target.handle(), late.handle()];
        let mut calls = 0;
        let (failures, interests) =
            observed_maintenance_pass(&mut pile, &targets, &signer, &mut calls);
        assert_eq!(
            failures, 2,
            "missing descriptor and unavailable target WRITE are independent failures"
        );
        assert!(interests.capability_proofs);
        for handle in [late.handle(), definition.get_handle()] {
            assert!(interests
                .blobs
                .contains(&Handle::<SimpleArchive>::to_hash(handle)));
        }
        assert!(!interests.all_records && !interests.all_blobs);
        let failed = pile.snapshot().unwrap();
        assert!(failed.collection(target).unwrap().cover().is_empty());
        pile.put::<UTF8String, _>("unrelated between failures")
            .unwrap();
        let unrelated = pile.snapshot().unwrap();
        assert!(!maintenance_changed(&failed, &unrelated, &interests));
        pile.put::<SimpleArchive, _>(definition).unwrap();
        pile.put::<SimpleArchive, _>(late_blob).unwrap();
        let available = pile.snapshot().unwrap();
        assert!(maintenance_changed(&unrelated, &available, &interests));
        let (failures, settled_interests) =
            observed_maintenance_pass(&mut pile, &targets, &signer, &mut calls);
        assert_eq!(failures, 0);
        let complete = pile.snapshot().unwrap();
        assert_eq!(
            complete
                .collection(target)
                .unwrap()
                .support()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(calls, 2);
        assert!(maintenance_changed(
            &available,
            &complete,
            &settled_interests
        ));
        pile.close().unwrap();
    }

    #[test]
    fn maintenance_name_lookup_remains_a_real_global_record_interest() {
        use triblespace_core::macros::entity;

        let mut pile = MemoryRepo::default();
        let signer = SigningKey::from_bytes(&[64; 32]);
        let source = pile
            .collection(
                "named maintenance target",
                direct_policy(signer.verifying_key()),
            )
            .unwrap();
        pile.commit(
            source,
            &signer,
            entity! { metadata::description: "named member" },
        )
        .unwrap();
        let snapshot = pile.snapshot().unwrap();
        let exact = ObservedStore::new(snapshot.clone());
        assert_eq!(
            resolve_maintenance_target(&exact, &format!("blake3:{}", handle_hex(source.handle())))
                .unwrap(),
            source.handle()
        );
        assert!(
            exact.dependencies().is_empty(),
            "an explicit handle needs no name inventory"
        );
        let named = ObservedStore::new(snapshot);
        assert_eq!(
            resolve_maintenance_target(&named, "name:named maintenance target").unwrap(),
            source.handle()
        );
        assert!(named.dependencies().all_records);
        assert!(!named.dependencies().all_blobs);
    }

    fn direct_policy(root: ed25519_dalek::VerifyingKey) -> CollectionPolicy {
        CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
    }

    /// A descriptor built in-process must round-trip through exactly the path
    /// `show` uses: store the blob, address it by its own handle, read it back
    /// as a `Blob<SimpleArchive>`, and decode. This pins the identity rule the
    /// whole subcommand rests on — the collection id is the hash of the
    /// descriptor blob, never the entity id inside it.
    #[test]
    fn show_decodes_a_descriptor_addressed_by_its_blob_handle() {
        let authority = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let representation = <SimpleArchive as MetaDescribe>::id();
        let policy = direct_policy(authority);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection("inspected", policy.clone())
            .expect("register collection");
        let handle = collection.handle();
        let snapshot = store.snapshot().expect("snapshot");
        let blob: Blob<SimpleArchive> = snapshot.get(handle).expect("read descriptor blob");
        let decoded = <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(blob.clone())
            .expect("decode descriptor");
        let entity_id = descriptor::entity(&decoded).expect("descriptor entity");
        assert_ne!(
            handle.raw[..16],
            <[u8; 16]>::from(entity_id)[..],
            "identity is the blob hash, not the intrinsic entity id"
        );

        let expected_name: Inline<triblespace_core::inline::encodings::hash::Handle<UTF8String>> =
            "inspected".to_owned().to_blob().get_handle();
        assert_eq!(descriptor::name(&decoded).unwrap().unwrap(), expected_name);
        assert_eq!(descriptor::policy(&decoded).unwrap(), policy);
        assert_eq!(
            descriptor::representation(&decoded).unwrap(),
            representation
        );
        assert_eq!(descriptor::mapping(&decoded).unwrap(), None);
        assert_eq!(descriptor::mapping_algorithm(&decoded).unwrap(), None);
        assert_eq!(descriptor::entity(&decoded).unwrap(), entity_id);

        // The trible dump `show` prints comes from the same bytes.
        let facts: TribleSet = snapshot
            .get::<TribleSet, SimpleArchive>(handle)
            .expect("unarchive descriptor");
        assert_eq!(blob.bytes.len(), facts.len() * 64);
        let entities: BTreeSet<Id> = facts.iter().map(|t| *t.e()).collect();
        assert!(
            entities.contains(&entity_id),
            "descriptor entity remains directly queryable among embedded policy descriptions"
        );
        assert!(entities.len() > 1, "policy entities are self-contained");

        assert!(matches!(
            anchor(&Fields::load(&snapshot, handle)),
            Anchor::Root(Ok(name)) if name == "inspected"
        ));
    }

    /// `show` must accept the handle in both shapes; `blob inspect` rejects
    /// the bare form with `BadProtocol`.
    #[test]
    fn handles_parse_with_and_without_the_blake3_prefix() {
        let hex = "1c1362fbde47aacdfe3ec872a61b5ff270ef57c30f97ef36511adb1e3536edd2";
        let prefixed = parse_collection_handle(&format!("blake3:{hex}")).expect("prefixed");
        let bare = parse_collection_handle(hex).expect("bare");
        let padded = parse_collection_handle(&format!("  {hex}\n")).expect("padded");
        assert_eq!(prefixed, bare);
        assert_eq!(prefixed, padded);
        assert_eq!(handle_hex(prefixed), hex);

        assert!(parse_collection_handle("sha256:00").is_err());
        assert!(parse_collection_handle("not-hex").is_err());
    }

    #[test]
    fn recipient_key_accepts_iroh_and_signing_key_init_spellings() {
        let expected = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let endpoint = iroh_base::PublicKey::from_bytes(&expected.to_bytes()).unwrap();

        assert_eq!(
            parse_recipient_key(&endpoint.to_string()).unwrap(),
            expected
        );
        assert_eq!(
            parse_recipient_key(&hex::encode_upper(expected.to_bytes())).unwrap(),
            expected
        );
        assert!(parse_recipient_key("not-an-endpoint").is_err());
    }

    /// Enumeration must see collections named by merges and by *both* sides
    /// of a derive, not just commit targets.
    #[test]
    fn enumeration_covers_merges_and_derive_targets() {
        use triblespace_core::collection::records::{CollectionDerive, CollectionMerge};

        fn collection(byte: u8) -> CollectionHandle {
            Inline::new([byte; 32])
        }
        fn data(byte: u8) -> Inline<Hash<Blake3>> {
            Inline::new([byte; 32])
        }

        let records = vec![
            CollectionRecord::Merge(CollectionMerge::sign(
                &SigningKey::from_bytes(&[1; 32]),
                collection(1),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(1), data(10)),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(1), data(11)),
                data(12),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &SigningKey::from_bytes(&[1; 32]),
                collection(3),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(3), data(20)),
                data(21),
            )),
        ];

        assert_eq!(
            referenced_ids(&records),
            // A derive names only its target now: the source is what the
            // target's descriptor says, so enumeration no longer learns a
            // collection from the derive that points into it.
            BTreeSet::from([collection(1), collection(3)])
        );
    }

    #[test]
    fn known_mapping_algorithm_and_representation_ids_resolve_to_names() {
        assert_eq!(
            mapping_algorithm_name(SIMPLE_TO_SUCCINCT_MAPPING_V1),
            Some("SIMPLE_TO_SUCCINCT_MAPPING_V1")
        );
        assert_eq!(
            representation_name(<SimpleArchive as MetaDescribe>::id()),
            Some("SimpleArchive")
        );
        let unknown = Id::new([0xFF; 16]).unwrap();
        assert_eq!(mapping_algorithm_name(unknown), None);
        assert!(named_id(
            SIMPLE_TO_SUCCINCT_MAPPING_V1,
            mapping_algorithm_name(SIMPLE_TO_SUCCINCT_MAPPING_V1)
        )
        .contains("9C8CFEB097B0A336E09D506E8DD361C2"));
    }

    /// Build one descriptor's decoded fields the way `list` sees them.
    fn root(name: &str, authority_seed: u8) -> Fields {
        let authority = SigningKey::from_bytes(&[authority_seed; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(name, direct_policy(authority))
            .expect("register fixture collection");
        let snapshot = store.snapshot().expect("snapshot fixture store");
        Fields::load(&snapshot, collection.handle())
    }

    fn anchorless(facts: TribleSet) -> Fields {
        Fields::Decoded {
            facts,
            name: Ok(None),
        }
    }

    fn row(handle_byte: u8, fields: Fields) -> Enumerated {
        Enumerated {
            handle: Inline::new([handle_byte; 32]),
            refs: Refs::default(),
            fields,
        }
    }

    /// The listing leads with names, so the order has to be the name order —
    /// not the handle order the tally happens to accumulate in. Anything
    /// without a name sorts after everything with one.
    #[test]
    fn named_roots_sort_by_name_ahead_of_everything_unnamed() {
        let mut rows = vec![
            row(9, Fields::Missing),
            row(3, root("wiki", 7)),
            row(4, anchorless(TribleSet::new())),
            row(1, root("compass", 7)),
        ];
        rows.sort_by_key(sort_key);
        let order: Vec<u8> = rows.iter().map(|row| row.handle.raw[0]).collect();
        assert_eq!(order, vec![1, 3, 4, 9], "compass, wiki, malformed, missing");
    }

    /// UTF-8 names can look exactly like handles. Explicit prefixes resolve
    /// that real ambiguity without restricting what a collection may be named.
    #[test]
    fn explicit_prefixes_disambiguate_a_hex_shaped_name() {
        let hex = "1c1362fbde47aacdfe3ec872a61b5ff270ef57c30f97ef36511adb1e3536edd2";
        let rows = vec![row(3, root(hex, 7)), row(4, root("wiki", 7))];
        assert!(resolve(&rows, hex).is_err(), "bare spelling is ambiguous");
        assert_eq!(
            resolve(&rows, &format!("blake3:{hex}")).expect("explicit handle"),
            parse_collection_handle(hex).expect("parses as a handle")
        );
        assert_eq!(
            resolve(&rows, &format!("name:{hex}")).expect("explicit name"),
            rows[0].handle
        );
        assert_eq!(resolve(&rows, "wiki").unwrap(), rows[1].handle);
    }

    /// Policy participates in descriptor identity, so two collections may
    /// both have a `wiki`. Lookup must not paper that over with a first match.
    #[test]
    fn a_name_shared_by_two_policies_refuses_to_resolve() {
        let rows = vec![row(3, root("wiki", 7)), row(5, root("wiki", 9))];
        let err = resolve(&rows, "wiki").expect_err("ambiguous");
        let text = err.to_string();
        assert!(text.contains("2 collections"), "{text}");
        assert!(text.contains(&handle_hex(rows[0].handle)), "{text}");
        assert!(text.contains(&handle_hex(rows[1].handle)), "{text}");
    }

    /// An unknown name must name what the pile does have, because the whole
    /// reason to type a name is not knowing the handle.
    #[test]
    fn an_unknown_name_reports_the_names_that_exist() {
        let rows = vec![row(3, root("wiki", 7)), row(1, root("compass", 7))];
        let text = resolve(&rows, "memory").expect_err("absent").to_string();
        assert!(text.contains("wiki"), "{text}");
        assert!(text.contains("compass"), "{text}");
    }

    /// Current descriptors require exactly one root name or derived source.
    /// Historical shapes remain visible as malformed, not silently promoted
    /// through a compatibility interpretation.
    #[test]
    fn a_descriptor_without_a_current_anchor_is_reported_as_malformed() {
        use triblespace_core::metadata;
        use triblespace_core::prelude::entity;

        let bare = entity! {
            metadata::tag: triblespace_core::collection::records::KIND_COLLECTION_DESCRIPTOR,
        }
        .into_facts();
        assert!(matches!(
            anchor(&anchorless(bare)),
            Anchor::Unreadable(message) if message.contains("neither collection_name nor collection_source")
        ));
    }

    /// A derive names only its target, and `log` filters records by the same
    /// question the tally counts, so the two can never disagree about which
    /// records belong to a collection.
    #[test]
    fn log_filters_records_by_the_same_question_the_tally_counts() {
        use triblespace_core::collection::records::{CollectionDerive, CollectionMerge};

        fn collection(byte: u8) -> CollectionHandle {
            Inline::new([byte; 32])
        }
        fn data(byte: u8) -> Inline<Hash<Blake3>> {
            Inline::new([byte; 32])
        }

        let records = vec![
            CollectionRecord::Merge(CollectionMerge::sign(
                &SigningKey::from_bytes(&[1; 32]),
                collection(1),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(1), data(10)),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(1), data(11)),
                data(12),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &SigningKey::from_bytes(&[1; 32]),
                collection(3),
                witnessed(&SigningKey::from_bytes(&[1; 32]), collection(3), data(20)),
                data(21),
            )),
        ];

        for handle in referenced_ids(&records) {
            let named: Vec<&CollectionRecord> = records
                .iter()
                .filter(|record| names_collection(record, handle))
                .collect();
            assert_eq!(
                named.len(),
                1,
                "each fixture record names exactly one collection"
            );
        }
        assert!(!names_collection(&records[0], collection(3)));
        assert!(!names_collection(&records[1], collection(1)));
    }
}

/// How many records of each kind name one collection, using its record index.
fn cover_census<R: CollectionRead>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<(usize, usize, usize)> {
    let mut commits = 0usize;
    let mut merges = 0usize;
    let mut derives = 0usize;
    let records = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            collection,
        )]))
        .map_err(|error| anyhow!("select collection records: {error:?}"))?;
    for record in records {
        match record {
            CollectionRecord::Commit(_) => commits += 1,
            CollectionRecord::Merge(_) => merges += 1,
            CollectionRecord::Derive(_) => derives += 1,
        }
    }
    Ok((commits, merges, derives))
}

/// Maintain `handle` under whichever encoding its descriptor names.
///
/// The descriptor is the whole of the information needed: a root names its
/// blob representation, a derivation names its source and mapping as well,
/// and `Collection::open` checks the typed handle against those facts. What
/// a binary cannot do is maintain an encoding it was not compiled with, so
/// the dispatch asks each encoding this binary implements for its own id,
/// exactly as [`representation_name`] does, and reports an unknown one
/// rather than guessing.
async fn maintain_by_representation<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    representation: Id,
    algorithm: Option<Id>,
    signer: &SigningKey,
    succinct_backend: SuccinctBackend,
) -> Result<S::Snapshot> {
    use triblespace_core::collection::latest::LatestBlob;
    use triblespace_core::collection::lww_register::LwwRegisterBlob;
    use triblespace_core::collection::CollectionRealization;

    async fn go<S, T>(
        pile: &mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        signer: &SigningKey,
    ) -> Result<S::Snapshot>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
        T: CollectionRealization + MetaDescribe,
        Handle<T>: triblespace_core::inline::InlineEncoding,
    {
        let collection: Collection<T> = Collection::open(snapshot, handle)
            .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
        pile.maintain(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain collection: {error}"))
    }

    if representation == <SimpleArchive as MetaDescribe>::id() {
        if algorithm.is_some() {
            return Err(anyhow!(
                "derived SimpleArchive mappings are not implemented by this binary"
            ));
        }
        go::<S, SimpleArchive>(pile, snapshot, handle, signer).await
    } else if representation == <SuccinctArchiveBlob as MetaDescribe>::id() {
        #[cfg(feature = "succinct-cuda")]
        if matches!(succinct_backend, SuccinctBackend::Cuda) {
            let collection = Collection::<SuccinctArchiveBlob>::open(snapshot, handle)
                .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
            return pile
                .maintain_with::<triblespace_gpu::CudaSuccinctMapping>(collection, signer)
                .await
                .map_err(|error| anyhow!("maintain CUDA Succinct collection: {error}"));
        }
        #[cfg(not(feature = "succinct-cuda"))]
        succinct_backend.check_available()?;
        go::<S, SuccinctArchiveBlob>(pile, snapshot, handle, signer).await
    } else if representation == <Rank9AcceleratedSuccinctArchiveBlob as MetaDescribe>::id() {
        go::<S, Rank9AcceleratedSuccinctArchiveBlob>(pile, snapshot, handle, signer).await
    } else if representation == <EntityIdSetBlob as MetaDescribe>::id() {
        go::<S, EntityIdSetBlob>(pile, snapshot, handle, signer).await
    } else if representation == <LatestBlob as MetaDescribe>::id() {
        go::<S, LatestBlob>(pile, snapshot, handle, signer).await
    } else if representation == <LwwRegisterBlob as MetaDescribe>::id() {
        go::<S, LwwRegisterBlob>(pile, snapshot, handle, signer).await
    } else if representation == <ReferenceSummaryBlob as MetaDescribe>::id() {
        eprintln!("reference summary: assuming complete producer-side blob closure");
        go::<S, ReferenceSummaryBlob>(pile, snapshot, handle, signer).await
    } else if representation == <triblespace_paths::PathSummaryBlob as MetaDescribe>::id() {
        go::<S, triblespace_paths::PathSummaryBlob>(pile, snapshot, handle, signer).await
    } else if nvfp4_embedding_set_id().is_some_and(|nvfp4| representation == nvfp4) {
        // Both the ordinary embedding conversion and model inference produce
        // this encoding. Its algorithm, not just its representation, chooses
        // the executable mapping.
        maintain_nvfp4_embedding_set(pile, snapshot, handle, algorithm, signer).await
    } else if bm25_carrier_id().is_some_and(|bm25| representation == bm25) {
        maintain_bm25(pile, snapshot, handle, signer).await
    } else {
        Err(anyhow!(
            "representation {representation:X} is not implemented by this binary; \
             nothing here can maintain it"
        ))
    }
}

/// Resolve an explicit maintenance selection without materializing a catalogue.
///
/// In particular, a descriptor handle does not need any record to name it yet:
/// `derive` registers its blob before its first maintenance publishes equations.
fn resolve_maintenance_target<R: StoreRead>(
    snapshot: &R,
    reference: &str,
) -> Result<CollectionHandle> {
    use triblespace_core::collection::records::{collection_name, KIND_COLLECTION_DESCRIPTOR};
    use triblespace_core::macros::{find, pattern};

    let reference = reference.trim();
    if reference.starts_with("blake3:") {
        return parse_collection_handle(reference);
    }
    let (name, explicit_name) = match reference.strip_prefix("name:") {
        Some(name) => (name, true),
        None => (reference, false),
    };
    // Bare handles, like explicit ones, are independent of the historical
    // record inventory. `name:` selects a literal hexadecimal name instead.
    if !explicit_name {
        if let Ok(handle) = parse_collection_handle(reference) {
            return Ok(handle);
        }
    }

    let mut candidates = BTreeSet::new();
    for record in snapshot
        .records()
        .map_err(|error| anyhow!("enumerate collection names: {error:?}"))?
    {
        let record = record.map_err(|error| anyhow!("read collection record: {error:?}"))?;
        candidates.insert(match record {
            CollectionRecord::Commit(commit) => commit.collection(),
            CollectionRecord::Merge(merge) => merge.collection(),
            CollectionRecord::Derive(derive) => derive.collection(),
        });
    }
    let mut matches = BTreeSet::new();
    for handle in candidates {
        let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(handle) else {
            continue;
        };
        for label in find!(
            label: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_name: ?label,
            }])
        ) {
            let Ok(label) = snapshot.get::<anybytes::View<str>, UTF8String>(label) else {
                continue;
            };
            if label.as_ref() == name {
                matches.insert(handle);
            }
        }
    }
    match matches.len() {
        1 => Ok(*matches.first().expect("one matching collection")),
        0 => Err(anyhow!(
            "no resident referenced collection named {name:?}; use its exact descriptor handle \
             for a newly registered collection"
        )),
        _ => Err(anyhow!(
            "multiple collections are named {name:?}; select an exact descriptor handle"
        )),
    }
}

/// A temporary call order, not a second model of the collection descriptors.
/// Source links are queried in one immutable observation and discarded.
fn maintenance_order<R: BlobStoreGet>(
    snapshot: &R,
    target: CollectionHandle,
    dependencies: bool,
    attempted: &BTreeSet<CollectionHandle>,
) -> Result<Vec<CollectionHandle>> {
    let mut order = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut current = target;
    loop {
        if attempted.contains(&current) {
            break;
        }
        if !visiting.insert(current) {
            return Err(anyhow!("cyclic collection source dependency"));
        }
        order.push(current);
        if !dependencies {
            break;
        }
        let facts: TribleSet = snapshot
            .get(current)
            .map_err(|error| anyhow!("read descriptor blake3:{}: {error}", handle_hex(current)))?;
        let Some(source) = descriptor::source(&facts)? else {
            break;
        };
        current = source;
    }
    order.reverse();
    Ok(order)
}

/// Ephemeral recomputation boundaries, never interpreted collection answers.
struct MaintenanceHop<R> {
    before: R,
    interests: StoreDependencies,
    // An implicitly selected root is ensured, whereas an explicit root is
    // maintained. Derived hops conservatively retry on this mode change too.
    dependency_only: bool,
    // Preserve the old retry opportunity whenever any selected input wakes
    // this worker. An Err is not a valid cached answer, especially when its
    // cause is runtime/provider state outside the stored dependency model.
    retry_on_pass: bool,
}

struct MaintenanceState<R> {
    planning: StoreDependencies,
    hops: BTreeMap<CollectionHandle, MaintenanceHop<R>>,
}

impl<R> Default for MaintenanceState<R> {
    fn default() -> Self {
        Self {
            planning: StoreDependencies::default(),
            hops: BTreeMap::new(),
        }
    }
}

fn extend_maintenance_interests(into: &mut StoreDependencies, from: &StoreDependencies) {
    into.records.extend(from.records.iter().copied());
    into.blobs.extend(from.blobs.iter().copied());
    into.capability_proofs |= from.capability_proofs;
    into.all_records |= from.all_records;
    into.all_blobs |= from.all_blobs;
}

impl<R: StoreSnapshot> MaintenanceState<R> {
    fn interests(&self) -> StoreDependencies {
        let mut interests = self.planning.clone();
        // A pass triggered by one chain must not forget skipped chains' misses
        // or record interests. Name lookup stays broad only at planning scope.
        for hop in self.hops.values() {
            extend_maintenance_interests(&mut interests, &hop.interests);
        }
        interests
    }

    fn rebase_unchanged(&mut self, current: &R) {
        for hop in self.hops.values_mut() {
            if !maintenance_changed(&hop.before, current, &hop.interests) {
                hop.before = current.clone();
            }
        }
    }

    fn needs_work(&mut self, handle: CollectionHandle, dependency_only: bool, current: &R) -> bool {
        let Some(hop) = self.hops.get_mut(&handle) else {
            return true;
        };
        if hop.retry_on_pass
            || hop.dependency_only != dependency_only
            || maintenance_changed(&hop.before, current, &hop.interests)
        {
            return true;
        }
        // Rebase only after proving this hop unchanged, releasing older shared
        // index versions without swallowing an unconsumed relevant arrival.
        hop.before = current.clone();
        false
    }
}

async fn maintenance_pass<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
) -> Result<usize> {
    maintenance_pass_observed(
        pile,
        references,
        signer,
        dependencies,
        succinct_backend,
        state,
        None,
    )
    .await
}

async fn maintenance_pass_observed<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
    mut telemetry: Option<&mut maintenance_telemetry::Telemetry>,
) -> Result<usize> {
    let started = telemetry
        .as_deref_mut()
        .map(|telemetry| telemetry.begin_pass());
    let result = maintenance_pass_inner(
        pile,
        references,
        signer,
        dependencies,
        succinct_backend,
        state,
        telemetry.as_deref_mut(),
    )
    .await;
    if let (Some(telemetry), Some(started)) = (telemetry, started) {
        telemetry.finish_pass(started, matches!(result, Ok(0)));
        telemetry.emit_due(pile);
    }
    result
}

async fn maintenance_hop<S: Store + AsyncBlobStoreAcquire + Send>(
    store: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    representation: Id,
    algorithm: Option<Id>,
    signer: &SigningKey,
    succinct_backend: SuccinctBackend,
    ensure_only: bool,
) -> Result<S::Snapshot> {
    if ensure_only {
        let root: Collection<SimpleArchive> = Collection::open(snapshot, handle)
            .map_err(|error| anyhow!("open foundational collection: {error}"))?;
        store
            .ensure(root, signer)
            .await
            .map_err(|error| anyhow!("ensure foundational collection: {error}"))
    } else {
        maintain_by_representation(
            store,
            snapshot,
            handle,
            representation,
            algorithm,
            signer,
            succinct_backend,
        )
        .await
    }
}

async fn maintenance_pass_inner<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
    mut telemetry: Option<&mut maintenance_telemetry::Telemetry>,
) -> Result<usize> {
    let snapshot = ObservedStore::new(
        pile.snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?,
    );
    let mut selected = BTreeSet::new();
    let mut failures = 0;
    for reference in references {
        match resolve_maintenance_target(&snapshot, reference) {
            Ok(handle) => {
                selected.insert(handle);
            }
            Err(error) => {
                eprintln!("maintenance target {reference:?}: {error:#}");
                failures += 1;
            }
        }
    }
    state.planning = snapshot.dependencies();
    drop(snapshot);

    // Give independent authors different stable priorities over the same
    // explicit selection. This is local scheduling, not exclusive ownership:
    // nodes may still choose the same first target or perform overlapping work.
    // Only the outer chain order changes; the dependency walk and canonical
    // per-collection merge/derive plans below remain untouched.
    let author = signer.verifying_key();
    let mut targets: Vec<_> = selected.iter().copied().collect();
    targets.sort_by_cached_key(|target| {
        let mut hash = blake3::Hasher::new();
        hash.update(b"trible/maintenance-target-order");
        hash.update(author.as_bytes());
        hash.update(&target.raw);
        (*hash.finalize().as_bytes(), target.raw)
    });

    let mut attempted = BTreeSet::new();
    for target in targets {
        let snapshot = ObservedStore::new(
            pile.snapshot()
                .map_err(|error| anyhow!("pile snapshot: {error:?}"))?,
        );
        let order = maintenance_order(&snapshot, target, dependencies, &attempted);
        extend_maintenance_interests(&mut state.planning, &snapshot.dependencies());
        let order = match order {
            Ok(order) => order,
            Err(error) => {
                eprintln!(
                    "maintenance target blake3:{}: {error:#}",
                    handle_hex(target)
                );
                failures += 1;
                continue;
            }
        };
        drop(snapshot);
        for handle in order {
            attempted.insert(handle);
            // Give shutdown and the runtime's I/O driver a boundary between
            // one-edge operations, including immediately-ready local stores.
            tokio::task::yield_now().await;
            let before = match pile.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    if let Some(hop) = state.hops.get_mut(&handle) {
                        hop.retry_on_pass = true;
                    }
                    eprintln!(
                        "maintenance blake3:{}: pile snapshot: {error:?}",
                        handle_hex(handle)
                    );
                    failures += 1;
                    continue;
                }
            };
            let dependency_only = dependencies && !selected.contains(&handle);
            if !state.needs_work(handle, dependency_only, &before) {
                continue;
            }
            let hop_started = telemetry.as_deref_mut().map(|telemetry| {
                let started = telemetry.begin_hop();
                telemetry.emit_due(pile);
                started
            });
            let mut observed = ObservedStore::new(&mut *pile);
            let result = async {
                let snapshot = observed
                    .snapshot()
                    .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
                let facts: TribleSet = snapshot
                    .get(handle)
                    .map_err(|error| anyhow!("read collection descriptor: {error}"))?;
                let representation = descriptor::representation(&facts)?;
                let algorithm = descriptor::mapping_algorithm(&facts)?;
                let source = descriptor::source(&facts)?;
                let ensure_only = dependency_only && source.is_none();
                let before = cover_census(&snapshot, handle)?;
                let started = Instant::now();
                let after = if let Some(telemetry) = telemetry.as_deref_mut() {
                    let mut counted = maintenance_telemetry::CountedStore {
                        inner: &mut observed,
                        counts: &mut telemetry.publications,
                    };
                    maintenance_hop(
                        &mut counted,
                        &snapshot,
                        handle,
                        representation,
                        algorithm,
                        signer,
                        succinct_backend,
                        ensure_only,
                    )
                    .await?
                } else {
                    maintenance_hop(
                        &mut observed,
                        &snapshot,
                        handle,
                        representation,
                        algorithm,
                        signer,
                        succinct_backend,
                        ensure_only,
                    )
                    .await?
                };
                let after = cover_census(&after, handle)?;
                println!(
                    "{} blake3:{} in {:.1} s: commits {} -> {}, merges {} -> {}, derives {} -> {}",
                    if ensure_only { "ensured" } else { "maintained" },
                    handle_hex(handle),
                    started.elapsed().as_secs_f64(),
                    before.0,
                    after.0,
                    before.1,
                    after.1,
                    before.2,
                    after.2,
                );
                Ok::<(), anyhow::Error>(())
            }
            .await;
            let interests = observed.dependencies();
            drop(observed);
            if let (Some(telemetry), Some(started)) = (telemetry.as_deref_mut(), hop_started) {
                telemetry.finish_hop(started, result.is_ok());
                telemetry.emit_due(pile);
            }
            // Retain the start boundary even after an error or partial write.
            // A later snapshot can contain records/proofs that the operation's
            // frozen frontier did not consume. Its own writes also request one
            // local catch-up; an unchanged sibling need not run again.
            state.hops.insert(
                handle,
                MaintenanceHop {
                    before,
                    interests,
                    dependency_only,
                    retry_on_pass: result.is_err(),
                },
            );
            if let Err(error) = result {
                eprintln!("maintenance blake3:{}: {error:#}", handle_hex(handle));
                failures += 1;
                // Failed upkeep does not retract its existing resident nodes.
                // A downstream target can still consume that available input.
            }
        }
    }
    // Entries no longer reachable from this selection hold no useful work.
    // Failed planning retains its exact misses above; when that route becomes
    // available, absent entries run afresh rather than reusing an old answer.
    state.hops.retain(|handle, _| attempted.contains(handle));
    Ok(failures)
}

fn maintenance_changed<S: StoreSnapshot>(
    previous: &S,
    current: &S,
    interests: &StoreDependencies,
) -> bool {
    !current.changes_for(previous, interests).is_empty()
}

async fn maintenance_loop(
    pile: &mut Pile,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    watch: bool,
    interval: Duration,
    succinct_backend: SuccinctBackend,
    mut telemetry: Option<&mut maintenance_telemetry::Telemetry>,
) -> Result<()> {
    let mut baseline = None;
    let mut catch_up = true;
    let mut interests = StoreDependencies::default();
    let mut state = MaintenanceState::default();
    loop {
        if let Some(telemetry) = telemetry.as_deref_mut() {
            telemetry.emit_due(pile);
        }
        // Pile::snapshot refreshes its externally appended prefix before
        // freezing all indexes. Blob arrivals count, not just new equations.
        let before = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        if catch_up
            || baseline
                .as_ref()
                .is_some_and(|previous| maintenance_changed(previous, &before, &interests))
        {
            let failures = maintenance_pass_observed(
                pile,
                references,
                signer,
                dependencies,
                succinct_backend,
                &mut state,
                telemetry.as_deref_mut(),
            )
            .await?;
            interests = state.interests();
            let after = pile
                .snapshot()
                .map_err(|error| anyhow!("pile snapshot after maintenance: {error:?}"))?;
            // A concurrent input can arrive after an earlier hop sampled its
            // source. Retain one dirty bit across our post-work baseline, then
            // run another bounded pass at the next interval. Our own writes
            // may cause one no-op pass; they cannot sustain an idle loop.
            catch_up = maintenance_changed(&before, &after, &interests);
            baseline = Some(after);
            if !watch {
                return if failures == 0 {
                    Ok(())
                } else {
                    Err(anyhow!("{failures} maintenance selection(s) failed"))
                };
            }
            if failures != 0 {
                eprintln!(
                    "{failures} maintenance selection(s) failed; waiting for relevant changes"
                );
            }
        } else {
            // Even a wholly skipped poll can have ingested unrelated frames.
            // Release old index versions only after each hop's own proof.
            state.rebase_unchanged(&before);
            baseline = Some(before);
        }
        tokio::time::sleep(interval).await;
    }
}

fn run_maintain(
    path: PathBuf,
    references: Vec<String>,
    key: Option<PathBuf>,
    dependencies: bool,
    watch: bool,
    interval_ms: u64,
    succinct_backend: SuccinctBackend,
    telemetry_options: maintenance_telemetry::Options,
) -> Result<()> {
    let telemetry_config = telemetry_options.config()?;
    // Reject an unavailable implementation before opening/mutating the pile.
    succinct_backend.check_available()?;
    let key_path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &path);
    let signer = triblespace_core::signing_key_file::load_existing(&key_path)
        .map_err(|error| anyhow!("load signing key {}: {error}", key_path.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let stop = {
        let _entered = runtime.enter();
        crate::cli::util::shutdown_signal()?
    };
    let mut pile = open_refreshed(&path)?;
    let mut telemetry = match telemetry_config {
        Some(config) => match maintenance_telemetry::Telemetry::open(&mut pile, config, &signer) {
            Ok(telemetry) => Some(telemetry),
            Err(error) => {
                let close = pile.close();
                if close.is_err() {
                    eprintln!("maintenance telemetry setup: cannot close pile");
                }
                return Err(error.into());
            }
        },
        None => None,
    };
    let res = runtime.block_on(async {
        tokio::select! {
            biased;
            stopped = stop => {
                stopped?;
                eprintln!("maintenance stopped; closing pile");
                Ok(())
            }
            result = maintenance_loop(
                &mut pile,
                &references,
                &signer,
                dependencies,
                watch,
                Duration::from_millis(interval_ms),
                succinct_backend,
                telemetry.as_mut(),
            ) => result,
        }
    });
    if let Some(telemetry) = telemetry.as_mut() {
        telemetry.finish(&mut pile);
    }
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close_res)
}

#[cfg(feature = "search")]
async fn maintain_nvfp4_embedding_set<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    algorithm: Option<Id>,
    signer: &SigningKey,
) -> Result<S::Snapshot> {
    use triblespace_core::collection::CollectionStoreExt as _;
    use triblespace_search::nvfp4::EMBEDDING_ATTRIBUTE_TO_NVFP4;
    use triblespace_search::schemas::Embedding;
    use triblespace_search::semantic::{SemanticIndex, NOMIC_ATTRIBUTES_TO_NVFP4};
    let collection: Collection<
        triblespace_search::nvfp4::NvFp4CosineSet<triblespace_search::schemas::Embedding>,
    > = Collection::open(snapshot, handle)
        .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
    if algorithm == Some(EMBEDDING_ATTRIBUTE_TO_NVFP4) {
        pile.maintain(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain NVFP4 embedding collection: {error}"))
    } else if algorithm == Some(NOMIC_ATTRIBUTES_TO_NVFP4) {
        pile.maintain_with::<SemanticIndex<Embedding>>(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain semantic index: {error}"))
    } else {
        Err(anyhow!(
            "NVFP4 mapping algorithm {} is not implemented by this binary; \
             historical or unknown mappings are not rebound to another algorithm",
            algorithm
                .map(|id| format!("{id:X}"))
                .unwrap_or_else(|| "<absent>".to_owned())
        ))
    }
}

#[cfg(not(feature = "search"))]
async fn maintain_nvfp4_embedding_set<S: Store + AsyncBlobStoreAcquire + Send>(
    _pile: &mut S,
    _snapshot: &S::Snapshot,
    _handle: CollectionHandle,
    _algorithm: Option<Id>,
    _signer: &SigningKey,
) -> Result<S::Snapshot> {
    unreachable!("the NVFP4 representation is only recognised with the search feature")
}

/// The optional per-kind arguments of `derive`, validated by the kind.
struct DeriveArguments {
    observes: Option<String>,
    identity: Option<String>,
    orders: Option<String>,
    attribute: Option<String>,
    dimension: Option<usize>,
    log2_bits: Option<u8>,
    probes: Option<u8>,
    text: Option<String>,
    tokenizer: String,
    expr: Option<String>,
}

fn parse_attribute_id(flag: &str, value: Option<&str>) -> Result<Id> {
    let text = value.ok_or_else(|| anyhow!("{flag} is required for this kind"))?;
    Id::from_hex(text.trim()).ok_or_else(|| anyhow!("{flag}: {text:?} is not a 32-hex-digit id"))
}

fn run_derive(
    path: PathBuf,
    source: String,
    kind: DeriveKind,
    arguments: DeriveArguments,
    key: Option<PathBuf>,
) -> Result<()> {
    let key_path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &path);
    let root = triblespace_core::signing_key_file::load_existing(&key_path).map_err(|error| {
        anyhow!(
            "load collection-root signing key {}: {error}",
            key_path.display()
        )
    })?;
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(root.verifying_key()),
        AdmissionPolicy::direct(root.verifying_key()),
    );

    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<CollectionHandle> {
        let source_handle = {
            let snapshot = pile
                .snapshot()
                .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
            let rows = enumerate(&snapshot)?;
            resolve(&rows, &source)?
        };
        fn open_source<E>(pile: &mut Pile, handle: CollectionHandle) -> Result<Collection<E>>
        where
            E: triblespace_core::collection::CollectionEncoding,
        {
            let snapshot = pile
                .snapshot()
                .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
            Collection::open(&snapshot, handle)
                .map_err(|error| anyhow!("open source collection descriptor: {error}"))
        }
        let registered = |error| anyhow!("register derived collection: {error:?}");
        let handle = match kind {
            DeriveKind::Succinct => {
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<SuccinctArchiveBlob>(source, (), policy)
                    .map_err(registered)?
                    .handle()
            }
            DeriveKind::Rank9 => {
                let source: Collection<SuccinctArchiveBlob> =
                    open_source(&mut pile, source_handle)?;
                pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(source, (), policy)
                    .map_err(registered)?
                    .handle()
            }
            DeriveKind::EntityIdSet => {
                let attribute = parse_attribute_id("--attribute", arguments.attribute.as_deref())?;
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<EntityIdSetBlob>(source, attribute, policy)
                    .map_err(registered)?
                    .handle()
            }
            DeriveKind::Latest => {
                let observes = parse_attribute_id("--observes", arguments.observes.as_deref())?;
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<triblespace_core::collection::latest::LatestBlob>(
                    source, observes, policy,
                )
                .map_err(registered)?
                .handle()
            }
            DeriveKind::Lww => {
                let identity = parse_attribute_id("--identity", arguments.identity.as_deref())?;
                let orders = parse_attribute_id("--orders", arguments.orders.as_deref())?;
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<triblespace_core::collection::lww_register::LwwRegisterBlob>(
                    source,
                    (identity, orders),
                    policy,
                )
                .map_err(registered)?
                .handle()
            }
            DeriveKind::Nvfp4 => derive_nvfp4(&mut pile, source_handle, &arguments, policy)?,
            DeriveKind::ReferenceSummary => {
                let layout = ReferenceSummaryLayout::new(
                    arguments.log2_bits.unwrap_or(32),
                    arguments.probes.unwrap_or(4),
                )?;
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<ReferenceSummaryBlob>(source, layout, policy)
                    .map_err(registered)?
                    .handle()
            }
            DeriveKind::Bm25 => derive_bm25(&mut pile, source_handle, &arguments, policy)?,
            DeriveKind::Path => {
                let text = arguments
                    .expr
                    .as_deref()
                    .ok_or_else(|| anyhow!("--expr is required for path"))?;
                let automaton = super::path_text::parse(text)
                    .map_err(|error| anyhow!("--expr: {error}"))?
                    .compile();
                let source: Collection<SimpleArchive> = open_source(&mut pile, source_handle)?;
                pile.derive::<triblespace_paths::PathSummaryBlob>(source, automaton, policy)
                    .map_err(registered)?
                    .handle()
            }
        };
        Ok(handle)
    })();
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    let handle = res.and_then(|handle| close_res.map(|()| handle))?;
    println!("blake3:{}", handle_hex(handle));
    Ok(())
}

#[cfg(feature = "search")]
fn derive_nvfp4(
    pile: &mut Pile,
    source_handle: CollectionHandle,
    arguments: &DeriveArguments,
    policy: CollectionPolicy,
) -> Result<CollectionHandle> {
    let attribute = parse_attribute_id("--attribute", arguments.attribute.as_deref())?;
    let dimension = arguments
        .dimension
        .ok_or_else(|| anyhow!("--dimension is required for nvfp4"))?;
    let argument = triblespace_search::nvfp4::NvFp4EmbeddingAttribute::new(attribute, dimension)
        .map_err(|error| anyhow!("nvfp4 argument: {error}"))?;
    let source: Collection<SimpleArchive> = {
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        Collection::open(&snapshot, source_handle)
            .map_err(|error| anyhow!("open source collection descriptor: {error}"))?
    };
    Ok(pile
        .derive::<triblespace_search::nvfp4::NvFp4CosineSet<triblespace_search::schemas::Embedding>>(
            source, argument, policy,
        )
        .map_err(|error| anyhow!("register derived collection: {error:?}"))?
        .handle())
}

#[cfg(not(feature = "search"))]
fn derive_nvfp4(
    _pile: &mut Pile,
    _source_handle: CollectionHandle,
    _arguments: &DeriveArguments,
    _policy: CollectionPolicy,
) -> Result<CollectionHandle> {
    Err(anyhow!(
        "this binary was built without the search feature and cannot register NVFP4 vector sets"
    ))
}

#[cfg(feature = "search")]
async fn maintain_bm25<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    signer: &SigningKey,
) -> Result<S::Snapshot> {
    use triblespace_core::collection::CollectionStoreExt as _;
    let collection: Collection<triblespace_search::portable_bm25::PortableBM25Blob> =
        Collection::open(snapshot, handle)
            .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
    pile.maintain(collection, signer)
        .await
        .map_err(|error| anyhow!("maintain BM25 collection: {error}"))
}

#[cfg(not(feature = "search"))]
async fn maintain_bm25<S: Store + AsyncBlobStoreAcquire + Send>(
    _pile: &mut S,
    _snapshot: &S::Snapshot,
    _handle: CollectionHandle,
    _signer: &SigningKey,
) -> Result<S::Snapshot> {
    unreachable!("the BM25 representation is only recognised with the search feature")
}

#[cfg(feature = "search")]
fn derive_bm25(
    pile: &mut Pile,
    source_handle: CollectionHandle,
    arguments: &DeriveArguments,
    policy: CollectionPolicy,
) -> Result<CollectionHandle> {
    use triblespace_search::text_bm25::{Bm25Tokenizer, TextAttributeToBm25};
    let attribute = parse_attribute_id("--text", arguments.text.as_deref())?;
    let tokenizer = Bm25Tokenizer::from_name(&arguments.tokenizer).ok_or_else(|| {
        anyhow!(
            "--tokenizer {:?} is not one of word, bigram, code",
            arguments.tokenizer
        )
    })?;
    let argument = TextAttributeToBm25 {
        attribute,
        tokenizer,
    };
    let source: Collection<SimpleArchive> = {
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        Collection::open(&snapshot, source_handle)
            .map_err(|error| anyhow!("open source collection descriptor: {error}"))?
    };
    Ok(pile
        .derive::<triblespace_search::portable_bm25::PortableBM25Blob>(source, argument, policy)
        .map_err(|error| anyhow!("register derived collection: {error:?}"))?
        .handle())
}

#[cfg(not(feature = "search"))]
fn derive_bm25(
    _pile: &mut Pile,
    _source_handle: CollectionHandle,
    _arguments: &DeriveArguments,
    _policy: CollectionPolicy,
) -> Result<CollectionHandle> {
    Err(anyhow!(
        "this binary was built without the search feature and cannot register BM25 collections"
    ))
}

#[cfg(feature = "search")]
fn run_search(
    path: PathBuf,
    reference: String,
    query: String,
    top: usize,
    snippet: bool,
) -> Result<()> {
    use anybytes::View;
    use anyhow::Context;
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::collection::{CollectionDerivation, CollectionSnapshotExt};
    use triblespace_core::inline::encodings::genid::GenId;
    use triblespace_core::inline::IntoInline;
    use triblespace_core::prelude::{find, TriblePattern};
    use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25View};
    use triblespace_search::text_bm25::Bm25Tokenizer;
    use triblespace_search::tokens::{
        bigram_tokens, code_tokens, hash_tokens, BigramHash, WordHash,
    };

    let mut pile = open_refreshed(&path)?;
    let res = (|| -> Result<()> {
        let snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        let rows = enumerate(&snapshot)?;
        let handle = resolve(&rows, &reference)?;
        let collection: Collection<PortableBM25Blob> = Collection::open(&snapshot, handle)
            .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
        // The descriptor says how the texts were cut and where they came from.
        let descriptor: Blob<SimpleArchive> = snapshot
            .get(handle)
            .map_err(|error| anyhow!("read descriptor: {error}"))?;
        let descriptor = Fragment::from(
            <TribleSet as TryFromBlob<SimpleArchive>>::try_from_blob(descriptor)
                .map_err(|error| anyhow!("decode descriptor: {error:?}"))?,
        );
        let argument = PortableBM25Blob::bind(&Fragment::empty(), &descriptor)
            .map_err(|error| anyhow!("bind BM25 mapping: {error}"))?;
        let source = triblespace_core::collection::descriptor::source(descriptor.facts())
            .map_err(|error| anyhow!("read source: {error:?}"))?
            .ok_or_else(|| anyhow!("BM25 descriptor names no source collection"))?;

        // Read the target's resident realization. New source commits may not
        // have index images yet; they do not make the existing index unreadable.
        let view = snapshot
            .collection(collection)
            .map_err(|error| anyhow!("attach cover: {error:?}"))?;
        let members: Vec<_> = view.cover().members().collect();
        if members.is_empty() {
            println!("the collection has no members yet; run 'collection maintain' first");
            return Ok(());
        }
        // Score under the tokenizer the descriptor names; the carrier bytes are
        // the same grammar whichever term space they hold. Interpreting a cover
        // does not rebuild a physical carrier, even when it has several shards.
        let hits: Vec<(Inline<GenId>, f32)> = match argument.tokenizer {
            Bm25Tokenizer::Bigram => {
                let index: PortableBM25View<GenId, BigramHash> = view
                    .view()
                    .map_err(|error| anyhow!("read carriers: {error}"))?;
                index
                    .query()
                    .map_err(|error| anyhow!("prepare BM25 scoring: {error}"))?
                    .query_multi(&bigram_tokens(&query))
            }
            Bm25Tokenizer::Word | Bm25Tokenizer::Code => {
                let index: PortableBM25View<GenId, WordHash> = view
                    .view()
                    .map_err(|error| anyhow!("read carriers: {error}"))?;
                let terms = if argument.tokenizer == Bm25Tokenizer::Code {
                    code_tokens(&query)
                } else {
                    hash_tokens(&query)
                };
                index
                    .query()
                    .map_err(|error| anyhow!("prepare BM25 scoring: {error}"))?
                    .query_multi(&terms)
            }
        };
        let mut hits = hits;
        hits.truncate(top);

        // The normal source view is needed only for selected snippets. Query it
        // at the point of use; do not serialize it again or build a shadow map.
        let source_facts: Option<TribleSet> = if snippet && !hits.is_empty() {
            let source_collection: Collection<SimpleArchive> = Collection::open(&snapshot, source)
                .map_err(|error| anyhow!("open source descriptor: {error}"))?;
            let support = view
                .support()
                .context("resolve indexed support for snippets")?;
            Some(
                snapshot
                    .collection_exact(source_collection, support)
                    .map_err(|error| anyhow!("attach source: {error:?}"))?
                    .view::<TribleSet>()
                    .map_err(|error| anyhow!("view source: {error:?}"))?,
            )
        } else {
            None
        };

        println!(
            "{} hit(s) for {:?} over {} carrier(s), tokenizer {}",
            hits.len(),
            query,
            members.len(),
            argument.tokenizer.name()
        );
        let text_attribute: Inline<GenId> = argument.attribute.to_inline();
        for (document, score) in hits {
            let entity: &Id = document
                .try_from_inline()
                .map_err(|error| anyhow!("document key is not an entity id: {error:?}"))?;
            let line = format!("{score:>8.3}  {entity:X}");
            if let Some(facts) = &source_facts {
                let text = find!(
                    handle: Inline<Handle<UTF8String>>,
                    facts.pattern(document, text_attribute, handle)
                )
                .find_map(|handle| {
                    let blob: Blob<UTF8String> = snapshot.get(handle).ok()?;
                    let text = View::<str>::try_from_blob(blob).ok()?;
                    // Only consume enough characters to display this snippet.
                    let mut chars =
                        text.split_whitespace()
                            .enumerate()
                            .flat_map(|(index, word)| {
                                (index != 0).then_some(' ').into_iter().chain(word.chars())
                            });
                    let mut snippet: String = chars.by_ref().take(110).collect();
                    if chars.next().is_some() {
                        snippet.push('…');
                    }
                    Some(snippet)
                })
                .unwrap_or_default();
                println!("{line}  {text}");
            } else {
                println!("{line}");
            }
        }
        Ok(())
    })();
    let close_res = pile
        .close()
        .map_err(|error| anyhow!("pile close: {error:?}"));
    res.and(close_res)
}

#[cfg(not(feature = "search"))]
fn run_search(
    _path: PathBuf,
    _reference: String,
    _query: String,
    _top: usize,
    _snippet: bool,
) -> Result<()> {
    Err(anyhow!(
        "this binary was built without the search feature and cannot search BM25 collections"
    ))
}
