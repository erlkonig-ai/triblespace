//! Content-addressed BM25 + HNSW indexes on top of triblespace
//! piles. See `docs/DESIGN.md` for the full design rationale.
//!
//! Three content-addressed BM25/HNSW blob types:
//! - [`portable_bm25::PortableBM25Index`] (schema
//!   [`portable_bm25::PortableBM25Blob`]) — an architecture-independent,
//!   canonical BM25 carrier containing exact term frequencies. Its resident
//!   view validates the bytes and derives scores without changing identity.
//! - [`succinct::SuccinctBM25Index`] (schema
//!   [`succinct::SuccinctBM25Blob`]) — term → doc retrieval
//!   where terms are 32-byte triblespace `Inline`s (text tokens,
//!   entity ids, tags, anything), loaded zero-copy via [`anybytes`] with a
//!   bit-packed [`jerky`] body.
//! - [`succinct::SuccinctHNSWIndex`] (schema
//!   [`succinct::SuccinctHNSWBlob`]) — approximate
//!   k-nearest-neighbour over caller-supplied embeddings, likewise using a
//!   native succinct query accelerator.
//!
//! [`bm25::BM25Builder::build`] goes direct-to-succinct
//! (sorts keys into a `CompressedUniverse` first, then
//! accumulates per-term postings in universe-code order — no
//! remap pass). [`hnsw::HNSWBuilder::build`] also returns the
//! succinct form directly (delegating through today's
//! `SuccinctHNSWIndex::from_naive` internally — the naive
//! intermediate is a necessary buffer because HNSW levels are
//! only revealed incrementally). Naive reference
//! implementations live under [`testing`] — see
//! [`testing::BM25Index`], [`testing::HNSWIndex`], and
//! [`testing::FlatIndex`] for oracles + benchmarks. Reach them
//! via `BM25Builder::build_naive()` / `HNSWBuilder::build_naive()`
//! / `FlatBuilder::build()`.
//!
//! Index blobs are immutable. Direct builders and collection derivations
//! return fresh content-addressed handles. Portable BM25 carriers join by
//! document union plus pointwise-maximum term frequency; HNSW builders return
//! standalone native or succinct graphs.
//!
//! # Query surface
//!
//! Three constraint shapes plug into `find!` / `and!` /
//! `pattern!`. They follow the same rule: scoring is *not* a
//! bound variable. The constraint filters on a fixed
//! `score_floor` parameter; callers recompute the precise
//! score afterwards if they need it for ranking.
//!
//! - [`BM25Index::matches`][m] — multi-term BM25 filter.
//!   Binds `doc` to documents whose summed BM25 score across
//!   the query terms is `>= score_floor`. Pass `0.0` for
//!   "any matching doc". Same method on [`SuccinctBM25Index`][sbm25].
//!   Pair with [`BM25Index::score`][s] for ranking.
//! - [`AttachedHNSWIndex::cosine_at_least`][sh] — exact symmetric,
//!   filter-only predicate over two [`EmbHandle`][emb]-typed variables.
//!   Same method on [`AttachedFlatIndex`][sf] and
//!   [`AttachedSuccinctHNSWIndex`][ssh].
//! - [`AttachedHNSWIndex::similar_to`][sth] — unary
//!   convenience for the common "search from a known handle"
//!   case; pins the probe on the call.
//!
//! [m]: bm25::BM25Index::matches
//! [s]: bm25::BM25Index::score
//! [sbm25]: succinct::SuccinctBM25Index
//! [sh]: hnsw::AttachedHNSWIndex::cosine_at_least
//! [sth]: hnsw::AttachedHNSWIndex::similar_to
//! [sf]: hnsw::AttachedFlatIndex::cosine_at_least
//! [ssh]: succinct::AttachedSuccinctHNSWIndex::cosine_at_least
//! [emb]: schemas::EmbHandle
//!
//! # Quickstart
//!
//! ```
//! use triblespace_core::find;
//! use triblespace_core::id::Id;
//!
//! use triblespace_search::bm25::BM25Builder;
//! use triblespace_search::succinct::SuccinctBM25Index;
//! use triblespace_search::tokens::hash_tokens;
//!
//! // 1. Build an in-memory index.
//! let mut b: BM25Builder = BM25Builder::new();
//! b.insert(Id::new([1; 16]).unwrap(), hash_tokens("the quick brown fox"));
//! b.insert(Id::new([2; 16]).unwrap(), hash_tokens("the lazy brown dog"));
//! b.insert(Id::new([3; 16]).unwrap(), hash_tokens("quick silver fox"));
//!
//! // 2. Build a succinct BM25 index in a single pass.
//! let idx: SuccinctBM25Index = b.build();
//!
//! // 3. Filter through the engine — constraint binds `doc`
//! //    only; `score_floor = 0.0` means "any matching doc".
//! let terms = hash_tokens("fox");
//! let docs: Vec<(Id,)> = find!(
//!     (doc: Id),
//!     idx.matches(doc, &terms, 0.0)
//! ).collect();
//! assert_eq!(docs.len(), 2);
//! ```
//!
//! See the `examples/` directory for runnable walkthroughs:
//! `compose_bm25_and_pattern` / `multi_term_bm25_search`
//! (BM25 + pattern joins), `compose_hnsw_and_pattern`
//! (vector similarity + pattern), `hybrid_search` (all
//! three composed in one `find!`), and `phrase_search` for
//! the typed-tokenizer pattern.
//!
//! [`jerky`]: https://docs.rs/jerky

pub mod bm25;
pub mod constraint;
pub mod hnsw;
pub mod nvfp4;
pub mod portable_bm25;
#[cfg(feature = "succinct")]
pub mod ring;
pub mod schemas;
#[cfg(feature = "semantic")]
pub mod semantic;
#[cfg(feature = "succinct")]
pub mod succinct;
pub mod text_bm25;
pub mod tokens;

/// Reference implementations for tests and benchmarks.
///
/// The types re-exported here are naive (canonical-key-order,
/// non-packed) forms that exist only to validate the succinct
/// builds and to measure "how much does jerky packing actually
/// save at this scale." They are not a production persistence
/// path: portable exact-TF BM25 uses [`portable_bm25`], while direct native
/// BM25 and HNSW use [`succinct`].
///
/// - [`BM25Index`][testing::BM25Index] — reference BM25 scoring
///   and query implementation. Produced by
///   [`bm25::BM25Builder::build_naive`].
/// - [`HNSWIndex`][testing::HNSWIndex] — node-major HNSW graph
///   with inline neighbour lists. Produced by
///   [`hnsw::HNSWBuilder::build_naive`]; also the input to
///   [`succinct::SuccinctHNSWIndex::from_naive`] for callers
///   who want to hold the naive form.
/// - [`FlatIndex`][testing::FlatIndex] /
///   [`FlatBuilder`][testing::FlatBuilder] — brute-force exact
///   k-NN baseline, used as HNSW's recall oracle.
pub mod testing {
    // `#[doc(inline)]` makes rustdoc render the re-exported
    // types' full docs at this path despite `#[doc(hidden)]` at
    // their original location — the blessed path shows up in
    // docs, the original doesn't.
    #[doc(inline)]
    pub use crate::bm25::BM25Index;
    #[doc(inline)]
    pub use crate::hnsw::{
        AttachedFlatIndex, AttachedHNSWIndex, FlatBuilder, FlatIndex, HNSWIndex,
    };
}

// Versioning policy: breaking byte-layout changes mint a new
// `BlobEncoding` id (see `PortableBM25Blob` in `portable_bm25.rs` and
// `SuccinctBM25Blob` / `SuccinctHNSWBlob` in `succinct.rs`). That metadata
// identity feeds derived typed
// schemas, but it is not an in-band runtime guard and does not
// make the Rust marker a new type. Persisted typed attributes or collection
// recipes that route handles to a reader must rotate with it. There is no
// single global version number; `git log docs/DESIGN.md` records
// the layout progression and the marker implementation is
// authoritative for the current identity.
