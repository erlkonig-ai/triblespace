//! BM25-style lexical / associative retrieval.
//!
//! Terms are 32-byte triblespace `Inline`s (as [`RawInline`], the
//! schema-erased byte array). Callers supply term values however
//! they want — [`crate::tokens::hash_tokens`] is one opt-in
//! helper that Blake3-hashes whitespace-separated tokens, but the
//! index is term-source-agnostic:
//!
//! | Term source | What this gets you |
//! | --- | --- |
//! | `hash(word)` | classic text search |
//! | entity `Id` | "docs mentioning this person" |
//! | tag `Id` | tag-weighted search |
//! | fragment `Id` | "docs citing this fragment" |
//!
//! The same schema handles all four.
//!
//! # Build and query
//!
//! ```
//! # use triblespace_search::bm25::BM25Builder;
//! # use triblespace_search::tokens::hash_tokens;
//! # use triblespace_core::id::Id;
//! let docs = [
//!     (Id::new([1; 16]).unwrap(), "the quick brown fox"),
//!     (Id::new([2; 16]).unwrap(), "the lazy brown dog"),
//!     (Id::new([3; 16]).unwrap(), "quick silver fox"),
//! ];
//! let mut b: BM25Builder = BM25Builder::new();
//! for (id, text) in &docs {
//!     b.insert(&*id, hash_tokens(text));
//! }
//! let index = b.build();
//!
//! // Query: how many docs mention "fox"?
//! let q = hash_tokens("fox");
//! let hits: Vec<_> = index.query_term(&q[0]).collect();
//! assert_eq!(hits.len(), 2);
//! ```
//!
//! # Current status
//!
//! This is the **naive** (non-succinct) implementation:
//! sorted-term table + flat `Vec<(doc_idx, score)>` postings.
//! Correctness first; the jerky/wavelet-matrix-backed succinct
//! version swaps in later behind the same public API.
//!
//! See `docs/DESIGN.md` for the target blob layout.

use std::collections::HashMap;
use std::marker::PhantomData;

use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::{Inline, InlineEncoding, IntoInline, RawInline};

/// Classic BM25 tuning. Defaults match Robertson & Zaragoza 2009.
const DEFAULT_K1: f32 = 1.5;
const DEFAULT_B: f32 = 0.75;

/// Accumulator for documents to be indexed. Add rows with [`insert`], then
/// [`build`] to produce a [`BM25Index`]. Repeated document keys join
/// canonically: occurrences within one row sum, while per-term frequencies
/// across rows take their maximum.
///
/// Generic over `D` (the doc-key [`InlineEncoding`]) and `T` (the
/// term [`InlineEncoding`]). Typical shapes:
///
/// - `BM25Builder<GenId, WordHash>` — classic text search
///   keyed by entity id; terms come from
///   [`crate::tokens::hash_tokens`] et al.
/// - `BM25Builder<Handle<UTF8String>, WordHash>` — keyed by a
///   text value (a title), compared by content handle.
/// - `BM25Builder<GenId, GenId>` — entity co-occurrence; terms
///   are themselves entity ids ("which fragments cite X?").
///
/// The two schemas buy compile-time safety: you can't
/// accidentally feed ngram terms into a word-hash index, or
/// query a title-keyed index with a GenId doc variable.
///
/// [`insert`]: Self::insert
/// [`build`]: Self::build
pub struct BM25Builder<D: InlineEncoding = GenId, T: InlineEncoding = crate::tokens::WordHash> {
    pub(crate) docs: Vec<(RawInline, Vec<RawInline>)>,
    pub(crate) k1: f32,
    pub(crate) b: f32,
    pub(crate) _phantom: PhantomData<(D, T)>,
}

// Manual `Clone` impl (not derive) so the bound stays on
// `D: InlineEncoding, T: InlineEncoding` rather than the auto-derive's
// `D: Clone, T: Clone` — `PhantomData<(D, T)>` is `Clone`
// regardless of `D` / `T`, and the rest of the fields are
// already `Clone`.
impl<D: InlineEncoding, T: InlineEncoding> Clone for BM25Builder<D, T> {
    fn clone(&self) -> Self {
        Self {
            docs: self.docs.clone(),
            k1: self.k1,
            b: self.b,
            _phantom: PhantomData,
        }
    }
}

impl<D: InlineEncoding, T: InlineEncoding> Default for BM25Builder<D, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: InlineEncoding, T: InlineEncoding> BM25Builder<D, T> {
    /// Create an empty builder with the standard BM25 tuning.
    ///
    /// Type parameters are usually inferred from downstream
    /// [`insert`][Self::insert] calls (the doc key's
    /// [`IntoInline<D>`] impl pins `D`, the term vector pins `T`).
    /// When you need to be explicit — e.g. for an index you'll
    /// populate only after some plumbing — spell the schemas
    /// with a turbofish:
    ///
    /// ```ignore
    /// let mut b: BM25Builder<GenId, BigramHash> = BM25Builder::new();
    /// ```
    ///
    /// The struct's own defaults (`D = GenId`, `T = WordHash`)
    /// let you spell only one schema when the other is the
    /// common text-search shape:
    ///
    /// ```ignore
    /// let mut b: BM25Builder<Handle<UTF8String>> = BM25Builder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            docs: Vec::new(),
            k1: DEFAULT_K1,
            b: DEFAULT_B,
            _phantom: PhantomData,
        }
    }

    /// Override the `k1` term-frequency saturation parameter.
    pub fn k1(mut self, k1: f32) -> Self {
        self.k1 = k1;
        self
    }

    /// Override the `b` length-normalization parameter.
    pub fn b(mut self, b: f32) -> Self {
        self.b = b;
        self
    }

    /// Add one document row. `key` is anything that converts to a
    /// `Inline<D>` — pass a `Inline<GenId>` directly, an
    /// `&Id` for entity-keyed indexes, or any user type that
    /// implements `IntoInline<D>`. `terms` is the caller's
    /// tokenization under schema `T` (see
    /// [`crate::tokens::hash_tokens`] for the usual token-handle
    /// default). Order of terms is irrelevant; duplicates
    /// contribute to this row's term frequency. If several rows use the same
    /// key, each term's final frequency is the maximum across those row-local
    /// counts. An empty row still preserves its document key.
    ///
    /// Accepts any `IntoIterator<Item = Inline<T>>`, so a
    /// `Vec<Inline<T>>` from `hash_tokens(...)` works directly,
    /// and so does an iterator chain
    /// (`tokens.iter().filter(...).copied()`, `(0..n).map(...)`,
    /// etc.) without an intermediate `.collect()`.
    pub fn insert<K, I>(&mut self, key: K, terms: I)
    where
        K: IntoInline<D>,
        I: IntoIterator<Item = Inline<T>>,
    {
        // Inline<_> is repr(transparent) around RawInline; strip
        // the phantom at the boundary, store raw bytes.
        let key_val: Inline<D> = key.to_inline();
        let term_rows: Vec<RawInline> = terms.into_iter().map(|v| v.raw).collect();
        self.docs.push((key_val.raw, term_rows));
    }

    /// Consume the builder and produce a succinct BM25 index,
    /// ready to `put` into a pile or query directly. This is the
    /// production path — the naive in-memory [`BM25Index`] is
    /// kept only as a reference oracle (see
    /// [`build_naive`][Self::build_naive]).
    #[cfg(feature = "succinct")]
    pub fn build(self) -> crate::succinct::SuccinctBM25Index<D, T> {
        crate::succinct::SuccinctBM25Index::from_builder(self)
    }

    /// Naive canonical reference index. Runs BM25 scoring in the simplest
    /// possible way (sorted document keys, flat `Vec<(doc_idx, score)>`
    /// postings) — useful as a
    /// correctness oracle when validating the succinct form, or
    /// when benchmarking the scoring cost independent of jerky
    /// encoding overhead. Most callers want [`build`][Self::build].
    pub fn build_naive(self) -> BM25Index<D, T> {
        self.build_naive_with_threads(1)
    }

    /// Parallelized naive build — reference implementation with
    /// sharded tf accumulation across `threads` worker threads.
    /// Output is byte-identical to single-threaded
    /// [`build_naive`][Self::build_naive]. Use [`build`][Self::build]
    /// for the production path.
    pub fn build_naive_with_threads(self, threads: usize) -> BM25Index<D, T> {
        let Self {
            docs: input_docs,
            k1,
            b,
            _phantom,
        } = self;
        let docs = canonicalize_docs(input_docs);
        let n_docs = docs.len();

        // Per-doc token count; average doc length for normalization.
        let doc_lens: Vec<u32> = docs.iter().map(|(_, t)| t.len() as u32).collect();
        let avg_doc_len = if n_docs == 0 {
            0.0
        } else {
            doc_lens.iter().map(|&n| n as f64).sum::<f64>() as f32 / n_docs as f32
        };

        let keys: Vec<RawInline> = docs.iter().map(|(key, _)| *key).collect();

        let term_to_tfs = if threads <= 1 || n_docs < 2 {
            // Single-threaded tf accumulation — cheap for small
            // corpora; also what we get when threads == 1.
            let mut m: HashMap<RawInline, HashMap<u32, u32>> = HashMap::new();
            for (doc_idx, (_, terms)) in docs.into_iter().enumerate() {
                accumulate_tfs(&mut m, doc_idx as u32, terms);
            }
            m
        } else {
            // Shard docs into `threads` contiguous ranges. Each
            // worker builds a local map over its slice using the
            // *global* doc_idx. Merge at the end.
            let threads = threads.min(n_docs);
            let base_chunk = n_docs / threads;
            let extra = n_docs % threads;

            // Partition `docs` into owned chunks the workers can
            // consume. We keep the start doc_idx of each chunk
            // to preserve global indexing.
            let mut starts = Vec::with_capacity(threads);
            let mut chunks: Vec<Vec<(RawInline, Vec<RawInline>)>> = Vec::with_capacity(threads);
            let mut docs_iter = docs.into_iter();
            let mut idx = 0usize;
            for t in 0..threads {
                let size = base_chunk + if t < extra { 1 } else { 0 };
                let chunk: Vec<_> = (&mut docs_iter).take(size).collect();
                starts.push(idx);
                idx += size;
                chunks.push(chunk);
            }

            // Scoped threads so references to `chunks` stay alive.
            let locals: Vec<HashMap<RawInline, HashMap<u32, u32>>> = std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(threads);
                for (shard_start, chunk) in starts.iter().zip(chunks) {
                    let start = *shard_start as u32;
                    handles.push(s.spawn(move || {
                        let mut m: HashMap<RawInline, HashMap<u32, u32>> = HashMap::new();
                        for (i, (_, terms)) in chunk.into_iter().enumerate() {
                            accumulate_tfs(&mut m, start + i as u32, terms);
                        }
                        m
                    }));
                }
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });

            // Merge local maps into one. Since shards cover
            // disjoint doc_idx ranges, each term's per-shard tf
            // submaps have disjoint keys — `extend` without
            // collision checks is sound and avoids the per-entry
            // hash lookup that `or_insert` costs.
            let mut merged: HashMap<RawInline, HashMap<u32, u32>> = HashMap::new();
            for local in locals {
                for (term, tfs) in local {
                    merged.entry(term).or_default().extend(tfs);
                }
            }
            merged
        };

        // Sort terms ascending so the term table supports binary
        // search (matches the succinct layout).
        let mut terms: Vec<RawInline> = term_to_tfs.keys().copied().collect();
        terms.sort_unstable();

        // Per-term postings with pre-baked BM25 scores. IDF follows
        // the Robertson smoothed form: ln(1 + (N - df + 0.5) /
        // (df + 0.5)).
        let mut offsets: Vec<u32> = Vec::with_capacity(terms.len() + 1);
        offsets.push(0);
        let mut postings: Vec<(u32, f32)> = Vec::new();

        let n = n_docs as f32;
        for term in &terms {
            let tfs = &term_to_tfs[term];
            let df = tfs.len() as f32;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

            let mut entries: Vec<(u32, f32)> = tfs
                .iter()
                .map(|(&doc_idx, &tf)| {
                    let tf = tf as f32;
                    let dl = doc_lens[doc_idx as usize] as f32;
                    let norm = if avg_doc_len > 0.0 {
                        1.0 - b + b * (dl / avg_doc_len)
                    } else {
                        1.0
                    };
                    let score = idf * (tf * (k1 + 1.0)) / (tf + k1 * norm);
                    (doc_idx, score)
                })
                .collect();
            // Postings sorted by doc_idx for future merge-join.
            entries.sort_unstable_by_key(|&(idx, _)| idx);
            postings.extend(entries);
            offsets.push(postings.len() as u32);
        }

        BM25Index {
            keys,
            doc_lens,
            avg_doc_len,
            terms,
            offsets,
            postings,
            k1,
            b,
            _phantom,
        }
    }
}

/// Canonicalize builder rows under the same `(Docs, F)` join used by the
/// succinct and portable representations. Repetitions within one row sum;
/// rows sharing a document key join by pointwise max. Document keys are kept
/// even when their joined token bag is empty and sorted for deterministic
/// internal codes.
fn canonicalize_docs(docs: Vec<(RawInline, Vec<RawInline>)>) -> Vec<(RawInline, Vec<RawInline>)> {
    let mut joined: HashMap<RawInline, HashMap<RawInline, u32>> = HashMap::new();
    for (key, terms) in docs {
        let mut row_tfs: HashMap<RawInline, u32> = HashMap::new();
        for term in terms {
            let slot = row_tfs.entry(term).or_default();
            *slot = slot
                .checked_add(1)
                .expect("BM25 term frequency exceeds u32::MAX");
        }
        let doc_tfs = joined.entry(key).or_default();
        for (term, tf) in row_tfs {
            doc_tfs
                .entry(term)
                .and_modify(|old| *old = (*old).max(tf))
                .or_insert(tf);
        }
    }

    let mut rows: Vec<_> = joined
        .into_iter()
        .map(|(key, tfs)| {
            let mut tfs: Vec<_> = tfs.into_iter().collect();
            tfs.sort_unstable_by_key(|(term, _)| *term);
            let terms = tfs
                .into_iter()
                .flat_map(|(term, tf)| std::iter::repeat_n(term, tf as usize))
                .collect();
            (key, terms)
        })
        .collect();
    rows.sort_unstable_by_key(|(key, _)| *key);
    rows
}

/// Accumulate token-frequency counts for one doc into `m`.
fn accumulate_tfs(
    m: &mut HashMap<RawInline, HashMap<u32, u32>>,
    doc_idx: u32,
    terms: Vec<RawInline>,
) {
    for term in terms {
        let entry = m.entry(term).or_default().entry(doc_idx).or_insert(0);
        *entry += 1;
    }
}

/// In-memory BM25 index — reference / oracle form. The
/// canonical path is [`crate::testing::BM25Index`];
/// `#[doc(hidden)]` at this location so the blessed path is
/// the only one that shows up in rendered docs.
///
/// Produce via [`BM25Builder::build_naive`]. All scores are
/// pre-baked at build time: per-(doc, term) BM25 weight with
/// saturating term frequency (`k1`) and length-normalized doc
/// length (`b`).
#[doc(hidden)]
pub struct BM25Index<D: InlineEncoding = GenId, T: InlineEncoding = crate::tokens::WordHash> {
    /// Per-doc 32-byte keys. Stored raw; `Inline<D>` at the API
    /// boundary.
    keys: Vec<RawInline>,
    doc_lens: Vec<u32>,
    avg_doc_len: f32,
    terms: Vec<RawInline>,
    offsets: Vec<u32>,
    postings: Vec<(u32, f32)>,
    k1: f32,
    b: f32,
    _phantom: PhantomData<(D, T)>,
}

impl<D: InlineEncoding, T: InlineEncoding> std::fmt::Debug for BM25Index<D, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BM25Index")
            .field("n_docs", &self.keys.len())
            .field("n_terms", &self.terms.len())
            .field("avg_doc_len", &self.avg_doc_len)
            .field("k1", &self.k1)
            .field("b", &self.b)
            .finish()
    }
}

impl<D: InlineEncoding, T: InlineEncoding> Clone for BM25Index<D, T> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            doc_lens: self.doc_lens.clone(),
            avg_doc_len: self.avg_doc_len,
            terms: self.terms.clone(),
            offsets: self.offsets.clone(),
            postings: self.postings.clone(),
            k1: self.k1,
            b: self.b,
            _phantom: PhantomData,
        }
    }
}

impl<D: InlineEncoding, T: InlineEncoding> BM25Index<D, T> {
    /// Number of documents in the index.
    pub fn doc_count(&self) -> usize {
        self.keys.len()
    }

    /// Number of distinct terms.
    pub fn term_count(&self) -> usize {
        self.terms.len()
    }

    /// Average document length in the corpus.
    pub fn avg_doc_len(&self) -> f32 {
        self.avg_doc_len
    }

    /// Look up a term's posting list.
    ///
    /// Returns `(Inline<D>, f32)` pairs in posting-list order.
    /// Empty iterator if the term is absent.
    pub fn query_term<'a>(
        &'a self,
        term: &Inline<T>,
    ) -> impl Iterator<Item = (Inline<D>, f32)> + 'a {
        let lo = self.terms.binary_search(&term.raw).ok();
        let range = match lo {
            Some(i) => self.offsets[i] as usize..self.offsets[i + 1] as usize,
            None => 0..0,
        };
        self.postings[range]
            .iter()
            .map(|&(doc_idx, score)| (Inline::<D>::new(self.keys[doc_idx as usize]), score))
    }

    /// Score a multi-term query as the sum of per-term BM25
    /// weights (standard OR-like bag-of-words).
    ///
    /// Returned `(Inline<D>, f32)` pairs are sorted descending by score, then
    /// ascending by raw document key for ties. No top-k truncation — caller
    /// slices what they need.
    pub fn query_multi(&self, terms: &[Inline<T>]) -> Vec<(Inline<D>, f32)> {
        // Internal document codes follow canonical raw-key order. Keeping
        // aggregation and tie-breaking in that compact domain avoids hashing
        // and repeatedly comparing 32-byte keys without changing identity.
        let mut acc: HashMap<u32, f32> = HashMap::new();
        for term in terms {
            let Ok(term_index) = self.terms.binary_search(&term.raw) else {
                continue;
            };
            let range = self.offsets[term_index] as usize..self.offsets[term_index + 1] as usize;
            for &(doc_code, score) in &self.postings[range] {
                *acc.entry(doc_code).or_insert(0.0) += score;
            }
        }
        let mut ranked: Vec<(u32, f32)> = acc.into_iter().collect();
        ranked.sort_unstable_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        ranked
            .into_iter()
            .map(|(doc_code, score)| (Inline::<D>::new(self.keys[doc_code as usize]), score))
            .collect()
    }

    /// Number of documents containing this term.
    pub fn doc_frequency(&self, term: &Inline<T>) -> usize {
        self.terms
            .binary_search(&term.raw)
            .ok()
            .map(|i| (self.offsets[i + 1] - self.offsets[i]) as usize)
            .unwrap_or(0)
    }

    /// BM25 `k1` used when this index was built.
    pub fn k1(&self) -> f32 {
        self.k1
    }

    /// BM25 `b` used when this index was built.
    pub fn b(&self) -> f32 {
        self.b
    }

    /// Raw doc-length table. `doc_lens()[i]` is the token count
    /// of the document at internal index `i`.
    pub fn doc_lens(&self) -> &[u32] {
        &self.doc_lens
    }

    /// Doc-key table: `keys()[i]` is the external 32-byte
    /// `RawInline` for internal index `i`. Exposed so succinct
    /// re-encoders can snapshot the table without roundtripping
    /// through query_term.
    pub fn keys(&self) -> &[RawInline] {
        &self.keys
    }

    /// Sorted 32-byte term table. Used by succinct re-encoders
    /// and anyone implementing a custom query plan over this
    /// index's internals.
    pub fn terms_slice(&self) -> &[RawInline] {
        &self.terms
    }

    /// Per-term posting list (internal `doc_idx` + score) for the
    /// term at sorted-table position `t`. Returns `&[]` if out of
    /// range. Lower-level than [`query_term`], which joins on
    /// external doc keys.
    ///
    /// [`query_term`]: Self::query_term
    pub fn postings_for(&self, t: usize) -> &[(u32, f32)] {
        if t >= self.terms.len() {
            return &[];
        }
        let lo = self.offsets[t] as usize;
        let hi = self.offsets[t + 1] as usize;
        &self.postings[lo..hi]
    }

    /// Theoretical size of the naive flat-array serialization in
    /// bytes — the baseline the succinct blob compresses against.
    /// Used by benchmarks and regression tests that want a "how
    /// big would this be without jerky" number without actually
    /// materializing the bytes.
    ///
    /// Layout this corresponds to: 20 B scalar header + `n_docs ×
    /// 32 B` keys + `n_docs × 4 B` doc_lens + `n_terms × 32 B`
    /// terms + `(n_terms + 1) × 4 B` offsets + `total_postings ×
    /// 8 B` postings.
    pub fn byte_size(&self) -> usize {
        20 + self.keys.len() * 32
            + self.doc_lens.len() * 4
            + self.terms.len() * 32
            + self.offsets.len() * 4
            + self.postings.len() * 8
    }
}

impl<D: InlineEncoding, T: InlineEncoding> PartialEq for BM25Index<D, T> {
    /// Bit-exact equality, including on `f32` fields — used by
    /// parallel-build tests that assert byte-identical output
    /// across thread counts. Canonical document and term ordering makes score
    /// computation deterministic for the same logical `(Docs, F)` carrier, so
    /// the f32s come out bit-equal.
    fn eq(&self, other: &Self) -> bool {
        fn f32_bit_eq(a: f32, b: f32) -> bool {
            a.to_bits() == b.to_bits()
        }
        self.keys == other.keys
            && self.doc_lens == other.doc_lens
            && f32_bit_eq(self.avg_doc_len, other.avg_doc_len)
            && self.terms == other.terms
            && self.offsets == other.offsets
            && self.postings.len() == other.postings.len()
            && self
                .postings
                .iter()
                .zip(other.postings.iter())
                .all(|(a, b)| a.0 == b.0 && f32_bit_eq(a.1, b.1))
            && f32_bit_eq(self.k1, other.k1)
            && f32_bit_eq(self.b, other.b)
    }
}

impl<D: InlineEncoding, T: InlineEncoding> Eq for BM25Index<D, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::hash_tokens;
    use triblespace_core::id::Id;

    fn id(byte: u8) -> Id {
        // `Id::new` returns None for the nil [0; 16] id.
        assert!(byte != 0, "test fixture: 0 is the nil Id");
        Id::new([byte; 16]).unwrap()
    }

    /// Test helper: the 32-byte `Inline<GenId>` representation of
    /// the Id used by `id(byte)`. Matches what `BM25Builder::insert`
    /// stores internally, so `query_term` results can be
    /// compared against it.
    fn id_key(byte: u8) -> RawInline {
        let v: Inline<GenId> = id(byte).to_inline();
        v.raw
    }

    #[test]
    fn empty_index_is_queryable() {
        let idx = BM25Builder::<GenId, crate::tokens::WordHash>::new().build();
        assert_eq!(idx.doc_count(), 0);
        assert_eq!(idx.term_count(), 0);
        let term: Inline<crate::tokens::WordHash> = Inline::new([0u8; 32]);
        assert!(idx.query_term(&term).next().is_none());
    }

    #[test]
    fn duplicate_rows_join_by_max_and_preserve_empty_documents() {
        let alpha = hash_tokens("alpha")[0];
        let beta = hash_tokens("beta")[0];
        let gamma = hash_tokens("gamma")[0];
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), std::iter::empty());
        b.insert(id(2), [alpha, alpha, beta]);
        b.insert(id(2), [alpha, beta, beta, beta, gamma]);

        let naive = b.clone().build_naive();
        let succinct = b.build();
        assert_eq!(naive.doc_count(), 2);
        assert_eq!(succinct.doc_count(), 2);

        let empty = naive
            .keys()
            .iter()
            .position(|key| *key == id_key(1))
            .unwrap();
        let joined = naive
            .keys()
            .iter()
            .position(|key| *key == id_key(2))
            .unwrap();
        assert_eq!(naive.doc_lens()[empty], 0);
        assert_eq!(naive.doc_lens()[joined], 6); // max(2,1)+max(1,3)+max(0,1)

        let reconstructed = succinct.reconstruct_docs();
        let (_, empty_terms) = reconstructed
            .iter()
            .find(|(key, _)| *key == id_key(1))
            .unwrap();
        let (_, joined_terms) = reconstructed
            .iter()
            .find(|(key, _)| *key == id_key(2))
            .unwrap();
        assert!(empty_terms.is_empty());
        let frequencies = joined_terms.iter().fold(HashMap::new(), |mut acc, term| {
            *acc.entry(*term).or_insert(0u32) += 1;
            acc
        });
        assert_eq!(frequencies[&alpha.raw], 2);
        assert_eq!(frequencies[&beta.raw], 3);
        assert_eq!(frequencies[&gamma.raw], 1);
    }

    #[test]
    fn equal_scores_use_raw_document_key_as_tie_break() {
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(3), hash_tokens("same terms"));
        b.insert(id(1), hash_tokens("same terms"));
        b.insert(id(2), hash_tokens("same terms"));
        let terms = hash_tokens("same");

        for ranked in [
            b.clone().build_naive().query_multi(&terms),
            b.build().query_multi(&terms),
        ] {
            let keys: Vec<_> = ranked.iter().map(|(key, _)| key.raw).collect();
            assert_eq!(keys, [id_key(1), id_key(2), id_key(3)]);
            assert!(ranked.windows(2).all(|pair| pair[0].1 == pair[1].1));
        }
    }

    #[test]
    fn insert_indexes_by_string_key() {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::inline::encodings::hash::Handle;
        use triblespace_core::inline::{Inline, IntoInline};

        let mut b: BM25Builder<Handle<UTF8String>> = BM25Builder::new();
        let red: Inline<Handle<UTF8String>> = "red".to_inline();
        let blue: Inline<Handle<UTF8String>> = "blue".to_inline();
        // Two docs keyed by string value rather than entity id.
        // The doc body is the token stream; the *key* is a
        // `Inline<Handle<UTF8String>>`, so a later query can find "docs
        // whose key/field value is 'red'".
        b.insert(red, hash_tokens("a tomato is red"));
        b.insert(blue, hash_tokens("the ocean is blue"));
        let idx = b.build();
        assert_eq!(idx.doc_count(), 2);

        // "red" appears in one doc, "blue" in another.
        let red_hits: Vec<_> = idx.query_term(&hash_tokens("red")[0]).collect();
        let blue_hits: Vec<_> = idx.query_term(&hash_tokens("blue")[0]).collect();
        assert_eq!(red_hits.len(), 1);
        assert_eq!(blue_hits.len(), 1);
        // Keys come back as `Inline<Handle<UTF8String>>` since that's the
        // doc schema; compare against the expected key.
        let red_raw: Inline<Handle<UTF8String>> = "red".to_inline();
        let blue_raw: Inline<Handle<UTF8String>> = "blue".to_inline();
        assert_eq!(red_hits[0].0, red_raw);
        assert_eq!(blue_hits[0].0, blue_raw);
    }

    #[test]
    fn three_docs_basic() {
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("the quick brown fox"));
        b.insert(id(2), hash_tokens("the lazy brown dog"));
        b.insert(id(3), hash_tokens("quick silver fox"));
        let idx = b.build();
        assert_eq!(idx.doc_count(), 3);

        // "fox" appears in docs 1 and 3.
        let fox = hash_tokens("fox");
        let hits: Vec<_> = idx.query_term(&fox[0]).collect();
        assert_eq!(hits.len(), 2);
        let doc_ids: Vec<_> = hits.iter().map(|(d, _)| *d).collect();
        assert!(doc_ids.iter().any(|v| v.raw == id_key(1)));
        assert!(doc_ids.iter().any(|v| v.raw == id_key(3)));

        // "the" is in doc 1 and doc 2.
        let the = hash_tokens("the");
        assert_eq!(idx.doc_frequency(&the[0]), 2);

        // Missing term returns nothing.
        let missing = hash_tokens("banana");
        assert!(idx.query_term(&missing[0]).next().is_none());
    }

    #[test]
    fn idf_prefers_rare_terms() {
        let mut b: BM25Builder = BM25Builder::new();
        // "rare" appears once, "common" appears in every doc.
        for i in 1..=10 {
            b.insert(id(i), hash_tokens("common common"));
        }
        b.insert(id(100), hash_tokens("common rare"));
        let idx = b.build();

        let rare = hash_tokens("rare");
        let common = hash_tokens("common");
        let rare_score = idx.query_term(&rare[0]).next().unwrap().1;
        let common_score = idx
            .query_term(&common[0])
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap()
            .1;
        assert!(
            rare_score > common_score,
            "rare_score={rare_score}, common_score={common_score}"
        );
    }

    #[test]
    fn term_frequency_saturates() {
        // Two docs, one contains "foo" once, one 100 times. With
        // k1 = 1.5 the second's score should be higher but not
        // 100x higher — saturation.
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("foo bar baz"));
        let many: String = "foo ".repeat(100);
        b.insert(id(2), hash_tokens(&many));
        let idx = b.build();

        let foo = hash_tokens("foo");
        let scores: HashMap<RawInline, f32> =
            idx.query_term(&foo[0]).map(|(v, s)| (v.raw, s)).collect();
        let s1 = scores[&id_key(1)];
        let s2 = scores[&id_key(2)];
        assert!(s2 > s1);
        assert!(
            s2 < s1 * 20.0,
            "tf saturation should keep ratio moderate: {s1} -> {s2}"
        );
    }

    #[test]
    fn multi_term_query_sums() {
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("quick brown fox"));
        b.insert(id(2), hash_tokens("quick red fox"));
        b.insert(id(3), hash_tokens("slow brown dog"));
        let idx = b.build();

        let q = hash_tokens("quick fox");
        let ranked = idx.query_multi(&q);
        // Docs 1 and 2 have both terms; doc 3 has neither.
        assert_eq!(ranked.len(), 2);
        let top_ids: Vec<[u8; 32]> = ranked.iter().map(|(d, _)| d.raw).collect();
        assert!(top_ids.contains(&id_key(1)));
        assert!(top_ids.contains(&id_key(2)));
        // Results are sorted descending by score.
        assert!(ranked[0].1 >= ranked[1].1);
    }

    #[test]
    fn tuning_params_round_trip() {
        let b = BM25Builder::<GenId, crate::tokens::WordHash>::new()
            .k1(1.2)
            .b(0.5);
        let idx = b.build();
        assert!((idx.k1() - 1.2).abs() < 1e-6);
        assert!((idx.b() - 0.5).abs() < 1e-6);
    }

    fn build_sample_index() -> BM25Index {
        let mut b: BM25Builder = BM25Builder::new().k1(1.4).b(0.72);
        b.insert(id(1), hash_tokens("the quick brown fox"));
        b.insert(id(2), hash_tokens("the lazy brown dog"));
        b.insert(id(3), hash_tokens("quick silver fox jumps"));
        b.build_naive()
    }

    #[test]
    fn byte_size_matches_naive_layout() {
        // Spot-check that `byte_size()` matches the formula it
        // documents. At 3 docs with the sample corpus we know the
        // exact term count, so the expected number is derivable.
        let idx = build_sample_index();
        let expected = 20
            + idx.keys().len() * 32
            + idx.doc_lens().len() * 4
            + idx.terms_slice().len() * 32
            + (idx.terms_slice().len() + 1) * 4
            + (0..idx.term_count())
                .map(|t| idx.postings_for(t).len())
                .sum::<usize>()
                * 8;
        assert_eq!(idx.byte_size(), expected);
    }

    #[test]
    fn build_is_deterministic() {
        // Same corpus → same index. Content-addressing of the
        // succinct form depends on this being exactly reproducible
        // across runs; PartialEq here is bit-exact including f32.
        let a = build_sample_index();
        let b = build_sample_index();
        assert_eq!(a, b);
    }

    #[test]
    fn parallel_build_matches_single_thread() {
        // Build a richer corpus so shards actually have work to
        // do. Threaded and single-threaded paths must produce
        // bit-identical indexes.
        fn build(threads: usize) -> BM25Index {
            let mut b: BM25Builder = BM25Builder::new();
            for i in 1..=50u32 {
                let text = format!(
                    "doc {i} text about {} {}",
                    (i % 5) + 1,
                    (i.wrapping_mul(7)) % 13
                );
                let byte = (i as u8).max(1);
                b.insert(id(byte), hash_tokens(&text));
            }
            b.build_naive_with_threads(threads)
        }
        let serial = build(1);
        for t in [2usize, 3, 4, 8] {
            assert_eq!(
                build(t),
                serial,
                "threads={t} produced a different index than serial"
            );
        }
    }

    #[test]
    fn parallel_build_on_empty_corpus() {
        let idx = BM25Builder::<GenId, crate::tokens::WordHash>::new().build_naive_with_threads(4);
        assert_eq!(idx.doc_count(), 0);
        assert_eq!(idx.term_count(), 0);
    }

    #[test]
    fn parallel_build_threads_cap_at_doc_count() {
        // 3 docs × 16 threads — the builder caps threads at n_docs
        // and doesn't spawn idle workers.
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("one two three"));
        b.insert(id(2), hash_tokens("two three four"));
        b.insert(id(3), hash_tokens("three four five"));
        let idx = b.build_naive_with_threads(16);
        assert_eq!(idx.doc_count(), 3);
        // "three" shows up in all 3 docs.
        let three = hash_tokens("three")[0];
        assert_eq!(idx.doc_frequency(&three), 3);
    }

    #[test]
    fn ngrams_enable_prefix_queries() {
        // Prefix / substring queries via an NgramHash index.
        // Query "fox" as a single 3-gram and recover docs that
        // contain the extended forms ("foxes", "fox at night").
        use crate::tokens::{ngram_tokens, NgramHash};

        let mut b: BM25Builder<GenId, NgramHash> = BM25Builder::new();
        b.insert(id(1), ngram_tokens("foxes are cunning", 3));
        b.insert(id(2), ngram_tokens("the dog barks", 3));
        b.insert(id(3), ngram_tokens("silver fox at night", 3));
        let idx = b.build();

        let q = ngram_tokens("fox", 3);
        let hits: Vec<_> = idx.query_multi(&q);
        let doc_ids: Vec<_> = hits.iter().map(|(d, _)| *d).collect();
        assert!(
            doc_ids.iter().any(|v| v.raw == id_key(1)),
            "prefix should match 'foxes'"
        );
        assert!(
            doc_ids.iter().any(|v| v.raw == id_key(3)),
            "prefix should match 'fox'"
        );
        assert!(
            !doc_ids.iter().any(|v| v.raw == id_key(2)),
            "must not match 'dog'"
        );
    }
}
