# triblespace-search

Content-addressed BM25 + HNSW indexes on top of
[triblespace](https://github.com/triblespace/triblespace-rs) piles.

Three typed blob representations. The portable BM25 carrier is
architecture-independent; the native query accelerators are loaded zero-copy
via [anybytes] and [jerky]:

- **`PortableBM25Index`** — architecture-independent lexical / associative
  retrieval carrier. Its canonical bytes carry sorted document and term
  domains plus positive exact `u32` frequencies; document lengths, IDF, and
  scores are derived after attachment. Portable merge is document union plus
  pointwise maximum frequency.
- **`SuccinctBM25Index`** (SB25 blob) — lexical / associative
  retrieval for direct native callers. Terms are 32-byte triblespace
  `Inline`s, so the index handles text search, entity co-occurrence, and tag
  weighting with the same schema. Document indices and exact
  `u32` term frequencies are bit-packed via jerky
  `CompactVector`s; scores are derived at query time.
- **`SuccinctHNSWIndex`** (SH25 blob) — approximate cosine
  similarity over caller-supplied embedding handles. Its graph
  is stored in a succinct jerky-backed representation. Nodes are
  `Handle<Embedding>` values; the caller's
  doc-to-embedding mapping is a trible they own, not a shadow
  datamodel inside the index.

The authoritative schema identities live in each marker type's
`MetaDescribe` implementation. A format rotation must also rotate any
persisted typed attribute or collection mapping that routes handles to that
reader; changing the metadata ID does not create a new Rust type or perform a
runtime check.

Index blobs are immutable. Direct builders and collection derivations return
fresh content-addressed handles. Portable BM25 elements join canonically;
native HNSW and succinct-HNSW builders return standalone immutable artifacts.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design.

[anybytes]: https://github.com/triblespace/anybytes
[jerky]: https://github.com/triblespace/jerky

## Status

**Pre-alpha.** Tracks the workspace version (`0.36.0`); the API
shapes are settling but not yet stable for downstream pinning. The
naive, portable, and native succinct paths are shipped end-to-end (see
[`docs/DESIGN.md`](docs/DESIGN.md) for the full picture and
[`CHANGELOG.md`](CHANGELOG.md) for the recent shape changes). The
remaining open items are perf/encoding refinements, not architecture.

### What works today

* **`BM25Index`** (naive in-memory): build + multi-term query,
  content-addressed byte serialization, plus a single
  triblespace `Constraint`: `matches(doc, &terms, score_floor)`
  — binds `doc` only; score is a fixed parameter. Pair with
  `idx.score(&doc, terms)` to recompute precise scores after
  the engine filters.
* **`PortableBM25Index`**: strict, canonical exact-TF carrier. Its bytes
  contain no native `usize`, padding, Jerky arena, persisted float, score, or
  redundant document-length table. Attachment retains the encoded backing;
  `index.query()` prepares the omitted scoring statistics and speaks the
  constraint surface. `PortableBM25View` does the same over a shared-member
  cover without constructing a serialized union.
* **`SuccinctBM25Index`**: jerky-backed zero-copy view — doc
  keys via `CompressedUniverse`, terms as a typed
  `View<[[u8; 32]]>` row table, doc-lengths + postings via
  `CompactVector`. The index *is* its blob: every section lives
  in one shared `anybytes::ByteArea`, so `ToBlob`/`TryFromBlob`
  are O(1) refcounted handovers.
* **`FlatIndex`**: brute-force exact cosine baseline, useful for
  ground truth and small corpora. Its `similar_to` result is complete.
* **`HNSWIndex`** (naive Malkov & Yashunin 2018) with
  deterministic level sampling, ef-search, byte serialization.
  Validated at 1 000 handles / 32-dim against `FlatIndex` at
  ≥ 70 % above-threshold recall.
* **`SuccinctHNSWIndex`**: jerky-backed zero-copy view — a
  `View<[[u8; 32]]>` row table of embedding handles plus a CSR
  graph encoded as two `CompactVector`s, all in one canonical
  `Bytes`. Nodes IS the handle; the caller's doc → embedding
  mapping lives in their tribles, not here.
* **Exact pair predicate** `cosine_at_least(a, b, score_floor)` on
  every attached view. It never invents a domain: other constraints source
  both variables, then the predicate filters pairs symmetrically.
* **Directional retrieval snapshot** `similar_to(probe, var,
  score_floor)`. Flat is complete; HNSW and succinct HNSW are approximate.
  Every backend freezes native order and duplicate occurrences at constraint
  construction.
* **Shared constraint traits** `CosineSimilarity` (HNSW, Flat,
  SuccinctHNSW) + `BM25Queryable` (naive + portable + succinct BM25).
* **`matches_text(doc, text, floor)`** + **`score_text(doc, text)`**:
  word-hash-keyed sugar over `matches` and `score` — tokenises the
  query string with `hash_tokens` internally, available on indexes
  whose term schema is `WordHash` (the default).
* **`tokens::hash_tokens`**: opt-in whitespace + lowercase word
  tokenizer that also preserves non-ASCII Unicode symbols as extended
  grapheme terms, then Blake3-hashes each term into 32 bytes.
* **`tokens::ngram_tokens`**: character n-gram tokenizer (n
  namespaced into the hash) for prefix / typo matching.
  Compose with `hash_tokens` to get both exact and fuzzy
  matching through a single BM25 index.
* **`tokens::code_tokens`**: identifier tokenizer — splits on
  camelCase, `snake_case`, digit boundaries, and acronyms
  (`HTMLParser` → `html`, `parser`). Lowercased output hashes
  the same as `hash_tokens`, so code and prose can share one
  index.
* **`tokens::bigram_tokens`**: word-level bigram tokenizer in its
  own `BigramHash` term schema. Index it beside the `WordHash`
  index to answer phrase queries — `bigram_tokens("quick brown")`
  hashes only the ordered pair, so a doc matches iff the two words
  appear adjacently.
* **`schemas::F32LE`**: general-purpose `InlineEncoding` for packing
  an `f32` into a 32-byte `Inline<F32LE>`. BM25 scores are returned
  directly and are not persisted through this schema.
* Eight runnable examples:
  - `query_demo` — text search, multi-term ranking via
    filter+rescore, value-as-term citation search.
  - `compose_bm25_and_pattern` — BM25 + `pattern!` over a
    `TribleSet` in one `find!`.
  - `multi_term_bm25_search` — multi-term `matches` filter
    joined with a `pattern!` author filter, ranked by
    post-collect `idx.score`.
  - `compose_hnsw_and_pattern` — a fixed-probe `SimilarTo` snapshot
    composed with `pattern!`.
  - `hybrid_search` — BM25 + similarity + `pattern!` in one
    `find!`; both filters active simultaneously.
  - `blob_sizes_at_scale` — naive vs. SB25 blob size + parallel
    build speedup at 1k / 5k / 10k / 50k docs.
  - `query_latency` — p50/p99 latency for BM25 queries and
    HNSW threshold walks.
  - `phrase_search` — `hash_tokens` + `bigram_tokens` in two
    typed indexes; same corpus answers single-word and phrase
    queries.
* Tests across unit, scale (1k-doc equivalence +
  naive-vs-SB25 size guard), engine-integration
  (`IntersectionConstraint` joins + `find!` / `pattern!`
  composition + `find!` over both succinct paths), and
  doctests.

### What's next

* Wavelet-matrix BM25 term table (would shrink the term column
  at large vocabularies; correctness-first is winning today).

See
[`docs/DESIGN.md`](docs/DESIGN.md),
[`docs/QUERY_ENGINE_INTEGRATION.md`](docs/QUERY_ENGINE_INTEGRATION.md),
[`docs/HNSW_GRAPH_ENCODING.md`](docs/HNSW_GRAPH_ENCODING.md),
and
[`docs/FACULTY_INTEGRATION.md`](docs/FACULTY_INTEGRATION.md) for
the rust-script faculty consumption pattern.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
