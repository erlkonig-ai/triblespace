# triblespace-search — design

Three typed content-addressed representations sit on top of a triblespace pile:
a portable BM25 carrier, a direct native BM25 accelerator, and a native HNSW
accelerator for approximate nearest-neighbour search. All are immutable typed
artifacts, but only the portable BM25 carrier is currently a collection lattice;
the native accelerators remain standalone derived blobs.

1. **Content-addressed.** Identical encoded bytes have the same blob hash.
   Portable BM25 also has canonical bytes for its logical exact-TF carrier.
   Native HNSW construction order remains part of the resulting artifact, so it
   is not yet a canonical semantic-search collection encoding.
2. **Immutable artifacts, no mutation.** A build returns a fresh
   content-addressed artifact without replacing prior nodes. Encodings with a
   canonical join may also return a fresh merged artifact. Collection-owned
   callers publish joins through collection evidence; direct callers may
   persist standalone handles in ordinary tribles.
3. **Typed self-contained bytes.** `try_from_blob` validates the representation
   selected by the handle type. Portable BM25 keeps a gapless fixed-width
   grammar; the native succinct accelerators use jerky. Every attached view
   retains one `anybytes::Bytes` backing and answers queries without copying
   the canonical payload.
4. **Unordered-query shape.** All attached views expose their query
   primitive as a triblespace constraint, and both follow the
   same rule: doc/handle is the only bound variable, score is
   a fixed parameter rather than another query variable.
     `bm25.matches(?doc, &terms, score_floor: f32)` — multi-
     term BM25 filter. Binds `doc` to documents whose summed
     BM25 across `terms` is `>= score_floor`. Recompute exact
     scores via `idx.score(&doc, &terms)` for ranking.
     `view.cosine_at_least(?a, ?b, score_floor: f32)` — exact,
     symmetric, filter-only predicate over two handle variables.
     `view.similar_to(probe, ?candidate, score_floor)` — one frozen
     directional retrieval bag (complete for Flat, approximate for HNSW).
   Callers combine with `and!` / `or!` / filters in the normal
   query engine; ordering is done in Rust after `.collect()`.

## Term is a `Inline`

BM25 in `triblespace-search` is not text-specific. Callers supply
terms as 32-byte `Inline`s; the library provides a
`hash_tokens(&str) -> Vec<Inline>` helper that Blake3-hashes
tokenized words but never forces it on the schema. Downstream uses:

| Term source                       | What this gets you                    |
| :-------------------------------- | :------------------------------------ |
| `hash(word)`                      | Classic text search.                  |
| entity `Id`                       | "Docs mentioning this person."        |
| tag `Id`                          | Tag-weighted search.                  |
| `hash(n-gram)`                    | Phrase search via query rewrite.      |
| fragment `Id`                     | "Docs citing this fragment."          |

The BM25 artifact is therefore a general lossless carrier `(Docs, F)`, where
`Docs` is the document-key set (including empty documents) and
`F(doc, term) -> u32` is sparse term frequency. IDF, average document length,
and BM25 scores are derived from that carrier at query time.

## `PortableBM25Index` — portable exact-TF carrier

`PortableBM25Blob` is independent of a native accelerator and has one gapless
little-endian grammar:

```text
[documents]  D x 32-byte keys, strictly increasing
[lengths]    D x u64, the sum of each document's frequencies
[terms]      T x 32-byte terms, strictly increasing
[postings]   P x (u32 document ordinal, u32 exact frequency), term-major
[ends]       T x u64 cumulative posting ends
[footer]     u64 D, u64 T
```

Every term has at least one posting, every frequency is positive, and posting
document ordinals are strictly increasing within a term, and each stored
length equals its document's frequency sum. There is no magic, in-band
version, native `usize`, padding, persisted float, score, or query-accelerator
metadata. An incompatible grammar gets a new blob encoding identity rather
than a compatibility reader: storing lengths minted
`166008918008AFF1028D28E36ECF8F6B` (2026-10-26), replacing
`A5B5F53351B46DECAED496E567D12F4F`.

The logical join is:

```text
(Docs₁, F₁) ⊔ (Docs₂, F₂)
  = (Docs₁ ∪ Docs₂, pointwise_max(F₁, F₂))
```

This preserves empty documents and makes segment merge associative,
commutative, idempotent, and byte-canonical; merge recomputes lengths from the
joined frequencies. Attachment checks framing only and retains the bytes;
scoring reads the stored lengths, derives the average in one pass over them,
and bounds-checks a term's postings when that term is queried, so no query
visits postings it does not score. `PortableBM25View` scores a cover of
carriers without merging them: its union domain is the sorted union of the
carriers' `(key, length)` tables. That assumes whole documents, i.e. a
document's postings are the same in every carrier holding it (true when terms
are a function of a content-addressed key); otherwise the view takes one
carrier's length and may score differently from the merged carrier.
`PortableBM25Index::merge` materializes the canonical join; collection
consumers supply their own domain projection and exact-cover evidence.

## `SuccinctBM25Index` — SB25 blob layout

The direct native accelerator remains available to callers that deliberately
choose its machine-specific Jerky representation. It is a self-contained
canonical blob, zero-copy via `anybytes::Bytes`, and bit-packed via jerky. It is
distinct from the portable exact-TF carrier. The exact schema identity is
`SuccinctBM25Blob::ID`; there are no magic bytes or in-band versions. Every
breaking layout or semantic change rotates that schema id.

```
[keys                ] variable         ; CompressedUniverse view:
                                        ; one 16-byte suffix per key,
                                        ; plus only the nonzero 16-byte
                                        ; prefixes after the leading
                                        ; intrinsic-ID run.
                                        ; `keys.access(code)` decodes
                                        ; the 32-byte RawInline.
[terms               ] n_terms × 32 B  ; sorted RawInline table
[doc_lens            ] variable         ; jerky CompactVector body
                                        ; width = ceil(log2(max_len + 1))
                                        ; indexed by universe-code order
[postings            ] variable         ; three jerky CompactVectors in
                                        ; one ByteArea:
                                        ;   doc_idx (width log2(n_docs+1),
                                        ;     stores universe codes, not
                                        ;     insertion indexes)
                                        ;   offsets (width log2(total+1))
                                        ;   term_frequencies (width
                                        ;     log2(max_tf+1), exact u32)
[meta suffix         ] fixed            ; n_docs, n_terms, avg_doc_len,
                                        ; k1, b, and zero-copy handles/metas
                                        ; for every preceding section
```

All sections share one `ByteArea`; its section writer supplies the alignment
required by jerky. The `SuccinctBM25Meta` suffix is a zerocopy load token whose
section handles reconstruct views into those same canonical bytes.

Lookup algorithm:
1. Binary-search the term in `terms` (typed
   `View<[[u8; 32]]>` over the canonical bytes — slice's
   `binary_search`) → term index *t*.
2. Read `(offsets[t], offsets[t+1])` from the postings offsets
   CompactVector.
3. For each *i* in that range, read `doc_idx[i]` (a
   `CompressedUniverse` code) from the postings doc_idx
   CompactVector and exact `tf[i]` from the frequency section;
   decode the external key via `keys.access(doc_idx)`.
4. Derive Robertson-smoothed IDF from `(n_docs, posting_count)`, then compute
   standard BM25 from `tf`, `doc_lens[doc_idx]`, `avg_doc_len`, `k1`, and `b`.

### Native build semantics

One inserted row counts repeated terms by addition. Repeated inserted rows
that share a document key join their frequency maps pointwise with `max`, while
document keys themselves join by set union. Document lengths are the sums of
those frequencies, not independent input fields, so empty documents survive
and input row order cannot affect the native bytes:

```text
(Docs₁, F₁) ⊔ (Docs₂, F₂)
  = (Docs₁ ∪ Docs₂, pointwise_max(F₁, F₂))
```

The direct native API builds one accelerator at a time. Exact portable
collection elements can instead be joined through the carrier above. `k1` and
`b` remain derived query parameters rather than persisted carrier identity.

### What's already compressed (as of the current impl)

- `doc_lens` → bit-packed to `ceil(log2(max_len + 1))` bits.
  At 100k docs with avg_doc_len ≈ 180 and max ≈ 1024, ~10 bits
  instead of 32 — 3.2× savings on that section.
- `postings.doc_idx` → bit-packed to `ceil(log2(n_docs + 1))`.
  At 100k docs, 17 bits instead of 32 — 1.9× savings.
- `postings.offsets` → bit-packed likewise.
- `postings.term_frequencies` → exact raw `u32` values bit-packed to
  `ceil(log2(max_tf + 1))`. Common low-frequency corpora typically use only a
  few bits per posting without losing the high-frequency tail.

### What's still flat (deliberately)

- `terms` — 32 bytes each (Blake3 hash). We tried fragment-
  dictionary compression here (phase 2a) and it **grew** the
  section: Blake3 hashes have maximum entropy, so the 4-byte
  fragment dictionary overhead exceeded any code-length win.
  See `tests/scale_smoke.rs` and the phase 2a revert in git
  history for the actual numbers.

### What keys-side compression buys us

`CompressedUniverse` stores a sorted key domain as every 16-byte suffix plus
only the nonzero 16-byte prefixes. For `N` keys of which the first `Z` have a
zero high half, the payload is exactly `32N - 16Z` bytes. A GenId-keyed corpus
therefore uses exactly half the flat 32-byte key payload before constant
metadata, independent of incidental byte-frequency patterns. Full-width hash
keys remain exactly flat rather than risking dictionary overhead.
- Whole-blob ratio moves too, but modestly: 0.48×→0.42× at 1 k
  docs with correlated keys; ~0.01×–0.02× improvement at 50 k
  because postings dominate the denominator.
- The architectural win is type-level: `keys.access(code)` goes
  through the same universe plumbing as every other `Inline`
  table in the stack; range / prefix / membership queries over
  the keys universe compose for free.
### Open compression directions

- **Delta-encoded posting doc_idx** — posting lists are now
  universe-code-sorted (Phase 2b), so consecutive deltas
  compress further via Simple16 / ELF / VByte. Roughly halves
  the `doc_idx` section at Heaps-law corpora. This is the
  next-biggest win to chase — postings dominate the blob.
- **Wavelet matrix on the term table** — would let rank/select
  queries hit terms without a linear-compare binary search.
  For identification-only lookups the current
  `View<[[u8; 32]]>` slice-binary-search is competitive; the
  wavelet matrix would unlock range queries over terms (useful
  for n-gram prefix scans).

## `SuccinctHNSWIndex` — SH25 blob layout

Self-contained blob, zero-copy via `anybytes::Bytes`. Schema id:
`27D71A473EF22DA4D916F61810AC5D86` (see
`succinct::SuccinctHNSWBlob`). As with SB25, the typed handle
is the identity — no in-blob magic or version.

```
[header              ] 144 B (fixed)
  dim                     u32
  m                       u16    ; max neighbours on non-zero layers
  m0                      u16    ; max neighbours on layer 0
  max_level               u8
  reserved                u8
  has_entry_point         u8
  reserved                u8
  entry_point             u32
  n_nodes                 u64
  n_layers                u64
  graph_neighbours_meta   32 B   ; CompactVectorMetaOnDisk
  graph_offsets_meta      32 B   ; CompactVectorMetaOnDisk
  (section_offset, section_len) × 3 = 48 B

[handles             ] n_nodes × 32 B          ; Inline<Handle<Embedding>>
                                               ; — the node IS the handle;
                                               ; no separate doc-key table.
[graph_bytes         ] variable                ; two CompactVectors in one
                                               ; ByteArea:
                                               ;   neighbours (width log2(n+1))
                                               ;   offsets    (width log2(E+1))
```

Schema id: `A96890DE5F85A4F2285C365549B21BC2` (see
`succinct::SuccinctHNSWBlob`; rotated from
`27D71A473EF22DA4D916F61810AC5D86` when the keys section was
dropped).

`graph_bytes` packs neighbour lists across all `(layer, node)`
pairs into a flat CSR: `offsets[L·(n+1) + i]` gives the start of
node *i*'s neighbour list on layer *L* inside `neighbours`. Nodes
absent from layer *L* encode as empty slices — search walks stay
correct because an empty neighbour list is a dead end, and the
search always enters from the top-level entry point.

Query algorithm (standard Malkov-Yashunin search, threshold-gated):
1. Start at `entry_point` on `max_level`.
2. Greedy-descend layer-by-layer down to 1.
3. On layer 0, ef-width beam search; keep every candidate whose
   cosine similarity clears `score_floor`.

The succinct path re-implements the greedy + ef-search against
the bit-packed graph; see
`AttachedSuccinctHNSWIndex::candidates_above` in
`src/succinct.rs`.

### What's already compressed

- Graph `neighbours` → `ceil(log2(n_nodes + 1))` bits per
  neighbour index (17 bits at 100k nodes vs. 32 bits raw).
- Graph `offsets` → `ceil(log2(total_edges + 1))` bits per
  offset, which for `M=16` / `M0=32` averages similar savings.

### What's still flat

- `doc_ids` — 16-byte natural size.
- `vectors` — raw f32. Caller-owned data; compression is the
  caller's decision via their embedding schema choice (the
  crate itself stays agnostic).

### Handle-keyed storage (shipped for both FlatIndex and HNSW)

Both `FlatIndex` and `SuccinctHNSWIndex` store a flat table of
`Inline<Handle<Embedding>>` (32 B per handle). There is
no separate "doc key" table — the node IS the handle. Callers
who want a book-id → embedding-handle mapping keep it as a
trible attribute they own (`book_embedding` in the examples),
not as shadow data inside the index. Embeddings live in the
pile's blob store, content-addressed, dedup'd across indexes:

```
pile blob store:
  Handle<Embedding> h_a → blob_a  (one copy of vector A)
  Handle<Embedding> h_b → blob_b  (one copy of vector B)

FlatIndex:         [h_a, h_b, h_c, ...]          ← 32 B per entry
SuccinctHNSWIndex: [h_a, h_b, h_c, ...] + graph  ← 32 B per entry + bits
```

The `Embedding` blob encoding id is
`EEC5DFDEA2FFCED70850DF83B03CB62B` (minted via `trible genid`).
At query time the walk resolves each handle through
`BlobStoreGet`, and the `BlobCache` wrapper in
`triblespace::core::blob` collapses repeat visits into a
single fetch per view lifetime.

For 100 k × 384-dim MiniLM: the HNSW blob is handles + graph =
~3.2 MiB + bit-packed CSR (a few more MiB); embedding blobs
(~147 MiB total) are dedup'd across every index that references
them.

### Open compression directions

- **2-ring graph encoding** — built and benchmarked in
  `src/ring.rs` + `examples/ring_vs_csr*.rs`. The fixed-
  predicate sub-ring from Arroyuelo et al. *The Ring* (TODS
  2024 §4.4) halves the graph blob vs CSR at every scale
  tested. We *didn't* adopt it as the default because it
  costs ~3× end-to-end query latency on in-memory / warm-
  cache workloads, and at 1B corpus scale the graph is only
  ~4 % of total storage (embeddings dominate). `RingGraph`
  stays as an opt-in primitive for storage- or transfer-constrained workloads,
  including deployments retaining many immutable graph versions. See
  [`docs/HNSW_GRAPH_ENCODING.md`](HNSW_GRAPH_ENCODING.md)
  for the full measurements and when-to-use-which.
- **Vector quantization** — the biggest lever at scale.
  The caller owns the embedding schema; we could ship
  `EmbeddingI8` / `EmbeddingPQ` alongside `Embedding` and
  let the distance function branch on the schema. At
  dim=384+ the embeddings are 90 %+ of total storage, so
  4–16× quantization shrinks wins far more than any graph
  encoding.

## Query engine integration

All attached search views expose their query as a `triblespace::Constraint`.
Callers load the blob once (cheap — mmap-backed
`anybytes::Bytes`) and produce a constraint by binding the
variables they want:

```rust
let snapshot = pile.snapshot()?;
let bm25: SuccinctBM25Index = snapshot.get(bm25_handle)?;
let hnsw: SuccinctHNSWIndex = snapshot.get(hnsw_handle)?;
let hnsw_view = hnsw.attach(&snapshot);

let rows: Vec<(Id,)> = find!(
    (doc: Id),
    and!(
        pattern!(&kb, [{ ?doc @ wiki::content: _ }]),
        bm25.matches(doc, &terms, 0.0),
    ),
)
.collect();
```

BM25 binds `doc` only — `matches(doc, &terms, score_floor)` is
a single-variable filter; ranking happens in Rust via
`idx.score(&doc, terms)` after `.collect()`. Fixed-probe ANN retrieval uses
`similar_to`; exact pairwise filtering over independently sourced handle
variables uses `cosine_at_least` (see `docs/QUERY_ENGINE_INTEGRATION.md`).

## What lives where

| Concern                       | Crate                   |
| :---------------------------- | :---------------------- |
| `Inline`, `Id`, `TribleSet`    | triblespace             |
| Blob byte buffers (mmap)      | anybytes                |
| Succinct primitives           | jerky                   |
| BlobEncoding + constraints      | **triblespace-search**  |
| Tokenizers (opt-in helpers)   | **triblespace-search**  |
| Caller-supplied embeddings    | downstream              |

`triblespace-search` does not depend on any embedding library.
Callers bring their own embeddings (local MiniLM via fastembed,
API-based Voyage/OpenAI, or anything that produces `f32` vectors
of a fixed dimensionality) and insert them into the pile under
an `Embedding<const D: usize>` schema they control.

## Non-goals (v1)

- In-place mutation. Range updates and compaction publish fresh immutable
  artifacts.
- Distributed/sharded indexes. Single-node first; sharding lives
  above the index API if/when it matters.
- Language-aware tokenization. `hash_tokens` is intentionally
  minimal; callers with real NLP needs tokenize themselves.
- Linear score combinations across BM25 + HNSW (hybrid search).
  Caller composes the boolean combination through `and!` /
  `or!` in `find!` (see `examples/hybrid_search.rs`); if they
  want to rank on a weighted sum of scores, they do so in Rust
  after `.collect()`.

## Worked example: 100 000 wiki fragments

Sizing exercise for the canonical downstream: indexing a Liora
pile of ≈ 100 k typst wiki fragments, average ≈ 180 words each
(≈ 300 raw tokens with punctuation). Numbers are back-of-envelope
for contrasting the naive flat representation with the succinct layout.

### Direct native BM25 — size estimate

Assume after `hash_tokens`:
- `n_docs = 100 000`
- `avg_doc_len ≈ 180` unique tokens per doc after trim/dedup
- distinct terms across corpus `n_terms ≈ 300 000` (Heaps' law
  with β ≈ 0.5, k ≈ 30 for English-ish text)
- total postings `≈ 100 000 × 180 = 18 000 000` entries

Two columns: a theoretical "naive flat-array" layout (the
pre-jerky baseline this crate started from — reported by
[`BM25Index::byte_size`], no actual serializer ships) and the
landed SB25 format with exact bit-packed term frequencies.

| Section            | Per-entry | Count      | Naive bytes | SB25 bytes  |
| :----------------- | --------: | ---------: | ----------: | ----------: |
| metadata           | —         | —          |       20 B  | small fixed suffix |
| keys               |    32 B   | 100 000    |   3.2 MiB   | ~1.5–3.2 MiB|
| doc_lens           |     4 B   | 100 000    |   0.4 MiB   | ~0.12 MiB   |
| terms (sorted)     |    32 B   | 300 000    |   9.6 MiB   |  9.6 MiB    |
| postings_offsets   |     4 B   | 300 001    |   1.2 MiB   | ~0.6 MiB    |
| postings.doc_idx   |     4 B   | 18 000 000 |    72 MiB   | ~38 MiB     |
| postings.tf        |     4 B   | 18 000 000 |    72 MiB   | depends on max tf |
| **Total**          |           |            | **~159 MiB**| corpus-dependent |

Every row computed the same way: the bit-packed sections use
`ceil(log2(n + 1))` bits per entry (doc_idx → 17 bits ≈ 2.12 B;
doc_lens at max ≈ 1024 → 10 bits ≈ 1.25 B; offsets at 18M max →
25 bits ≈ 3.1 B). Exact frequencies use
`ceil(log2(max_tf + 1))` bits: a maximum within-document frequency of 255
uses one byte per posting, while larger values widen losslessly.

For 100k keys, the key carrier ranges from raw 3.2 MiB for full-width values to
about 1.5 MiB for GenIds with their implicit zero high half. Neither end moves
the blob total much because postings dominate.

The **postings dominate** either blob. SB25 bit-packs both `doc_idx` and exact
term frequency; the remaining keys, terms, and document lengths are already
close to their direct representation.

Term table is the second-largest chunk (9.6 MiB of 32-byte
Blake3 hashes). Phase 2a tried fragment-dictionary compression
here and it made the section **bigger** — maximum-entropy hashes
have no shared 4-byte fragments for the dictionary to exploit.
Left uncompressed.

### Direct native BM25 — build time

Build is O(total postings) with hashmap bookkeeping: `18 M`
insertions into the `HashMap<RawInline, HashMap<u32, u32>>` tf
table, then a sort over 300 k term hashes (32-byte compare).
On current laptop hardware:
- Hash-tokenize 100 k fragments × 180 tokens ≈ 18 M Blake3 hashes.
  Blake3 is ~3 GB/s on short inputs → ~0.5 s.
- Hashmap inserts: ~100 ns each × 18 M ≈ 1.8 s.
- Term sort: 300 k × log₂(300 k) × 32-byte compare ≈ 50 ms.
- BM25 score computation is absent from the build; queries derive scores only
  for postings they visit.

So **~3 s single-threaded** for the full corpus.
`BM25Builder::build_naive_with_threads(n)` shards canonicalized docs across `n`
scoped threads (std::thread::scope, no rayon dep) and merges
per-shard tf maps at the end. Observed speedups at 4 threads
on a laptop: ~1.2× at 10 k docs, ~1.3× at 50 k — the merge
cost stays serial and caps the win. Byte-identical output vs.
single-threaded. A term-partitioned variant would push further
but needs a routing hash per insert; filed as future work when
build-time actually bites.

### Direct native BM25 — query latency

`cargo run --release --example query_latency` on current laptop
hardware (10 k / 50 k docs with Zipf-ish vocab):

| Corpus              | Path   | p50     | avg     | p99     |
| :------------------ | :----- | ------: | ------: | ------: |
| 10 k × 64 tokens    | naive  |  167 ns |  203 ns |  875 ns |
| 10 k × 64 tokens    | SB25   | 4.94 µs | 6.15 µs | 12.3 µs |
| 50 k × 96 tokens    | naive  |  333 ns |  500 ns | 1.50 µs |
| 50 k × 96 tokens    | SB25   | 18.7 µs | 26.0 µs | 48.3 µs |

The harness now black-boxes materialized results; earlier sub-3-µs figures did
not and were compiler-sensitive. SB25 pays to unpack compact document/frequency
vectors and derive BM25, while the naive oracle reads pre-baked scores.

For 3-term `query_multi`, canonical document-code aggregation avoids hashing
and comparing 32-byte keys until final decoding. Measured p50 is 35.6 / 67.9 µs
(naive / SB25) at 10 k and 161 / 370 µs at 50 k. This is about 28–29% faster on
SB25 than the retired baked-score implementation despite deriving exact scores.

Multi-element collection reads can use the portable carrier. Constructing the
resident canonical merge is an all-postings pass that belongs at
attachment/change time. Once resident, queries operate directly on that merged
view. The `bm25_merge_bench` example reports portable merge, resident query,
reattached query, and deliberately non-amortized direct merge-plus-query
timings for the same corpus, verifying bit-identical ranking first.

### HNSW — size estimate

At `n = 100 000`, `dim = 384` (MiniLM), `M = 16`, M0 = 32.
Embeddings are not in the HNSW blob — they live in the pile's
blob store, content-addressed, and shared across every index
that references them. The HNSW blob only carries the handles
table and the graph:

- `handles`: 100 k × 32 B = **3.2 MiB** (one
  `Inline<Handle<Embedding>>` per node, the sole
  per-node table)
- graph `neighbours`: ~1 M directed edges (average `M`
  neighbours per node plus layer-0 fill-in with `M0 = 32`),
  each packed at `ceil(log2(n + 1)) = 17` bits ≈ 2.1 MiB
- graph `offsets`: `(layers + 1) × n` entries at
  `ceil(log2(edges + 1)) = 20` bits; layers stay ~4–5 by
  design (`log_M(100k) ≈ 4`), so roughly 500 k entries ≈
  1.25 MiB
- SH25 header: 128 B (negligible)
- **Total HNSW blob ~6.5 MiB.**

Separately, in the pile's blob store:
- `Embedding` blobs: 100 k × 384 × 4 B = **147 MiB** (caller-
  owned, dedup'd — two indexes over the same vectors share
  the bytes)

The handle-indirected design moves embedding compression out
of this crate's surface: `Embedding` is agnostic to the on-
disk encoding, so callers who care about footprint swap in
`EmbeddingI8` / `EmbeddingPQ` schemas at their level. The
crate's own succinct pass targets the graph — which at this
scale is already ~4 % of the total corpus footprint, so
there's no transformative graph win to chase.

### HNSW — query latency

`query_latency` example on 5 k / 10 k × 32-dim corpora, probes
sampled from the indexed handles, threshold `cos ≥ 0.5`,
`ef_search = 50`:

| Corpus          | Path  | p50      | avg      | p99      |
| :-------------- | :---- | -------: | -------: | -------: |
| 5 k × 32        | naive | 190 µs   | 191 µs   | 215 µs   |
| 5 k × 32        | SH25  | 190 µs   | 191 µs   | 222 µs   |
| 10 k × 32       | naive | 226 µs   | 228 µs   | 273 µs   |
| 10 k × 32       | SH25  | 220 µs   | 221 µs   | 248 µs   |

SH25 tracks naive within noise — both paths fetch every
visited embedding through the same `BlobCache<MemoryBlobStore,
Embedding>` and compute cosine against a
contiguous `&[f32]` view, so the graph-access difference
(pointer hop vs. bit-unpack) is swamped by the O(ef_search ×
dim) distance-eval work. Threshold walks visit more nodes
than the old top-k shape did (no early exit once `k` hits),
which accounts for the absolute-number jump versus earlier
measurements.

### Takeaways

- The naive BM25 layout remains a useful speed and correctness oracle; SB25 is
  the persisted, losslessly mergeable representation.
- Postings are the biggest lever; exact bit-packed term frequencies claim much
  of it without making cover shape observable. Delta-encoded `doc_idx` remains
  a plausible next compression step.
- For HNSW, the interesting compression sits in *caller-owned*
  embedding bytes — this crate's pass is about graph compactness
  and graph-walk speed, not bulk size.
- At these scales a single-node mmap-backed blob is fine; the
  "distributed indexes" non-goal holds even at 1 M docs.
