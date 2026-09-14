# Inventory

## Collection materialization

Measured on a 404-commit, 26.26 M-fact collection (1.98 GB pile) after the
whole-archive decode landed. A warm `Collection::snapshot` is ~2.8 s, of which:

- ~80 ms — record discovery, 404 signature checks, canonical validation of
  1.86 GB of committed archives, merge/resolution/physical-cover planning.
  The whole collection calculus is under 3% of a snapshot; optimizing it is
  optimizing noise.
- ~0.3 s — the partitioned canonical union.
- ~85 ms — validating and hashing the 26.26 M rows of the merged archive, one
  contiguous run per worker.
- ~2.1 s — six PATCH orders built bottom-up over the whole archive at once.

The union-reduce that used to follow is gone: the decode no longer chops the
archive into per-worker chunks, so there are no per-chunk sets to merge back
together. What is left is one build per order.

Per-order wall time for that build, all six over the whole 26.26 M-row
archive on sixteen cores:

    eav  97 ms   eva 162 ms   aev 288 ms   ave 458 ms   vea 513 ms   vae 604 ms

Against the same orders built serially over the same rows, that is 13x to 22x
— **82% to well over 100% of sixteen cores** (`aev` beats linear because the
old per-chunk build rebuilt the same attribute-prefix spine sixteen times).
There is essentially no parallelism left to win here. What remains is work:
the four value-first orders are 88% of the build, and `vae` alone is 28%.

Ideas, in descending measured leverage:

- **Cut the work the value-first orders do, not the time they take.** Each trie
  level re-reads a scattered 64-byte row per row — one cache miss per row per
  level — and a shallow trie over random values is two or three such levels.
  Carrying a compact `(tree-order prefix, row)` record instead would make every
  level after the first a sequential scan, and would turn the
  longest-common-prefix search from a byte loop into one integer compare.
  Untried, and **it is not uniform across orders**: `vea`/`vae` sort on random
  value bytes and would benefit throughout, but `aev`/`ave` share all sixteen
  attribute bytes inside any one attribute's bucket, so a fixed-width prefix is
  exhausted at the first level and the full-key path has to take over. Expect it
  to pay on the two most expensive orders and to need a fallback for the other
  two — which is also the reason it is a real piece of work rather than a
  substitution.
- **Building the six orders lazily is a public-API change** — the six `PATCH`
  fields are `pub` — and it is a worse trade than the 88% suggests. `union`,
  `intersect` and `difference` are defined index-by-index, so a lazy order
  would have to be re-derived rather than combined after every set operation,
  and the first query to open a cold order would pay a whole-archive build
  **serially, in the middle of a join**, replacing a uniform cost model with a
  data-dependent one. The engine's worst-case-optimal join is built on being
  able to open any order for free. This wants a deliberate decision about what
  a `TribleSet` promises, not a drive-by.
- **Fuse the merge with the decode.** The partitioned merge produces sorted,
  canonical, worker-sized runs and then concatenates them into one 1.68 GB
  buffer that the decoder re-scans — roughly 0.2 s of 2.8 s, in a serial
  `extend_from_slice` and a peak allocation. Two ways in, both with a price:
  copy the runs into the destination in parallel (cheap, but keeps the
  allocation and only removes ~0.1 s), or hand the runs to the decoder
  unconcatenated, which now means teaching the trie build segmented row
  addressing in its hottest inner loop for 7%.

Measured and rejected: **building the six orders concurrently with each other**
rather than one after another. Each needs its own row permutation, so six at a
time costs 6 x 105 MB instead of 105 MB; interleaved medians were 2.27 s
sequential, 2.26 s two at a time, 2.19 s three, 2.17 s six. A 4% gain, inside
the run-to-run spread of a loaded machine, for five times the transient
permutation memory on the one path whose job is large archives.

Not an idea, a finding: **no `MERGE` or `DERIVE` record can make a cold read
faster under the current admission rule.** Unsigned equations are admitted by
recomputation — `api.rs` recomputes `join(low, high)` for every candidate
merge, and `succinctarchive_union::validate_derive` compares the target
"byte-for-byte with a fresh direct construction from the source". Validating a
balanced merge tree over N leaves rewrites every byte once per level, which is
strictly more memory traffic than one k-way merge, and attaching a persisted
accelerated SuccinctArchive closure over these facts measured **105 s** against
a 4.16 s `TribleSet` rebuild, because attachment proves the raw/index structure
before exposing the runtime. Persisted derivation can only pay off behind
a *trusted* attach — bytes checked by content hash alone, admitted because a
key the reader already treats as ground truth named them — which is a change
to what "checkable" means, not a change to the code.

**Ruled out for `MERGE`, 2026-08-21.** Signed `MERGE` and `DERIVE` records were
built and then removed. A signature on a *checkable* claim never makes the claim
correct — recomputation does — so its only value is permission to skip the check,
which is worth something exactly when checking is expensive. A `DERIVE` is
expensive to check. A `MERGE` is not: `succinctarchive_union::join` is
`SuccinctArchiveBlob::merge`, which parses each input, proves it canonical, merges
the ordered domains once and k-way merges the sorted runs — no query runtime, no
Rank9 accelerator, no wavelet. It is cheaper than re-deriving, which is why the
path exists at all, so nobody would ever skip it and the signature bought nothing.
A root collection is named by its name, public-key namespace, optional
capability trust root, representation, recipe, and reach. A per-signer
signature establishes *who* asserted a `COMMIT`; an explicit admission policy
separately decides whether that signer may contribute. An equation is found
bad by checking it, at which point it is already rejected. That is forensics,
not defence. `COMMIT` keeps its signature because a commit asserts something no
reader can recompute.

## Potential Removals
- None at the moment.

## 0.7.0 Release Preparation
- **Documentation polish.**
  - Draft advanced query examples that compose multiple `attributes!` modules
    and slot them into the book structure.
  - Extract deep reference content from the API docs (`value`, `blob`, `repo`,
    and trible structure discussions) into dedicated book chapters.
  - Author the requested FAQ chapter and cross-link it from the landing page and
    changelog for discoverability.
- **PATCH performance notes.**
  - Stand up a repeatable benchmark suite covering the iterator and
    `with_sorted_dedup` improvements.
  - Summarise empirical findings alongside complexity notes in either the book
    or changelog.
  - Capture any uncovered hotspots or tuning ideas back into this inventory for
    future releases.

## Query engine documentation follow-ups
- `triblespace-core/src/query/residual/` is still tracked (`delta.rs`,
  `materialize.rs`, `positive_hedge_credit.rs`, `set_admit.rs` — ~640 KB) but
  no `mod residual;` declaration reaches it anywhere in the crate. Orphaned by
  the residual-engine deletion; delete it or re-attach it deliberately.
- The `ProjectionKey` type alias in `triblespace-core/src/query.rs` is dead —
  it keyed the terminal projection claim table, which no longer exists.
- The `find!` macro's doc comment in `triblespace-core/src/query.rs` still
  documents relational SET semantics, raw-head claiming before conversion, and
  the "at most one `()`" rule for the unit head. The engine is a bag of
  complete bindings (see the F8 fixture in `tribleset-bench`), so the doc
  comment contradicts both the implementation and the rewritten book chapters.
  The `Constraint` trait's own doc table likewise lists five methods for a
  seven-method trait (`propose_chunk` and `influence` are missing).
- The `[Unreleased]` section of `CHANGELOG.md` still carries entries describing
  the deleted residual/typed-Program engine (residual compiler policy, typed
  Program pagers, `OrderKeyMode`, RPQ scheduling) as if they shipped. They
  should be reconciled before the next release notes are cut.
- A book chapter on the `triblespace-paths` closure index is owed once that
  crate's surface stabilises; the interim guidance lives in
  `book/src/query-language.md#recursive-traversal`.

## Desired Functionality
- Bound aggregate unauthenticated inbound connection state. Protocol v8 now
  gives every connection a single 10-second deadline covering the first stream
  and complete `AUTH` exchange, but the host still spawns one task per accepted
  connection. Measure iroh's own admission limits, then add the smallest
  transport-independent concurrent-admission bound if a connection flood can
  retain materially unbounded tasks or QUIC state within that deadline. Apply
  the same measurement to post-auth request streams: an authorized peer can
  currently open multiple partial operations whose per-stream tasks have no
  independent deadline or concurrency budget.
- Choose the oversized native Succinct shard policy. Exact-cover Rank9
  acceleration now uses an ABI-qualified, source-bound blob whose embedded
  handle names its exact raw Succinct source. Raw and Rank9-accelerated members
  are both joinable; a Rank9 join requests the exact raw union as an immutable
  dependency when it is not resident. A single derived raw shard still rejects
  more than `u32::MAX` rows or domain values.
  Decide how to split or spool oversized source covers without changing
  collection identity.
- For pathological single commits or Succinct LSM levels that cannot keep the
  domain, EAV rows, and equal rotation scratch in memory, add a file-backed EAV
  spool plus stable radix/counting passes into the final portable sink; choose
  it structurally from representability, not a tuning threshold.
- If exact Succinct collection maintenance is accelerated again, build and
  measure a direct adapter over canonical raw collection blobs. Do not restore
  an adaptive threshold and process-local circuit breaker around the low-level
  freeze backend.
- Reconcile the residual branch's workspace-wide rustfmt baseline (or pin the
  intended formatter toolchain): `cargo fmt --all` currently rewrites many
  unrelated files, obscuring focused query-engine diffs.
- Provide additional examples showcasing advanced queries and collection usage.
- Helper to derive delta `TribleSet`s for `pattern_changes!` so callers don't
  have to compute them manually.
- Add an exporter for the lossless JSON schema so archived JSON can be
  reconstructed (including field ordering).
- Add a diagnosis tool that reports attributes missing `name`, `value_encoding`,
  or `value_formatter` metadata so strict renderers can explain omissions.
- Generate `attributes!` modules from a `TribleSet` description so tooling can
  derive them programmatically. Rewriting `pattern!` as a procedural
  macro will be the first step toward this automation.
- Benchmark PATCH performance across typical workloads.
- Investigate the theoretical complexity of PATCH operations.
- Measure practical space usage for PATCH with varying dataset sizes.
- Explore hash-prefix-partitioned Pile bootstrap PATCH construction: keep all
  duplicate candidates for a key in one ordered worker, preserve the decoded
  order of immutable legacy pin records separately, and merge only disjoint key
  ranges so value-insensitive PATCH union cannot alter first-valid duplicate
  selection.
- Extend PATCH to associate values with keys, turning it into a map structure.
- Expose value-aware PATCH iterators and lookup helpers so callers can access
  stored payloads.
- Benchmark recursive `ByteTable` displacement planner versus the greedy random insert to measure fill rate and performance across intermediate table sizes.
- Explore converting the recursive `ByteTable` planner into an iterative search to reduce stack usage.
- Generalise the declarative key description utilities to other key types so
  segment layouts and orderings can be defined once and generated automatically.
- Provide a macro to declare key layouts that emits segmentation and
  ordering implementations for PATCH at compile time.
- Expose segment iterators on PATCH using `KeySchema`'s segment permutation instead of raw key ranges.
- Consolidate pile header size constants to avoid repeated magic numbers.
- Add an explicit `Pile::put` guard/error for oversized single-record appends
  (e.g. platform `writev` limits) so failures are deterministic and actionable.

## Formal Verification
### Invariant Catalogue
- Translate the `book/src/formal-verification.md` matrix into individual GitHub
  issues, each covering one subsystem (TribleSet, PATCH, values, queries,
  collection algebra, storage primitives).
- Document how each invariant maps to existing modules so new contributors can
  locate the relevant code without spelunking.

### Harness Work
- Make the public `triblespace-paths` product-oracle harness tractable for
  full CBMC verification. `cargo kani -q --package=triblespace-paths --harness
  path_index_matches_two_vertex_product_oracle --only-codegen` succeeds, but a
  32-subgraph solve was capped after 347 seconds without a verdict, and the
  original 256-graph symbolic family was capped after ten minutes while using
  roughly 16 GiB. The same 256 cases pass instantly as a native exhaustive
  test. The fixed closure carrier has only four product nodes; the dominant
  formula comes from the public `Automaton`/`PathSummary` path through `Vec`
  allocation and `BTreeSet` canonicalization/destruction. Investigate a sound
  proof-only abstraction for those already-tested canonical containers, or a
  separately callable fixed-carrier closure kernel, before increasing bounds.
- Generalise the `triblespace-paths` product-oracle rung beyond its exhaustive
  two-vertex, fixed two-state automaton: first add a non-nullable automaton rung,
  then bound symbolic transition tables without making private closure
  internals part of the verification surface.
- Build shared bounded-data generators for Kani harnesses (tribles, PATCH
  entries, and native collection record sets) and publish them under
  `proofs/util.rs`.
- Add `proofs/tribleset_harness.rs` validating ordering-preserving union,
  intersection, difference, and iterator round-trips.
- Add `proofs/patch_harness.rs` with ByteTable checks proving `plan_insert`
  respects `MAX_RETRIES`, `table_insert` hands growth entries back to
  `Branch::modify_child`, and `table_grow` preserves every occupant.
- Extend `proofs/value_harness.rs` with schema-aware helpers ensuring
  `TryFromInline` conversions reject truncated buffers.
- Add a collection-algebra harness covering intrinsic record identity,
  commutative merge inputs, and authority-preserving physical covers.

### Tooling & Execution
- Integrate `cargo miri test` into `scripts/preflight.sh` with appropriate
  guards for unsupported harnesses.
- Stand up a `cargo fuzz` workspace covering PATCH encoding/decoding, query
  planning, and collection sync flows; publish nightly cadence expectations in
  the roadmap.
- Record deterministic simulation scenarios (sparse evidence, garbage
  collection, concurrent set union, and remote sync) that double as regression tests.

## Additional Built-in Schemas
The existing collection of schemas covers the basics like strings, large
integers and archives.  The following ideas could broaden what can be stored
without custom extensions:

### Inline schemas
- `Uuid` for RFC&nbsp;4122 identifiers.
- `Ipv4Addr` and `Ipv6Addr` to store network addresses.  IPv6 could dedicate
  spare bits to a port or service code.
- `SocketAddr` representing an IP address and port in one value.
- `MacAddr` for layer‑2 hardware addresses.
- `Duration` for relative time spans.
- `GeoPoint` with latitude and longitude stored as two 64‑bit floats.
- `RgbaColor` packing four 8‑bit channels into one value.
- `BigDecimal` for high‑precision numbers up to 256 bits.

### Blob encodings
- `Json`, `Cbor` and `Yaml` for structured data interchange.
- `Csv` for comma‑separated tables.
- `Protobuf` or `MessagePack` for compact typed messages.
- `Parquet` and `Arrow` for columnar analytics workloads.
- `Lance` for memory-mapped columnar datasets.
- `CompressedBlob` wrapping arbitrary content with deflate or zip compression.
- `WasmModule` for executable WebAssembly.
- `OnnxModel` or `Safetensors` for neural networks.
- `HnswIndex` for vector search structures.
- `TantivyIndex` capturing a full-text search corpus.
- `Url` for web links and other IRIs; best stored as a blob due to the value
  size limit.
- `Html` or `Xml` for markup documents.
- `Markdown` for portable text.
- `Svg` for vector graphics.
- `Png` and `Jpeg` images.
- `Pdf` for print‑ready documents.

Formats with solid memory-mapping support in the Rust ecosystem should be
prioritized for efficient zero-copy access.

## Documentation
- Add diagrams or pseudocode to the Atreides Join chapter illustrating variable selection and search.
- Move the "Portability & Common Formats" overview from `src/inline.rs` into a
  dedicated chapter of the book.
- Migrate the blob module introduction in `src/blob.rs` so the crate docs focus
  on API details.
- Keep the collection algebra discussion in the book aligned with the narrow
  API-level documentation in `src/collection`.
- Split out the lengthy explanation of trible structure from `src/trible.rs`
  and consolidate it with the deep dive chapter.
- Add a FAQ chapter to the book summarising common questions.

## Discovered Issues
- Refine the sanitized collection-repair failure taxonomy beyond generic
  `Failed`/`Deadline`, so operator health can distinguish transport loss from
  authorization or protocol/version incompatibility without retaining error
  strings, bearer handles, or other sensitive wire detail.
- CubeCL 0.10's CUDA type registry does not advertise `f64`, even though the
  resident NVFP4 kernels compile and run correctly on GB10. Make the fork's
  capability report truthful before treating the scanner as portable across
  CUDA runtimes.
- Measure resident NVFP4 query latency against LSM cover fragmentation. The
  scanner intentionally performs one launch per nonempty member and one joined
  readback; if many small members dominate, batch descriptors or compaction may
  matter more than kernel arithmetic.
- Make `#[value_formatter]` WASM generation concurrency-safe. A cold parallel
  workspace build can race after both macro processes observe the same missing
  final path, then invoke `rustc` against the same stem and scratch object names;
  one linker may read the other's partial object while the other successfully
  produces the final `.wasm`. Compile under a per-stem inter-process lock or to
  unique temporary paths followed by an atomic publish, and retain the existing
  content-derived final name.
- Add a separate bounded cache planner for useful unsigned `MERGE`/`DERIVE`
  equations and materialized results. Strong retention intentionally ignores
  them—even when accepted and active—so append-only cache work cannot
  manufacture durable ownership. Prefer weak/budgeted retention and keep this
  policy orthogonal to signed commit ground truth.
- Add an executor-local shadow observer at the residual action-task boundary.
  It should quote critical-path and total service cost for the exact
  `(action, bound schema, batch geometry)` without giving planning-only Ready
  or Candidate states a fabricated backend quote. Keep observation opt-in
  until its clock/counter cost is measured, then compare an unsplit parent
  task with concrete child tasks using confidence and reconvergence loss
  rather than a global hardware cutoff.
- Publish the checked Rank9 accelerated-root seam as a new Jerky crate version,
  then replace the exact git-revision pins in `triblespace-core` and
  `triblespace-search` before the next crates.io release. The git pin is an
  intentional integration bridge, not the final publishable dependency.
- Define archive-message semantics when one entity carries multiple content
  handles. BM25 preserves the union of their term presence, while result
  materialisation currently selects one matching body; either make the schema
  cardinality explicit or make resolution deterministic and test it.
- The optional CubeCL succinct-merge backend's per-level block-prefix scan is
  still one serial device thread. Packed CPU reduced the measured WGPU gain to
  5–8% on large Apple Metal tiers; investigate a hierarchical device scan and
  rotation batching before considering GPU acceleration for default archive
  maintenance. Keep the summed-input crossover hardware-calibrated.
- Yard collection currently evicts blobs from per-generation live PATCH sets
  while leaving the append-only Pile records in place. Add a future physical
  compaction/rewrite path when Yard needs to reclaim disk space, preserving
  live readers while replacing generation files.
- The packed device confirm path assumes `UNIT_POS_PLANE` relates linearly to
  the cube-local invocation index — condition (c) on
  `membership_confirm_ballot_kernel`. It is true on Metal and CUDA and is what
  makes ballot bit `L` the verdict of the lane at `plane_base + L`, but the
  WGSL subgroups extension leaves the invocation-to-subgroup mapping
  implementation-defined and a violation shows up only as wrong query answers.
  A standalone "pack N predicate bits with a ballot and compare against a CPU
  pack" kernel, run over `n x bit_offset` grids, would turn the assumption into
  a measurement on each adapter we ship on; it is also the test the
  shared-memory-atomic alternative would need.
- The packed confirm kernels hardcode ballot component 0 and are gated on
  `plane_size_min == plane_size_max == 32` (`require_plane_packing`). Widening
  to 64-lane planes needs a *dynamic* index into `Vector<u32, Const<4>>`
  (`ballot[UNIT_POS_PLANE / 32]`), which cubecl 0.10 has no in-tree usage of
  and which naga's MSL backend would defeat anyway — it writes components
  1..3 as literal zeros. Only worth doing if a 64-wide target enters scope.
- The confirm round trip is dominated by fixed cost, not by the verdict
  buffer: three fresh device allocations per membership confirm, six per range
  confirm, and one blocking readback. Packing the verdicts 32x shrinks the part
  that was already ~10% of the trip. The order-of-magnitude move is keeping the
  region's liveness resident on the device across confirms — at which point two
  confirms over adjacent regions of the same buffer really do collide on the
  shared edge word and the merge has to become `atomicAnd`, which kill-only
  makes idempotent and order-free.
- `ProposalBuffer::retain_region` moves each survivor's liveness bit down one
  index at a time. It is correct (writes only trail reads) but is a per-entry
  read-modify-write where the word-per-candidate layout had a slot copy; it is
  the one compaction path packing made *worse*, and it runs once per
  `UnionConstraint::propose` variant that is satisfied on only some rows. If a
  union-heavy profile ever shows it, the word-aligned bulk case (`base % 32 ==
  0` and a run of survivors) can be lifted to whole-word shifts.
