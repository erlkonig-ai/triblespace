# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Replace retained BTree state with PATCH across collection resolution and
  covers, store dependencies and retention roots, maintenance observations,
  network routing/providers/health, automata, registers, and semantic-index
  configuration. Collection relations use flat typed keys and borrowed prefix
  views; actual per-operation scratch and independent ordered-map test oracles
  remain. Preserve value-sensitive observations and deterministic ordering;
  public set/view types change, but wire and persisted formats do not.

- Make Pile's blob index content-keyed with a single first-valid representative.
  Ignore redundant readable occurrences within one mapping while preserving
  corruption recovery and conservative rewrite invalidation. Replace scoped
  pointer-prefix comparisons with semantic record deltas; duplicate replay may
  now perform payload validation. No wire or persisted record format changes.

- Remove the generic storage-snapshot timestamp and `snapshot_at` APIs. A
  snapshot is an immutable content observation; application deadlines use an
  explicit evaluation time instead. Content change and dependency comparison
  retain their existing semantics.

- Handle both SIGINT and SIGTERM in the Unix CLI sync and maintenance workers.
  Register before writable pile open, cancel awaited work or idle waits on stop,
  and reach the existing explicit close boundary. Synchronous work remains
  cooperative; request limits, maintenance plans and persistence APIs are unchanged.

- Remove the unused hybrid residual-read API and PatternUnion query wrapper.
  Reads expose the selected resident index cover; exact historical support and
  explicit maintenance remain separate operations. A record whose target blob
  is absent does not make the reader fall back to raw source members.

- Make Net admission and hydration visible after local put without automatic
  disk flushes or a retained durable-answer cache. Explicit close remains the
  persistence boundary; manual flush, put and refresh errors remain observable.
  Keep physical corruption/valid-duplicate read semantics, frozen observations,
  and existing request concurrency. Remove obsolete pending-flush health state.

- Add an owning `Leech<S>` with the existing local store and exact-acquisition
  traits, but no serving-inventory refresh or collection activation. Keep
  ordinary Peer serving behavior and the exact-H bearer protocol unchanged;
  no new public reader adapter, cache, durability policy or background task.

- Add test-only foreground Peer lifecycle counters separating frozen exact
  reads, bare blob-reader refresh, first full serving-inventory construction,
  and subsequent locator-index deltas. Count enumerated handles rather than
  payload hashes; production refresh and publication policies are unchanged.

- Carry the existing `Blob<UnknownBlob>` through interactive, descriptor and
  bulk-replication landing. The wire constructs it once and checks its cached
  handle against the request; destination insertion no longer reconstructs and
  hashes that Blob again. Existing Pile first-read validation is unchanged.

- Experiment with exact-H directory queries during authenticated routing
  progress. FIND_NODE, directory and body requests share three slots; routing
  retains one slot while open. At most K early directory attempts plus the
  final K preserve a bounded final-replica query opportunity, not guaranteed
  acquisition under the unchanged 64-provider cap. Caller deadlines, body
  verification and final-union publication/collection discovery are unchanged.

- Use an existential early exit when deciding resident collection-frontier
  membership, without changing canonical cover selection, support, or admission.
  This avoids traversing the complete upper history merely to prove one
  resident subsumer exists.

- Avoid recomputing collection-record fingerprints for field-only selectors.
  Mixed selector unions hash only when their field routes do not match;
  physical identities, result ordering and authentication are unchanged.

- Add bounded test-only exact-H diagnostics: fresh versus retained routing
  counts, repeated publication/acquisition opcode counts, routing-versus-directory
  stall controls, and an exact bearer GET application-byte control. These use
  production routing and RPC code but do not measure simulated link throughput
  or change transport, scheduling, wire bytes, or live state.

- Experiment with four concurrent exact-handle hydration fetches within one
  service class's existing deadline. Completed bodies land serially;
  a stalled first request no longer blocks ready later answers. Owned lazy Peer
  fetch futures start only when polled. Cancellation, retry accounting and
  frozen rounds remain bounded; recursive speculation stays serial and keeps
  its existing allowance. This is not a measured live-throughput claim.

- Scope CLI maintenance-watch eligibility to the preceding active pass's raw
  record/blob/proof interests through opt-in `repo::ObservedStore` forwarding.
  Misses and relevant concurrent arrivals remain retry interests; unrelated
  writes and WANTs need not repeat collection algebra. Native collection APIs,
  canonical plans, publication and protocol formats are unchanged.

- Keep an already-started recursive hydration startup window across later
  root arrivals, so its next word does not repeatedly lose priority. Enforce
  its 128-word allowance even for partial local-word quanta; completion or
  local unavailability releases it. Ordinary turns, collection rotation and
  global fetch limits are unchanged.

- Exact-body reception no longer holds shared scratch capacity across idle
  network waits. Independent bodies use one 1 MiB scratch buffer, at most
  sixteen admitted body attempts, and a 64 GiB rounded temporary-storage budget
  retained through the last returned byte owner. Configured receive-limit
  exhaustion fails without a queued permit or discarding the authenticated
  provider connection; caller deadlines, bearer proofs and hashes are unchanged.

- Start exact-H blob GETs from verified provider hints while other directory
  replies remain pending. Directory and provider operations share the existing
  three request slots and at most 64 distinct provider attempts. Transient
  attempt selection is arrival-sensitive; canonical collection discovery,
  bearer authorization, byte validation and caller deadlines are unchanged.

- Rotate hydration service between eligible WANT, new direct-root, ordinary
  direct-root, and recursive-scan classes. First-attempt priority does not renew
  on re-observation; frozen ordinary rounds preserve old-demand service under
  arrivals. Retry deadlines and exact-H acquisition remain unchanged. Service
  uses whole fetch-budget quanta, not a low-latency or completion guarantee.

- Separate target-first collection reading from lazy exact support queries.
  Accepted target endorsements remain readable before their historical source
  records arrive. Collection observations track their consulted dependencies
  and expose `is_current`; Pile and Peer snapshots preserve scoped comparison
  through native record and physical blob-occurrence indexes.

- Add a compact grow-only entity-ID set encoding with canonical authored union,
  structural shared-byte attachment, and lazy logical cover iteration. Audits
  stay explicit, and entity IDs do not become blob dependencies. The encoding
  ID `0BF639287590CFC9CE0E2B83D9FBC1E3` was minted with `trible genid` on
  2026-09-15. An ordinary `SimpleArchive` derivation projects the typed `GenId`
  values of one configured attribute, not assertion subjects or qualifiers;
  receipt COMMITs remain unchanged. Configuration reuses `metadata::attribute`.
  Mapping algorithm `7E4257A14880E8B4855B6282B337B4B5` was minted with installed
  `trible genid` on 2026-09-15; encoding bytes and identity are unchanged.

- Separate maintained-index attachment from canonical audits and query
  preparation. Typed views retain persisted backing and check safe framing;
  they do not reconstruct canonical data or serialize temporary cover unions.
  Sparse reference summaries expose an explicit prepared membership query,
  while dense summaries remain direct byte views. NVFP4 attachment no longer
  scans every row, and SimpleArchive interpretation unions its archive-backed
  PATCH leaves directly. BM25 and LWW expose query preparation for information
  their wire formats do not store. Persisted bytes and identifiers are unchanged;
  full representation audits remain explicit.

- Path-summary attachment retains the stored carriers and their automaton.
  Canonical automaton/summary audits are explicit; `PathSummaryView::prepare`
  joins decoded summaries once and computes cross-member reachability without
  re-encoding or hashing an expanding sequence of intermediate members.

- Connect the existing CubeCL wavelet backend to canonical raw Succinct
  construction and target compaction through `BackendSuccinctMapping`.
  Collection identity remains backend-independent; CPU-reference plumbing tests
  and explicit, ignored CUDA byte/hash/union and signed-maintenance gates cover
  the execution choice. CUDA maintenance is opt-in, not a new rollup lifecycle.

- Bias explicitly selected CLI maintenance targets by the author's public key.
  Each author retains deterministic priority independent of argument order;
  dependency-first scheduling, once-per-pass deduplication, and canonical
  collection equation plans are unchanged. This spreads first attempts, not
  exclusive ownership or a guarantee of no duplicate computation.

- Pin AnyBytes `066c32a7` so freezing an immutable section no longer flushes
  its temporary mmap. Persistence retains an explicit durability barrier.

- Reuse the collection-repair record PATCH when only blobs or authorization
  proofs change. Hydrating one blob no longer enumerates and rehashes every
  active collection's unchanged records. Authorization still observes current
  resident capability definitions, and newly activated collections construct
  their own record component.

- Interpret AUTH permissions from immutable capability-definition blobs. Proof
  edges carry only a definition handle, delegate key, and prefix signature;
  invocation and onward delegation are independent action sets, with attenuation
  checked along each valid prefix. Collection READ/WRITE admission is timeless.
  Generic subordinate resources advertise their own immutable repair audience
  and policy without inheriting collection authority. Bootstrap discloses only
  the needed subject prefix. This is a new AUTH record and pile-sync/26 epoch;
  existing collection descriptors and entity identities are unchanged.
  Minted anchors: delegation action `628AB41154C8BAE6F985591B58487374`, AUTH
  descriptor `C7116B04EE6DA4BADFDE77D79692AEFF`, resource handle
  `5059416BAF824B364FF52F56A0D1CF9F`, repair audience
  `62E951EC3ABB7F9B7F123BB7DE2F9F99`.

- Use the existing per-collection record selector for foundational admission,
  avoiding a whole-store record enumeration for each collection attachment.
  Preserve author admission, direct-reference residency, trusted local signature
  handling, and canonical results; cover the indexed route with counters rather
  than elapsed-time assertions.

- Add descriptor-driven `trible pile collection maintain-all` and foreground
  `--watch` maintenance for explicitly selected collections. Schedule source
  dependencies with ordinary one-edge operations, deduplicate shared work, and
  keep snapshot change detection separate from authorization time. Mapping
  kernels, collection identities, and pile record formats are unchanged.

- Semantic-index descriptors now reference the selected model and tokenizer
  root ids plus Mary's containing collection handle, never its member archive
  support. Extra observations, other models, and support repackaging leave the
  same selected index identity unchanged. Mapping reads receive the existing
  frozen `StoreRead` context so explicit collection dependencies share source
  admission and authorization. A bounded thread cache reuses one attached
  observation without inventing another model identity. No existing descriptor,
  result, or live pile is rewritten. Minted with `trible genid` on 2026-09-14:
  algorithm `2B69128192930EE0782CCA03B97677F5`, tokenizer-reference anchor
  `E6A241C22B0457CD24AE65C1FC6AC177`. Collection references reuse Mary's anchor
  `CC07F0AFB3DCFD254A54A883E86E2617`; independently minted
  `CEB51BC9B3A56A0F29AEE923F13B3D71` was not used.

- Add a read-only cluster dashboard projection over one immutable pile
  snapshot. It keeps exact local blob residency, stored COMMIT/MERGE/DERIVE
  equations, durable requested work, and replicated observer reports as four
  separate evidence planes. Swarm-health reports now carry optional counters
  for local blob count, pairwise record/proof leaves, and DHT publication work;
  absence remains distinct from zero and record convergence is never presented
  as blob availability.

- `Pile::rewrite_retained_into` carries frames of unknown kind exactly, by
  their own length, instead of refusing the whole rewrite: it keeps every
  resident blob, so it cannot orphan whatever such a frame names, and a binary
  that knows the kind reads it from the rewritten pile unchanged. The frames
  are counted in `PileRewriteStats::opaque_frames`; retries dedupe them by
  exact bytes. `PileRewriteError::OpaqueRecords` is gone. Yard reclamation,
  which drops blobs, still fails closed on them (JP, 2026-09-13: copy them
  whole, we have their length).
- Sign native MERGE and DERIVE equations and admit their producers through the
  target collection's WRITE policy. Foreign dense record decoding verifies each
  signature once; trusted local replay and attachment do not repeat that work.
  COMMIT's signed bytes are unchanged. The repair protocol advances to epoch 25;
  legacy unsigned equations remain inert, byte-preserved evidence with their
  resident references retained. Re-endorsing them is an explicit migration, not
  an automatic receiver-side signature.
- Pass an explicit signing key to ensure/maintain operations. Reuse needs no
  producer grant; missing derivations require target WRITE, while optional
  compaction may retain a finer cover. Add `trible pile verify` for a read-only
  physical-record signature audit without loading collection payloads.

- Give explicitly selected Full-replication collections sustained scan quanta,
  including work beyond the recent startup window. Preserve shared exact demand,
  physical roots and aggregate budgets; shared closures retain per-selection
  positive progress without a priority registry or persistent negative frontier.

- Add a bounded in-memory exact-fetch diagnostic using normal DHT discovery
  and bearer transport, with an ephemeral key and no publication or WANTs.

- Seed full scans with positively resident selected descriptor roots after
  ordinary roots, so the existing finite recent window also serves descriptors
  promptly at cold startup. Preserve root membership and idempotent progress.

- Schedule full-replication scans in fair resumable positive-source quanta,
  with a bounded recent-arrival startup window and lane turns retained across
  fetch deadlines. Retry completed parents independently of large unfinished
  blobs; preserve aggregate budgets and keep speculative negatives out of
  persistent traversal state and WANTs.

- Add explicitly selected demand/shallow/full blob replication without changing
  record repair, bearer authorization, or WANT semantics. Bound recursive work
  with a resumable positive PATCH frontier and retry speculative misses without
  persisting negative demand.
- Add canonical unionable reference-summary collections over complete producer
  closures. Consumers reuse resident or fetched outputs as support-scoped Bloom
  negatives; they never derive summaries from incomplete local caches. Share the
  existing opaque blob-locator KDF between the encoding and network layer, and
  expose registration/maintenance plus replication selection in `trible`.

- Expose bounded local swarm-health observations from existing collection
  repair, serving-snapshot, event-loop, and DHT-publication work. Opt-in
  `trible pile net sync --health-key` publishes timestamped private native facts;
  `pile net health` reads them locally. Stable alert/recovery episodes avoid
  heartbeat spam; no new wire protocol, eager blob probe, or global health claim.

- Keep an aged collection-repair comparison non-actionable when the latest
  completed pull succeeded. After startup grace, alert on a stale comparison
  only when the latest pull failed or timed out; persistent differing frontiers
  remain actionable independently.

- Make swarm-health sample age a reader policy: reports carry `created_at`
  without producer expiry. `pile net health --max-age SECONDS` and
  `TRIBLESPACE_HEALTH_MAX_AGE_SECS` select the maximum age (default 180 seconds),
  ignoring legacy expiry annotations while keeping future reports unknown.

- Constrain the netwatch dependency to the tested patched version so a newer
  registry candidate cannot silently bypass the root's multi-sender wakeup fix.

- Distinguish Iroh handshake/registration from host dispatch with opt-in
  connection-handoff tracing. Keep RPC spans scoped to future polls rather
  than holding entered spans across awaits; no wire or admission change.

- Clarify that exact repair includes native MERGE/DERIVE records, and that
  bearer-handle discovery does not encrypt or hide guessable blob content.

- Select the next pending provider publication by direct ordered PATCH descent
  instead of constructing and sorting a full iterator for one key. Preserve
  lexical order, stale-entry removal, lane fairness, and current resident values;
  the long-lived renewal traversal is unchanged.

- Document the measured directory representation tradeoff and the existing
  retention effect of WANT's resident direct blob references.

- Prototype a two-PATCH provider directory beside the live four-index version.
  Differential tests retain exact capacity, expiry, renewal, provider ordering,
  and responsibility eviction semantics; an opt-in fresh-process probe measures
  representation cost. No live directory or persistence change.

- Add a test-only DHT restart experiment using the real XOR routing and lookup
  machine. Save authenticated endpoint identities as a bounded canonical PATCH
  set in native bytes, restore only candidates, and compare cold/warm discovery,
  dead contacts, authenticated poisoned views, and a configured-bootstrap first
  wave. No host persistence, provider lease, pile format, or protocol change.

- Wake SimNet accept calls on connection close even while they wait for the
  accept-queue mutex. Capture the close notification before the flag check and
  prioritize it over queued streams, with deterministic mutex-held regressions.

- Make SimNet stream halves observe connection close, crash, and partition:
  pending reads/writes wake with a reset, buffered bytes are discarded, and
  healing or endpoint restart cannot revive old streams. A deterministic
  production-acquisition regression crashes during a backpressured exact-blob
  response, rejects the old transfer, then retries on a fresh connection
  without collection/WANT effects. Production Iroh/runtime behavior is unchanged.

- Exercise exact-H acquisition after provider loss with an unchanged stale
  directory lease, an independently advertised alternate, and a same-endpoint
  handler restart. Cover cancellation of a discovered provider dial followed
  by a same-client retry, retaining the directory connection without abandoned
  pool entries or collection/WANT effects, and cancellation of a stalled dial
  when another discovered provider succeeds. These paused-time simulation
  tests change no production protocol or persistence behavior.

- Extend the test-only DHT directory model with bounded immutable PATCH proof
  node reuse across signed inventory roots. Compare actual node/fanout byte
  counts, digest references and cache-miss requests against independent paths
  for cold transfer, unchanged renewal, growth and partial responsibility.
  Preserve full proof verification, every root-bound membership change, and
  original lease expiry; no provider wire, host, routing or persistence change.

- Recheck Pile shared-replay parse failures once under an exclusive file lock
  with a fresh observed length. This distinguishes an in-flight append from a
  persistent malformed record without retrying writes or truncating data, and
  covers both snapshots and shared blob-writer preflight. Preserve readback's
  stop at the completed blob before any later partial tail.

- Add a wire-free DHT directory model using the existing Merkle PATCH repair
  walker. Seven deterministic tests compare per-entry leases with signed
  inventory roots, including forwarding, restart, expiry, partial responsibility
  ranges, membership-proof binding, and logical publication budgets. Unchanged
  inventory renewal can leave content untouched; the changed-root probe exposes
  the cost of refreshing membership proofs. This is test-only exploration with
  a trusted shared clock and synthetic placement, not a wire change, persistent
  cache implementation, or live-network performance claim.

- Release abandoned connection-pool entries when the last pending dial caller
  is cancelled, preserving shared initializer takeover, cached connections,
  and live borrowers of evicted entries. Keep descriptor fetches owned by the
  host and coalesced per active collection while waiting for the bounded
  admission bridge, instead of accumulating detached downloads on each repair tick.

- Generalize AUTH to resource-declared capability definitions. Prefix proofs
  retain inline delegation/time attenuation while naming exact definition
  handles; collection admission and custom audiences query generic policy
  bindings. Net ALPN24 repairs all declared capabilities through scoped
  resource/proof-hash indexes without fetching definitions or weakening READ
  admission. Old proof grammars remain known-inert for explicit cutover.

### Changed

- Let a DHT-selected directory answer an exact blob-locator query with its own
  snapshot-resident provider hint before background publication reaches that
  key. Reserve one bounded reply slot for self, deduplicate stored self entries,
  and preserve deterministic foreign-lease order. This deliberately extends
  lease-only answers without reading payloads, storing leases, announcing,
  changing DHT selection or bearer proof, or adding collection/WANT effects.
  Distinguish valid self and foreign tokens in the read-only directory probe;
  a self hint alone is no longer evidence of a provider PUT.
- Retain finite, hard-bounded local learned-route failure cooldowns across
  repeated DHT referrals. Filter both lookup seeds and reply candidates without
  tying lookup-local progress to positive K-bucket retention; configured routes,
  direct authenticated recovery, and retry after expiry remain available.
- Alternate startup provider-publication backlog with incremental arrivals in
  bounded pending turns, preserving due-renewal/retry fairness and each pending
  lane through topology outages. Report scalar queue, attempt, and retained
  directory counts every thirty seconds without logging handles, locators, or
  tokens; remote acknowledgements count attempts, not unique lease coverage.
- Retire issued, unanswered learned DHT routes when a bounded routing window
  cancels them, so stale close candidates cannot monopolize repeated background
  publication attempts. Preserve configured routes, unissued candidates, partial
  authenticated responders, and existing lookup deadlines; cover the remaining
  configured-only cold-start limit explicitly.
- Add a bounded, read-only DHT directory example for exact blob locators. Reuse
  the public protocol operations and expose the existing locator/token
  derivations without sending bearer handles, fetching bodies, or publishing
  leases. An optional passive pile scan reports locator rank and probes the
  minimum resident locator with constant additional inventory state.
- Isolate exact-blob receiver unit tests that otherwise shared one process-wide
  receive permit across independent paused Tokio clocks. Cover same-runtime
  receive contention within the unchanged ten-second foreground deadline;
  production receive limits, DHT scheduling, and lookup deadlines are unchanged.
- Let peer snapshots fetch and cache exact immutable blobs with shared async
  `get`, without advancing frozen records, proofs, authorization time, or
  selected covers. Keep passive residency/collection reads local, never emit
  implicit WANTs, and allow explicit close with retained snapshots. Apply the
  same separation to object-store snapshot GETs.
- Let foreground exact-H DHT acquisition use its existing end-to-end deadline
  instead of cancelling cold bootstrap connections at the background lookup's
  three-second cap. Retain short background lookup bounds and distinguish
  responsive provider misses from transport failures and deadline exhaustion
  in diagnostics, without changing bearer authorization or creating WANTs.
- Make the canonical PROOF magic the native Pile record kind itself. Records
  are generic framing followed directly by the prefix-signed proof; remove the
  nested length/reserved wrapper and separate inner magic. Fixed-width edges
  and zero padding preserve exact proof bytes without another length field.
  The standalone wire value, signatures, content hash, and mmap view all start
  at the same 32-byte type identifier. New description anchor minted with
  `trible genid` on 2026-09-06: `D81538DE724347280A6D97F51EDE08F6`.
- Store resource authorization as descriptor-local capability-handle bindings
  to Open or independent-root quorum policies. Collection READ/WRITE remain
  construction conveniences over stable SimpleArchive definition blobs; custom
  definitions share exact-handle grant and audience APIs without borrowing
  READ/WRITE authority. Preserve definition attachments and raw custom binding
  facts, and keep ordinary admission query-shaped. New attribute anchors minted
  with installed `trible genid` on 2026-09-06:
  `D6065F21923709C72144866C05F74B46` (resource_policy) and
  `2949050AA6092F5689EA7EAA52700CE9` (capability_handle).
- Store capability proofs as shared owning byte views. Pile replay validates
  canonical framing once and retains mmap-backed proof values in its existing
  PATCH index; snapshots, exact lookups, and iteration clone those values without
  reparsing or copying proof bytes. Borrowed parsing remains available, and
  `from_owned_bytes` accepts existing byte owners without copying. Proof bytes,
  content identities, signature checks, and authorization semantics are unchanged.
- Let derived maintenance follow the coarsest resident immediate-source cover
  before ordinary target size-tier carries. Reuse existing child images when
  a source merge witnesses their union, or map the resident coarse source
  directly; do not construct historical intermediate images or upstream blobs.
  Source-guided carries can cross target size tiers. Keep `ensure` coverage-only.
  Add an optional image-join computation hook, allowing Rank9 construction to
  reuse the resident raw union without serializing or hashing it again and to
  decline unwitnessed carries before speculative raw work. Persisted records,
  descriptor identities, and canonical blob encodings are unchanged.
- Replace the unshipped observed-only register collection with
  `collection::latest::{LatestBlob, LatestIndex}`. Maintain known live heads
  and all historical superseded targets with a canonical no-resurrection join;
  project every source subject so derivation distributes over split entity
  fields. Expose positive `.has(state)` membership through the ordinary query
  protocol, also for `LwwIndex`'s existing known complete winners. Correct the
  distinction between fixed-order antichains and observation-dependent heads.
  Fresh encoding/mapping ids were minted with installed `trible genid` on
  2026-09-05: `35304D6FF3421A1F9C0DCF4F8C45D392` and
  `2D3DFB807700200A43FD841406B46D77`. Source identities and old bytes are unchanged.
- Remove whole-document collection descriptor validation: retired attributes,
  extra names, and annotations on derived descriptors no longer reject usable
  collection facts. Typed opening/registration recognizes its requested encoding
  independently of policy. Ordinary READ/WRITE admission queries supported
  policy alternatives on the same descriptor entity as the requested encoding;
  any authorizing alternative suffices, without pooling quorum shares between
  alternatives. Missing/unknown policy interpretations grant nothing and leave
  ordinary root observations empty. Network repair uses the same policy-query
  semantics. Explicit scalar policy inspection and executable lineage retain
  their ambiguity diagnostics; plural source/mapping interpretation remains
  unresolved. Descriptor, blob, native-record, and protocol bytes are unchanged.
- Ordinary derived `ensure` and `maintain` select the admitted support already
  realized by their immediate source. A new foundational commit, an unbuilt
  intermediate member, or a dangling source equation no longer makes a
  downstream maintenance call fail or construct upstream work. Explicit
  `*_exact` requests retain their strict support requirement.
- Add `Peer::lazy` over the existing store adapter. Resident reads, snapshots,
  writes, and durability boundaries start no host and build no serving inventory;
  a missing exact-handle acquisition or explicit activation starts networking
  once. Snapshot reads remain resident-only and acquisition never creates WANT.
  Forward explicit flush and close, withdrawing host snapshots before closing
  the backing store.
- Preserve the exact absent handle in `repo::MissingBlob` through Pile read
  error sources, so live callers can acquire demanded content without making
  frozen snapshots networked or prefetching entire attachment graphs.

- Add `CollectionStoreExt::acquire_read_audience_at` as the live counterpart
  to inert snapshot audience discovery. It freezes the proof/control frontier,
  acquires only the exact collection descriptor, evaluates self-contained
  proofs rooted in READ(C), emits no WANT, and excludes concurrently arriving
  proofs until the next call.
- Cover the cold collection-bootstrap path where a recipient knows only a
  collection handle and one issuer endpoint: issuer-held complete READ(C)
  evidence admits repair, while a transferred native proof is already complete
  and the repaired payload remains an ordinary exact-H acquisition which
  creates no WANT.
- Make each derived target encoding own its canonical `Source`, runtime
  `Argument`, descriptor binding, and member map through
  `CollectionDerivation`. `derive::<Target>(source, argument, policy)` still
  returns an ordinary `Collection<Target>`, while `ensure` and `maintain` now
  infer the derivation directly from that target and require no public mapping
  witness type. Preserve `CollectionMapping` and the explicit `derive_with`,
  `ensure_with`, and `maintain_with` seam for downstream mappings between two
  foreign encoding types that Rust's orphan rule prevents either crate from
  attaching to the target.
- Make `NvFp4CosineSet<E>` own its canonical `SimpleArchive` derivation, with
  `NvFp4EmbeddingAttribute` carrying the selected attribute and dimension as
  runtime descriptor arguments. This removes the public per-edge mapping
  witness without changing descriptor or member bytes.
- Retain each canonical regular-path automaton as a typed content-addressed
  blob and interpret `PathSummaryBlob` members through that immutable child.
  The existing 32-byte fingerprint header is already the BLAKE3 handle of the
  canonical wire, so summary bytes and handles remain unchanged; new mapping
  fragments carry the automaton blob in their attachment closure. Make
  `PathSummaryBlob` own this canonical derivation with `Automaton` as its
  runtime argument, removing the separate `RegularPathMapping` witness from
  derive, ensure, and maintain calls without changing persisted descriptors.
- Let active exact collection realization recover from a dangling immediate
  `DERIVE` whose output cannot be acquired. When its source input is resident,
  the unusable equation remains semantically invisible and the canonical
  mapping deterministically reconstructs and republishes the output.
- Make authorization time an explicit input to every frozen collection read.
  Remove the hidden-current-clock `Collection` conveniences in favor of their
  existing `*_at` forms, and make exact-support attachment clock-free. Live
  `ensure` and `maintain` operations continue to sample one instant at their
  mutable store boundary.
- Rename the peer's effect-neutral exact-byte transport from
  `fetch_wanted_blob` to `fetch_blob`, and abort an entire reconciliation pass
  when its frozen collection-record observation fails instead of treating the
  partial observation as an empty receipt set.
- Make physical blob lifetime a structural law shared by MemoryRepo, Pile, and
  Yard. Every retained COMMIT, MERGE, DERIVE, and WANT now owns each
  independently resident direct blob reference recursively, without fetching,
  signature/admission filtering, or failure for missing sibling references.
  Authorization proofs remain retained native records but are self-contained
  and own no blob closure. Remove the collection-specific retention planner and
  Yard's weak/budgeted WANT eviction path.
- Keep native authorization-proof repair independent of blob demand: receiving
  a self-contained proof creates no blob acquisition or `Blob(H)` WANT.
- Replace separate collection WRITE evidence with one collection-scoped
  authorization-evidence projection containing structurally relevant native
  READ(C) and WRITE(C) proofs. Repair transports the complete proof records and
  no authorization blob closure. `ReconcileDirection` now gates only collection
  repair, so H discovery, publication, serving, and fetching remain available
  in every direction. The record component contains every signature-valid
  exact-C COMMIT independent of WRITE admission, so records and grants commute;
  each receiver derives activation locally.
- Restore bounded target-carry batching under invariant foundational support.
  Maintenance resolves collection semantics once per actionable dyadic tier
  round instead of once per individual `MERGE`, while each disjoint result is
  still stored and published immediately. Tier planning retains only indexed
  member identities and loads one input pair at a time.

- Remove the obsolete `SimpleArchive`-specific publication and materialization
  facade. Signed publication now has one public path through
  `CollectionStoreExt::commit` (or the retained prepared/staged commit
  boundary), merge work through generic collection maintenance, and logical
  reconstruction through `Cover` / `CollectionSnapshot` and `TryFromCover`.

- Split exact derived construction from physical maintenance. `ensure` and
  `ensure_exact` now publish missing `DERIVE` work only; `maintain` and
  `maintain_exact` additionally perform deterministic dyadic size-tiered LSM
  `MERGE` work in the target lattice. Every mapping hop is explicit over the
  same invariant foundational `Support = Cover<SimpleArchive>`; downstream
  maintenance never creates upstream blobs or merges. The store-level
  operations return a fresh immutable `StoreSnapshot`, from which callers
  select a typed `CollectionSnapshot<R, E>` and reconstruct views on demand.

- Make `ensure`, `ensure_exact`, `maintain`, and `maintain_exact` the single
  asynchronous live-store API. They may acquire exact missing dependencies
  without recording a durable `WANT`; local stores complete resident
  acquisition immediately. Remove the duplicate resident-only public methods
  and the `_async` method-name variants.

- Add a derived segmented pile index over `collection handle || record fingerprint` so
  collection-only selector unions visit only the named descriptors' records
  while preserving the full-width fingerprint index as physical storage and
  ordering. Collection records themselves have no synthetic semantic identity.

- Replace WANT's per-request LWW assertion/retraction log with one grow-only
  canonical request set. `WantStore::unwant`, every adapter, and direct
  mutation of `MemoryRepo`'s backing set are removed; Blob, Merge, and Derive
  requests share the freshly minted
  `pile-want-v3` kind rooted at `E6CEE6F8578E3B8DB4C081486A8CBD28`
  (`82EE8C72E252AB403C431AA98C9E77C0EA89796A8111DFF8C252ABCDE6F87D6F`).
  Former blob/typed assert/retract and weak-pin/unpin records remain
  structurally readable but inert. The deliberately explicit, additive
  `trible pile migrate <pile> run monotone-wants` resolves their old log once
  and appends only missing current positives; semantic reframe does the same,
  while ordinary compaction drops retired frames. Yard unions wants across all
  generations and treats each retained request's resident direct references as
  recursive ownership roots until a deliberate physical rewrite omits the
  request.

- Retire the obsolete team-era repository state. `Store` snapshots no longer
  require `PeerRead`, mutable stores no longer require `PeerStore`, and Pile,
  Yard, Hybrid, Lazy, and MemoryRepo carry no PEER or STORE_SCOPE indexes.
  Existing framed records remain structurally readable as known inert kinds;
  semantic reframe, reclaim, and compaction deliberately drop them while still
  refusing genuinely unknown records.

- Keep the 30-second collection PATCH-repair cadence while making KDF(C)
  provider discovery bootstrap- and recovery-only. Healthy signed origins stay
  live through five-minute leases renewed by successful repair, each
  collection has one exponentially backed-off lookup in flight only after
  activation, lease exhaustion, or failure of every candidate, and bounded
  learned gossip peers survive topic resubscription.

- Keep `Cover<E>` as the sole public collection-lattice value and add checked
  PATCH-backed union, intersection, difference, and subset operations. Replace
  public physical `resolve` with `available`, which returns the greatest subset
  of requested semantic members having a complete resident realization, and
  `materialize`, which selects a support-equivalent physical decomposition
  privately through the supplied snapshot before invoking the typed view.

- Replace the pile's semantic-handle PATCH and Arc-linked duplicate chains with
  one segmented `hash || offset` PATCH relation. Its zero-copy 32-byte prefix
  projection provides semantic listing, membership, differences, and cover
  intersection without duplicating every handle. Lazy validation lives inline
  in occurrence leaves, walks offsets in file order, and can recover from any
  valid duplicate.

- Return exact empty NVFP4 search results before query preparation or scanner
  execution when a cover has no logical rows, and document that Mary scan
  segments receive the persisted reconstruction-norm and error-certificate
  planes while row handles and exact sources remain search-owned.

- Make Rank9 acceleration an ordinary full derived lattice. Raw Succinct and
  Rank9-accelerated members each own a canonical join. The accelerated join may
  consume its exact immutable raw union when already resident, but never
  creates that upstream blob or `MERGE`. Without the dependency, maintenance
  retains a finer accelerated cover; callers maintain each mapping hop
  explicitly with the same foundational support.

### Added

- Add `CollectionSnapshotExt::collection_at` so a caller can bind admission
  and maximal resident target selection to one explicit authorization instant.

- Add `Collection::policy` for reading a validated descriptor's immutable
  READ and WRITE policy from one store snapshot without proof discovery.

- Add `trible pile compact <SOURCE> --into <DESTINATION>` for out-of-place,
  non-GC pile repacking. It retains every distinct valid blob, collapses exact
  duplicate native set records, preserves all distinct COMMIT/MERGE/DERIVE and
  capability evidence, and projects active local WANT/pin state once. Blob
  records receive fresh timestamps; corrupt duplicate occurrences and known
  semantically inert retired records—including PEER and STORE_SCOPE—are
  omitted. It
  refuses opaque records, attempts to remove an incomplete fresh destination
  after failure, and reports cleanup failure. On Unix the destination is
  created no broader than mode 0600 before source permissions are applied
  through its retained file handle after rewriting. Quiesce writers when the
  result must cover the exact whole file rather than a valid observed prefix.

- Add an optional resident CUDA scanner for canonical two-stage NVFP4 search.
  Mary receives validated compact stage and certificate planes and returns
  conservative raw-dot uppers; cover deduplication, exact source fetches,
  reranking, and result ordering remain singular in `triblespace-search`. One
  combined readback covers every physical LSM member.

- Make `WantRequest::Blob(H)` the sole durable exact-content request.
  `MemoryRepo`, `Pile`, Yard, retained rewrites, and pile diagnostics preserve
  its canonical identity, while collection-independent reconciliation can
  satisfy it from the global exact-content provider directory.

- Add private exact-content discovery under the full-width, domain-separated
  locator `L = KDF(H)`. DHT leases carry an H-bound endpoint token. On the
  direct stream the authenticated provider proves knowledge of H first and the
  requester proves it second, with both proofs bound to the two TLS endpoint
  identities. H never crosses the wire, and returned bytes are accepted only
  after hashing to H. Collection READ(C) remains solely the admission boundary
  for collection anti-entropy and never gates exact GET.

- Add `pile collection init <PILE> <NAME> [--key PATH]` to register one
  canonical `SimpleArchive` root descriptor under an existing durable signing
  key's direct READ and WRITE authority. It prints the exact descriptor handle,
  emits no synthetic commit, and is replay-idempotent.

- Add symmetric `grant_collection_read` / `grant_collection_write` APIs and
  `pile collection grant-read` / `grant-write` commands for an exact existing
  collection and recipient key. Each root-only operation validates the
  descriptor's matching action policy before mutation, issues and inserts one
  unbounded self-contained Invoke proof, and is deterministic and
  replay-idempotent. There are no companion claim blobs to persist.

- Add a read-only `Collection::<E>::open` boundary for validating an existing
  descriptor handle against a coherent snapshot, plus descriptor-free
  `PreparedCollectionCommit` staging against an already typed
  `Collection<SimpleArchive>`. Importers can write fragment dependencies once,
  validate or publish derived artifacts, and insert the native signed commit
  last through `finalize`.

- Add a stock `iroh-gossip` collection wake plane on the existing endpoint and
  router. A domain-separated one-way image of the collection handle is the
  topic, while C remains its discovery capability; a dense 145-byte non-serde
  nonce-v4 envelope carries only version, strictly signed endpoint origin, one
  opaque repair root, fresh nonce, and signature. Payload synchronization
  remains separate and bearer-addressed.

- Add an immutable per-collection repair overlay: exact signed COMMIT records and
  every structurally relevant self-contained native READ(C) or WRITE(C) proof
  form two canonical grow-only PATCHes and one opaque, domain-separated wake digest.
  Authorization evidence inventory is independent of wall-clock expiry,
  quorum completeness, and current mode admission. Repair sends native proof
  bodies only; each body already contains the complete path and restrictions.
  A bounded set of native READ proofs may cold-bootstrap a server for a later
  retry, but never admits the same immutable session. Core also exposes
  deterministic finite READ-audience enumeration while representing open READ
  as non-enumerable.

- Add the policy-independent collection-delta element for a future
  READ-authorized push overlay. It strictly frames sparse records, verifies
  embedded COMMIT signatures without deciding WRITE activation, preserves
  MERGE/DERIVE as structurally canonical inert evidence, constructs one opaque
  valued PATCH through an exact collection selector, and selects only bounded
  canonical `current - previous` deltas between patches for that same
  collection. A startup or large gap yields a PATCH-repair decision instead of
  full flooding.

- Extract root-and-count PATCH summaries, node proofs, validation, and the
  pipelined repair walker from the legacy inventory vocabulary. Existing
  inventory reconciliation now uses the overlay-neutral machinery directly
  while preserving pinned snapshots, compressed paths, out-of-order traversal,
  exact count accounting, and fail-closed adversarial checks.

- Add self-contained independent READ and WRITE admission policies to every
  collection descriptor. Each action is either `Open` or a validated quorum
  over a canonical root set with one threshold. Evaluation counts distinct
  independently valid root paths, admits configured roots directly, and adds
  the distinct `ACTION_READ` boundary. Downstream delegation is controlled by
  the mode signed into each path, never by a sibling-proof fixed point or a
  second semantic threshold.

- Add the lean store-owned construction API:
  `store.collection(name, policy)` creates a root `SimpleArchive` collection,
  `store.derive(source, mapping, policy)` creates any derived collection from
  a mapping value with associated `Source`/`Target` encodings, and
  `register_collection::<E>(descriptor)` remains the explicit raw boundary.
  `Collection::admitted_with_commits` returns the exact signed COMMIT roots
  selected by the same admission decision.

- Add `CollectionStoreExt::writer_is_admitted` as a read-only
  pre-publication check. Open policies and subjects satisfying the descriptor's
  WRITE quorum succeed without scanning collection commits.

- Add `Collection::admitted_with_commits` for consumers which need the exact
  strictly verified COMMIT roots selected by one admission decision. The
  returned roots stay narrower than later provenance queries over the same
  cover and immutable store snapshot.

- Give collection validation, canonical joins, mappings, and cover views one
  frozen store-snapshot boundary. Encodings and mappings may resolve immutable
  content-addressed dependencies named by their source members without making
  ambient resident content a semantic input.

- Make every collection member an ordinary typed `Blob<E>`.
  `CollectionEncoding` validates that blob and defines one canonical join;
  `Cover<E>` keeps the logical join total when one member hits a deterministic
  capacity boundary, so every source and derived collection is a full lattice.
  `CollectionMapping` maps blobs to blobs as a join homomorphism, while storage
  owns deterministic merge/derive sequencing and immutable dependencies.

- Add a typed collection API above the representation-neutral wire records.
  `Collection<E>` validates a descriptor's canonical member encoding,
  `Cover<E>` carries only `Handle<E>` members, and `TryFromCover<E>`
  reconstructs either eager values or lazy mmap-backed unions. Signed
  `store.commit` introduces authored `Fragment` leaves into `SimpleArchive`
  source collections; typed covers and logical materialization work across
  encodings. Each `CollectionEncoding` owns canonical validation and one direct
  physical join operation, while covers retain finer equivalent shapes across
  deterministic capacity boundaries and exact derivations bind one parameterized
  `CollectionMapping<Source, Target>` whose ordinary trible fragment is
  embedded in the target descriptor.

- Add an exact maintained last-write-wins register collection. Its canonical
  projection keeps state identity and raw order facts as two independently
  unionable row sets, so the derivation remains a join homomorphism when those
  facts are split across source commits. Attachment pairs complete coordinates
  and indexes the greatest `(order, state-id)` per register; missing halves
  remain incomparable even when an unrelated half is multivalued, while a
  completed conflicting coordinate fails a documented single-coordinate
  contract instead of depending on iteration order.

- Add immutable `CollectionSnapshot<R, E>` values which pair one store
  snapshot with invariant foundational `Support = Cover<SimpleArchive>` and a
  resident target `Cover<E>`. Logical projections are reconstructed on demand
  through `view`; change processing compares the frozen supports without
  reconstructing a `TribleSet` or joining temporary views. The
  evolving-collection benchmark keeps its support accounting outside
  production code.

- Add an end-to-end incremental collection-query benchmark comparing full
  re-query with `pattern_changes!` maintenance over source-identical exact
  Succinct views. It measures one fixed-size commit observation, including
  view admission and application result-set maintenance, while checking raw
  rows, accumulated results, covers, and checkpoints at every step.

- Add `Cover::additions_since` as the pure continuation boundary between two
  exact collection observations. It compares PATCH sets of payload identities,
  returns newly observed members only when the previous cover remains a
  subset, and reports `ResetRequired` before additions-only incremental
  processing can cross a shrinking admission view. A runnable example combines
  exact Succinct full and changed snapshots, `pattern_changes!`, and candidate
  adoption after successful consumption.

- Make a consumer's own records joinable to `telemetry`'s spans rather than
  merely correlated with them by a string. `telemetry::current_span_entity()`
  returns the entity the layer minted for the innermost telemetry span entered
  on this thread, so a consumer inside that span can reference it from its own
  tribles and have "this span" and "this record" be the same entity in a query.
  The layer also captures *every* span field, not only `source`, and implements
  `on_record`, so a fact the caller only learns mid-span is no longer dropped —
  fatal before now for any consumer whose facts are not all known at span
  creation. Fields are `(field_name, field_value)` entities linked by `field`;
  identity is the name/value pair, so spans sharing a field share its entity.
  Values are text, because the layer cannot know a consumer's encodings; typed
  facts belong to the consumer, joined through the span entity. `source` is
  still promoted to its own attribute when it arrives with the span's creation,
  which is all it has ever meant.

- Make successful collection publication automatically emit durable OFFER
  intent before its semantic record. An operation-scoped capture facade covers
  signed COMMIT dependencies and Fragment attachments, SimpleArchive MERGE,
  exact DERIVE and compaction, and Succinct raw/accelerated artifacts. OFFER
  failure withholds the semantic record with a deterministic retry-all batch;
  record failure leaves only harmless grow-only offers. Staged commits expose
  only the capturing facade, so intervening artifact writes cannot silently
  bypass advertisement.

- Add `trible pile migrate <PILE> seed-artifact-offers [--dry-run]` as an
  explicit bridge for resident collection artifacts published before OFFER
  became part of the normal publication boundary. It freezes native records,
  validates every selected resident artifact before appending, recursively
  follows only strictly signed COMMIT ownership, and treats MERGE results and
  DERIVE outputs as direct cache artifacts without pulling their inputs into
  policy. Missing references are counted without becoming WANTs; invalid
  commits are inert; unrelated blobs are never scanned. Re-running is
  idempotent, and seeded OFFERs remain service intent rather than GC roots.

- Add `ArtifactOfferStore`, a bulk-first grow-only local willingness-to-serve
  set with cheap deterministic snapshots. `MemoryRepo`, `Pile`, `Yard`, and
  `HybridStore` implement the primitive; Pile persists each novel offer as one
  self-describing 256-byte record rooted at the `trible genid`-minted anchor
  `6EE89EEA7E6ECB2463FA5EE9C955B378`. Concatenation unions offers, while
  reframing and conservative Pile/Yard rewrites preserve the marker without
  retaining or manufacturing the named blob. OFFER grants no authority,
  demand, reach, collection evidence, or synchronized-inventory membership.

- Add a transport-independent bounded XOR routing core. Its 256 Kademlia-style
  buckets retain at most 20 learned peers each and distinguish remotely named
  candidates from direct authenticated responders. Explicit bootstrap
  configuration remains separate from evictable learned state. A caller-driven
  alpha-3 iterative lookup accepts bounded FIND_NODE hints, retains its K
  closest direct responders independently of long-lived route eviction,
  promotes only the peer that actually answered, removes failed learned routes,
  and terminates without actors, a second transport, or new dependencies.

- Route immutable-artifact provider placement and lookup through authenticated
  alpha-3 FIND_NODE walks. Exact fetch no longer probes the learned peer set:
  serving holders publish only their snapshot-bound admitted collection
  closure through the DHT, while ambient or WRITE-inactive artifacts remain
  clean misses.
  Wire protocol identity advances to pile-sync ALPN v13.

- Add a monotone native store-scope assertion binding one physical repository
  to exactly one Ed25519 team trust root. `MemoryRepo`, `Pile`, and `Yard`
  expose explicit idempotent binding; pile concatenation preserves every
  assertion so conflicting teams fail closed on observation. Reframing,
  retained rewrites, and Yard reclamation preserve the assertion, while it is
  deliberately excluded from synchronized network inventory. `Peer`
  construction is now fallible and refuses unbound, conflicting, or
  wrong-team stores before spawning or exposing a network snapshot. Every
  later refresh revalidates the assertion around snapshot construction and
  withdraws the serving view if an external append introduces disagreement.

- Add one authorized four-component inventory synchronization protocol for a
  single-team store. Exact `SYNC_TEAM(team_public_key)` authority selects PEER,
  collection-record, capability-proof, and blob PATCH roots independently of
  CONNECT. Expected-digest node and bounded blob-range frames pin exact roots
  and reject unavailable snapshots instead of falling back to current state.
  Demand versus Mirror and bidirectional/read-only/write-only direction are
  local policy; evidence presence never grants authority. Bounded periodic
  pairwise reconciliation is the epidemic exchange itself.
- Add deterministic simulation coverage for unified authorized inventory
  synchronization: direction and Demand/Mirror QoS, durable exact WANTs,
  non-serving ReadOnly peers, root/leaf/expiry/mode authorization failures,
  periodic convergence with no broadcast plane, and authenticated PEER-based
  route expansion all exercise the production host and wire path.

- Add native monotone `PEER(team_public_key, peer_public_key)` routing
  evidence. `PeerStore`, `MemoryRepo`, and `Pile` expose one canonical
  validated 64-byte positive fact as a grow-only set; Pile writes it in a
  self-describing fixed frame and indexes it with `PATCH<64>`. Concatenation,
  reopen, reframe, and retained rewrites preserve union semantics, while the
  fact deliberately grants no authority and implies no liveness,
  reachability, residency, or retention. Authorized inventory sessions
  synchronize this evidence and use it as routing candidates; unverified DHT
  referrals never become periodic anti-entropy targets.

- Make PATCH's subtree summary a sealed policy parameter while preserving
  `XorSip128` as the zero-overhead default. Add `Blake3Merkle`, a canonical
  256-bit digest over path-compressed branches in ascending edge order, for
  durable indexes and anti-entropy. Every branch binds its compressed prefix,
  total count, and each child edge/count/digest tuple; archive-backed and heap
  construction share the same policy-generic path and root.

- Recognize the retired V4 collection `DERIVE` record as known inert
  computation rather than an opaque future record. Replay projects no current
  collection evidence from it, and semantic retention rewrites may omit it;
  genuinely unknown kinds continue to stop destructive rewriting.

- Expose `FrontierStats::peak_region()` as the largest proposal region one
  query level materialised at once. This is the proposal-memory high-water
  mark that cumulative proposal count and widest frontier rows cannot recover;
  it is observational only and does not change scheduling.

- Add `trible pile migrate <pile> branch-to-collection` as the generic,
  same-pile bridge from one legacy `Repository` branch to a native
  `SimpleArchive` union collection. The command requires the target collection
  name and signing key; its mandatory descriptor authority defaults to that
  signer and may be overridden explicitly. The command validates the branch
  head and complete reachable commit history before registering the target,
  then publishes locally without conflating storage with admission. It
  preserves each authored commit's exact `repo::content` and
  `metadata::archive`, skips verified contentless merges, resolves both current
  and historical branch-name encodings, and reports every source-to-target
  mapping, including deterministic many-to-one collapse and idempotent replays.

- Add `trible pile net inventory`, a read-only exact manifest probe for the
  bound pile. It prints the canonical `/14` generation plus every component's
  leaf count and PATCH root, and fails closed if sync-visible state changes
  during sampling.

### Changed

- Separate collection repair discovery from exact-content discovery. Active
  collections use endpoint-bound KDF(C) leases for READ(C)-authorized
  anti-entropy, while every served resident blob uses an opaque KDF(H) lease
  with an H-bound provider token. Directory nodes see neither C nor H, and
  WANT(H) can be fulfilled without naming a collection.

- Make store registration the sole source of typed collection values.
  `register_collection` validates a raw descriptor and returns the exact handle
  produced while storing its attachment closure; canonical root/derive builders
  are internal, `Collection::from_descriptor` and the phantom SimpleArchive
  facade are removed, and derived maintenance binds only store-issued source
  and target values while reloading and validating their lineage at use time.

- Make Yard reclaim derive its final store-scope and opaque-record safety
  decisions from one refreshed Pile state, so an opaque record appended during
  rewrite planning is refused instead of being projected away.

- Replace split reader/revision APIs with one coherent immutable store
  observation. `SnapshotSource::snapshot` freezes Blob access, collection
  records, capability proofs, and PEER evidence together; the resulting
  `StoreSnapshot` classifies local invalidation through `changes_since`.
  `PileSnapshot` compares persistent PATCH roots per component, including
  value-only root replacement, while unrelated append-only records remain a
  no-op. Collection reads now follow
  `collection.admitted(&snapshot) -> cover.materialize(&snapshot)`, with
  `cover.available(&snapshot)` exposing resident support in semantic
  coordinates and `collection.read(&snapshot)` as the convenience path.

- Replace the unpublished commit-bearing `CollectionTicket`, `store.ticket`,
  and `exact_ticket_additions` surfaces with one opaque PATCH-backed `Cover`
  value. A cover is identified by its collection descriptor and distinct payload
  handles; duplicate signatures or metadata claims over the same payload are
  optional provenance reported by `cover.claims(&snapshot)`, not new members or
  data work. Replay and derivation require no resident commit or metadata.
  collection admission, exact derivations, maintained Succinct views,
  paths, and network reuse now share this continuation type. Distinct covers
  may have equal foundational support through validated merges. Every mapping
  hop is explicit and receives that same `Support = Cover<SimpleArchive>`.
  Exact derivation can
  reverse-ground a compacted source member through freshly validated `MERGE`
  inputs, so `{c}` may reuse resident `{f(a), f(b)}` when `a join b = c`, while
  forged equations remain inert and fall back to direct construction. Rank9
  uses that same ordinary equivalence route: callers maintain the raw Succinct
  mapping hop and the accelerated mapping hop as separate operations over the
  same support.
  The equivalence route also lets capacity replanning replace a blocked
  compacted member with its resident lower shards. Resolution tries the
  explicit Cover path first and widens into reverse decompositions only when
  needed; unreadable optional inputs and incomplete Merkle closures cannot
  poison an otherwise valid replay or turn speculative misses into durable
  demand.

- Port the remaining benchmark, path/network test, macro-instrumentation, and
  benchmark-ledger callers to the store-centric collection API with mandatory
  descriptor authority. The tribleset benchmark results ledger now uses one
  fixed deliberately public authority key, preserving its prior pile-local
  open trust boundary while giving every run one canonical authority-bearing
  descriptor and ordinary collection admission against one store snapshot.

- Replace the stateful `Collection<S>`/`CollectionAdmission` facade with
  store-centric collection operations. `store.collection(name, policy)` and
  `store.derive(source, mapping, policy)` construct canonical descriptors;
  `store.register_collection::<E>(descriptor)` is the raw custom-descriptor
  boundary; `store.commit(collection, key, fragment)` publishes locally
  without conflating storage with authorization; and
  `collection.admitted(&store_snapshot)` applies the descriptor WRITE policy
  and resident proofs. `Cover` carries one canonical exact payload set for
  resolution and replay through the same immutable store snapshot.
  Descriptor handles are the collection values,
  publication never flushes implicitly, and repeated commits remain
  idempotent native records.

- Advance collection descriptors to one authority-scoped epoch. Root and
  derived descriptors now carry exactly one local `collection_authority`;
  roots no longer carry a redundant namespace, and names use attached
  unbounded `UTF8String` blobs under the `trible genid`-minted anchor
  `A2EEF06D4E1AA4B17B745AA2E8C37867`. Descriptor readers bind every known
  field to the tagged descriptor entity, reject ambiguous optional fields,
  and reject absent, repeated, malformed, or off-entity authority rows.

- Let maintained observed-set and LWW mappings use independently registered
  source and derived descriptors. Every descriptor carries its policy locally,
  so derived collection admission never inherits ambient source policy.

- Bound the unified inventory/DHT outbound pool to 64 fully reciprocal
  CONNECT+SYNC_TEAM-authorized sessions with deterministic LRU residency.
  Retirement releases cache ownership without interrupting in-flight shallow
  connection leases, and late failures can evict only their exact session
  generation rather than a newer redial.

- Make immutable store-snapshot invalidation component-aware. `MemoryRepo`,
  `Pile`, and `Yard` now distinguish the observable Blob view, collection
  records, capability proofs, and PEER evidence through
  `StoreSnapshot::changes_since`. Network refreshes
  enumerate and rebuild only changed BLAKE3 inventory PATCHes, carry unchanged
  component snapshots forward directly, and rebuild the Blob component when
  physical pile backing changes under identical membership.

- Make provider-cover directory admission purely aggregate and work-conserving.
  Receivers now bound only live shard count and total live memberships; one
  provider may use all otherwise-free capacity. Atomic replacement tests the
  exact `(directory - old shard + candidate)` weight, so equal-weight renewal
  remains possible at either full boundary without a fixed publisher quota.

- Stop `telemetry::Telemetry::layer_from_env` from falling back from
  `TELEMETRY_PILE` to `PILE`. A caller that set only `PILE` previously got
  telemetry and now gets none: `PILE` names an application's own append-only
  store, so the fallback aimed a per-span firehose at data the caller never
  offered, permanently and — for a replicated pile — on every machine holding a
  copy. An unset `TELEMETRY_PILE` now disables telemetry, warning only when
  `TELEMETRY_COLLECTION_NAME` is set, which is the case where telemetry was
  clearly intended and the destination is genuinely missing.

- Remove publisherless inventory-generation gossip end to end, including the
  iroh-gossip dependency and simulator side plane. Authenticated pairwise PATCH
  reconciliation is now the only epidemic inventory exchange, while explicit
  immutable-artifact publication and lookup remain in the bounded DHT.
- Bound periodic anti-entropy to a fair rotating budget of `K = 20` newly
  admitted peers per 30-second period and at most eight live sweeps. The host
  retains at most one period's eligible queue, examines backoff-delayed peers
  only at period boundaries, carries its identity cursor across peer-set
  insertion/removal, and arms only on the first installed snapshot so repeated
  local generations cannot amplify work.

- Keep canonical collection progress in the existing signed commits and
  `MERGE`/`DERIVE` equations, and keep `Blake3Merkle` focused on compact
  in-memory anti-entropy roots. Remove the unused parallel witness and
  materialized-node storage layers.

- Replace the remaining in-memory ordered sets for inert legacy V3 collection
  headers and Yard operation WANTs with PATCH indexes. Canonical PATCH
  traversal preserves their byte order, while Yard no longer sorts the full
  request vector when enumerating already-canonical keys.

- Split a collection descriptor's public-key namespace from its optional
  capability authority. Roots are named by `collection_name` plus
  `collection_namespace`; roots and derivations may each state their own
  `collection_authority`, and derived descriptors never inherit authority by
  walking `collection_source`. Both fields remain ordinary identity-bearing
  descriptor facts. `collection_namespace` retains the published wire identity
  `6C1ED6495491E32FEBB9FDD4EE5E8907` of the former `collection_team` field, so
  an old root reconstructed with no explicit authority keeps its descriptor
  handle. The new authority anchor `7C31D328E9C369CCB6049D05CC8E8C77`
  was minted with `trible genid` on 2026-08-24.

- Replace the current-facing Repository, Workspace, mutable branch, pin, and
  compare-and-swap documentation with the native collection model. The book now
  presents self-describing descriptors, signed `COMMIT` members, validated
  `MERGE`/`DERIVE` equations, exact covers, and orthogonal WANTs as one coherent
  workflow; obsolete speculative chapters and their retired proof harnesses are
  removed, while immutable legacy pin snapshots remain documented only for
  diagnosis, retention, and explicit migration.

- Replace the claim-blob capability grammar with one self-contained,
  prefix-signed proof value:
  `magic16 | resource32 | root32 |`
  `N*(action16 | flags1 | validity32 | delegate32 | signature64)`. Each
  signature is last and covers the exact prefix through its delegate, so every
  signed prefix is itself a proof and paths cannot be grafted or reordered.
  Root and delegate keys are canonical non-weak principal identities, and
  signed `i128` validity bounds remain exact at authorization-clock boundaries.
  Verification takes an external trust root, expected subject, explicit epoch,
  and exact request, and computes the path-local meet without storage
  discovery. Quorum counts independent paths from distinct configured roots
  under one threshold; sibling paths cannot supply delegation support. Proof
  records use a fresh V2 pile kind, are addressed by BLAKE3 over their exact
  bytes, and have no blob closure, portable bundle wrapper, implicit WANT, or
  claim-retention edge. The retired `K(S,C,K)+` pile kind remains recognizable
  as inert so old append-only files can still be traversed; authority must be
  reissued because old signatures covered different bytes.

- Pin inventory history per component rather than retaining whole store
  snapshots for every changed root. Unchanged roots reuse their immutable
  trees; each semantic snapshot installation carries fresh Blob access so
  obsolete backend generations can retire. Record and proof PATCHes carry their key-validated bodies
  as values while preserving key-only Merkle identities; and concurrent node
  or exact-blob reads no longer serialize through a global snapshot mutex.

- Fix the telemetry facade's explicit private-reach construction after the
  collection reach API became fragment-based.

- Advance the pinned CubeCL zero-copy fork to the clean canonical line with
  stricter CUDA alias eligibility and ownership-preserving slice uploads.

- Keep telemetry session collections explicitly private now that collection
  reach is a required, identity-bearing fragment.

- Make frontier row order and depth plans implicit until the data proves they
  are not. Consecutive row selections now remain allocation-free views; a
  unanimous frontier records only its preferred variable; and a fragmented
  frontier stores explicit row ordinals only when stable grouping genuinely
  permutes them. Query results and scheduling semantics are unchanged. In the
  frozen four-arm gate this cut allocation calls by 21% to the first result,
  17% over a full unanimous traversal, and 9% over a fragmented traversal;
  process CPU time remained effectively neutral overall (0.990x geometric
  mean, 1.014x when weighted by measured work).

- Tighten PATCH's archive and parallel-scatter safety contracts. Parallel
  scatter pointers are `Send + Sync` only when their written value is `Send`;
  archive-backed leaf constructors now state that retained bytes must remain
  initialized and immutable; and the public API documents tree-ordered removal
  keys and the intentionally unspecified value survivor for duplicate-key
  union.

- Document frontier width as a multiplicative proposal-memory budget:
  proposal residency grows as `Theta(width * fanout)` and is observable through
  `FrontierStats::peak_region()`, while `Query::with_frontier_width` bounds the
  number of parents expanded together.

- Make `tribleset-bench` result announcements interruption-safe. Session start
  and each announced result batch are now committed through the native results
  collection and explicitly flushed before stdout; failed publication retains
  the pending fragment for retry, while only a successful final checkpoint
  carries the session end marker and `--verify` labels interrupted sessions as
  incomplete.

- Rename the arbitrarily sized UTF-8 blob encoding from `LongString` to
  `UTF8String`, including its module and all current examples, tests, and
  documentation. The pinned encoding ID and payload bytes are unchanged, so
  existing handles and encoding-derived attribute identities remain valid.

- **Reach is a fragment, not an enum.** `Reach::{Private, Public}` and its
  `declared()` are gone. `collection::reach` states the same thing as data:
  `reach::private()` is an empty `Fragment`, `reach::public()` one that exports
  `reach::PUBLIC`, and every descriptor builder spreads what it is handed into
  `collection_reach` instead of interpreting a variant. The design already said
  a narrower law would be *a different id carrying its audience with it*, and
  an enum cannot hold that case -- it would need a new variant, a new
  signature, and every caller recompiled -- while a fragment already can, with
  nothing between the caller and the descriptor changing shape. Reach remains a
  required argument for the reason it became one: there is no default left to
  forget. Identity is unmoved in both directions. A descriptor that declares
  nothing writes nothing and keeps the handle it had before the attribute
  existed; one that declares `REACH_PUBLIC` writes the same single row it wrote
  before. Both are pinned against handles captured from the enum-era builder.
  `descriptor::reach` and `descriptor::travels` moved to `reach::declared` and
  `reach::travels`, and `REACH_PUBLIC` is now `reach::PUBLIC`.

- **A decoded archive is one build per index, not sixteen builds and a merge.**
  Decoding the 1.68 GB canonical union of a 404-commit, 26.26 M-fact collection
  spent 4.0 s: 85 ms validating and hashing rows, 2.25 s building six PATCH
  orders over sixteen per-worker chunks, and **1.6 s unioning those sixteen
  `TribleSet`s back together**. That union bought nothing. It was the price of
  the chunking, and the chunking existed only because parallelism lived at the
  chunk boundary: the four value-first orders interleave across any range of
  archive rows, so every chunk boundary put the same keys in the same subtries
  and left the reduce to walk them a second time.

  Parallelism now lives inside the build. `PATCH`'s bottom-up archive
  constructor is an MSD-radix partition, which already splits a node's rows
  into disjoint key ranges and hands each child a contiguous interval of one
  permutation buffer — so the children can be built on separate workers with
  nothing to synchronise, and a node wide enough to matter splits by counting
  into per-worker histograms and scattering into a second buffer instead of by
  the in-place American-flag pass, which is a chain of dependent swaps and can
  only ever run on one worker. The decoder therefore builds each order over the
  whole archive at once, and there is no union left to do.

  Decode of that archive: **4.29 s -> 2.42 s** (interleaved medians, sixteen
  cores under other load; the union phase goes from 1.6 s to 40 µs). Warm
  admitted-cover read on the same collection: **4.50 s -> 2.81 s**. The
  decoded set is byte-identical — all six orders match an independent
  online-insert build root-hash-for-root-hash, key-for-key and
  fanout-for-fanout at full scale, and the result's re-encoded facts still
  hash to the same 32 bytes as an independent `sort_unstable` + `dedup` of
  every one of the 404 commits' rows.

  Row *order within a bucket* is now unspecified, and the tests say so rather
  than depending on it: keys in an archive are distinct, so the subtrie a
  bucket produces is a function of its key set alone. Boundary errors are still
  reported ahead of anything a worker finds inside a run, which is what makes a
  duplicate straddling two runs report as a duplicate.

- **SimpleArchive cover materialization merges in parallel, and stops naming a
  value it immediately consumes.** On a 404-commit, 26.26 M-fact collection
  (`bultmann.pile`, 1.98 GB) the admitted-cover read spent 6.38 s, and the
  collection calculus was 78 ms of it — discovery, 404 signature checks,
  canonical validation of 1.86 GB of committed archives, and physical-cover
  planning together are 1.2% of the read. The rest was two byte-level steps
  under the calculus: a **serial** binary-heap merge of the cover into one
  canonical 1.68 GB archive (1.44 s), a BLAKE3 pass to name that archive
  (0.72 s), and the `TribleSet` decode of it (4.16 s).

  The merge is now partitioned by key range — regular sampling picks the cuts,
  each worker merges one interval, and concatenating the runs in range order
  reproduces the serial answer byte for byte, because disjoint key intervals
  cannot share a duplicate. And materialization no longer builds a `Blob` for
  the union: it decodes the bytes through the new
  `simplearchive::try_from_archive_bytes`. The handle it used to compute was
  dropped one expression later; hashing 1.68 GB to name a value on its way into
  a decoder is a fifth of the merge that produced it, spent on nothing.

  Warm admitted read of that collection: **6.38 s -> 4.38 s**, with
  byte-identical union bytes (verified against an independent sort/dedup of
  every commit's rows) and an identical decoded set. What remains is the decode: ~2.3 s
  building six PATCH orders over 16 chunks and ~1.75 s unioning those chunks,
  which no equation record can avoid — see `INVENTORY.md`.

- **Pile records are framed 28/4/32, and a record kind resolves.** The
  envelope's 36-byte prefix (16-byte marker, 16-byte kind, 4-byte span) left
  every 32-byte field in every body four bytes short of a 32-byte boundary, so
  each digest, handle, and signature component straddled two. The framing is
  now a 28-byte magic, the 4-byte block span, and a **32-byte record kind**,
  putting the body at byte 64 — aligned, and aligned at absolute file offsets
  because records start on 256-byte boundaries. The arithmetic is exact: a
  signed commit's six 32-byte fields fill `64..256` with nothing reserved and
  nothing wasted.

  The widened kind is a blob handle naming a `SimpleArchive` that **describes
  the record's own layout**, so a reader meeting an unfamiliar record can
  resolve what it is instead of only failing to recognise it — the move the
  collection layer already made when descriptors replaced bare definition ids.
  Each description is rooted at the 16-byte id the kind was already minted
  under, so nothing was renamed. The handles are pinned in
  `triblespace-core/src/repo/pile/record_kind.rs`, and a test recomputes each
  one from its description so editing a description is a loud format change
  rather than a silent reframing.

  **The compatibility surface is v0.46.4** (tagged 2026-06-10, the last
  released version): its three V1 markers are the only records anyone outside
  this workspace can hold, and they are read forever. Everything introduced
  since — the V3 family, all three collection-record generations, typed wants,
  retired local cells, and the 36-byte legacy envelope — never shipped, is not
  a compatibility commitment, and is read exactly once by the new
  `trible pile migrate <pile> reframe --into <dest>`. Those decoders are marked
  for deletion once the workspace piles have been reframed.

  **An unknown frame is corruption, and that is the point.** An unknown *kind*
  inside a valid frame still resolves to `Opaque` and is skipped by its span —
  that is forward compatibility. An unknown *frame* means nothing about the
  bytes is trustworthy, not even where the next record starts, so the decoder
  fails at exactly that offset. 28 bytes is a sentinel rather than an
  identifier: a mismatch is 224 bits of evidence that these bytes are not a
  record, so a torn write or a mis-seek is caught where it happens. A torn tail
  that is a proper prefix of the magic reports `CorruptPile` (which `amputate`
  repairs) rather than `UnsupportedRecord` (which it refuses to truncate,
  because the remedy there is `reframe`). The span stays early and at a fixed
  offset ahead of anything version-specific, so a future reader can still cross
  what it cannot interpret.

  The magic was minted on 2026-08-20 from two `trible genid` calls,
  `0371B249F0626B2ABDDB80E23EA96905` and
  `9D9656A5EA5A497320351F3BE712CF82`, concatenated and truncated to 28 bytes;
  the `KIND_PILE_RECORD` tag `29D9F7F6B5062623F65D63DBF4F633B3` was minted the
  same day.

  `PileRecordContent::Opaque` now carries an `OpaqueKind`, which distinguishes
  a 16-byte legacy kind from a 32-byte resolvable one rather than flattening
  the two.

- **Encodings join; mappings map.** The intermediate recipe/lattice-wrapper
  layer is removed. A `CollectionEncoding` is now the canonical blob shape
  together with its validation and intra-encoding join, so collections are
  typed directly as `Collection<SimpleArchive>`,
  `Collection<SuccinctArchiveBlob>`, and so on. A derived descriptor instead
  links one concrete mapping entity. Canonical builders derive its id from its
  facts, but decoders obey the substitution rule and do not make that minting
  history semantic. The entity names a reusable
  mapping algorithm and carries its concrete parameters as ordinary tribles:
  the observed attribute, register coordinate attributes, or complete path
  automaton remain queryable while also participating in mapping and target
  identity. The target embeds the encoding and mapping-algorithm descriptions,
  and `CollectionMapping<Source, Target>` validates the declared algorithm and
  parameters before computing any member. These descriptor identities never
  shipped, so the old recipe shape and compatibility aliases are removed
  outright.

- **A derived collection is anchored by its source.** New `collection_source`
  names, by handle, the collection a derivation is computed from. The
  extrinsic anchor — a minted scope when this landed, a name within a team
  since — narrows to what it can honestly be: a property of a *root*, still
  needed there because without it every root collection sharing an encoding
  would have one descriptor and one handle. The
  validators changed with it: they compared two descriptors' *scopes*, a label
  either side could claim independently, and now ask whether the target names
  this exact source descriptor. `ScopeMismatch` became unconstructible and is
  removed in favour of `WrongSource`.

- **`CollectionId` is now `CollectionHandle`.** It is a 32-byte blob handle,
  and calling it an id was the one place in the codebase where the two were
  confused — enough to mislead a reader into asking why descriptors take ids
  when the pile stores handles. Handle means 32 bytes, Id means 16.

- **A descriptor is a `TribleSet`, and a root is named within a team.**
  `CollectionDescriptor` is deleted. It parsed an archive into a parallel
  struct and reconstructed it on the way out, and of its eighteen methods two
  did work — encode and decode — while the rest were queries hand-rolled as
  `iter().find()` scans over the very `TribleSet` it wrapped. It enforced
  nothing: `from_tribles` and `from_fragment` were public and wire data went
  through neither. Its `structural_attributes()` array was a hand-maintained
  mirror of the schema and had already drifted — `collection_source` was
  missing, so every derived descriptor reported its own anchor as a recipe
  argument.

  A descriptor is now the facts themselves, and the collection is the handle of
  those facts archived as a `SimpleArchive`. `collection::descriptor` is free
  functions over `&TribleSet` — `entity`, `representation`, `recipe`, `source`,
  `name`, `team`, `argument` — each a `pattern!`, each failing where the value
  is needed and naming the missing field instead of rejecting a whole archive
  over a field the caller may never read. An argument for a recipe this binary
  has never heard of decodes, answers questions, and re-emits byte-for-byte.
  No table classifies attributes as structural or argument, because which
  attributes are arguments is the recipe's business and nothing else can have
  the information. There is deliberately no helper for hashing a descriptor you
  have not stored: on the write side a handle comes from what `put` handed
  back, because one computed beside a store rather than by it can name a
  collection whose descriptor is absent.

  A **root** is anchored by `collection_name` plus `collection_team`, the
  team's root public key, instead of an opaque minted scope id. The scope
  discriminated roots correctly and told a reader nothing: every consumer
  carried its scope as a hex constant in its own source, so “which collection
  is this?” was answerable only by someone holding the code. A team's root
  keypair is archived offline after creation, so it is a genesis fact and can
  be part of an identity without going stale. A **derived** collection carries
  `collection_source` instead and inherits its team transitively; it is not
  forbidden from stating one, because a recipe we have not written yet may mean
  something by it, and forbidding shapes is how forwards compatibility dies.

  Because a commit signs a transcript containing the descriptor's handle, and
  the handle is the hash of the descriptor, the existing signature already
  covers the team. No record format moved. Existing collections live under the
  old anchor and are not reachable through the new one until the naming
  migration re-seats them.

  Attributes minted with `trible genid` on 2026-08-20: `collection_name`
  `436A04C372CBBFBD9C619CF50F59C4A1` (ShortString), `collection_team`
  `6C1ED6495491E32FEBB9FDD4EE5E8907` (ED25519PublicKey).

- **Decoding no longer re-derives a descriptor's intrinsic root.** A
  non-canonical root does not break anything; it names a second collection with
  the same meaning, which is wasteful rather than corrupt, and rejecting it
  turned that into a hard error.

- **A stated register is an identity and an order, and the scope axis is
  gone.** `StatedOrder` shipped taking a *grouping* attribute plus optional
  `.among(attr, value)` / `.within(attr)` knobs narrowing who may dominate.
  The knobs were the missing half of the grouping, spelled at the call site:
  a register is a set of states that are versions of the same thing, ordered,
  and a timestamp carries only the order. An observation edge asserts both at
  once — "I observed that" is same-thing *and* later — which is why
  `ObservationOrder` needs no second attribute and now carries no scope
  either. A stated key asserts neither, so `StatedOrder::new` takes the
  identity attribute explicitly. Reconstructing it from a grouping plus a kind
  filter — Compass's `(goal, status-kind)` — over-includes by construction:
  notes and status events both hang off `board::task` and both carry a clock,
  so a later note retired a status on 778 of 2939 live goals. Both attributes
  are carried on the collection descriptor, so which measure of domination a
  reader is using is the collection's identity and never an argument. `.among` and `.within` are
  removed with no replacement; the live relations track heads that motivated
  `.within` agree with the unscoped order on every subject in the pile, and a
  supersedes edge crossing a track is a referential-integrity finding for a
  validation pass, not something resolution should quietly disbelieve.

- **The reusable JSON scanner now enforces RFC 8259 scalar syntax.** Its
  mmap-friendly `anybytes::Bytes` string parser decodes UTF-16 surrogate pairs,
  rejects lone surrogates and all unescaped control bytes, and its zero-copy
  number parser rejects leading zeroes and incomplete fractions or exponents.
  The new `take_value` primitive returns an exact borrowed slice for one nested
  value, allowing source adapters to retain raw evidence without materializing
  a `serde_json::Value` tree.
- **Mutable pin stores now forward through ordinary mutable borrows.**
  `&mut S` implements `PinStore` whenever `S` does, matching the existing
  `BlobStore`, `CollectionStore`, and `StorageFlush` forwarding surfaces and
  allowing a temporary `Repository` view without transferring backend
  ownership or reimplementing the pin trait in downstream crates.
- **Direct `SimpleArchive` collections use the same typed snapshot path as
  every other encoding.** `snapshot.collection_exact(collection, &support)`
  selects a resident cover against one immutable store snapshot and requires
  only its descriptor and payload bytes; no signed commit or metadata needs to
  remain resident. It shares ordinary descriptor, member, and merge-cover
  validation, while provenance remains independently queryable.
- **The unpublished branch-index persistence stack is gone.** Core no longer
  exposes commit-range manifests, `IndexKind`, repository on-commit hooks, or
  their branch-head maintenance path. Search no longer exposes the
  `HnswRollup` facade or its manifest attributes. Direct `HNSWIndex` and
  `SuccinctHNSWIndex` construction, attachment, and query constraints remain.
  Existing opaque annotation entities in branch-head metadata still round-trip
  through the open-fact carry rule, and conservative blob scanning preserves
  any handles they name; no migration or compatibility reader is required for
  the unpublished API.
- **Succinct archives now use two explicit native collection mappings.** Their
  former branch-index recipe and branch-bound read wrappers are removed.
  Callers derive and maintain portable `SuccinctArchiveBlob` members, then
  derive ordinary `Rank9AcceleratedSuccinctArchiveBlob` members with the same
  foundational support and expose their sharded `UnionArchive` query view.
- **The SuccinctArchive example now follows the native collection lifecycle.**
  `native_succinct_collection` publishes intrinsic fragments as independent
  signed commits, freezes the admitted value as a payload cover, and queries an
  exact typed Succinct collection snapshot without branch hooks, manifests, or
  a checkout. The pile re-id/rename integration test now exercises its real
  generic contract by carrying unrelated canonical branch annotations instead
  of depending on a Succinct-specific manifest fixture.
- **The portable Succinct LSM benchmark now measures the native exact
  collection lifecycle.** Source chunks are published and their cover is
  discovered outside the timer; `build_exact` measures canonical raw
  construction, deterministic raw target compaction, source-first accelerated
  derivation, and query-ready view construction as one fixed operation. The
  report replaces legacy fanout/range/manifest counters with exact-cover, raw-cover,
  serialized-byte, and physical-shard metrics
  while retaining the union-versus-`TribleSet` query identity gates.
- **The speculative adaptive Succinct rollup wrapper is gone.** Core retains
  the stateless `WaveletMatrixFreezeBackend` and
  `merge_ordered_archives_with_backend` experiment seams, but no longer mixes
  CPU and device execution behind the public `AcceleratedSuccinctRollup`, a
  row threshold, and a process-local circuit breaker. The current Apple M4
  end-to-end measurement showed no useful win from that legacy adapter. Native
  GPU execution for the exact raw-Succinct collection would require a separate
  direct-raw adapter rather than restoring a branch-bound lifecycle.
- **Derived collections now share one store-centric exact-cover engine.** The
  engine supplies strict cover discovery, payload validation, deterministic
  resident covers, residual lowering, target-before-`DERIVE` publication, and
  read-side attachment without `PinStore` or an implicit flush. Regular paths
  and both Succinct stages use this kernel. Each mutation returns a fresh
  `StoreSnapshot`; `snapshot.collection_exact(target, &support)` then returns a
  typed collection snapshot which owns that store observation, invariant
  foundational support, and target cover, preserving its physical shape until
  a caller reconstructs a sharded `UnionArchive` through `view`.

  `Rank9AcceleratedSuccinctArchiveBlob` is an ordinary ABI-qualified
  `CollectionEncoding` and a Merkle root: its first 32 bytes name the exact
  portable raw `SuccinctArchiveBlob` child whose Rank9/select data it carries.
  Four explicitly minted encoding ids and four mapping-algorithm ids distinguish
  32/64-bit and little/big-endian profiles; the current target selects one of
  each. The raw-to-accelerated stage is an ordinary `DERIVE`. Raw
  `SuccinctArchiveBlob` and Rank9-accelerated members each own a canonical
  `MERGE`. The accelerated join names the corresponding raw union as an
  immutable dependency and may use it when already resident, but never creates
  the upstream raw blob or `MERGE`. If that dependency is absent, maintenance
  leaves a finer accelerated cover. A cover-aware view reads the embedded raw
  handle through its immutable store snapshot and validates the exact raw/index
  pair before constructing the query runtime. The typed view rejects an
  accelerated root whose named raw child is absent.

  Exact attachment no longer requires every previously computed intermediate
  blob to remain resident. Descriptor-typed lattice methods validate fixed
  descriptors and terminal blobs while resolution follows durable equations
  from explicit source-cover leaves to resident target results. Invalid or
  incomplete paths are ignored and another support-equivalent physical cover
  may be selected. This adds neither receipts nor authority/retention records,
  and `attach` remains write-free even after a retained Pile rewrite collects
  intermediate artifacts; `ensure` repairs missing cross-lattice `DERIVE`
  work, while `maintain` additionally rebuilds the deterministic target LSM
  cover.

  Lattice operations return `CollectionOperationError::{Fatal, Capacity,
  MissingDependency}`. `Capacity` is reserved for
  deterministic fixed-representation geometry, never transient allocation,
  I/O, or malformed persisted bytes. `MissingDependency` names exact immutable
  content the operation cannot consume from its immutable snapshot; target
  maintenance leaves the corresponding finer cover rather than synthesizing
  upstream state. A capacity-terminal source mapping leaves that
  support represented by a finer physical decomposition; a capacity-terminal
  target merge leaves a stable tier collision. Every successful mapping or
  merge is published immediately before planning continues. Succinct raw
  construction and merge preserve typed input-versus-union-growth phases.
  Paths remains fatal on all algebra failures, including fixed summary limits:
  its public operation currently rejoins every shard before closure, so a
  finer cover cannot make an oversized result representable. `Capacity` is
  reserved there until fragmented closure/materialization exists.

  Exact derivation separates construction from maintenance. Every mapping hop
  receives the same invariant foundational `Support = Cover<SimpleArchive>`.
  `ensure` and `ensure_exact` reuse resident target images and
  support-equivalent stored equations, cross one mapping for missing work, and
  publish `DERIVE` records but never `MERGE` or upstream state. `maintain` and
  `maintain_exact` additionally carry the disjoint target
  lowest-handle pairs in the lowest colliding dyadic serialized-byte tier,
  then re-enter exact planning before choosing another tier. Every computed
  target artifact is stored before its unsigned `DERIVE` or `MERGE` record. A
  capacity failure retires only the lower input for that planning round, so the
  higher input remains eligible for another deterministic pair and every
  attempt shrinks the active set. A no-claim round returns a capacity-stable
  cover (which may retain a tier collision) with zero writes. Repeated and
  concurrent work is content-addressed and idempotent; if an acknowledged
  `MERGE` or `DERIVE` remains absent from a fresh store snapshot, maintenance
  reports a stalled backend instead of repeating it indefinitely. No flush,
  planner, manifest, receipt, retention root, background task, or authority
  record is introduced. The store-level operations return a fresh
  `StoreSnapshot`. Each raw shard retains the explicit `u32::MAX` row/domain
  boundary.
- **Regular paths now use the direct native collection path.** Their mapping
  validates one immediate source member and closes it into a `PathIndex`.
  Generic `CollectionStoreExt` operations provide DERIVE-only ensure versus
  tiered target maintenance and return fresh store snapshots; immutable
  collection snapshots select and materialize the view afterward. The empty
  support is a no-write local bottom. `PathRollup`, its range attribute,
  range-manifest attachment, repository hooks, commit ranges, and
  manifest-specific path tests are removed; the direct path works without
  `PinStore`.
- **Read-only pin snapshots are now an explicit storage capability.**
  `PinStore::pin_snapshot` and its partial-on-error default are removed;
  callers request the strict `PinSnapshotSource::snapshot_pin_heads`
  capability instead. `Pile`, `MemoryRepo`, and `Yard` opt in directly, while
  `HybridStore` and `Lazy` forward only when their underlying pin side exposes
  the narrow snapshot trait. Authorization, serving, and CLI snapshot users
  therefore retain fail-closed complete-snapshot refresh without acquiring CAS
  mutation through a blanket bound.
- **Telemetry no longer turns an unknown pile read failure into destructive
  repair advice.** Unsupported record markers are identified as likely
  format/version skew with an upgrade-first diagnostic, while every refresh
  failure leaves the pile unchanged and disables only the optional sink.
- **Scoped collection discovery verifies independent commits concurrently.**
  The exact collection-and-signer filter still runs during the store's serial,
  fail-loud enumeration, then matching Ed25519 signatures use Rayon's indexed
  parallel iterator so worker completion order cannot affect canonical commit
  or diagnostic order. A structural singleton path remains serial. The scoped
  signer is parsed once, and internal fixed-size signing transcripts are built
  on the stack while the public `signing_transcript()` API remains a `Vec`;
  unscoped discovery continues to verify each embedded key serially. On a
  16-logical-core Apple M-series release build, a synthetic Compass-shaped
  5,500-commit scope fell from 141.6 ms to 12.9 ms steady-state, 128 commits
  from 3.22 ms to 0.41 ms, and eight commits from 199 us to 111 us, while a
  singleton remained 24 us. Initializing a fresh Rayon pool cost the first
  plural scope roughly 0.23--0.26 ms; a first singleton does not initialize it.
- **Plural authorized collection reads validate commit data in parallel.** Data
  fetches and metadata validation remain sequential; no backend error crosses
  into Rayon. Only successfully fetched bytes enter the
  parallel identity and canonical `SimpleArchive` checks. Results replay in
  intrinsic commit order, preserving data-before-metadata and deterministic
  fail-loud attribution. Single-commit reads and builds without the
  `parallel` feature retain the direct serial path.
- **Authorized collection reads validate each distinct data handle and each
  distinct metadata handle once per admission.** Every observed commit still
  undergoes strict Ed25519 verification and remains available as claim
  provenance, but commits that name identical content share one fetch,
  identity check, and canonical `SimpleArchive` validation. This preserves
  fail-loud mandatory roots while avoiding work proportional to repeated
  content.
- **Physical collection covers follow the sparse order once per candidate.**
  Resident-frontier selection now walks reachable successors and tests the
  resident set during that walk, instead of comparing every resident pair
  through an independent reachability query. Exact resident obligations are
  discharged before any traversal. This preserves the canonical proof choice,
  overlap reuse, cycle behavior, and nonresident-intermediate fallback while
  making an equation-free collection linearithmic rather than quadratic in
  its resident leaves.
- **SimpleArchive collection covers now become one query index build.**
  Materialization validates every selected canonical member, merges their
  sorted rows with one overlap-deduplicating k-way pass, and constructs the
  final six-index `TribleSet` once. This removes one transient `TribleSet` and
  PATCH union per collection leaf without changing collection semantics,
  persisted records, physical-cover selection, or the one-member path.
- **Authorized collection reads scope signed-commit verification before
  Ed25519.** `Collection` now discards commits whose descriptor does not match
  or whose signer lacks exact `ACTION_WRITE` invocation authority before
  verifying their signatures, while retaining all native `MERGE` and `DERIVE`
  equations for downstream semantic closure. Matching invalid signatures
  remain rejected diagnostics, unrelated invalid signatures are inert, and
  structural storage failures still abort discovery.
- **The destructive pile CLI requires the current reader's exact boundary.**
  `trible pile amputate <path> --truncate-to <byte-offset>` refuses a guessed
  or stale offset before mutation. Read failures now say explicitly that a
  malformed known record and an interrupted append share one conservative
  error class, direct operators through the non-mutating `record-at`
  diagnostic, and require a backup plus independent confirmation instead of
  presenting truncation as routine repair. Boundary comparison and truncation
  occur under the same exclusive file lock. The old copy-pasteable
  `trible pile amputate <path>` form is intentionally incomplete.

### Added

- **`trible pile migrate <pile> reframe --into <dest>`** re-encodes a whole pile
  into the current framing. Semantic and in source order: content-addressed blob
  payloads keep their identities *and* their original insertion timestamps
  (`Pile::put_at`), last-writer-wins pins and wants are replayed in order,
  grow-only collection records and grants are re-inserted idempotently, and
  records that never carried live state are dropped and counted. Every commit in
  the result is verified afterwards rather than assumed to survive — a signature
  covers a transcript, not a frame, but that claim spans two layers and the
  cheap way to be sure is to check. Verified on APFS clones of a 12.8 GB and a
  1.7 GB pile: 100% of records reframed, all 34,181 commits still
  signature-valid, every collection resolving identically, no blob lost.

- **`trible pile migrate run record-kind-descriptions`** stores every record-kind
  description into a pile, so it can answer "what is this record?" about its own
  bytes without an external lookup. Backed by
  `Pile::publish_record_kind_descriptions`; idempotent under content addressing,
  and its census distinguishes "already resident" from "left to store" so a
  re-run reports honestly instead of repeating its worklist.

- **Registers: `latest` generalised to a parameterisable resolution
  substrate.** `triblespace::core::query::register` makes "which states are
  current" a question with knobs instead of one hard-coded rule, and `latest`
  is now the thin unscoped-multi-value reading of it.

  The design finding is that *policy is not a second knob*. Multi-value is the
  maximal set under a partial order, last-write-wins is the maximal set under a
  total order, first-write-wins is that order reversed, and named-by-the-reader
  is the empty order. There is one operation — take the maximal elements — and
  the policies are orders to take it under. `sole` is therefore a *check* that
  the order left a singleton, never a tie-break that invents one.

  Three axes are parameterised. **Order**: `ObservationOrder` reads an
  observation DAG (partial, so concurrency stays visible); `StatedOrder`
  compares a stated key by value within a group, with an opt-in id tie-break
  that makes it total. **End**: `.first()` resolves to the minimum instead of
  the maximum; `min` is the join of the opposite order, so first-write-wins is
  as lawful a derivation as last-write-wins. **Observer scope**: `.within(attr)`
  admits only states sharing the candidate's group, and `.among(attr, value)`
  only states asserting a fact — the axis every hand-rolled holdout in practice
  differs on, and the one candidate scoping cannot express, because an observer
  need not be a candidate.

  Two exposures. `maximal(var, &order)` is an ordinary `Constraint` in the
  `InlineRange` shape: filter-only, estimating `usize::MAX` so the planner
  sorts it last and a `pattern!` proposes the scope — which removes the
  caller's obligation to materialise candidates. For an exact cardinality the
  planner can order around, `resolve` materialises and `SortedSlice` proposes.
  `collection::observed_union` was the initial maintained form: an exact derived
  collection over `SimpleArchive` whose target is the sorted set of observed
  ids. It materialises the *dominated* half deliberately, because that half is
  the monotone one — a commit can only add to it — while the frontier is
  non-monotone in the store's inclusion lattice. This unshipped design was
  replaced by the maintained `(H,D)` latest lattice described above. The reader
  subtracted the dominated set in its own frame. `ObservedIndex` implemented
  `RegisterOrder`; the replacement positively exposes known live membership.

  Gated read-only against the live pile, with every count asserted non-zero so
  nothing passes vacuously: wiki frontiers (13006 revisions, 3098 entries),
  memory heads (~3850 nodes, ~3550 heads — the pile is written concurrently, so
  these drift between runs), ERP `group_heads`, and the derived index (9908
  observed states, the same 3098-member frontier as live probes) all identical.
  `relations`' four snapshot tracks, which narrow *both* scope axes at once,
  agree with `track_head` on 776 of 776 subjects; what does not carry over is
  its integrity checking — a wrong-track predecessor and `GroupHead::Invalid`'s
  intrinsic-id re-derivation are schema validation sitting next to head
  resolution, not part of it. Compass's `(created_at, event id)` rule — which
  the observation frontier cannot express, and converting it would drop 160
  notes — agrees with `sole(StatedOrder…)` on 2939 of 2939 goals.

  New stable ids, minted with `trible genid` on 2026-08-19:
  `3C98E1A6F691E8EE888F3F49D10B8CF2` (`observed-set-v1` blob encoding),
  `A808ECA30730EF0F1C7FD96F3FC7CB03` (observed-set algorithm/recipe),
  `E61092974C734142217EC718CC184673` (`register_observes` attribute).


- **`latest` resolves the frontier of any observation DAG.**
  `triblespace::core::query::frontier::latest(facts, observes, candidates)`
  (re-exported from the prelude) returns the candidates no entity in `facts`
  observes over the given attribute — the maximal states of a
  successor-to-predecessor DAG such as `metadata::supersedes`. The attribute is
  a parameter, not a constant, and the source is any `TriblePattern`, so a
  commit-set view answers for its own frame: there is no global "current", only
  `latest(C)`. The map is a join homomorphism from the commit-set lattice
  (union) to the antichain lattice ordered by domination, which is why head
  resolution reads as non-monotone only when it is evaluated in the inclusion
  lattice. The predicate `s is maximal in C ⟺ no state in C observes s` is
  local: immediate edges suffice, no transitive closure and no vector clock are
  needed, and it compiles to one short-circuited reverse-index probe per
  candidate.

- **Ordinary collections expose authority-resolved exact covers.**
  `collection.admitted(&store_snapshot)` admits the descriptor authority
  directly and
  verifies every resident self-contained proof for exact WRITE access to that
  descriptor, then returns the distinct payload handles named by admitted
  signed COMMITs. Invalid, expired, or irrelevant proof candidates grant
  nothing. Admission reads no collection-member or commit-metadata blobs.
  Cover resolution and materialization therefore share one multi-author
  known-prefix payload frontier rather than treating a publishing key as
  ambient authority.

- **Path summaries now form a native typed collection algebra.** A source
  `SimpleArchive` collection can be lowered through an automaton-specific
  `DERIVE` into canonical `PathSummaryBlob` elements, and exact `MERGE`
  validation proves their byte-level set union. The 48-byte zero-vertex
  summary is the explicit bottom for each automaton, making lowering total and
  preserving joins across empty, nullable, and cross-fragment inputs. Closure
  remains a separate `PathIndex` materialization step, so paths may span any
  number of independently derived source fragments.

- **Money is a first-class inline encoding, parameterised by currency, and its
  value is an exact rational.** `Currency<C>` stores a monetary amount as an
  exact `Ratio<i128>` in `ROrd256`'s encoding — the canonical continued
  fraction, whose bytes sort in numeric order. **There is no decimal scale
  anywhere**: €1.50 is `3/2`. That is the point rather than a detail. A
  fixed-point money encoding has to pick a scale, and that constant then has to
  be right for every currency and every future use, and cannot be revised
  without rewriting every amount ever written, because the same figure at a
  different scale is a different byte string and so a different intrinsic id.
  A rational has no such constant, holds values a fixed-point form cannot
  (`1/3`), and makes rates exact: 19% VAT on €19.99 is `37981/10000`, so the
  intermediate keeps its full value and rounding happens once, where the
  document is produced. Canonical form still holds — rationals are stored
  reduced, so one amount has exactly one byte string — and byte order is still
  numeric order, so ordered indexes answer range queries directly.
  The currency lives in the *encoding*, not the value: a trible always carries
  its attribute, so repeating the currency in every amount buys nothing, while
  making it a type parameter makes currency confusion structurally impossible.
  `Currency<Euro>` and `Currency<UsDollar>` are different encodings with
  different ids, so one anchored attribute name yields one attribute id per
  currency (`Attribute::<Currency<Euro>>::anchored`) with nothing minted per
  currency, and `Amount<Euro> + Amount<UsDollar>` does not compile. Per-currency
  identity is derived from `CurrencyUnit::CODE`, so two codebases that
  independently declare a currency land on the same ids and their data merges
  without coordination; `MINOR_UNITS` is an annotation rather than part of
  identity, so a disagreement about presentation cannot fork a currency, and it
  is what `Display` pads *to* and never truncates to.
  Costs, measured rather than assumed: encode ~480 ns, decode ~82 ns, validate
  ~86 ns per two-decimal value (release, Apple M-series), so a 133k-record
  ingest spends ~64 ms encoding money. The representable subset is `ROrd256`'s
  and is data-dependent — every `p/q` with `max(|p|, q) ≤ 2^104` is guaranteed,
  wider values are rejected with a typed `OrderedRatioError::OutOfDomain` rather
  than rounded. Verified against the source rather than today's data: every
  Revolver monetary column is a PostgreSQL `bigint` at three decimal places, so
  the widest value such a column can hold reduces to a numerator below `2^60`
  over a denominator dividing 100 — 44 bits of margin that new data cannot
  erode. A zeroed buffer cannot pass for money either: the all-zero byte string
  is not a canonical continued fraction and is rejected, with no niche reserved
  for it.
  Ships `Euro`, `UsDollar`, `PoundSterling`, `SwissFranc`, `Yen`, `Bitcoin` and
  `Ether`; any other currency is a four-line marker type. `Amount<C>` carries
  exact `from_units`/`to_units` and `from_minor`/`to_minor` conversion, checked
  arithmetic with no currency-mismatch error (the types prevent it), exact
  `checked_mul_ratio` for applying a rate, and `Display`/`FromStr` that render a
  finite decimal where one exists and the fraction where it does not (`1/3 EUR`).
  No binary float touches an amount anywhere.
  **This depends on `ROrd256` and must land after it.** It also makes
  `rord256`'s wasm formatter module `pub(crate)` so money reuses it rather than
  growing a second copy, and names `num-traits` (already in the graph under
  `num-rational`) for checked rational arithmetic.
  New ids, minted with `trible genid` on 2026-08-13: encoding-family anchor
  `51D01773A3AF0A26A936C56B3A95A9F0`, `money::code`
  `CE4138C8D49DE483673E21822D63E6C4`, `money::minor_units`
  `3B3C14395D9BCD5DFB0E63485E073FAB`.
- **Durable wants now name blobs and reproducible collection work through one
  canonical request key.** `WantRequest` has a fixed 97-byte codec: a one-byte
  versioned kind followed by three 32-byte fields. `Blob` uses one handle and
  zero padding, `Merge` uses a collection plus canonically ordered inputs, and
  `Derive` uses a target collection, input, and zero padding because the target
  descriptor already names its source. Pile assertions
  and retractions use new one-block envelope kinds
  `9A06797600FA90B8A8259B0ED029EC21` and
  `2D957A780A52E474F58A06D44D6FE46C`, minted with `trible genid` on
  2026-08-13. Legacy weak-pin records still replay into the same set as `Blob`
  requests. Blob writes retain the historical weak-pin envelope kinds so an
  older reader's forgetful projection remains sound; the new kinds are used
  only for operation wants. Only blob wants participate in exact fetch and
  bounded cache retention; merge and derive wants are durable questions whose
  answers are ordinary collection records. The authorized team inventory
  converges all such records, including conflicting answers, and reconciliation
  checks the local indexed union after refresh instead of issuing a second
  receipt RPC. Inputs—not unknown result hashes—remain the discovery key, so
  this path deliberately does not use the blob DHT. Blob fulfillment crosses
  an explicit durability barrier before quiescing.
- **Native collection records now use one dense typed representation.**
  `COMMIT`, `MERGE`, and `DERIVE` no longer masquerade as queryable
  `SimpleArchive` entities: their exact payloads are fixed at 192, 128, and 96
  bytes, respectively, with structural `to_bytes`/`from_bytes` codecs.
  Generic record stores use one stable versioned variant tag around those
  payloads. Records have no synthetic semantic ID; fixed-width physical stores
  and network PATCHes key them by the full BLAKE3 digest of their semantic kind
  and every dense payload byte. Merge decoding rejects noncanonical input
  order. Collection descriptors remain self-describing
  `SimpleArchive` blobs whose handles are the collection identity.
- **Pile diagnostics can decode one exact physical record boundary.**
  `trible pile diagnose record-at <pile> <offset>` walks the canonical replay
  decoder without modifying the pile, reports the marker, classification,
  known span, next offset, and safely decoded fields, and rejects offsets that
  land inside a record. Unsupported unenveloped markers now remain an explicit
  upgrade/version-skew diagnosis with no amputation suggestion; only malformed
  or torn known records mention the opt-in destructive repair. `diagnose check`
  also reports the count and boundary offsets of inert legacy V3 collection
  evidence and opaque records.
- **Ordinary collections now consume coherent store snapshots.**
  `store.snapshot()` freezes every read surface at one prefix;
  `collection.admitted(&snapshot)` discovers the authority-approved semantic
  cover, and `cover.materialize(&snapshot)` privately selects resident physical
  support before constructing the logical value without crossing observations.
  Later physically visible blobs cannot alter that authority frontier.
- **New pile writes use a generic, length-delimited record envelope.** The
  envelope marker `E5A95E5D8A0BBA8782E46B9C9E73B313` was minted with
  `trible genid` on 2026-08-11; the next 16 bytes reuse each current V3/V4
  marker as its semantic kind, followed by a little-endian `u32` span measured
  in 256-byte blocks. Unknown enveloped kinds remain raw-visible through
  `PileRecords` and are semantically skipped so later known records still
  replay, while unknown unenveloped markers remain unsupported. Pile/Yard
  collection and physical rewrites refuse before mutation in the presence of
  opaque records because older tooling cannot infer their retention closure.
  Existing V1/V3/V4 records remain readable byte-for-byte, and focused tests
  cover every writer, legacy/enveloped concatenation, opaque multi-block
  crossing, malformed spans, amputation, Lazy reopen/append, and conservative
  reclamation.
- **Raw SuccinctArchive collections now validate the exact collection laws.**
  The raw representation reuses the canonical TribleSet union recipe while
  remaining a distinct collection through its representation identity.
  Validators bind every unsigned `DERIVE` and `MERGE` endpoint to freshly
  hashed bytes, require canonical portable artifacts, and admit only the exact
  `SimpleArchive -> SuccinctArchiveBlob` mapping or raw set union. The canonical
  empty artifact and byte-identical commuting derivation/merge paths are pinned
  by focused tests; none of these equations authorize membership or retention.
- **Node operational policy now lives in one private signer-owned collection.**
  Capability requests have stable cores and immutable receipt observations;
  request decisions, renewal policy, and team-cap versions form explicit
  `metadata::supersedes` DAGs. Stable terminal renewal versions keep local
  retraction times in separate observations, and delivery acknowledgements name
  exact versions. Approval and initial issuance publish in one collection
  commit, retries are intrinsic-idempotent, and a union of independently
  modified piles exposes concurrent heads as a fail-closed conflict instead of
  selecting an order-dependent winner. Explicit successors can converge those
  forks. `Peer` deliberately exposes no direct `CollectionStore` adapter;
  native records already present in its dedicated team store participate in
  the authorized inventory like every other collection record. The public
  `LocalCellStore`/`AsyncLocalCellStore` footgun and every backend writer were
  removed. Existing enveloped and unenveloped cell records remain raw-visible
  as opaque migration evidence; semantic rewrite and Yard reclaim refuse them
  rather than silently discarding private state. Old policy pins remain
  raw-visible migration evidence but are not current semantic state.
- **Signed records now use neutral metadata and attestation namespaces.** The
  generic metadata-archive link and Ed25519 signer/signature attributes moved
  out of the legacy repository module without changing their stable IDs or
  wire encodings. Collection records, capabilities, and legacy commits now
  share those structural fields without making collection semantics depend on
  branch/CAS code.
- **The native compressed Succinct universe now uses one zero-prefix layout.**
  Every ordered 32-byte value contributes its second 16-byte half, while the
  leading run of intrinsic identifiers shares an implicit all-zero first half;
  only later first halves are stored. The payload is therefore exactly
  `32N - 16Z` bytes, never exceeds the ordered universe, and supports direct
  access and binary search without the former fragment dictionary, frequency
  pass, hash tables, or DAC decoding. Strict attachment checks pin its boundary,
  section cardinalities, and ordering. Portable raw Succinct and accelerated
  Merkle-root bytes remain byte-for-byte independent of this native runtime
  choice. The direct native `SuccinctBM25Blob`, whose bytes embed the runtime
  metadata, rotates to schema ID `7ECEC029EEE4CA89582599E83B0E9508`
  (minted with `trible genid` on 2026-08-08). The unused
  `Universe::validate_metadata_prefix` compatibility seam was removed;
  attachment validates the concrete runtime layout directly.
- **Canonical `SimpleArchive` leaves can now derive raw Succinct artifacts
  without constructing a query runtime.**
  `SuccinctArchiveBlob::build_from_simple_archive` validates the source's
  existing EAV bytes, builds one ordered domain, and walks the six Ring
  rotations through five stable counting-sort passes. It writes prefixes,
  pair-change masks, and minimal-width wavelet planes directly into the final
  portable allocation, constructs no PATCH indexes, Jerky runtime arena, or
  accelerated root, and hashes the finished artifact exactly once.
- **Canonical Succinct artifacts now merge directly as raw blobs.**
  `SuccinctArchiveBlob::merge` exact-validates every portable input without
  attaching a query runtime or Rank9 accelerator, unions and remaps their
  ordered domains, performs a deterministic EAV k-way set union, and emits the
  result through the shared raw writer with one final hash. Empty inputs,
  overlap, segment duplication, and input order all preserve canonical bytes.
  In-place derivation checks cover every prefix run, pair-change bit, and stable
  wavelet plane without allocating a second portable input payload.
- **BM25 now has a portable exact-frequency carrier distinct from its native
  succinct accelerator.** The new blob stores only the canonical document set
  and positive exact `u32` `(document, term)` frequencies in a fixed-width,
  gapless little-endian grammar. Empty documents are first-class; merge is
  document union plus pointwise maximum; scores and document statistics are
  reproducibly derived by the attached query view. Strict byte/hash goldens and
  malformed-spelling tests pin the fresh representation identity
  `A5B5F53351B46DECAED496E567D12F4F` (minted with `trible genid` on
  2026-08-08).
- **CPU and GPU wavelet backends now share the portable codec's minimal
  alphabet width.** Jerky and the CubeCL freeze geometry use
  `max(1, bit_length(D - 1))`, including `D=0/1` and exact power-of-two
  boundaries. Rank treats out-of-domain values as absent and select returns no
  result on both scalar, batched, and device-resident paths, so removed leading
  zero planes cannot make code `D` alias code zero.
- **SuccinctArchive now has one portable v2 raw format.** Its gapless
  little-endian layout derives every section boundary from
  only trible and ordered-domain cardinalities. The domain begins at byte zero
  so its 32-byte values remain visible to generic conservative child scans;
  `N,D` occupy a fixed terminal footer. The codec uses the mathematically
  minimal wavelet width for codes in `0..D`, and exact-validates sizes,
  canonical bit tails, unary prefixes, ordered-domain role invariants,
  in-domain codes, and last-column histograms. Empty, singleton, and multi-row
  byte/hash goldens pin the representation. Attachment independently derives
  all prefixes, changed masks, and six rotations from the decoded EAV source
  ring and requires exact byte equality before rebuilding the native query
  arena. An accelerated Merkle root remains source-bound and can attach without
  rebuilding rank/select structures. Native v1 serialization and parsing were
  removed rather than retained as a compatibility path, and the incompatible
  public format has a freshly minted schema ID.
- **Signed collection commits can be prepared and staged before visibility.**
  The `SimpleArchive` union kind can now construct the exact canonical commit
  entirely in memory, stage its attachments, descriptor, data, and metadata
  while withholding the record, permit caller-owned unsigned cache artifacts
  in between, and consume the staged value to append the signed `COMMIT` last.
  Durability is an explicit caller policy. Abandonment is deliberately inert:
  unrooted staged dependencies remain undiscoverable as membership and produce
  no retention roots.
- **Collection algebra records now have a native grow-only storage surface.**
  `CollectionStore` admits exact canonical signed `COMMIT` and
  unsigned `MERGE` and `DERIVE` records without a mutable head, CAS, tombstone,
  or branch cell. A canonical `SimpleArchive` descriptor carries
  `(scope, representation, recipe)` and its 32-byte content handle is the sole
  `CollectionId`; every record names descriptor handles directly, so there is
  no definition record or registry. Pile stores each equation as one fixed
  256-byte V4 record and replays their set union in record-fingerprint order;
  object-store remotes use immutable
  `collection-records/<full-width-fingerprint>` objects and validate both
  canonical bytes and path fingerprint. Memory, hybrid, lazy,
  blocking-async, and generational Yard adapters preserve the same idempotent
  algebra, including across cat/reopen/reclaim boundaries. Legacy V3
  definition/16-byte-ID records remain recognizable for safe replay and
  conservative rewriting but are semantically inert.
- **Collection retention now follows signed ownership rather than a blind hash
  walk.** Native collection records live outside the blob root set.
  Conservative Pile/Yard rewrites preserve every native record and recursively
  retain every signed COMMIT's descriptor, data, metadata, and resident
  attachment closure;
  unsigned `MERGE` and `DERIVE` endpoints remain descriptive, reproducible cache
  work rather than ownership edges. The policy-aware planner can still narrow
  this to locally authorized, admitted COMMIT ground truth for an explicit
  destructive retention operation. Wants remain demand markers and never
  silently become ownership roots.
- **Resolved `SimpleArchive` collections have one narrow read-side
  materializer.** It probes residency only for known semantic members, selects
  the deterministic overlap-aware physical cover, reports uncovered frontier
  obligations before fetching, and decodes the selected archives into one
  `TribleSet`. Descriptor, metadata, fetch, missing-cover, and archive failures
  remain distinct without reintroducing repositories, heads, catalogs, or
  authorization policy.
- **Durable Ed25519 key files now have one strict core utility.** Callers can
  resolve an explicit path, `TRIBLESPACE_KEY`, or the lexical `self.key` beside
  a pile without following symlinks during resolution; load only regular,
  exact 64-hex seed files with private Unix permissions and no nontrivial
  Darwin or FreeBSD ACL; and explicitly initialize a mode-0600 file through a
  synced same-directory temporary and an atomic no-replace install. Fresh
  temporaries shed inherited ACLs before any seed bytes are written. Unix
  initialization pins one parent-directory handle across creation,
  installation, cleanup, and winner loading, so a concurrent rename or symlink
  retarget cannot redirect the transaction. Concurrent initializers load the
  winning key, while ordinary loads never create or silently substitute an
  identity. `trible pile signing-key init` exposes that deliberate provisioning
  step without coupling key creation to an ordinary reader or writer.
- **Fragments now carry their descriptions as first-class metafacts.** A
  `Fragment` consists of exports, content facts, metafacts, and one
  content-addressed blob store shared by both fact sets. `entity!` automatically
  carries the cached description of every attribute that actually emits a fact;
  optional and repeated fields that emit nothing add nothing. Composition and
  spread preserve all four channels without making descriptions participate in
  content-derived entity identity. The `SimpleArchive` collection helper now
  accepts one fragment, archives its facts as data and its metafacts as metadata,
  and writes every shared attachment before the native `COMMIT` record.
  Publication recomputes embedded byte identities and rejects forged store keys
  or cached handles before writing.
- **Canonical collection records preserve dependency-before-record order.**
  The concrete `SimpleArchive` union kind normalizes and validates supplied
  bytes, writes descriptor and element dependencies before a signed `COMMIT`
  or exact `MERGE`, and leaves durability barriers to explicit caller policy.
  Completed operation prefixes leave only inert dependencies or a record whose
  dependencies were already admitted. Replay after any backend-required I/O
  recovery is content-addressed and idempotent, without a repository
  transaction layer.
- **Discovered collection records now resolve through a stateless production
  semantic layer.** Callers select eligible self-signed commits and validate
  descriptor-bound `COMMIT`, `MERGE`, and `DERIVE` claims through one narrow
  callback. Accepted equations are checked for deterministic functional
  conflicts before a least membership fixed point produces members, maximal
  frontiers, and on-demand supporting-commit provenance without a persistent
  registry or full transitive order matrix. A separate pure physical-cover
  query uses active merge lineage and current residency, including overlapping
  compactions, while never substituting source-representation bytes across a
  derivation.
- **The first production collection kind is canonical `SimpleArchive`
  TribleSet union.** `collection::simplearchive_union` constructs descriptors,
  validates commit and merge endpoints against freshly computed Blake3
  identities, and validates or computes exact set unions directly over sorted
  64-byte rows without constructing PATCH indexes. The version-1 recipe ID
  `6D64C5F4B9E9B73F57C5F8702AB7FE45` was minted with `trible genid` on
  2026-08-07 and names the union law independently of this implementation.
- **Typed collection records can be discovered without a catalog.** The
  top-level `triblespace_core::collection` module enumerates structurally
  canonical `COMMIT`, `MERGE`, and `DERIVE` values from `CollectionStore` and
  returns them in record-fingerprint order. Signed commits are included only after
  strict Ed25519 self-signature verification, leaving key authorization to
  caller policy; invalid signatures remain diagnostics and structural storage
  failures remain hard errors. Descriptor bytes resolve through the ordinary
  blob store by the exact handles carried in claims, not through discovery or a
  definition registry.
- **The collection calculus has a wire-format-neutral executable test oracle.**
  The bounded reference model folds accepted signed `COMMIT` leaves, exact
  unsigned `MERGE`, and canonical unsigned `DERIVE` relations to their least
  membership closure, induced
  subsumption order, and maximal known frontier. Declared join
  homomorphisms close commuting squares in either direction and reject
  construction paths that claim different canonical results. Local blob
  residency remains outside the replicated equations: a separate physical
  cover search can use a resident compacted result or recursively fall back to
  resident exact inputs, while reporting genuinely uncovered frontier
  obligations. Authentication remains an opaque, externally validated witness;
  data alone enters each typed lattice while supporting commit metadata and
  provenance accumulate by outer set union without synthesizing merged commits.
  Exhaustive finite-set tests pin ACI reconciliation, idempotent retries,
  concurrent headless commits, pending relation activation, structural
  canonical-function conflicts, deterministic cover proofs, and
  path-independent derivation before a pile record format is chosen.
- **Demand-curve receipts render as explicit performance fingerprints.** The
  feature-gated `tribleset-bench` GORBIE notebook normalizes fragmented TSV
  axes in memory and gives every engine/storage/execution subject the same
  query-shape × scale × demand panel. Its primary curve is median
  `c(k)=T(k)/k`, with `full` retained as terminal iterator exhaustion and setup
  kept separate. Exact matrices keep missing, unsupported, producer-error,
  and cardinality-mismatch cells visible instead of silently dropping them
  from successful timing curves, and partial ABBA/repetition or identity grids
  cannot masquerade as medians. An embedded demo and headless renderer make the
  view testable without a benchmark run.
- **A bounded oracle checks the regular-path closure kernel.** A Kani harness
  symbolically selects every subgraph of a five-edge, two-vertex labeled
  universe, while an ordinary deterministic test exhausts all 256 graphs whose
  directed cells independently select no edge, a forward label, a reverse
  label, or an unmatched label. Both lower through the public
  `PathSummary`/`PathIndex` API and compare with an independent direct-product
  Floyd--Warshall relation. The nullable fixed automaton covers matched
  support, the complete supplied identity domain, reverse traversal, SCC
  closure, and the canonical accepted-pair stream.
- **Canonical property-path expressions compile directly to epsilon-free
  automata.** `triblespace-paths::PathExpr` composes `Step`s with sequence,
  alternative, repetition, optionality, and structural inversion, normalizes
  associative/commutative structure deterministically, and lowers with the
  Glushkov position construction without restoring query-time traversal or a
  path macro. Regression coverage pins repeated multi-position cycles and the
  complete expression-to-rollup-to-query lifecycle.
- **`triblespace-paths` provides exact regular-path indexes outside the core
  query solver.** Fixed epsilon-free automata lower graph edges into unionable
  direct-product summaries. A single SCC/bitset kernel materializes canonical
  forward and reverse endpoint relations, including exact cross-segment paths,
  and exposes them through the ordinary two-variable constraint protocol.
- **The book now teaches the stable standalone regular-path index.** A dedicated
  chapter leads with canonical `PathExpr` construction and Glushkov lowering,
  retains explicit epsilon-free automata as the low-level escape hatch, and
  covers direct `PathIndex` joins, exact collection maintenance, cross-range
  closure, nullable universes, and the potentially quadratic endpoint
  relation. Interim status guidance and its resolved documentation backlog
  entry are removed.

### Changed

- **Ordinary collection publication no longer implies a durability barrier.**
  Commit and merge publication still writes every content-addressed dependency
  before its native collection record, but performs no implicit storage flush.
  Callers may batch publications behind an explicit `StorageFlush::flush()` or
  rely on storage close, matching Pile's append-only visibility model and
  removing two `sync_all` calls from every collection commit.

- **Durable demand/cache interest is now a standalone `WantStore`.** The
  public `want`, `unwant`, and `wants` surface no longer inherits named
  compare-and-swap pins, so lazy readers and cache policy can compose with
  stores that have no mutable heads. Pile retains the historical weak-marker
  bytes solely as its compatible physical encoding; MemoryRepo, HybridStore,
  Lazy, Yard, Peer fetches, and reconciliation expose only want semantics.
  Explicitly wanting resident Yard content now records the interest uniformly
  and makes it participate in the configured want budget.

- **The optional telemetry sink now publishes native collection commits.**
  Per-thread `Fragment` batches retain their attachments until a central
  `Collection<Pile>` commits them, carry the telemetry protocol as
  metafacts, and remain intact for an identical retry after publication
  failure. `TELEMETRY_COLLECTION_SCOPE` replaces the former branch setting;
  telemetry no longer creates Repository/Workspace histories or CAS heads.

- **Collection resolution now honors every `DERIVE` pair as an observation of
  a canonical join homomorphism.** Source subsumption is lifted into target collections without
  requiring redundant target `MERGE` records, and active source/target
  commuting squares complete either missing equation. Implied target merges
  participate in physical-cover fallback, and incompatible explicit or implied
  equations completed by active squares produce deterministic functional
  conflicts. Concrete validators remain the trust boundary for the ACI join
  and canonical-homomorphism laws: the generic resolver does not materialize
  every absorption equation or diagnose all order-only global inconsistencies.

- **`UnionArchive` is now a storage-neutral Succinct data source.** Its owned
  shard union and query constraint live beside `SuccinctArchive` under
  `blob::encodings::succinctarchive` and are available through the blob
  encodings prelude. Collection consumers can query an attached exact physical
  cover without depending on branch-head machinery.

- **Portable BM25 is now a recipe-neutral canonical join carrier.** The
  unpublished `Bm25Rollup`, `seg_bm25`, and `query_across` repository-range
  facade is removed. Collection consumers derive exact `PortableBM25Blob`
  elements with their own domain projection and join the selected cover once
  with `PortableBM25Index::merge`; direct callers use the same operation.
  Direct native BM25, HNSW, and Succinct HNSW remain independent.

- **Breaking: Yard collection and compaction now require an explicit retention
  plan.** The parameterless `Yard::collect()` and `Yard::compact()` shortcuts
  are removed, and the duplicate `collect_with_retention` and
  `compact_with_retention` names become the singular `collect(&RetentionRoots)`
  and `compact(&RetentionRoots)` APIs. Callers that intentionally rely only on
  legacy strong pins must now say so by passing an empty plan.

- **Breaking: blob enumeration now returns lightweight handle-and-length
  metadata.** Sync and async `BlobStoreList` implementations yield `BlobInfo`
  values containing the content handle and storage-observed payload length.
  Memory stores reuse their resident byte length, piles read `data_len` from
  accepted record headers without hashing payloads, and object stores reuse
  LIST response sizes without issuing one HEAD per object. The length is an
  unvalidated enumeration hint; accepting typed content still requires
  `BlobStoreGet`, while point `BlobStoreMeta` semantics remain unchanged.

- **Breaking: Identity Epoch 2 redefines every implicit entity root from its
  canonical trible rows.** `entity!`, the JSON object importer, and non-orphan
  N-Triples blank nodes now share one protocol: encode each defining fact as
  `NIL || attribute || value`, sort and deduplicate the complete 64-byte rows,
  hash their contiguous bytes with BLAKE3, and take the final 16 digest bytes.
  Every persisted non-empty implicit entity ID changes, including dynamic
  attribute IDs and identities that transitively contain them. Treat all
  Epoch-1 implicit-ID data as incompatible: migrate or re-ingest it as one
  corpus, and never mix epochs even where the empty-row digest happens to
  coincide. `RangeRecord` canonical validation and commit, branch, capability,
  index-recipe, and dynamic-attribute identities all rotate transitively; the
  corresponding faculties migration is a separate downstream release cut.
  Implicit whole-set construction exports a reproducible plain `Id`
  and emits exactly its hashed defining rows; incremental explicit subjects
  still require an `ExclusiveId`. JSON namespace salts remain supported over
  the new canonical row stream. N-Triples orphan blank nodes remain on a
  deliberately separate, domain-separated protocol, now scoped by the
  byte-exact source-document hash so retrying identical input is idempotent.

- **SuccinctArchive CPU range confirmation batches wavelet descents.** The
  frontier still forms and routes each complete candidate region before any
  fallback, while the canonical CPU path resolves adjacent distinct values in
  bounded 1,024-probe tiles and carries their row-range endpoints through one
  layer-major Jerky descent. This removes the terminal select and second rank,
  preserves probe-group ordering, pre-killed candidates, and adjacent-value
  memoization, and adds no public tuning surface.

- **Rayon can divide a TribleSet CPU confirmation without fragmenting its
  frontier.** Queries explicitly converted with `into_par_iter()` carry that
  intent through their frontier views; ordinary iterators remain serial even
  when invoked inside a Rayon pool. Above an internal crossover, a TribleSet
  confirmer computes the logical frontier's probe groups once and recursively
  divides only its CPU membership work at packed-liveness word boundaries.
  The resulting `Candidates` regions own disjoint mutable words, so workers
  kill in place without atomics, scratch verdicts, or a merge pass. Proposal
  batches and descendant frontiers remain whole, and WGPU still decides its
  route from the complete candidate region before any CPU fallback. A frozen
  threshold sweep selected a 1,024-candidate CPU crossover: against the 8,192
  baseline it cut the dense common-plan full drain by 25% and the causal
  parent-batch full drain by 5%, without a repeatable regression at demands
  one through eight.
- **TribleSet confirmation no longer builds a disabled candidate-sort
  permutation.** The value-order region sort was permanently set to
  `usize::MAX` after losing 33--46% on the fixtures that exercised it, yet its
  unsorted path still copied every parent tag and allocated an identity index
  vector. Confirmation now walks proposer order directly, recognizes the same
  adjacent probe-key runs, and passes ordinary index ranges to the unchanged
  membership dispatch. This removes two region-sized allocations from serial
  confirmation and from every leaf-local Rayon shard without restoring the
  rejected sorting strategy.
- **Breaking: candidate liveness is bit-packed.** The query engine's
  one-`u32`-per-candidate liveness becomes 32 candidates per `u32`, with
  `count_live`/`next_live` folding whole words through
  `count_ones`/`trailing_zeros`. `ProposalBuffer` and `Candidates` move into
  their own `query::liveness` module, so the packing is contained by a module
  boundary rather than by convention. `Candidates` now carries a bit offset —
  a packed region cannot sub-slice at an arbitrary bit the way a word slice
  can — which makes its first and last words shared with neighbouring regions;
  every write masks to the bits it owns and every word handed out is zeroed
  outside them. That applies to the per-parent runs `for_each_parent` cuts as
  much as to the region itself. `Candidates::live_word_len` is the new (and
  only) source of truth for how many words a region's liveness occupies, and
  `Candidates::bit_offset` reports where entry 0 sits inside the first of them
  — the one piece of the layout code that indexes liveness *bits* rather than
  candidates needs. Parent tags are unaffected: they stay one `u32` per entry.
  `and_words`/`or_words` are unchanged too: they were always an abstraction
  over liveness *words*, so word-wise composition still merges verdict sets
  whatever a word carries. The word-per-candidate layout is gone rather than
  kept behind a flag; it lives in git history if it ever needs remeasuring.
- **`query::LIVENESS_WORD_BITS` exports the core/device geometry.**
  `triblespace-gpu` const-asserts it against the 32 its packed kernels
  hardcode — the ballot component they read, the one-store-per-plane guard,
  and the bit/word arithmetic — next to the existing `THREADS % 32` assert.
  Widening the liveness word without widening the kernels would otherwise
  compile, run, and return silently wrong query answers rather than crash.
- **The device confirm path packs its verdicts with a plane ballot.**
  `triblespace-gpu`'s verdict kernels no longer write one verdict word per
  candidate. The flat index is the *bit position* in the region's liveness word
  array rather than the candidate index, so candidate `i` is bit
  `bit_offset + i` and a 32-lane plane's `plane_ballot` yields a whole packed
  verdict word with every bit already in the position the word wants it in: no
  rotation by the region's bit offset, no read-modify-write of a word two lanes
  share, no atomic, and one store per 32 candidates. The probe-fill kernels
  stay candidate-indexed — their outputs feed Jerky's per-candidate rank batch
  — and only bit-address their liveness *input*. Out-of-region bit slots vote
  `false`, which is the value that survives `live_words`'s zeroing and
  `set_live_words`'s masking unchanged, so a confirm still cannot reach the
  neighbouring regions that share its first and last word. The host sizes every
  verdict buffer from `live_word_len`, dispatches `bit_offset + n` slots, and
  refuses the device — demoting to the CPU arm and counting a device error —
  unless the adapter reports planes of exactly 32 lanes, the width both
  supported targets (NVIDIA warps, Apple Silicon) have and the width the packed
  store's exclusivity argument rests on.
- **The batch-confirm parity suite exercises non-zero region bit offsets.**
  `triblespace-gpu`'s parity tests built every region with `buffer.region(0)`,
  so the region's bit offset was always zero and the suite structurally could
  not catch a packed write landing at the wrong offset or trampling a
  neighbour. Every case now runs at bases 0, 1, 5, 31, 32, 33, 63, 64 and 1000,
  reads liveness back through `ProposalBuffer::is_live` instead of spelling a
  word layout, and asserts three things at each base: the region's verdicts
  match the CPU arm's, the verdicts do not move with the base, and every entry
  *below* the base comes back exactly as it went in — live ones live,
  pre-killed ones dead.
- **Public `TribleSet` fingerprints no longer expose PATCH's linear root
  aggregate.** The O(1), process-local cache token is now a domain-separated
  SipHash-2-4 PRF of the internal XOR under a distinct random key. `as_u128`,
  `Debug`, and `Hash` retain their API while revealing only the blinded value,
  closing the chosen-singleton linear-dependency oracle.
- **PATCH rejects unequal LocalLeaf/Branch cardinalities before hashing.** Set
  operations skip the uncached `LocalLeaf` fingerprint when the other subtree's
  cached count is not one. Unary Branches remain eligible for fingerprint
  equality, so this optimization does not assume that every Branch has at least
  two leaves; pairs without a `LocalLeaf` retain their existing hash path.
- **PATCH set operations decide archive-backed leaf pairs by exact keys before
  fingerprints.** `union`, `intersect`, and `difference` compare keys directly
  whenever either singleton is a `LocalLeaf`; heap/heap pairs retain their
  cached-fingerprint fast path. Distinct union carries each child's one
  required hash into the new Branch, while equal intersection and difference
  need no hash at all.
- **Parallel SimpleArchive decoding builds each worker chunk bottom-up.** For
  aligned archives at or above the existing 4,096-row parallel threshold, each
  worker validates every canonical row, computes its construction hash once,
  reuses one `u32` permutation across all six PATCH orderings, and constructs
  path-compressed branches with an in-place sparse MSD partition. Known fanout
  preallocates tables, eager subtree hashes are carried through construction,
  and one root owner cover is shared across all six bottom-up-built indexes.
  Small, unaligned, and oversized inputs keep their existing serial or
  heap-leaf fallbacks.
- **Archive-backed PATCH ownership is closed under every structural
  operation.** `LocalLeaf` lifetime is now independent of trie shape: each
  PATCH root carries a persistent binary Patricia set of retained archive
  allocations, keyed by allocation address and exactly deduplicated across
  clone, union, intersection, difference, removal, and consuming iteration.
  Set operations may conservatively retain provenance no longer reachable
  from their result, but cannot omit a reachable owner or accumulate duplicate
  owners through overlapping diamond unions. `TribleSet` joins provenance once
  and shares the resulting cover across all six indexes. Asymmetric difference
  also collapses its edited root when only one child survives, preserving the
  compressed-trie shape invariant. This adds one thin eight-byte Arc to PATCH
  while restoring the ownership-neutral 48-byte Branch header (sixteen bytes
  smaller than the per-Branch owner design).
- **Parallel query splits transfer whole frontier units.** Rayon now steals one
  complete preferred-variable group, or one complete terminal page, instead of
  bisecting a proposal buffer. Geometric pages and accelerator-sized batches
  stay intact. The sibling is re-rooted and fenced to its unit; a split is
  admitted only when the left producer retains a later group or ancestor
  candidate continuation. Every successful split therefore removes work from
  the left and cannot rediscover it, so the old `num_threads²` split budget and
  candidate-buffer `split_off` machinery are gone. An indivisible 1:1 chain
  remains serial and keeps its zero-copy in-place descents rather than cloning
  useless siblings at every depth.
- **Rayon siblings share immutable proposal buffers.** `LevelValues` now holds
  `Option<Arc<ProposalBuffer>>` plus its branch-local consumption cursor, so a
  query split bumps refcounts instead of deep-cloning every live variable's
  values, parent tags, and liveness words. `None` keeps an empty 128-slot
  `BindingStore` allocation-free. Refill reuses a uniquely owned buffer, but
  replaces a shared buffer *before* clearing or proposing, preserving the
  sibling snapshot without copying data that is about to be discarded.
- **Breaking: `propose` and `confirm` operate on a frontier of bindings.** Both
  methods take a `Frontier` — the whole collection of parent bindings at one
  point of the search — instead of a single `Binding`; a single binding is a
  frontier of one (`BindingStore::frontier`, `Frontier::default`) and behaves
  exactly as before. `ProposalBuffer` is segmented (a proposer calls
  `open(row)`; every entry carries a parent tag) and `Candidates` exposes the
  tags plus `for_each_parent`, so one region spans a whole batch. The engine
  expands up to `DEFAULT_FRONTIER_WIDTH` = 16384 rows per step
  (`Query::with_frontier_width` to tune; width 1 is the pre-batching shape).
  Motivation is measured: a region-size census over dblp finds a median
  confirm region of 1–7 candidates at every scale, so batched tiers — the GPU
  path's 16384-candidate crossover above all — engaged only at the root. The
  variable choice stays per row: a row is never moved onto a variable it did
  not choose, the frontier is partitioned by each row's own adaptive choice,
  and `FrontierStats` reports how often that fragmented. Bag semantics and
  worst-case optimality are unchanged; the cost is frontier memory,
  `O(width × variables × depth)`.
- **Breaking: `Constraint::estimate`'s relevance must not depend on bound
  *values*.** Whether it answers `Some` or `None` may depend only on *which*
  variables are bound, never on what they are bound to. Composites now read
  relevance off the batch rather than per binding — `IntersectionConstraint`
  ORs it across the rows in `propose` and takes it from row 0 in `confirm` —
  and both are exact only under this rule. Every in-tree constraint already
  satisfies it, including `EqualityConstraint`, whose `None` keys on a peer's
  *boundness* and so is uniform across a frontier; but an out-of-tree
  constraint that keys on the bound value instead is the natural way to get
  this wrong, and it fails as **wrong rows in either direction**, not as a
  panic. Debug builds now assert it (exhaustively in `propose`, which visits
  every row anyway; sampled with a stride in `confirm`), and
  `tests/estimate_relevance_contract.rs` pins the enforcement.
- **The frontier width is a ceiling, and levels ramp by base eight from one
  binding.** `INITIAL_FRONTIER_WIDTH` = 1; later chunks grow through
  8, 64, 512, … up to the query's full width. A query the caller stops after
  one row — `exists!`, `.next()` —
  now does exactly the work the pre-batching engine did instead of
  materialising a 16384-wide root frontier it will throw away; measured on a
  first-row-only join, the flat engine was **8.8x** slower than pre-batching
  and one narrow chunk closes the whole gap. This is the same insight as the
  `INITIAL_CHUNK`/`WIDEN_FACTOR` pair removed with the widening path, and as
  the residual engine's rule that search width grows geometrically after
  negative work — recovered at the frontier, which is the layer that can
  actually carry it, rather than at per-parent chunking, which could not.
  A geometric 1, 2, 4, … ramp was measured and rejected because its last chunk
  holds only half a level's candidates. The failure was the base, not the
  ramp: base eight retains seven eighths asymptotically and reaches a 16384
  ceiling in six terms. Across 300 registry spans it retained 99.61% of the
  flat schedule's aggregate widest frontier and 93.30% rather than 97.46% of
  GPU-routed candidate work, at 44.7% more expansions. A conservative tail
  merge recovers small remainders without exceeding the width ceiling.
- **A 1:1 descent reuses the parent frontier's matrices instead of copying
  them.** When a level's draw yields exactly one surviving child per parent
  row, in order, over the whole frontier, with nothing left pending, no row
  was gained, lost or reordered — so the child block *is* the parent block
  with one more slot written, and the child estimate rows are bit-identical
  to the parent's. Both matrices are handed down rather than rebuilt. The
  engine's standing invariants are what license it: confirmers may only kill
  candidates and never revive them, and buffers are write-once, so the newly
  bound variable's slot was previously unwritten. Ownership needs no separate
  flag — the matrices already sit behind `Arc`, so `Arc::get_mut` succeeds
  exactly when no rayon split holds the other half and the copying path runs
  when it does not. `FrontierStats::inplace_descents`/`copied_descents`
  report the split. This is what a chain-shaped query (fan-out 1 at every
  level, where batching can never pay because there are no sibling parents)
  stops being charged for. The fast path is gated on `proposed == rows`, an
  `O(1)` test from what the engine already knows, so a fan-out descent never
  pays for a path it cannot take: recognising a 1:1 draw needs the child rows
  deferred until its shape is known, and charging that second pass to every
  descent measured +10% and +20% on two fixtures.
- **`FrontierStats::widest` reports the widest frontier a search reached.**
  `mean_width` says what the typical expansion looked like; it cannot say
  whether the ceiling was ever approached, and without that a benchmark
  cannot distinguish "the engine does not scale with depth" from "the fixture
  never filled a batch".
- **Breaking: `propose_chunk`, `ProposeCursor` and the widening path are
  removed.** No leaf source ever overrode them, they addressed a
  time-to-first-result problem that pure conjunctive queries do not have
  (depth-first already yields the instant the stack bottoms out), and their one
  real case — a wide root — is a lottery on iteration order rather than a work
  saving. With widening gone no level is appended to while its variable is
  bound, so `BindingStore` loses its detached-buffer special case and asserts
  the buffer-stability invariant instead. Narrowing a wide level remains open;
  galloping intersection is the standing candidate, and it will not be bought
  with a seek requirement on sources.
- **`triblespace-gpu` confirms a whole frontier in one dispatch.**
  `range_probe_fill_kernel` takes per-candidate row-range arrays instead of two
  scalars, so the CPU computes one archive band per frontier row and the device
  resolves each candidate through its parent tag. Membership arms are
  parent-independent and needed no change. Verdicts still merge by word-wise
  AND, and the parity suite still pins CPU and device to identical liveness
  words.

- **Breaking: the query engine is the propose/confirm engine.** The residual /
  typed-Program engine is gone — `residual.rs`, the Program VM, query-time
  regular-path evaluation (`path!` and `RegularPathConstraint`), and the
  terminal projection claims table are deleted, roughly 70k lines net. What
  replaces it: stateless constraints speaking a seven-method protocol over
  write-once `ProposalBuffer`s and kill-only `Candidates` liveness, a
  depth-first driver with dynamic cardinality ordering, and
  bag-of-complete-bindings semantics at the interface (deduplication is the
  consumer's choice — collect into a set, or use an outer enumeration with an
  inner `exists!`). Constants are Term-native again, so `or!` arms with
  differing literals align. Regular paths return as a materialized closure
  index in `triblespace-paths`, not as query-time traversal.
  Measured against the engine it replaces on a 1M-trible dblp rung: interactive
  queries recover 2.5-5.7x, archive build is unchanged, and the one capability
  lost with query-time RPQ is exactly the one moving to the index.
- **The book's query chapters describe the engine that exists.** Nine
  chapters still narrated the deleted residual engine — `RowsView` row
  blocks, canonical residual states, typed Programs, `proposal_coverage`,
  the terminal projection gate, residual action observation, and the
  `path!` macro. `query-engine.md` is rewritten as the flagship account of
  the propose/confirm protocol: the seven `Constraint` methods and which
  four a source must implement, statelessness and what it buys (free
  backtracking, a clonable tree, a plain-data `ProposeCursor`), depth-first
  search with dynamic variable ordering including the `ilog2` specificity
  bucket and influence-count tie-break, the write-once `ProposalBuffer`
  with per-entry liveness words, the kill-only `confirm` contract as the
  reason confirmation needs no coordination, geometric chunked proposing,
  rayon split-or-descend, BAG semantics at the interface (with a runnable
  example and an account of why the claims table was removed), Term-native
  constants below the variable layer, the GPU as batched confirm against a
  measured threshold, where regular paths went, and a closing section on
  the four refusals — no optimizer, no negation, no query-time recursion,
  no projection dedup — and what each one buys. `query-language.md`,
  `macro-cookbook.md`, and `incremental-queries.md` drop the stale
  set-semantics phrasing; `atreides-join.md`, `glossary.md`,
  `formal-verification.md`, `architecture.md`, `patterns-and-recipes.md`,
  and `documentation-improvements.md` drop the deleted engine's
  vocabulary. `path!` material is replaced honestly: paths moved to a
  materialized closure index in `triblespace-paths`; fixed-depth joins remain
  available as ordinary explicit patterns.
- **Bindings are paths, not value copies.** A bound variable's value
  always originates from that variable's own level buffer, so `Binding`
  now stores the `u32` index of the chosen entry and resolves it through
  the buffers on read instead of carrying a 32-byte copy per variable.
  Two engine properties license the swap: a level's buffer is only
  cleared and refilled when its variable is (re-)pushed — at which moment
  the variable is unbound — and buffers are write-once (confirmers kill
  entries by clearing a parallel liveness word; nothing rewrites a value
  the engine can already see). `Binding` is consequently a *view* — the
  index row plus a borrow of the level buffers — and the new
  `BindingStore` owns both halves; `Binding::set` is replaced by
  `BindingStore::bind`, `Binding::get` and every `Constraint` signature
  are unchanged (`&Binding` still elides). `size_of::<Binding>()` goes
  4112 → 32 bytes (a view), the value-carrying part of the search state
  goes 4 KiB → 512 bytes, a bind is a 4-byte write instead of a 32-byte
  copy, and `Query` shrinks 22640 → 19040 bytes, which the rayon splitter
  pays per fork. The engine gets the `&mut` on the level it is proposing
  into by moving that level out of the array for the duration of the call
  (no `unsafe`); widening is the exception and appends a detached chunk
  instead, because the engine reaches a widen by exhausting a level whose
  variable is *still bound* and whose binding must keep resolving. The
  real point is downstream: a batch of bindings is now a small integer
  matrix over shared, device-resident buffers — the shape GPU *descent*
  needs, not just GPU confirm.
- **Pattern constants are Term-native again — `or!(pattern!, pattern!)`
  works.** Resurrects 78c1a1b7's constant folding on the June-protocol
  engine: `TribleSetConstraint`, `SuccinctArchiveConstraint`, and the GPU
  wrapper store each position as a `RawTerm` (`Var` or `Const`), and the
  `pattern!`/`pattern_changes!` macros emit attribute constants, literal
  values, and constant entity ids as constant terms instead of hidden
  variables pinned by `ConstantConstraint`. Constants live below the
  variable layer: they never enter the `Binding`, are never proposed, and
  `variables()` excludes them — so union arms compare only the query
  variables the caller wrote, literals no longer consume the 128-variable
  budget, and estimates treat constants as bound from step 0. The
  `RawTerm::position_value` helper unifies "bound variable" and
  "constant", so every backend's bound-position dispatch handles constants
  with zero new arms. A fully-constant pattern has an empty variable set
  and is settled by one exact `satisfied()` probe in `Query::new`
  (`SuccinctArchiveConstraint` regains its fully-bound `satisfied`
  override for this). `Term::expect_variable` — the transplant-era seam
  that panicked on constant terms — is deleted, and
  `UnionConstraint::new`'s mismatch panic names the offending variable
  sets again. The `or_pattern.rs` suite returns (11 tests), extended with
  runtime proofs that constants never enter the `Binding` and that a
  161-constant pattern allocates zero variables.
- **`triblespace-gpu` is rewritten around batched confirm and rejoins the
  workspace.** The old integration served the removed engine paradigm (typed
  Program routing, resident frontier machinery, residual-action observation)
  and is deleted wholesale. The new `WgpuSuccinctArchive` keeps the value
  universe, per-axis occupancy boundaries, and six Ring wavelet matrices
  resident on WGPU; its constraint mirrors the canonical
  `SuccinctArchiveConstraint` and evaluates `confirm` regions with at least
  `DEFAULT_MIN_CONFIRM_BATCH` (16,384, measured on Apple M4 Max Metal) live
  candidates on the device — one fused binary-search/occupancy kernel for the
  three unbound membership arms, a probe-fill/batched-rank/verdict-fold chain
  for the nine range arms — merging verdicts by the kill-only word-wise AND
  the confirm contract guarantees. Everything below the threshold and any
  device error falls back to the CPU arm; a parity suite holds both paths to
  identical liveness words. The umbrella crate's `gpu` feature returns as
  `dep:triblespace-gpu` + `parallel`. The stale device-neutral
  `RingBatchQuery` seam is removed from core.
- **`triblespace-search` is ported to the propose/confirm protocol and
  rejoins the workspace.** The crate's row-batch-era Constraint impls
  (TypedProgramSpec, program states, route consts) are deleted and the three
  constraint shapes now speak the cooperative protocol directly: `BM25Filter`
  and `SimilarTo` are unary set sources (estimate = entry count, propose
  appends the frozen entries, confirm retains membership), while
  `CosineAtLeast` stays confirmation-only — `usize::MAX` estimate, empty
  propose, kill-only confirm that leaves candidates alive while the peer
  variable is unbound. Duplicate occurrences in `from_entries` /
  `from_candidates` collapse at construction: the engine has no raw-head
  claiming layer, so the constraints themselves enforce their raw-value SET
  denotation. The umbrella crate's `search` feature returns as
  `dep:triblespace-search` (not in default).
<!-- ------------------------------------------------------------------ -->
<!-- SUPERSEDED: everything below this line documents the residual /      -->
<!-- typed-Program engine, which was replaced before it was ever          -->
<!-- released. The entries are kept as the record of that work, but they  -->
<!-- describe machinery that no longer exists: typed Programs, residual   -->
<!-- states, projection claims, SET head semantics, RPQ scheduler bounds. -->
<!-- The entries ABOVE are authoritative for the current engine. Drop     -->
<!-- this block deliberately when release notes are cut.                  -->
<!-- ------------------------------------------------------------------ -->

- **Union constraints now expose one physical occurrence-stream protocol.**
  Live arms propose into independent empty sinks whose occurrences concatenate
  in arm order; confirmation derives relational support from every live arm
  and retains the original stream's order and multiplicity. Logical
  idempotence remains at the engine's raw-head SET-admission boundary.
  SuccinctArchive fixed-pair walks now use their structural uniqueness
  directly, and the stale standalone bag-scheduler model is removed.
- **Breaking: cyclic constraint execution now has one typed Program runtime.**
  The ten never-shipped residual pager, seed, and expansion hooks are removed
  from `Constraint`, together with their source/transition queues, descriptor
  registry lane, and forwarding adapters. A selected typed Program enters the
  affine scheduler; a structurally absent route uses the ordinary constraint
  action. Custom constraints that need resumable work implement a typed Program
  instead of a second residual protocol.
- **Built-in finite proposal sources now use one typed Program
  pager.** PATCH value/ID membership, sorted slices, SuccinctArchive and
  TribleSet patterns and ranges, and UnionArchive use the same typed paging
  substrate.
- **Breaking: ordinary queries now have one fixed residual compiler policy.**
  Serial iteration, ordinary Rayon iteration, saturated parallel iteration,
  and private RPQ subframes all compile native AND regions with finite
  Union-leaf continuations and the typed Programs returned for each action.
  `Query::residual_lowering`, `ResidualLowering`, `FormulaScope`,
  `ProgramScope`, and `solve_residual_state_lazy_with` are removed rather than
  retained as never-shipped compatibility or tuning surfaces.
- **The residual compiler no longer carries the synthetic WholeRoot
  experiment.** Native AND leaves remain in the ordinary residual plan, while
  finite Formula control begins only at Union occurrences. The deferred
  root-AND quote carrier, its direct-root candidate paging path, and the
  never-shipped `Constraint::residual_and_estimate_is_child_minimum`
  certificate are removed; production Union Formula and RPQ execution are
  unchanged.
- **Breaking: serial residual execution now has one iterator implementation.**
  The never-shipped eager `solve_residual_state` and
  `solve_residual_state_profiled` entry points, their private worklist loop,
  and the obsolete opaque-plan compiler alias are removed. Full enumeration
  drains `solve_residual_state_lazy`; profiling drains that iterator through
  `collect_profiled`. Focused unit tests retain a private opaque ordinary
  `Constraint` oracle for differential checking.
- **Breaking: adaptive variable choice now has one fixed specificity key.**
  `OrderKeyMode`, `order_key_mode`, and the `TRIBLES_ORDER_KEY` environment
  switch are removed. Directed action costs still choose the proposal source
  within one variable; variables compare that source's raw candidate-count bit
  length, then `VariableId`. The stranded `Constraint::influence` hook and its
  plan-local count array are removed: every production built-in supplied the
  same count for all of its variables, while every Ready state already computes
  fresh per-row estimates.
- **RPQ complete actions now obey exact scheduler work bounds.** Bound-endpoint
  graph-product traversal admits only a descending parent tail whose examined
  transitions and distinct endpoint outputs fit the current grant; positive
  PATCH branches preflight exact fanout, while negated branches remain
  cursor-bounded.
- **Ordinary Rayon query iteration now reuses the canonical residual
  producer.** A fresh `Query::into_par_iter()` moves directly into the
  adaptive-width residual iterator and its affine splitter instead of entering
  the removed scalar split-or-descend path. Already-started queries remain one
  exact-remainder leaf.
- **Breaking: ordinary confirmation now pages under weak support refinement.**
  The never-shipped public `Constraint::residual_confirm_is_page_local` and
  `residual_delta_confirm_grouping_requirements` hooks are removed. Every newly
  proposed `(parent, value)` is SET-admitted before its first independent
  split; a confirmer may vary conservative false positives by page while
  preserving every true support and becoming exact once its peers are bound.
  Formula OR retains its live-frame payload barrier, and repeated RPQ
  `ParentAtomic` grouping remains only a typed Program activation-reuse hint,
  not a stronger semantic law. Positive Confirm publication now uses an exact
  relational-prefix receipt rather than historical SET-boundary crossing.
- **Compiled Formula proposals now record whether their outer self-confirm
  obligation is discharged.** The private boolean records that no later
  self-confirm is required—whether by an Exact source proof or validation
  performed along the route—instead of overloading `ProposalCoverage::Exact`,
  whose public meaning remains equality with the existential fiber. Scheduler
  choices and checked-state transitions are unchanged.
- **The `Constraint` protocol now has unconditional relational SET
  semantics.** Every occurrence denotes a fixed raw-inline relation shared by
  its ordinary, paged, typed-Program, and complete-equivalent routes; the
  never-shipped `fixed_denotation` switch and parallel certified action methods
  are removed. Planning always uses `ProposalCoverage` for logical source
  eligibility, physical proposal multiplicity remains an execution detail, and
  estimates remain cost guidance only.
- **Finite-Formula structural control is interned independently from its
  canonical outer Candidate exit.** Residual Formula state now carries an
  exact `(program-counter, candidate-exit)` cursor. The exit records only the
  future ordinary Candidate descriptor `(variable, relevant, checked)`, while
  child selection, skipping, completion, and the persistent return spine
  transform only the structural counter. Proposal and confirmation histories
  therefore converge exactly when they reach identical structural control and
  future Candidate work; exit checked-count plus structural grade supplies the
  corresponding rank. Delta and private reducer suspensions retain the full
  cursor, preserving affine payload and SET boundaries across that quotient.
- **Finite Formula AND now threads one affine candidate payload without
  structural frames.** `FormulaBatch` stores one live cell per irreducible OR
  source/ordered-set reducer plus a trailing candidate cell only in phases
  where that affine stream exists. Proposal planning, Support, action
  execution, and OR admission/emission therefore retain no dummy candidate
  payload. Canonical PC return edges, rather than payload-stack shape, decide
  whether a completed action or connective returns to the root, a parent AND,
  or a parent OR. Parent partitioning, paging, cloning, delta finalization, and
  ordered OR admission preserve the same SET and lazy-scheduling semantics.
- **Positive Support hedges now spend parent-local demand credit.** Each public
  pull may assign one demand unit to one parked semantic parent; only then may
  validated exact Confirm work mint additional allowance. Support Program
  tasks reserve that allowance before dispatch and settle it against actual
  examined work, refunding short pages and retiring every unspent unit on
  success, exhaustion, cancellation, or parent closure. Wakes remain
  parent-isolated, Exact credit returns the directed Exact lease to global
  arbitration, and clones preserve both parked affine custody and ledger
  conservation. New post-validation statistics expose assigned demand,
  Support work, paired and credited Exact work, retired credit, and
  source-specific publication wins.
- **Positive Support hedges now have explicit live-but-parked scheduler
  custody.** Their opaque typed handles and affine producer credits can leave
  the runnable Program frontier without being consumed, survive deep clones
  with fresh registry brands, and are drained by the same cancellation
  transaction as queued work. A directed parked lease is released without
  claiming quiescence or stable progress, so the exact Confirm parent remains
  the sole completeness-bearing runnable lineage. Demand and exact-work credit
  assignment are layered on this custody without changing SET semantics.
- **Eligible target-Confirm activations can publish their first candidate from
  the authoritative exact traversal.** A new structural Program certificate
  lets every eligible exact RPQ Confirm reuse a real replacement receipt that
  newly accepts occurrence zero while exact Confirm remains the sole
  completeness owner. A separately authorized fully-bound Support hedge races
  inverse, same-variable, mixed-family, and routes without an early-publication
  receipt; a conservative cumulative-work dominance receipt may elide it when
  retaining Support cannot improve first-positive latency. That performance
  receipt requires no internal state, page, ordering, or trace equality. Both
  feeders share the generation-fenced parent/value SET ledger and immediate
  grant/release path, so duplicate or stale receipts cannot publish twice, a
  false first occurrence never feeds later candidates, and quiescent
  finalization receives exactly `G \ P`. PositiveSupport now affinely discards
  queued typed handles,
  consumes issued credits, and retires as inert cleanup after its first
  positive receipt, an exact winner, or exact quiescence; exact work is never
  cancelled. Nullable seed acceptance remains deliberately ineligible for
  early publication. The corresponding `ResidualStateStats` fields are now
  named `delta_positive_publication_*` because they count either feeder.
  Ineligible continuations still acquire no ledger, and generic joined
  `AfterChildren` propagation remains outside the Support fallback.
- **Residual Confirm continuations now carry an executable publication
  receipt.** The private three-valued proof distinguishes an exact terminal
  binding, a nonterminal relational prefix whose exact successor has already
  admitted the `(parent, value)` occurrence, and a conservative barrier. This
  freezes the structural law used by PositiveHedge integration.
- **Directed singleton Program chains can spend one scheduler grant locally.**
  An unjoined streaming activation may consume exact same-cohort sole children
  inside its producing receipt until the original work budget is exhausted or
  a direct page effect, resume, placement, dispatch change, or join boundary
  is reached. Accepting sole-child endpoints are SET-admitted at the final
  receipt in their original page order. The producer registry still observes
  one affine replacement, while global cohorts retain their existing
  scheduling behavior.
- **Typed Program activation retirement scans its arena at most once per
  cohort.** A fully drained arena retires immediately; singleton receipts keep
  their allocation-free one-entry scan, while wider live arenas build
  activation membership once. Every checked path validates owners before
  deleting novelty in original receipt order, removing the activation-count
  multiplier without taxing insert/take.
- **Canonical Succinct archive paging is selected directly.** Propose, Confirm,
  and Support routes participate in ordinary execution, keeping their typed
  paging and physical-backend seam available through the one plan.
- **`UnionArchive` returns typed Propose and Support routes and declines
  Confirm.** Ordinary execution keeps sparse, geometrically
  widened paging for low-demand and nonterminal work. A fresh multi-parent
  terminal Propose cohort may instead use its `CompleteActionEquivalent`
  certificate, preserving the exact parent-major then shard-major raw
  occurrence bag before parent-local SET admission.
- **Specialized `UnionArchiveConstraint`s can now retain per-shard execution
  attachments.** `from_shards` accepts already-constructed Succinct archive
  constraints, validates their exact ordered entity/attribute/value terms, and
  preserves normalized union ordering, duplicate, tag, and Program semantics.
- **Flattened residual AND planning can price directed backend work instead of
  raw proposal width alone.** Lawful leaves may publish immutable logarithmic
  proposal and confirmation unit classes while their existing estimates quote
  physical candidate occurrences. The directed price chooses a source within
  one target variable; cross-variable ordering and generic composite estimates
  remain on raw cardinalities. Planning includes proposal, engine SET
  admission, and every required confirmation occurrence, with an atomic
  raw-cardinality fallback unless all relevant peers opt in. HashSet and
  single-position Succinct sources publish broad hash/sequential versus
  random-rank classes; finite-formula actions, repeated-position Succinct
  targets, and multi-shard UnionArchive constraints remain on raw-cardinality
  estimates.
- **Finite equality work and pointwise TribleSet checks stay on the ordinary
  path, while TribleSet proposal cursors remain resumable.** Equality exposes
  no typed Program. TribleSet declines typed Confirm and Support, so ordinary
  execution uses their already bounded kernels.
  TribleSet Propose remains pageable for low-demand
  and high-fanout work. For multi-parent terminal cohorts, its exact complete
  occurrence-bag certificate lets the geometrically widened scheduler drain a
  batch without opening one Program activation per parent.
- **Hash-set and hash-map membership filters stay on the ordinary production
  residual path.** Their pointwise Confirm and Support work is already bounded
  by the scheduler's input page, so production execution does not expand each
  cheap hash lookup into a typed Program activation. They expose no typed
  Program.
- **Ordinary residual queries use one production structural policy.** Exposed
  associative AND regions are flattened into residual occurrences, finite
  Union leaves become formula continuations, and typed Programs such as
  regular-path execution are enabled when they return a route for the exact
  action. An absent route uses the ordinary constraint protocol and cannot
  inherit typed grouping or a stronger Program receipt.
- **Cyclic Confirm actions now cross the same parent-local SET boundary as
  ordinary actions.** Graph traversal retains the immutable original
  occurrence bag and raw confirmation telemetry until its complete result
  first reaches a candidate continuation that may split or commit. Contiguous
  results use the tail-stable fast path; segmented ropes enter a bounded,
  clone-cheap scan/emit Program that preserves last-position storage order
  without materialization. Independent affine parents remain independent.
- **Streaming proposal sources and typed Programs now admit SET candidates per
  affine activation.** Direct values, accepting roots, and typed observations
  retain their raw receipt counts for telemetry, then first-occurrence-stably
  collapse before each stable handoff; later pages cannot replay an equal
  value for the same parent, while independent parent activations remain
  independent.
- **Proposal actions now enter the search as SETs.** One-row actions
  reverse-stably remove duplicate proposed values, while wider actions admit
  `(parent, value)` pairs at their stable boundary. Tail-pop order and equal
  values under distinct parents remain intact, while proposal telemetry
  continues to report raw occurrence counts.
- **Breaking: query heads now have relational SET semantics.** `find!` emits
  each distinct ordered tuple of raw projected inline values once, collapsing
  assignments that differ only in hidden witnesses. The empty head therefore
  yields at most one `()`. Strict projections claim raw identity before
  conversion or mapper code, so a filtered row or panic is not retried through
  another witness; non-injective Rust conversions do not collapse distinct raw
  tuples. Complete heads are already injective over the engine's universally
  SET-admitted bindings, so they elide the terminal claim table, projected-key
  allocation, and Rayon claim mutex entirely. Direct `Query::new`
  conservatively uses that complete constraint-variable head. Iterator clones
  snapshot strict-head claims independently, while Rayon strict-head siblings
  share one run-owned claim domain. Repeating a variable in a `find!` head is
  now a compile error; project it once and duplicate the converted value in
  application code if needed. There is no public bag mode.
- **Certified complete Program proposals now cross the SET boundary before
  publication.** The adapter first validates the entire raw grouped occurrence
  bag, then admits each distinct `(parent, value)` in first-occurrence order.
  Proposal statistics continue to charge the raw bag, while terminal row and
  receipt accounting sees only the admitted per-parent relation.
- **Ordinary residual actions admit SET candidates at their first semantic
  boundary.** Opaque Propose and Confirm actions retain raw work telemetry,
  then tail-stably collapse equal values per affine parent before candidates
  may split or a fully checked binding is committed. Equal
  values belonging to different parent rows remain independent. Segmented
  affine ropes are explicitly left for bounded reducer admission rather than
  being materialized merely to deduplicate them.
- **Finite Formula actions use the same first-boundary SET admission.** An
  exposed AND tail-stably admits `(parent, value)` support before the
  continuation may split candidate pages or commit the outer binding. Equal values under
  distinct parents remain independent, Formula OR keeps its private ordered-
  set reducer semantics, and segmented affine ropes cross the boundary through
  bounded engine admission instead of synchronous materialization.
- **Internal occurrence bags remain observable below public SET projection.**
  Core source and scheduler regressions now assert both sides of that boundary:
  PATCH, sorted-slice, TribleSet, attached-range, intersection, and archive
  confirmation paths preserve raw affine multiplicity and order, while public
  `Query` results expose each distinct raw head exactly once.

### Fixed

- Activate a `pile net sync` collection cohort through one coherent serving
  snapshot instead of rebuilding the serving view once per `--collection`
  argument during startup.

- Replace the global 8-bit provider-cover rendezvous with exact full-width
  derived-key DHT PUT/GET leases. Directory requests never carry bearer blob
  handles, while unrelated artifacts no longer collapse onto 256 fixed
  hotspots. Exact-content publication covers every served resident blob and
  remains independent of collection READ policy. This locator change and the
  later self-contained proof-body cutover use the current pile-sync ALPN
  generation, `/triblespace/pile-sync/23`.

- Make nonempty exact-derived network attachment fail closed when refreshing
  discovers a conflicting store scope, rather than clearing the serving view
  and then continuing against that physical store. Speculative remote cover
  members now also share one absolute interactive fetch deadline, so stale
  cover width cannot multiply the operation's network latency bound.

- Workspace preflight now runs `cargo fmt --all -- --check`; the repository
  root is also the `triblespace` facade package, so the bare form silently
  omitted other workspace members. Contributor instructions now state the
  matching workspace-wide formatting and test commands.

- **Unknown pile record markers can no longer arm destructive repair under
  version skew.** A complete unknown marker at a record boundary now returns
  `ReadError::UnsupportedRecord` with its offset and marker, while malformed or
  truncated known records remain `CorruptPile`. `Pile::amputate` refuses the
  unsupported case without truncating, and CLI diagnostics direct operators to
  upgrade the reader without recommending tail removal. Unknown records are
  not skipped because their lengths are unknowable.

- **Pile and Yard retention now authenticate native commit ownership before
  rooting blobs.** A structurally decodable but invalidly signed `COMMIT`
  remains preserved as an immutable collection record, while none of its
  attacker-controlled descriptor, data, or metadata fields affect retention.
  Valid commits recursively retain only dependencies resident in the rewrite's
  coherent source snapshot or live in the Yard, so partially synchronized
  dangling commits remain available for later synchronization without
  poisoning local retention. Caller-supplied `RetentionRoots` and strong pins
  retain their existing backend-specific missing-data behavior.

- **Index recipes ignore blobs carried only by their schema metafacts.** Recipe
  validation still rejects blob-backed descriptor facts, but automatic
  `entity!` attribute descriptions no longer make an otherwise inline,
  single-root recipe invalid.

- **Conservative TribleSet handle scans now read the value column.**
  `potential_handles` previously traversed the VAE index but interpreted the
  canonical leaf's leading entity-and-attribute bytes as a handle. It now
  extracts bytes 32..64, so referenced blobs survive retention passes.

- **Object-store reads now verify fetched bytes against their requested
  content address before decoding.** A mismatched object returns the expected
  and computed BLAKE3 digests through `GetBlobErr::HashMismatch` instead of
  accepting bytes solely because they occupy a hash-shaped path.

- **PATCH removal commits structure before reclaiming values or archive owners.**
  Heap leaves are retired until every ancestor has repaired its aggregates and
  collapsed unary branches; the final owner cover is detached only after an
  empty root is published. A panic in user `Drop` code therefore cannot leave
  the PATCH observing a half-applied removal or a dangling representative.

- **Borrowing PATCH iteration now reaches the maximum trie depth.** The
  stack-allocated iterator seeds its traversal from the root branch's child
  table instead of spending one of its `KEY_LEN` frames on a synthetic root.
  A path may therefore contain a branch at every key byte without overflowing;
  empty and singleton zero-length-key PATCHes also require no stack frame.

- **PATCH thread-safety now follows its associated values.** Persistent PATCH
  snapshots may share a leaf across threads, so both `Send` and `Sync` now
  require `V: Send + Sync`; compile-time coverage includes the important
  `Cell<u64>` case where `Send` alone is insufficient. Type-only key schemas
  remain independent of these bounds.

- **Safe PATCH entries cannot observe an uninitialized or racing hash key.**
  The internal leaf key and independent public-fingerprint key now live in one
  immutable `OnceLock` bundle. Heap entries, archive entries, bulk hashing,
  LocalLeaf fallback hashing, and public blinding all initialize through that
  accessor, so constructing an `Entry` before the first `PATCH` produces the
  same cached hash as every later construction.
- **Consuming one cloned PATCH snapshot no longer creates a mutable reference
  to a leaf shared by another snapshot.** The internal mutation view now keeps
  reference-counted leaves read-only while retaining copy-on-write mutable
  access to branches. This removes a safe-code aliasing violation in both
  consuming iterators.

- **Typed `UnionArchive` proposals no longer re-scan every attached shard for
  every emitted value.** Bounded shard paging and dense complete drains share
  the same already-located Succinct Ring walk. Sparse continuations keep their
  current shard and ordered cursor, while raw cross-shard duplicates remain
  visible to work telemetry until the engine's parent-local SET boundary. The
  normalized proposal-page capability retains its globally ordered,
  duplicate-free stream.

- **Exact compiled Formula proposals no longer confirm the whole Formula
  twice.** The residual planner derives the execution receipt recursively: OR
  takes the meet of its arm receipts, while AND takes the meet across every
  child that row-local planning may select as a covering source. A route proved
  Exact therefore enters its outer candidate continuation already checked;
  Covering routes retain the mandatory self-confirmation.

- **Source-less relational queries now fail at construction.** A surviving,
  non-full seed must expose a covering proposal source for at least one
  variable, so every residual width rejects filter-only roots at the same
  construction boundary. Seeds already proven false remain valid
  empty queries, and peer-dependent sources such as Equality remain eligible
  after another constraint binds their peer.

- **The residual delta handoff regression now constructs a reachable Formula
  state.** Its streaming proposal runs through a coverage-bearing linear AND
  suffix with the irrelevant sibling already skipped, rather than manually
  placing a streaming reducer beneath an OR barrier that the production
  planner cannot cross.
- **Search and core now share one Jerky crate identity.** The search crate is
  pinned to the same Jerky revision as core and GPU, restoring its succinct
  build and preventing `Serializable` methods from disappearing behind two
  revision-distinct copies of the same trait.
- **Attached range constraints now denote an index-domain intersection.**
  `TribleSet` value/entity/attribute ranges and `SuccinctArchive` value ranges
  reject in-range candidates that do not occur on the attached V/E/A axis in
  ordinary confirmation, typed Program confirmation, and bound-row support;
  proposals and confirmations therefore implement the same relation even when
  another constraint supplies the candidate.
- **The residual query branch builds as an ordinary workspace again.** The
  core crate now declares its `im` dependency directly instead of inheriting a
  workspace dependency table that does not exist, and the formula reducer's
  accumulated-length, continuation, and shared-input borrow paths once again
  type-check under the workspace toolchain. A test-only panic is also fully
  qualified so newer compilers do not report an ambiguous macro import.
- **Variable grouping no longer changes a row's semantic proposal action.**
  The residual engine retains each row's exact adaptive next variable instead
  of reassigning estimate-compatible groups. Since the selected proposer owns
  occurrence multiplicity, the old physical coalescing could make raw terminal
  rows depend on scheduler width despite the constraint protocol supplying no
  cross-variable bag-equivalence law. Equal ordering keys now use an explicit
  lower-variable-ID tie break instead of inheriting unstable-sort behavior.
  Within an intersection, equal child estimates likewise choose the lower
  child occurrence consistently across residual widths.

### Removed

- **Breaking: the unpublished query-engine families are gone.**
  `Query` now has one block-native production engine: the canonical residual
  state machine, with adaptive ordinary iteration and an explicit saturated
  residual/Rayon control. The `solve_blocked`, `solve_dag*`,
  `lazy_dag_scheduler`, and `into_par_dag_iter` APIs, their worklist types,
  gates, statistics, probes, and dedicated benchmarks were removed outright,
  together with the scalar DFS selector and runtime. Historical engine
  comparisons remain reproducible from frozen Git revisions rather than a
  compatibility matrix in the current tree.
- **Obsolete query-engine tuning fixtures are gone.** The source-identical
  cross-generation benchmark and the experimental backoff-policy matrix were
  deleted instead of being kept compiling against adapters that no longer
  exist. Current probes compare meaningful lowering, geometry, constraint, or
  backend choices within the single residual runtime.
- **The unpublished estimate-free constructed-Program planner is gone.**
  Residual queries now always keep the ordinary adaptive Ready/Candidate
  negotiation and select typed Program routes only after that semantic action
  is chosen. The probe-only admission function, rejection types, frozen-plan
  metadata, and planner introspection were removed rather than retained as a
  second query mode.
- **External database comparisons no longer burden benchmark builds.**
  Removed the Oxigraph and OxRDF development dependencies and comparison paths;
  the retained JSON roundtrip and insertion benchmarks now measure TribleSpace
  directly without pulling in RocksDB.

### Added

- **`pattern_changes!` documents its delivery boundary.** Its API docs now
  distinguish per-invocation projected SET semantics from legitimate
  recurrence of the same tuple through a witness introduced by a later delta,
  with guidance for caller-retained once-only state and witness projection.
- **Typed Program novelty activation scope has executable regression coverage.**
  Equal novelty keys now have tests proving first-receipt ownership across
  input tags of one activation while remaining independently admissible for
  distinct activations.
- **Constraints publish proposal-coverage receipts.**
  `proposal_coverage` distinguishes no source proof, a covering proposal, and
  exact proposal support. It defaults conservatively, forwards through
  transparent wrappers, and composes structurally through AND/OR; coherent
  finite, indexed, search, path, and resident-GPU constraints opt in. Repaired
  attached range constraints publish Exact coverage for their attached-axis
  domain intersections as well. Coverage, rather than estimates, selects a
  source; Covering proposals retain self-confirmation, while Exact proposals
  may discharge it. Approximate ANN publishes no exact source receipt.
- **Typed Program capabilities compose by immutable semantic route arm.**
  `PreferredProgram` chooses a preferred typed family only when that family
  structurally owns an action, otherwise choosing a canonical typed fallback
  before runtime construction. The private arm is part of the occurrence-local
  Program address, while each selected child keeps its own state and novelty
  arena unchanged. A physical backend decline therefore runs that same child's
  Native step and never crosses into the semantic fallback. Direct programs
  retain the original single-trait-object `ProgramRef` and unchanged runtime;
  composition adds no state enum, handle tag, or per-row dispatch.
- **Typed Program novelty commits from one fully validated batch plan.** The
  erased adapter now checks batch-local repetitions before consulting runtime
  novelty, records first admissions in receipt order, and mutates runtime state
  only after every page, tag, rank, budget, and raw-effect law succeeds. Existing
  and repeated keys no longer pay a second admission lookup, while endpoint
  stability, affine handle publication, and no-prefix failure remain exact.
- **Fresh positive typed RPQ cohorts use an exact-all-fit PATCH traversal.**
  When every activation starts at its initial cursor, every frontier branch is
  positive forward/inverse attribute traversal, and each exact fanout fits its
  per-input physical grant, the whole cohort consumes borrowed bounded infixes
  atomically; a resumed, negated, or oversized member preserves the existing
  pageable path for everyone. This recovers 2.4–2.5x on the measured mixed
  formula+RPQ cells without implying a general engine-wide speedup.
- **Typed RPQ complete actions now drain the compiled product automaton
  directly.** Bound-endpoint proposal cohorts use a parent-local
  `(value, program-counter)` novelty set and direct PATCH transition pages for
  finite and fixpoint paths, preserving nullable graph-term gating, inverse
  traversal, endpoint distinctness, and duplicate outer parents without
  opening a nested WCO frame. The conservative ordinary constraint evaluator
  remains unchanged.
- **Typed Program cohorts separate physical compatibility from activation
  identity.** Program buckets now own one pacing-sensitive selection law:
  Search pages retain LIFO order and may mix physically identical reducer
  policies, Activation streaming pages preserve append order across all
  compatible activations, quiescent pages cap distinct activations by the
  geometric activation width, and terminal pages keep each activation's
  sparse quantum aligned with its append-ordered task. Dispatch class, bound
  schema, candidate shape, and terminal feedback class remain exact cohort
  boundaries while affine activation identity stays row payload.
- **Residual RPQs now execute through one typed affine program runtime.**
  Occurrence-local program addresses erase each family once per dense cohort
  while generational handles retain exact typed continuations, family-owned
  novelty keys and finite ranks, and receipt-local `AfterChildren` joins.
  Every RPQ Propose, Confirm, and Support shape—including inverse products,
  same-variable duplicate bags, nullable graph-gated identities, and cyclic
  fixpoints—uses this single route. Generic
  Search/Activation pacing keeps physical grants independent of family
  telemetry; terminal cohorts allocate and advance sparse grants per affine
  activation, so aggregate or truncated cohorts cannot manufacture widening.
- **Demand-wide terminal RPQ admissions change execution regime without
  disturbing live sparse traversals.** When completed-yield evidence admits
  more than one new terminal parent in a turn, an action-specific Program route
  certificate lets that fresh suffix run through the family's exact complete
  proposal executor and publish full rows directly. The semantic certificate
  is pure in the request and bound schema; the scheduler independently supplies
  terminality, cohort width, and physical phase evidence. Per-parent receipts
  are reserved only after the family call succeeds and share the delta
  activation namespace without owning registry state or producer credit;
  publication staging and immediate completion preserve exact zero-yield and
  projected-yield accounting while existing activations remain sparse.
- **Activation-indexed terminal delta buckets preserve affine cohort order
  without rescanning mixed work.** Ordinary and formula transition buckets
  remain contiguous vectors; terminal cohort selection lazily promotes only
  the buckets that need append-order task slots, per-activation slot runs, and
  an ordered tail index. Geometric tombstone compaction preserves the original
  order of selected and retained work without a full scan per wide dispatch.
- **Completed terminal yield drives exact parent admission.** For each
  canonical proposer family, the scheduler estimates projected rows per
  completed parent and admits only the cumulative parent deficit needed to
  cover `produced + remaining-window` demand. Unseen, zero-yield, and known
  multi-family workloads keep a one-parent floor until global demand has an
  explicit cross-family partition; parent suffix slicing and eager seed-tag
  rebasing preserve exact order and multiplicity without cutoff constants.
- **Terminal demand learns only from completed projected-yield samples.** Each
  admitted terminal parent now retains its exact delta activation through
  direct-publication batching and projection. Per-proposer ledgers distinguish
  cumulative admissions from live activations, close a sample only after both
  affine quiescence and every staged projection attempt, and treat a caught
  projection unwind as consumed but rejected. Exact seed and completion
  receipts cover immediately quiescent activations; Rayon conservatively keeps
  an admitted learner in one shard until cross-shard origin transfer exists.
- **Terminal cyclic work shares physical cohorts without sharing feedback.**
  Compatible final-variable source activations now use one block call with a
  shared budget `B=S`. Transition activations use
  `B=min(S, sum activation_quantum)` and ragged per-task limits whose total for
  each activation cannot exceed its own sparse quantum. Publication resets and
  live misses update those quanta independently; source misses never widen
  them, and directed latency continuations remain exact-activation affine.
- **All proven terminal activations publish directly.** Terminal rows now
  bypass canonical Candidate/Ready/Emit states whether the activation is the
  depth-first lease or globally scheduled cold work. The scheduler still
  transfers exactly one affine parent per admission in this causal step.
- **Terminal source search and graph-traversal effort are scheduled separately.**
  Confirmed result windows may raise stable, nonterminal, and source-search
  `S`, while a terminal transition activation widens its local examined-work
  quantum only after a live no-publication dispatch and resets to one after
  publication. Sub-`S` terminal traversal misses no longer double-charge the
  outer geometric search width.
- **Confirmed projected demand floors residual search width.** Exhausting a
  projected-result window leaves search width unchanged until the caller pulls
  again; that later pull doubles the result window and raises search `S` to at
  least the confirmed demand. The floor is cap-bounded and counter-neutral when
  search is already ahead, while `growth(1)` continues to disable only
  negative-work growth. Raw emission alone remains outside the search-feedback
  signal, while exhausting a staged projection suffix without satisfying the
  public pull grows `S` as negative work without charging projected demand.
- **Proven direct-terminal delta lanes publish final rows without stable-state
  churn.** A selected singleton or retained affine lease may turn accepted
  proposal pages directly into the ordinary projection buffer only when its
  reducer and return payload already classify it as terminal. The path shares
  the candidate-commit row builder, preserves first-occurrence source order and
  independent cyclic credits, applies the same per-activation SET admission as
  the stable path, and bypasses Candidate planning plus terminal Ready pops.
  Cold cohorts and nonterminal leases remain unchanged; output does not widen
  search `S`, and projected demand `q` is still charged only after a successful
  public projection.
- **Finite RPQ helper joins enter private seeded residual frames.** Closure-free
  forward, existential, and same-variable fallback joins now import captured
  endpoint values as a canonical one-row seed instead of starting a nested
  `Query` with synthetic constant constraints. Each frame owns its local plan,
  interner, ranks, and worklist; typed distinct-projection and existence
  reducers execute it synchronously—distinct projection drains the frame while
  existence may short-circuit and drop its private remainder—keeping local
  residual states out of the caller's ordering domain.
- **Estimate-only wrappers preserve native residual execution.**
  `EstimateOverrideConstraint` remains a structural opaque leaf so its planner
  cardinality overrides cannot be bypassed, while forwarding bounded proposal
  sources, transition programs, and Boolean
  Support to its inner constraint. `DebugConstraint` remains deliberately
  opaque because native proposal execution would bypass its observation log.
- **Built-in constraints have executable residual-oracle parity coverage.**
  Constants, equality, inclusive ranges, sorted slices, hash-set and hash-map
  membership, finite unions, diagnostic wrappers, and repeated pattern
  variables preserve exact relational SET parity between the fixed production
  solver and independent ordinary or plain-Rust oracles.
- **SuccinctArchive preserves equality for repeated pattern variables.**
  Triple patterns that reuse one unbound variable across E/V, E/A, A/V, or
  all three positions now estimate, propose, and confirm through exact Ring
  membership filters instead of reaching an unreachable distinct-position
  dispatch. Their strict distinct Ring drivers now page under geometric demand;
  rejected equality candidates count as examined work and resume after the last
  examined value. Normalized `UnionArchive` sources deliberately keep these
  filtered shapes non-paged because their one-head merge requires rejection-free
  shard pages.
- **Succinct shard unions page one globally normalized source.**
  `UnionArchive`'s normalized proposal-page capability merges one ordered head
  per shard behind a single activation-local `After(value)` cursor, preserving
  cross-shard deduplication without materializing complete union arms. Generic
  `UnionConstraint` remains unchanged, and schemas not admitted by every shard
  remain non-paged.
- **Residual source pages dispatch as compatible affine cohorts.** Canonical
  delta identity remains structural while the scheduler physically partitions
  source activations by bound-row schema, candidate mode, and cursor family.
  One block-native hook receives a same-schema row batch with ragged per-parent
  limits and tagged outputs; its one-row default preserves existing constraints.
  Page limits share the current global geometric budget instead of multiplying
  it by cohort size.
- **Residual transition pages expose one block-native cohort seam.** Live
  product nodes under the same structural transition operator now pass their
  activation-private nodes, cursors, and ragged page limits through one tagged
  batch call. Mixed pageable and eager nodes retain exact fallback, while the
  sum of page limits remains the scheduler's single geometric width.
- **RPQ product-state transitions gain bounded affine pages.** Positive and
  inverse attribute branches now advance by a branch-qualified lexical cursor,
  so one high-degree automaton node consumes at most the residual scheduler's
  current geometric demand before its continuation is refiled. Cursor state is
  activation payload rather than canonical state identity; clones retain the
  exact remainder, duplicate outer parents remain distinct bags, and accepted
  endpoints keep their existing per-activation set semantics. Negated-property
  branches page distinct destinations in EVA/VEA order with the same cursor,
  then test the destination's attribute suffix for an exact non-excluded
  witness. Excluded-only destinations consume demand without producing a
  successor, so mixed positive/negated nodes obey one global width; pages with
  no novel effect feed the same geometric negative-width ramp as dead source
  pages.
- **Accepting transition seeds publish without probing adjacency.** A delta
  activation now returns its distinct accepting seed endpoints as an immediate
  scheduler-owned effect receipt while retaining independent traversal
  credits. Streaming proposals and fully-bound Boolean Support can therefore
  yield nullable epsilon results before any transition page; grouped confirms
  and non-linear formula proposals keep the same quiescent reducer barriers.
  Seed effects consume no transition demand, preserve affine parent bags and
  NODES(G) scope, and cannot replay during the first later expansion.
- **Positive path publications retain their live affine traversal.** A cyclic
  activation entered from a singleton stable continuation keeps its exact
  physical token across accepted endpoints. The stable tail still runs first,
  but a traversal that remains live resumes afterward instead of surrendering
  locality to cold global harvesting. The token never enters canonical state
  identity, result ordering, or bag ownership, and quiescence releases it
  without moving scheduler work.
- **Terminal cyclic publication uses confirmed demand rather than output
  production.** Search width and projected-result demand are now independent:
  raw `Emit` no longer widens search, and a `1, 2, 4, ...` result window grows
  only when the caller pulls after consuming it. Only postprocessor-accepted
  rows count. A final-variable `StreamProposal` is classified on activation
  payload, admitted one parent at a time, and dispatched from source and
  transition buckets through one exact activation. Its local examined-work
  quantum resets to remaining confirmed demand on publication and doubles
  toward the separate search width on sparse no-publication steps. Canonical
  `StateDesc` and `DeltaDesc` identity remain unchanged. This causal probe is
  bounded but not strongly fair across perpetually productive terminal
  activations, so it remains an experimental branch rather than an integration
  candidate until service-credit rotation is supplied.
- **Ordered proposal sources can page direct candidate occurrences.** The
  residual source cursor now distinguishes raw-value and native-ordinal
  frontiers while preserving proposal order and multiplicity. Sorted slices
  page their immutable native sequence by offset; standalone full-width and ID
  PATCH constraints page strict lexical keys; and TribleSet patterns page all
  twelve single-position E/A/V schemas plus bounded entity, attribute, and
  value ranges through PATCH cursors. SuccinctArchive patterns page the same
  twelve schemas by ordered-universe, distinct-pair, and fixed-pair wavelet
  cursors, while Succinct value ranges seek directly into their bounded V-axis
  domain. TribleSet patterns with one variable repeated across E/V, E/A, A/V,
  or all three positions now page a strict ordered driver under the same
  examined-candidate budget and apply the remaining equality as an exact
  secondary filter; SuccinctArchive and shard-union repeated shapes retain
  their eager fallback.
- **Formula Support gains composed affine parity receipts.** End-to-end RPQ
  tests now pin duplicate-parent affine handling through terminal SET
  projection, nested AND/OR arm-order
  invariance, monotone graph growth, live clone and Rayon worker parity, and
  the activation-reuse barrier during candidate confirmation.
- **Fully-bound constraints can expose transition-backed support seeds.** The
  hidden constraint protocol now exposes one structural expansion route for a
  block of fully-bound boolean checks.
  Regular paths reuse their forward Thompson program with the bound target as
  an activation-private acceptance anchor, including exact NODES(G) scope for
  nullable epsilon witnesses, without enumerating the graph-term universe.
  Lowered formula guards reduce those roots per affine parent: the first
  accepted endpoint publishes `true` exactly once, while only producer
  quiescence publishes `false`; witnesses never enter a candidate stream.
- **Residual shadow observation preserves native cyclic execution.** Direct
  and observed iterators now instantiate one statically dispatched mixed
  stable/delta pull and Rayon split loop, so source paging, fixpoint
  quiescence, geometric handoffs, continuations, statistics, and exact affine
  remainders cannot diverge behind the observer. Delta actions are observed
  once at their native seed boundary; later canonical expansion cohorts remain
  unattributed because they may combine activations from several action sites.
- **Cyclic RPQ actions now execute inside lowered finite formulas.** Direct
  path atoms under OR and OR-to-AND arms share the residual delta fixpoint for
  both proposal and activation-reuse confirmation while retaining an exact affine
  formula continuation per parent. Formula proposals remain private until
  quiescence, empty root sets resume as empty branch results, and structural
  delta buckets may merge expansion work across distinct formula return masks.
- **Cyclic same-variable RPQs gain bounded ordered source frontiers.**
  The residual scheduler now pages NODES/FIRST sources at its geometric demand
  width, suspends each cursor until every product-state lineage from the page
  retires, and widens on pages that file no stable effect. Source cursors and
  exact stable or formula returns remain activation payload rather than
  canonical state identity, so equivalent expansion work still merges across
  parents. Grouped confirmation ranges only over the distinct values in its
  immutable candidate sequence, then restores original order and multiplicity
  after the complete fixpoint quiesces.
- **PATCH gains ordered infix lower-bound and successor descent.**
  `first_infix_range` returns the first distinct infix in an inclusive range,
  and `next_infix_after` advances a strict bounded cursor without materializing
  matches or depending on cuckoo-table order. Both follow compressed trie paths
  directly and support heap and archive-backed leaves.
- **PATCH can retain one cardinality-bounded infix traversal.**
  `bounded_infixes` locates a prefix once and returns an opaque borrowed view
  only when the cached distinct-segment count fits the caller's limit. The view
  exposes its exact count for reservation and enumerates from that same trie
  head in ordinary `infixes` order; missing prefixes are successful empty
  views, while over-limit prefixes expose no partial traversal. RPQ transition
  cohorts use these retained views to prove every fresh positive branch fits
  the geometric page budget before emitting, eliminating the former count
  descent followed by a second enumeration descent.
- **WGPU Succinct confirmation can opt into exact residual-action executor
  samples.** `WgpuSuccinctArchive::observe_residual_actions()` returns a
  borrowing, non-`Deref` `ObservedWgpuSuccinctArchive` whose pattern route
  attaches only tagged whole-frontier rank streams to the current action.
  Empty streams and calls outside an observed action attach no sample; the
  direct wrapper remains free of correlation lookups and clocks. A private
  per-call route seam truthfully labels threshold CPU work and admitted WGPU
  round trips, records exact `rank-probes`, and brackets only backend work,
  leaving route selection, counters, and sample attachment outside the wall
  measurement.
- **Residual action shadow observation is opt-in, unwind-safe, and
  cancellation-sound.** A closed epoch proves both affine frontier exhaustion
  and ordinary completion of every begun action; live or aborted actions fail
  closed as invalidated, and normal closure is owned privately by the draining
  iterator or top-level Rayon drive. A whole-pull guard covers planning,
  action, and projection unwinds, while per-producer guards detect initial-full
  consumers, abandoned split sides, and short-circuit cancellation. Dispatch
  metadata is snapshot-linearized before a separate execution-only wall timer
  begins. `ActionOutcome::Aborted` records action unwinds, and a serially
  exhausted wrapper remains closed when later converted to Rayon.
- **Ordinary `Query` owns a canonical residual-state cursor.**
  The arbitrary-root residual machine keeps borrow-free raw state behind
  `Query::next`. Mid-iteration
  clones snapshot candidate remainders and staged raw rows without requiring
  `R: Clone`; a partially consumed residual query converts to Rayon as one
  exact unsplittable remainder leaf. Fresh ordinary Rayon conversion divides
  one adaptive affine residual frontier into at most one shard per worker. The
  explicit `into_par_residual_state_iter` path uses the same splitter at
  saturated width, paging SET-admitted candidates unless a selected typed
  route retains one parent activation for reuse.
- **Constraints gain a canonical residual-state solver.** Every root
  `Constraint` participates in the same runtime: roots that expose associative
  AND structure are recursively flattened, while an opaque root is represented
  by one empty-path leaf and retains its own path, constant, range, or custom
  semantics. The solver jointly chooses each row's next variable and proposing
  leaf occurrence, then interns both planning states and uniform
  `Propose`/`Confirm` protocol actions as exact control-state descriptors.
  Planning only estimates and partitions rows; a separately scheduled action
  invokes one flattened leaf over its assembled bucket. The interleaved
  history-independent rank gate lets variable-order, proposal, confirmation,
  and independently planned action histories reconverge before shared work
  runs, while row payloads retain multiplicity. The maximal nested AND region
  is flattened into deterministic preorder leaf occurrences; production
  lowering represents finite unions as formula continuations, while path
  wrappers and custom constraints remain opaque unless they explicitly expose
  more structure. Profiled iterator collection reports planning/action pops,
  interner and bucket merges, and leaf-call batch measurements.
- **Canonical residual states gain a demand-driven batch-fill iterator.**
  `solve_residual_state_lazy` starts with a narrow desired parent-atom width so
  descendants can yield before sibling rows are evaluated. Filing a nonempty
  successor—including a merge into an already-live bucket—keeps that width;
  an action that compacts to no successor or raw terminal output grows it
  geometrically. Successful first paths therefore retain their exact width-one
  trace, while negative prefixes ramp within a single pull even when no result
  is ever projected. The deepest live state able to fill the desired width
  wins; when none can, minimum-rank readiness drains the remaining feeder
  frontier. The saturation cap only bounds width growth. Candidate chunks may
  split admitted `(parent, value)` occurrences independently; a selected typed
  Program may retain one complete parent activation solely to reuse its
  traversal. Candidate fanout therefore remains distinct from a total-work
  estimate. Exact descriptors remain interned so early states can safely reopen
  when later histories reach them. Full drains preserve the distinct raw
  projected-row set; partial consumers may drop the remaining
  affine frontier after the first useful result. Ready planning retains each row's
  exact adaptive variable and proposing leaf, then cohorts only rows with the
  same action.
- **Succinct archives separate canonical raw data from ABI-qualified Rank9
  acceleration.** `SuccinctArchiveBlob` ends after the deterministic
  Ring/wavelet sections and EOF metadata, while
  `Rank9AcceleratedSuccinctArchiveBlob` is the collection-member Merkle root
  carrying native Rank9/select payloads. Its exact raw handle occupies the
  first aligned 32 bytes for generic reachability; exact version, ABI,
  relative-section, raw-source, rank/select, and source-handle validation
  prevents mismatched closures from attaching. Direct and accelerator-backed
  builders preserve canonical raw parity without an index-sized intermediate
  allocation. Fresh per-ABI encoding and mapping identities replace the
  unpublished former public name/id family with no compatibility aliases.
- **Succinct archives expose decoded fixed-attribute AVE iteration.**
  `SuccinctArchive::iter_attribute_value_entities` yields one raw
  `(value, entity)` tuple per matching fact in byte-lexicographic AVE order.
  The exact-size iterator is double-ended, enabling descending short-circuit
  consumers via `.rev()`. Because values and IDs are decoded before leaving
  each archive, callers can safely k-way merge independent LSM segments
  without comparing segment-local universe codes; joins and deduplication
  remain explicit caller responsibilities.

- **Resident succinct two-bound proposals have a real `pattern!` entry.**
  `WgpuSuccinctArchive::two_bound_route[_with]` wraps the canonical succinct
  constraint and exposes one typed Program for `(A,V) -> E`, `(E,V) -> A`, and
  `(E,A) -> V` proposals. One immutable rotation descriptor drives both Native
  paging and resident WGPU dispatch with exact ragged grants, absolute
  continuations, branded receipts, and raw occurrence-bag execution below the
  SET-admission boundary. Its typed capability is
  now left-biased over the canonical Succinct Program: qualifying two-bound
  proposals select the resident family, while insufficiently bound proposals,
  Confirm, and Support select the canonical family before runtime construction.
  Physical decline remains within the selected family. Placement is Off by
  default and `Force` is the all-target parity probe. The experimental `WarmM4`
  score remains calibrated only for `(E,A) -> V`; E/A targets decline Native
  until measured.
- **Resident value routes expose honest snapshot-local preparation.**
  `WgpuSuccinctArchive::prepare_value_route` synchronously runs one real
  nonempty `(E,A) -> V` parent with grant one through the exact production
  resident path, checks its receipt/readback against the canonical Native
  pager while the snapshot lease remains held, and only then commits
  `ValueRouteReadiness::Prepared`. A default-fail guard makes errors and
  panics publish `Failed`; empty snapshots remain `Cold`, and successful
  preparation is idempotent. Generic `auto` remains rejected because this
  snapshot-local proof is not a device-wide cooperative idleness gate.

### Fixed

- **Explicit parallel residual queries use the production compiler policy.**
  `Query::into_par_residual_state_iter` carries the same fixed production plan
  as serial and ordinary Rayon execution into its affine shards.
- **BM25 tokenization preserves non-ASCII symbols and emoji.**
  `hash_tokens` previously discarded every token without an alphanumeric
  character, making standalone emoji queries produce an empty term list.
  It now adds Unicode symbol graphemes alongside the existing word terms,
  keeping ZWJ sequences, flags, and modifier emoji atomic while continuing
  to discard punctuation. Existing word hashes are unchanged; persisted
  indexes must be rebuilt once to gain the new symbol postings.
- **`or!(pattern!(..), pattern!(..))` no longer panics — pattern constants
  are folded into the constraint instead of becoming hidden variables.**
  `UnionConstraint` requires every arm to declare the same variable set
  (a flat-result-schema requirement: every row binds the same variables
  exactly once). The macro layer used to allocate a fresh hidden variable
  plus a `ConstantConstraint` for every attribute constant, literal value,
  and constant entity id — so two separate `pattern!` invocations never
  declared equal sets and the book's own `or!` example deterministically
  tripped the assertion. Triple-pattern positions are now `Term`s (a
  variable to solve for, or a constant pinned at construction): constants
  enter the backends' existing bound-position dispatch as "born bound" and
  never appear in the variable set, so union arms compare only the query
  variables the caller wrote. `TriblePattern::pattern` accepts
  `impl Into<Term<_>>` per position (plain `Variable` arguments keep
  working unchanged); `TribleSetConstraint`, `SuccinctArchiveConstraint`,
  and `UnionArchive` store terms; `pattern!`/`pattern_changes!` emit
  constant terms with zero helper allocations (queries also get tighter
  initial estimates and shed the per-constant binding steps). A pattern
  whose positions are all constants now has an empty variable set and acts
  as a pure existence check: `Query::new` settles it with one exact
  `satisfied()` probe up front (the fully-bound exactness law with zero
  variables). The union's variable-set mismatch panic now names the
  offending sets instead of failing in a bare `assert!`.

### Changed

- **Bound-endpoint RPQ planning uses precompiled boundary statistics.**
  Single-hop and union-arm estimates retain their historical local index
  counts, including exact negated-attribute destinations. Composite arms use
  the monotone value/entity output-domain statistic of each possible final
  hop instead of opening a private WCO frame or recursively materializing a
  depth-bounded closure. Query execution and result semantics are unchanged;
  generated RPQ tests cover nested-closure and skewed-ordering adversaries.
- **Residual formula continuations use compact persistent arena records.**
  Canonical state descriptors now carry a four-byte query-local program-counter
  ID. Each arena record names its exact parent return edge and outer WCO resume
  by interned ID, so child selection, completion, resume, state hashing, and
  rank lookup no longer clone or walk a boxed return stack. Compiler-derived
  grades remain exact under adaptive child order, OR guard reconvergence,
  delta suspension, query cloning, and independent Rayon shard execution.
- **One-parent residual candidate payloads stay tagless.** Ordinary and lowered
  formula actions now receive the plain `Values` candidate sink whenever one
  affine parent is live, while reconverged multi-parent work promotes to the
  existing tagged COO representation. Splits, partitions, compaction, and
  delta handoffs normalize back to values at singleton boundaries without
  changing candidate order, multiplicity, OR deduplication, or canonical state
  identity.
- **Residual formula payloads retain only their required ordering.** Candidate
  actions and confirmation handoffs now trust the protocol's ascending-parent
  grouping instead of value-sorting every leaf result. OR accumulators still
  sort after combining sibling arms, so their completion boundary can
  deduplicate exactly without sorting the already-normalized output again.
- **Residual state interning stores each canonical descriptor once.** An
  insertion-ordered, AHash-backed index set now supplies both exact descriptor
  identity and deterministic `StateId` lookup without a mirrored map and
  vector.
- **Canonical residual child sets keep one bitset word inline.** State
  descriptor cloning and interning avoid heap allocation for the common
  at-most-64-leaf formula while wider formulas transparently spill, preserving
  exact identity, hashing, canonical remerging, and geometric scheduling.
- **Singleton continuation-selected cyclic seeds retain physical focus.** The
  residual scheduler follows the activation-local source/transition lineage it
  just seeded until its first stable effect or quiescence; canonical delta
  identity and affine work ownership remain unchanged.
- **RPQ transition programs quotient equivalent residual kernels.** After
  epsilon elimination, deterministic forward-bisimulation refinement merges
  program counters with the same accepting bit and ordered labeled future.
  Remapping retains the first occurrence of each distinct transition and drops
  only copies that would recreate an identical product node already rejected
  by activation novelty. Syntactic Thompson branches therefore no longer make
  repeated unions traverse the same graph state once per equivalent counter;
  regular-path set semantics and first-discovery order remain unchanged.
- **Typed transition activation reuse is a predicate of canonical bound
  state.** Per-variable bound prerequisites compiled into the residual plan
  select when an RPQ Program benefits from retaining one complete parent
  activation. Candidate pages remain independent while those prerequisites
  are absent. Repeated distinct-endpoint RPQs therefore page ordinary
  first-step confirmation while the opposite endpoint is free, then retain
  one complete admitted relation when that endpoint is bound and a real
  transition reducer can reuse it; repeated same-endpoint paths retain the
  activation unconditionally. This is a physical scheduling preference, not
  an ordered-bag admission law.
- **Finite residual formulas avoid materializing administrative row copies.**
  Uniform child selections now retain their complete affine batch, and mixed
  selections partition on compact child ordinals before constructing canonical
  continuation states. Quiescent formulas eagerly consume finite direct
  proposal sources instead of registering paged affine activations; a distinct
  structural capability keeps product-state root sources and heterogeneous
  formula/path frontiers on the bounded transition substrate. Exact arm-local
  bags and the normalization barrier remain unchanged.
- **Delta scheduling retains native successor ranges and unordered registries.**
  Transition cohorts now pass their contiguous tagged output slices directly
  into activation replacement, allocating per-task successor vectors only for
  constraints that use the legacy ordinary fallback. Internal interner, credit,
  activation, novelty, and acceptance maps use fast unordered storage wherever
  iteration order is semantically invisible, while cohort selection retains
  its canonical ordering. Complete positive-transition batches reserve their
  cached fanout before the bulk PATCH expansion kernel.
- **Each delta activation owns one authoritative live-credit ledger.**
  Activation-local `nonce -> kind` entries now prove traversal or generator
  authority, replay safety, and quiescence directly. The redundant global
  owner table and accumulated retired-nonce set are gone; retiring a producer
  removes its sole live entry, so bookkeeping memory follows the active
  frontier rather than every transition visited before fixpoint completion.
  Registry brands and globally monotone nonces still seal credits across
  registries, and deep clones rebuild exact affine handles from the live map.
- **Residual RPQ scheduling separates fixpoint depth from parent breadth.**
  Transition work that can publish endpoints immediately still batches across
  activations. Quiescent formula, support, and grouped-confirm reducers instead
  spend the ordinary geometric row budget within a bounded activation cohort;
  that cohort grows independently after visible or terminal progress. Exact
  transition-cohort handoffs remain hot as one appended stable tail, while
  storage-oriented source-page batches retain the one-row latency probe.
  Fully checked candidates that bind the final variable also keep their exact
  output tail hot, so terminal rows are not stranded behind the cyclic
  readiness barrier. Positive
  transition cohorts whose complete fanouts fit their page limits now use
  cached PATCH segment counts and the existing bulk expansion kernel, avoiding
  per-successor trie descent and per-row scratch allocation without changing
  resumable lexical pages.
- **Residual action dispatch now preserves an affine executor task.** Every
  residual execution shape carries the selected interner state, canonical
  descriptor, and owned row/candidate payload through one internal dispatch
  boundary. Concrete Propose and Confirm states expose a hardware-neutral
  action view with the exact state, leaf occurrence, variable, bound-row
  schema, parent count, candidate count, and scheduler action units; Ready and
  Candidate planning states expose no backend action. The ordinary path still
  performs no timing or quote lookup, and scheduling, multiplicity, and the
  public `Constraint` protocol are unchanged.
- **Piles use one authoritative PATCH replay path.** The unpublished alternate
  locator-sidecar API, overlays, and CLI were removed before release. Refresh
  retains the useful one-observed-length optimization: each pass decodes one
  bounded prefix, while persistent PATCH clones give readers immutable
  snapshots and cheap structural differences.
- **Plain Pile replay keeps one record offset per blob.** The in-memory blob
  locator shrinks from a 32-byte payload locator plus one eagerly allocated
  validation cell to an 8-byte record offset. Reads recover payload length,
  location, and timestamp from the canonical immutable record header, bounded
  by the reader's accepted pile prefix. Validation results live in a shared
  sparse offset-keyed cache populated only by reads and duplicate challenges;
  corrupt candidates cannot poison later replacements at different offsets.
  On the 93.36 GB working archive this reduced replay's peak process footprint
  from 1.123 GB to 674 MB (40%) while preserving first-valid duplicate choice,
  lazy payload hashing, pin LWW, and bounded append replay.
- **Large pile payload validation now uses BLAKE3's Rayon join strategy.**
  With the existing `parallel` feature enabled, lock-free `PileSnapshot` blob and
  metadata reads validate a contiguous payload of at least 1 MiB with
  `update_rayon` when the current Rayon pool has more than one worker. The
  parallel digest is computed outside the sparse validation-cache mutex before
  racing to publish the immutable result, avoiding cache/pool liveness cycles;
  concurrent first misses may duplicate hash work and then converge. Replay,
  duplicate repair, and deduplicating puts remain serial because they can run
  under file locks. Smaller inputs, single-worker
  pools, and no-default-feature builds also retain the serial digest path. All
  paths share one strategy-aware validation helper and preserve the existing
  cached-result and corruption behavior.
- **Read-only pile closes no longer issue a whole-file durability barrier.**
  `Pile` now tracks mutations made through each handle, and `close` calls
  `sync_all` only for a handle with unflushed appends or truncation. Replaying
  bytes appended by another handle remains read-only. Explicit `flush` stays a
  whole-file durability barrier, and blob, branch, weak-pin, and repair writes
  retain the existing durability contract.
- **The opt-in GPU companion now shares the project CubeCL 0.10 fork.**
  `triblespace-gpu` no longer pulls a second CubeCL 0.9/WGPU 26 stack beside
  the model and widget runtime. Its WGPU backend is ported to CubeCL 0.10,
  repository builds pin the fork with the immutable external-buffer seam, and
  the crate now declares Rust 1.92 to match CubeCL 0.10. The GPU-free core
  remains on Rust 1.89. Core's device-neutral `RingBatchQuery` seam now lets
  `triblespace-gpu::WgpuSuccinctArchive` keep all six Jerky wavelet matrices
  resident and execute whole-frontier confirmation ranks in WGPU while the
  canonical archive, planner, prefix navigation, proposals, estimates, and
  small query actions stay on CPU. An 8,192-rank default admission threshold,
  per-wrapper fallback/fragmentation counters, a CPU fake-backend gate, and a
  native Metal parity gate keep this hybrid explicit. The deterministic
  `residual_reconverge_bench` compares canonical CPU, wrapper CPU, forced WGPU,
  and thresholded hybrid rank execution under adaptive/saturated serial and
  Rayon residual drivers with exact sorted-output parity. Adapter
  construction/device enqueue is reported separately from the first
  synchronizing query rather than mislabeled as upload latency. Selecting the
  fork still only makes future mmap-to-Metal aliasing possible: both this
  resident query wrapper and the existing structural merge currently enqueue
  device copies, and structural merge reads canonical packed planes back.
- **Succinct-archive structural merge decodes source rows once.** The merger
  now materializes the remapped, deduplicated EAV union and derives the other
  five canonical Ring rotations with stable linear counting sorts. This
  replaces one counting decode plus five additional rank/select-heavy source
  wavelet traversals with bounded `O(rows + domain)` scratch while preserving
  byte-identical archive output and the accelerator freeze seam. With the
  `parallel` feature, merges of at least 4,096 input rows decode and remap two
  or more non-empty source segments concurrently, then perform the small
  deterministic k-way deduplication serially; single-segment and smaller
  merges retain the original cursor path.
- **The public `Constraint` protocol is now block-native.** Every verb receives
  a borrowed `RowsView` of sibling partial bindings; `EstimateSink` and
  `CandidateSink` provide compact plain-value representations for one-row
  actions and per-row/tagged representations for wider frontier execution.
  Custom constraints must obey four soundness
  laws: `propose` receives and owns an empty sink, `confirm` only filters, and
  `satisfied` is exact whenever all relevant variables are bound. The latter
  includes constant, zero-variable constraints and lets unions reject dead arms
  while negotiating variables owned by another arm. In addition, every
  row-taking verb is row-homomorphic: splitting a block and concatenating the
  row-remapped answers cannot change its semantics.
- **The ordinary `Query` iterator now runs every live seed through canonical
  residual states.** Opaque roots, one-leaf and disjoint conjunctions, finite
  unions, regular paths, and custom wrappers all exercise the same residual
  substrate; exact seed rejection starts no worklist. This is a full semantic
  coverage switch, not a claim that residual control overhead pays back for
  every shape. Production structural lowering is fixed rather than carried as
  per-query state.
  Demand-adaptive chunk width starts with depth-first, first-result-oriented
  execution and grows into readiness-gated batch harvesting. Residual planning
  cohorts explicit `(variable, proposer occurrence)` actions and never
  reassigns a row's choice, because that action owns candidate support and
  first-seen order.
  Ordinary fresh Rayon iteration partitions the adaptive affine residual
  frontier into at most one shard per worker. A partially
  consumed ordinary residual query still drains its exact remainder as one
  Rayon leaf. The constraint protocol states the row-homomorphism law that
  makes chunking and sharding semantics-neutral.
  Fully-bound rows stay raw until the consumer pulls them: the worklist never
  stores projected `R`s, preserving `Query` auto traits and allowing exact
  mid-iteration clones without `R: Clone`.
  Fully drained geometry and lowering variants preserve the same distinct raw
  projected-row set, but result order may differ. Probe solvers require a
  never-pulled `Query`; freshness is tracked explicitly so exhausted
  zero-variable queries cannot be mistaken for untouched ones.
- **`Pile::restore()` is now `Pile::amputate()` — the destructive
  truncation stops wearing a comforting name.** The operation TRUNCATES
  the pile file at the first invalid record, destroying everything after
  it; "restore" read like a safe recovery and invited routine use on
  open, which under version skew is exactly how stale binaries eat valid
  data. `Yard::restore` (which amputates every generation pile) is
  renamed to `Yard::amputate` for the same reason, and the CLI command
  moves from `trible pile restore` to `trible pile amputate` with help
  text that states the destruction plainly. No deprecation shims — the
  old names are gone. Additionally, the crate's telemetry sink was the
  last remaining restore-on-open holdout: it now opens its pile with the
  non-mutating `refresh()` and disables telemetry (with a warning) on a
  corrupt tail instead of truncating it.
- **V3 on-disk pile format: uniform 256-byte records.** Every new record —
  blob, branch (pin) head, branch tombstone, weak-pin marker, weak-unpin
  marker — is written with a FIXED 256-byte header and padded to a 256-byte
  multiple. Consequences: blob data starts at the constant
  `record_start + 256` (no offset-derived pre-pad), so records are
  position-independent — they survive relocation and `cat a.pile >> b.pile`
  remains a valid merge; a pure-V3 pile stays 256-aligned throughout under
  the atomic lock-free append, so every blob's data is zero-copy
  GPU-aliasable (CUDA/Metal `min_storage_buffer_offset_alignment`); and the
  blob header carries 192 reserved zero bytes that are NOT part of the
  content hash. The reader still accepts the original V1 records, so
  existing piles read byte-identical with no migration. **Version-skew
  warning:** a binary from before V3 treats the new markers as unknown
  records and reports `CorruptPile` at the first V3 record. With a
  *current* pre-V3 build that is merely fail-loud — but **deployed
  binaries from before the fail-loud change auto-ran the truncating
  repair on open, so a stale binary touching a V3 pile WILL truncate it
  at the first V3 record, destroying everything after it.** Writing V3
  records into a shared pile arms every stale binary that can reach the
  file; upgrade every reader/writer of a pile before letting V3 records
  into it, and never "repair" a `CorruptPile` report without first ruling
  out version skew.
- **One record decoder; the CLI no longer hand-rolls pile parsing.**
  `triblespace-core` now exports `repo::pile::PileRecords` — a record-level
  iterator over a pile file yielding `PileRecord { offset, len, content }`
  with `PileRecordContent::{Blob, Branch, BranchTombstone, WeakPin,
  WeakUnpin}` — backed by the same decoder the `Pile` replay path uses, so
  V1 (64-byte) and V3 (uniform 256-aligned) records are both understood. An
  unknown or truncated record surfaces as `ReadError::CorruptPile`, never a
  silent stop. The `trible` CLI's two independent V1-only parsers
  (`branch.rs::scan_pile_records` and `diagnose locate-hash`) — which
  silently truncated their view at the first V3 record and fed
  `branch consolidate` decisions from that truncated view — are rewritten on
  top of `PileRecords`, and the duplicated V1 magic constants and stride
  logic are deleted from the CLI. `diagnose locate-hash` additionally
  reports weak-pin marker matches and now exits non-zero when parsing stops
  on an unreadable record.
- **`UpdateBranchError` is now `PileWriteError`.** The error covers every
  non-blob pile append — pin-head CAS updates and weak-pin/unpin markers
  (both `WeakPinStore` impls alias it as `WeakPinError`) — so the
  branch-specific name was misleading. Its redundant
  `unsafe impl Send/Sync` are gone (the payload is `std::io::Error`, which
  already provides both).
- **`Yard` no longer auto-repairs generation piles (fail-loud, matching
  `Pile`).** `Yard::open` used to call `Pile::restore()` on every generation
  pile, silently truncating a corrupt tail on open; reclaim-recovery paths
  swallowed restore failures entirely. `Yard::open` now loads each generation
  with the non-mutating `Pile::refresh()` and fails loud with
  `YardOpenError::Pile { path, err }` naming the corrupt generation file;
  nothing is truncated. Repair is an explicit opt-in via the new
  `Yard::amputate(paths, config)` constructor (mirroring
  `Pile::refresh`/`Pile::amputate`). Rewrite (`reclaim`/`compact`) recovery
  reopens the generation without repair and propagates a double failure as
  the new `YardReclaimError::Reopen { path, primary, err }` instead of
  silently leaving the segment closed.
- **`trible pile reid`/`squash`/`migrate` no longer auto-truncate a corrupt
  pile on open (fail-loud, last `restore()`-on-open holdouts).** All three
  commands opened their pile with `Pile::restore()`, silently truncating a
  torn or corrupt tail as a side effect — on the *source* pile for the
  rewrite commands (`reid`, `squash`) and on the in-place-migrated pile for
  `migrate`. They now open with the non-mutating `Pile::refresh()` and fail
  loud with the standard repair pointer (`trible pile amputate <path>`),
  leaving the file byte-identical; `reid` and `squash` also never create the
  destination when the source refuses to open. `trible pile amputate` is now
  genuinely the only entry point that calls `Pile::amputate()`.
- **Want-record failures are errors, and wants are flushed durable.**
  `Peer::get_or_fetch_async` now returns
  `Result<Option<Bytes>, WantRecordError>` — a pin/flush failure while
  recording the demand-born weak pin is an `Err` and no fetch is attempted
  (never hand the caller bytes whose demand isn't on record); previously both
  Peer want-record paths warned and continued. The transparent async read
  surfaces the same failure as the new `PeerReaderGetError::WantRecord`
  variant. Both paths flush after `pin_weak`, and `Peer<S>`'s store bound
  gains `StorageFlush`. The want-on-record invariant now holds
  unconditionally: on record-failure the read errors instead of proceeding.
- **`Peer<S>` single-store collapse.** `Peer<Durable, Cache>` is now
  `Peer<S: BlobStore + BlobStorePut + PinStore + WeakPinStore + Send + 'static>`
  — the separate cache tier is gone, and any tiering (bounded retention,
  generational eviction) lives in the store `S` itself (e.g. a `Yard`).
  Read-miss swarm fetches land in `S` under a **weak pin**, following the
  retention lattice `pin ⊐ weak-pin ⊐ weak-unpin ⊐ unpin`: the demand-born
  want is recorded *before* the fetch (a failed fetch leaves it as an
  outstanding want — a sync daemon's work queue), then it is the retention
  marker for the fetched blob, then the eviction target. There is no
  "promote to durable" operation — durability is reachability from strong
  pins. `triblespace-net`'s `cache` module (`NullCache`, `BoundedBlobStore`)
  is removed along with `Peer::with_wiring_and_cache`/`cache_len`/
  `land_in_cache`. `WeakPinStore` is now also implemented for `MemoryRepo`
  (in-memory `HashSet`, LWW = insert/remove; weak pins there are exactly as
  ephemeral as the blobs — the trait is a capability, durability is the
  store's own property).
- **Faculties no longer auto-truncate a corrupt pile on open (data-loss fix).**
  **WARNING:** every faculty and tool at or before the prior version opened piles
  with `Pile::open` + `Pile::restore()`, and `restore()` silently truncates the
  file to the last valid record on a torn or corrupt tail. Under version skew this
  is a silent data-loss hazard: a stale binary that hits a newer-format record
  reads it as corruption and eats all data past that point. Faculties now open with
  `Pile::open` + `Pile::refresh()` (a non-mutating full load) and **fail loud** with
  a non-zero exit on any corruption, printing the byte offset and a repair
  instruction instead of quietly repairing. Repair is now explicit and lives in one
  place: `trible pile amputate <path>`, the only entry point that still calls
  `Pile::amputate()`.

### Added

- **Async blob-store trait family.** New
  `triblespace_core::repo::async_store` module: `AsyncBlobStoreGet` /
  `AsyncBlobStorePut` / `AsyncBlobStoreList` / `AsyncBlobStore` /
  `AsyncPinStore` / `AsyncBlobStoreMeta` / `AsyncBlobStoreForget` — the
  async counterparts of the sync storage traits, with `SyncAsAsync<S>`
  lifting any sync store into them. Executor-agnostic (no tokio in core).
  Implemented by the `object_store` backend (`ObjectStoreReader`),
  `Lazy<S>`/`LazyReader` (the waiting read), and `triblespace-net`'s
  `PeerReader` (the transparent local-then-swarm async get).
- **Exact Demand fetch proven over the real iroh transport** (the v0.47.0
  release gate). `tests/iroh_two_pile_sync.rs` runs two `Peer<Pile>`s over
  real iroh endpoints on the `iroh::test_utils` `TestNetwork` packet layer;
  everything above it—DHT node, protocol router, CONNECT and SYNC_TEAM
  authorization, team-derived gossip, and host loop—is the production stack
  via `transport::iroh::bind_with_endpoint`. A never-committed blob held only
  by A is exact-fetched and content-verified when B's `Reconciler` services a
  durable WANT over its configured route. Host wiring remains public so the
  real adapter can be composed with the controlled packet transport.

- **`Lazy<S>` — the no-network-by-construction lazy reader.**
  New `triblespace_core::repo::lazy` module (exported from the prelude):
  wraps a store Peer-style (`Arc<Mutex<S>>`) but answers a read miss with a
  **durable want** instead of a swarm fetch — `pin_weak` + `flush` (the
  marker must survive an immediate process exit; a faculty exits right after
  its read). Two read surfaces, split by which trait you call (mirroring
  `PeerReader`): the **sync probe** (`BlobStoreGet`) returns
  `Err(WantGetError::NotYet)` on a miss — "the want is durably recorded; a
  sync daemon (`Peer` + `Reconciler`) services it" — and never waits; the
  **async waiting read** (`AsyncBlobStoreGet` on `LazyReader`, plus
  `AsyncBlobStore`/`AsyncBlobStorePut` on `Lazy`) records the same
  durable want and then *suspends* until the blob lands, resolving instead
  of erroring (`WantWaitError` has no not-yet variant; compose deadlines
  externally, e.g. `tokio::time::timeout` — the want stays recorded on
  timeout or drop). Absence is always "not obtained yet", never
  definitely-absent. A failed want-record is an error
  (`WantGetError::WantRecord` / `WantWaitError::WantRecord`), never a
  silent proceed, and store refresh errors propagate immediately
  (`WantWaitError::Store` — fail loud, never auto-amputate). Waking is an
  implementation detail: in-process `put`s signal waiters directly; a
  lazily-spawned, self-retiring cadence thread re-checks (with a store
  refresh) for landings by other handles/processes — pure `std`, no tokio
  in core, executor-agnostic futures. The type lives in `triblespace-core`,
  which has no network dependency, so "never networks" is enforced by the
  linker.
  `Repository`/`Workspace` compose with it unchanged: a checkout over a
  partially-absent closure fails `NotYet` while enqueueing durable wants for
  exactly the missing blobs.
- **`StorageFlush` trait.** The generic durability hook (mirrors
  `StorageClose`): `flush(&mut self)` makes pending writes/markers
  crash-durable. Implemented by `Pile` (delegates to the inherent
  `Pile::flush`), `MemoryRepo` (no-op, `Infallible`), and `Yard` (flushes
  every open generation pile). Required by `Lazy<S>` and now by
  `Peer<S>` — recording a want without flushing it was a durability hole.
- **End-to-end fetch deadline.** The on-demand blob fetch
  (`Peer::fetch_blob`, `get_or_fetch_async`, the transparent `PeerReader`
  async get) previously had per-stage deadlines only (3s DHT lookup, 10s
  dial + 30s op per provider) and could stack them to 40s+ of caller hang
  across a provider list. The whole resolution is now bounded: interactive
  reads get a 10s overall budget (`host::INTERACTIVE_FETCH_DEADLINE`),
  `Peer::fetch_blob_with_deadline` exposes the knob, and the background
  want-reconciler keeps a generous 30s default
  (`reconcile::RECONCILE_FETCH_DEADLINE`, tunable via
  `Reconciler::with_fetch_budget`). Expiry is plain Unavailable — a recorded
  want stays recorded, so an expired budget defers the fetch, never loses
  the demand.
- **Route-first shortcut for read-miss fetches.** On-demand fetches try
  configured bootstrap routes and synchronized PEER routing candidates before
  falling back to DHT provider lookup. Gossip neighbors are never routes, and
  every candidate must pass both CONNECT and SYNC_TEAM authorization.

- **Durable weak pins.** Two new V3 pile record kinds — weak-pin and
  weak-unpin markers (fixed 256-byte headers, keyed by blob handle, no branch
  id) — make the soft half of the retention lattice
  `pin ⊐ weak-pin ⊐ weak-unpin ⊐ unpin` durable, resolved last-writer-wins by
  log position (the branch record is `pin`, the branch tombstone `unpin`). A
  weak pin is the demand-born want-signal ("I want this blob; fetch if
  absent; evictable"), the cache-retention marker, and the eviction target in
  one record. New `WeakPinStore` trait (`pin_weak` / `unpin_weak` /
  `weak_pins`) implemented by `Pile` (appends markers, rebuilds the
  LWW-resolved set on scan) and `Yard` (persists markers to the young
  generation's pile; `Yard::open` now reloads the weak state from the durable
  markers instead of resetting it — fixing the restart amnesia of the
  previously in-memory-only weak state — and `reclaim`/`compact` re-record
  surviving markers when they rewrite the young pile). `Yard` also gains a
  `PinStore` impl (in-memory CAS over its strong pins), required by the
  `WeakPinStore: PinStore` bound. Note the loud-failure posture: binaries
  from before this change treat the new markers as unknown records — they
  fail loud on such piles (and never truncate, per the explicit-amputate
  posture above).
- **Demand content sync — the want-reconcile loop.** `trible pile net sync`
  services durable blob WANTs whenever its direction permits pulling. Each
  pass reobserves externally appended requests, compares them with resident
  blobs, and exact-fetches missing content through authorized routes and then
  DHT candidates. A want nobody serves stays pending—normal, never an error or
  proof of absence—and retries with exponential backoff from 1s to a 60s cap.
  Write-only mode suppresses all fetches; read-only and bidirectional modes
  service WANTs intrinsically, with no separate enable/disable flag. Sync
  reports seen, fulfilled, and pending counts, and `--quiescent-for` counts a
  serviced want as activity while a persistently pending want does not prevent
  local quiescence. The library mechanism remains
  `triblespace_net::reconcile::Reconciler::tick`.
- **`trible pile amputate <path>`.** Explicit, opt-in, DESTRUCTIVE repair for a
  pile with a partial or corrupt (torn) tail: loads every valid record and, if the
  tail is torn, truncates the file back to the last known-good offset — destroying
  everything after it — reporting bytes before/after (or "already valid"). This
  replaces the implicit auto-repair that faculties used to perform on open.
- **`repo::yard` generational blob storage.** Adds a standalone Yard storage
  component that layers young-to-old Pile generations, union reads, per-blob
  strong/weak retention, weak-veto reachability pruning, and size-triggered
  strong tenuring without changing existing Peer or Pile APIs.
- **Physical reclamation for `repo::yard`.** Adds explicit `Yard::reclaim()`
  rewriting each generation's Pile to a sibling temporary Pile containing only
  the current live set, then atomically renaming it over the original so
  logically evicted blobs release disk space.
- **Deterministic `repo::yard` property tests.** Adds seeded operation-sequence
  tests covering strong/weak retention, collect/compact/reclaim consistency,
  hole-safe walks, live-set exactness after collection, and deterministic replay.
- Add a PATCH branch fanout diagnostic histogram for inspecting real trie
  shapes in benchmark probes.
- Add a PATCH traversal-depth diagnostic for read-side benchmark probes.

### Removed

- **`ignore!` and `IgnoreConstraint`.** The wrapper dropped variable slots
  from a sub-constraint's outward set, but each occurrence of an ignored
  variable acted as an independent wildcard — no join across occurrences —
  which read like existential quantification and repeatedly confused users.
  Its sound uses are covered by pattern-local `_?var` helpers (equality
  without projection, scoped to one `pattern!`) and by `temp!` when a hidden
  helper must join across clauses. No replacement shim; the surface is gone.
- **`BlobStorePut::put_aligned`.** Vestigial since V3: every record is a
  uniform 256-byte multiple with data at a fixed header offset, so every
  `put` is already GPU-aliasably aligned; the method had collapsed into an
  alias of `put`.
### Fixed

- **`trible pile diagnose check` no longer doubles the blake3 prefix.** The
  per-branch `meta` line printed `meta blake3:blake3:<hex>` because it prepended
  `blake3:` to a string `from_inline()` already returns in `blake3:<hex>` form.
  Cosmetic only.

## [0.46.4] - 2026-06-10

### Fixed

- **`providers_for` is publisher-first.** The peer that announced a
  head holds its entire closure (bottom-up insertion invariant), so
  when a publisher is known it is returned immediately as the sole
  provider. Previously every closure-walk step awaited an unbounded
  DHT lookup first — on meshes with no DHT reachability (local pairs,
  offline LAN, firewalled venue wifi) that await pended forever,
  freezing sync while the known-good provider sat unused. The DHT
  path remains for the no-publisher case, now bounded by a 3s timeout.
  Found during a live two-daemon repro; validated by the deterministic
  sim suite (fault scripts incl. partitions/crashes/heals).

### Added

- **triblespace-net deterministic simulation, stage 4**:
  `tests/sim_swarm.rs` — N-node seeded fault scripts
  (commits/partitions/crashes/heals → quiescence) with convergence,
  full-closure-via-checkout, and bit-identical-replay-per-seed
  invariants, plus a seed sweep. Quiescence-driven stepping in SimNet
  (replaces poll-rationing that starved the task queue under load).
- **ntriples import**: provenance split (`rdf_uri` out of graph
  facts), pure `Fragment` output with `commit_with_metadata` taking
  fragments, and predicate describe-entities recorded in meta for
  full self-description.

- **SimConn close/drop fail-fast contract** pinned with tests:
  dropping the remote handler's end wakes pending ops with a reset
  error, matching iroh semantics (sim fidelity for evict/retry paths).

### Notes

- Known hardening follow-up tracked for a future release: idle
  deadlines at the Transport seam with OnceCell reset on dial failure.

## [0.46.3] - 2026-06-10

### Fixed

- **`team approve` and remaining `team` subcommands route through
  `with_pile`**, so `close()` runs on every exit path. Previously an
  early-return (error or otherwise) could skip the pile close,
  leaving the flush to the OS and the lock held until process exit —
  exactly the wrong failure mode for the founder side of a live
  join handshake.
- **`path!` no longer silently fuses adjacent bare-ident atoms** in
  a regex body; the macro now rejects the ambiguous form instead of
  parsing `a b` as `ab`.

### Added

- **triblespace-net DST stages 1-3**: Transport seam extracted,
  virtualizable time + seedable ids, deterministic simulation
  transport with first sim tests. Groundwork for deterministic
  simulation testing of the sync stack; no behaviour change in
  production paths.

### Docs

- Dedup embeddings paragraph; spell out UFOID/FUCID acronyms;
  clarify attribute-id hex-literal guidance.

## [0.46.2] - 2026-06-07

### Fixed

- **`team approve` no longer hangs when the subject is offline.**
  Previously dispatched OP_DELIVER_CAP via `block_on(one_shot_deliver_cap)`
  before marking the request `STATUS_APPROVED`, which had no timeout
  and would block forever if the subject couldn't be reached (the
  whole-point case for async approve). The CLI now does only local
  pile writes — persist cap+sig blobs, record the renewal-policy
  entry, mark the request approved, close — and relies on the
  running sync daemon's `redispatch_undelivered` loop to push the
  cap on its next tick. That loop has to exist anyway (subjects are
  commonly offline at approve time), so the in-CLI dispatcher was
  redundant; it also spun up a fresh iroh endpoint with the
  *same* signing key as the daemon's long-lived endpoint, producing
  the `"Another endpoint connected with the same endpoint id"`
  warns we kept seeing on the N0 relay.
- **`record_policy_entry` deduplicates by `(subject, scope)`.** If
  an active (non-retracted) entry already exists for the same
  subject+scope pair, the helper returns its id rather than
  minting a phantom-twin entry. Handles the
  killed-approve-then-retry case (the killed CLI's writes are
  durable; the retry would otherwise create a duplicate entry the
  renewal daemon would dispatch in parallel with the original).
  Genuine re-issuance with a fresh cap+sig still goes through
  `update_policy_entry` (in-place rewrite).

### Removed

- **`triblespace_net::handshake::one_shot_deliver_cap`** — was used
  only by `team approve`, which now delegates dispatch to the
  running daemon. `one_shot_endpoint` and `one_shot_request_cap`
  stay (still legitimately used by `team request-join`, where the
  requester has no daemon yet by definition).

## [0.46.1] - 2026-06-07

### Fixed

- **`CapDeliveryConfirmed` lookup matched against the wrong handle.**
  OP_AUTH wires the signature blob (since that's the credential the
  dialer needs to prove possession of), so the
  `cap_handle_raw` carried by the host's `CapDeliveryConfirmed`
  event is the **sig** handle — but
  `find_policy_entry_by_subject_and_cap` was comparing it against
  `PolicyEntry::latest_cap` (the cap-blob handle). The lookup always
  returned `None`, the entry never got marked delivered, and the
  renewal daemon kept redispatching `OP_DELIVER_CAP` forever instead
  of stopping after the first successful auth. Renamed the helper
  to `find_policy_entry_by_subject_and_sig` and the `NetEvent`
  field to `sig_handle`, comparing against `latest_sig` — which
  matches the wire reality and removes the conceptual confusion
  that produced the bug. (Discovered during 24/7 relay deployment.)

### Changed

- **`trible team list-issued` now shows `delivered_at`** so
  operators can see whether the subject has authenticated back with
  the dispatched cap (and the renewal daemon will stop
  redispatching) or whether the entry is still in the
  re-dispatch set.

## [0.46.0] - 2026-06-05

### Added

- **`triblespace_core::repo::PinSnapshot`** — type alias for
  `PATCH<16, IdentitySchema, Inline<Handle<SimpleArchive>>>`, the
  natural representation of a frozen "what's pinned right now" view.
- **`PinStore::pin_snapshot()`** — cheap point-in-time snapshot of
  the (pin id → head) map. Default impl walks `pins()` + `head()`;
  Pile overrides with `self.branches.clone()` (O(refcount bump)).
  Replaces the per-refresh Vec rebuild that previously lived in
  `triblespace-net`'s `StoreSnapshot::from_store`.

### Changed

- **`triblespace-net`: snapshot-first publish ordering.** Every
  `announce` / `gossip` site in `peer.rs` now runs *after*
  `update_snapshot`. Closes a race where a peer dialing in fast
  after a gossip would hit the still-stale serving snapshot,
  `has_blob` returned false, and `OP_CHILDREN` / `OP_GET_BLOB`
  denied the request as "out of scope" even though we'd just told
  them we have the closure. Four sites fixed: `refresh`,
  `republish_branches`, `BlobStorePut::put`, `PinStore::update`.
- **`triblespace-net`: `StoreSnapshot.branches` is now a
  `PinSnapshot`.** Drops the per-refresh `Vec<(RawPinId, RawHash)>`
  rebuild in favor of the cheap PATCH clone on the Pile fast path.
  `AnySnapshot::branches()` returns `&PinSnapshot` (was
  `list_branches() -> &[(RawPinId, RawHash)]`).
- **`triblespace-net`: OP_DELIVER_CAP verifies inline + swarm-fetches
  missing chain blobs** using the just-received signature handle as
  bootstrap credential. Receiver runs a dialer-equals-issuer
  precheck on the incoming cap so a malicious peer can't make us
  swarm-fetch garbage chains. Sender side: renewal daemon retries
  undelivered caps with a 15s per-entry cooldown; delivery is
  considered confirmed when the subject authenticates against
  pile-sync with the new cap (`NetEvent::CapDeliveryConfirmed`),
  not on the wire `STATUS_OK` ack.
- **`triblespace-net::host`: trace-level instrumentation** at the
  fetch-reachable hot path (pool seed, children_one, providers_for,
  fetch_one) for diagnosing sync stalls in the field.

## [0.45.0] - 2026-06-03

### Added

- **PATCH `LocalLeaf` archive-leaf elimination.** New body kind for
  PATCH heads that points directly into archive memory instead of
  allocating a heap `Leaf<KEY_LEN, V>` per trible. Three node types
  total — `Branch`, `Leaf`, `LocalLeaf` — with one local invariant:
  a `LocalLeaf` may only appear as a direct child of a `Branch`
  whose `owner: Option<Arc<dyn ArchiveOwner>>` is `Some(_)`. The
  Branch's owner Arc keeps the underlying archive bytes alive for
  the lifetime of the tree; reification to a heap `Leaf<KEY_LEN, ()>`
  happens only at owner-mismatch boundaries. Reduces resident memory
  from ~204 B/trible to ~109 B/trible (~47% saved) and drops
  per-trible allocation count by ~83% for `SimpleArchive` ingest.
- **`ArchiveEntry<'a, KEY_LEN>` + `PATCH::insert_archive` +
  `TribleSet::insert_archive`.** Ingest path that constructs a
  `LocalLeaf` head from a `(NonNull<[u8; KEY_LEN]>, &Arc<dyn
  ArchiveOwner>)` pair and threads the owner reference (not clone)
  through `insert_leaf_with_owner` so per-trible insert pays zero
  atomic ref-count traffic on the shared archive Arc. Clones happen
  only at genuine `Branch.owner` adoption sites (~1 per ~30 tribles
  given the trie's branching factor).
- **Pre-computed siphash24 in `ArchiveEntry`.** `ArchiveEntry::new`
  computes the LocalLeaf's hash once and threads it through both
  `Head::insert_leaf_with_owner` (via the new
  `BranchMut::modify_child_with_inserted_hint(key, hash, f)`
  variant) and `Branch::new_with_owner_and_rchild_hash` so the
  6-way index fan-out per trible runs one siphash instead of six.
  This was the dominant per-trible cost before the optimization:
  heap `Leaf` caches its hash in the struct; `LocalLeaf` has no
  storage, so every `Head::hash()` was recomputing siphash24 over
  64 bytes. Brings serial archive ingest from 1.59× slower than
  the heap path to parity; at 4-8 threads archive is now 19-37%
  *faster* than heap thanks to no per-trible malloc bandwidth
  contention.
- **`SimpleArchive` `try_from_blob` LocalLeaf ingest path.** Detects
  16-byte alignment of the packed-trible buffer and, when satisfied,
  wraps the blob's `Bytes` as an `Arc<dyn ArchiveOwner>` and feeds
  `ArchiveEntry`s into the new path. Misaligned buffers (rare) fall
  back to the heap-`Leaf` path. The parallel-reduce path
  (`rayon::reduce` over per-chunk `serial_unarchive`) is re-enabled
  for archive ingest now that `union` correctly handles same-owner
  Branches and the per-trible Arc clones are eliminated.

### Changed

- **`Branch.childleaf` representation:** `*const Leaf<KEY_LEN, V>`
  → `*const [u8; KEY_LEN]`. For heap `Leaf`s the pointer is to the
  inline `key` field (offset 0 thanks to `#[repr(C, align(16))]`);
  for `LocalLeaf`s it's the archive-resident bytes directly. All
  `childleaf().key` / `childleaf().has_prefix` call sites delegate
  to `leaf::key_ops` free functions against `childleaf_key()`. The
  `V` type parameter on `Branch` becomes phantom-only (still
  threaded through the child-table `Head<KEY_LEN, O, V>` slots).
- **`Branch::get` value access** for ZST `V`: returns a
  dangling-pointer reference (the only flavor compatible with
  LocalLeaf-backed childleaves). Non-ZST `V` recovers the
  `Leaf<KEY_LEN, V>` by casting `childleaf` back since `key` is at
  offset 0.
- **`trible team revoke` removed.** The descriptive-caps model
  evicts via per-issuer non-renewal (`team retract` +
  renewal-policy entries), not by team-root-signed revocation
  blobs. The `revoke` subcommand had been a bail-out stub for
  several releases; this release drops the `Command::Revoke`
  variant, the `run_revoke` stub, the env-var
  `TRIBLE_TEAM_ROOT_SECRET`, and sweeps stale revocation
  references from the book's capability-auth chapter, the
  `triblespace-net::host` module's doc comments, the
  `triblespace-core::repo::capability::verify_chain` docstring,
  the `PERM_ADMIN` description, and the `AUTH_REJECTED`
  rejection-cause list.

### Fixed

- **Latent UAF in archive-backed PATCH union.** A regression test
  for unioning two `SimpleArchive`-decoded TribleSets with
  overlapping keys + different owner Arcs caught the structural
  invariant violation at Branch::new(owner=None) with a LocalLeaf
  direct child. Currently functionally fine because the parent's
  owner Arc transitively keeps the bytes alive, but the regression
  test pins the behavior and the union path is hardened to keep it
  that way for the parallel reduce.

## [0.44.0] - 2026-05-31

### Added

- **`triblespace-net` descriptive-capabilities substrate.** Caps are past-tense
  `K_A authorised K_B for scope S during interval [t0, t1]` statements with
  chain proofs carried in sig blobs (parallel cap fetch + multi-path
  resilience). Verification asks "is this statement covering wall-clock now?";
  eviction = non-renewal. New `/triblespace/auth-handshake/1` ALPN with
  `OP_REQUEST_CAP` / `OP_DELIVER_CAP`, plus a renewal daemon in `pile net sync`
  that signs successors and dispatches them. Schema for local-only pins
  (renewal policy, pending requests, team cap).
- **`trible` CLI: `pile pin list/inspect/delete`** as generic primitive ops
  on the pin namespace. `pile branch list` now filters to pins carrying
  `metadata::name` (the named content-branch view) while `pile pin list`
  exposes all roles (BRANCH / TRACKING / POLICY / UNNAMED).
- **`trible team` subcommands**: `approve`, `request-join`, `list-pending`,
  `list-issued`, `retract` — drive the cap-issuance workflow end-to-end via
  the one-shot iroh CLI helpers in `triblespace_net::handshake`.
- **`PathOp::NotAttr(RawId)`** for SPARQL's negated property-set
  operator `!p`. Combined with closures (`(!p)+` / `(!p)*`),
  expresses "reachable via any edge that isn't `p`". New
  `PathExpr::NotAttr` / `InverseNotAttr` variants route through
  the existing per-mid `eval_from` fallback via `eval_not_attr` /
  `eval_not_attr_inverse` helpers (two-step EAV/VAE infixes scans
  that enumerate attributes, filter the excluded one, then
  enumerate values per surviving attribute). Three new proptests
  cover the exclusion semantics, the positive case via a different
  attribute, and the closure interaction.
- **Same-Variable handling in `TribleSetConstraint`.** All
  duplicate-position cases — including the full triple-share
  `pattern(x, x, x)` — are arms in the existing match dispatch
  in each of `estimate` / `propose` / `confirm`:
  `pattern(x, a, x)` (e==v), `pattern(x, x, v)` (e==a),
  `pattern(e, x, x)` (a==v), the three free-position variants,
  and `pattern(x, x, x)` (e==a==v). Each arm enumerates from
  the most selective covering index and checks
  `EAV.has_prefix` on a fully constructed trible key — the
  position-equality IS the prefix match. No HashSet, no
  parallel code path, no allocation per candidate. All six
  legal same-Variable shapes are now native; the engine no
  longer rejects any well-formed `pattern(...)` call.
- **Same-Variable handling in `RegularPathConstraint`.** When
  `start == end`, propose enumerates `all_nodes()` filtered by
  `has_path(id, id)` — only nodes with a self-loop via the path
  appear. Confirm retains via the same predicate; estimate
  returns a conservative `set.len()` upper bound.
- **Symmetric end-bound proposal in `RegularPathConstraint`.**
  Case B (start free, end bound) previously enumerated
  `all_nodes()` and ran a per-candidate `has_path(c, end_id)`
  — O(n × graph). It now BFS-walks the cached
  `inverse_expr` from `end_id` via `eval_from`, mirroring
  Case A (start bound, end free). O(graph), one traversal,
  dedup built in. The HashSet that used to do `all_nodes ∪
  {end_id}` set-union for the reflexive-path rule is gone:
  `eval_from`'s Star/Optional arms already include the start
  node by construction. `estimate` for the same case
  similarly upgrades from a `set.len()` conservative bound
  to `estimate_from(inverse_expr, end_id)` for a tight
  estimate. Two new direct tests (`end_bound_propose_start_*`)
  cover the case the existing tests didn't.
- **`path!` macro infix syntax for `?`, `!`, and `^` operators.**
  Three formerly hand-built PathOp shapes now have macro support:
  `?` (Optional, postfix unary at Star/Plus precedence), `!p`
  (single-attribute negated property set, lex-time prefix
  collapse into a NotSym variant), and `^` (Inverse prefix, with
  a `resolve_inverse` pre-pass that moves each `^` past its
  PathElt — PathPrimary + optional postfix — to match SPARQL
  1.1 §17.5 precedence so `^p+` parses as `^(p+)`). Five new
  tests in `tests/regular_path_constraint.rs`. Multi-attribute
  negated property sets `!{p1, p2, ...}` still pending —
  requires `PathOp::NotAttrSet` first; the lexer errors out
  cleanly when it sees `!(...)`.

### Fixed

- **Duplicate proposal in `RegularPathConstraint::propose` for
  reflexive paths.** When end was bound and start free, `end_id`
  was pushed into the candidate list unconditionally even when
  `all_nodes()` already covered it (true whenever end appears as a
  value somewhere). The duplicate survived the filter and inflated
  row counts by one for `?` and `*` paths. Now dedups via HashSet
  before filtering.

### Changed

- **`BranchStore` trait renamed to `PinStore`.** Branch is now the
  specialization of pin that carries a commit chain and a `metadata::name`;
  unnamed / non-commit-chain pins (tracking pins, local-only policy pins)
  share the storage primitive. Downstream code should rename imports.
- **`Repository::new` signature** widened to `F: Into<crate::trible::Fragment>`
  (was `commit_metadata: TribleSet`). Existing TribleSet callers continue to
  work via `impl Into<Fragment> for TribleSet`; the new signature lets callers
  pass schema metadata + auxiliary blobs (handle-referenced doc strings,
  etc.) in a single self-contained Fragment. Repository absorbs the
  Fragment's blobs into storage.
- **`NetEvent` / `NetCommand` / `IncomingOp` payloads** switched from
  `Vec<u8>` to `anybytes::Bytes` for cap and blob payloads. Arc-refcounted
  zero-copy along the cap delivery path.
- **`TribleSetConstraint`'s catch-all `panic!()`** now carries a
  message pointing at the workaround (distinct Variables +
  EqualityConstraint) and the docs entry — still fires only for
  edge cases that the same-Variable branches don't cover, since
  this release added branches for all three duplicate-position
  cases.

All five engine additions/fixes plus the macro extensions
were surfaced and validated via the wd_bench cookbook recipes
(paths/114, paths/307, paths/355, single_bgps/213, and the
five new path! macro tests). See `wd_bench/docs/GAPS.md` for
the full narrative — items 2, 5, 8, and 9 are now closed.

## [0.43.1] - 2026-05-18

### Added
- **mDNS local-network discovery** (`address-lookup-mdns` feature on
  iroh). Peers on the same LAN find each other without any internet
  roundtrip — useful for home WiFi, conference rooms, sneakernet, or
  any environment where pkarr/DNS isn't reliably reachable. Subject
  to the network permitting client-to-client multicast (some hostile
  APs filter mDNS).
- **pkarr-over-BitTorrent-DHT discovery** (`address-lookup-pkarr-dht`
  feature on iroh). Adds a third discovery path that doesn't depend
  on n0.computer's DNS server being reachable. Default `relay_only`
  filter — no direct-IP leakage to the public DHT.

Both layer onto the existing `presets::N0` pkarr+DNS path. All three
providers run in parallel; lookup results union. If any one path is
reachable, peers can find each other.

Pulls in `mainline` (BitTorrent DHT) and `swarm-discovery` (mDNS) as
transitive deps via the iroh feature flags.

## [0.43.0] - 2026-05-18

Two correctness fixes for the sync protocol's chain-integrity story,
plus a CLI surface simplification that drops the EndpointTicket form.

### Fixed
- **`fetch_reachable` Phase 2 aborts on first fetch failure.** The
  old skip-and-continue path violated the bottom-up "stored blob ⇒
  closure stored" invariant: if a deeper blob couldn't be fetched
  but Phase 2 kept going on its siblings and parents, the parents
  got written without their full closure. `fetch_reachable`'s own
  Phase 1 `have_local` short-circuit then trusted that invariant
  on every subsequent sync, so the gap became permanent — `pile
  diagnose check` would report a chain break that no amount of
  re-gossiping could heal. The fix: any single fetch failure aborts
  the whole walk and returns `Err`, so the tracking branch isn't
  advanced and the next gossip rebroadcast retries from a clean
  state. Anything written before the failure is deeper in BFS
  order and therefore complete; Phase 1 short-circuits on those
  next time and only the still-missing ancestors get re-walked.
- **`Workspace::merge_commit` propagates ancestry walk errors
  instead of silently falling through to a divergent-merge commit.**
  The old code's `.ok().unwrap_or(false)` pattern treated "couldn't
  walk the chain because a blob is missing" as "not an ancestor,"
  then wrote a brand-new merge commit recording the missing handle
  as a parent. Pile is append-only, so the dangling reference stays
  forever, and the chain-integrity break hides itself from future
  syncs (Phase 1 short-circuits on the merge commit, never re-fetches
  the missing parent). New `MergeError::AncestryWalkFailed(String)`
  variant lets callers retry once the closure is repaired.

### Removed
- **`--peers` only accepts bare hex pubkeys.** The `EndpointTicket`
  form is gone; iroh's standard discovery (pkarr + DNS via
  `presets::N0`) handles all address lookup. The id-only ticket
  form was equivalent to a bare pubkey anyway, and the address-
  bundled form encoded ephemeral relay/direct addrs that were a
  source of bugs (the trailing-dot relay leak in 0.41.4 was one).
- **`pile net identity` drops the `ticket:` output line** — prints
  only `node: <pubkey>`. Use the pubkey hex with `--peers`.
- **`triblespace_net::dot_stripped_endpoint_addr` public fn removed.**
  It existed to normalise ticket-encoded relay URLs at the channel
  boundary; with tickets gone, the only remaining dot-strip site is
  the outbound RelayMap construction inside `host_loop`, which
  doesn't need a public helper.
- **`triblespace_net::address_lookup::StaticAddressLookup` removed,
  module deleted.** Seeded iroh's address lookup from ticket-encoded
  addresses; no longer needed.
- **`iroh-tickets` dependency dropped** from `triblespace-net` and
  `trible`.

## [0.42.5] - 2026-05-18

### Fixed
- **`Peer::new` startup-sweep race.** The sweep iterated blobs from
  one `store.reader()` snapshot and captured the diff baseline from
  a second `store.reader()` call. An external append (e.g. `trible
  team invite` writing a cap blob to the pile file) landing between
  the two reads slipped into the baseline without ever being
  announced — the blob then was locally present but invisible to
  `find_providers` DHT lookups. Symptom: cap-chain swarm-fetch
  fallback failing because the cap-holder appeared to be the only
  provider in the DHT (the actual minter never announced).

  Fix: start with `last_blob_reader = None`. The first refresh
  announces every blob in `current` directly (no diff), then
  captures baseline. Single `reader()` call, no race. `Peer::new`
  drives one synchronous refresh before returning so the DHT
  learns about pre-existing blobs before the first incoming AUTH
  can land.

## [0.42.4] - 2026-05-18

Stale-update gate replaced by storage-layer idempotency.

### Changed
- **`Pile::update` short-circuits no-op writes.** When the
  requested head equals the current head, `Pile::update`
  returns `PushResult::Success` without appending a record.
  The branch table is logically an `(id → head)` map; a write
  where `new == current` carries no information and would
  just churn the append-only file. Steady-state gossip
  rebroadcasts of unchanged heads (tracking-branch
  re-publication at 30s ticks) hit this path heavily.

### Removed
- **Wall-clock stale-update gate in
  `triblespace_net::tracking::update_tracking_branch`.** The
  gate compared `metadata::updated_at` of the incoming
  gossip to the tracking branch's stamp and rejected
  not-strictly-newer updates. With the storage-layer
  idempotency above, identical heads collapse to a no-op
  inside `Pile::update`; semantically different out-of-order
  heads are reconciled downstream by `Workspace::merge_commit`'s
  ancestry check (no-op if remote is already in local's
  ancestry, fast-forward if local is in remote's ancestry,
  merge commit otherwise). The wall-clock comparison was
  redundant.

## [0.41.4] - 2026-05-17

The two follow-ons surfaced by the first successful sandbox sync.

### Fixed
- **Trailing-dot leak through `ep.addr()`.** 0.41.3 stripped
  dots from the *outbound* RelayMap, so our local relay
  connect path was clean. But iroh's `Endpoint::addr()` can
  still return an `EndpointAddr` whose `TransportAddr::Relay`
  carries the dotted form (the relay server reports its
  canonical URL back to the client and iroh stores that for
  its own-address reporting). When we serialise that
  EndpointAddr into a ticket via `pile net sync` startup,
  the dotted URL propagates to whoever consumes the ticket;
  their iroh then dials us via the dotted URL and trips
  WAFs on their egress.

  Adds `triblespace_net::dot_stripped_endpoint_addr(addr)` —
  a normaliser applied at every channel boundary that emits
  or consumes an `EndpointAddr`. Used in
  `triblespace-net`'s ticket print + in `trible`'s
  `parse_peers` and `pile net pull <REMOTE>` parsing, so
  outbound tickets are dot-free and inbound tickets get
  normalised even when minted by an unpatched peer.

- **Connection-per-RPC stall in `fetch_reachable`.**
  Previously the BFS over a remote pile opened a fresh
  `connect_authed` for every `op_children` parent and every
  `op_get_blob` child. Each auth handshake costs roughly
  600ms (TLS + QUIC + OP_AUTH round trip + `verify_chain`),
  so even a small remote pile of ~30 blobs would exhaust
  the `pull_branch` 30-second deadline before the walk
  completed.

  `fetch_reachable` now opens **one** authed connection at
  the top of the function and reuses it for every
  `op_children` and `op_get_blob` call along the BFS.
  iroh's QUIC multiplexes streams cheaply, and our
  `SnapshotHandler::accept` already accepts multiple
  sequential bi-streams per connection — auth state is
  per-connection, set on the first OP_AUTH stream, and
  reused on every subsequent stream.

  The previous DHT-fallback path that lived in the
  per-blob `fetch_blob` helper is dropped from this hot
  path; DHT reachability hasn't been load-bearing for any
  current use case and adding a per-blob connect to a
  different peer would defeat the reuse. The standalone
  `fetch_blob` helper is still used by the single-blob
  `NetCommand::Fetch` RPC path.

  Net effect: a remote-pull walk that took 39+ connections
  on 0.41.3 now takes 1. The previously-observed "connect
  → auth_ok → LocallyClosed → reconnect" cycle disappears.

### Notes
- Diagnosed by the same other-Claude instance — the
  diagnostic surface from the tracing instrumentation
  continues to pay off.
- File-upstream candidate: iroh's `RelayUrl::parse` could
  normalise trailing dots, which would let us drop both
  workarounds. The full-completeness fix is in iroh.

## [0.41.3] - 2026-05-17

The trailing-dot fix. The reason iroh's HTTPS probes to the
default relays were getting 503'd from the Anthropic web
sandbox — and likely from any other corporate environment
fronted by a strict WAF.

### Fixed
- **iroh default relay hostnames had a trailing FQDN dot** —
  `iroh-0.98.2/src/defaults.rs` ships e.g.
  `"use1-1.relay.n0.iroh-canary.iroh.link."` (note the
  trailing dot, the DNS absolute-form marker). When iroh
  builds an HTTPS probe URL from those, the dot propagates
  into reqwest's `Host` header. WAFs that treat trailing-dot
  Host as a known bypass-attempt signature reject those
  requests with synthetic 503s, leaving iroh's `net_report`
  cycle permanently stuck and — in iroh's current connect
  design — preventing direct-dial attempts that would
  otherwise honor a ticket's pre-known addresses.

  triblespace-net now transforms iroh's prod default relay
  map at endpoint-build time, stripping the trailing dot from
  each relay's hostname before iroh constructs the `RelayUrl`s.
  Same upstream relay (DNS doesn't care about
  absolute/relative-form distinction); HTTP-canonical Host
  header on the wire.

  Diagnosed by another Claude instance in the web sandbox via
  an exhaustive narrowing experiment that ruled out User-Agent
  (`reqwest/0.12.x` works), TLS fingerprint (vanilla rustls
  +reqwest+native-roots works), burst rate (20× concurrent
  curls all 200), HTTP version, and headers — then nailed it
  with a side-by-side comparison: identical rustls-reqwest
  probes succeeded 20/20 in the same second iroh's own
  probes got 12/12 503'd. The smoking gun was the URL form
  iroh logged: `https://...iroh.link./` (dot before slash).

  Fix transforms `iroh::defaults::prod::default_relay_map()`
  rather than hardcoding hostnames, so we stay in sync with
  whatever n0 ships. Filed upstream-fix candidate: have iroh
  normalize trailing dots in `RelayUrl::parse` or its
  hostname constants. Until that lands, this is the
  triblespace-side workaround.

## [0.41.2] - 2026-05-17

The address-symmetry release. Closes the
"tickets-work-for-pull-but-not-sync" asymmetry from 0.41.1
by seeding iroh's address lookup with bootstrap-peer
addresses, so the gossip mesh / DHT bootstrap path can dial
ticket peers directly — no pkarr/DNS roundtrip.

### Added
- **`triblespace-net::address_lookup::StaticAddressLookup`**:
  an `iroh::address_lookup::AddressLookup` implementation
  seeded with a fixed `EndpointId → EndpointAddr` map at
  construction. Hooked into the endpoint via
  `Builder::address_lookup(static_lookup)`; layered alongside
  the `presets::N0` pkarr+DNS lookups (lookup services are
  additive on the iroh builder). For known peers, returns
  the cached `EndpointAddr` immediately; for unknown peers,
  yields an empty stream so the other registered lookup
  services get their turn.

### Changed (breaking — public API)
- **`triblespace_net::peer::PeerConfig.peers`** is now
  `Vec<EndpointAddr>` (was `Vec<EndpointId>`).
  Source-compatible for `EndpointId` callers via the
  standard `EndpointId: Into<EndpointAddr>` impl
  (`peers: vec![id.into()]`).

  Callers passing an `EndpointTicket` through
  `pile net sync --peers <STR>` now get a real address
  benefit on the gossip + DHT bootstrap path:
  iroh-gossip's `JoinOptions::bootstrap` still takes
  `Vec<EndpointId>`, but iroh's connect goes through
  `AddressLookup` to resolve the id, and our static
  provider answers immediately with the ticket's addresses.

### Fixed
- **`pile net sync` direct-dial in sandbox / restricted-
  network environments.** Previously the gossip mesh
  bootstrap path needed iroh discovery to resolve peer
  addresses; in environments where pkarr publish or DNS
  are blocked (Anthropic web sandbox, corporate proxies,
  etc.) gossip silently couldn't connect even when
  `--peers <EndpointTicket>` carried the addresses. With
  the static lookup seeded from `PeerConfig.peers`, gossip
  bootstrap now succeeds.

## [0.41.1] - 2026-05-17

The `EndpointTicket`-everywhere release. Makes sandbox /
corporate-proxy environments actually able to dial peers
without going through iroh discovery — the missing piece
behind the v0.41.0 / faculties v0.14.4 round of testing.

### Changed (breaking — public API of `triblespace-net::peer`)

- **`Peer::track`, `Peer::pull_branch`, `Peer::list_remote_branches`,
  `Peer::fetch`, `Peer::head_of_remote`, and the free function
  `resolve_branch_name`** now take `impl Into<EndpointAddr>`
  instead of bare `EndpointId`.

  Source-compatible for existing callers passing `EndpointId`
  (the `Into<EndpointAddr>` impl is automatic). Lets new
  callers pass a full `EndpointAddr` — carrying the relay URL
  and direct socket addresses — through to iroh's
  `Endpoint::connect`, which honours those addresses and
  skips discovery entirely.

  Why this matters: discovery is broken in many real
  environments. claude.ai's web sandbox is a Firecracker
  microVM behind a TLS-intercepting egress with a shared IP
  rate-limited by iroh-canary; corporate networks block pkarr
  publish; some restricted CI environments block UDP entirely.
  In all these cases, `Endpoint::connect(EndpointAddr, ALPN)`
  with the addresses pre-filled in the `EndpointAddr`
  succeeds where the discovery-resolved path fails silently.

- **`NetCommand::Track`, `NetCommand::ListBranches`,
  `NetCommand::HeadOfRemote`, `NetCommand::Fetch`** carry
  `EndpointAddr` instead of `EndpointId` on the wire from
  `NetSender` to `host_loop`. Internal but listed here for
  anyone implementing the channel directly.

- **`fetch_blob`, `fetch_reachable`, `track_known_head`,
  `connect_authed`** (private helpers in `host.rs`) take
  `EndpointAddr` so address info flows through to the QUIC
  layer. Callers with only an `EndpointId` use
  `EndpointAddr::from(id)` (no addresses → discovery fallback,
  same behaviour as before).

### Added

- **`pile net sync` prints an `EndpointTicket`** to stderr
  once the iroh endpoint is online — the rich form encoding
  `node_id + relay URL + direct addrs`. This is what to copy
  into a peer's `--peers` flag for direct dial in
  discovery-hostile environments. Printed via `eprintln`
  (not just tracing) so it shows at default log levels.

- **`pile net identity` prints an `EndpointTicket`** alongside
  the bare pubkey. Without a running endpoint this carries
  only the id (no addresses); use the richer ticket from
  `pile net sync` startup for direct-dial scenarios.

- **`pile net pull <REMOTE>` accepts an `EndpointTicket`** as
  the `<REMOTE>` argument in addition to the legacy bare-
  pubkey form. Backward-compatible.

- **`pile net sync --peers <STR>` accepts `EndpointTicket`s**
  in addition to bare hex pubkeys. Mixed lists are fine.
  Tickets are decoded to `EndpointAddr`; for the gossip
  bootstrap path the id is extracted (the address info is
  not yet used to seed iroh's address cache for gossip, but
  the address info IS used end-to-end for the
  `pile net pull` path).

### Notes

- The `pile net sync` gossip bootstrap doesn't yet seed iroh's
  address cache from ticket addresses, so sandbox-side `sync`
  with bare tickets still needs discovery for the gossip mesh
  to populate. The `pile net pull` path is fully address-
  threaded and works without discovery. Address-cache seeding
  for sync's gossip bootstrap is a follow-up (would require an
  `AddressLookup` provider plugged into iroh's
  `address_lookup` builder, or an `ep.connect()` seed pass
  at startup).

- `iroh-tickets 0.5` added as a dependency of both
  `triblespace-net` (for the rich-ticket print) and `trible`
  (for parsing). Pairs cleanly with iroh-base 0.98.

## [0.41.0] - 2026-05-16

The iroh-0.98 release. Replaces the 0.40.3 Cargo.lock workaround
for the upstream ed25519-dalek mess with a proper resolution.

### Changed
- **`triblespace-net` upgraded to the iroh 0.98 family.**
  - `iroh` 0.97 → 0.98 (still with `platform-verifier`)
  - `iroh-base` 0.97 → 0.98
  - `iroh-gossip` 0.97 → 0.98
  - `iroh-blobs` 0.99 → 0.100
  - `irpc` 0.13 → 0.14, `irpc-iroh` 0.13 → 0.14 (lock-step
    iroh-family bump)

  Upstream had pinned `ed25519-dalek = "=3.0.0-pre.1"` in
  `iroh-base 0.97`, which stopped compiling against
  `ed25519 v3.0.0` (released 2026-05-03) because
  `pkcs8::Error::KeyMalformed` changed from a unit variant to
  a tuple variant. `iroh-base 0.98` re-pins to
  `=3.0.0-pre.6`, which is API-compatible with current
  `ed25519`. Fresh `cargo install trible --locked` now
  resolves cleanly without needing the lockfile-shipping
  workaround that 0.40.3 used as a stopgap.

  No surface API changes in `triblespace-net` itself —
  iroh's `Endpoint::builder`, `presets::N0`,
  `CaRootsConfig::system()`, and the `ProtocolHandler`
  trait all kept their shape across 0.97 → 0.98. All 17 lib
  tests + 2 + 3 integration + 1 doctest pass.

- **Lock-step 0.40.x → 0.41.0 across all 8 workspace
  crates.** No source changes to `triblespace-core`,
  `triblespace-search`, `triblespace-macros{,-common}`,
  `triblespace-core-macros`, or the `triblespace` facade;
  versions bump to keep workspace alignment.

### Notes
- `trible 0.40.2` is yanked. `trible 0.40.3` (the Cargo.lock
  fix from earlier today) is left in place; it works but is
  obsoleted by 0.41.0. Downstream users on caret-permissive
  pins (`trible = "0.40"` will fall through to 0.40.3;
  `trible = "0.41"` picks up the proper fix).

## [0.40.2] - 2026-05-16

The TLS-roots-from-OS-store release. Patches one specific
failure mode in corporate-proxy / sandbox environments where
egress does TLS interception with a non-Mozilla CA.

### Fixed

- **`triblespace-net` now reads TLS trust anchors from the OS
  trust store** (via `rustls-platform-verifier`) instead of
  the compiled-in Mozilla `webpki-roots` bundle. The
  `platform-verifier` feature on iroh is enabled and the
  endpoint builder calls `.ca_roots_config(CaRootsConfig::system())`.

  Without this fix, sandbox environments that present a custom
  CA at TLS egress (e.g. Anthropic's web-sandbox's
  "sandbox-egress-production TLS Inspection CA") silently
  break iroh's discovery layer: every relay HTTPS probe and
  every pkarr publish/lookup to `dns.iroh.link` returns
  `invalid peer certificate: UnknownIssuer`, hole-punching
  never starts, and the QUIC peer handshake has no chance.

  Normal environments are unaffected — the OS trust store
  contains the same Mozilla roots that `webpki-roots` ships,
  so iroh's HTTPS to public infrastructure still works on
  macOS (Security framework), Linux (`/etc/ssl/certs`), and
  Windows (certificate store).

  Diagnosed by another Claude instance running in the web
  sandbox after the 0.40.0 tracing-instrumentation pass
  surfaced the `UnknownIssuer` WARN lines from iroh's
  internal logging. See `triblespace-net/CHANGELOG.md`.

- **`triblespace-core`, `triblespace-search`,
  `triblespace-macros{,-common}`, `triblespace-core-macros`**:
  lock-step 0.40.1 → 0.40.2 patch bump, no source changes.

## [0.40.1] - 2026-05-16

### Changed

- **`parallel` is now a default feature.** The workspace `triblespace` crate
  and `triblespace-core` enable it out of the box, so consumers get rayon
  transparently — no `--features parallel` needed to pick up the parallel
  query iterators and the `TribleSet::union` fan-out. WASM / embedded
  callers can still opt out via `--no-default-features`.

### Added

- **`TribleSet::union` 6-way rayon fan-out** (when `parallel` is on, which
  is now the default). The six trible indexes (`eav`/`eva`/`aev`/`ave`/
  `vea`/`vae`) touch disjoint memory during a union, so the per-index
  unions parallelise via nested `rayon::join` once `other.len()` clears
  `PARALLEL_UNION_THRESHOLD` (4096 tribles). Wins on the parallel
  `entities` bench family:

  | bench                       | 0.40.0   | 0.40.1   | delta   |
  |-----------------------------|----------|----------|---------|
  | union_parallel/5M           |  2.44 s  |  1.79 s  | -26.5%  |
  | union_parallel_chunked/2    |  224 ms  |  113 ms  | -49.5%  |
  | union_parallel_chunked/10   |  583 ms  |  247 ms  | -57.7%  |
  | union_parallel_chunked/100  |  1.75 s  |  794 ms  | -54.6%  |
  | union_parallel_chunked/1000 |  3.03 s  |  1.35 s  | -55.4%  |

  Serial fold (`union/5M`) sees ~5% feature-dispatch overhead because the
  per-`+=` `other` is too small to clear the threshold; small unions stay
  on the serial path.

## [0.40.0] - 2026-05-16

### Attribute id cache (perf)

`Attribute::id()` now reads from a cached `Id` field on `Attribute<S>`
instead of walking the wrapped Fragment's exports PATCH on every
call. The `From<Fragment>` impl captures the root id once at
construction. `entity!{}` codegen calls `.id()` once per attribute
per fact, so the pre-cache cost dominated the entities/union
benches:

| bench                     | size | pre-0.40 | 0.40   | delta vs pre |
|---------------------------|------|----------|--------|--------------|
| `entities`                | 5    | 2.88 µs  | 2.36 µs | recovered    |
| `union/5M`                |      | 9.00 s   | 7.94 s  | recovered    |
| `union_parallel/5M`       |      | 8.38 s   | 2.44 s  | recovered    |
| `union_prealloc/5M`       |      | 6.15 s   | 5.55 s  | recovered    |

(post-0.40 vs pre-conversion-arc baseline; full regression details
in commit `666e4764`.)

### Fragment annotation API simplification

- **`Fragment::annotated` and `Fragment::try_annotated` removed.**
  Saved 2-3 lines per call site at the cost of a closure
  indirection that obscured what was happening. The replacement
  pattern is `parent += entity!{ &id @ ... }` — when the
  annotation shares the parent's root (the common case),
  `Fragment += Fragment` re-unions the same id idempotently and
  folds facts + auto-put blobs through.
- **Schema describe collapse.** Every built-in `MetaDescribe::describe()`
  impl now reduces to a single `entity!{ ExclusiveId::force_ref(&id) @
  metadata::name: "...", metadata::description: "...", metadata::tag: ... }`
  expression. Auto-put through `entity!{}`'s blob-source machinery
  handles the string blobs; no more `Fragment::rooted + put + put +
  tribles += entity!{...}` dance. Net deletion of ~600 lines across
  the schema crate.
- **`Spread for Fragment` is allocation-free.** Replaced the
  `Vec<Id>` collect with `iter_ordered().map(raw_to_id)` using a
  free function pointer (so `Map`'s type is nameable in
  `Spread::Iter`). One fewer allocation per
  `Fragment::spread()` invocation.

### Conversion-system rewrite

A multi-step refactor of the value/blob conversion machinery
landed across 2026-05-14 → 2026-05-16. The user-facing surface is
now consistent under a single `Inline`/`Encoded`/`Encoding`/
`Encodes` vocabulary. On-disk format is unchanged — every
constant and metadata-attribute identifier that moved kept its
hex id.

#### Storage form: `Value<S>` → `Inline<S>`

The 32-byte stored payload is now `Inline<S>`. The name `Value`
is gone; `Encoded<V>` (below) is the higher-level sum that takes
its place.

- `Value<S>` (the 32-byte struct) → `Inline<S>`
- `RawValue` → `RawInline`
- `VALUE_LEN` → `INLINE_LEN`
- `UnknownValue` → `UnknownInline`
- `ValueRange` → `InlineRange`
- Method renames: `to_value` → `to_inline`, `from_value` →
  `from_inline`, `value_from` → `inline_from`,
  `try_to_value` → `try_to_inline`, `try_from_value` →
  `try_from_inline`.

#### Sum: `(Inline, Option<Blob>)` → `Encoded<V>`

The macro pipeline previously returned an `(Inline<V>,
Option<Blob<UnknownBlob>>)` tuple whose `Option` was `Some` iff
`V` was a `Handle` schema — an implicit invariant. Replaced with
a sum:

```rust
pub enum Encoded<V: InlineEncoding> {
    Inline(Inline<V>),
    Blob(Blob<UnknownBlob>),
}
```

`Encoded::inline()` rederives the typed handle from the blob's
cached Blake3 (phantom recast, no rehash). `into_parts()` yields
the old tuple for the macro consumer in one call. Initially named
`Value<V>`, renamed to `Encoded<V>` for vocabulary coherence.

#### Conversion: From-direction with blanket-derived ergonomics

Conversion is implemented schema-side (mirroring std's `From<T>`)
and source-side ergonomic methods are auto-derived:

```rust
pub trait Encodes<Source> {
    type Output;
    fn encode(source: Source) -> Self::Output;
}

pub trait IntoEncoded<S> {
    type Output;
    fn into_encoded(self) -> Self::Output;
}
impl<S, T> IntoEncoded<S> for T where S: Encodes<T> { ... }
```

Downstream impls no longer require "local type at trait position 0"
juggling — the schema sits at the impl-target, satisfying Rust's
orphan rule trivially.

- `ToValue` (old) → `IntoInline` (supertrait alias over `IntoEncoded`)
- `ToBlob` → `IntoBlob` (supertrait alias)
- `IntoValue` (interim) → `IntoInline`
- `IntoSchema` → `IntoEncoded`
- `into_schema` → `into_encoded`
- `IntoSchema::Form` → `IntoEncoded::Output`
- `FieldFormFor<V>` → `ToEncoded<V>` (the sum-lift dispatch shim)
- `ToValue` (the dispatch shim trait) → `ToEncoded`
- `to_value` (the dispatch shim method) → `to_encoded`
- `Attribute::into_field_value(v)` → `Attribute::encoded_from(v) ->
  Encoded<S>`, parallel to `Attribute::inline_from(v) -> Inline<S>`.

#### Trait family: `Schema` → `Encoding`

After removing semantic-marking schemas (Schema removals below)
the trait family genuinely describes encodings — byte format plus
validity plus identity. The name follows the role.

- `ValueSchema` → `InlineSchema` → `InlineEncoding`
- `BlobSchema` → `BlobEncoding`
- `InlineSchema::FieldKind` → `InlineEncoding::Encoding` (dispatch
  projection)
- Module renames:
  - `crate::value::*` → `crate::inline::*`
  - `value::schemas/` directory → `inline/encodings/`
  - `blob::schemas/` directory → `blob/encodings/`
  - `prelude::valueschemas` → `prelude::inlineencodings`
  - `prelude::blobschemas` → `prelude::blobencodings`
- Constants (Rust identifiers; hex ids unchanged):
  - `KIND_VALUE_SCHEMA` → `KIND_INLINE_ENCODING`
  - `KIND_BLOB_SCHEMA` → `KIND_BLOB_ENCODING`
- Attribute identifiers (Rust names; hex ids unchanged):
  - `metadata::value_schema` → `metadata::value_encoding`
  - `metadata::blob_schema` → `metadata::blob_encoding`

#### Schema removals

Two encodings whose distinction was *semantic* rather than
*structural* were removed. Semantic distinctions belong at the
attribute level, not the encoding level:

- `IRI` removed. Encoding is byte-identical to `LongString`; the
  semantic "this is an IRI" lives at the attribute. Removing it
  unlocks query unification (`Variable<Handle<IRI>>` and
  `Variable<Handle<LongString>>` couldn't unify before despite
  representing identical bytes) and ingestion robustness
  (validation at encoding boundary rejected mistyped IRIs;
  validation now lives at application boundary).
- `FileBytes` collapsed into `RawBytes`. Same decode target
  (`Bytes`), same validity (none); two ids labeling identical
  behavior. The "file-provenance" semantic lives at the attribute
  level.

`WasmCode` is kept distinct — its decode target is `WasmModule`
(structured type with its own validation), not just `Bytes`. The
schema label genuinely gates "safe to attempt WASM decode" and
prevents structural-but-garbage decodes (e.g. a PNG handle
decoded as `WasmModule`).

#### Eager handle caching (perf)

`Blob<S>` now caches its Blake3 handle at construction. This
eliminates a double-hash that surfaced at every
`MemoryBlobStore::insert` site in the `entity!{}` pipeline.
`Blob::with_handle` is the explicit "trust me" constructor for
read paths where the handle is already known. See commit
`536c364d`.

#### `entity!{}` auto-puts `Blob<T>` for `Handle<T>` fields

Passing a `Blob<T>` (or any blob-source like `&str`) as the value
for a `Handle<T>`-typed field absorbs the bytes into the
fragment's local blob store and uses the derived handle as the
trible's value. Replaces the explicit `ws.put(blob)` + handle
dance for the common case. See commit `8b8e7c0a`.

#### Items intentionally NOT renamed

- `value_range`, `value_in_range`, `entity_in_range`,
  `attribute_in_range` (query helpers; "value" refers to the V
  slot in (E, A, V) tribles, the slot name).
- `metadata::value_encoding` / `metadata::blob_encoding`
  (attribute identifiers; "value_" / "blob_" are part of the
  attribute name).
- `WasmValueFormatter`, `value_formatter` module/attribute (the
  "Value" here is generic "rendered value", not our Rust type).
- 3rd-party `Value`-named items: `clap::ValueEnum`,
  `proptest::strategy::ValueTree`, `Strategy::Value`,
  `serde_json::Value`.

#### Documentation

- `book/src/schemas.md` renamed to `book/src/encodings.md` with
  chapter title + intro rewrite.
- Doc-comment and prose updates across ~80 files to use the
  current Encoding vocabulary.
- README quickstart now demonstrates the `entity!{ note: "hi" }`
  auto-put pattern instead of the explicit `ws.put(...)` form for
  the canonical case.

## [0.39.0] - 2026-05-13

The canonical-attribute-id + origin-typed-identity + metadata-trait
unification release. Four related cleanups:

1. **Dynamic-name attribute id derivation** now goes through the
   same `entity!{...}.root()` mechanism every other entity uses,
   rather than bespoke flat-Blake3 hashing. The metadata
   `describe()` output and the attribute's identity come from a
   single source of truth.
2. **Each origin gets its own identity-determining attribute.** RDF
   predicates derive from `metadata::iri` (IRI is the canonical
   identifier); JSON fields and similar display-name-as-identity
   origins keep `metadata::name`. Collision is avoided structurally
   — an IRI-derived attribute and a same-bytes JSON-field-derived
   attribute differ in the (attr_id, value) pair feeding the
   intrinsic-id hash.
3. **`ConstId` + `ConstDescribe` collapsed into `MetaDescribe`** (renamed
   from interim `TypeDescribe`). The schema id is now
   `describe().root()` — one trait, one method, no separate identity
   trait. Every schema's identity-determining hex literal lives inline
   in its `MetaDescribe::describe` body. `const_blake3` (which existed
   to derive `Handle<H,T>::ID` and `Array<T>::ID` at compile time from
   `H::ID` / `T::ID`) is no longer needed: those types now derive their
   ids at runtime via the *entity-core* pattern (no-`@` `entity!` over
   a minimal identity-determining fact set; the fragment's intrinsic
   root IS the schema id) — the "entity core" mental model.
4. **`Fragment` is now self-contained.** It carries an internal
   `MemoryBlobStore<Blake3>` alongside its exports and facts, so any
   handle that appears in a fragment's facts has its bytes available
   without consulting an external blob store. `MetaDescribe::describe`
   collapses from `fn describe<B>(blobs: &mut B) -> Result<Fragment,
   B::PutError> where B: BlobStore<Blake3>` to plain `fn describe() ->
   Fragment` — the bytes live with the fragment that references them,
   describe is a pure (id, type) → Fragment function with no
   parameter threading and no error propagation, and `Describe for
   Attribute<S>` simplifies to `self.fragment.clone()`. See "Fragment
   self-containment" below for the full breakdown.

### Added
- **`blob::encodings::iri::IRI` BlobEncoding** for Internationalized
  Resource Identifiers. Byte layout matches `LongString` but the
  distinct schema lets handles carry their IRI-ness at the type
  level, enables boundary validation (`iri::looks_like_iri` —
  permissive RFC 3987 subset; debug-asserted at `ToBlob`), and makes
  IRI-derived attribute ids distinct from same-bytes
  LongString-derived ones. Re-exported as `prelude::blobencodings::IRI`.
- **`metadata::iri: Handle<Blake3, IRI>`** attribute. The canonical
  identity-determining attribute for RDF-imported entities.
  Distinct from `metadata::name` (which stays display-only).
- **`impl<S: InlineEncoding> From<Fragment> for Attribute<S>`** — the
  canonical dynamic-attribute constructor. Hand it an
  `entity!{ metadata::<identity-attr>: <value>,
  metadata::value_encoding: S::id() }` fragment whose root captures the
  identity-determining facts, and you get the typed attribute back.
  This is the *only* dynamic-attribute path: there is no specialized
  helper privileging any specific identity-attribute, so call sites
  must spell out which origin the id derives from (`metadata::name`
  for display-name origins, `metadata::iri` for RDF predicates, or
  whatever custom origin makes sense).
- **`metadata::array_item_schema: GenId`** attribute (id
  `56C43BEE48BE99521886D99BE9026A3B`). `Array<T>` references its
  element schema through this attribute rather than abusing
  `metadata::blob_encoding` (element schemas are not themselves
  `BlobEncoding`s).

### Changed (breaking)
- **`Attribute<S>` now stores a rooted `Fragment` (not just a raw
  id).** The wrapped fragment carries the identity-determining facts
  (`metadata::iri | metadata::name` + `metadata::value_encoding`),
  which `describe()` re-emits so the metadata registry stays
  queryable by IRI / name — that round-trip was lost in the prior
  `raw: RawId`-only shape. `id()` becomes
  `self.fragment.root().expect("rooted")`.
- **`Attribute::<S>::from_name`, `from_iri`, `from_id`, and
  `from_id_with_usage` removed.** The single public construction
  path is `impl<S: InlineEncoding> From<Fragment> for Attribute<S>`.
  Replace each call with explicit `Attribute::<S>::from(entity!{ … })`,
  naming the identity attribute (`metadata::name`, `metadata::iri`,
  or an explicit `@`-prefixed hex id) at the call site:
  ```rust
  // display-name origins (JSON fields, config keys, column headers):
  Attribute::<S>::from(entity! {
      metadata::name:         name.to_blob().get_handle::<Blake3>(),
      metadata::value_encoding: <S as MetaDescribe>::id(),
  })

  // RDF / JSON-LD predicates (IRI as canonical identifier):
  Attribute::<S>::from(entity! {
      metadata::iri:          iri.to_blob().get_handle::<Blake3>(),
      metadata::value_encoding: <S as MetaDescribe>::id(),
  })

  // Explicit hex id (schema pinning, bootstrap attrs):
  let id: Id = id_hex!("…");
  Attribute::<S>::from(entity! { &ExclusiveId::force_ref(&id) @
      metadata::value_encoding: <S as MetaDescribe>::id(),
  })
  ```
  The derivation is unchanged — canonical
  sorted+deduped+Blake3-hashed (attr, value) pairs, lo16 bytes — so
  attribute ids for migrated callers stay the same; only the call
  shape changes.
- **`attributes!{ "hex" as name: schema; … }`** no longer produces
  `const Attribute<S>` — Fragment isn't const-constructible, so
  fixed-id attrs become `static LazyLock<Attribute<S>>` like
  derived ones. Within the LazyLock init, the Hex branch
  constructs via `Fragment::rooted(id, TribleSet::new())` (low-
  level API, no `entity!{}`) to avoid a bootstrap deadlock —
  foundational attributes like `metadata::value_encoding` would
  otherwise reference themselves during their own init.
- **`Describe for Attribute<S>`** is a pure accessor: it returns
  `self.fragment.clone()` and nothing else. The wrapped identity
  fragment already carries `metadata::iri` / `metadata::name`
  together with `metadata::value_encoding: S::id()` from construction,
  which is the complete identity-determining fact set. Schema-level
  facts (the schema's own name, description, hash protocol info)
  belong to the schema, not the attribute — consumers wanting them
  call `<S as MetaDescribe>::describe()` directly. Drops the
  `S: MetaDescribe` bound on the impl (no longer needed); no `blobs`
  parameter is threaded through (no blob puts needed to describe an
  attribute, and `describe()` is infallible). Per-attribute
  `describe()` also doesn't emit usage facts — those live in the
  macro-generated top-level `describe()` as separate usage entities.
- **`AttributeUsage` / `AttributeUsageSource` types removed.**
  An `attributes!{}` declaration site IS an attribute usage; the
  abstract attribute is the shared thing multiple parties agree
  on, and the macro emits the codebase-local annotations (rust
  identifier as `metadata::name`, `module_path!()` as
  `metadata::source_module`, doc comment as
  `metadata::description`) inline at the declaration site, in the
  macro-generated top-level `pub fn describe() -> Fragment` function.
  Per-attribute `Attribute<S>` no longer carries usage data, and
  there is no `with_usage` builder. The usage entity's id and
  fact structure are byte-identical to the prior
  `AttributeUsage::describe` output (`(metadata::attribute,
  metadata::source_module)` → usage id; `metadata::name`,
  `metadata::tag: KIND_ATTRIBUTE_USAGE`, optional
  `metadata::description` under the usage id).
- **`Fragment::annotated` added.** Collapses the recurring three-step
  pattern:
  ```rust
  let mut frag = entity! { <core facts> };
  let id = frag.root().expect("rooted");
  frag += entity! { &ExclusiveId::force_ref(&id) @ <annotations> }.into_facts();
  ```
  into a single chained call:
  ```rust
  entity! { <core facts> }.annotated(|id_ref| {
      entity! { id_ref @ <annotations> }
  })
  ```
  The annotation fragment's facts merge in but its root is dropped —
  `self.root()` still returns the pre-annotation id. With `describe()`
  no longer fallible the previously-paired `try_annotated` variant is
  gone; closures that need to add blobs to the fragment now do so via
  the *outer* `Fragment::put` before calling `annotated`. Used by
  `Describe for Attribute<S>` (schema spread) and by the
  `attributes!{}` macro's per-attribute usage emission, so the
  generated code no longer has the temp-root extraction dance.
- **`attributes_impl` no longer invokes a sibling proc-macro for
  `entity!{}` expansions**. It calls `entity_impl` (same crate)
  directly, expanding to a `TokenStream2` with the
  `attributes_impl` caller's own `base_path`. The two macro shims
  (`triblespace_core_macros::attributes` →
  `::triblespace_core` paths; `triblespace_macros::attributes` →
  `::triblespace::core` paths) keep working as before, but
  attribute declarations no longer emit *N* inner `emit_metadata`
  invocation records per `attributes!{}` block — only the outer
  user-facing macro invocation gets recorded by the metadata
  emitter.
- **`ImportAttribute` removed.** It was a thin wrapper around two
  separate patterns: (1) "build an attribute from a name handle"
  (now just `Attribute::<S>::from(entity!{ metadata::name: handle,
  metadata::value_encoding: <S as MetaDescribe>::id() })` in the
  JSON object importer) and (2) "attach a contextual name fact to
  an existing attribute id" (the `import::json_tree::build_json_tree_metadata`
  rename pattern, which is gone — the macro-generated `describe()`
  already emits a usage entity with `metadata::source_module:
  "triblespace_core::import::json_tree"`, which disambiguates the
  module's view of each attribute without needing a separate
  `json.kind` / `json.string` / … rename. Nothing in the codebase
  queried those rename strings.)

  **Tooling-side migration**: any external metadata-browser that
  previously string-matched `?attr @ metadata::name = "json.kind"`
  directly on attribute entities will not find that fact in fresh
  manifests. The new shape is a usage entity:
  `?usage @ metadata::attribute = <attr_id>,
            metadata::source_module = <handle of "triblespace_core::import::json_tree">,
            metadata::name = "kind"`.
  Old piles still contain the direct-name facts and remain readable;
  mixed old/new manifests will surface both shapes, so name-discovery
  tooling should fall back to the usage-entity query if the direct
  one yields nothing.
- **`import::ntriples`** now derives all predicate URI attributes
  through `metadata::iri` (the `NTriplesAttrCache` builds the
  per-(IRI, S) `Attribute` via the inlined entity-core pattern).
  Net effect: RDF-imported attribute ids change to new values that
  ALSO differ from JSON field name-derived ids on the same byte
  content.
- **`ConstId` trait removed.** Every schema's identity-determining
  hex literal moves from `impl ConstId for X { const ID: Id =
  id_hex!("…"); }` to an inline `let id: Id = id_hex!("…");` inside
  its `MetaDescribe::describe` body. Callers reach the id via
  `T::id()` (default = `T::describe().root()`).
- **`ConstDescribe` renamed to `MetaDescribe`.** The trait emits
  facts in the `metadata::*` namespace; the new name signals the
  intent rather than the call shape. Mechanical rename — same method
  signature, same default `id()` derivation.
- **`HashProtocol` super-trait now `+ MetaDescribe`** (was `+
  ConstDescribe + ConstId`). The id flows through describe like
  every other schema; the bound stops conflating "I have a stable
  identifier" with "I implement a digest function".
- **`InlineEncoding` and `BlobEncoding` super-traits now `+ MetaDescribe`**
  (was `+ ConstId`). Schemas must describe themselves; the id is a
  property of that description, not a separate trait method.
- **`Handle<H,T>::describe`, `Array<T>::describe`, and
  `Attribute<S>::describe` use the entity-core split with `entity!`'s
  `*:` spread syntax** — sub-schemas are described *once* and their
  roots become the values of `metadata::blob_encoding` /
  `metadata::hash_schema` / `metadata::array_item_schema` /
  `metadata::value_encoding`, while their facts fold into the parent
  fragment automatically. Annotations (name, description, tag) attach
  via `&id @ …` so reworking documentation doesn't rotate the id.
  Net effect: `Handle<Blake3, LongString>::id()` and similar
  derived-id schemas have *new* id values vs. 0.38.0's `const_blake3`
  hashes. Re-ingest is required (consistent with the 0.39 attribute-
  id break above).
- **`Array<T>` uses `metadata::array_item_schema` (not
  `metadata::blob_encoding`)** to reference its element type. Element
  schemas (`array::F32`, `array::U8`, …) are not themselves
  `BlobEncoding`s — they only carry an `ArrayElement::Native` byte
  layout — so the dedicated attribute prevents semantically misleading
  edges. The id derivation is structurally the same shape but
  attribute-id differs, so existing `Array<T>` ids rotate again.
- **`const_blake3` workspace crate dropped.** Was a `triblespace-core`
  dep purely for compile-time `Handle`/`Array` id derivation;
  superseded by the runtime entity-core path. Workspace member,
  path dependency, and the `const-blake3/` directory are all gone.
- **Blanket `impl<T: ConstDescribe> Describe for T` dropped.**
  Instance `Describe` and type-level `MetaDescribe` are now distinct
  concepts; calling `Boolean.describe()` (instance-method form on a
  unit-struct schema marker) no longer compiles — use
  `Boolean::describe()` (associated-fn form) instead. No in-repo
  callers used the blanket; the change is documented for downstream
  crates.
- **`MetaDescribe::id()` is runtime, not const.** Pre-`0.39.0` code
  could use `T::ID` in `const` contexts. Post-rename `T::id()` is a
  fn that runs `T::describe().root()` each call.
  `Attribute<S>` amortizes per attribute via its stored
  `fragment.root()` lookup (cheap — single PATCH read). Hot
  dispatch sites that call `<S as MetaDescribe>::id()` repeatedly
  should hoist via `LazyLock<Id>` — see
  `triblespace-core/src/export/json.rs::render_schema_value`.

### Fragment self-containment
- **`Fragment` carries an internal `MemoryBlobStore<Blake3>`**
  alongside its exports and facts. The shape goes from
  `{ exports: PATCH<16>, facts: TribleSet }` to
  `{ exports: PATCH<16>, facts: TribleSet, blobs: MemoryBlobStore<Blake3> }`.
  Any handle that appears in the fragment's facts has its bytes
  available *with* the fragment — no external store lookup needed.
  An empty `MemoryBlobStore` is structurally a single PATCH-root
  pointer, so fragments without blobs pay essentially zero
  overhead.
- **New `Fragment` API:**
  - `put<S, T>(&mut self, item: T) -> Inline<Handle<Blake3, S>>` —
    insert a blob into the fragment's local store and get the
    content-addressed handle back. Idempotent.
  - `blobs() -> &MemoryBlobStore<Blake3>` — read the embedded
    store.
  - `into_facts_and_blobs(self) -> (TribleSet, MemoryBlobStore<Blake3>)` —
    consume the fragment, drop the exports, keep the payload.
  - `from_facts_and_blobs`, `rooted_with_blobs`, three-tuple
    `into_parts` for low-level wrap/unwrap.
  - `Fragment += Fragment` (`AddAssign`) now also unions the
    embedded blob stores. `TribleSet += Fragment` still drops
    blobs (facts-only merge); pull blobs out with
    `into_facts_and_blobs` if you need them downstream.
- **`Spread::spread` returns `(Iter, TribleSet, MemoryBlobStore<Blake3>)`**
  instead of `(Iter, TribleSet)`. The `entity!{ field*: spread_source }`
  syntax now propagates blobs from spread sources into the parent
  fragment automatically — a spread of a sub-schema's `describe()`
  fragment carries that schema's documentation blobs forward without
  any caller-side bookkeeping.
- **`MetaDescribe::describe` signature collapses from**
  ```rust
  fn describe<B>(blobs: &mut B) -> Result<Fragment, B::PutError>
  where B: BlobStore<Blake3>;
  ```
  **to**
  ```rust
  fn describe() -> Fragment;
  ```
  No `<B>` parameter, no `Result`, no `?` threading just to bubble
  `B::PutError`. Schemas build their fragments via
  `Fragment::put(item)` on a local
  `Fragment::rooted(id, TribleSet::new())` and then fold
  annotations via `Fragment::annotated`. The bytes live with the
  fragment that references them.
- **`Describe::describe(&self) -> Fragment`** likewise drops `<B>` /
  `Result`. The instance form is now a pure (self → Fragment)
  accessor. `Describe for Attribute<S>` shrinks to a one-liner:
  `fn describe(&self) -> Fragment { self.fragment.clone() }`.
- **`MetaDescribe::id()` default** is `Self::describe().root().expect(…)`
  (no scratch store needed). `Describe::id(&self)` parallels.
- **`try_annotated` removed.** With describe infallible the
  fallible annotation variant has nothing to propagate; closures
  that need to add blobs to the surrounding fragment do so via
  `Fragment::put` on the *outer* fragment before calling
  `annotated`. The `annotated` debug-assertion that the closure's
  returned fragment is rooted at the same id remains.
- **`MemoryBlobStore<H>` gains `Clone`, `PartialEq`, `Eq`** so
  Fragment can derive the same traits cleanly.
- **JSON importers' `metadata()` is infallible.** `JsonObjectImporter::metadata()`
  and `JsonTreeImporter::metadata()` both return `Fragment` directly.
  `build_json_tree_metadata` drops its blob-store parameter; it
  builds a self-contained fragment internally and returns it.
- **`entity!{}` macro emits a `MemoryBlobStore<Blake3>` accumulator**
  alongside the `TribleSet`, unions spread-source blobs into it, and
  wraps the final result via `Fragment::rooted_with_blobs`. Pure
  `entity!{}` calls with no spreads compile to an empty store
  (single PATCH pointer) — no overhead vs. the old `Fragment::rooted`
  shape.
- **Conceptual win.** `describe()` is now a pure function from a
  type/instance to a self-contained Fragment. No state mutation,
  no fallibility, no parameter threading. The "where do the bytes
  live" question collapses to a single answer: with the Fragment
  that references them.

### Migration
- **Attributes declared with explicit hex via `attributes! { "ID"
  as name: schema; ... }`** are unaffected. Their ids are stable.
- **Attributes derived from URIs/field-names** (the RDF and JSON
  importers' default path; `wd_bench::loader::predicate_id` for
  cookbook recipes) get new ids. Re-ingest the source data into a
  fresh pile to pick them up. No automatic migration of existing
  piles — we caught this design issue before the system has any
  external users, so the cleanest move is to break and re-ingest.

### Why this matters
- One canonical content-addressing mechanism for entity ids. The
  `describe()` metadata that documents an attribute now *is* the
  attribute's identity — adding a new dimension (cardinality,
  inverse-of, etc.) to the description automatically participates
  in the id derivation, with no hand-rolled hash to update.
- Sets up the eventual "URI position-asymmetry" cleanup: predicate
  attributes and rdf-position entities will both go through
  `entity!` so the asymmetry becomes a query distinction (which
  attribute facts describe the URI's role) rather than a hash-
  formula distinction.
- Every dynamic-id-deriving path in core now goes through one
  mechanism. `blake3::Hasher` is no longer imported anywhere in
  `attribute.rs` / `import/import_attribute.rs` (the macro handles
  hashing internally).

### Path-query: bounded-depth closure estimation
- **`estimate_from`'s closure-fallback no longer full-materialises**
  the result set (`triblespace-core/src/query/regularpathconstraint.rs`).
  When shallow estimation doesn't apply — i.e. the path body
  contains an unbounded closure that can't be re-shaped through
  the WCO `build_join` — the previous fallback ran
  `eval_from(set, body, start).len()`, which paid the full cost
  of computing the closure just to measure its size. The new
  `bounded_eval_from` helper caps closure BFS at
  `RPQ_ESTIMATE_DEPTH = 5` levels, matching Karalis et al.
  ESWC 2024 §4.3's "default estimation" technique. Bounded depth
  → bounded estimate cost, sufficient for driving the WCO
  planner's variable ordering without paying for the materialisation
  it was meant to inform. Non-closure expressions (Attr,
  InverseAttr, Concat, Union) don't consume depth — the bound
  only fires on Plus/Star iteration steps.
- Shallow estimation (the constant-time per-attribute count from
  the segmented index) was already in place; this commit just
  closes the remaining gap where shallow doesn't apply. All 10
  path proptests pass; 49 broader query proptests pass.

## [0.38.0] - 2026-05-07

The team-rooted-gossip release. The gossip mesh id is now
derived directly from the team root pubkey, so `triblespace-net`
and `trible` no longer ask users to coordinate a separate topic
string with their team. One identifier per team handles both
auth (cap chain verification) and rendezvous (gossip mesh).

### Changed (breaking)
- **`triblespace::net::peer::PeerConfig.gossip_topic:
  Option<String>` → `gossip: bool`.** When `gossip = true`, the
  topic is `team_root.to_bytes()` directly (32 uniform bytes
  from the ed25519 pubkey — perfect as a `TopicId`, no hashing
  needed). `gossip = false` is serve/pull-only (no mesh
  subscription). Migration: `Some(_)` → `true`, `None` → `false`.
  See `triblespace-net/CHANGELOG.md`.
- **`trible pile net sync --topic NAME` flag removed.** Sync
  always joins the team's gossip mesh, identified by
  `TRIBLE_TEAM_ROOT` (or single-user fallback to the node's own
  pubkey when unset). Migration: drop the `--topic` flag from
  any sync invocation. See `trible/CHANGELOG.md`.
- All 8 workspace crates bumped 0.37.0 → 0.38.0 in lock-step
  (`triblespace`, `triblespace-core`, `triblespace-core-macros`,
  `triblespace-macros`, `triblespace-macros-common`,
  `triblespace-net`, `triblespace-search`, `trible`). Only
  `triblespace-net` and `trible` carry source changes; the rest
  bump to keep workspace versions aligned.

## [0.37.0] - 2026-05-06

The search release. `triblespace-search` (BM25 + HNSW indexes
on top of triblespace piles) lands as a first-class workspace
crate; the umbrella re-exports it at `triblespace::search`
behind the `search` feature. Includes the canonical-bytes
storage-layout refactor, the auth-arc test maturation, and a
range-query primitive in core.

### Added
- **`triblespace-search`** — first crates.io release of the
  BM25 + HNSW search crate. Two blob types
  (`SuccinctBM25Blob`, `SuccinctHNSWBlob`) backed by zero-copy
  `anybytes`-frozen `ByteArea` bytes; the index *is* its blob,
  so `ToBlob` is an `O(1)` refcounted clone. Re-exported at
  `triblespace::search` behind the `search` feature. Full
  surface details in `triblespace-search/CHANGELOG.md`.
- **`Universe::search_range` / `search_lower` / `search_upper`**
  in `triblespace-core` — log-time range primitives over a
  monotonic universe, with `O(log n + K)` `value_in_range`
  proposals on `SuccinctArchive`. See
  `triblespace-core/CHANGELOG.md`.
- **`trible team show [--verify]`** end-to-end chain walk +
  `verify_chain` rehearsal against a configured team root.
  Same code path the relay's `OP_AUTH` uses; result mirrors
  what a real connection attempt would see.
- **`trible team invite --branch <BRANCH_HEX>`** restricts the
  issued cap to the named branch(es); `team list` surfaces
  the per-cap details (issuer → subject, perms, branches,
  expiry — sorted soonest-first) and the `(revoker, target)`
  pairs for each verifiable revocation.
- **`pile net status`** diagnostic prints the node id, team
  root, and self_cap a peer would present on `OP_AUTH`,
  annotated with their source ("from `TRIBLE_TEAM_ROOT`",
  "single-user fallback", "NOT SET — remote will reject").
- **Live revocation propagation** in `triblespace-net`: each
  `Peer::refresh` rescans the new snapshot for `(rev, sig)`
  blob pairs signed by the configured team root and unions
  them into the live revoked set. No restart needed for a
  revocation gossiped into the pile.
- **Capability auth book chapter**
  (`book/src/capability-auth.md`) covering the model, CLI
  lifecycle, wire protocol, two-tier scope gate, and
  revocation. Linked from the workspace TOC.
- **`pattern!` free-attribute form** — `{ ?e @ ?attr: ?val }`
  patterns where the predicate slot is a query variable.
  Building block for SPB-style outer projections (Q3/Q4
  `?cw ?pred ?value`) and general-purpose schema-erased
  iteration over an entity's triples. The value variable
  must be typed `Variable<UnknownInline>` (compile-time
  enforced); decoding to a concrete schema is an explicit
  `try_from_inline::<S>()` step at the use site.
- **`PathOp::Optional` (`(p)?`) primitive** in the path-query
  language. Zero-or-one application of a sub-path; recognised
  inline so the zero-step branch reuses the bound start node.
  Plus a `from_postfix`-time normalisation pass that lifts
  `Optional`/`Union` out of `Concat` (`a / b? ↔ a | (a / b)`)
  so the typical WDBench shape `p / q?` actually translates.
  See `triblespace-core/CHANGELOG.md`.
- **`PathOp::Inverse` (`^p`) primitive** in the path-query
  language. Per-attribute reverse traversal via the VAE
  index; compound expressions normalise via standard reversal
  rewrites. See `triblespace-core/CHANGELOG.md`.

### Changed
- **Pile-sync protocol stays at v4** (`/triblespace/pile-sync/4`)
  but the test suite matures: e2e iroh-backed auth tests are
  un-ignored, three pass green over real `TestNetwork`
  endpoints (smoke + AUTH_OK + AUTH_REJECTED). Reachability
  BFS for `OP_CHILDREN` is amortised across responses.
- **`triblespace-search`'s `pub bytes: Bytes` is the persistence
  surface** — the canonical-bytes pattern (mirroring
  `SuccinctArchive`) means `ToBlob` is `Bytes::clone`,
  `to_bytes` / `try_from_bytes` retired. Schema ids rotated
  for both blob types — see search CHANGELOG.
- **`Cargo.lock` ethnum bumped to 1.5.3** (was 1.5.2). Fixes
  the transmute UB on nightly that was failing docs.rs builds
  for `triblespace 0.36.0`. Constraint stayed at `^1.5.0`, so
  this release picks up the fix automatically; the failing
  build will be replaced when 0.37.0 publishes.

### Removed
- Pre-existing rustdoc-link warnings across the workspace —
  14 `unresolved link` / `links to private item` warnings
  cleared in `triblespace-core` and `triblespace-search`.
  `cargo doc --workspace --no-deps` is now warning-free.

## [0.36.0] - 2026-04-28

The chain-of-trust capability auth release. New
`triblespace_core::repo::capability` module + protocol v4 + `trible
team` CLI surface. See `book/src/capability-auth.md` for the
user-facing chapter and the per-crate CHANGELOGs
(`triblespace-net/CHANGELOG.md`, `trible/CHANGELOG.md`) for the
surface-level details. Highlights:

### Added
- **`triblespace_core::repo::capability`** — chain-of-trust
  capability lib: `build_capability` / `verify_chain` /
  `build_revocation` / `extract_revocation_pairs` /
  `scope_subsumes`, plus the `VerifiedCapability` type with
  `permissions` / `granted_branches` / `grants_read` /
  `grants_read_on` helpers. 27 lib tests; runnable rustdoc
  examples on every primary public fn.
- **Pile-sync protocol v4** (`/triblespace/pile-sync/4`):
  mandatory `OP_AUTH` first stream, two-tier scope gate
  (branch level on `OP_LIST` / `OP_HEAD`, blob-reachability on
  `OP_GET_BLOB` / `OP_CHILDREN`), live revocation propagation
  through snapshot rescans.
- **`trible team {create, invite, revoke, list}`** subcommand group;
  `team invite --branch <BRANCH_HEX>` for branch-restricted caps;
  `team list` audits caps with issuer→subject, scope, expiry sorted
  soonest-first.

### Changed
- `triblespace::net::peer::PeerConfig` is now non-`Default` —
  every construction site must specify `team_root`, `revoked`,
  `self_cap`.
- `trible pile net sync` / `pile net pull` read `TRIBLE_TEAM_ROOT`
  + `TRIBLE_TEAM_CAP` env vars for multi-user team operation.

## [0.19.0] - 2026-03-13
### Changed
- **Breaking:** Renamed the `matches!` query macro to `exists!` to resolve the
  name collision with `std::matches!` that made the macro unusable in practice.

## [0.35.0] - 2026-04-18
### Breaking
- **`Id::aquire` → `Id::acquire`** (fixing a long-standing typo).
  Paired: `ExclusiveIdError::FailedAquire` → `FailedAcquire`.
- **Commit metadata is now content-addressed.** `commit_metadata`
  derives the commit's entity id intrinsically from its
  `(attribute, value)` pairs via `entity!`'s content-hash form instead
  of minting a random `rngid()`. Merge commits (content = `None`) also
  drop `metadata::created_at` since no authorial act produced them.
  Existing piles aren't invalidated — old commits with random entity
  ids remain queryable — but newly-minted commits have different
  entity ids and therefore different blob hashes than the pre-change
  world. Payoff: two peers merging the same parent set produce
  bit-identical merge commits, so parallel-merge scenarios in
  distributed sync converge in zero extra rounds via content
  addressing.
- **Branch metadata is now content-addressed the same way.**
  `branch_metadata` and `branch_unsigned` use `entity!`'s intrinsic id
  form instead of the deleted `derive_metadata_entity` helper. Every
  publish also stamps `metadata::updated_at: NsTAIInterval` so peers
  can order concurrent HEAD gossips without an ancestor walk.
  Tradeoff: because `updated_at` varies per publish, the same
  `(head, name, signer)` state at two different moments no longer
  produces an identical metadata blob hash.

### Added
- `SortedSlice::from_mut(&mut [T])`: sort-in-place constructor that
  mirrors the `new_unchecked` ergonomics when the caller has a mutable
  slice but no pre-sortedness guarantee.
- `ContainsConstraint` impl for `&'a mut [T]` that sorts the slice in
  place and produces a `SortedSliceConstraint`. Via `DerefMut` method
  resolution this also picks up `&mut Vec<T>`, `&mut [T; N]`,
  `&mut Box<[T]>`, and any other mutable borrow that derefs to a slice,
  so callers can write `(&mut my_vec).has(var)` without hand-rolling
  the sort.
- `import::ntriples::{ingest_ntriples, ingest_ntriples_file}`:
  N-Triples importer generic over any
  `Workspace<Blobs: BlobStore<Blake3>>`. XSD datatypes map to native
  triblespace schemas (`xsd:integer` → `I256BE`, `xsd:decimal` →
  `R256BE` exact rational, `xsd:float`/`xsd:double` → `F64`,
  `xsd:boolean` → `Boolean`, strings → `Handle<LongString>`, URI
  objects → `GenId`). Predicate URIs become attributes via
  `Attribute::from_name` so repeated imports of the same data converge
  deterministically.
- `import::rdf_uri`: canonical "this entity is the referent of this
  URI" attribute, used by the N-Triples importer to derive stable
  entity ids from URIs.
- `triblespace-net` joins the workspace as a first-class member. The
  facade crate gains a `net` feature
  (`triblespace = { version = "x", features = ["net"] }`) that
  re-exports it as `triblespace::net`, so
  `use triblespace::net::peer::Peer;` is the one-liner for distributed
  sync. The subtree merge preserves the full commit history from the
  previously-standalone repo.
- `triblespace-net` now inlines the `iroh-dht` implementation as an
  internal module (`triblespace_net::dht`) instead of depending on the
  separate `iroh-dht` crate. The implementation was a triblespace fork
  of `iroh-dht-experiment` with API migration and a `ContentDiscovery`
  trait impl; integrating it into triblespace-net eliminates the
  unpublished-fork blocker for the `net` feature and keeps DHT
  evolution co-located with its only consumer.
- **Edition bump**: `triblespace-net` is now on Rust edition 2024
  (inherited from iroh-dht's let-chain syntax). Users depending on
  `triblespace-net` directly or on the facade's `net` feature need
  Rust 1.85 or newer.

### Changed
- `Pile::put` now handles blobs larger than the kernel's atomic
  `write_vectored` ceiling (~2&nbsp;GiB on macOS / Linux). Records
  below a 1&nbsp;GiB threshold keep the existing shared-lock +
  single-`writev` fast path; larger records take an exclusive lock and
  append via plain `write_all`, lifting the previous ~2&nbsp;GiB
  per-blob cap. The exclusive-lock path remains append-only and
  `Pile::restore` still truncates any partial tail after a crash.
  Test coverage added as `put_and_get_oversized_blob`
  (`#[ignore]`d because the exercise allocates ~1&nbsp;GiB of memory).

### Documentation
- New book chapter: **"Distributed Sync"** (under Repositories &
  Workflows) covers the `Peer<S>` mental model, gossip / DHT / QUIC
  transports, `track` vs `fetch` primitives, `merge_tracking_into_local`,
  convergence rounds under sequential vs parallel gossip, and the CLI
  surface (`trible pile net {identity, sync, pull}`).
- "Importing Data Formats" chapter gains an "Importing N-Triples"
  section with the XSD → triblespace schema mapping table and a query
  roundtrip example.
- "Deep Dive: Identifiers" chapter reframed around clearer axes:
  *derivability* (intrinsic/extrinsic = "can the id be recomputed from
  the entity?") and *content encoding* (abstract/semantic = "do the
  bits carry meaning about the entity?"). New "Quadrant Properties"
  section names the structural invariants (extrinsic + semantic +
  global scope ⇒ authority; the other quadrants can be decentralized).
- `book.toml` enables MathJax so the chapters' `\( 2^{128} \)` notation
  actually renders.

## [0.34.1] - 2026-04-04
### Added
- Optional `telemetry` feature in the facade crate:
  - `triblespace::telemetry::Telemetry` for pile-backed tracing sinks
  - `triblespace::telemetry::TelemetryLayer` for embedding into custom
    subscribers
  - `triblespace::telemetry::schema` metadata/attribute ids used by the sink
  - environment controls: `TELEMETRY_PILE`,
    `TELEMETRY_FLUSH_MS`.

### Changed
- Trimmed `triblespace::telemetry` schema to generic span/session fields by
  removing GORBIE-specific `card_index` capture from the shared sink.
- `exists!` now supports the zero-variable form `exists!(constraint)` for pure
  existence checks without the tuple head ceremony.

### Fixed
- `PATCH::difference` now returns an empty set when the left-hand side is
  empty (`∅ \ B = ∅`) instead of incorrectly cloning the right-hand side.
- `find!` now rejects the common footgun where a projected variable never
  appears in the constraint tokens, and the fallback unbound-variable panic now
  points users toward `find!((), ...)` / `exists!(constraint)`.
- Pile-backed tests now create the pile file explicitly before calling
  `Pile::open`, matching the newer no-auto-create semantics and restoring the
  full workspace test suite.

### Documentation
- Documented `PushError::StoragePut` guidance for large local `Pile` writes:
  platform `writev` limits can surface `EINVAL`, and oversized payloads should
  be chunked semantically behind a manifest/root record.
- Added rustdoc coverage for the public macro surface and a new book chapter,
  "Macro Cookbook", with runnable doctest examples for the main query and data
  construction macros.

## [0.20.0] - 2026-03-14
### Changed
- **Breaking:** Removed the `FromInline` trait. `TryFromInline` is now the sole
  value conversion trait. `Inline::from_inline()` is constrained to
  `TryFromInline<Error = Infallible>`.
- **Breaking:** `find!` now uses filter semantics: when a variable's
  `TryFromInline` conversion fails the row is silently skipped instead of
  panicking. For types with `Error = Infallible` (e.g. `f64`, `Inline<_>`) no
  rows can ever be accidentally filtered.
- **Breaking:** `find!` variable declarations support a `?` suffix
  (`name: Type?`) that yields `Result<T, E>` without filtering, matching
  Rust's `?` semantics of "bubble the error to the caller."
- **Breaking:** `Query::new` now expects the post-processing closure to return
  `Option<R>`. Returning `None` skips the current binding and continues the
  search. Direct callers of `Query::new` must wrap their return values in
  `Some(...)`.
- `find!` is now implemented as a hybrid `macro_rules!` + proc macro
  (`__find_impl!`), replacing the previous three-arm `macro_rules!` definition.
- `HashSet`/`HashMap` constraint bounds relaxed from requiring
  `TryFromInline<Error = Infallible>` to accepting any `TryFromInline`; values
  that fail to convert are rejected during `confirm()`.

## [0.16.0] - 2026-02-15
### Changed
- JSON importer metadata builders now return `Fragment`:
  - `import::json::JsonObjectImporter::metadata`
  - `import::json_tree::JsonTreeImporter::metadata`
  - `import::json_tree::build_json_tree_metadata`
  These fragments export the derived schema/attribute/kind ids to make merging
  and discovery more convenient.

## [0.15.0] - 2026-02-15
### Changed
- Cleanup/polish after 0.14.0: fixed benches and minor clippy lints, and added
  small convenience helpers (`Universe::is_empty`).
- `metadata::ConstDescribe::describe` now returns a rooted `Fragment` (exporting
  the schema id) instead of a raw `TribleSet`, aligning constant schema metadata
  with runtime `Describe`.
### Added
- Additive set ergonomics: `TribleSet + Fragment` and `Fragment + TribleSet`
  (plus corresponding `+=` forms) to union facts while preserving exports on
  the fragment side.

## [0.14.0] - 2026-02-14
### Added
- `Fragment`: a rooted (or multi-root) graph fragment that bundles a `TribleSet`
  with exported entity id(s).
- `Id::raw()`: a `const` helper returning the raw 16-byte identifier.

### Changed
- `entity!` now returns a `Fragment` instead of a raw `TribleSet`. Merge facts
  into datasets via `+=` (only facts are unioned). Use `.into_facts()` when you
  explicitly need to drop exports and work with a plain `TribleSet`.
- `Workspace::commit` now accepts `impl Into<TribleSet>` for content, so you can
  commit a `Fragment` directly.
- Renamed metadata traits: `metadata::Metadata` -> `metadata::Describe` and
  `metadata::ConstMetadata` -> `metadata::ConstDescribe`.
- `metadata::Describe::describe` now returns a `Fragment` (with exports as the
  described root id(s)) and no longer has a separate `id()` accessor.
- Introduced `metadata::ConstId` (`const ID: Id`) for schema identifiers and
  kept `metadata::ConstDescribe` focused on emitting optional discovery
  metadata. Composite `Handle` schema IDs are derived in `const` context via
  the new `const_blake3` workspace crate.
- `import::json::JsonObjectImporter::import_*` now returns a `Fragment` instead
  of root id lists and no longer retains accumulated facts internally (removed
  `data()`/`clear_data()`; callers merge fragments explicitly).
- `import::json_tree::JsonTreeImporter::import_*` now returns a rooted `Fragment`
  and no longer retains accumulated facts internally (removed `data()`).

## [0.13.2] - 2026-02-13
### Added
- `entity!` now supports repeated facts via `attr*: iter_expr`.

## [0.13.1] - 2026-02-13
### Added
- `entity!` now supports optional facts via `attr?: option_expr`.

## [0.13.0] - 2026-02-13
### Changed
- `entity! { ... }` (without an explicit `id @` prefix) now derives a deterministic
  intrinsic entity id from its attribute/value pairs. Use an explicit id expression
  (for example `&ufoid() @`, `rngid() @`, or `genid() @`) when you want a fresh,
  extrinsic identity per invocation.
- `entity!` now accepts the explicit `_ @` prefix as a synonym for the derived-id
  behavior (useful when you want to be explicit in code reviews).

## [0.12.2] - 2026-02-10
### Changed
- PATCH tagged pointers now store node tags in the low 4 bits (16-byte aligned bodies)
  and keep the per-child key byte in the top byte, freeing address bits for larger
  virtual address spaces.

### Fixed
- PATCH no longer performs x86_64 sign-extension when decoding tagged pointers,
  avoiding incorrect canonicalization on systems with wider virtual addresses.

## [0.12.1] - 2026-02-10
### Fixed
- Fixed a Linux/aarch64 crash in `PATCH::clone()` when decoding tagged pointers.

## [0.12.0] - 2026-02-09
### Changed
- `Repository::create_branch` now mints branch ids with `genid` (high-entropy random ids) instead of `ufoid` (time-prefixed ids).

## [0.11.0] - 2026-02-08
### Added
- Branch tombstone records in the pile format for explicit branch deletion.

### Changed
- `BranchStore::update` now takes `new: Option<Handle<..>>`; `None` deletes the branch.
- `Pile` applies tombstones by removing branch heads from its in-memory branch index.
- `ObjectStoreRemote` represents tombstones as empty branch objects (size=0) and filters them out of `branches()`.

## [0.10.0] - 2026-02-07
### Added
- Attribute usage annotations with `metadata::attribute`,
  `metadata::source_module`, and `KIND_ATTRIBUTE_USAGE` for capturing
  contextual names/descriptions.

### Changed
- Clarified `metadata::name` and `metadata::description` as general-purpose
  entity naming/description attributes in docs and metadata comments.
- `Attribute::describe` now emits usage annotations when available, and the
  `attributes!` macro attaches contextual usage metadata (name/description/
  source) to declared attributes.
- Attribute usage ids are now anchored on the attribute id + module path only,
  so renames and file/line shifts do not churn usage identities.
- JSON importers validate UTF-8 strings via `View<str>` while reusing the
  parsed bytes.

## [0.9.0] - 2026-02-03
### Added
- Lossless JSON importer that preserves structure and ordering with explicit
  node/entry entities and content-addressed ids.
- `FileBytes` blob schema for explicit file-backed byte payloads.

### Changed
- Removed the serde-based and non-deterministic JSON importers; the remaining
  deterministic importer is now `JsonObjectImporter`.
- Renamed JSON importers for clarity: `JsonImporter` -> `JsonObjectImporter`,
  `LosslessWinnowJsonImporter` -> `JsonTreeImporter`, and `json_lossless` ->
  `json_tree`.

### Fixed
- Added the missing `Inline` import in the lossless JSON importer.

## [0.8.0] - 2026-01-22
### Added
- `TribleSetFingerprint` plus `TribleSet::fingerprint` for fast, in-process
  cache keys that match `TribleSet` equality.
- `Workspace::commit` now accepts optional commit metadata, plus
  `Workspace::checkout_metadata` and `Workspace::checkout_with_metadata` for
  reading commit metadata `TribleSet`s. Supplying commit metadata does not
  modify the workspace default.
- `Repository::set_default_metadata` and `Workspace::set_default_metadata`
  for configuring default commit metadata handles, plus
  `Repository::pull_with_metadata` for per-workspace overrides.
- `Repository::storage` and `Repository::storage_mut` for direct access to the
  underlying storage backend.
### Changed
- Renamed `WasmFormatterLimits` to `WasmLimits`.
- Commits can now carry an optional `metadata` handle alongside `content`.
- `repo::commit::commit_metadata` now takes an optional metadata handle instead
  of a metadata blob.
- `CommitSelector` ranges now treat branches without a head commit as empty
  history, so `Workspace::checkout` returns an empty `TribleSet` instead of an
  error when no commits exist.
- JSON importers now include schema metadata in their emitted metadata sets so
  value formatter lookups can succeed.

## [0.7.0] - 2026-01-18
### Changed
- Updated the README quote to Joe Armstrong’s talk “The Mess We’re In.”
- `Metadata` and `ConstMetadata` now use a shared `id` method as the canonical
  schema identifier, eliminating the former `metadata_id` accessors.
- `Metadata::describe` and `ConstMetadata::describe` are now fallible so blob
  write errors can be propagated instead of silently ignored.
- `InlineEncoding` inherits its identifier and default description behavior from
  `ConstMetadata`, removing duplicate `id`, `metadata_id`, and `describe`
  methods from the schema trait itself.
- Hash protocol metadata now emits the protocol name alongside the identifier
  so descriptions include the declared `NAME` for each digest.
- Replaced the `SchemaMetadata` helper with direct `ConstMetadata` impls on
  value schemas so static metadata stays in sync with runtime metadata roots.
- Removed explicit blob schema hooks from value schemas and attribute metadata,
  relying on metadata identifiers instead of nested blob schema entries.
- Updated schema documentation to reflect metadata-driven identifiers and
  examples that call `ConstMetadata::id()`.
- `Handle` value schemas now forward metadata from their hash protocol and blob
  schema components so composite schema descriptions stay discoverable.
- Removed the WASM module byte-size limit checks from module compilation and
  formatter loading; callers can enforce limits by checking blob sizes before
  compilation.
- `triblespace_core::wasm::shared_engine` is no longer part of the public API;
  module compilation uses an internal, lazy-initialized engine.
- Hash/handle WASM value formatters now always use the generic hex formatter,
  instead of special-casing specific hash protocols.
- Hash/handle WASM formatter output now prefixes `hash:` before the hex digest.
- Inlined schema-level value formatter metadata emission, removing the
  `wasm_formatters` helper module.
- Metadata describe helpers now bind schema IDs once and inline blob puts when
  emitting tribles.
- `entity!` now accepts `ExclusiveId` values in addition to `&ExclusiveId`
  references.
- Renamed `ExclusiveId::as_transmute_force` to `ExclusiveId::force_ref`.
- WASM value formatter limits are now supplied per formatting call (with a
  default helper), and the eager formatter loader no longer captures limits at
  construction time.
- `WasmModuleResolver` has been removed in favor of the generic `BlobCache`.
- `WasmValueFormatterResolver` has been removed in favor of direct
  `metadata::value_formatter` lookups with `BlobCache`.
- `load_wasm_value_formatters` has been removed in favor of `BlobCache` and
  `metadata::value_formatter` lookups.
- `#[value_formatter]` can override the generated WASM byte constant name and
  visibility via `const_wasm = NAME` and `vis(...)` arguments.
- Attribute identifiers derived from hashed names now use the rightmost 16 bytes
  of the Blake3 digest to stay consistent with the ID-to-value layout.
- Consolidated JSON import into a single deterministic
  `import::json::JsonObjectImporter` with fixed primitive mappings and optional salt
  support, replacing the prior nondeterministic importer and configurable
  encoder callbacks.
### Added
- Guidance on how `ExclusiveId` ownership narrows safe absence checks while
  keeping queries monotonic across collaborators in the incremental queries
  chapter of the book.
- `metadata::KIND_INLINE_ENCODING` and `metadata::KIND_BLOB_ENCODING` tags, now
  emitted by built-in schema metadata for discovery.
- `metadata::description`, a LongString-backed attribute for schema
  documentation, and `metadata::name`/`metadata::description` emission for
  built-in value and blob schemas.
- `metadata::Metadata` trait for emitting self-describing `TribleSet` and
  `MemoryBlobStore` pairs, enabling attributes and schemas to publish
  documentation metadata recursively.
- `TryToInline` implementations that convert `serde_json::Number` directly into
  the `F256` schema so JSON import code can call `.to_inline()` instead of
  hand-packing high-precision floats.
- Criterion benchmark covering deterministic JSON import performance using the
  serde-rs/json-benchmark fixtures.
- `GenId` value schema conversions for `uuid::Uuid`, including fallible packing and support for nil UUID values
  and unpacking helpers that enforce the non-nil invariant.
- Bundled the `canada.json`, `citm_catalog.json`, and `twitter.json` datasets to
  keep the JSON import benchmark self-contained.
- `import::json::JsonObjectImporter` for deterministic JSON imports that map strings
  to `Handle<Blake3, LongString>`, numbers to `F256`, booleans to `Boolean`,
  and nested objects to `GenId` links, hashing attribute/value pairs (with an
  optional 32-byte salt) to derive stable entity ids, while streaming blobs into
  a caller-provided store and exposing data/metadata separately.
- `inlineencodings::Boolean` for encoding `false` as all-zero bytes and `true` as
  all ones, providing an unambiguous target for JSON boolean importers.
- `RangeU128` and `RangeInclusiveU128` value schemas for encoding pairs of
  packed `u128` values, enabling compact storage of start/end markers such as
  source ranges.
- `LineLocation` value schema for storing explicit `(line, column)` start and
  end coordinates without manual packing, now used by the macro metadata
  instrumentation when recording invocation spans.
- `wasm` feature flag that bundles WebAssembly value formatters for the built-in
  value schemas and attaches them via `metadata::value_formatter` when emitting
  schema metadata.
- `#[value_formatter]` proc macro support in `triblespace-core-macros`, enabling
  the core crate to compile and embed formatter modules without introducing a
  dependency cycle.
- `triblespace-macros` crate wrapping the procedural macros and query helpers
  to record invocation metadata in an optional repository configured via the
  `TRIBLESPACE_METADATA_PILE` and `TRIBLESPACE_METADATA_BRANCH` environment
  variables.
- `TRIBLESPACE_METADATA_SIGNING_KEY` environment variable for configuring the
  signing key used when committing metadata; instrumentation skips emission when
  the value is unset or invalid.
- `Id::from_hex` helper for parsing hexadecimal identifiers, now reused by the
  macro metadata instrumentation when decoding branch IDs.
- Attribute definition metadata emitted alongside `attributes!` expansions,
  recording attribute identifiers, names, invocation IDs, and the declared
  schema type tokens for downstream analysis tools.
- Runtime helper `Attribute::from_name` for deriving deterministic attribute IDs
  from dynamic field names using schema metadata and hashed field handles.
- Shared `proofs::util` module providing bounded Kani generators for tribles,
  PATCH entries, and small commit DAGs, and updated the query harness to reuse
  them.
- `metadata::value_formatter` and `blobencodings::WasmCode` for attaching
  schema-level WebAssembly value formatters, plus an optional `wasm` feature
  (enabled by default in the `triblespace` facade crate) that runs them in a
  sandboxed `wasmi` interpreter with strict limits.
- `BlobCache`, a generic handle-keyed cache for blob conversions.
- `#[value_formatter]` proc macro attribute (in `triblespace-macros`) that
  compiles standalone Rust formatter functions into sandboxed WebAssembly
  modules and embeds the resulting bytes in the caller crate.
- Repository ancestor harness exercising `CommitSelector::ancestors` against
  nondeterministic DAGs generated by the shared bounded helpers.
- PATCH harness verifying entry insertion and replacement using the shared
  bounded generators.
- Documented the deterministic JSON importer flow and added regression tests
  covering integration with the fixed primitive mappings.
- Added a book chapter on importing external data formats that covers the
  JSON importers, attribute derivation, encoder callbacks, and strategies for
  extending the namespace to new formats.
- 0.6.0 release preparation checklist in `INVENTORY.md` detailing actionable
  subtasks for the remaining blockers and polish items.
- Formal verification roadmap outlining Kani, Miri, fuzzing, and simulation
  testing plans in the book.
- Expanded the roadmap with an explicit invariant catalogue, spelling out the
  PATCH/ByteTable invariants exercised by `Branch::modify_child`, clarifying the
  value-schema guarantees around `TryFromInline`, and synchronised follow-up
  tasks in `INVENTORY.md`.
  PATCH/ByteTable invariants exercised by `Branch::modify_child`, and synchronised
  follow-up tasks in `INVENTORY.md`.
- Documented the set-combinator commit selectors (`union`, `intersect`,
  `difference`) in the book with usage examples.
- `_?ident` scoped variables for `pattern!` and `pattern_changes!`, enabling
  fresh bindings without declaring them in `find!` heads, along with
  documentation and tests.
- `temp!` macro for allocating hidden query variables across constraints, plus
  documentation and regression tests covering cross-pattern joins.
- Clarified the `and!` example in the Query Language chapter to show how
  membership helpers can pair with pattern constraints drawn from a different
  collection.
- Documented repository storage backends and added a book page tracking future
  documentation improvements.
- Clarified the `Trible` layout, indexing strategy, and edge semantics in the
  deep dive chapter of the book.
- Expanded the documentation backlog with notes on remote object-store conflict
  handling, succinct archive indexes, and extending regular path engines.
### Changed
- `Attribute` now retains its declared name, uses the field name for dynamic
  attributes, and relies on the `Metadata` trait to emit attribute metadata in
  both code-generated and runtime scenarios.
- Simplified the attribute constructors to `from_id`, `from_id_with_usage`, and
  `from_name`, removing `from_id_with_name`/`from_handle` in favor of explicit
  usage metadata and internal handle derivation.
- Simplified attribute naming by replacing the internal `AttributeName` enum
  with an optional `Cow<'static, str>`, keeping const-friendly static ids while
  storing dynamic field names directly.
- Replaced the `InlineEncoding::VALUE_SCHEMA_ID` and `BlobEncoding::BLOB_SCHEMA_ID`
  associated constants with `ConstMetadata::id()` across value and blob schemas,
  preserving existing identifiers and deriving composite `Handle` schema IDs
  deterministically from their hash protocol and blob schema components.
- Made `HashProtocol` extend `ConstMetadata` so protocol identifiers come from
  the unified metadata API alongside value and blob schemas.
- Documented why schema identifiers remain regular functions until `blake3`
  exposes a const-friendly hashing API for composite handle schemas.
- Removed the `InlineEncoding::BLOB_SCHEMA_ID` associated constant and stopped
  emitting attribute metadata that relied on blob schema coupling.
- Glossary chapter in the book for quick reference to core terminology.
- Expanded the Identifiers chapter with a `local_ids` + `IdOwner` workflow
  example showing how to borrow freshly minted IDs in queries.
- `nth_ancestor` commit selector corresponding to Git's `A~N` syntax and
  documentation updates.
- `parents` commit selector corresponding to Git's `A^@` syntax.
- `INVENTORY.md` file and instructions for recording future work.
- README now links to the corresponding chapters on https://triblespace.github.io/triblespace-rs.
- `Constraint::influence` method for identifying dependent variables.
- Documentation and examples for the repository API.
- Book section showing how to stage and fetch workspace blobs with `Workspace::put`
  and `Workspace::get`.
- Guidance on integrating custom constraints with external data sources in the book.
- Garbage-collection chapter now shows how `BranchStore::branches`, `reachable`,
  and `transfer` work together to enumerate branch roots and traverse blobs in
  practice.
- Clarified the garbage-collection root description to highlight that the
  traversal retains everything reachable from enumerated branch metadata.
- Remote store workflow example in the book showing how to open
  `ObjectStoreRemote` repositories and clarifying that no explicit close is
  required for remote backends.
- `union`, `intersect`, and `difference` commit selectors that expose PATCH set
  operations through the `CommitSelector` interface.
- Documented `TribleSet` set operations and monotonic semantics in the Trible
  Structure chapter.
- Test coverage for `branch_from` and `pull_with_key`.
- Migrated `SuccinctArchive` to new `jerky`/`anybytes` APIs and added
  serializable metadata.
- `_?name` scoped variables for `pattern!`/`pattern_changes!` along with
  documentation and tests demonstrating their use.
- Implemented `ToBlob`/`TryFromBlob` for `SuccinctArchive`, enabling archive
  serialization as a blob.
- `Pile::restore` method to repair piles with trailing corruption.
- Documented zero-length blob support and added tests for empty blob insertion and retrieval.
- `with_sorted_dedup` constructor for universes to build from already sorted,
  deduplicated value sequences.
- Troubleshooting table in the repository workflows chapter covering common
  push, branch, and pull failure modes.
- Book section documenting how to manage multiple signing identities with
  `Repository::set_signing_key`, `Repository::create_branch_with_key`, and
  `Repository::pull_with_key`.
- Reworked Chapter 1 introduction to clarify Trible Space's goals, distinguish
  fixed-width tribles from blob payloads, and guide readers through the rest of
  the book.
- Dedicated "Portability & Common Formats" chapter in the book capturing value
  schemas, identifiers, and conversion guidance, referenced from the `Inline`
  crate docs, and closing out the documentation backlog request to move this
  material out of the API reference.
- Chapter exploring the TribleSpace type algebra linking `attributes!`,
  `entity!`, and query semantics.

### Changed
- Expanded the Pile Blob Metadata chapter with an accurate header field
  breakdown, timestamp conversion example, and details on lazy validation.
- Corrected the BlobMetadata description to state it surfaces the timestamp and
  length fields from the header.
- Expanded the Pile Format chapter with a restore-first operational workflow,
  corrected usage example showing a restore-after-open startup without an
  explicit refresh, and detailed record field breakdowns.
- Clarified that `Pile::restore` already applies intact records before
  truncating and that reader/branch helpers refresh automatically, so manual
  refreshes are only needed when scanning between operations.
- Corrected the PATCH deep-dive chapter so its descriptions of persistence,
  node layout, resizing, and hash maintenance match the implementation.
- Clarified the PATCH deep-dive resizing description to avoid implying growth
  beyond the 256-entry table.
- Clarified the PATCH hash-maintenance discussion so hash comparisons
  short-circuit on matches and walk on mismatches.
- Expanded the deep-dive blobs chapter with guidance on when to use blob
  storage, how handles relate to schemas, and annotated examples.
- Corrected the Trible Structure deep dive to describe how `TribleSet::union`
  mutates its receiver while the other set operations return new views.
- Expanded the deep-dive philosophy chapter with explicit guiding principles,
  clarified how asynchronous backends surface through blocking entry points, and
  grounded the practical implications in the currently available tooling.
- Expanded the Formal Verification roadmap with a stack overview, contributor
  workflow guidance, and milestone tracking suggestions.
- Expanded the garbage-collection chapter with guidance on choosing root sets,
  operational tips, clearer explanations of the conservative traversal, and a
  scan description that matches the implementation (including the fact that the
  walker scans every blob in 32-byte chunks because the store is type-agnostic).
- Reworded the garbage-collection safety-margin tip to emphasize that
  near-impossible hash collisions make extra roots a conservative way to protect
  reachable data.
- Refined the garbage-collection example loop to iterate branch IDs directly
  when collecting roots from `BranchStore::branches`.
- Reworked the documentation improvement chapter with prioritised sections and
  contribution guidance for future book updates.
- Standardised citation formatting in the documentation backlog to match the
  book's reference style.
- Refined the Descriptive Typing chapter with accurate workspace lifecycle
  guidance, corrected `find!` pattern syntax, clearer advice on structuring
  ad-hoc projections and strongly discouraging long-lived typed wrappers,
  updated the
  manager-owned repository DI section to emphasize using short-lived
  `&mut Repository<_>` borrows, handing out task-scoped `&mut Workspace<_>`
  handles, highlighting how multiple mutable workspaces coexist over a
  single repository, clarified that cloning an already-fetched blob is cheap
  compared to the cost of retrieving it from storage, and corrected the
  description of composable clauses so it no longer suggests optional
  attribute matching.
- `json_import` benchmark now publishes separate element- and byte-throughput
  groups, precomputing importer-specific trible counts so Criterion reports
  both perspectives.
- Inlined the JSON importer's trible insertion helper to avoid an extra
  function hop when staging statements.
- Updated both JSON importers to stage objects as `TribleSet`s and have the
  entrypoints union the staged results after validation, removing the
  `PendingJsonObject` scaffolding.
- Inlined the deterministic JSON importer's raw trible helper so hashed
  statements insert without bouncing through an additional function.
- Constructed deterministic JSON importer statements with `Trible::new`
  instead of hand-assembling raw buffers each time a pair flushes.
- Restored the JSON importer's `PrimitiveRoot` error for non-object roots,
  dropped the deterministic importer nil-id guard, and added regression tests
  covering both cases.
- Allowed both JSON importers to accept top-level arrays by returning multiple
  root entities, keeping primitive roots rejected while permitting batches of
  objects.
- Simplified the JSON importer API to return root ids while exposing data and
  metadata via accessors on `JsonObjectImporter`, avoiding an extra wrapper type.
- Simplified JSON importer error diagnostics to avoid tracking JSON paths in
  the hot import loop.
- JSON importers now emit `metadata::name` and `metadata::attr_value_schema`
  tribles when minting attributes so imported datasets carry their own schema
  descriptions.
- Attribute metadata emission now uses the public `entity!` macro so schema
  descriptions are assembled with the same ergonomic syntax exposed to
  consumers.
- Both JSON importers now merge their cached attribute metadata into the
  result set after converting documents instead of inserting metadata entries
  mid-import, keeping the hot path lean while still returning the schema
  descriptors for every derived attribute.
- JSON importers now compute metadata tribles directly from their attribute
  caches at the end of each import, avoiding duplicate metadata storage while
  preserving the descriptors for all derived fields.
- Clarified the importing guide to explain that `metadata()` returns attribute
  descriptors generated from the cached ids after an import completes.
- Documented how deterministic JSON imports collapse repeated subdocuments,
  explaining why they can outperform nondeterministic runs even with cheap ID
  generators.
- JSON importers retain the accumulated tribles inside the importer, exposing
  `data()`/`metadata()` accessors along with `clear_data()` and `clear()` helpers
  so multiple JSON documents can be staged—or reset entirely—before reading the
  results instead of returning a fresh `TribleSet` from each `import_value`
  call.
- Replaced the JSON importer's `anyhow` dependency with a lightweight encoder
  error wrapper so callbacks stay flexible without pulling in extra baggage.
- Dropped the JSON importer's `JsonValueKind` helper and folded the top-level
  type detection directly into the error path to trim unused indirection.
- Parameterized the JSON importer's ID generation so callers can provide
  deterministic sequences via `with_id_generator`, and added a regression test
  covering custom generators.
- Cached JSON importer attributes per field name so repeated values reuse the
  same hashed identifiers without recomputing them.
- Expanded the Schemas chapter with validation examples, clarified how schema
  identifiers power cross-language tooling and deterministic attribute imports,
  outlined schema evolution best practices, and corrected the built-in blob
  schema references for succinct archives.
- Expanded the Incremental Queries chapter with practical guidance on
  preparing delta sets, reusing `TribleSet` set operations, and tying the
  workspace and local-buffer stories together through the shared set
  algebra that powers both workflows.
- Expanded and corrected the Atreides Join chapter with a structured
  walkthrough: it now explains the constraint interface, details the
  Jessica/Paul/Ghanima/Leto heuristic ladder, clarifies what quantity each
  variant estimates, describes the ordering heuristics used by the guided
  search, motivates the worst-case optimal guarantee, and clarifies how
  per-variable estimates are derived in the worked example while tying the
  introduction back to the broader worst-case optimal join literature.
- Macro instrumentation now records the entire span of each invocation in a
  single `source_range` attribute instead of separate line and column values.
- Implemented `ToEncoded<LineLocation>` for `proc_macro::Span` so metadata
  wrappers can hand spans directly to `entity!` without manual tuple
  construction.
- Attribute metadata emission no longer attempts to resolve value/blob schema
  identifiers, sticking to the information reliably available at macro
  expansion time.
- Metadata emission callbacks now receive a mutable context exposing the
  workspace, invocation ID, and tokens so wrapper macros can commit additional
  metadata directly without reopening the repository.
- Metadata emission now commits records to the configured repository branch
  instead of appending raw archives to a standalone pile, aligning the
  instrumentation with the standard storage workflow and renaming the
  environment variable knobs accordingly.
- Regenerated the macro instrumentation attribute identifiers from
  command-line randomness to document their provenance and avoid
  hand-crafted values.
- Metadata instrumentation now reuses the shared hex parsing helpers when
  decoding signing keys and branch identifiers from the environment and
  requires exact hexadecimal strings without a prefix, eliminating bespoke
  sanitization logic in the wrapper crate.
- Reworked the Query Engine chapter to describe the in-search Atreides
  cardinality estimates, clarify how constraints cooperate at runtime, and remove
  references to a nonexistent planner.
- Clarified how the Query Engine search loop derives join variants from
  cardinality heuristics, documented the role of `confirm` inside `and!`, and
  replaced the chapter's query example with a runnable snippet that mixes
  `pattern!` constraints with a `HashSet` filter.
- Updated the architecture overview and trible structure deep dive so they
  describe join ordering as a search-loop choice driven by constraint
  heuristics instead of a separate planner.
- Clarified in the Architecture chapter that blob stores, not repositories, perform
  deduplication of uploaded content.
- Corrected the push/pull arrows in the Architecture diagram to match the actual
  workspace and repository data flow.
- Refined the Architecture diagram and explanation to match
  `Repository::pull`, `Workspace::commit`, and `Repository::try_push`
  responsibilities.
- Reworked the Architecture diagram again to restore the approachable
  workspace overview, clarify the `commit`/`add_blob` interactions, and ensure
  the push arrow flows from the workspace into the repository box.
- Tightened the Architecture diagram so `push/try_push` rises from the
  workspace, `pull` flows back from the repository, and the workspace box now
  highlights concise `commit`/`add_blob` annotations plus a `checkout` link to
  the application layer, then nudged the arrow spacing and arrowheads for
  clearer alignment.
- Re-reviewed the book and codebase to tighten the Glossary definitions:
  clarified how attributes carry their schemas via `attributes!`, explained
  that schemas stay language agnostic instead of binding to Rust types, noted
  that blobs hold archived `TribleSet`s and commit metadata, documented commits
  as `SimpleArchive` blobs with signed metadata, and highlighted identifier
  ownership in the entity entry alongside the existing PATCH description.
- Reorganized the workspace so the new `triblespace` crate exposes the public
  prelude, examples, and documentation while the implementation lives in
  `triblespace-core` with procedural macros in `triblespace-core-macros`,
  enabling future proc-macro crates to depend on the core without cyclic
  dependencies.
- Moved the README regression test and Kani proof harnesses into the
  `triblespace` facade crate so `triblespace-core` stays lean for proc-macro
  consumers while the public API remains thoroughly exercised.
- Expanded Chapter 1 of the book with clearer motivation, reader guidance, and
  an outline of the subsequent chapters. Streamlined the "Why Trible Space
  exists" section so it stays focused on the data-management pains Trible Space
  solves and how pairing blobs with fine-grained facts addresses them, and
  reworded the flexible querying description to show how a single query blends
  trible sets, succinct indexes, and Rust collections such as hash maps.
- Aligned the README regression test with the expanded library conflict resolution walkthrough so documentation stays exercised.
- Regenerated the quick-start alias attribute ID with a CLI-generated value so the README, book, and regression test stay in sync.
- Unified the getting started walkthrough around the library example, showing `push` for automatic retries, `try_push` for manual conflict handling, and updating the README snippet to match.
- Expanded the book's getting started chapter with clearer step-by-step setup,
  execution instructions, and explanations of the repository workflow pieces.
- Restored the README's quick-start example while keeping the expanded
  walkthrough in the getting started chapter so newcomers can skim or dive
  deeper as they prefer.
- Contributor guidelines now require reading the entire `./book` before starting each new task to stay aligned with project concepts.
- `proofs::util::bounded_id` now rejects the nil sentinel with `kani::assume`
  to keep identifier generation unbiased while ensuring exclusivity checks stay
  sound in verification harnesses.
- Expanded the Developing Locally chapter with setup steps, workflow scripts,
  and book rebuild instructions.
- Reconciled the duplicated Query Language edits by combining the reorganised
  introduction, conversion guidance, simplified `ignore!` syntax that always
  captures the surrounding query context while still minting distinct
  temporary variables, richer `or!` and `pattern!` examples, and updated
  regular path query coverage.
- Clarified the regular path example to use `temp!` when hiding an endpoint so
  the traversal still participates in follow-up constraints without projecting
  the hidden binding.
- `ignore!` now always infers its context from `find!`/`exists!`. Use
  [`IgnoreConstraint::new`](https://docs.rs/tribles/latest/tribles/query/ignore/struct.IgnoreConstraint.html)
  directly when building bespoke constraints outside those macros.
- `temp!` now mirrors `ignore!` by taking both the tuple-style binding list and
  the scoped expression, so helper variables introduce their own temporary
  block without wrapping the surrounding query body manually.
- `temp!` no longer accepts explicit type annotations. Hidden bindings never
  project into the result tuple, so their value schemas are inferred entirely
  from how they are used inside the scoped expression.
- Documented `temp!` alongside the other built-in macros in the Query Language
  chapter's constraint table so readers can spot it at a glance.
- Clarified the `ignore!` documentation to highlight that ignored bindings are
  never solved or unified, showing how triple-style constraints can drop unused
  positions while branches that reference only ignored variables never even get
  scheduled.
- Streamlined the `ignore!` partial-projection example by trimming unrelated
  namespace discussion and added an introduction note that highlights how the
  macros wrap the underlying constraint builders for manual use.
- Query Language chapter now gives `or!` its own subsection, calls out
  `_?name` placeholders in `pattern!`/`pattern_changes!` as an alternative to
  `temp!` when hidden helpers stay within a single pattern, clarifies that each
  branch behaves as an independent constraint whose matches are all retained so
  the overall query stays monotonic, documents that all branches must reference
  the same variable set, and notes that mismatches panic at runtime.
- Documented the `.is(...)` constant constraint alongside the other built-in
  operators, added a dedicated subsection showing how to pin bindings,
  highlighted that `pattern!`/`pattern_changes!` already materialise constant
  constraints for literal values, and pointed readers to membership helpers
  such as `.has(...)` when accepting several literals.
- Added `pattern!` and `pattern_changes!` to the built-in constraints table,
  noting that incremental patterns emit only additions and pointing readers to
  the Incremental Queries chapter for the full evaluation workflow.
- Clarified the `has` membership entry so it points to `ContainsConstraint`
  implementors like set-style collections while steering triple sources toward
  `pattern!`.
- Added an "Intersections (`and!`)" subsection to the Query Language chapter
  covering how conjunctions combine clauses, share bindings, and nest within
  other combinators.
- Normalized the Descriptive Typing chapter to use consistent Markdown headings
  and remove unused front matter.
- Re-reviewed the type algebra chapter, linking its claims directly to the
  `Attribute`, `TribleSet`, and query constraint implementations for accuracy.
- Softened the Type Algebra chapter summary to describe the design without
  value-laden language.
- Rephrased the Type Algebra chapter's closing sentence to highlight surface
  simplicity backed by rich type theory.
- Clarified `PATCH::iter_ordered` and `PATCHOrderedIterator` documentation to
  describe the full tree-order traversal without a prefix filter and point to
  the prefix iterator for filtered traversal.
- Reframed the identifiers deep-dive chapter to highlight the abstract/semantic
  and intrinsic/extrinsic axes, expand the embeddings discussion, and provide
  clearer guidance on choosing identifier families.
- Audited the identifier taxonomy guidance to align the RNGID/UFOID/FUCID
  comparison with their implementations and fix crate-qualified links in the
  table.
- Trimmed the Portability & Common Formats chapter by removing the "Why this
  chapter lives in the book" subsection after documenting the move from the
  `Inline` module docs.
- Documented the `path!`, `attributes!`, and `pattern_changes!` procedural
  macros in the `tribles-macros` crate overview.
- `attributes!` procedural macro now resolves the caller's crate path so
  downstream users can depend solely on the `triblespace` facade when
  generating attribute constants.
- Reframed commit range selectors so `start..end` walks from the end selector
  until encountering a commit yielded by the start selector, reducing
  redundant ancestor exploration and making the traversal cost explicit.
- Query Engine chapter now directs readers to the crate-level `pattern!` and
  `entity!` macros and shows how to import them via the prelude.
- Removed the outdated note that parentheses "force" literals in the getting
  started guide now that the macros rely on regular Rust expression syntax for
  literal detection.
- Commit selectors chapter now highlights range semantics, composability, and
  Git parity to help readers choose the right selector for their workflow,
  clarifies that selectors only pick commits while `Workspace::checkout`
  materializes the `TribleSet`, refreshes the composition example to layer
  entity filters over a time range, and shows how to combine selectors with the
  built-in set-operation helpers.
- Pinned `anybytes` and `jerky` to specific git revisions via a crates.io patch
  so all dependents use a single source and API surface.
- Refined the selector debugging guidance to encourage validating each layer
  independently before composing them with the built-in set-operation helpers.
- Documented the trade-off that empty start selectors rewalk the full history,
  and showed how incremental queries can reuse the previous head commit as the
  next range boundary to avoid repeating the walk.
- Corrected the commit selector range description to note inclusive end
  boundaries and clarified that selectors compose via the `CommitSelector`
  trait instead of `IntoIterator`.
- Clarified the commit selector traversal description to avoid implying a
  specific order, fixed the `ancestors(A)..B` exclusion example, and tightened
  the debugging guidance wording.
- Clarified that `find!` retrieves `ExclusiveId` bindings via `TryFromInline` and
  that restricting queries with `local_ids` keeps the conversion safe.
- Getting started guide now demonstrates defining custom attributes alongside
  the quick-start example, hides doc-test-only cleanup, and exercises the
  quick-start snippet as a runnable doc test.
- Updated README and book code samples to use the public `entity!`/`pattern!`
  macros so snippets copy-and-paste outside the crate.
- Updated the README and book examples to use `Repository::create_branch` plus
  `pull` instead of the removed `branch` helper when initializing workspaces.
- Combined the README quick-start and standalone example into one repository
  workflow that stages, queries, and pushes a dataset backed by freshly minted
  `attributes!` definitions instead of the shared literature namespace.
- Updated the release preparation inventory to call out multi-`attributes!`
  module examples instead of cross-namespace guidance.
- Pruned completed 0.6.0 release checklist items (prefix guards, succinct archive parity,
  pile property tests) from the inventory after auditing the codebase.
  - README walkthrough and regression test now commit the staged dataset by value
    instead of cloning it before submission.
  - Updated `SuccinctArchive` to use `BitVectorDataMeta` for prefix bit vectors.

### Fixed
- Reinstated the `InlineEncoding` documentation that notes hash handles still carry
  their referenced blob schema type parameter.
- Updated deterministic JSON importer metadata tests to align with attribute
  metadata now emitting only value schema descriptors.
- Added the missing `blake3` dev-dependency and adjusted the JSON importer
  benchmark to allocate owned strings and convert JSON numbers via
  `f256::from`, restoring the json benchmarks after recent refactors.
- Updated JSON importer benchmarks, core tests, and book snippets to ensure the
  `LongString` generic parameter stays attached to the trait, fixing
  compilation failures introduced by the new benchmark and documentation
  examples. Book snippets now rely on type inference for `to_blob()` to match
  idiomatic usage.
- Corrected the JSON import benchmark to use the re-exported
  `inlineencodings::Blake3` handle schema so it compiles again.
- Added the missing `serde_json` and `f256` dev-dependencies so the JSON import
  benchmark builds successfully.
- Buffered the JSON importers so encoding errors roll back an entire import
  instead of leaving partially imported tribles in the accumulated set.
- Routed the JSON importer staging helpers through a shared temporary
  `TribleSet` so field emitters avoid building intermediate sets before the
  batch commits.
- Updated the procedural macros to resolve either the `triblespace-core` or
  `triblespace` crate path automatically so downstream users can rely on the
  facade crate without declaring extra dependencies.
- `SuccinctArchive` now derives domain metadata via `Serializable` instead of storing raw handles.
- `SuccinctArchive` now retains a handle to a contiguous byte area so blob serialization clones the underlying bytes without rebuilding.
- Simplified blob deserialization by reading archive metadata via `Bytes::view_suffix`.
- `SuccinctArchive`'s `Serializable` implementation now reports concrete
  `jerky::error::Error` values instead of relying on `anyhow`.
- Removed the custom empty `WaveletMatrix` metadata workaround now that the
  builder accepts zero-length sequences.
- `SuccinctArchive::from` now seeds wavelet matrices without guarding against
  empty archives because the builder handles zero-length iterators.
- Verified the wavelet-matrix builder path against empty archives via
  `./scripts/preflight.sh` after the jerky upgrade.
- `OrderedUniverse` now stores values as `View<[RawInline]>` for zero-copy access.
- Simplified `OrderedUniverse::with_sorted_dedup` to always collect incoming
  values before writing them into the reserved section, avoiding reliance on
  unstable iterator detection.
- Universes now allocate their own byte sections via a `SectionWriter`, so callers only pass an iterator. `CompressedUniverse::with` no longer clones its values.
- `SuccinctArchive` constructs universes with `with_sorted_dedup`, avoiding an extra sort/dedup pass when the caller already guarantees ordering.
- Updated the repository workflow documentation to use `Repository::create_branch`
  and provide a runnable blob staging example.
- Expanded the repository workflows chapter with an overview of repository
  initialization, branching conventions, and guidance on choosing between
  `push` and `try_push`.
- Getting started guide now highlights the need to close pile-backed repositories so callers can handle flush errors explicitly.
- README example now inlines the shared `tribles::examples::literature` namespace so the getting started walkthrough and crate examples stay aligned without depending on internal modules.
- README walkthrough and regression test keep the namespace name `literature` to match the shared example module.
- `with_sorted_dedup` now accepts iterators so compressed universes can build domains without materializing values.
- `SuccinctArchiveMeta` now accepts the domain's serialized metadata type,
  removing its hardcoded `SectionHandle<RawInline>` dependency.
- Architecture chapter now explains the system layers, copy-on-write behaviour,
  and how repositories coordinate blob and branch stores.
- `SuccinctArchiveMeta` bounds metadata types with jerky's `Metadata` marker
  to guarantee zero-copy-safe layouts.
- `CompressedUniverse` now relies solely on jerky's `DacsByte` and a section-
  backed fragment table, enabling fully zero-copy serialization via
  `Serializable`.
- Documented that branch updates do not ensure referenced blobs exist, enabling
  piles to serve as head-only stores.
- Clarified repository workflow docs with a sidebar highlighting
  `repo::transfer` alongside `BlobStoreKeep::keep`, including
  garbage-collection scenarios that only copy live blobs.
- Removed the suggested branch conventions subsection from the repository
  workflows chapter so the page concentrates on API behavior and storage
  guidance.
- Clarified that multiple pile writers require filesystems with atomic append
  semantics; noted unsupported filesystems in documentation.
- Streamlined the merge troubleshooting note to highlight
  `MergeError::DifferentRepos` and the `reachable` + `repo::transfer` steps for
  cross-repository merges.
- Documented the pile as a write-ahead log database ("WAL-as-a-DB").
- Rewrote the pile blob metadata chapter to describe the `BlobMetadata`
  API and linked it from the pile format documentation.
- Documented that the pile is an immutable append-only log: only the un-applied tail is validated and mutating existing data is undefined behavior.
- Removed in-flight blob tracking. `Pile::put` now holds a shared lock,
  refreshes before writing, then reads back its blob with `apply_next` to ensure
  it was indexed. `Pile::update` similarly verifies the written branch record
  using `apply_next` under its exclusive lock.
- `Pile::close` now consumes the pile and manually drops its fields to bypass
    `Drop`, which always warns when a pile is not explicitly closed.
- `Pile::close` now drops all fields before returning the result of `flush`,
  ensuring resources are cleaned up even if flushing fails.
- `Pile::refresh` now aborts if the pile file shrinks below data already
  applied, guarding against truncated data.
- Documented that truncation below `applied_length` invalidates previously
  issued `Bytes`, so only the un-applied tail is checked for corruption and
  shrinkage into validated data requires aborting.
- Clarified that shrinkage into already applied data triggers an immediate
  process abort to avoid undefined behavior from dangling `Bytes` handles.
- `Pile::refresh` acquires a shared file lock while scanning to avoid races with
  `restore` truncating the file.
- `Pile::restore` truncates the pile without rescanning after truncation,
  removing a redundant refresh pass.
- `Pile::refresh` uses a simple `insert` for new blob index entries.
- `Pile::update` no longer flushes or `sync_all`s automatically; callers must
    invoke `flush()` for durability.
- `Pile::open` now returns an empty handle without scanning the file. Call
  `refresh` to load existing data or `restore` to repair corruption. The
  `try_open` helper was removed.
- Additional unit tests for `Pile` blob iteration, metadata, and conflict handling.
- `Workspace::checkout` helper to load commit contents.
- Documentation and example for incremental queries using `pattern_changes!`
  plus additional tests.
- `pattern!` now implemented as a procedural macro in the new `tribles-macros` crate.
- Regression test ensuring `PATCHOrderedIterator` returns keys in sorted order.
- `entity!` now implemented as a procedural macro alongside `pattern!`.
- `ThompsonEngine` implementing a new `PathEngine` trait for regular path queries,
  and `RegularPathConstraint` is now generic over `PathEngine`.
- `reachable` iterator, `transfer` helper, and `potential_handles` expose the
  conservative blob traversal for composition. `BlobStoreKeep::keep` and
  `MemoryBlobStore::keep` now retain blobs by handle iterators.
- Implemented `size_hint`, `ExactSizeIterator`, and `FusedIterator` for `PATCHIterator` and `PATCHOrderedIterator`.
- Compile-time check restricting builds to 64-bit little-endian targets.
- `PileReader` now reconstructs blob data from the underlying memory map,
  and `IndexEntry::Stored` tracks offsets and lengths instead of holding `Bytes` directly.
- Regression test ensures `PATCH::iter_ordered` yields canonically ordered keys.
- `PATCH::replace` method replaces existing keys without removing/ reinserting.

### Fixed
- Corrected the repository workflow documentation to describe the actual
  `Repository::push` and `Repository::try_push` return values and clarify that
  remote backends expose a no-op `repo.close()`.
- Corrected the `PATCHOrderedIterator` documentation to describe its
  lexicographic key-order traversal instead of prefix iteration.
- Restored `_?ident` locals in `pattern!`/`pattern_changes!` to infer their
  value schema from usage instead of forcing `GenId`, so scoped bindings work on
  non-`GenId` attributes again.
- Resolved hygiene issues in `pattern!`/`pattern_changes!` so user bindings like
  `__ctx` no longer collide with generated identifiers, and added trybuild
  coverage to prevent regressions.
- Corrected the blob book example to import the repository module via `tribles::repo`.
- Removed an unused `anyhow` import from the succinct archive schema.
- `SuccinctArchive::from` now handles empty `TribleSet`s and returns an
  empty archive instead of panicking.
- `CachedUniverse::search` avoids underflow when querying an empty universe.
- Opening excessively large piles now returns an error instead of panicking when calculating the mapped size.
- Regression tests verify blob bytes remain intact after branch updates and across flushes.
- `PileReader::metadata` now validates blob contents and returns `None` for corrupted blobs.
- `PileBlobStoreIter` now lazily verifies blob hashes and reports errors for invalid blobs.
- `PileBlobStoreIter` now skips missing index entries instead of ending iteration silently.
- `Pile::flush` now calls `sync_all` to persist file metadata and prevent
  potential data loss after crashes.
- `Pile::restore` now syncs the file after truncation to ensure durability.
- `Pile` requires explicit closure via `close()`; dropping without closing emits a warning.
- Debug helpers `EstimateOverrideConstraint` and `DebugConstraint` moved to a new
  `debug` module.
- Debug-only `debug_branch_fill` method computes average PATCH branch fill
  percentages by node size.
- Added a simple `patch` benchmark filling the tree with fake data and printing
  branch occupancy averages.
- Trible key segmentation and ordering tables are now generated from a
  declarative segment layout, simplifying maintenance.
- Deterministic proptest simulation tests cover multi-reader and writer pile
  operation sequences via actor-scheduled operations.
- Simulation now exercises branch updates, branch listing, and fetching
  previously stored blobs and branch heads for comprehensive pile coverage.
- Additional pile unit tests exercising branch conflicts and size limits.
- Additional unit tests cover pile blob metadata, iteration, and branch update
  conflicts.
- Additional unit tests covering pile deduplication, metadata, and branch
  update conflicts.

- `Pile` no longer requires a compile-time size limit, grows its mmap on demand,
  and `ReadError::PileTooLarge` was removed.
- Initial pile mapping now uses a page-sized (×1024) base to avoid frequent remaps.
- Mapping size now derives from the mmap length instead of an internal counter.
- Replaced fs4 with Rust std file-locking APIs.
- Declared Rust 1.89 as the minimum supported toolchain.
- Dropped the inventory item about validating externally appended blobs during
  `refresh`; blob data is verified lazily on read.
- `refresh` replaces invalid blob entries with newer candidates and verifies
  unknown duplicates before deciding whether to keep or replace them.
- `refresh` now uses `get_or_init` to compute blob validation state and
  replace invalid duplicates.
- Simplified `refresh` padding logic by using `padding_for_blob` to compute blob alignment.
- `BlobStore::reader` now returns a `Result` so implementations can signal errors during reader creation.
- Renamed pile read errors from `OpenError` to `ReadError` since they can surface during refresh.
- PATCH exposes const helpers to derive segment maps and ordering
  permutations from a declarative key layout.
- `Entry` now supports an optional value via `with_value`, preparing `PATCH`
  for key-value mappings.
- Set semantics now use the zero-sized unit `()` value instead of a dummy
  byte to avoid extra storage.
- `PATCH::get` retrieves the value associated with a key, if present.
- `Leaf` stores the associated value and `PATCH`/`Head`/`Branch` now carry a
  value type parameter so keys can map to arbitrary payloads.
- Moved the value type parameter to the end of generic parameter lists for a
  more ergonomic `PATCH<KEY_LEN, Order, Inline>` API.
- Documented that hashing and equality ignore leaf values and added a
  regression test verifying patches with identical keys but different values
  compare equal.
- Introduced `key_segmentation!` and `key_schema!` macros to emit
  `KeySegmentation` and `KeySchema` implementations from those declarative
  layouts.
- Added `byte_table_resize_benchmark` measuring average fill ratios that cause
  growth for random vs sequential inserts. It now tracks the number of elements
  inserted at each power-of-two table size to compute per-size and overall
  averages over many random runs.
- Preallocated the resize counts vector to avoid repeated allocations during
  the benchmark.
- Per-size results now include sizes that never triggered growth so the output
  has no gaps.
- Documented PATCH's cuckoo-hashing compression as an alternative to ART-style
  node compression, explained its compressed-permutation hash with an identity
  first permutation and a random second permutation and why the smallest and
  largest nodes are always fully occupied, and included benchmark fill ratios in
  the book.
- Annotated the benchmark output to highlight path compression in the size-two
  case and that the identity hash lets 256-ary nodes store all 256 children.
- `entity!` subsumes the old `entity_inner!` helper; macro invocations can
  optionally provide an existing `TribleSet`.
- Procedural `namespace!` macro replaces the declarative `NS!` implementation.
- Implemented a procedural `delta!` macro for incremental query support.
- Expanded documentation for the `pattern` procedural macro to ease maintenance, including detailed comments inside the implementation.
- Expanded Query Language chapter with iterator examples and clarified that
  `ignore!` removes the named variables from planning while the scoped bindings
  still unify inside the ignored expression, making it easy to drop value
  columns from multi-position constraints without losing the join on the
  remaining variables.
- `EntityId` variants renamed to `Var` and `Lit` for consistency with field patterns.
- `Workspace::checkout` now accepts commit ranges for convenient history queries.
- Git-based terminology notes in the repository guide and a clearer workspace example.
- Expanded the repository example to store actual data and simplified the conflict loop.
- Failing test `ns_local_ids_bad_estimates_panics` shows mis-ordered variables return no results when a panic is expected.
- Diagram and explanation of six trible permutations and shared leaves for skew‑resistant joins.
- Additional example in the Commit Selectors chapter demonstrating how to
  compose `filter` with `time_range`.
### Changed
- `Branch::upsert_child` now always refreshes `childleaf`, removing the `replaced_leafchild` check.
- Blob index now uses value-aware `PATCH` for cheap reader clones.
- Inlined `refresh_range` logic into `refresh`, removing the partial-range helper.
- Blob appends now issue a single `write_vectored` `O_APPEND` call to stream header, data and padding without extra copies or retries.
- Simplified vectored blob appends by always including a padding slice.
- Branch updates now perform `flush → refresh → lock → refresh → append → unlock` directly instead of queuing.
- Branch headers are written with a single `write` call to avoid partial updates.
- Max-size checks and mmap offsets now derive from the file's actual length instead of tracked counters.
- Restored an `applied_length` tracker to incrementally refresh new blobs and branches without rescanning the entire pile.
- Blob inserts now compare the write start with the previous `applied_length`, ingesting any intervening records before advancing.
- `refresh` now uses the same framing parser as `try_open` to detect truncated or malformed records while deferring blob hash checks to reads.
- `try_open` now reuses `refresh` for log scanning, unifying corruption checks.
- `succinctarchive` schema is now gated behind an optional `succinct-archive`
  feature until it aligns with upstream `jerky` APIs.
- `refresh` retains existing blob entries when encountering duplicates instead of
  replacing validated records.
- `refresh` now uses `PATCH::replace` to update blob entries without explicit remove/insert.
- Expanded commit selector documentation with an overview, example and clearer
  wording about loading commits from a workspace.
- Temporarily gate the `SuccinctArchive` schema behind a feature to restore
  compilation while its Jerky dependency is updated.
- Expanded repository workflows chapter with clearer branching steps and a
  dedicated history section.
- Expanded Schemas chapter with additional context on schema identifiers and runtime lookup.
- Renamed `mask!` macro to `ignore!` for clarity.
- Expanded the Atreides Join chapter with an example, clearer algorithm explanations, and a note that random access remains only for confirming candidates.
- Rephrased Atreides Join discussion of sorted indexes to highlight efficient value lookup.
- Gave each Atreides join variant a descriptive name alongside its Dune nickname.
- Clarified the query engine book chapter with improved wording and examples.
- Expanded discussion on RDF's per-value typing limitations in the query engine chapter.
- Expanded Architecture chapter's blob storage section for clearer responsibilities and examples.
- Expanded the "Developing Locally" book chapter with guidance on helper scripts and local setup.
- Expanded the "Getting Started" book section with dependency setup and run instructions.
- PATCH infix and segment-length operations now require prefixes to align with
  segment boundaries.
- `KeySchema` and `KeySegmentation` now expose translation tables as associated const arrays instead of methods.
- Removed `key_index`, `tree_index`, and `segment` helper methods in favor of direct const-table lookups and tied `KeySchema` to its `KeySegmentation` with an explicit segment permutation.
- `KeySchema` now declares its `KeySegmentation` via an associated type instead of a separate generic parameter.
- Renamed `KeyOrdering` trait and `key_ordering!` macro to `KeySchema` and `key_schema!` for clearer terminology.
- Blob writes are now synchronous; `put` records an `InFlight` entry so repeated writes of the same blob are deduplicated until a refresh.
- Pile size limits are enforced during `refresh` rather than on each write.
- `ByteTable` plans insertions by recursively seeking a free slot and shifts entries only after a path is found, returning the entry on failure so callers can grow the table.
- ByteTable's planner tracks visited keys with a stack-allocated bitset to avoid heap allocations.
- Simplified the planner and table helpers for clearer ByteTable insertion code.
- Replaced redundant option check with an `expect` when traversing full buckets in
  the ByteTable planner.
- Restored the simpler `ByteSet` and inlined bucket checks to reduce indirection in the planner.
- Removed the reified `ByteBucket` abstraction and indexed buckets directly in the byte table.
- `ByteSet` now stores raw `[u128; 2]` bitsets instead of relying on `VariableSet`.
- Detailed query engine documentation moved from the `query` module to the book, leaving a concise overview in code.
- Moved verbose inline documentation for Pile, Trible, Blob and PATCH modules
  into the book.
- Expanded Trible Structure deep-dive with design rationale and advantages
  previously kept inline.
- Added remaining rationale from the blob, patch, pile and schema docs to the
  corresponding book chapters so code comments stay concise without losing
  detail.
- Expanded the incremental queries chapter with step-by-step delta evaluation
  and clearer `pattern_changes!` guidance.
- Refined the book's introduction with a clearer overview of Trible Space and
  its flexible, lightweight query engine, plus links to later chapters.
- Simplified blob length handling in `Pile::refresh` by relying on
  `take_prefix`'s implicit bounds checking.
### Removed
- `nth_parent` commit selector and helper; parent-numbering is not planned.
- Unused `crossbeam-channel` dependency.
### Fixed
- Detect oversized blob headers whose declared length exceeds the file size.
- Restored atomic vectored blob appends and single-call branch writes; errors
  if any bytes are missing.
- Removed duplicate `succinct-archive` feature declarations that prevented
  builds.
- Corrected blob offsets in `Pile` so retrieved blobs no longer include headers or
  branch records.
- Scheduled branch writes through the pile's write handle to avoid orphaned
  branch heads when crashes occur before pending blobs flush.
- Applied branch head updates immediately and sized branch records using
  `size_of` to preserve compare-and-swap semantics without magic numbers.
- Fixed compiler warnings by clarifying lifetime elision and ignoring
  generated imports when unused.
- Removed remaining 64-byte assumptions from blob writes by computing header
  length and padding with `size_of::<BlobHeader>()`.
- `ignore!` now hides variables correctly by subtracting them from inner constraints.
- ByteTable resize benchmark now reports load factor for fully populated 256-slot tables.
- `PatchIdConstraint` incorrectly used 32-byte values when confirming IDs, causing
  `local_ids` queries to return no results with overridden estimates.
- Documentation proposal for exposing blob metadata through the `Pile` API.
- Branch updates now sync branch headers to disk to avoid losing branch pointers after crashes.
- `IndexEntry` now stores a timestamp for each blob. `PileReader::metadata`
  returns this timestamp along with the blob length.
- Design notes for a conservative garbage collection mechanism that scans
  `SimpleArchive` values in place to find reachable handles.
- Clarified that accidental collisions are practically impossible given 32-byte
  hashes, explaining why the collector can treat any matching value as a real
  reference.
- Expanded the book's garbage collection chapter with clearer reachability
  description, traversal overview and handle-based pruning.
- Repository workflows chapter covering branching, merging, CLI usage and an improved push/merge diagram.
- Separate `verify.sh` script for running Kani verification.
- Documented conflict resolution loop and clarified that returned workspaces
  contain updated metadata which must be pushed.
- Explained BranchStore's CAS-based optimistic concurrency control in the
  repository guide.
- Property tests for `ufoid` randomness and timestamp rollover.
- Further clarified `timestamp_distance` documentation that it only works with
- Documentation for built-in schemas and how to create your own.
  timestamps younger than the ~50-day rollover period.
- Added `HybridStore` to combine separate blob and branch stores.
- Added tests for the `ObjectStoreRemote` repository using the in-memory
  object store backend.
- Implemented `Debug` for `ObjectStoreRemote` and replaced `panic!` calls
  with `.expect()` in object store tests.
- Initial scaffold for a narrative "Tribles Book" documentation.
- Build script `build_book.sh` and CI workflow to publish the mdBook.
- Expanded the introduction and philosophy sections of the Tribles Book and
  documented how to install `mdbook`.
- Documented the pile file format in the book and expanded it with design rationale.
- Expanded the pile format chapter with recovery notes and a link to the `Pile` API docs.
- Added a book chapter describing the `find!` query language, listed
   built-in constraints, and included a reusable sample dataset for
   documentation examples.
- Added an architecture chapter that explains how `TribleSet` differs from the repository layer and details branch stores and commit flow. The diagram now better illustrates the commit flow.
- Added a "Developing Locally" chapter and linked it from the README and book introduction.
- Expanded the architecture chapter with design goals, semantic background and
  cross-references to other chapters.
- Clarified that the branch store's compare-and-set operation is the only
  place-oriented update, leaving the rest of the system value oriented and
  immutable.
- Documented the incremental query plan in `INVENTORY.md` and linked it
  to a new "Incremental Queries" book chapter detailing the approach.
- Noted that namespaces will expose a `delta!` operator, similar to
  `pattern!`, for expressing changes between `TribleSet`s. The macro
  computes the difference and uses `union!` internally to apply the
  delta constraint.
 - Documented potential commit selector redesign using git-style
   reachability semantics. Added a "Commit Selectors" design note with
    a table comparing Git syntax to the planned set-based API. The table
    is now exhaustive for Git's revision grammar, using only the general
    forms. Each entry links to the official documentation and marks
    selectors that are not planned for the initial implementation.
- Noted plans for a `delta!` operator to assist with incremental
  queries. Documentation describes how it will union patterns with
  each triple constrained to the dataset delta.
- Recorded a future task to generate namespaces from a TribleSet
  description and to rewrite `pattern!` as a procedural macro.
- Documented the internal `pattern_inner!` macro with expanded usage notes.
- Added inline comments for every `pattern_inner!` rule describing what it
  matches and why.
- Added a "PATCH" chapter to the book's deep dive section explaining the trie
  implementation.
- Recorded tasks to benchmark PATCH, analyze its algorithmic complexity and
  measure real-world space usage.
- Listed candidate built-in schemas with design notes in `INVENTORY.md` for
  future implementation.
- Documented commit range semantics explaining that `a..b` equals
  `ancestors(b) - ancestors(a)` with missing endpoints defaulting to an empty set
  and the current `HEAD`.
- Commits now record a `timestamp` using `NsTAIInterval` and workspaces provide a
  `TimeRange` selector to gather commits between two instants.
- Compressed zero-copy archives are now complete.
- Incremental queries use a new `pattern_changes!` macro.
- Added an `exists!` macro (formerly `matches!`) mirroring `find!` for boolean checks.
- Regular path queries via a new `RegularPathConstraint` and namespaced `path!` macro.
- `path!` automata now store transitions in a `PATCH` for efficient lookups and set operations.
- Added a `filter` commit selector with a `history_of` helper.

### Changed
- Switched `anybytes` to a git dependency and used its `Bytes` integration
  to avoid copying blob data when writing to object stores.
- README no longer labels compressed zero-copy archives as WIP.
- Switched from `sucds` to `jerky` for succinct data structures and reworked
  compressed archives to use it directly.
- Construct archive prefix bit vectors using `BitVectorBuilder::from_bit`.
- Removed completed tasks from `INVENTORY.md` and recorded them here.
- Removed the experimental `delta!` macro implementation; incremental
  query support will be revisited once `pattern!` becomes a procedural
  macro.
- Split branch lookup tests into independent cases for better readability.
- `Repository::checkout` was renamed to `pull` for symmetry with `push`.
- `IntoCheckoutRange` trait became `CommitSelector` and its `into_vec` method
  was renamed to `select`.
- Updated bucket handling to advance RNG state in `bucket_shove_random_slot`.
- Clarified need for duplicate `bucket_get_slot` check in `table_get_slot`.
- Replaced Elias--Fano arrays in `SuccinctArchive` with bit vectors for
  simpler builds and equivalent query performance.
- `SuccinctArchive` now counts distinct component pairs using bitsets,
  improving query estimation accuracy.
- Domain enumeration skips empty identifiers via `select0` and prefix bit
  vectors are constructed with `BitVector` for lower memory overhead.
- Improved `Debug` output for `Query` to show search state and bindings.
- Replaced branch allocation code with `Layout::from_size_align_unchecked`.
- Removed unused `FromBlob` and `TryToBlob` traits and updated documentation.
- Documented how `MemoryBlobStore::insert` deduplicates blobs by handle in the
  deep dive chapter.
- Simplified constant comparison in query tests.
- `pattern!` now reuses attribute variables for identical field names.
- Clarified that the project's developer experience goal also includes
  providing an intuitive API for library users.
- Renamed the `delta!` macro to `pattern_changes!` and changed its
  signature to `(current, changes, [pattern])` assuming the caller
  computes the delta set.
- Documented Kani proof guidelines to avoid constants and prefer
  `kani::any()` or bounded constructors for nondeterministic inputs.
- Fixed Kani playback build errors by using `dst_len` to access `child_table`
  length without implicit autorefs.
- Introduced `InlineEncoding::validate` to verify raw value bit patterns.
- Query and value harnesses use this to avoid invalid `ShortString` data during playback.
- `InlineEncoding::validate` now returns a `Result` and `Inline::is_valid` provides
  a convenient boolean check.
- Corrected the workspace example to merge conflicts into the returned workspace
  and push that result.
- `preflight.sh` now only checks formatting and runs tests; Kani proofs run via `verify.sh`.
- Removed instruction to report unrelated Kani failures in PRs.
- Added missing documentation for several public structs and functions in
  `blob` and `repo` modules.
- Expanded the descriptions to clarify usage of public repository APIs.
- Moved repository and pile guides into module documentation and updated README links.
- Simplified toolchain setup. Scripts install `rustfmt` and `cargo-kani` via
  `cargo install` and rely on the system's default toolchain.
- Depend on the crates.io release `hifitime` 4.1.2 instead of the git repository.
- Added a README "Getting Started" section demonstrating `cargo add tribles` and
  a pile-backed repository example.
- Documented iteration order of `MemoryBlobStoreReader`, noted workspace use of
  `MemoryBlobStore::new` and improved `Pile::try_open` description.
- Restricted `PileSwap` and `PileAux` to crate visibility.
- Repository guidelines now discourage asynchronous code in favor of
  synchronous implementations that can be parallelized.
- Renamed `ObjectStoreRepo` to `ObjectStoreRemote` in the object-store backend.
- Listing iterators for the object-store backend now stream directly from the
  underlying store instead of collecting results in memory.
- `Repository::push` now returns `Option<Workspace>` instead of the custom
  `RepoPushResult` enum, simplifying conflict handling.
- Split identifier and trible structure discussions into dedicated deep-dive book chapters.
- `preflight.sh` now verifies that the mdBook documentation builds successfully.
- Fixed book `SUMMARY.md` so preflight passes without parse errors.
- `Workspace` now exposes a `put` method for adding blobs, replacing the old
  `add_blob` helper. The method returns the stored blob's handle directly since
  the underlying store cannot fail.
- `Workspace::get` method retrieves blobs from the local store and falls back to
  the base store when needed.
- `ReadError` now implements `std::error::Error` and provides clearer messages when opening piles.
- Removed the `..=` commit range selector. The `..` selector now follows Git's
  semantics and excludes the starting commit.
- Extracted `collect_range` into a standalone function for clarity.
- Moved `first_parent` into a standalone function for clarity.
- Added a `collect_reachable` helper to gather all commits reachable from a
  starting point.
- Scalar commit selectors once again return only the specified commit.
- Introduced an `ancestors` selector to retrieve a commit and its history.
- Commit selectors now return a `CommitSet` patch of commit handles instead of a `Vec`.
- Renamed the `CommitPatch` type alias to `CommitSet`.
- The `..` commit selector now walks from the end boundary until it encounters
  a commit returned by the start selector. To reproduce Git's set-difference
  semantics, wrap the boundary explicitly as `ancestors(start)..end`.
- Added a `symmetric_diff` selector corresponding to Git's `A...B` three-dot
  syntax.
- Refined candidate built-in schemas in `INVENTORY.md`; removed `Bool`, the
  `BinaryLargeObject` placeholder, and the 64-bit integer types.
- Expanded the built-in schema ideas with a fuller list of value and blob
  formats to explore.
- Brainstormed an even broader range of potential schemas for long-term
  consideration.
- Added Lance, neural-network, vector-search and full-text index formats to the
  candidate blob schemas, with a note to favor memory-mapped Rust crates.
- Trimmed the candidate schemas, dropping seldom-used formats like neural
  networks, search indexes, media and font types.
- Reinstated the neural-network, HNSW and full-text index schema ideas and
  removed the tar/zip archive formats.
- Added `SocketAddr` and `RgbaColor` value types alongside a `CompressedBlob`
  wrapper, while dropping `DateYMD` and `TimeOfDay` from consideration.
- `RangeFrom` now returns `ancestors(head)` minus `ancestors(start)` while
  `..c` selects `ancestors(c)` and `..` resolves to `ancestors(head)`. The old
  `collect_range` and `first_parent` helpers were removed.
- `TimeRange` commit selector now delegates to the generic `filter` selector.
- Removed the `Completed Work` section from `INVENTORY.md`; finished tasks are
  now tracked in this changelog.
- Canonicalized epsilon closures in regular path queries and documented the
  Thompson-style automaton construction.
- Documented the currently implemented commit selectors in the book.

### Fixed
- Enforce `PREFIX_LEN <= KEY_LEN` for prefix checks in PATCH.
- Release file locks if `refresh` fails during pile branch updates to avoid lingering locks.
- Blob insertion now returns an error instead of panicking if the system clock goes backwards.
- Delay branch map updates until after branch records are written to disk, preventing divergence when writes fail.

## [0.5.2] - 2025-06-30
### Added
- Initial changelog file.
- Repository guidelines now require documenting tasks in `CHANGELOG.md`.
- Converted object-store backend to `BranchStore`/`BlobStore` API.
