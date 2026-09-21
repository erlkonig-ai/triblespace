# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `ensure_derived`, `maintain_derived` and `upkeep_derived` are now
  `ensure_downstream`, `maintain_downstream` and `upkeep_downstream`.
  `derived` names what a collection *is*; `downstream` names where it sits
  relative to the one you asked about, which is what these functions walk.
  Naming them by direction makes the pair visible and the missing member
  obvious: under the old names `maintain_derived` had no upstream counterpart
  and nobody noticed. `seed_derived` keeps its name, because it names the kind
  of collection it registers rather than a direction of travel.

- Reads select from the coverage index, as maintenance does. `collection`
  attaches the target's frontier from the index -- widest node first, a node
  whose bytes are here taken, a node whose bytes are not descended through
  the MERGE that produced it -- and its support is the union of what those
  nodes stand for, read from the same index in the same selection. A target
  the fold has nothing for stands for nothing until its records are
  admitted; a target whose source descriptor is not resident is a
  `MissingDependency`. Gone with the walk: the record-walk fallback behind
  `collection`, the per-record certificates (`record_certificate`,
  `structural_certificate`, `CollectionRealizationError::IncompleteSupport`),
  the semantic re-resolution behind `Cover::available`, `Cover::materialize`
  and `Cover::commits` (the whole `collection::resolution` module:
  `CollectionSemantics`, `resolve_collection_semantics`,
  `CollectionFunctionalConflict`, `CollectionValidationRequest`,
  `CollectionClaimValidation`, `CollectionResolutionError`), record
  discovery (`DiscoveredCollectionRecords` and every `discover_*` function;
  `CollectionDiscoveryError` stays, with only its `Records` variant, as the
  error of the generation and migration walks), and the witness walk behind
  the unsigned-equation migration (`admitted_record_witnesses`,
  `preview_record_witnesses`). `Collection::admitted` reads the index: the
  union of what the collection's frontier stands for, resident or not, as
  `Result<Cover, S::RecordsError>` for any `StoreRead`. `Collection::read`
  returns `CollectionReadError<GetError, ViewError>` -- the attach error or
  the view error; `CollectionMaterializationError`, `CollectionCoverError`,
  `CoverAvailabilityError` and `FactMaterializationError` are gone.

- `CollectionRead::collections`, required on every record reader: every
  collection at least one known record names, read from the record index's
  first segment on a pile and never by enumerating records. Composite readers
  forward or union it; in-memory test stores read it off their values.

- `collection::derived`: the collections derived from a source, found from
  their descriptors. `derived_from` lists them each after its own source, one
  descriptor read per known collection and no record walk. `ensure_derived`
  realizes every one's missing images and publishes no merge, so a write that
  calls it after its commit leaves the commit readable through every view at
  the cost of that commit's own images; `maintain_derived` carries each to
  its LSM fixed point, as a daemon does. A `RealizeDerived` realizer maps a
  descriptor's representation to a typed `ensure` or `maintain`; `CoreRealizer`
  knows this crate's encodings and a binary with more wraps it. The report
  names what was realized, what the signer may not write, and what no
  realizer knows; nothing is guessed and nothing decides what is too costly.
  A derived collection joins the listing with its first record, so whoever
  creates one ensures it right then, for the commits already there.

- `join_images` on `CollectionDerivation` and `CollectionMapping` no longer
  takes a source union; it is the mapping's own route for joining two
  images, defaulting to the encoding's `join_members`. The Rank9 route that
  reused the raw union's bytes is gone, with the `source_union` parameter of
  the archive merge. A source merge is mirrored by joining the two images
  and recording `MERGE(image a, image b) -> image c` beside `DERIVE(c ->
  image c)`, true by the homomorphism law; the merged source node is neither
  read nor required to be resident, and the source frontier comes from the
  index. The carry's absorbing merge takes the pairwise form whenever
  exactly the two dominated images stand for their dominator. Rank9's tier
  carry joins now instead of declining.

- Remove the exact collection API. `ensure_exact`, `ensure_exact_with`,
  `maintain_exact`, `maintain_exact_with` and `collection_exact` are gone,
  and `CollectionRealization::ensure`/`maintain` take no support. A derived
  target stands for what its source's frontier stands for, a root for what
  its admitted commits say, and `collection` attaches what a target stands
  on; two derived views of one source attached from one snapshot agree by
  construction. Gone with the request: the lattice-granularity closure,
  explicit root members without an admitted COMMIT, the functional check on
  conflicting images (a diagnostic now), and the structural-certificate
  fallback for a target whose source writer is not admitted locally.
  Derived ensure asks for absent source nodes it needs before giving up.

- Plan maintenance from the coverage index. The new `collection::maintenance`
  module replaces the per-round semantic probes (`probe_mapping`,
  `resolve_target`, `witnessed_physical_cover`, `source_residual`,
  `coarsen_from_resident_source`, `attach_exact_resolution`) and the old
  `exact_target_compaction` carry. A *selection* reads what a collection
  stands on for a request straight from the frontier, widest node first,
  and descends through a node's MERGE producers (one produced-member
  lookup) only when the node is wider than the request, absent, incomplete,
  or refused by the mapping; the same descent is the capacity fallback to
  finer inputs. Requests are compared at lattice granularity, the closure
  of the requested rows. A target holding attestations the fold could not
  drive falls back to structural certificates from its own admitted records,
  as reads do. The functional check stays: two admitted images for one input
  is a `Resolution` error. `resolve_endorsed_lineage` remains only behind
  `admitted_record_witnesses`.

- Carry by support size. Tiers are keyed by `ilog2` of a node's support, not
  its byte length, so a target's tiers mirror its source's. Before pairing,
  a frontier node whose support lies inside another's is consumed by
  `MERGE(fine, coarse -> coarse)`, no bytes loaded, so the redundancy between
  a fine image and the coarser one that covers it disappears in the fold
  instead of being coarsened at every read; two nodes with one support keep
  the lower node, as readers do. Source-guided coarsening is kept for the
  joins that need the source union (Rank9): exactly two images under a
  source node that together stand for it are joined with the union in hand.

- An acquisition ends the operation. `ensure_with`, `maintain_with` and the
  root ensure no longer freeze one control snapshot and then fetch through
  it: `acquire_authority` and the root's commit acquisition run on fresh
  snapshots holding nothing across a fetch, and a publishing operation that
  names a missing image or descriptor returns, releases its control
  snapshot, acquires, and runs again as a new operation on a fresh
  snapshot -- which sees every record, proof and blob that landed
  meanwhile, so an acquired descriptor or definition simply counts. The
  operation view (`OperationSnapshot::index`) therefore re-offers nothing
  (`CoverageIndex::wake_proofs_for` is gone) and needs no `BlobStoreList`
  bounds. A root's admitted support is read from the index
  (`Coverage::frontier_support`) rather than from a witness walk.

- Park on the definition a proof needs. A capability proof whose
  definition blob is not resident used to be dropped silently by the quorum
  walk, so the record it would admit parked on its signer and no blob
  arrival could wake it. `capability_quorum_decide` (and `_if`) now returns
  a `QuorumOutcome`: `Met`, `Unmet` (only a proof could change it), or
  `Undefined(definitions)` naming the capability definitions that proofs
  for this subject stopped at; `AdmissionEvidence::decide` folds the
  alternatives. `Admittance::Undefined` carries every definition the fold
  could not read -- the descriptor's policy definitions and the proofs'
  capability definitions -- and the attestation is parked under each of
  them and under its signer, so whichever arrives first re-offers it and
  that decision reads everything again.

- Keep each collection's frontier in the coverage index. The fold now tracks,
  beside every node's support, the nodes no driven MERGE has consumed
  (`Coverage::frontier`, `Coverage::frontier_support`): a MERGE takes its
  inputs off and puts its result on, a DERIVE or COMMIT puts its node on
  unless a driven MERGE already consumes it. A COMMIT written straight into
  a derived collection attests nothing.

- Attach a target from its frontier. `observation::attach` reads the
  frontier from the index when the whole lineage is resident and every
  frontier node's bytes are here, drops a node whose support lies inside a
  kept one, and takes the union as the support; a missing descriptor, an
  empty frontier or a node ahead of its bytes still walks the target's own
  records. Maintenance reads its source through the same attach. The
  certified read path (`attach_collection`) and the accumulated certified
  support in `resolve_endorsed_lineage`, one Merkle union per record on
  every maintenance pass, had no reader left and are gone. Measured on sky,
  2026-09-20, live 26 GB pile: a compass read that attaches only went from
  13.5 s to 4.4 s; the same read that maintained took 49 s.

- `PartialOrd` for `PATCH` is set inclusion: `a <= b` says every key of `a`
  is in `b`, and `partial_cmp` is `None` when neither contains the other. An
  early-exit walk over both tries with the shape of `difference` that builds
  nothing: a shared subtree is settled by its hash, and a key one side lacks
  decides the direction the moment it is met. `Cover::is_subset` and the
  read attach's narrowing of the frontier use it instead of materializing a
  difference. The coverage fold's growth check is a union followed by one
  hash comparison.

- `BlobStoreMeta::resident`: the members of a key set that are present in
  the store, as a set. Presence, not validity: the bytes are validated where
  they are read. The pile answers with one intersection of its occurrence
  relation projected at the hash segment; the default asks per handle; the
  tracked reader charges every asked handle, present or absent. The read
  attach intersects the target's frontier with it instead of probing each
  node.

- A cover attached from the frontier charges only the target's records to
  its observation, as the record walk did: a commit landing in the source
  does not make the target's cover stale. The one exception is a target
  record still blocked on an input's support (`Coverage::has_blocked`),
  while which the whole lineage is charged. The support taken from the
  index charges the lineage when it is asked for.

- Remove `uncovered_source_members` and `PatternUnion`, introduced only for
  hybrid editor reads. Indexed readers do not manufacture a source-freshness
  guarantee; maintenance and exact support queries retain their existing APIs.

- Stop resident-frontier membership searches at the first strict resident
  subsumer. Canonical cover-witness selection is unchanged; counted regressions
  cover merge chains, nonresident intermediates, and self/cycle exclusion.

- Avoid hashing every record when selecting a collection or a raw record
  relationship. Exact fingerprint selectors still compare the canonical hash;
  counted tests cover field-only and mixed unions.

### Fixed

- Remove support-redundant physical-cover repair members before LSM planning.
  A later resident member may already carry every exact witness of an earlier
  addition; retaining both could repeat a useless subsuming carry and report a
  stalled collection. Selection preserves full witnessed support, and genuine
  publication-progress failures remain errors.

### Added

- Expose the opt-in `repo::ObservedStore` raw read-set observer for active
  stores as well as immutable readers. Fresh snapshots share its private
  tracker; explicit acquisitions retain their exact handle before forwarding,
  including misses, errors and cancellation. Writes and existing collection
  operation return contracts are unchanged. External provider availability is
  not a stored dependency and still requires the caller's own retry policy.

- Attach ordinary collection snapshots from admitted target endorsements and
  resident outputs without eagerly expanding historical COMMIT support.
  `CollectionSnapshot::support()` is now a fallible, lazy exact-provenance
  query shared across clones; missing or mismatched historical routes do not
  hide a readable endorsed target. Explicit `collection_exact` still requires
  complete requested support. `is_current` compares the observation's tracked
  record, proof, and exact blob dependencies, including misses, so unrelated
  pile appends need not reconstruct the collection.

- Add `StoreDependencies` and conservative `StoreSnapshot::changes_for`
  comparison for retained read-sets, including absent records and blobs. Pile
  narrows comparison through shared record relationship prefixes and physical
  blob-occurrence prefixes, so unrelated changes can be ignored without losing
  same-hash payload recovery. Unoptimized backends remain component-conservative.

- Add `EntityIdSetBlob`, a canonical grow-only set of opaque, nonnil 16-byte
  entity IDs, and its shard-backed `EntityIdSet` cover view. Authored encoding
  sorts/deduplicates; collection joins use sorted union. Ordinary attachment
  checks framing without re-auditing, copying, or hashing content; membership
  and lazy merged iteration use the persisted rows. Explicit canonical audits
  remain separate. The encoding ID `0BF639287590CFC9CE0E2B83D9FBC1E3` was minted
  with installed `trible genid` on 2026-09-15. Its ordinary `SimpleArchive`
  derivation projects the individually typed nonnil `GenId` VALUES of one
  configured attribute, never assertion subjects or multi-fact qualifiers.
  Configuration reuses `metadata::attribute`; algorithm
  `7E4257A14880E8B4855B6282B337B4B5` was minted with installed `trible genid` on
  2026-09-15. Split facts, duplicate assertions, and optional timestamps retain
  the union law. No generic root-publication API, record format, or implicit
  blob dependency is added.

- Add raw `ProducedMember(C, H)` and `ReferencingRecord(FP)` collection-record
  selectors. Pile maintains snapshot-shared producer and immediate-witness
  PATCH indexes during replay, including consumers whose inputs have not
  arrived. Mixed selections use primary/relationship/collection indexes and
  preserve the scan fallback's fingerprint-sorted, deduplicated union without
  authorization, support resolution, or payload reads during refresh.

- Add crate-private PATCH prefix-sharing checks for scoped snapshot
  invalidation. They compare shared node bodies, including physical occurrence
  suffixes and attached-value replacements, without exposing hashes or treating
  equal key counts as unchanged inputs.

- Add opt-in raw Succinct build/merge wavelet backends, sharing the canonical
  CPU domain/rotation preparation and portable writer. Backend output uses the
  existing prefix/tail checks and explicit little-endian serialization; there
  is no native query arena, new encoding identity, or device dependency in Core.

- Add witness-bound MERGE/DERIVE endorsements over actual native input-record
  fingerprints as well as payload handles. Their new dense tags are 6/7 with
  288/224-byte bodies; both native frames occupy 512 bytes. New semantic kinds,
  signature domains, and pinned record descriptions prevent old payload-only
  signatures from acquiring the stronger meaning. COMMIT is byte-identical.

- Resource-scoped capability definition handles and generic descriptor policy
  bindings. AUTH-v5 has a 96-byte header and 128-byte handle/delegate/signature
  edges, with no inline flags or time bounds. Immutable definitions describe
  independent invocation and delegation action sets; child invocation and
  delegation must be contained in the parent's delegation set. Policy bindings
  select actions from definitions rather than requiring grant-handle equality.
  Standard READ/WRITE definitions and existing collection descriptors keep
  their identities. Pile indexes share owning proof byte views; GC retains
  resident definitions, not opaque resource identities. Old proofs require
  explicit owner reissuance, not signature translation or silent removal of
  application-specific restrictions.

- Freeze immutable content observations in `StoreSnapshot`, with required
  `snapshot` methods on synchronous and asynchronous sources. Remove the
  generic snapshot clock and explicit-time construction; applications own
  any clock needed for their restrictions. Content revision comparisons and
  timeless generic capability authority are unchanged. Passive collection
  observation remains resident-only and inert; active acquisition belongs to
  asynchronous store operations or exact-handle networked reads.

- Use the same `ensure` and `maintain` operations for root and derived
  collections. Roots fetch their exact admitted dependencies without a
  fictitious self-derivation or durable WANT; derived targets continue to
  publish only their own one-hop images. Remove separate acquisition and
  admission-plus-commit-list methods. `collection.read(&snapshot)` is exactly
  the resident `snapshot.collection(collection)?.view()` path.

- Make canonical `WantRequest::Blob(H)` the sole durable exact-content
  request. Repository implementations retain its exact identity and every
  independently resident reference while the WANT remains retained.

- Add independent descriptor-local READ and WRITE admission policies. Each is
  `Open` or a canonical multi-root quorum with one invocation threshold. The
  evaluator counts independently valid paths from distinct roots and adds
  exact `ACTION_READ` authorization beside `ACTION_WRITE`; delegation comes
  only from delegation-action facts in each signed grant's definition. The
  byte-compatible legacy delegation-threshold descriptor field is ignored by
  authorization.

- Add store-owned collection construction:
  `collection(name, policy)`, `derive(source, mapping, policy)`, and the raw
  `register_collection::<E>(descriptor)` boundary. `CollectionMapping` now
  carries associated `Source` and `Target` encodings plus its concrete mapping
  fragment. Store snapshots expose immutable typed collection observations;
  mutating ensure/maintain operations take only the target and mapping type,
  cross one explicit hop over invariant foundational support, and return a
  fresh store snapshot.

- Define foundational `Support` as exactly `Cover<SimpleArchive>` and preserve
  it unchanged across every mapping hop. `CollectionSnapshot<R, E>` pairs one
  store watermark with that support and its resident target cover. Remove the
  lifecycle facades and synthetic collection-record entity IDs; exact native
  records carry semantics and provenance, while full-width fingerprints name
  those records for storage, transport, and signed witness references.
  `Collection::cover` names a typed exact coordinate without store access so
  durable manifests can preserve a
  cover; later admission and resolution still decide whether it is usable in a
  particular immutable snapshot.

- Make every collection member an ordinary typed `Blob<E>`.
  `CollectionEncoding` validates that blob and defines one canonical join;
  `Cover<E>` keeps the logical join total when one member hits a deterministic
  capacity boundary, so every source and derived collection is a full lattice.
  `CollectionMapping` maps blobs to blobs as a join homomorphism, while storage
  owns deterministic merge/derive sequencing and immutable dependencies.

- Add direct typed collection encodings, covers, and logical cover
  views. `CollectionEncoding` attaches canonical validation and one canonical
  member join to the member encoding; `Collection<E>` and
  `Cover<E>` retain that encoding through the public API; signed commits accept
  authored `Fragment` values in `SimpleArchive` source collections, while
  typed materialization works for non-`SimpleArchive` collections. Derived
  descriptors link a concrete mapping entity carrying its algorithm and
  concrete parameters, while exact derived lifecycles bind one
  `CollectionMapping<Source, Target>` whose law is a join homomorphism.

- Add top-level `capability`, a direct authorization kernel. One canonical
  proof encodes `magic32 | resource32 | root32 |`
  `N*(capability_handle32 | delegate32 | signature64)`. Each strict
  Ed25519 signature is last and covers the exact prefix through its delegate,
  so every signed prefix is itself a proof and paths cannot be grafted or
  reordered. Root and delegate encodings are canonical non-weak principals;
  a bad later suffix cannot invalidate an earlier valid subject prefix. BLAKE3
  over the exact proof bytes is its stable identity. Byte-only signature checks
  need no blobs; action authorization takes an external trust root, expected
  subject, resource/action request, and a reader for capability definitions.
  Application restrictions may filter each validated prefix before quorum
  counting; the generic kernel does not impose an expiry interpretation.
- Add `CapabilityProofStore` to `MemoryRepo`, `Pile`, and `Yard` as a native
  grow-only set of self-contained proofs with deterministic enumeration and
  exact proof-ID lookup. Native records use bounded canonical framing.
  Conservative collection preserves exact proof records and resident referenced
  capability definitions, without following the opaque resource identity or
  fetching missing blobs. Proof presence alone grants no authority.

### Changed

- Construct aggregate endorsed collection support once from the selected
  witness DAG's distinct COMMIT payloads, avoiding repeated unions of
  overlapping certificates while preserving exact support alternatives,
  requested-support filtering, and complete conflict checks.

- Preflight each invocation and delegation action of a compound collection
  grant against that action's roots before publishing it. An open action may
  accompany useful restricted actions, but one action's authority cannot make
  an unrelated or unknown action's grant construction succeed.

- Attach a collection by admitting its target producers, then walking only
  their exact signed witness DAGs. Preserve the trusted-local/checked-ingress
  boundary: attachment does not repeat collection-record signature checks,
  ancestor capability admission, or ancestral payload/metadata reads.
  Selected outputs still require their encoding dependency closure; missing
  native witnesses leave support unknown. Immediate-source maintenance uses
  the same witness mechanism without recursively constructing upstream work.

- Keep physical cover selection support-aware under non-injective mappings.
  Different certified routes to one payload retain their exact supports; a
  coarser payload does not discard a finer resident member whose extra support
  it did not endorse. Fingerprint-bound traversal prevents unrelated equations
  sharing a handle from inflating an existing endorsement's support.

- Treat retired signed payload-only equation kinds as opaque native frames,
  outside current collection semantics and repair. Conservative Pile copying
  preserves them and every resident blob; Yard and semantic reframe continue
  to refuse opaque ownership. Record witnesses are native-record references,
  never blob references or a new persistent validation ledger.

- Restore bounded target-carry batching under invariant foundational support.
  Maintenance resolves collection semantics once per actionable dyadic tier
  round instead of once per individual `MERGE`, while each disjoint result is
  still stored and published immediately. Tier planning retains only indexed
  member identities and loads one input pair at a time.

- Make `YardSnapshot::blobs_diff` use the PATCH difference of the two immutable
  live-set unions, so exact-provider locator refresh is proportional to changed
  handles instead of relisting the complete Yard twice.

- Keep structural record retention independent of WRITE admission and chosen
  physical covers. Exact-content availability remains a separate,
  collection-independent property of resident blobs; read-time endorsement
  reuse does not weaken ownership of already-resident historical references.

- Make store registration the sole source of typed collection values.
  `register_collection` validates a raw descriptor and returns the exact handle
  produced while storing its attachment closure; canonical root/derive builders
  are internal, `Collection::from_descriptor` and the phantom SimpleArchive
  facade are removed, and derived maintenance binds only store-issued source
  and target values while reloading and validating their lineage at use time.

- Make local `commit(collection, signer, fragment)` correct by construction:
  it stores attachments, data, and metadata before inserting the native signed
  COMMIT, without rereading a descriptor, revalidating the generated archive,
  or implicitly advertising OFFER state. Admission remains a read/sync-boundary
  decision.

- Make Yard reclaim derive its final store-scope and opaque-record safety
  decisions from one refreshed Pile state, so an opaque record appended during
  rewrite planning is refused instead of being projected away.

- Clean-cutover the unpublished Rank9 API and identities.
  `Rank9AcceleratedSuccinctArchiveBlob` is now an ABI-qualified Merkle-root
  `CollectionEncoding` whose first 32 bytes name its portable raw
  `SuccinctArchiveBlob` child. `RawToRank9AcceleratedMappingV1` maps raw members
  through ordinary `DERIVE` records. Raw Succinct and accelerated roots both
  own canonical joins. The accelerated join may consume its exact immutable raw
  union when already resident, but downstream maintenance never creates that
  upstream blob or `MERGE`. Without the dependency it retains a finer target
  cover. Cover-aware
  views pull the named child through the immutable store snapshot and validate
  the complete raw/index pair. The former `Rank9MappingV1`/`RANK9_MAPPING_V1`,
  intermediate `Rank9SidecarMappingV1*`, old blob names, and their obsolete id
  family have no compatibility aliases. The separate mapping-evidence record
  kind and store surface were removed after a scan found no live records in
  known piles; derived artifacts may be recomputed.

- Treat handles cached by typed `Blob` values returned from `BlobStoreGet` as
  trusted content identities. Collection operations retain structural and
  semantic validation at real ingress boundaries while deleting duplicate
  rehashes and post-write rereads of values produced or loaded in-process.

- Replace split Reader and revision APIs with `SnapshotSource` and one coherent
  immutable `StoreSnapshot`. Blob access, collection records, capability
  proofs are frozen together. `changes_since` defaults to
  conservative full invalidation, while `MemoryRepo`, `Pile`, and `Yard`
  compare persistent component PATCHes directly. `BLOBS` covers membership,
  metadata, and retrievability; Pile's lineage-local root-sharing comparison
  catches same-handle backing replacement while ignoring unrelated appended
  records, even though semantic PATCH equality intentionally hashes keys, not
  attached storage offsets. Yard retention planning now uses one snapshot for
  opaque-record refusal, live membership, commits, and proofs.

- Remove the obsolete `PeerRead`, `PeerStore`, and `StoreScope` repository
  surfaces and their Pile, Yard, Hybrid, Lazy, and MemoryRepo state. Historical
  framed PEER and STORE_SCOPE records decode as known inert records so old
  piles still open, while semantic rewrites omit them and continue to refuse
  unknown kinds.

## [0.41.4] - 2026-05-17

Lock-step bump alongside the trailing-dot-leak +
connection-reuse fixes in `triblespace-net` / `trible`. No
source changes in `triblespace-core`. See the workspace
[`../CHANGELOG.md`](../CHANGELOG.md) for the full release notes.

## [0.41.3] - 2026-05-17

Lock-step bump alongside the trailing-dot relay-URL fix in
`triblespace-net` / `trible`. No source changes in
`triblespace-core`. See the workspace
[`../CHANGELOG.md`](../CHANGELOG.md) for the full release notes.

## [0.41.2] - 2026-05-17

Lock-step bump alongside the address-symmetry work in
`triblespace-net` / `trible`. No source changes in
`triblespace-core`. See the workspace
[`../CHANGELOG.md`](../CHANGELOG.md) for the full release notes.

## [0.41.1] - 2026-05-17

Lock-step bump alongside the EndpointTicket-everywhere work
in `triblespace-net` / `trible`. No source changes in
`triblespace-core`. See the workspace
[`../CHANGELOG.md`](../CHANGELOG.md) for the full release notes.

## [0.41.0] - 2026-05-16

Lock-step bump alongside the iroh 0.98 family upgrade in
`triblespace-net`. No source changes in `triblespace-core`.
See the workspace [`../CHANGELOG.md`](../CHANGELOG.md) for
the full release notes.

## [0.39.0] - 2026-05-11

The canonical-attribute-id + bounded-path-estimation release.
See the workspace [`../CHANGELOG.md`](../CHANGELOG.md) for the
full release notes on dynamic-name attribute id derivation,
the IRI BlobEncoding, `metadata::iri`, `Attribute::from_iri`, the
`MemoryBlobStore::union` structural merge, and the `Workspace`
`local_blobs → staged` rename.

### Path-query: bounded-depth closure estimation
- **`estimate_from`'s closure-fallback no longer full-materialises**
  the result set
  (`triblespace-core/src/query/regularpathconstraint.rs`). The
  previous fallback ran `eval_from(set, body, start).len()` —
  paying the full cost of computing the closure just to measure
  its size. The new `bounded_eval_from` helper caps closure BFS
  at `RPQ_ESTIMATE_DEPTH = 5` levels, matching Karalis et al.
  ESWC 2024 §4.3's "default estimation": bounded depth →
  bounded estimate cost, sufficient for variable ordering.
  Non-closure expressions don't consume depth; the bound only
  fires on Plus/Star iteration steps. Nested closures multiply
  (`Plus(Plus(q))` runs the inner Plus to depth 5 for each of
  the outer's 5 steps — `O(depth^k)` for closure-nesting
  depth `k`), which the doc comment flags. Shallow estimation
  (the constant-time per-attribute count from the segmented
  index) was already in place; this commit closes the remaining
  gap where shallow doesn't apply.

## [0.38.0] - 2026-05-07

Lock-step bump alongside the team-rooted-gossip release in
`triblespace-net` / `trible`. No source changes in
`triblespace-core`. See the workspace
[`../CHANGELOG.md`](../CHANGELOG.md) for the full release notes.

## [0.37.0] - 2026-05-06

First per-crate CHANGELOG. Earlier `triblespace-core` releases
are documented at the workspace level in
[`../CHANGELOG.md`](../CHANGELOG.md).

### Added
- **`PathOp::Optional` (`(p)?`) primitive** in the path-query
  language. `Optional(p)` matches zero-or-one applications of
  `p`; semantically `Union(Identity, p)` but recognised inline
  so the zero-step branch reuses the bound start node directly
  instead of materialising every node as an `Identity`
  candidate. Same shape as the `Star` arm but with the zero-
  step alone (no transitive frontier). Plus a `from_postfix`-
  time normalisation pass that distributes `Optional` and
  `Union` out of `Concat` via the standard rewrites
  (`a / b? ↔ a | (a / b)`, `(a | b) / c ↔ (a / c) | (b / c)`,
  etc.) — without it, the typical WDBench shape
  `Concat(Attr, Optional(Attr))` (`p / q?`) would hit the
  `build_constraint` `unreachable!()` arm. Macro syntax in
  `path!` (`(p)?`) is the follow-up; until then callers
  construct `PathOp::Optional` postfix-style via
  `RegularPathConstraint::new`. Two proptests cover the
  standalone `(p)?` boundary case and the `p / p?` Concat-
  with-Optional case post-normalisation.
- **`PathOp::Inverse` (`^p`) primitive** in the path-query
  language. `^attr` reverses the direction of an attribute
  edge (VAE-index lookup yielding entity bytes, mirroring the
  existing forward `eval_attr` / EAV-index path). Compound
  expressions push down via the standard reversal rewrites
  (`^(a/b) ↔ ^b/^a`, `^(a+) ↔ (^a)+`); double negation
  (`^^a → a`) cancels at `from_postfix`-time. Macro syntax in
  `path!` (`^p`) is the follow-up; until then callers
  construct `PathOp::Inverse` postfix-style via
  `RegularPathConstraint::new`. Two proptests cover
  standalone `^link` and `(^p / p)+` (mid-path inverse inside
  a Plus loop).
- **`Universe::search_range(min, max) -> Range<usize>`**, plus
  the underlying `search_lower(v)` / `search_upper(v)`
  primitives. `O(log n)` half-open code range over a monotonic
  universe; default impls fall through to a binary search via
  `Universe::access`. Implementations with a flat sorted slice
  override to skip the virtual-call overhead.
- **`SuccinctArchive::value_in_range`** constraint exploits
  the new universe primitive: `O(log n + K)` proposals over
  range-bounded values, where `K` is the number of distinct
  in-range codes that actually appear on the indexed axis.
  Composable with `pattern!` / `find!` / `and!`. Combined with
  `enumerate_in_range` (the bounded variant of
  `enumerate_domain`), it gives the engine a real range-query
  primitive without scanning the full value column.
- **`repo::capability` runnable doctests** on every primary
  public function: `build_capability`, `verify_chain`,
  `build_revocation`, `extract_revocation_pairs`,
  `VerifiedCapability` (covering `permissions`,
  `granted_branches`, `grants_read`, `grants_read_on`).

### Changed
- **`SuccinctArchive`'s value-axis enumeration** routes
  range-bounded queries through `Universe::search_range`
  rather than enumerating the full domain and post-filtering.
  Same result; `O(log n + K)` instead of `O(n)`.
- **Workspace doc warnings cleaned** — 9 stale intra-doc-link
  warnings in `Universe` trait method docs and the
  `succinctarchive` module fixed (`[Self::search]`,
  `[Self::access]`, `[Self::search_lower]`,
  `[Self::enumerate_domain]` etc.). `cargo doc -p
  triblespace-core --no-deps` is now warning-free.
