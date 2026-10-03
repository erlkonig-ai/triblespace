# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.47.1] - 2026-10-03

- Build SimpleArchive binary/k-way unions and portable Succinct archives in
  file-backed `ByteArea` sections rather than artifact-sized heap vectors.
  The CPU Succinct domain, decoded merge inputs, counting-sort and wavelet
  scratch, and final output use mapped sections; freezing retains their
  mappings without copying. Canonical archive bytes and encoding identities
  are unchanged. Allocation failures are reported separately from malformed
  archives, with checked section-size arithmetic. GPU device readback,
  runtime-to-portable serialization, explicit canonical audits and small
  per-input metadata remain separate allocations; mapped pages still consume
  working-set memory and temporary backing space.

## [0.47.0] - 2026-10-01

- Reuse the lazy coverage memo across consecutive snapshots only when the
  backend reports no changed component. Warming an older operation control
  after a newer equivalent residency snapshot now also warms later readers.
  Changed records, proofs or blob observations still fork the memo; frozen
  membership, authority and residency are not advanced.

- `repo::async_store::AcquiringReader` bridges exact async blob gets into
  synchronous foreground reads without refreshing records, proofs or residency.
  First collection selection retries only the frozen index's parked records
  against acquired descriptor/admission definitions. Acquiring admission checks
  retain actual backend errors instead of letting open-world policy queries
  hide them as denial. Missing memory-store bytes now carry `MissingBlob` in
  their error source chain, like pile/peer reads.
- `collection_acquiring` selects known target foundations not represented by
  the resident cover; `attached_acquiring` exact-gets the explicit lineage
  descriptors before first selection, without falsifying frozen residency.
  `AttachedSnapshot::read_acquiring` and
  `succinctarchive_union::read_attached_acquiring` read a fixed selected cover
  and request residual foundations even when frozen metadata says absent.
  They neither publish mappings nor select later records. Unavailable or
  unrepresentable residual support stays structured `unread`; actual read,
  archive validation and fatal mapping errors fail the read. Passive APIs
  remain resident-only. Removing an acquisition adapter with `into_frozen`
  retains the exact selected coordinates, not a replacement snapshot.

- Derived collections carry their own lattice. `maintain` on a derived
  collection derives its leaves and then carries its own frontier exactly as
  a root's carry does: held leaf images, eight per support tier, joined into
  the host's own MERGEs by `DeriveMapping::join_images`, which is now the
  k-way join of target images (default: the encoding's `join_many`;
  `CollectionDerivation::join_images` likewise). It never reads the source's
  merges. The mirror of a source's merges is gone, and with it
  `ownership::owns_merge` and `CoverageIndex::drives_join`, which only it
  used; `CoverageIndex::joins_reading` is test-only. A merge needs no WRITE:
  under `maintain` a key the target does not admit derives nothing, reads
  nothing of the source and carries, and that is all it reports; only the
  per-write `ensure` still answers `UnauthorizedProducer` for a key that owes
  leaves for foundations of its own. `realize_as` follows: a signer without
  WRITE answers `Realized::Unadmitted` and, under `Upkeep::Maintain`, carries
  the collection. What deriving could not do holds back neither the rest, nor
  the carry, nor the fetches of outputs the rest is waiting for: a blob an
  own foundation needs (`MissingDependency`) is fetched and everything runs
  again, and what is reported -- the carry's own failure first, then a
  refused own foundation (`Derive`), then, for `ensure`,
  `UnauthorizedProducer`, then `Unmappable` -- is returned only after the
  outputs the call went on without were asked for. A storage error ends the
  call at once, the carry's included (a MERGE or image that cannot be stored,
  a held node that cannot be loaded), ahead even of a blob an own foundation
  needs, and is the one reported; those outputs and that blob are then asked
  for by the next call. A carry that fails otherwise (a join that refuses a
  leaf) is reported after that blob is fetched, so it hides no payload. A
  fetch that fails outright (the store cannot reach other holders, or cannot
  keep what it got) is a fault, not an answer about any holder, and never
  counts a blob unavailable, whatever the blob is to the call -- needed by
  one foundation, the output of another's leaf, or both: what needs it waits
  for that call, and nothing is derived in its place. The first fault is
  reported once the work is done, ahead of what the operation reported,
  except `HostMismatch`, which stops an upkeep pass and so comes first. A
  derived collection stored in a root's encoding carries only through its
  mapping (`maintain_with`); `maintain` still refuses it.
- Derivation is scheduled by leaf, and any admitted leaf suffices: a source
  foundation is derived only when no believed leaf for its locator has an
  output that is here or can be fetched, whoever signed that leaf, and any
  key the target admits may derive it, not only its owner. A leaf whose
  output cannot be obtained does not count; the fetch is tried once per
  pass, and a failed one means the output is unavailable now, not lost, so
  an original output arriving after a second derivation stands beside it and
  nothing further is derived. Outputs that are not here are named by the
  operation and asked for together after its work -- deriving what needs no
  fetch, and the carry -- rather than one restart each before anything is
  mapped. The outputs of one foundation's leaves are asked for as a group
  until one arrives or all have failed; the leaves of two foundations may
  name one output, and a group one of whose outputs the call already
  fetched asks nothing more. One call starts no further foundation once
  eight fetches have failed. Each call starts the
  foundations in an order drawn afresh, so foundations whose fetches always
  fail cannot keep the same others waiting call after call: of `n`
  foundations waiting, a given one is reached in a call with probability at
  least `1/n`, and at least `min(8, n)/n` when each has one leaf. A leaf
  counts only when its output reads: an output a store lists but cannot read
  (damaged bytes in a pile) is treated exactly as an absent one -- asked for
  through a store that can reach other holders, whose network peers fetch
  good bytes for a damaged copy, and waited for through one that cannot.
  The carry holds only frontier nodes whose bytes read, so a damaged node
  sits out like an absent one instead of failing every carry, a root's too:
  maintenance then succeeds and names nothing. Readers are unchanged:
  attaching a cover validates no byte, so a read that takes a damaged node
  fails naming it (`TryFromCoverError::MemberGet`). A foundation whose leaf
  another writer publishes while the pass runs is left to that leaf (read
  from a fresh observation, used only to skip work), and each key derives its
  own foundations first and then the rest, each in an order hashed from the
  key and the foundation, so two hosts rebuilding one collection at once do
  not walk it in step. The per-write `ensure` still derives only the key's
  own foundations with no leaf at all; another owner's payload is never
  fetched. `DeriveMapping::FOREIGN_DERIVABLE` is gone.
  `DeriveMapping::computable_here` is the class-pin hook: a mapping pinned to
  a class of host answers false elsewhere, and there maintenance derives
  nothing, raises nothing for it, and still carries. The `DeriveMapping`
  documentation states the contract: foundations only, a total target join,
  a homomorphism when deterministic, and possibly non-deterministic or
  class-pinned.
- `AsyncBlobStoreAcquire::acquires_remotely` says whether `acquire` can bring
  bytes that are not already here. It defaults to `false`, which the local
  stores (`MemoryRepo`, `Pile`, `Yard`) keep; wrappers answer as the store
  they wrap, and the network peers answer `true`. Derive scheduling asks for a
  leaf's missing output only through a store that answers `true`: from any
  other a miss says nothing about elsewhere, so the foundation waits for its
  output rather than being derived again.
- `CollectionStoreExt::rederive` and `rederive_with` supplement a leaf known
  to be bad: they map the named foundations of the target's immediate source
  again and publish each result no believed leaf names as another leaf,
  replacing none. They need a key the target admits and a host that can
  compute the mapping, and they fetch each named payload that is not here.

- A retained rewrite can leave collection-algebra frames behind:
  `PileFile::rewrite_retained_into_filtered` asks a `CollectionFrameFilter`
  about every current COMMIT, MERGE and DERIVE frame, every retired v8/v9
  equation, every legacy unsigned equation and V3 header and every retired
  signed frame it crosses as opaque, before drained generations and
  supersession apply, and counts what it refuses in
  `PileRewriteStats::filtered_frames`. Its retention follows the frames it
  carries: a frame left behind roots nothing, a carried legacy V3 header roots
  the blob handles its fields name, and a carried frame of unknown kind roots
  the resident blobs any 32 bytes of it name, at any offset (the legacy V1
  envelope put its fields four bytes off 32-byte boundaries), rather than
  every resident blob, so without explicit roots it keeps exactly what the
  carried state reaches. It finds every resident blob its walk meets of
  which no occurrence matches its hash, whether a carried frame, a root
  (direct or recursive) or another blob names it. Under
  `CorruptBlobPolicy::Refuse` such a blob fails the rewrite before anything
  is written (`PileRewriteError::Corrupt`), as an invalid explicitly
  selected blob fails the plain rewrite; under `CorruptBlobPolicy::SetAside`
  it is not copied and is listed in `PileRewriteStats::corrupt_blobs`. Its
  damaged bytes are read for children, but a valid blob named only by a
  damaged word of it cannot be reached and is left behind, which is why
  refusing is the first choice. `PileFile::plan_retained_rewrite` runs the
  same selection pass and retention walk without writing and returns the
  same counts, the set of blobs it would copy (`RetainedRewritePlan`), their
  bytes as the copy takes them (each blob's first valid occurrence) and the
  corrupt blobs it met.
  `rewrite_retained_into` and `rewrite_retained_into_leaving` keep their
  retention.
- Retired capability proofs (pile kinds v1 and v2 of the proof record) are
  capability records: every retained rewrite now carries each distinct one
  byte for byte, as it carries current proofs, keeps every resident blob any
  32 bytes of it name, and counts them in
  `PileRewriteStats::retired_capability_proofs`. Yard reclamation carries
  them too, and its collection keeps what they may name. Both used to drop
  them.
- Every retained rewrite considers a frame held again at a later offset (a
  current collection record, or a frame of unknown kind, as concatenation
  leaves them) once, and counts the repeats in
  `PileRewriteStats::repeated_frames`. The destination already stored each
  once; the counts now say so.
- A held-blob index per tracked collection (`collection::held`), kept by
  `Covered` beside the coverage index under its own lock and fed by the same
  snapshot difference. `held(C)` is every resident blob reachable from the
  blobs C's replicated records name (descriptor, COMMIT data and metadata,
  DERIVE outputs, proof capability definitions), never a MERGE result, plus
  the resident blobs peers reported in C (`HeldStore::note_held`, in memory
  only). Each blob is scanned once and its edges cached for every collection;
  a periodic full walk on a `HeldWalker` catches children that arrived after
  their parent was scanned. With a walker attached, a newly tracked
  collection's existing closure is computed by a start-up walk of that
  collection alone, and peer reports for it wait for that walk instead of
  being read while a snapshot is taken. Snapshots carry fixed held sets
  (`HeldRead::held`); background walks only enter later ones. A collection
  whose records or proofs the store cannot read is left out of the held sets
  and read again, never published short. A store that tracks nothing
  (`HeldStore::track_held`) pays nothing and starts no thread
  (`held::held_threads_spawned` counts every thread the index starts).
  New selector `CollectionRecordSelector::Foundations(C)`: the COMMITs and
  DERIVEs of C, named positively, so a MERGE or any later record kind never
  matches.
  A held set is closed: a blob joins only after every resident child it had
  when scanned, so a walk publishes each batch of roots deepest first and a
  new record's closure never stops at a blob a running walk has not finished.
  Reports that waited for a start-up walk are read by that walk, never while
  a snapshot is taken. Proof seeds are only the proofs C's authorization
  evidence keeps. The index's retained state is PATCH relations.
  Held sets are closed under the edge cache: a walk publishes each batch
  children before parents, a child it learns under a held blob joins with
  the edge, and a blob that cannot be read holds back everything above it on
  every path. Every seed of a new record is reached, and a walk re-reads
  blobs it could not read before its report rounds (at most 16 per walk).
  Proofs judged against a resident but unreadable descriptor are judged
  again after the next walk. `HeldView` equality compares each held set.
- `descriptor::validate_proof_evidence` (with `validate_proof_for_policies`,
  `ProofEvidenceError` and `AdmissionPolicy::has_root`): whether a capability
  proof is authorization evidence for a collection, the one predicate both
  the sync host's AUTH and the held-blob index's proof seeds apply.

- Attached collections. `CollectionRecord::Map` is a fourth native record,
  `CollectionMap` (`attached`, `node`, `attachment`, signed), framed in a pile
  as one 256-byte block under record kind `KIND_ID_COLLECTION_MAP`, with
  semantic kind `KIND_COLLECTION_MAP` and transcript domain
  `MAP_TRANSCRIPT_DOMAIN`. An attached descriptor names its parent through
  `collection_parent`; a mapping that reads another attached collection names
  it through `mapping_reads_attached` (Rank9 names its Succinct collection).
  `MapMapping` states the contract of an attached mapping and its law,
  cover-query equivalence: a cover of attachments answers every query as the
  attachment of the union of their nodes; for a mapping that aggregates
  facts of several entities this is a premise about its input, which the
  implementor states. `CollectionAttachment` is the
  target-owned canonical form, implemented by `SuccinctArchiveBlob`,
  `Rank9AcceleratedSuccinctArchiveBlob`, `EntityIdSetBlob`, `LatestBlob` and
  `LwwRegisterBlob`, which are no longer `CollectionDerivation`s.
  `CollectionStoreExt::attach`, `attach_with`, `ensure_attached` and
  `maintain_attached` register and maintain them; `CollectionSnapshotExt::attached`
  reads an `AttachedSnapshot` (cover, support, residual, currency). Its
  `read` and `read_with` form a view over the cover and an image of every
  residual foundation built in memory through the mapping, so an index answers
  for what a fact read of the same observation holds; `view` is the cover
  alone. `succinctarchive_union::read_attached` reads a Succinct or Rank9 one
  with its residual read from the bytes that are here. Both return an
  `AttachedRead`, which names the residual foundations it could not include
  (`unread`: bytes or a dependency not here, or a node the mapping cannot
  represent). `descriptor::parents` lists an attached descriptor's parents
  without counting them; the fold treats any descriptor naming a parent as
  attached. The fold believes a `MAP` only
  from the host, keeps it as the attachment of a node of the parent, and drops
  a `COMMIT`, `DERIVE` or `MERGE` aimed at an attached handle
  (`SourceResolution::Attached`). `attached_to` and `realize_attached_as` find
  and maintain every collection attached to a root, siblings first, in
  `ensure_downstream` and `maintain_downstream`, whose report names attached
  representations it does not know in `unknown_attached`, attached
  collections whose upkeep failed in `failed_attached`, and derived
  collections whose upkeep failed in `failed`; one failing does not stop the
  pass, a signer that is not the host does. `attached_to` lists only
  descriptors naming the root as their one parent, the only kind an attached
  read serves. New ids, minted with
  `trible genid`: `KIND_COLLECTION_MAP` `329669AA662709605053C123671DF1D2`,
  pile kind anchor `ED7B98CD20AD9A4D172F037A08CC47F1`,
  `MAP_TRANSCRIPT_DOMAIN` `4A5191C36898D0B453FEFF99ED0E3852` +
  `4AADD87ED8EB8620BD39623B5221B5BE`, `collection_parent`
  `9B20AA2BE739DB1B4911186620368262`, `mapping_reads_attached`
  `7A852B1D4097983EA823D04C8CD1A53A`.
  Removed with the derived Succinct and Rank9 path they checked:
  `succinctarchive_union::validate_derive`, `validate_merge`,
  `SuccinctArchiveUnionValidationError`, `DescriptorRole` and `ElementRole`.
  One member is validated by `CollectionEncoding::validate_member`, and an
  attachment's usability by `missing_representation_dependencies`.

- `CollectionMapping` is now `DeriveMapping`, named for what its images
  become: `DERIVE` leaves of a derived collection. A new, still empty
  `MapMapping` trait states the contract of a mapping attached to another
  collection's nodes instead (deterministic, computable by every host that
  can read the node, no join required) and its law, cover-query equivalence.
  `REPLICA_INDEPENDENT` is gone from `DeriveMapping` and
  `CollectionDerivation`. The one thing it decided, whether `maintain`
  derives a leafless foundation another key owns, is now decided by leaf
  (see the scheduling entry above).

- A MERGE is believed only when the store's own host key signed it, with no
  WRITE check; a COMMIT or a DERIVE is still believed when its signer may
  WRITE its collection. `CoverageIndex` carries a host key fixed for its
  life (`CoverageIndex::for_host`, `with_host`, `host`), set by
  `Pile::open_as`, `Covered::with_host` and `Covered::for_host`, and
  `MemoryRepo::for_host`. `Pile::open` and `MemoryRepo::default` stay
  keyless: they believe no MERGE, and every believed foundation stays on the
  frontier. Another key's MERGE stays in the store and folds into nothing --
  no support, consumer edge, owner or frontier move -- which closes support
  injection by other keys for records whose signatures were checked at
  ingress (native pile replay and object-store listings do not check
  signatures again). `Coverage::owners` names only COMMIT and DERIVE
  signers. The believed host joins are published in `Coverage`, and
  `Coverage::producers(collection, node)` returns the driven ones by the
  node's own key; a join parked but not decided yet is not published.
  `CoverageIndex::believes_join` is gone: `producers` answers which joins
  are driven. `fold_index` and `fold_coverage`, which had no callers, are
  removed.

- The root carry merges every held node into the host's own merges, whoever
  signed the foundations beneath it; the fan-in stays 8 and merges need no
  WRITE. A frontier node whose bytes are not here is never joined or fetched,
  so it raises no `MissingDependency` and restarts no acquisition loop, but a
  held node that covers it absorbs it. Maintenance that would publish a
  MERGE with a key other than the store's host, or into a keyless store,
  fails with the new `CollectionRealizationError::HostMismatch` instead of
  stalling: open the store as the signing key to maintain it.

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

- `join_images` on `CollectionDerivation` and `DeriveMapping` no longer
  takes a source union; it is the mapping's own route for joining images,
  defaulting to the encoding's join. The Rank9 route that reused the raw
  union's bytes is gone, with the `source_union` parameter of the archive
  merge. (The source-merge mirror this entry introduced was removed again
  before release: a derived collection carries its own leaves, see above.)

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

- Carry by support size. Tiers are keyed by the size of a node's support,
  not its byte length (now `floor(log_8)`, with eight held nodes per MERGE).
  Before joining, a frontier node whose support lies inside another's is
  consumed by `MERGE(fine, coarse -> coarse)`, no bytes loaded, so the
  redundancy between a fine image and the coarser one that covers it
  disappears in the fold instead of being coarsened at every read; two nodes
  with one support keep the lower node, as readers do. (The source-guided
  coarsening this entry kept for Rank9 is gone: Rank9 is an attached
  collection, and a derived collection never reads its source's merges.)

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
  `register_collection::<E>(descriptor)` boundary. `DeriveMapping` now
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
  `DeriveMapping` maps blobs to blobs as a join homomorphism, while storage
  owns deterministic merge/derive sequencing and immutable dependencies.

- Add direct typed collection encodings, covers, and logical cover
  views. `CollectionEncoding` attaches canonical validation and one canonical
  member join to the member encoding; `Collection<E>` and
  `Cover<E>` retain that encoding through the public API; signed commits accept
  authored `Fragment` values in `SimpleArchive` source collections, while
  typed materialization works for non-`SimpleArchive` collections. Derived
  descriptors link a concrete mapping entity carrying its algorithm and
  concrete parameters, while exact derived lifecycles bind one
  `DeriveMapping<Source, Target>` whose law is a join homomorphism.

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
