# Collection Workflows

TribleSpace publishes data into self-describing grow-only collections. A
collection has no mutable head and no privileged linear history: independent
signed commits coexist, replicas combine records by set union, and stored
merge or derivation equations preserve reusable physical work.

## Vocabulary

- **`Fragment`** — facts, descriptive metafacts, exported IDs, and referenced
  blob attachments produced as one composable value.
- **`BlobStore`** — immutable content-addressed bytes.
- **`CollectionStore`** — a grow-only set of native `COMMIT`, `MERGE`, and
  `DERIVE` records.
- **Collection descriptor** — a canonical `SimpleArchive` which describes a
  collection's anchor, member encoding, and independent READ and WRITE
  admission policies. A derived descriptor
  additionally links one concrete mapping entity carrying its algorithm and
  concrete parameters. The descriptor's content handle is the
  `CollectionHandle`.
- **`Collection<E>`** — a cheap descriptor handle whose
  `CollectionEncoding` type `E` owns the canonical member bytes and join.
  Constructing it validates that the runtime descriptor names `E`.
- **`Cover<E>`** — one typed collection identity plus a PATCH of distinct
  `Handle<E>` members selected for one read or derivation.
  Signatures, authors, and metadata remain queryable provenance, but are not
  coordinates of the value. Checked union, intersection, difference, and
  subset operations reject covers from another collection.
  `collection.cover(members)` names such a coordinate without store access,
  which lets a durable manifest preserve an exact cover; it does not by itself
  admit, evidence, or make those members resident.
- **`Support`** — exactly `Cover<SimpleArchive>`: distinct `COMMIT.data`
  handles at the foundational fact collection, admitted directly or through
  an authorized producer's exact input-record endorsement. It is the
  denotational coordinate shared by every representation. An equation preserves
  its witnessed support; it does not endorse every other route to the same blob.
- **`TryFromCover<E>`** — the encoding-specific reconstruction hook used by a
  collection snapshot. A view may join eagerly or retain mmap-backed shards
  and query their union lazily.
- **`CollectionSnapshot<R, E>`** — one immutable store snapshot together with
  the foundational `Support` and the resident `Cover<E>` which realizes
  exactly that support in this observation. It reconstructs a caller-chosen
  logical value later with `view`.
- **WANT** — an orthogonal local request for content or existing computation;
  it is neither collection membership nor authority.

`MemoryRepo`, `Pile`, and the storage composition wrappers implement both the
blob and native collection surfaces. A collection is its descriptor handle;
the store remains the sole owner of I/O, durability, and lifetime.

An existing descriptor is opened through the same frozen read boundary used
for later observation:

```rust,ignore
let snapshot = storage.snapshot()?;
let models = Collection::<SimpleArchive>::open(&snapshot, collection_handle)?;
```

`open` fetches the canonical archive and queries for a tagged descriptor entity
naming `SimpleArchive`, without requiring either policy. Extra representation
facts, retired attributes, or descriptive names do not negate that match. The
encoding may require its own interpretation context. This explicit typed-open
boundary reports a wrong-type error when no supported encoding interpretation
exists. It never registers, rewrites, or otherwise mutates the store.

Raw `register_collection::<E>` similarly recognizes the encoding context it
needs and stores the complete fragment; policy and lineage are queried when a
consumer needs them. Descriptor decoding checks the canonical archive bytes,
not a closed-world document shape. No descriptor or native-record bytes change
when a reader learns these query semantics.

### Admission is a positive query

Ordinary admission considers every supported policy interpretation for the
requested action. The existing policy binding still names a capability
definition handle; a reader queries that definition's invocation-action facts,
not equality with a grant's handle. A typed consumer joins the encoding fact
and policy link on
the **same tagged descriptor entity**; it cannot borrow a policy from another
entity merely because both occur in one archive. Representation-neutral network
disclosure queries the tagged descriptor's generic bindings for `ACTION_READ`.
The linked policy must explicitly describe `Open` or a usable quorum. Unknown kinds,
undecodable values, and unsupported thresholds contribute no interpretation.

A subject is admitted when at least one supported alternative authorizes it.
Each quorum is evaluated independently: one share from each of two alternatives
does not combine into a threshold proof of either. This is union of query
results, not another serialized policy kind. Finite READ audiences likewise
union; an explicitly recognized open alternative makes the audience `Open`.
No matching READ interpretation means denied disclosure, and no matching WRITE
interpretation means no admitted COMMITs. A root with no usable WRITE policy
therefore has an empty ordinary collection snapshot. Missing READ policy does
not hide otherwise admitted local data: the two actions are independent.
Real descriptor/proof-store I/O failures remain errors, as do malformed archive
bytes; query invisibility does not excuse failed storage observations.

The explicit `collection.policy()`/`descriptor::policy` inspection and
root-grant conveniences still require one unambiguous scalar policy. Executable
ancestry also remains singular: source, mapping, and argument ambiguity is
diagnosed when that route is demanded. General plural lineage is unresolved,
not silently selected by hash order or combined into a made-up foundation.
`Support` still belongs to exactly one foundational collection, and native
`DERIVE(target, input, output, input_witness)` still names no separate mapping
definition: the target descriptor supplies it. This query-use improvement does
not claim to define every possible descriptor
interpretation.

## Publish a root collection

Register the descriptor once, then pass its returned handle to store
operations:

```rust,ignore
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use triblespace::core::{
    blob::encodings::simplearchive::SimpleArchive,
    collection::{grant_collection_write, AdmissionPolicy, CollectionPolicy},
};
use triblespace::prelude::*;

let team_key = SigningKey::generate(&mut OsRng);
let writer = SigningKey::generate(&mut OsRng);
let team = team_key.verifying_key();
let writer_subject = writer.verifying_key();
let mut storage = MemoryRepo::default();
let models = storage.collection(
    "models",
    CollectionPolicy::new(
        AdmissionPolicy::direct(team),
        AdmissionPolicy::direct(team),
    ),
)?;
let _proof = grant_collection_write(
    &mut storage,
    models.handle(),
    &team_key,
    writer_subject,
)?;

let commit = storage.commit(
    models,
    &writer,
    entity! { metadata::name: "first-model" },
)?;
let snapshot = storage.snapshot()?;
let cover = models.admitted(&snapshot)?;
assert!(cover.contains(Handle::<SimpleArchive>::from_hash(commit.data())));
storage.flush()?;
```

Local publication deliberately performs no authorization check: the local
store is a grow-only record ledger, not an access-control boundary. Observation
loads the independent policies from the descriptor. A policy root contributes
its own share; every author still needs the policy's distinct-root threshold for
`ACTION_WRITE` on this descriptor. Interpreting the paths requires their resident
capability definitions. Invalid or irrelevant candidate evidence grants nothing;
inability to enumerate the proof store remains an error. Generic WRITE admission
is clock-independent; advancing the snapshot instant does not expire a grant.

READ and WRITE are explicit because both participate in collection identity.
Either may be `Open` or a canonical quorum over capability roots, with
one semantic threshold. Derived collections state their own policies rather
than inheriting ambient authority from a source or a network-wide team scope.
Whether a subject may delegate a share onward is carried by the independent
delegation-action facts in that path's capability definitions, not by a second
policy threshold. A child may invoke or delegate only actions its parent permits
delegating; invocation alone never confers delegation.

### What publication writes

One `store.commit(collection, signer, fragment)` performs these semantic steps:

1. consume the fragment once into attachments, facts, and metafacts;
2. store the fragment's attachments;
3. encode and store the facts as the canonical `SimpleArchive` member;
4. encode and store metafacts as the mandatory canonical metadata
   `SimpleArchive`;
5. insert a signed `COMMIT` naming the already typed collection, data, and
   metadata handles.

Dependencies precede the record which gives them authority. Publication does
not flush implicitly. Call `flush()` at the application's chosen durability
boundary or explicitly close the backend. Repeating the same fragment with the
same signer produces the same exact signed record and is a set no-op; distinct
attestations coexist.

`COMMIT` is deliberately a source operation over authored `Fragment` values.
Other collection encodings enter the lattice through reproducible `DERIVE` and
`MERGE` records rather than alternative signed leaf formats.

Importers which must validate additional artifacts before making the source
commit visible use the same path with an explicit pause before step 5:

```rust,ignore
let prepared = PreparedCollectionCommit::from_fragment(candidate);
let mut staged = prepared.stage_for(&mut storage, models, &signer)?;

// Dependencies are resident, but COMMIT is still withheld. Any validation or
// reproducible DERIVE/MERGE publication can use this exact store now.
validate_candidate(staged.store_mut())?;

let commit = staged.finalize()?; // the sole signed COMMIT insertion
```

Preparation is store-free and dropping either a prepared or staged value never
publishes a commit. `stage_for` accepts `Collection<SimpleArchive>`, not a raw
handle or a reconstructed descriptor fragment.

## The native algebra

The collection descriptor is the only collection-control structure represented
as a trible archive. The algebra records are fixed-width native records:

```text
COMMIT(collection, data, metadata, author, signature)                  // 192 bytes
MERGE(collection, low, high, result, low_witness, high_witness,
      author, signature)                                             // 288 bytes
DERIVE(target, input, output, input_witness, author, signature)         // 224 bytes
```

`COMMIT` is a signed exogenous assertion: no machine can recompute whether an
author intended to publish a member. `MERGE` is an exact join equation within
one collection. `DERIVE` is one observation of the mapping linked by its
target descriptor; that descriptor already names its source, mapping
algorithm, and concrete mapping parameters.

Each witness is the full fingerprint of an actual native input record, not a
blob handle or synthetic entity. MERGE keeps `(payload, witness)` pairs together
in canonical order; DERIVE's witness belongs to its descriptor's exact source
collection. The referenced record must produce the signed input payload.

The exact native record is the set element. `CollectionStore::insert`
therefore implements set insertion rather than an update. Concatenating stores
unions evidence. Collection records have
no synthetic entity identity; their full-width fingerprints identify the exact
persisted records for lookup, deduplication, and signed witness references.
`Support` still contains payload handles, never record fingerprints.

Signed equations endorse both materialized computation and validation of the
exact input records' support. They do not create new exogenous membership.
Publishing a `MERGE` or `DERIVE` records work which has already been performed;
warm resolution follows that endorsement without executing the join or mapping
again.
Foreign bytes are signature-checked at the store/synchronization boundary;
the producer must satisfy target WRITE through the observation's resident
proof and capability-definition evidence.
A trusted local store is not reverified on every read. Once a target producer
is admitted, attachment selects its resident output without expanding the
historical support. Exact record relationships order the physical cover; only
selected outputs and their encoding-required dependencies must be resident.
A missing result cannot suppress an available finer realization. An explicit
`support()` query follows the exact witness DAG and descriptor lineage without
re-admitting ancestors or reading ancestral payloads, metadata, and proofs.
A missing or mismatched witness route makes that query fail, not return empty
support, and does not prevent reading the endorsed target value.

This deliberately trusts authorized producers to validate inputs and compute
correctly. Signatures identify who endorsed that claim; they do not prevent an
authorized dishonest producer from lying. Read-time recomputation is not part
of the contract.

Low-level signing and store insertion remain unconditional. A publisher which needs to predict
whether an authority-aware observation will admit a signer can freeze a store
snapshot and call
`collection.writer_is_admitted(&snapshot, signer)`: it checks
the descriptor WRITE policy and resident exact authorization evidence without scanning
collection commits or publishing anything.

## Known-prefix snapshots and covers

`store.snapshot()` freezes one immutable observation containing a resident blob
index, collection records, and capability proofs from the same known prefix, together
with one interpretation instant for application queries. The
snapshot, rather than a source frontier or a later materialization, is the
watermark. Ask it what representation is actually readable at that instant:

```rust,ignore
let snapshot = store.snapshot()?;
let observed = snapshot.collection(collection)?;
let cover = observed.cover();
let value: V = observed.view()?;
// Only a consumer which needs provenance asks for historical support.
let support = observed.support()?;
```

`snapshot.collection(target)` admits producers of target records from the
snapshot's proof and resident definition evidence and chooses their resident
target cover. Neither upstream descriptor residency nor a complete historical
witness closure is a prerequisite for this read. The observation retains exact
endorsements for its lazy `support()` query, not a fresh admission query over
every source COMMIT. Admitted but not yet derived data is absent: an immutable
snapshot never promises work which will happen later.
`snapshot.collection_exact(target, &support)` is the assertion form and fails
unless that exact foundational support is completely realized.
Neither observation method reads the clock: identical operations on one frozen
store snapshot have identical results even while wall time passes. A decision
using later-arriving proof or definition evidence requires a new snapshot.
`store.snapshot_at(instant)` is the construction seam for deterministic tests;
it selects the
interpretation time of newly observed content, not a historical content revision.
`changes_since` classifies content only, so a new instant alone reports no
content change. Generic collection authorization has no proof-validity clock;
action-specific deadlines belong to the application interpreting that action.

`observed.is_current(&later_snapshot)` compares the raw dependencies actually
consulted by attachment, views, and explicit support queries. Indexed backends
ignore unrelated collection and blob appends. Missing lookups count too: a
later matching record or a recoverable physical occurrence of a blob triggers
a refresh. This is conservative dependency comparison, not a global sequence
number or another materialized catalog. Query deadlines remain caller-owned.

Both forms keep the chosen target cover inseparable from the store snapshot
which established its residency. `view` invokes `TryFromCover<E>` solely
through that frozen observation. For a `SimpleArchive`, `V = TribleSet`; for a
`SuccinctArchiveBlob`, `V` may be an mmap-backed union retaining selected
shards. `collection.read::<V, _>(&snapshot)` remains a concise
resident collection read when the intermediate support and physical cover are
irrelevant.

For maintained indexes, attachment checks safe typed framing and retains the
stored sections; it does not rerun canonical construction or semantic audits.
An interpretation can expose a separate fallible `query()` preparation step
when its wire format omits data needed for querying, such as sparse-summary
search positions or BM25 document lengths. Keep that prepared value for the
queries which share it. Requesting a different representation can still be
real work: `TribleSet` interpretation constructs PATCH indexes from raw facts,
whereas attaching a persisted Succinct index uses its existing index sections.

Physical compaction is support-aware. If distinct source members `a` and `b`
map to the same payload `x`, an endorsement of `z` through `b` and `c` does not
also endorse `a`, even when payload order says `x <= z`. A resident `x` must
remain alongside `z` to represent `{a,b,c}`. With only `z` resident, the snapshot
reports `{b,c}`; it does not invent the missing support. The exact-record route,
not an inverse walk over all equations sharing payload handles, decides this.

`cover.commits(&snapshot)` queries available native provenance over the
selected payloads. These attestations are not necessarily authorized membership
claims: another signer can attest an already admitted payload without changing
its support or becoming an authority root.

This is a coherent **known-prefix** observation, not a global latest
transaction. A concurrent immutable insert may appear in this call or a later
one. A mutating `ensure` or `maintain` operation returns a new store snapshot;
the caller may then ask that snapshot for the collection it actually contains.

Raw record readers still expose dangling native collection records and stored
proof records for repair. A member is readable only when its selected payload
and representation dependencies are resident in that exact frozen snapshot.
An endorsed result does not need its historical input payloads or COMMIT
metadata to remain resident. Its exact record witnesses must still close when
support is requested; merely holding the result blob does not establish that
provenance.
A capability proof's signatures can be checked from its bytes
alone; action and delegation interpretation also needs the referenced
definition blobs. A missing definition does not erase the raw proof, but it
cannot support an interpreted grant. These passive observations never acquire,
wait, write, or emit `WANT`.

Exact immutable payload reads are a separate capability of network-backed
snapshots:

```rust,ignore
let snapshot = peer.snapshot()?;
let observed = snapshot.collection(collection)?;
// A queried attachment handle is sufficient; no collection authorization
// argument or mutable writer borrow is needed for this exact byte read.
let bytes: Bytes = snapshot.get(attachment_handle).await?;
```

`PeerSnapshot::get` and `ObjectStoreSnapshot`'s asynchronous `get` can fetch
bytes which arrived after the snapshot. That cache operation changes neither
the captured records/proofs, the interpretation instant, the frozen residency
index, nor `observed.cover()`. Passive collection selection still uses the
captured resident prefix; reading a newly acquired collection member requires
another store snapshot. A synchronous consumer can use one `Blocking` adapter
at its outer runtime boundary to decode payloads without threading a mutable
writer through its domain queries. It must not nest that boundary inside an
already running async task. Closing a peer ends live acquisition, while bytes
already captured in its snapshots remain readable.

Record retention is a separate lifetime rule: a retained non-blob
record strongly retains every directly referenced blob which is resident, but
does not fetch an absent one; proofs reference stable capability definitions,
not the opaque resource. A `WANT`
is itself only an explicit durable demand record, never automatic cache-miss
bookkeeping.

The four live store operations are asynchronous even for local stores. They may
fetch exact missing blobs named by frozen records, explicit support, or immutable
dependencies needed for the work, publish target collection equations, and
return a fresh snapshot; they never emit `WANT`. Local stores implement the same
contract with immediately ready acquisition from their resident snapshot, while
a networked store may await exact-H fetch.

Raw `Cover` value algebra is deliberately a lower-level operation than
attaching a `CollectionSnapshot`. The caller already names exact descriptor
and payload identities. Replaying those bytes needs no publishing key or
foundational COMMIT/metadata records; algebraic alternatives may reuse
authorized signed MERGE math without establishing authenticated foundational
support. Such a resolved cover is not evidence that its members were admitted
to the collection. Only the collection-snapshot path above claims `Support`
and therefore requires closed exact witness records.

Use `cover.commits(&snapshot)` when currently resident authorship and metadata
provenance matters; zero commits is a valid answer and
does not invalidate replay. Several admitted commits over the same payload are
distinct provenance fibers but one member of `Support`.

## Reuse merge work without changing meaning

A logical collection value is the join of a cover's members. It does not need
one monolithic blob. A resolver may choose members consisting of committed
payloads and stored merge results:

```text
    a       b       c           explicit payloads
     \     /        |
      a⊔b           |           reusable MERGE result
        \           /
         (a⊔b)⊔c                logical collection value
```

Distinct covers can have the same support: `{a, b}` and `{a⊔b}` are different
PATCH sets, but the stored `MERGE` equation records that they denote the same
join. This is useful for LSM-like maintenance: small commits remain
independently attributable, while deterministic merges amortize reads into
larger canonical shards. A selected target cover is replaceable computation,
never a second history or a new authority root.

## Derive another representation

Suppose `f` is a canonical join homomorphism. Its target encoding implements
`CollectionDerivation`, naming one canonical `Source` encoding and a runtime
`Argument` carried by the concrete mapping descriptor:

If a downstream crate owns neither the source nor target encoding, Rust's
orphan rule prevents that target-owned implementation. It can instead provide
an explicit `CollectionMapping` and select the same engine through
`derive_with`, `ensure_with`, and `maintain_with`.

```text
f(a ⊔ b) = f(a) ⊔ f(b)
```

Then a resolver may derive a merged source once, derive leaves separately and
merge their images, or reuse any stored mixture already present. `DERIVE`
records expose those reusable edges across collection lattices. Newly executed
joins and mappings publish every successful result and equation, even when a
later planning or storage step fails or selects another route. Publication is
operation-ordered rather than phase-batched, so a failure leaves the complete
successful prefix addressable instead of stranding its blobs without their
equations. Canonical joins, mappings, and logical cover views receive one
frozen store snapshot and may resolve immutable dependencies named by their
inputs; unrelated resident blobs are never ambient semantic input.

Succinct storage applies this model as two ordinary derivations:

```text
SimpleArchive --DERIVE--> SuccinctArchiveBlob --DERIVE-->
    Rank9AcceleratedSuccinctArchiveBlob
```

```rust,ignore
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
    UnionArchive,
};

let source = storage.collection("models", source_policy)?;
let raw = storage.derive::<SuccinctArchiveBlob>(source, (), raw_policy)?;
let accelerated = storage.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
    raw,
    (),
    accelerated_policy,
)?;

storage.ensure(source, &writer).await?;
storage.maintain(raw, &writer).await?;
let after = storage.maintain(accelerated, &writer).await?;

let observed = after.collection(accelerated)?;
let facts: UnionArchive<OrderedUniverse> = observed.view()?;
```

Each ordinary mapping call selects only the admitted support already realized
by its immediate source in the call's initial snapshot. If a new commit arrives
after raw maintenance, accelerated maintenance processes the raw members which
exist; it does not demand an unbuilt raw image of that new commit. A later pass
advances the two lattices again. Source support is still expressed in the same
foundational coordinates; only the selection of currently usable input changes.

For a command-line maintenance owner, `trible pile collection maintain-all`
discovers this source order from explicitly selected descriptor handles and
calls those same operations. Shared upstream dependencies run once per pass;
a foundational dependency is ensured rather than needlessly compacted. The
one-edge `maintain` command remains available. Either command accepts `--watch`
to retain one open pile and repeat after snapshot content changes, including
new proofs or resident definitions. There is no ambient AUTH-expiry timer.
This adds scheduling, not recursive effects inside a mapping kernel. Exact
target selection prevents an old, superseded index from
being restarted merely because its descriptor is still present.

The signing author's public key deterministically biases the order of the
explicitly selected targets, independently of argument order or duplicate
selections. Independent authors therefore tend to attempt different chains
first; each chain still runs upstream first, and shared dependencies run once
per pass. This is priority rather than exclusive ownership: duplicate work is
still possible, no distributed lock is introduced, and each collection's
canonical merge/derive plan remains unchanged.

```sh
trible pile collection maintain-all self.pile blake3:<RANK9_TARGET> --watch
```

The executable still needs the encoding and concrete mapping implementation;
descriptors are data, not dynamically loaded code. This local maintainer and
a network sync process can run independently over the same append-only pile.
Readers attach the resident target from their own snapshot and do not wait
for a global maintenance frontier.

When a caller specifically needs matching representations for one selected
support, use `maintain_exact(raw, &writer, &support)` and
`maintain_exact(accelerated, &writer, &support)`, then
`collection_exact(accelerated, &support)`. Those are explicit requirements,
not necessary boilerplate for an ordinary multi-hop read.

- `ensure(source, &writer)` freezes collection records, capability proofs, and
  resident authorization evidence before acquiring exact missing descriptor,
  selected data, and representation-dependency bytes needed for that root
  frontier. Historical metadata is not a materialization dependency.
  Concurrent records and proofs do not extend its work. The returned snapshot
  is a fresh observation; select
  support from it once and pass that same support across the following edges.
- `snapshot.collection` remains the purely read-only alternative: it
  performs no acquisition or collection algebra and binds only the
  support-aware resident target cover visible in that immutable snapshot.
  `collection_exact` requires a complete realization for explicit support.
- For a derived target, `ensure` freezes the resident, admitted realization of
  its immediate source, while `ensure_exact` accepts explicit foundational
  support. Both publish only missing `DERIVE` work and return a fresh store
  snapshot. Missing source members are invisible to ordinary selection, but
  remain unsatisfied obligations when explicitly requested.
- `maintain` and `maintain_exact` additionally reuse coarsening already resident
  in the immediate source, then carry colliding target members by serialized-size
  tier. They also return a fresh store snapshot.

An ensure may follow existing `MERGE` equations to reuse a resident
support-equivalent target decomposition, but newly executed work crosses only
the mapping. It stores each target artifact before its signed `DERIVE`
record. It never creates a source or target `MERGE`.

Maintenance starts from that derive-complete target cover. If a member `c` of
the coarsest resident source cover provably subsumes at least two current target
images, maintenance can publish `f(c)` even when those images occupy different
target size tiers. A direct source equation `a ⊔ b = c` and resident images
`f(a)`, `f(b)` let the mapping reuse their join with the already-built `c` as a
witness. Otherwise it maps `c` directly. Historical intermediate images are not
constructed merely to reach the selected coarse image; existing equal or larger
target images already discharge the opportunity.

This adds a source-guided route, not recursive upstream maintenance or a global
cost optimizer. It publishes only target `DERIVE` and `MERGE` records and their
outputs. If a target join cannot run because an optional immutable dependency
is absent or the encoding has reached a capacity limit, the finer exact target
cover remains the answer. A downstream operation never constructs an upstream
member as a side effect.

The signing key is explicit on every ensure/maintain call. A call which only
reuses existing work does not need WRITE. If missing support requires a new
derivation, an unauthorized producer receives `UnauthorizedProducer` before
the mapping runs. Optional compaction without WRITE leaves the finer cover
unchanged. Raw local `sign` and `insert` remain unconditional; typed publication
does not reverify signatures it just produced.

New work authenticates the immediate source and target producers it actually
uses. Its signed equation names those exact native input witnesses. It does
not recursively acquire foundational data or re-run ancestral authorization
merely because the immediate input was itself derived. A mapping remains one
hop; `maintain-all` is the explicit scheduler for upstream work.

The subsequent target-only LSM policy has no knob: a target member belongs to
`floor(log2(max(1, serialized_len)))`, and the lowest two content handles in
the lowest colliding tier are carried first. An unavailable join route or
capacity limit may leave a collision stable; otherwise the resulting cover has at
most one member per tier. Pairwise-disjoint carries in one tier share a
deterministic semantic plan, but each output is constructed against a cheap
fresh store snapshot and published immediately. The exact per-point planner is
re-entered before another tier is selected. This avoids a full semantic
re-probe per pair without retaining a tier of newly generated bytes in memory.

Every position uses the same `Cover<E>` shape, but its typed handles cannot be
mixed across representations. `Cover<SimpleArchive>` contains only
`Handle<SimpleArchive>`; `Cover<SuccinctArchiveBlob>` contains only
`Handle<SuccinctArchiveBlob>`; the second stage uses
`Handle<Rank9AcceleratedSuccinctArchiveBlob>`. Stored `MERGE` equations define
support-equivalent routes; `Cover` carries no route-mode bit. Ordinary raw
Succinct derivation follows the resident-node priority above while preserving
foundational support. The accelerated stage resolves the ordinary derived
lattice over that same support. Its cover-aware view
reads each embedded raw handle through the store snapshot and validates the
exact raw/index pair before constructing the query runtime. There is no
separate member-image mode.

None of them signs a replacement root, advances a head, flushes implicitly, or
adds a special manifest. [Regular-path summaries](regular-path-indexes.md) and
Rank9 acceleration both use the same collection algebra. The accelerated
encoding is a Merkle root whose first 32 bytes name its exact portable raw
child. It is also a full lattice: resident accelerated children `A(a)` and
`A(b)` join canonically to `A(a ⊔ b)` when their exact raw union is already
resident with a source-merge witness. The mapping's optional `join_images` hook
passes that union to accelerated construction, avoiding raw serialization and
hashing; the hook's default is the ordinary canonical target join. If the raw
union is absent, accelerated maintenance declines that carry before attempting
to reconstruct it and keeps `{A(a), A(b)}`; a
separate upstream maintenance call may later publish the raw union, after which
a retry can carry the accelerated lattice. Each mapping or join emits exactly
one blob and then its equation. Physical resolution excludes an accelerated
member whose named raw child is unavailable and retries a finer
support-equivalent route; the typed view repeats the raw/index check at its
decoding boundary.

## WANT missing content or computation

Sparse evidence discovery deliberately does not fetch commit dependencies.
`WantStore` adds operational interest to one idempotent grow-only set with
three request shapes:

- `Blob(handle)` — obtain those exact bytes;
- `Merge(collection, low, high)` — discover an existing matching merge result;
  and
- `Derive(target, input)` — discover an existing matching derivation; the
  target descriptor already names the source collection and concrete mapping.

`Blob(H)` is the only exact-content identity. A reconciler may satisfy it from
local workers or discover providers under opaque KDF(H), without activating or
even naming a collection. The provider proves H first and the requester second,
with both proofs bound to the authenticated endpoints; H itself is never sent,
and landed bytes must hash to H. The answer to an operation WANT is the
ordinary native equation; obtaining its result bytes is a separate blob WANT.
A WANT grants no collection authority and does not change the value of any
collection. There is no `unwant` operation: cache eviction belongs to Yard's
physical rewrite policy, which re-records only surviving blob demand, while
merge and derive requests remain durable.

## Migrate a legacy branch explicitly

Old piles may contain signed commit DAGs and mutable pin records. Current
readers retain an immutable `PinSnapshot` and legacy decoders so operators can
inspect and migrate that evidence without restoring the old publication API.

```text
trible pile migrate data.pile branch-to-collection \
  --branch legacy-events \
  --collection-name events \
  --signing-key ./writer.key
```

The command is deliberately same-pile: source commit blobs must already be
resident. It freezes the selected legacy head, validates the complete reachable
DAG, and converts each authored node into a native commit using its exact
`repo::content` and `metadata::archive` handles. A missing metadata archive maps
to the canonical empty archive. Contentless merge wrappers are validated but do
not become members.

With no further options the target descriptor gives the migration signing key
one-root direct READ and WRITE policies. The resulting commits are therefore
admitted directly by ordinary collection admission against a store snapshot.

The migration-only `--authority` option instead uses another trust root for
both direct policies:

```text
trible pile migrate data.pile branch-to-collection \
  --branch legacy-events \
  --collection-name events \
  --authority <64-hex-character-ed25519-public-key> \
  --signing-key ./writer.key
```

Local publication remains unconditional, so this form still writes commits
signed by the migration key. A later read admits them only when the store holds
enough exact root-to-signer `ACTION_WRITE` evidence for the resulting
descriptor handle. The migration command does not invent, scan for, or store
that delegation.

The complete source DAG and every prepared target element are validated before
the target descriptor, dependency, or commit is published. Storage failures
remain backend errors; authorization is deliberately deferred to reads rather
than treated as permission to append locally.

Legacy wrapper parents, messages, timestamps, authors, and signatures are not
silently reinterpreted as application metadata. Two source nodes with identical
data and semantic metadata map to one intrinsic native commit. Re-running with
the same collection identity and key is idempotent.

Migration is the only reason application-facing tooling needs to name a legacy
branch. New code publishes directly to collections.

## Operational invariants

- Persist dependencies before the record that makes them meaningful.
- Treat a cover's payload identities as semantic ground truth. Availability is
  expressed as a subset in those coordinates; physical decomposition stays
  private to same-snapshot materialization. Signed commits and metadata remain
  lazy provenance queried separately.
- Treat stored signed equations as reusable materialized LSM work. Never
  replay algebra merely to trust a local equation; apply target WRITE and
  follow its exact endorsed record route instead. Payload aliases must not
  enlarge that route's support.
- Persist every successful join or mapping. Yard/GC policy alone decides when
  its result bytes leave local storage.
- Keep admission, retention, and WANT policy orthogonal.
- Carry exact covers across derivation boundaries instead of asking for an
  ambient “latest”.
- Flush at explicit application durability boundaries.
- Merge stores by union; never choose meaning from append order.

These rules are sufficient for both low-latency single-process use and sparse
distributed collection maintenance without introducing a second execution
model.
