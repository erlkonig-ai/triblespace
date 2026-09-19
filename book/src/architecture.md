# Architecture Overview

TribleSpace is an embedded knowledge graph whose storage and distribution model
is a small join algebra. Facts, blobs, and publication records are immutable;
independent stores combine by union. The architecture follows from that choice
rather than wrapping an ordinary mutable database in a replication protocol.

## The load-bearing principles

### Content addressing

Every blob is named by a hash of its bytes. Identical values deduplicate,
readers can validate integrity without trusting storage, and a reference has
the same meaning in memory, in a pile, or on an object store. Handles fit in a
trible's 32-byte value slot, so descriptions, datasets, metadata, and large
attachments all use the same reference primitive.

### Monotone evidence

A `TribleSet` is a set of immutable facts. A `CollectionStore` is a set of
immutable algebra records. Their merge is set union, which is associative,
commutative, and idempotent. Concatenating independently written piles therefore
cannot create a last-writer-wins conflict or change the meaning of an existing
record.

This is the practical consequence of the [CALM
principle](https://arxiv.org/abs/1901.01930): monotone conclusions do not need a
coordination protocol. Application-level change is represented explicitly as
new facts, version links, or successor DAGs rather than by overwriting an
ambient current value.

### Authority and computation are separate

A signed `COMMIT` says that an author places one element in a collection.
A signed `MERGE` or `DERIVE` endorses a reproducible computation connecting
known elements. The former introduces membership; the latter lets a reader
reuse materialized work from a producer admitted by the target's WRITE policy.
A signature identifies the endorser; it does not prove the equation correct.
Readers do not repeat the encoding join or mapping to check it.

Foreign record bytes are signature-checked once at ingress. Typed local
publication and trusted store replay do not repeat that check. Admission still
uses the proofs and resident capability definitions of each frozen snapshot:
a later grant or newly resident definition may activate an old equation.
Generic collection authority does not expire as the clock advances.

That separation is why a materialized index does not become ground truth merely
because it is convenient, and why collecting an accelerator does not erase the
committed facts from which it can be rebuilt.

Who may make that signed assertion can be proven without making storage a
policy oracle. A descriptor carries independent READ and WRITE policies. Each
is open or a canonical quorum over external trust roots with one semantic
threshold.
Each resident proof is one self-contained, prefix-signed path from one root:
its header binds the exact resource, and every edge carries a capability
definition handle, delegate, and signature over the complete prefix. Definitions
describe independent invocation and delegation action sets; a child's actions
must all be delegated by its parent. The handles may differ. Ordinary collection
operations count independently valid rooted prefixes against `ACTION_WRITE`
on the descriptor, with roots selected for that action rather than the grant's
exact handle. Sibling paths cannot lend one another delegation authority, and
merely finding an unverified or irrelevant proof in storage grants nothing.

## Architectural layers

```text
┌──────────────────────────────────────────────────┐
│ Application                                      │
│ entity! · Fragment · find! · pattern!            │
├──────────────────────────────────────────────────┤
│ Typed collections and immutable observations     │
│ publish, select exact covers, materialize views  │
├──────────────────────────────────────────────────┤
│ Collection algebra                              │
│ signed COMMIT · stored MERGE · stored DERIVE     │
├──────────────────────────────────────────────────┤
│ Storage                                          │
│ CollectionStore · BlobStore · WantStore          │
│ CapabilityProofStore                             │
├──────────────────────────────────────────────────┤
│ Data and representations                         │
│ TribleSet/PATCH · SimpleArchive · SuccinctArchive│
└──────────────────────────────────────────────────┘
```

The boundaries are deliberately narrow. Query constraints do not know how
bytes were published. A collection encoding or mapping does not decide
replication policy. A blob store does not infer authority from a handle it
happens to contain.

## Tribles, sets, and fragments

A [`Trible`](https://docs.rs/triblespace/latest/triblespace/trible/struct.Trible.html)
is a fixed 64-byte entity–attribute–value fact. The attribute determines how
the value's 32 bytes are interpreted. A [`TribleSet`](https://docs.rs/triblespace/latest/triblespace/trible/struct.TribleSet.html)
stores each fact once while maintaining the six entity/attribute/value
permutations needed by the query engine. The underlying persistent adaptive
tries make cloned sets cheap and union, intersection, and difference structural
operations.

A `Fragment` is the publication unit applications normally construct. It
carries:

- ordinary facts;
- descriptive metafacts;
- exported intrinsic entity IDs; and
- the content-addressed attachments referenced by either fact set.

Fragments compose with `+=`. The `entity!` macro derives an ID when no explicit
subject is supplied and inserts encoded blob payloads into the fragment's
attachment store. This keeps provenance and required bytes together without
mixing schema descriptions into ordinary application queries.

## Blob storage

`BlobStorePut`, `BlobStoreGet`, `BlobStoreMeta`, and `BlobStoreList` describe
small independent capabilities rather than one all-or-nothing database trait.
The main backends are:

- `MemoryRepo` for process-local work and tests;
- `Pile` for one append-only, memory-mapped file; and
- `ObjectStoreRemote` for S3-compatible storage.

Content addressing makes storage placement a physical concern. A missing local
blob is not a semantic retraction: another node may still provide the exact
bytes later.

## Collections are self-describing lattices

A collection descriptor is an ordinary `TribleSet`, encoded as a canonical
`SimpleArchive`. Its content handle is the `CollectionHandle`. A root descriptor
normally states:

- a human-readable UTF-8 name;
- the canonical member encoding; and
- independent descriptor-local READ and WRITE admission policies.

A derived descriptor replaces the name with its source collection and one
concrete mapping entity. Canonical builders derive that entity's id, while
readers preserve the substitution rule by validating its algorithm and
parameters instead of its minting history. The entity names a mapping algorithm
and carries its concrete parameters as ordinary tribles. The target encoding
and both policies remain local to the derived descriptor; policy never
inherits from the source. Descriptions of the encoding and mapping algorithm
travel in the same archive, so a record naming the descriptor remains
interpretable without a separate registry entry.

`CollectionStore` contains three native record kinds:

| Record | Meaning | Dense payload |
|---|---|---:|
| `COMMIT(C, x, metadata, author, signature)` | The author asserts `x` as an independent member of `C`. | 192 bytes |
| `MERGE(C, a, b, c, author, signature)` | The author endorses `a ⊔ b = c` under `C`'s join law. | 224 bytes |
| `DERIVE(T, a, b, author, signature)` | The author endorses the mapping named by `T` from `a` to `b`. | 192 bytes |

The exact canonical record value is the semantic object; none of the three has
a synthetic entity ID. A repeat insert is a no-op. Fixed-width physical indexes
and the network PATCH use a full-width BLAKE3 fingerprint of the kind and
canonical payload, but that key is not collection semantics. All three records
are signed and admitted by WRITE on the collection they name. Multiple
endorsers can sign the same equation: these are distinct provenance records
but one semantic equation. Inferred equations carry only endpoints, not
fabricated signatures or provenance records.

The algebra has no distinguished head. Several commits coexist, and the value
of a selected collection view is the join of its admitted members. This makes a
commit the atomic publication boundary without inventing a mutable register
above it.

## Publishing and observing

The collection value is its canonical descriptor handle, and the storage
backend owns I/O and durability. `store.collection(name, policy)` constructs
and registers a canonical root descriptor. `store.derive::<Target>(source,
argument, policy)` does the same for a target-owned canonical derivation.
Mappings between two foreign encoding types use the explicit
`store.derive_with(source, mapping, policy)` coherence seam.
`store.commit(collection,
signer, fragment)` publishes attachments, canonical data, canonical metadata,
and the signed native record in dependency order. Local publication performs
no authorization check and no implicit flush: authorization governs which
resident assertions another operation admits, not what a process may append to
its own store.

Reads are exact about what they observed, not magical about global time:

- `store.snapshot()` freezes blob bytes, collection records, capability proofs,
  and backend state from one coherent known prefix;
- `collection.admitted(&snapshot)` applies the descriptor WRITE policy and
  resident capability evidence to obtain one semantic `Cover<E>` without
  fetching member data;
- `cover.available(&snapshot)` projects complete resident realizations back
  into the cover's semantic coordinates; and
- `cover.materialize::<V, _>(&snapshot)` privately selects a resident
  support-equivalent physical decomposition and reconstructs the logical value
  through that same immutable observation.
  `collection.read(&snapshot)` concisely observes and materializes the maximal
  resident collection view at that same frozen prefix.

Snapshots carry no clock. Content-change masks compare stored evidence, and
collection authorization does not expire with wall time. An application action
such as Secrets key delivery supplies its own evaluation time and interprets
its deadline facts before counting each root's proof prefix; that does not
expire collection membership.

Cover identity is the collection descriptor plus distinct payload handles.
Signer, signature, and metadata attestations currently known to the store
remain queryable, but no attestation is required for replay, and another one
over the same payload does not change the cover or repeat data work.

Each store snapshot observes one known prefix of an append-only store. A
concurrent commit may appear now or on the next call, but one observation never
combines records from one prefix with payloads from another. The
WRITE-policy roots and every signer with sufficient valid resident support
participate; unauthorized commits remain inert.

## Derived physical representations

The same logical data can be projected into encodings optimized for a
particular task. A canonical SuccinctArchive collection or a regular-path
summary is connected to its source by a mapping which is a join homomorphism:

```text
f(a ⊔ b) = f(a) ⊔ f(b)
```

That law makes equations on either side of the mapping reusable evidence.
Construction and representation maintenance are separate operations. The
foundational support is always `Support = Cover<SimpleArchive>`: the admitted
committed payloads at the root of the descriptor lineage. Mapping and merging
never change those denotational coordinates. Ordinary multi-hop maintenance
invokes each mapping in order over whatever its immediate source already
realizes. Explicit support is needed only when the caller requires matching
representations of a chosen support; it is never an intermediate physical cover.

`ensure` and `ensure_exact` are live asynchronous store operations. For a root
`SimpleArchive` collection, they acquire missing blobs for admitted or explicit
foundational support without publishing equations. For a derived target,
ordinary `ensure` selects the admitted support already realized by resident
immediate-source members; `ensure_exact` instead requires the explicit support.
Both reuse resident target nodes and stored equations, acquire exact missing
dependencies for selected work, and publish only missing `DERIVE` work for
their one immediate mapping. Neither operation creates a `MERGE`, computes
an upstream blob, or emits a durable `WANT`. `maintain` and `maintain_exact` first
perform that same realization work and then repeatedly join target members in the
deterministic dyadic serialized-size tiers. A target join whose exact immutable
dependency cannot be acquired leaves a finer target cover in place. Different
target covers may denote the same join, and every lattice position uses the
same `Cover<E>` shape while retaining its own typed member handles. Missing
derived artifacts are cache misses, not missing facts.

Every store-level ensure or maintain operation returns a fresh
`StoreSnapshot`. The result is the post-operation temporal boundary, including
work concurrently published before that snapshot. Read-only
`CollectionSnapshotExt::{collection, collection_exact}` selects a resident
target cover from one such store snapshot and returns a `CollectionSnapshot`
which owns that immutable observation, the invariant foundational support, and
the realized target cover. A caller chooses the logical projection later with
`CollectionSnapshot::view`.

`Cover` carries no route mode. The resolver checks its explicit members first
and, only when needed, widens through stored `MERGE` equations to a resident
equal-support route. Rank9 acceleration is another ordinary derived collection.
Its members are ordinary
`Blob<Rank9AcceleratedSuccinctArchiveBlob>` values whose first 32 bytes name the
exact portable `SuccinctArchiveBlob` child carrying their source rows. The root
and named child together are a complete source-bound accelerated encoding, not
a separate sidecar or runtime artifact.

Both raw Succinct and Rank9-accelerated members own canonical joins. The Rank9
join computes the same union, but its result names the exact raw Succinct union
as an immutable child. It may consume that raw union when the blob is already
resident; it never creates the upstream raw blob or its `MERGE` record. If the
child is absent, target maintenance leaves the exact finer accelerated cover
in place. A caller which wants both lattices compact invokes ordinary maintenance
on their mapping hops explicitly, in order. Exact requests can instead pin the
same foundational support across both hops. A cover-aware view
follows each embedded handle through its store snapshot, validates the exact
raw/index pair, and only then builds the transient query runtime. A root whose
raw child is absent is not a usable query value.

## WANT is operational, not semantic

A `WantStore` records operational interest in obtaining a blob. `Blob(H)` is
the only request shape and names no collection. WANTs do not add collection
members, authorize authors, retain all referenced data, or force another node
to perform work. They are durable coordination-free questions which a
reconciler may satisfy by fetching content into the local store.

The network reconciler discovers exact providers under the opaque,
domain-separated locator KDF(H). An H-bound endpoint token rejects false
directory entries before dialing. The direct stream then performs a
provider-first, requester-second proof of H, bound to both authenticated
endpoint identities, without ever transmitting H. Returned bytes must hash to
H. This path does not load a collection descriptor or consult READ(C).

Keeping WANT orthogonal prevents evidence convergence from becoming
involuntary blob mirroring. A peer can repair a READ-authorized collection's
record and authorization-evidence overlay, then decide which blobs and derived
representations are useful locally.

## Routing is soft state, not semantic evidence

Bootstrap peers are process configuration. Gossip origins, DHT referrals,
connection liveness, provider leases, and backoff are bounded process-local
state. Restarting may forget them without changing a collection, and none of
them authorize a peer, promise content residency, or retain a blob. Historical
PEER and STORE_SCOPE records remain physically decodable for old piles but do
not participate in current synchronization or repository snapshots; semantic
rewrites drop them.

## Storage and synchronization compose by union

`Pile` stores blobs, native collection records, capability proofs, and WANT
records in one
append-only log. `ObjectStoreRemote` places immutable collection records under
content-derived object keys. The network layer uses an opaque collection-topic
wake and READ(C)-authorized Merkle walks to union that collection's records and
structurally relevant native READ(C)/WRITE(C) proof records. Each proof record
is the complete authorization value and has no referenced blob closure.
Independently, every resident blob may
publish an opaque XOR-DHT lease under KDF(H); knowing H is the bearer capability
for its exact bytes regardless of collection policy or collection-repair
direction. Collection READ(C) gates collection anti-entropy, but never exact
GET. Merge/derive questions are answered from the
converged local record index.
In every case convergence means unioning evidence; it does not mean electing a
winner.

Legacy branch and pin records remain decodable only so old piles can be
inspected, conservatively retained, and explicitly migrated. They are not part
of the current publication or authorization model.
