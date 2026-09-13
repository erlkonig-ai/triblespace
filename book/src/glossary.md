# Glossary

This chapter collects the core terms that appear throughout the book. Skim it
when you encounter unfamiliar terminology or need a refresher on how concepts
relate to one another in TribleSpace.

### Action
An uninterpreted 128-bit identifier naming one exact operation. Actions do not
form a hierarchy and never imply one another. For example, `ACTION_WRITE` and
`ACTION_READ` are separate atoms even when they concern the same collection.

### Attribute
A property that describes some aspect of an entity. Attributes occupy the
middle position in a trible and carry the `InlineEncoding` (or blob-handle
encoding) that interprets and validates the value. Modules mint them with the
`attributes!` macro, so they behave like detached struct fields: each attribute
remains independently typed even when many are combined to describe the same
entity, preserving its individual semantics. Provide an explicit 128-bit id in
the macro when you need a canonical column shared across crates or languages;
omit the literal to derive a deterministic id from the attribute name and
encoding (the macro wraps the name + encoding id in an `entity!{}` fragment and
takes the root for you), which is handy for short-lived or internal attributes.

### Blob
An immutable chunk of binary data addressed by the hash of its contents. Blobs
store payloads that do not fit in the fixed 32-byte value slot—long strings,
media assets, archived `TribleSet`s, commit metadata, and other large
artifacts. Each blob is tagged with a `BlobEncoding` so applications can decode it
back into native types.

### Blob Store
An abstraction that persists immutable content-addressed blobs. Implementations
back local piles, in-memory collections, or remote object stores while exposing
small capability traits for insertion, retrieval, metadata, and enumeration.

### Capability Proof
A canonical self-contained, prefix-signed byte string. Its header contains a
grammar magic, opaque resource, and one Ed25519 root. Each edge then contains
an exact action, mode, optional inclusive validity interval, delegate, and a
strict Ed25519 signature over the complete prefix through that delegate. Every
signed prefix is therefore a proof for its intermediate subject. Its BLAKE3
digest is the proof ID used for exact physical lookup. Verification also
receives the external trust root, expected subject, explicit instant, and exact
request; authority is the meet of the path's restrictions, never a consequence
of proof presence.

### Capability Proof Store
A grow-only native set of canonical capability proofs. It supports
deterministic enumeration and exact lookup by proof ID, but no discovery by key
or semantic request. Storing a proof preserves evidence but does not make the
proof authorized or root any blob closure.

### Commit
A signed native collection membership assertion. A `CollectionCommit` names
the exact collection descriptor, data element, mandatory metadata archive, and
author. Its exact canonical 192-byte value is the assertion; it has no
synthetic entity ID. Commits are independent leaves rather than snapshots in a
parent chain.

### Capability Presentation
One owned `CapabilityProof` paired with the exact subject key the caller
expects it to establish. The expectation prevents a valid prefix or proof for
another principal from silently becoming an admission decision; no companion
bundle or claim blobs are needed.

### Collection
A self-describing grow-only join semilattice. Signed commits introduce members;
stored merge records describe materialized joins within the lattice; derivation
records describe materialized mappings into another collection. Warm resolution
reuses those equations without executing their algebra again. A
collection has no distinguished head. In Rust, `Collection<E>` is the cheap
descriptor handle after the runtime member encoding has been validated against
the `CollectionEncoding` type `E`.

### Cover
One exact point in a collection lattice, represented by a typed collection
descriptor and a PATCH set of distinct `Handle<E>` payload handles.
Signatures, authors, and metadata are optional provenance fibers queryable from
the store, not part of cover identity or required for replay, so several commits
over identical data collapse to one member. Distinct covers may have the same
support: a stored merge records that `{a, b}` and `{a⊔b}` denote the same join.
Cover construction is opaque; admission and stored collection algebra produce
them rather than accepting caller-forged hash sets.

### Collection Admission
The read-time signer decision performed by
`collection.admitted(&store_snapshot)`. Each WRITE-policy root acts directly;
resident proof paths rooted in the policy's canonical root set are considered
at the snapshot's frozen instant for the exact `ACTION_WRITE`/collection atom. A writer is
admitted only when it has the policy's required distinct root support. Invalid,
expired, or irrelevant candidates grant nothing without poisoning other
evidence.

### Collection Descriptor
A canonical `SimpleArchive` describing a collection's UTF-8 root name or exact
derived source, member encoding, and independent READ and WRITE admission
policies. Each policy is open or a canonical quorum over capability roots with
one semantic threshold. A derived descriptor also links one concrete mapping
entity carrying its algorithm and parameters. Its content handle is the
`CollectionHandle`, so every native record which names a
collection can resolve its meaning through the ordinary blob store. A derived
descriptor states its own policies and never inherits them through its source.

### Collection Encoding
A `BlobEncoding` with one canonical member validation rule, exposed by
`CollectionEncoding`. Every member is an ordinary typed blob, and every
collection encoding defines one canonical associative, commutative, and
idempotent member-join operation. When one blob cannot hold the result, a finer
`Cover<E>` represents the same join, so the collection lattice remains total.
Derived collections are full lattices connected by mappings, not
projection-only representations.

### Collection Member
One ordinary typed `Blob<E>` admitted into a `Collection<E>`. A source-bound
encoding may name another blob in its bytes; validation and cover-aware views
follow that handle through the same immutable store snapshot rather than
wrapping the member in another runtime artifact. For Rank9-accelerated
SuccinctArchive, the root embeds its exact raw source handle. Its canonical join
names the corresponding raw union as an immutable dependency and succeeds once
that blob is resident.

### Collection Derivation
A parameterized source-to-target conversion owned by the target encoding's
`CollectionDerivation` implementation. Its associated `Source` fixes the
incoming encoding, while `Argument` carries the concrete runtime parameters in
the target descriptor's mapping entity. It maps ordinary source blobs to
ordinary target blobs. The mathematical contract is a join homomorphism over
their logical values:
`f(a ⊔ b) = f(a) ⊔ f(b)`.

When neither encoding crate can own that implementation, `CollectionMapping`
is the coherence-safe explicit extension seam. The `derive_with`,
`ensure_with`, and `maintain_with` operations select such a mapping value or
type; both surfaces execute the same derivation engine and persist the same
descriptor facts.

### Collection Store
A grow-only set of native `COMMIT`, `MERGE`, and `DERIVE` records. Insertion is
idempotent by exact canonical record value; combining two stores is set union.
Physical fixed-width indexes may key that value by its full-width fingerprint.

### Store Snapshot
One immutable, coherent known-prefix observation produced by
`SnapshotSource::snapshot`. A snapshot owns all blob, collection-record,
and capability-proof reads for that prefix and implements
`StoreSnapshot::changes_since` for conservative local invalidation. Collection
admission produces a semantic `Cover<E>` from it; `Cover::available` returns
the greatest semantic subset with a complete resident realization; and
`Cover::materialize` privately selects physical members before reconstructing
either an eager value or a lazy sharded view through the same snapshot.

### Collection READ
The exact `ACTION_READ` capability over one collection descriptor handle.
Network repair presents bounded independent proof paths for the authenticated
endpoint and the descriptor's READ policy. Knowing the collection handle
permits joining its opaque wake topic, but does not reveal records, proofs,
counts, or blobs; collection evidence crosses only after READ(C) admission.
`Open` READ needs no proof. Exact immutable content is a separate bearer
system: every served resident H may be advertised under opaque KDF(H), and
exact GET neither names a collection nor consults READ(C).

### Constraint
The trait that every query operator implements. Its methods—`variables`,
`estimate`, `propose`, `confirm`, `satisfied`, and `influence`—let the Atreides
solver navigate the search space without a separate planner. `propose` and
`confirm` take a *frontier*: a whole batch of parent bindings, of which a
single binding is the width-1 case. Constraints are stateless: every method
receives the bindings it needs as a parameter, so the engine can backtrack,
batch, and split without telling anyone.
Estimates guide variable ordering and never change results; `confirm` may only
kill candidates, never add or revive them. Custom data sources and application
predicates participate in queries by implementing this trait.

### Entity
The first position in a trible. Entities identify the subject making a
statement and group the attributes asserted about it. They are represented by
stable identifiers so multiple facts about the same subject cohere.

In practice you pick an identifier policy:
- **Extrinsic ids** (for example `ufoid`, `fucid`, `genid`) track a conceptual
  subject across edits and versions. Use these when you intend to accumulate
  additional facts over time.
- **Intrinsic ids** (content-derived hashes) are recomputed from the entity's
  asserted fields. The `entity!` macro uses this policy when you omit the
  explicit `id @` prefix (or when you write `_ @`), so identical records unify
  naturally.

Ownership policies and schemas determine who may mint new facts for a given
identifier.

### Fragment
A self-contained bundle of exported IDs, content facts, descriptive metafacts,
and one content-addressed blob store shared by both fact sets. `entity!` and
import pipelines return fragments; `entity!` carries descriptions for the
attributes that actually emitted facts. Fragments compose via `+=` without
mixing descriptions into ordinary queries. Use `Fragment::root()` to extract
derived IDs, `Fragment::empty()` to start accumulation, and spread (`*`) to pass
child fragments into parent entities, giving Merkle trees for free.

### Derive
A signed endorsement of an exact mapping from one source element into a derived collection.
The target descriptor names both source and concrete mapping, so the
record carries the target, input, output, signer, and signature. Target WRITE
admits its producer; the source's WRITE policy does not. Derivations are
reusable materialized work, not new membership. Every successful mapping is stored
with its equation; Yard/GC decides later whether its bytes remain resident.

### Merge
A signed endorsement of `a ⊔ b = c` inside one collection. A resident stored
result can replace its inputs in a physical cover without changing the logical
value or creating new membership. Warm resolution admits the producer by that
collection's WRITE policy and does not recompute the join.

### PATCH
The **Persistent Adaptive Trie with Cuckoo-compression and Hash-maintenance**.
A single PATCH stores one ordering of a trible set in a 256-ary trie whose
nodes use byte-oriented cuckoo hash tables and copy-on-write semantics. A
`TribleSet` maintains six PATCH instances — one per permutation of entity,
attribute, and value. Shared leaves keep permutations deduplicated, rolling
hashes let set operations skip unchanged branches, and queries only visit the
segments relevant to their bindings, further described in
[the deep-dive chapter](deep-dive/patch.md).

### Pile
An append-only collection of blobs, native collection records, native
capability proofs, WANT records, and legacy pin evidence stored in one file.
Retired PEER and STORE_SCOPE records remain structurally readable but do not
enter repository state and disappear under semantic compaction. Piles are memory
mapped, recoverable after interrupted appends, and mergeable by byte
concatenation. Legacy pin records remain decodable only for conservative
retention and explicit migration.

### Encoding
The byte-layout contract for a typed value. Encodings assign language-agnostic
meaning to the raw bytes — they are not the concrete Rust types — so any
implementation that understands the encoding can interpret the payloads
consistently. **Inline encodings** map the fixed 32-byte payload of a trible to
native types; **blob encodings** describe arbitrarily long payloads so tribles
referencing those blobs stay portable. The corresponding traits are
`InlineEncoding` and `BlobEncoding`.

### Policy Root
One Ed25519 key named by an admission policy. Roots have inherent support for
their policy's action and may issue capability paths. A collection may name
several roots and require one threshold; READ and WRITE have independent root
sets and thresholds. Whether one root share remains delegable is carried by
the signed mode on that path, not derived from sibling proofs. A root is not a
network namespace, routing scope, roster, or mutable owner.

### Collection WRITE
The exact `ACTION_WRITE` capability over one collection descriptor handle.
Signed COMMITs are active only when their author satisfies the descriptor's
WRITE policy in the observed proof set. Local stores may retain inactive
commits; synchronization and concatenation remain monotone because later proof
evidence can activate them without retracting bytes.

### Collection Wake
A fixed signed `iroh-gossip` message on the collection-handle topic. It names
the endpoint origin and one opaque semantic repair root, but contains no records,
proofs, blob handles, counts, or component roots. A changed wake prompts a
separate READ(C)-authorized exact PATCH repair; gossip is a latency hint, not
the source of truth.

### Trible
A three-part tuple of entity, attribute, and value stored in a fixed 64-byte
layout. Tribles capture atomic facts, and query engines compose them into joins
and higher-order results.

### TribleSpace
The storage model which organises tribles across blobs, PATCHes, and native
collections. It emphasizes immutable content-addressed data, monotone set
semantics, and reproducible derived representations.

### Inline
The third position in a trible. Values store a fixed 32-byte payload interpreted
through the attribute’s schema. They often embed identifiers for related
entities or handles referencing larger blobs.

### WANT
A durable operational request for a blob or for an existing merge/derive
result. `Blob(H)` is the sole exact-content request and can be fulfilled through
collection-independent KDF(H) discovery. WANT is operational policy: it
neither adds collection authority nor changes a collection's logical value.
