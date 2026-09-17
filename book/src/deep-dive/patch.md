# PATCH

The **Persistent Adaptive Trie with Cuckoo-compression and Hash-maintenance**
(PATCH) is TribleSpace’s workhorse for set operations. It combines three core
ideas:

1. **Persistence.** Updates clone only the modified path, so existing readers
   keep a consistent view while writers continue mutating. The structure behaves
   like an immutable value with copy-on-write updates.
2. **Adaptive width.** Every node is conceptually 256-ary, yet the physical
   footprint scales with the number of occupied children.
3. **Hash maintenance.** Each subtree carries a policy-selected summary that
   allows set operations to skip identical branches early.

Together these properties let PATCH evaluate unions, intersections, and
differences quickly while staying cache friendly and safe to clone.

## Retained state and typed relations

PATCH is the default for retained TribleSpace state. A collection's membership,
for example, is one relation keyed by `(collection, member)`, not a map from
collections to separately owned sets. A prefix view answers one collection's
membership without materializing another catalog. Retained read dependencies
combine by structural union; prior observations remain unchanged.

Key design determines what equality means. PATCH compares key sets, **not
attached values**. Put all semantic operands into a relation key. When a key
names mutable observed metadata instead, replace the leaf through copy-on-write
and compare that metadata explicitly where it affects change detection. A
key-only equality test must not hide a changed timestamp, rejection reason, or
worker state. Inserting an already-present key is not a value replacement.

Use ordered traversal where ordering is observable, with key encodings that
preserve that order (for example big-endian state numbers). Keep domain types
at public boundaries rather than exposing malformed raw identifiers merely to
reuse a trie. Operation-local planning scratch, query projections, and
independent test oracles can still use ordinary ordered maps or sets; they are
not an additional retained database. These representation choices establish
sharing and identity semantics, not a measured speedup for every workload.

## Node layout

Traditional Adaptive Radix Trees (ART) use specialised node types (`Node4`,
`Node16`, `Node48`, …) to balance space usage against branching factor. PATCH
instead stores every branch in the same representation:

* The `Branch` header tracks the first depth where the node diverges
  (`end_depth`) and caches a pointer to a representative child leaf
  (`childleaf`). These fields give PATCH its path compression — a branch can
  cover several key bytes, and we only expand into child tables once the
  children disagree below `end_depth`.
* Children live in a byte-oriented cuckoo hash table backed by a single
  slice of `Option<Head>`. Each bucket holds two slots and the table grows in
  powers of two up to 256 entries.
* A heap `Leaf` owns its key and value. An archive-backed `LocalLeaf` is instead
  a tagged pointer directly into immutable archive bytes. It has no allocation
  or reference count of its own; the enclosing `PATCH` keeps the archive alive.

Insertions reuse the generic `modify_child` helper, which drives the cuckoo loop
and performs copy-on-write if a branch is shared. When the existing allocation
is too small we allocate a larger table with the same layout, migrate the
children, and update the owning pointer in place. Because every branch uses the
same structure we avoid the tag soup and pointer chasing that ARTs rely on while
still adapting to sparse and dense fan-out.

## Resizing strategy

PATCH relies on two hash functions: an identity map and a pseudo-random
permutation sampled once at startup. Both hashes feed a simple compressor that
masks off the unused high bits for the current table size. Doubling the table
therefore only exposes one more significant bit, so each child either stays in
its bucket or moves to the partner bucket `index + old_bucket_count`.

The `byte_table_resize_benchmark` demonstrates how densely the table can fill
before resizing. The benchmark inserts all byte values repeatedly and records the
occupancy that forced each power-of-two table size to grow:

```
ByteTable resize fill - random: 0.863, sequential: 0.972
Per-size fill (random)
  size   2: 1.000  # path compression keeps two-entry nodes fully occupied
  size   4: 0.973
  size   8: 0.899
  size  16: 0.830
  size  32: 0.749
  size  64: 0.735
  size 128: 0.719
  size 256: 1.000  # identity hash maps all 256 children without resizing
Per-size fill (sequential)
  size   2: 1.000  # path compression keeps two-entry nodes fully occupied
  size   4: 1.000
  size   8: 0.993
  size  16: 1.000
  size  32: 0.928
  size  64: 0.925
  size 128: 0.927
  size 256: 1.000  # identity hash maps all 256 children without resizing
```

Random inserts average roughly 86 % table fill while sequential inserts stay
near 97 % before the next doubling. Small nodes stay compact because the
path-compressed header only materialises a table when needed, while the largest
table reaches full occupancy without growing past 256 entries. These predictable fill
factors keep memory usage steady without ART’s specialised node types.

## Archive-backed leaf lifetimes

A `LocalLeaf` is safe only while the allocation containing its bytes remains
alive. Each `PATCH` therefore carries an exact persistent owner cover: a binary
Patricia trie keyed by the data address of each retained `Arc<dyn
ArchiveOwner>`. Retaining the owner also prevents its address from being reused.
The cover is deduplicated by address and structurally shared across snapshots.
Its governing invariant is

```text
owners(LocalLeaves(root)) ⊆ cover
```

Structural operations preserve that invariant as follows:

* archive insertion retains the owner before publishing its `LocalLeaf`;
* cloning clones the root and cover together;
* union joins both covers before either root is moved or detached;
* intersection retains both input covers, because it may reuse a leaf from
  either side;
* difference retains the left cover, because it can only reuse left-hand
  leaves; and
* consuming iterators carry the cover beside their detached traversal queue
  until every queued key has been copied out or dropped.

The cover is a lifetime receipt rather than a reachability index. Operations
may conservatively retain an owner whose leaves disappeared from the result;
direct clearing and removal paths that empty a `PATCH` clear that provenance.
Aggregate reconciliation may nevertheless install or retain a conservative
cover on an already-empty `PATCH`, so emptiness alone does not promise immediate
release. A `TribleSet` shares one such cover across all six PATCH indexes,
joining any divergent covers once at aggregate set-operation boundaries.

## Hash maintenance

PATCH is generic over a sealed hash-maintenance policy. Sealing is part of the
correctness boundary rather than API conservatism: set operations treat equal
subtree summaries as equal key sets, so an invalid third-party implementation
could silently lose data. The built-in policies share the same canonical trie
and differ only in the summary cached by leaves and branches.

The default `XorSip128` policy preserves PATCH's original hot-path layout and
cost. On first use in a process it samples a private random key. Each leaf
fingerprint is the 128-bit output of SipHash-2-4 under that key, and each branch
stores the XOR of its children’s fingerprints. On insert or delete, the old
contribution is XORed out and the new one XORed in, so aggregate maintenance is
constant-time. Set operations compare aggregates first: equal fingerprints
short-circuit under the practical assumption that they denote equal key sets,
while unequal ones force a structural walk. For any fixed pair of unequal sets,
the false-positive probability is approximately 2^-128 under the keyed-hash
assumption.

The raw subtree fingerprints are process-local implementation values, not
serialized identities. They must remain opaque to untrusted chosen-input
callers. Although XOR is linear, the usual linear-dependency construction
requires observing the fingerprints of chosen keys; the private key makes that
attack inapplicable without such an exposure oracle. PATCH's raw root aggregate
therefore stays crate-private.

`TribleSet::fingerprint` preserves the useful O(1) public cache-key API without
opening that oracle. It applies a domain-separated SipHash-2-4 PRF to the root
aggregate under a second process-random key initialized beside the leaf key.
`TribleSetFingerprint::as_u128`, `Debug`, and `Hash` expose only this nonlinear
blinding. Equal sets retain equal tokens within one process, while the XOR of
public singleton tokens reveals nothing useful about the aggregate of their
union. The token remains a 128-bit cache hint, not a durable content identifier
or proof of equality.

The `Blake3Merkle` policy provides a stable 256-bit root for durable indexes and
anti-entropy. Leaves and branches have separate domains. A branch commits to
the key width, canonical compressed-prefix bytes, fanout, subtree leaf count,
and each `(edge, child leaf count, child digest)` tuple in ascending edge
order.
The count and routing metadata used by a reconciliation proof is therefore
authenticated at the branch that advertises it; insertion order and the cuckoo
table's random physical placement cannot affect the root. BLAKE3 has no inverse
update law:
an edited branch is marked dirty and summarized once, in canonical order, when
its branch editor closes. Only branches on the copy-on-write edit path pay that
cost.

For a complete owned key inventory, use
`PATCH::<N, IdentitySchema, (), Blake3Merkle>::from_keys`. It canonicalizes
order and duplicates, then constructs the compressed trie bottom-up so every
retained leaf and every final branch is hashed once in the construction pass.
Debug builds additionally recompute branch hashes to audit the invariants.
Sorted unique input takes a linear fast path; other input first pays for
sorting and deduplication.
Repeated `insert` remains the right operation for a small edit to an existing
snapshot. The `patch_bulk` benchmark compares those two construction paths on
deterministically shuffled distinct 16-, 32-, and 64-byte keys at 10,000 and
100,000 keys; source-buffer cloning is excluded from both timings.

BLAKE3's native chunk tree is not PATCH's tree. It represents fixed-size chunks
of one byte stream, while PATCH is a sparse radix trie with path compression
and changing fanout. Reusing BLAKE3 chaining values would require PATCH to cache
the chunk tree's geometry as a second tree and would not make a child edit
algebraic. Explicit branch framing through BLAKE3's streaming API is both
simpler and canonical. Team-specific anti-entropy salts belong outside PATCH:
key or domain-separate the stable Merkle root at the protocol boundary rather
than making the collection's identity depend on who is comparing it.

Archive-backed leaves do not cache their fingerprint, so PATCH avoids hashing
them when an exact, cheaper decision is available. Pairs of leaf nodes involving
a `LocalLeaf` compare key bytes directly. A `LocalLeaf` paired with a subtree of
cardinality other than one rejects fingerprint equality from the cached count;
a unary branch remains eligible for the ordinary fingerprint path. These are
performance shortcuts only, not collision remediation. Pairs without a
`LocalLeaf` retain the normal cached-fingerprint path.

Consumers can reorder or segment keys through the [`KeySchema`](../../src/patch.rs)
and [`KeySegmentation`](../../src/patch.rs) traits. Prefix queries reuse the
schema’s tree ordering to walk just the matching segments. Because every update
is implemented with copy-on-write semantics, cloning a tree is cheap and retains
structural sharing: multiple owners can clone, mutate independently, and merge
results without duplicating entire datasets.
