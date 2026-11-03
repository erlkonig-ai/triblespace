The `trible` module defines the `Trible` struct, the smallest unit of
knowledge the system stores. Instances of `Trible`s live inside
`TribleSet`s, which index each fact in several complementary ways so that
queries can be answered with as little work as possible.

``` text
┌────────────────────────────64 byte───────────────────────────┐
┌──────────────┐┌──────────────┐┌──────────────────────────────┐
│  entity-id   ││ attribute-id ││        inlined value         │
└──────────────┘└──────────────┘└──────────────────────────────┘
└────16 byte───┘└────16 byte───┘└────────────32 byte───────────┘
─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶
```

At a high level a trible is a three-tuple consisting of an entity, an
attribute, and a value. The entity and attribute are both 128‑bit abstract
extrinsic identifiers as described in [triblespace::core::id], while the value is an
arbitrary 256‑bit [triblespace::core::inline::Inline]. The value width deliberately matches
the size of an intrinsic identifier so larger payloads can be referenced via
blobs without inflating the inlined representation.

## Abstract identifiers

Entities and attributes are purely extrinsic; their identifiers do not encode
any meaning beyond uniqueness. An entity may accrue additional tribles over
time and attributes simply name relationships without prescribing a schema.
This keeps the format agnostic to external ontologies and minimises accidental
coupling between datasets.

The value slot can carry any 256‑bit payload. Its size is dictated by the need
to embed an intrinsic identifier for out‑of‑line data. When a fact exceeds this
space the value typically stores a blob handle pointing to the larger payload.

Tribles are stored as a contiguous 64‑byte array with the entity occupying the
first 16 bytes, the attribute the next 16, and the value the final 32 bytes.
The name "trible" is a portmanteau of *triple* and *byte* and is pronounced
like "tribble" from Star Trek – hence the project's mascot, Robert the
tribble. This rigid layout keeps the representation friendly to SIMD
optimisations and allows the storage layer to compute sizes deterministically.

In Rust the record is the `Trible` struct, `#[repr(C, align(16))]` with three
private fields in exactly that order (`e: Id`, `a: Id`, `v: RawInline`) and
no padding, so its bytes are the bytes on disk and on the wire.
`Trible::as_raw` lends them out as a `&[u8; 64]`. A trible's only validity
rule is that neither the entity nor the attribute is nil (all zero), and
zerocopy checks it whenever bytes become a `Trible`: `Trible::force_raw`
copies one row in, and a `View<[Trible]>` borrows many in place. Such a view
also requires a 16‑byte‑aligned base, which pile records (256‑byte aligned)
and archives encoded from a `Vec<Trible>` always have. The derived `Ord`
compares the fields in layout order and each field by its raw bytes, so
tribles sort exactly as their 64 bytes do.

A `SimpleArchive` blob is a sequence of such rows in strictly increasing
order. Readers obtain it as `CanonicalTribles`, which can only be built by
validating bytes: the length and alignment (`BadArchive`), then the row rule
on every row (`BadTrible`), then strict increase
(`BadCanonicalizationRedundancy` or `BadCanonicalizationOrdering`). Empty
input is accepted at any address. Holding a `CanonicalTribles` proves those
checks ran, so code downstream of it reads typed rows instead of
re-validating byte chunks.

## Index permutations

`TribleSet`s index each fact under all six permutations of entity (E),
attribute (A) and value (V) so any combination of bound variables can be
resolved efficiently. Regardless of which columns a query fixes the
search can reach matching leaves with a handful of comparisons:

```text
┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐
│ EAV │  │ EVA │  │ AEV │  │ AVE │  │ VEA │  │ VAE │
└──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘  └──┬──┘
   │        │        │        │        │        │
┌───────────────────────────────────────────────────────┐
│            order-specific inner nodes                 │
└───────────────────────────────────────────────────────┘ 
   │        │        │        │        │        │
   ▼        ▼        ▼        ▼        ▼        ▼

┌───────────────────────────────────────────────────────┐
│                   SHARED LEAVES                       │
│     single canonical E–A–V tribles used by all        │
└───────────────────────────────────────────────────────┘
```

Each permutation maintains its own inner nodes, but all six share leaf nodes
containing the 64‑byte trible. This avoids a naïve six‑fold memory cost while
still letting the search pick the most selective ordering, keeping joins
resistant to skew even when cardinalities vary widely.

## Advantages

- A total order over tribles enables efficient storage and canonicalisation.
- Simple byte‑wise segmentation supports indexing and querying without an
  interning mechanism, keeping memory usage low and parallelisation easy while
  avoiding the need for garbage collection.
- Schemas describe the value portion directly, making serialisation and
  deserialisation straightforward.
- The fixed 64‑byte layout makes it easy to estimate the physical size of a
  dataset as a function of the number of tribles stored.
- The minimalistic design aims to minimise entropy while retaining collision
  resistance, making it likely that a similar format would emerge through
  convergent evolution and could serve as a universal data interchange format.

## Set operations and monotonic semantics

`TribleSet`s provide familiar set-theoretic helpers such as
[`TribleSet::union`](https://docs.rs/triblespace/latest/triblespace/trible/struct.TribleSet.html#method.union),
[`TribleSet::intersect`](https://docs.rs/triblespace/latest/triblespace/trible/struct.TribleSet.html#method.intersect)
and
[`TribleSet::difference`](https://docs.rs/triblespace/latest/triblespace/trible/struct.TribleSet.html#method.difference).
`union` consumes the right-hand operand and merges its contents into the
receiver in place, while `intersect` and `difference` each produce a fresh
`TribleSet` without mutating their inputs. Together these helpers make it
straightforward to merge datasets, locate their overlap or identify the facts
that still need to propagate between replicas while keeping the original
sources intact.

This design reflects the crate's commitment to CALM-friendly, monotonic
semantics. New information can be added freely, but existing facts are never
destroyed. Consequently, `difference` is intended for comparing snapshots
(e.g. "which facts are present in the remote set that I have not yet
indexed?") rather than for destructive deletion. This keeps workflows
declarative and convergent: sets can be combined in any order without
introducing conflicts, and subtraction simply reports the gaps that remain to
be filled.

## Direction and consistency

In many triple stores the direction of an edge is chosen incidentally—there
is no intrinsic preference for `hasColor` over `colorOf`. This ambiguity often
leads to confusion, duplication, or both as different writers pick different
conventions. Common mitigations either mirror every edge automatically (as
done by OWL and RDF through `inverseOf`, doubling storage or demanding runtime
inference) or devolve into bikeshedding about the "correct" orientation.

`tribles` avoids that trap by giving edge direction explicit semantics: the
arrow points from the entity making the claim to the entity being described.
The observer owns the identifier and is responsible for the consistency of the
facts it asserts—see [ID Ownership](triblespace::core::id). This rule naturally fits the
distributed setting where each entity has a single authoritative writer.

Viewed another way, edges always flow from describing to described entities,
while cycles represent consensus between the parties involved. For example,
`hasColor` must point from the object that exhibits the colour to the entity
representing that colour. The orientation is therefore a consequence of the
statement's meaning, not an arbitrary modelling choice.
