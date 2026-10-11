# The Type Algebra of TribleSpace

## Queries as Types, Data as Proofs

TribleSpace grew out of a pragmatic goal: keep data declarative, composable, and statically checkable in Rust.
Along the way we discovered that the core operations already form a **type algebra**.
The macros used to define attributes, entities, and queries map directly onto familiar type-theoretic constructions, yielding an isomorphism between *relations over triples* and *types over records*.

## Attributes Introduce Atomic Types

Each attribute introduced with `attributes!` defines an **atomic type** — a unary relation between an entity identifier and the attribute’s value:

```text
"A74AA..." as pub title : Handle<UTF8String>
```

Formally this is a function `title : Id → ValueTitle`, or, in relational terms, the set `{ (id, value) }`.
In the codebase the macro emits a `static LazyLock<Attribute<S>>` for each declared attribute, so the generated binding already carries the `InlineEncoding` that governs the value column.
The derived form (omit the hex id) hashes the attribute name together with the schema metadata via the entity-core mechanism — equivalent to `Attribute::<S>::named(name)` — which is convenient for quick experiments; shared protocols should still pin explicit ids so collaborators and other languages read the same column.
These atomic pieces are the building blocks for everything else.

## Entities as Intersection Types

An `entity!` expression forms a **record type** by intersecting atomic ones.
Semantically it is the meet (`∧`) of its constituent relations:

```text
Entity{A, B}  ≡  { A : ValueA } ∧ { B : ValueB }
```

At runtime `entity!` expands to a small [`Fragment`](../src/trible/fragment.rs): exported entity ids, a [`TribleSet`](../src/trible/tribleset.rs) containing the asserted facts, descriptive metafacts for the attributes that emitted those facts, and one blob store shared by both sets. The description channel does not participate in intrinsic entity identity or ordinary content queries. Use `+=` to union every channel, and use `root()`/`exports()` when you want the produced entity id(s) back alongside the facts.
At the type level it represents their conjunction.
Records are therefore intersection types: every additional field refines the shape without invalidating existing data.

## Merge Drives Dataset Composition

For content facts, the `+=` operator delegates to [`TribleSet::union`](../src/trible/tribleset.rs), exposed through the `AddAssign` implementation. Fragment composition applies the same set union independently to facts and metafacts, unions exports, and structurally joins the shared blob stores.
`TribleSet::union` performs **set union** on the six internal indexes that back a `TribleSet`.
When the entity identifiers are disjoint the effect is classic dataset union; when they coincide we get field conjunction—record extension.
This dual role is what keeps TribleSpace’s algebra compact.

### One Operator, Two Readings

Everything that looks like “add another field” or “add another record” derives from the single law

```text
union(facts₁, facts₂) = facts₁ ∪ facts₂.
```

The surrounding context determines how to read the result:

| Context        | Effect        | Algebraic Face        |
| -------------- | ------------- | --------------------- |
| same entity ID | extend record | ∧ (field conjunction) |
| different IDs  | add record    | ∨ (set union)         |

The behaviour follows from the idempotent, commutative nature of `TribleSet::union`; no special cases are required in the implementation.

## Patterns as Row-Type Predicates

A `find!`/`pattern!` pair behaves like a **row-type predicate**:

```text
pattern!([A, B])  ≈  ∀r. {A, B} ⊆ r.
```

Read this as “find every entity whose row type `r` is a supertype of this shape.”
The macro expands to an [`IntersectionConstraint`](../src/query/intersectionconstraint.rs) built from [`TriblePattern`](../src/query.rs) constraints, so queries literally evaluate the conjunction of the row predicates.

Patterns compose intersectionally as well: combining two patterns is equivalent to requiring both row predicates simultaneously, mirroring intersection types at the query level.

## The Lattice Perspective

`TribleSet`s form a **join-semilattice** under `union`:

```
union(a, b) = a ∪ b
a ≤ b  ⇔  a ⊆ b.
```

Projection, join, and filtering are lattice homomorphisms: they preserve joins and the partial order.
Because the same algebra handles both data and metadata, the implementation remains uniform and performant—merging facts is always the same low-level operation.

## Practical Payoffs

Seeing the primitives through a type-theoretic lens clarifies several ergonomic choices:

- **Queries as proofs.** Successful `find!` rows witness that an entity inhabits the requested type; absence is simply failure to prove the predicate.
- **Descriptive schemas.** Structural typing drops the need for globally declared records—the type system is implicit in the patterns you write.
- **Composable extensions.** Adding new attributes is monotonic: existing entities continue to satisfy prior predicates, and refined queries simply intersect more row constraints.

## Summary Table

| Level          | Concept           | Operation        |
| -------------- | ----------------- | ---------------- |
| Attribute      | atomic type       | unary relation   |
| Entity         | conjunction       | record formation |
| Dataset        | union             | set composition  |
| Query          | sub-row predicate | type constraint  |
| Implementation | lattice union     | `∪`              |

With a single associative, commutative, idempotent union, we obtain both row extension and dataset union, and a unified logical framework that bridges *data engineering* with *type theory*.
That economy of primitives allows the system to feel simple on the surface yet provide rich type theory underneath.

[Trible]: ../src/trible.rs
