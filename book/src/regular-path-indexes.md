# Regular Path Indexes

Regular path queries ask whether two graph terms are connected by a path whose
edge labels are accepted by a finite automaton. TribleSpace keeps that recursive
work outside the core query solver: the standalone `triblespace-paths` crate
materializes the accepted endpoint relation, then exposes it as an ordinary
two-variable [`Constraint`](triblespace::core::query::Constraint).

This separation keeps query-time constraints stateless. The expensive fixpoint
is built once for one exact collection cover; `find!`, `and!`, constants,
and normal dynamic variable ordering then treat the result like any other
relation.

Add the companion crate alongside the facade crate:

```toml
[dependencies]
triblespace = "0.47"
triblespace-paths = "0.47"
```

## Describe the path, then materialize it

Most callers describe a regular path with `PathExpr`. Each leaf is a graph
property `Step`; the expression builders add concatenation, alternatives, and
repetition. `compile` freezes that description into the fixed, epsilon-free
automaton consumed by `PathIndex` and embedded in the descriptor of the
corresponding `PathSummaryBlob` collection.

For example, `friend+` means one or more forward `friend` edges:

```rust,ignore
use triblespace::prelude::*;
use triblespace::prelude::inlineencodings::GenId;
use triblespace_paths::{PathExpr, PathIndex, Step};

mod social {
    use triblespace::prelude::*;
    use triblespace::prelude::inlineencodings::{GenId, ShortString};

    attributes! {
        "A19EC1D9DD534BA9896223A457A6B9C9" as pub name: ShortString;
        "C21DE0AA5BA3446AB886C9640BA60244" as pub friend: GenId;
    }
}

let friend = social::friend.id().into();
let friend_automaton = PathExpr::from(Step::Forward(friend)).plus().compile();

let alice = fucid();
let bob = fucid();
let carol = fucid();
let mut graph = TribleSet::new();
graph += entity! { &alice @ social::friend: &bob };
graph += entity! { &bob @ social::friend: &carol, social::name: "Bob" };
graph += entity! { &carol @ social::name: "Carol" };
let paths = PathIndex::from_tribles(friend_automaton.clone(), graph.iter())?;
```

Every trible is viewed as a directed graph edge from its entity to its inline
value, labeled by its attribute id. Values do not have to encode entity ids,
although a path endpoint must use a compatible inline encoding when it shares a
query variable with another constraint.

The expression operations are regular-language operations:

- `a.then(b)` matches `a` followed by `b`;
- `a.or(b)` matches either expression;
- `star`, `plus`, and `optional` mean zero-or-more, one-or-more, and
  zero-or-one repetitions; and
- `inverse` reverses the complete path. It flips each atomic step, reverses
  sequence order, distributes over alternatives, and preserves repetition.

`Step::Forward` and `Step::Reverse` match one exact attribute in either graph
direction. `ForwardExcept` and `ReverseExcept` match every attribute except a
provided list; an empty exclusion list is a wildcard, available as
`Step::forward_any()` or `Step::reverse_any()`. Inverting an exclusion or
wildcard changes only its direction.

## Canonical expressions and compilation

`PathExpr` canonicalizes structure as it is assembled. Nested sequences are
flattened while retaining their order. Nested alternatives are flattened,
sorted by a stable explicit order, and deduplicated. Exclusion lists are also
sorted and deduplicated. Thus independently assembled expressions that differ
only by alternative ordering, duplicate alternatives, sequence association, or
exclusion ordering compile to the same canonical automaton and fingerprint.

This is **structural** canonicalization, not regular-language minimization.
Distributively equivalent expressions, or identities such as a nested star,
may still compile to different language-equivalent automata. Do not use
automaton equality to decide arbitrary regular-language equivalence.

Compilation uses the Glushkov position construction. State zero is the sole
initial state, and each atomic `Step` occurrence contributes one additional
state. First-position and follow-position relations become transitions;
nullable expressions make state zero accepting. The result is a fixed NFA with
no epsilon transitions and no determinization pass. Repetition changes the
finite follow relation rather than unrolling an unbounded machine.

The current high-level surface is the Rust builder API, not a string parser or
`path!` macro. Every `PathExpr` contains at least one atomic step, so a pure
epsilon language or the empty language must be expressed with a manual
automaton. State ids are `u32`; `compile` panics if the expression contains
`u32::MAX` atomic occurrences, because no valid `Automaton` can represent it.

## Manual automata are the low-level escape hatch

Construct `Automaton` directly when importing another compiler's output or
when a deliberately shared state topology matters, or when the language has no
atomic step. The `friend+` expression above is equivalent to this explicit
two-state NFA:

```rust,ignore
use triblespace_paths::{Automaton, Step, Transition};

let friend_automaton = Automaton::new(
    2,
    [0],
    [1],
    [
        Transition::new(0, 1, Step::Forward(friend)),
        Transition::new(1, 1, Step::Forward(friend)),
    ],
)?;
```

`Automaton::new` validates state numbers and canonicalizes duplicate or
out-of-order transitions and exclusion lists. Its input must already be
epsilon-free. Represent nullability by making an initial state accepting; for
example, one initial-and-accepting state with no transitions accepts only the
empty path.

## Join paths with ordinary constraints

`PathIndex::constraint(start, end)` creates the two-column relation. Either
term may be a query variable or an inline constant, and using the same variable
twice asks for the accepted diagonal. The relation composes directly with
`pattern!` and every other constraint:

```rust,ignore
let alice_value: Inline<GenId> = (&alice).to_inline();

let reachable_people: Vec<(Id, String)> = find!(
    (person: Id, name: String),
    and!(
        paths.constraint(alice_value, person),
        pattern!(&graph, [{ ?person @ social::name: ?name }]),
    )
)
.collect();
```

The index also has direct read methods when no join is needed: `contains`,
`reachable_from`, `reaching`, `accepted_pairs`, `starts`, `ends`, and
`diagonal`. All endpoint fibers are sorted and duplicate-free. The path
relation therefore contains one pair per accepted `(start, end)`, not one row
per distinct route between them; ordinary query joins can still introduce bag
multiplicity through their other witnesses.

## Persist through the native collection algebra

A durable path index is identified by the exact source descriptor, one
automaton, and the independent READ/WRITE policies of its derived descriptor:

```rust,ignore
use std::sync::Arc;
use triblespace::core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_paths::{PathIndex, PathSummaryBlob};

let source_policy = CollectionPolicy::new(
    AdmissionPolicy::direct(source_reader),
    AdmissionPolicy::direct(source_writer),
);
let index_policy = CollectionPolicy::new(
    AdmissionPolicy::direct(index_reader),
    AdmissionPolicy::direct(index_writer),
);
let source = store.collection("social", source_policy)?;
let paths = store.derive::<PathSummaryBlob>(source, friend_automaton, index_policy)?;

let before = store.snapshot()?;
let support = source.admitted(&before)?;
drop(before);

let after = store.maintain_exact(paths, &writer, &support).await?;
let observed = after.collection_exact(paths, &support)?;
let index: Arc<PathIndex> = observed.view()?;
```

The foundational support replaces ambient heads, commit-chain traversal,
manifests, registered hooks, and range planning.

The derivation selects a target `Cover<PathSummaryBlob>` whose support is the
same `Cover<SimpleArchive>` at the root. The path mapping permits any stored
combination of source merges, target merges, and derivations with that support,
so route choice is not encoded as a cover mode.

The opaque cover is the value boundary. It must name the canonical
policy-bearing `SimpleArchive` source descriptor, and every member names one
exact source payload identity. Source bytes are needed only when missing target
work must actually be computed.

Distinct signed claims that name identical data collapse to one cover member
and one unit of derivation work. Their authorship, signatures, and metadata are
queryable, possibly absent provenance through `cover.commits(&snapshot)` and are
intentionally unnecessary for replay or path semantics.

`snapshot.collection(paths)` never writes or executes collection algebra. It
follows existing source `MERGE`, path-summary `MERGE`, and source-to-target
`DERIVE` equations and returns the maximal complete resident target cover plus
exactly the foundational support represented by it.

`snapshot.collection_exact(paths, &support)` additionally requires both:

1. the union of support on the logical target frontier is exactly the supplied
   payload set; and
2. the target frontier has a complete resident target `Cover`.

Only then does `view::<Arc<PathIndex>>()` load the canonical automaton blob
named by every selected summary, join those summaries, and close them once
into the endpoint relation. For the empty cover, the descriptor names the same
blob so the canonical bottom remains available. The mapping descriptor carries
the automaton facts for source-to-target derivation and retains its blob in the
descriptor closure; interpretation otherwise uses the immutable
content-addressed representation dependency rather than mutable state retained
in a lifecycle facade.

`CollectionStoreExt::ensure{_exact}` asynchronously acquires exact missing
dependencies and publishes missing `DERIVE` work only; `maintain{_exact}`
additionally performs deterministic size-tiered target `MERGE` work. Both
return a fresh store snapshot rather than pretending that mutation itself
selected one final physical cover. Every successful artifact is persisted
before its producer-signed equation, no implicit durability flush or durable `WANT`
is performed, and an unchanged warm call executes no maps or joins.

The explicit `writer` key must satisfy the derived descriptor's WRITE policy
to publish missing derivations. Reusing an admitted result needs no new grant;
optional compaction may leave the existing finer cover in place.

An empty cover returns the automaton-indexed bottom relation locally and
appends nothing.

## What a persisted summary means

The automaton fingerprint participates in the target collection descriptor.
Two automata over the same source scope therefore inhabit different
collections.

Each `PathSummaryBlob` contains only:

- the sorted endpoint domain required by the fixed automaton; and
- the sorted direct arcs of the graph × automaton product.

These summaries are sparse constructional data, not independently closed path
relations. Their join is associative, commutative, and idempotent. Closure runs
only after the selected summaries have been joined. This order is essential: a
path may take its first edge from source fragment A, its next edge from fragment
B, and later re-enter A. Unioning closures built independently per fragment
would miss such paths. Merge order remains irrelevant because closure is
derived only after the canonical semilattice join.

The low-level `path_summary_union` module exposes the concrete law directly.
`store.derive::<PathSummaryBlob>(source, automaton, policy)` identifies
one target lattice by the handle of the collection it summarises, the
`PathSummaryBlob` representation, the canonical automaton fingerprint, and its
independent policy.
`derive_element` lowers one canonical `SimpleArchive` into direct product arcs,
`join` unions two summaries, and `validate_derive` / `validate_merge` bind all
supplied blobs to the record's exact identities and recompute the claimed
equations byte for byte. Those explicit validators are producer, ingress, or
offline-audit tools; warm attachment does not invoke them:

```text
paths(∅) = ⊥
paths(a ∪ b) = paths(a) ⊔ paths(b)
```

The same derivation is available from the command line without writing Rust.
`trible pile collection derive <pile> <source> path --expr '<expression>'`
registers the path summary collection; the expression names attributes by
their 32-hex-digit ids, juxtaposition is sequence, `|` alternation, `*`, `+`
and `?` the usual repetitions, `^` before an atom or group follows those edges
in reverse, and parentheses group:

```text
--expr '2B3A… (^4C5D… | 6E7F…)+ 8091…?'
```

`trible pile collection maintain` then folds the summary like any other
derived collection; the automaton travels in the descriptor, so a later
maintainer needs nothing but the pile.

The same grammar is a macro in Rust, with attributes named by their paths
instead of their ids (and `{ expression }` for one computed elsewhere):

```rust,ignore
use triblespace::macros::path_expr;

let friends = path_expr!(social::friend (social::friend | ^social::friend)* social::name?);
let index = PathIndex::from_edges(friends.compile(), edges)?;
```

Both front ends lex into `triblespace_paths::syntax::Token`, parse with one
`syntax::parse`, and lower the same `syntax::Ast`, so an expression means the
same thing on the command line and in code.

The bottom is an explicit 48-byte summary: automaton-blob handle, state count,
and zero vertex and arc counts. Derivation is therefore total even for an empty
source or a non-nullable source with no matching labels.

## Nullable paths and the vertex universe

A nullable expression uses an accepting initial state. Its zero-hop answers are
identity pairs `(v, v)` for the summary's complete vertex universe. The
universe includes both endpoints of every supplied trible, even when its
attribute matches no transition.

Non-nullable summaries omit unmatched endpoints. Nullable summaries retain
them as the identity universe, but closure runs only over endpoints incident to
matching product arcs before mapping the relation back and adding the diagonal.
Unrelated attributes therefore do not widen the quadratic closure workspace.

An entirely empty source has no graph terms and therefore no identity pairs.
Its native collection derivation is nevertheless the explicit 48-byte bottom,
so “covered and empty” remains distinct from “not materialized.”

## Cost model: sparse input, potentially dense answer

Summaries retain an endpoint domain and direct product arcs, so they can remain
close to sparse input and merge cheaply. Attachment is a different operation:
it materializes the complete accepted endpoint relation as CSR plus reverse and
domain views. Some regular paths accept every pair of vertices, making that
relation Θ(|V|²). No exact materialized representation can avoid paying for
that output, and the closure construction also uses bitset scratch space.

The current canonical blob stores product endpoints as full-domain `u32`
ordinals. Persisted nullable summaries consequently require
`|universe| × |automaton states| <= u32::MAX`, even though attachment closes
only the smaller matched support. Crossing that format ceiling is an explicit
error rather than ordinal truncation.

Use a native path collection when a stable automaton and repeated queries
amortize materialization. For a one-off traversal over a large sparse graph, an
application-side search may use less memory; for a fixed small hop count,
explicit joined `pattern!` clauses remain simpler. The path index is a
deliberate materialized-view trade, not a hidden lazy traversal.
