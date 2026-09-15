# Query Language

This chapter introduces the core query facilities provided by `triblespace`.  A
query is described in a small declarative language that states which values
should match instead of spelling out the iteration strategy.  When you read a
query, you are effectively looking at a logical statement about the data: *if*
the constraints can all be satisfied, *then* the variable bindings are produced
as results.  The declarative style gives the engine freedom to reorder work and
choose efficient execution strategies.

Every macro shown here is a convenience wrapper around a concrete
[`Constraint`](triblespace::core::query::Constraint) implementation.  When you need finer
control—or want to assemble constraints manually outside the provided
macros—reach for the corresponding builder types in
[`triblespace::core::query`](triblespace::core::query).

## Declaring a query

The [`find!`](triblespace::core::prelude::find) macro builds a
[`Query`](triblespace::core::query::Query) by declaring variables and a constraint
expression. The macro mirrors Datalog syntax: the head `((...))` lists the
variables you want back, and the body describes the conditions they must meet.
A minimal invocation looks like this:

```rust,ignore
let results = find!((a), a.is(1.into())).collect::<Vec<_>>();
```

`find!` returns an [`Iterator`](core::iter::Iterator) over the bound
variables. Matches can be consumed lazily or collected into common
collections.

The head is an ordered projection with **BAG semantics**. The engine emits one
row every time a complete binding is found, and the head selects which of its
variables you get back. Hidden variables therefore multiply: an assignment
proved by eight different witnesses is emitted eight times. Deduplication is
the consumer's job — collect into a `HashSet`, or ask the question with
[`exists!`](triblespace::core::prelude::exists) so the fan-out is never
enumerated. The [Query Engine](query-engine.md#bag-semantics-at-the-interface)
chapter explains why the engine does not deduplicate for you.

When the head declares a **single variable**, omit the parentheses to get bare
values instead of 1-tuples:

```rust,ignore
for a in find!(a, a.is(1.into())) {
    println!("match: {a}");
}
```

When the head declares **multiple variables**, wrap them in parentheses to get
tuples:

```rust,ignore
for (a, b) in find!((a, b), and!(a.is(1.into()), b.is(2.into()))) {
    println!("{a}, {b}");
}
```

Adding more variables is as simple as expanding the list:
`find!((a, b, c), ...)` yields `(a, b, c)` tuples.
Variables declared in the head can be reused multiple times inside the
constraint to express joins. When a variable appears in several clauses the
engine ensures every occurrence binds to the same value. Repeating a variable in
two patterns, for example, restricts the result set to entities that satisfy
both attribute assignments simultaneously. The order of declarations defines the
shape of the tuple in the iterator, so reorganising the head changes how you
destructure results.

### Typed variables

Variables optionally include a concrete type to convert the underlying value.
The constraint phase still works with untyped [`Inline`](triblespace::core::inline::Inline)
instances; conversion happens when results are emitted.  These conversions use
[`TryFromInline`](triblespace::core::inline::TryFromInline).

By default, if a conversion fails the entire row is silently skipped — like a
constraint that doesn't match.  For types whose `TryFromInline::Error` is
[`Infallible`](core::convert::Infallible) the error branch is dead code and no
rows can ever be accidentally filtered.

Append `?` to a variable to receive the raw
[`Result<T, E>`](core::result::Result) instead. Both `Ok` and `Err` values pass
through without filtering, matching Rust's `?` semantics of "bubble the error
to the caller."

```rust,ignore
// `x` is filtered (rows where conversion fails are skipped).
// `y` is passed through as Result (no filtering).
find!((x: i32, y: Inline<ShortString>?),
      and!(x.is(1.into()), y.is("foo".to_inline())))
```

| Syntax | Meaning |
|--------|---------|
| `name` | inferred type, filter on conversion failure |
| `name: Type` | explicit type, filter on conversion failure |
| `name?` | inferred type, yield `Result<T, E>` (no filter) |
| `name: Type?` | explicit type, yield `Result<T, E>` (no filter) |

The query engine explores assignments that satisfy the constraint and yields
the declared variables in head order, one row per satisfying assignment.
Variables omitted from the head still participate in the search — they decide
whether an assignment exists, and each distinct value they take is a separate
row. A repeated variable in the head is rejected because it would not add a new
projected column.

The empty head `find!((), constraint)` therefore yields one `()` per satisfying
assignment, which makes `find!((), ...).count()` a way to count them. When you
only want to know whether *any* assignment exists, use `exists!`: it stops at
the first one instead of draining the fan-out.

### Collecting results

Any type that implements [`FromIterator`](core::iter::FromIterator) can collect
the results of a query.  `Vec<_>` is common for tests and examples, while
`HashSet<_>` is useful when the match order is irrelevant.  When you only need
the first result, call iterator adapters such as `next`, `find`, or `try_fold`
to avoid materializing the full result set.

## Built-in constraints

`find!` queries combine a small set of constraint operators to form a
declarative language for matching tribles.  Each operator implements
[`Constraint`](triblespace::core::query::Constraint) and can therefore be mixed and nested
freely.

| Macro | Purpose | Notes |
| ----- | ------- | ----- |
| [`and!`](triblespace::core::prelude::and) | Require every sub-constraint to hold | Builds an [`IntersectionConstraint`](triblespace::core::query::intersectionconstraint::IntersectionConstraint). |
| [`or!`](triblespace::core::prelude::or) | Accept any satisfied alternative | Produces a [`UnionConstraint`](triblespace::core::query::unionconstraint::UnionConstraint) whose branches must reference the same variables. |
| [`temp!`](triblespace::core::temp) | Mint hidden helper variables | Allocates fresh bindings for the nested expression so the helpers can join across patterns without being projected. |
| [`pattern!`](triblespace::core::macros::pattern) | Match attribute assignments in a collection | Expands to a [`TriblePattern`](triblespace::core::query::TriblePattern)-backed constraint that relates attributes and values for the same entity. |
| [`pattern_changes!`](triblespace::core::macros::pattern_changes) | Track attribute updates incrementally | Builds a [`TriblePattern`](triblespace::core::query::TriblePattern) constraint that yields newly added triples from a change set because incremental evaluation stays monotonic; see [Incremental Queries](incremental-queries.md) for the broader evaluation workflow. |
| `.is(...)` | Pin a variable to a constant | Wraps a [`ConstantConstraint`](triblespace::core::query::constantconstraint::ConstantConstraint) that compares the binding against a literal value. |
| `has` | Check membership in a collection | Collections such as [`HashSet`](std::collections::HashSet) expose `.has(...)` when they implement [`ContainsConstraint`](triblespace::core::query::hashsetconstraint::ContainsConstraint); triple stores like [`TribleSet`](triblespace::core::trible::TribleSet) instead participate through [`pattern!`](triblespace::core::macros::pattern). |
| [`EqualityConstraint`](triblespace::core::query::equalityconstraint::EqualityConstraint) | Require two variables to bind the same value | Auto-desugared by `pattern!` for self-referencing patterns like `{ _?e @ link: _?e }`. |
| [`SortedSlice`](triblespace::core::query::sortedsliceconstraint::SortedSlice) | Check membership via binary search | A binary-search alternative to `HashSet` for sorted data; implements `ContainsConstraint`. |
| [`value_range`](triblespace::core::query::rangeconstraint::value_range) | Restrict a variable to a byte-lexicographic range | Builds a [`InlineRange`](triblespace::core::query::rangeconstraint::InlineRange) constraint between a min and max bound. |

Any data structure that can iterate its contents, test membership, and report
its size can implement `ContainsConstraint`. Membership constraints are
particularly handy for single-column collections such as sets or map key views,
while multi-position sources like `TribleSet` rely on `pattern!` to keep entity,
attribute, and value bindings aligned.

### Constant matches (`is`)

Call [`Variable::is`](triblespace::core::query::Variable::is) when you need a binding to
equal a specific value.  The method returns a
[`ConstantConstraint`](triblespace::core::query::constantconstraint::ConstantConstraint)
that checks whether the solver can assign the variable to the provided
[`Inline`](triblespace::core::inline::Inline).  Constant constraints behave like any other
clause: combine them with `and!` to narrow a variable after other constraints
have proposed candidates, or place them inside `or!` branches to accept
multiple literals.

```rust,ignore
find!((title: Inline<_>),
      and!(dataset.has(title), title.is("Dune".to_inline())));
```

The snippet above keeps only the rows where `title` equals `"Dune"`.  Because
`is` constrains the variable's value rather than projecting a new binding, it
is also handy for helpers such as `temp!` when you want to filter hidden
bindings without exposing them in the result tuple.

`pattern!` and `pattern_changes!` fold literal values (and attribute
constants) directly into the pattern constraint as constant
[`Term`](triblespace::core::query::Term)s — no variable is allocated for
them — so you often get the same behaviour simply by writing the desired
value in the pattern:

```rust,ignore
find!((friend: Inline<_>),
      pattern!(&dataset,
               [{ _?person @ social::friend: ?friend,
                  social::city: "Caladan" }]));
```

Repeating `.is(...)` on the same variable with different values causes the
query to fail—just as conflicting `pattern!` clauses would—so prefer `or!` (or
switch to a membership helper such as `.has(...)`) when you want to accept
several constants.

### Intersections (`and!`)

[`and!`](triblespace::core::prelude::and) combines multiple constraints that must all hold
simultaneously.  Each sub-clause can introduce new bindings or further narrow
existing ones, and the solver is free to reorder the work to reduce the search
space.  When a sub-constraint fails to produce a candidate that is compatible
with the current bindings, the whole conjunction rejects that branch and moves
on.  The macro accepts any number of arguments, so `and!(...)` is often a
convenient way to keep related clauses together without nesting additional
`find!` calls:

```rust,ignore
let favourites = favourite_titles(); // e.g. a HashSet<Id> built elsewhere
find!((book: Inline<_>, author: Inline<_>),
      and!(favourites.has(book),
           pattern!(&dataset,
                    [{ ?book @ literature::title: "Dune",
                       literature::author: ?author }])));
```

Here the membership test over `favourites` and the attribute pattern from
`dataset` run as part of the same conjunction.  The solver joins them on their
shared bindings (`book` and `author`) so only tuples that satisfy every clause
make it into the result set.  Because `and!` simply returns a constraint, you
can nest it inside other combinators such as `temp!` or `or!` to structure
queries however you like.

### Alternatives (`or!`)

Use [`or!`](triblespace::core::prelude::or) to express alternatives. Each branch behaves
like an independent constraint and may introduce additional bindings that
participate in the surrounding query, provided every branch mentions the same
set of variables:

```rust,ignore
find!((alias: Inline<_>),
      temp!((entity),
            or!(pattern!(&dataset,
                         [{ ?entity @ profile::nickname: ?alias }]),
                pattern!(&dataset,
                         [{ ?entity @ profile::display_name: ?alias }]))));
```

Each branch contributes every match it can produce given the current bindings.
Results are a bag of complete bindings: one row per witness of the declared
variables (here `entity` and `alias`), so a nickname and display name with
different raw values contribute two rows, equal values for the same entity
collapse (the union is a set per binding step), and the same alias witnessed
by different entities yields one row per entity — dedup of projected columns
belongs to the consumer. Branches that cannot match simply contribute
nothing.

All branches of an `or!` must bind exactly the same set of variables;
branch-local variables are not supported. This is a consequence of the
engine's flat result schema — every result row binds the same variable set
exactly once, so there is no way to represent a variable that only exists
in some alternatives. (It is *not* a semantic or monotonicity limitation:
the union itself is monotonic.) Attribute constants and literal values do
not count towards a branch's variable set: `pattern!` folds them into the
constraint as constant [`Term`](triblespace::core::query::Term)s rather
than allocating hidden variables, which is what lets the branches above use
*different* attributes (`nickname` vs. `display_name`) while still
declaring the identical set `{entity, alias}`. Only genuine query variables
must align: if two branches reference different variables the constraint
panics at construction time, naming the mismatched sets. Note that an
anonymous entity (`{ attr: ?v }` without an `?entity @` id) introduces a
fresh variable scoped to its own `pattern!`, so bind entities explicitly —
as the example does with `temp!((entity), ...)` — when combining such
patterns with `or!`.

### Temporary variables (temp!)

Real queries often need helper bindings that participate in the joins but do
not show up in the result tuple. Wrap the relevant constraint with
`temp!((...vars...), expr)` to mint hidden variables and evaluate `expr` with
them in scope:

```rust,ignore
find!((person: Inline<_>),
      temp!((friend),
            and!(pattern!(&dataset,
                          [{ _?p @ social::person: ?person, social::friend: ?friend }]),
                 pattern!(&dataset,
                          [{ ?friend @ social::city: "Caladan" }]))));
```

The helper binding `friend` links the two patterns, ensuring the same entity is
used across both clauses without expanding the result tuple. `temp!` can create
multiple variables at once (`temp!((street, city), ...)`). You always wrap the
hidden bindings in a tuple, so each invocation reads
`temp!((...vars...), ...)`. Here `social` would be a namespace module exporting
the `person`, `friend`, and `city` attributes. The variables adopt the value
schemas implied by the constraints they appear in, so no extra annotations are
required. When working outside the query macros, call
[`VariableContext::next_variable`](triblespace::core::query::VariableContext::next_variable)
directly instead.

Temporary variables are hidden from the result tuple, but they are not hidden
from the search: several friends that prove the same projected `person` produce
that person several times. Collect into a set when you want each `person` once,
or restructure the query so the inner condition is an `exists!` check and the
fan-out is never enumerated at all.

When the helper variable lives entirely within a single pattern, consider using
`_?alias` instead of `temp!`. Both [`pattern!`](triblespace::core::macros::pattern) and
[`pattern_changes!`](triblespace::core::macros::pattern_changes) support `_?ident` placeholders that
mint fresh bindings scoped to that one macro invocation. They behave like
non-projected variables: you can reuse the `_?ident` multiple times inside the
pattern to relate attributes, but the binding vanishes once control leaves the
macro. Reach for `temp!` when the helper must span several constraints or when
you need to reuse the same hidden binding across multiple patterns.

## Example

```rust,ignore
use triblespace::prelude::*;
use triblespace::core::examples::{self, literature};

let dataset = examples::dataset();

for (title,) in find!((title: Inline<_>),
                     and!(dataset.has(title), title.is("Dune".to_inline()))) {
    println!("Found {}", title.from_inline::<&str>());
}
```

This query searches the example dataset for the book titled "Dune".  The
variables and constraint can be adapted to express more complex joins and
filters.  For instance, you can introduce additional variables to retrieve both
the title and the author while sharing the same dataset predicate:

```rust,ignore
for (title, author) in find!((title: Inline<_>, author: Inline<_>),
                             and!(title.is("Dune".to_inline()),
                                  pattern!(&dataset,
                                           [{ _?book @ literature::title: ?title,
                                              literature::author: ?author }]))) {
    println!("{title} was written by {}", author.from_inline::<&str>());
}
```

The extra variables participate in the join automatically; no explicit loop
nesting or indexing is required.

## Attribute patterns (pattern!)

The `pattern!` macro provides a concise way to match entities by attribute
assignments. It expands to a constraint that can be used directly inside
`find!`.

Important: in `pattern!` values prefixed with `?` refer to variables declared
in the surrounding `find!` head while string/number literals and more complex
expressions are treated as literal values. Use `_?name` when you need a fresh
variable that is scoped to a single macro invocation; you can reference it
multiple times within the same pattern without adding it to the `find!` head.
Parenthesised expressions remain supported for explicit literals.

```rust
# use triblespace::prelude::*;
# mod literature {
#     use triblespace::prelude::*;
#     attributes! {
#         "0DBB530B37B966D137C50B943700EDB2" as firstname: inlineencodings::ShortString;
#         "6BAA463FD4EAF45F6A103DB9433E4545" as lastname: inlineencodings::ShortString;
#     }
# }
let mut kb = TribleSet::new();
let e = ufoid();
kb += entity! { &e @ literature::firstname: "William", literature::lastname: "Shakespeare" };

let results: Vec<_> = find!((ee: Id), pattern!(&kb, [{ ?ee @ literature::firstname: "William" }])).collect();
assert_eq!(results.len(), 1);
```

Patterns may contain multiple clauses and reuse `_?` bindings to relate
attributes without introducing extra columns in the result set.  A single
`_?person` variable can connect several attribute/value pairs while staying
scoped to the pattern:

```rust
# use triblespace::prelude::*;
# mod literature {
#     use triblespace::prelude::*;
#     attributes! {
#         "0DBB530B37B966D137C50B943700EDB2" as firstname: inlineencodings::ShortString;
#         "6BAA463FD4EAF45F6A103DB9433E4545" as lastname: inlineencodings::ShortString;
#     }
# }
let mut kb = TribleSet::new();
let e = ufoid();
kb += entity! { &e @ literature::firstname: "Frank", literature::lastname: "Herbert" };

let author_last_names: Vec<_> = find!((last: Inline<_>),
    pattern!(&kb, [{ _?person @ literature::firstname: "Frank", literature::lastname: ?last }])
).collect();
```

Here `_?person` remains scoped to the pattern while ensuring both attributes are
drawn from the same entity.  When a pattern references collections other than a
`TribleSet`, ensure the collection implements
[`TriblePattern`](triblespace::core::query::TriblePattern) so that the macro can materialize
the requested triples.

To share a hidden binding across multiple patterns, declare it once with
`temp!` and reference it with `?name` from each clause:

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     attributes! {
#         "A19EC1D9DD534BA9896223A457A6B9C9" as name: inlineencodings::ShortString;
#         "C21DE0AA5BA3446AB886C9640BA60244" as friend: inlineencodings::GenId;
#     }
# }
let mut kb = TribleSet::new();
let alice = ufoid();
let bob = ufoid();
kb += entity! { &alice @ social::name: "Alice", social::friend: &bob };
kb += entity! { &bob @ social::name: "Bob" };

let results: Vec<_> = find!((friend_name: Inline<_>),
    temp!((friend),
          and!(pattern!(&kb, [{ _?person @ social::friend: ?friend,
                                  social::name: ?friend_name }]),
               pattern!(&kb, [{ ?friend @ social::name: "Bob" }]))))
.collect();
```

The `_?person` variable is still local to the first pattern, while `friend`
joins the two constraints without changing the projected results. As above,
`social` denotes a namespace that defines the `name` and `friend` attributes.

## `exists!`

Sometimes you only want to check whether a constraint has any solutions.  The
`exists!` macro mirrors the `find!` syntax but returns a boolean:

```rust,ignore
use triblespace::prelude::*;

assert!(exists!((x), x.is(1.into())));
assert!(!exists!((x), and!(x.is(1.into()), x.is(2.into()))));
```

Internally, `exists!` stops as soon as the first result is found.  It is a
lightweight alternative to `find!` when the mere existence of a match matters
more than the actual bindings.

## Custom constraints

Every building block implements the
[`Constraint`](triblespace::core::query::Constraint) trait.  You can implement this trait on
your own types to integrate custom data sources or query operators with the
solver. Collections that want to power `pattern!` implement
[`TriblePattern`](triblespace::core::query::TriblePattern) so they can materialize the
entity/attribute/value triples a pattern asks for.  Membership-style helpers
such as `has(...)` work with anything that implements
[`ContainsConstraint`](triblespace::core::query::ContainsConstraint), making it easy to join
against pre-existing indexes, caches, or service clients without copying data
into a [`TribleSet`](triblespace::core::trible::TribleSet).

```rust,ignore
use std::collections::HashSet;

use triblespace::prelude::*;
use triblespace::prelude::inlineencodings::ShortString;
use triblespace::core::query::hashsetconstraint::SetConstraint;

struct ExternalTags<'a> {
    tags: &'a HashSet<String>,
}

impl<'a> ContainsConstraint<'a, ShortString> for ExternalTags<'a> {
    type Constraint = SetConstraint<ShortString, &'a HashSet<String>, String>;

    fn has(self, variable: Variable<ShortString>) -> Self::Constraint {
        SetConstraint::new(variable, self.tags)
    }
}

let tags: HashSet<String> = ["rust", "datalog"].into_iter().map(String::from).collect();
let external = ExternalTags { tags: &tags };
let matches: Vec<_> =
    find!((tag: Inline<ShortString>), external.has(tag)).collect();
```

The example wraps an external `HashSet` so it can be queried directly.  A
`TriblePattern` implementation follows the same shape: create a constraint
type that reads from your backing store and return it from `pattern`.  The query
engine drives both traits through `Constraint`, so any data source that speaks
the protocol can participate in `find!`. Four methods are required:

| Method | Role |
|---|---|
| `variables` | Declare the variables touched by the constraint. |
| `estimate` | Quote a candidate count for one variable under the current binding, or `None` if the variable is not yours. |
| `propose` | Append candidate values for a variable to the proposal buffer, for every binding in the frontier. |
| `confirm` | Kill candidates proposed by someone else that violate this constraint under their own binding. |

`propose` and `confirm` take a `Frontier` — a batch of parent bindings, of
which a single binding is the width-1 case. Loop over `Frontier::rows`, calling
`ProposalBuffer::open(row)` before each row's candidates; on the confirm side,
ignore the parent tags if your verdict does not depend on the binding, or walk
the region with `Candidates::for_each_parent` if it does.

Two more methods have defaults you can override: `satisfied` (defaulting to
`true`) and `influence` (defaulting to "every variable I touch except this
one").

The rules a custom constraint has to respect are short:

- **`estimate` is a cost quote.** It steers variable ordering and nothing else.
  A wrong estimate makes the search slower, never incorrect. `None` means "not
  my variable", not "no candidates".
- **`propose` only appends.** Entries already in the buffer belong to a
  sibling constraint in an enclosing composite; leave them alone. Within one
  chunked enumeration, never deliver the same value twice — a duplicate
  inflates row multiplicity.
- **`confirm` only kills.** It may never add a candidate or revive a dead one,
  and it may skip entries that are already dead. This is what lets several
  confirmers write into the same region in any order, or in parallel, and still
  compute their conjunction.
- **`satisfied` may be optimistic, but only upward.** Returning `true` while a
  relevant variable is unbound is fine; returning `false` must mean there is
  genuinely no completion. Once every variable the constraint touches is bound,
  the answer must be exact — `or!` relies on that to discard dead alternatives,
  and a fully constant constraint is settled by a single `satisfied` call at
  construction with no search to correct it later.

The [Query Engine](query-engine.md#the-constraint-protocol) chapter explains the
protocol, the search that drives it, and the reasoning behind these rules in
detail.

## Frontiers (`latest`)

A recurring modelling shape is *the same thing, changing over time*: a set of
immutable states, each naming the states it observed, with reads wanting the
ones nothing has moved past yet. Because the observer owns the identifier it
writes under (see [Direction and consistency](deep-dive/trible-structure.md)),
the edge always runs successor-to-predecessor — "I observed that" is a claim
about your own new entity, whereas "I replace that" would be a claim about
someone else's. `metadata::supersedes` is the published attribute for it.

The pure utility answers "which of these candidates has no known successor"
with reverse-index probes. It lives in the query layer as
[`latest`](triblespace::core::query::frontier::latest):

```rust,ignore
use triblespace::prelude::*;
use triblespace::core::metadata;

let heads = latest(&facts, metadata::supersedes.id(), candidates);
```

Three things are worth stating explicitly, because each one is a place where
designs usually go wrong:

- **There is no global "current".** There is a current state *for a given set
  of commits*, which is exactly what a collection view is. Two readers holding
  different commit sets legitimately disagree, and that is frame-relativity,
  not a consistency bug. The `facts` argument is that frame.
- **A maintained head set needs its evidence.** For a fixed transitive partial
  order, antichains join by taking maxima of their union. Here the order evidence
  arrives with the source facts: bare opaque head ids do not retain discarded
  ancestry. The maintained form below therefore retains historical superseded
  targets beside known live heads, and is monotone under that pair's join order.
- **The predicate is local.** `s` is maximal in `C` exactly when no state in
  `C` observes `s` — note "in `C`", not "in the frontier". Anything that
  observes `s` already dominates it, so immediate edges suffice: no transitive
  closure, no reachability query, and no vector clock. Each candidate costs one
  short-circuited reverse-index probe, and the answer cannot depend on the order
  states arrived in.

The answer is a set. Concurrent states are a genuine fork, and collapsing them
to one would invent an order the data does not have.

### Registers: the general form

`latest` hard-codes two choices — order by the observation edge, report the
whole antichain — and both are parameters in
[`query::register`](triblespace::core::query::register). `latest` is now just
the multi-value reading of that substrate over an observation DAG.

The useful thing to see first is that a *resolution policy* is not a second
knob beside the order. It **is** a choice of order:

| policy | is |
|---|---|
| multi-value | the maximal set under a **partial** order |
| last-write-wins | the maximal set under a **total** order |
| first-write-wins | the maximal set under that order **reversed** |
| named by the reader | the maximal set under the **empty** order |

There is one operation — take the maximal elements — and `sole` is a *check*
that the order left exactly one, never a tie-break that invents one.

Two axes are parameterised, and the second is smaller than it looks:

- **Order.** `ObservationOrder` reads the DAG, as `latest` does. `StatedOrder`
  reads an **identity** attribute and an **order** attribute — a wall-clock
  timestamp, a counter, a version number, plus the thing it is a measurement
  *of*. Order values are compared as raw inline bytes, which is value order
  exactly when the encoding is order-preserving (`NsTAIInterval`, `I256BE`,
  `ROrd256` — deliberately *not* `R256`); this is the same contract
  [`value_range`] carries, and the wide half of every comparison is pushed into
  the engine through it.
- **End.** `.first()` resolves to the minimum. `min` is the join of the
  opposite order, so first-write-wins is as lawful a derivation as
  last-write-wins.

There is no scope axis, and there was briefly one, which is worth saying
plainly because it is an easy mistake to make twice.

A register is a set of states that are *versions of the same thing*, ordered.
That is two facts. An observation edge asserts both at once — "I observed
that" says same-thing and later in one breath — which is why the DAG order
takes a single attribute and needs no scope. A timestamp asserts only one of
them: it says *when*, never *of what*. So a stated order must be told the
identity, and if it is not, the missing half comes back as a filter.

Compass hangs status events, notes, and priority events off a goal through the
same `board::task` edge, all timestamped. `board::task` means *belongs to this
goal* — not an identity: a note is not a later version of a status event. Read
as one, a note at t=20 dominated a status event at t=10 and the goal reported
no status at all, on 778 of 2939 live goals. The patch was an
`.among(tag, STATUS)` knob narrowing who may dominate — which is
`(goal, status-kind)`, a composite identity reconstructed at the call site out
of a grouping plus a type filter, because the real one was not in the data.

The cure is to put it in the data: an attribute meaning *the status of goal G*.
Then nothing needs narrowing, because a note is not in that register to begin
with.

**Which attribute carries identity and which carries order is a property of the
register, not of the reader's question.** Both are carried as tribles on one
concrete mapping entity embedded in the derived collection descriptor. That
entity separately names the stable mapping algorithm, so its content-derived
identity includes the concrete attribute pair without making the pair opaque.
Two registers over one dataset are therefore distinct mappings and distinct
collections -- their descriptors differ in content, so they differ in handle
-- and cannot share a cache. What is left at the call site is the frame, and
nothing else.

An earlier design folded concrete parameters into an otherwise opaque
algorithm id. The digest became their only carrier, so no reader could recover
which attributes a register was over. The current shape stores parameters on
the mapping entity itself; `latest`, `lww_register`, and other derived
collections all use the same content-derived mechanism.

An order composes into a query directly. `maximal` is a filter-only constraint:
it estimates `usize::MAX` so the planner always sorts it last and a `pattern!`
proposes the scope, which is what relieves the caller of materialising
candidates.

```rust,ignore
use triblespace::prelude::*;

// The register: identified by `status_of`, ordered by `created_at`.
let order = StatedOrder::<_, inlineencodings::NsTAIInterval>::new(
    &facts, board::status_of.id(), metadata::created_at.id(),
)
.tiebreak_by_id();

let current: Vec<Id> = find!(
    event: Id,
    and!(
        pattern!(&facts, [{ ?event @ board::status_of: &goal }]),
        maximal(event, &order),
    )
).collect();
```

When an exact cardinality is wanted instead — so the planner can order *around*
resolution rather than after it — materialise with `resolve` and propose from a
`SortedSlice`, whose estimate is the resolved count itself.

### The maintained form

[`collection::latest`](triblespace::core::collection::latest) maintains an
ordinary latest-state lattice. `LatestBlob` stores `(H, D)`: known live states
and all historically superseded targets, including targets whose own facts
have not arrived. Its canonical join is

```text
(H₁, D₁) ⊔ (H₂, D₂) = ((H₁ ∪ H₂) ∖ (D₁ ∪ D₂), D₁ ∪ D₂)
```

Leaf derivation projects every source subject into `S` and every well-formed
target of the configured observation attribute into `D`, then stores
`(S ∖ D, D)`. Both projections preserve source union. They do not require a
multi-field state shape, whose fields might arrive in separate commits.
`derive(C₁ ∪ C₂) = derive(C₁) ⊔ derive(C₂)` therefore holds byte-exactly.

Historical `D` is necessary: after `b → a, c → b` leaves only `c` live, a
later arrival of `a` must still be suppressed. Cycles are deterministic too:
every observed cycle member is retired; no DAG validation is imposed. The
head projection is **neither monotone nor antitone under inclusion**. The
maintained pair is monotone under its own join order.

`LatestIndex` exposes `H` as ordinary positive membership, with exact
cardinality, complete proposals, and binary-search confirmation:

```rust,ignore
let index: LatestIndex = snapshot.collection(latest_collection)?.view()?;
let heads: Vec<Id> = find!(state: Id, index.has(state)).collect();
let current: Vec<Id> = find!(state: Id, and!(
    index.has(state),
    pattern!(&facts, [{ ?state @ metadata::tag: revision_kind }]),
)).collect();
```

Unknown candidates are excluded, unlike the pure negative register utilities.
Facts and latest may advance independently: an unobserved new state stays
invisible, while an already-known old state can remain visible until latest
advances. There is no shared-support requirement or global-current promise.
Queries are pure reads of frozen observations; ordinary `ensure`/`maintain`
advances the collection outside the query.

[`collection::lww_register`](triblespace::core::collection::lww_register) is
the maintained counterpart for a stated last-write-wins register. Its target
element keeps the identity and order fact halves in separate canonical row sets.
That detail is essential: the two facts for one state may arrive in different
source commits, so deriving only already-complete coordinates would not commute
with source union. `LwwIndex` attaches those row sets without copying them.
Its explicit `query()` step pairs them across the cover and returns a `LwwQuery`
selecting the greatest `(order, state-id)` coordinate for every register.
The prepared query's `.has(state)` constraint positively proposes and confirms only known
complete winners, excluding unknown and incomplete states. Its existing
`RegisterOrder` implementation remains available for pure order-based reads.

The maintained LWW form makes one validity contract explicit: within an exact
cover, a state which has both halves has at most one well-formed identity and
at most one order value under the descriptor's attributes. Incomplete states
remain incomparable even if the present half is multivalued. The row sets
retain those values so a later counterpart exposes rather than hides a
conflict, including one split across source commits. Order bytes must use an
order-preserving encoding, just as they must for the live `StatedOrder`.

## Recursive traversal

Queries in this chapter all have a fixed number of clauses, which means a fixed
number of hops. Genuinely recursive questions — "everyone reachable through a
chain of `follows`", "all ancestors via repeated `parent`" — cannot be written
this way.

Earlier versions of the crate answered them with a `path!` macro that evaluated
a regular expression over edge attributes inside the query engine. That macro
and its evaluator have been removed: query-time traversal needs per-activation
state, which the stateless constraint protocol has no place for, and keeping it
inside the protocol meant every constraint paid for machinery only paths used.

The stable replacement is the standalone `triblespace-paths` crate. Its
`PathExpr` builder describes sequence, alternatives, repetition, optionality,
and inverse steps, then compiles them to a fixed epsilon-free automaton. The
crate combines that automaton with graph edges to materialize an accepted
endpoint relation, exposed through an ordinary two-variable constraint. That
constraint composes directly with `find!`, `and!`, and `pattern!`; see
[Regular Path Indexes](regular-path-indexes.md) for expression construction,
the low-level automaton escape hatch, and exact collection maintenance.

For a fixed small number of hops, explicit pattern clauses joined on `temp!`
variables remain simpler. For unbounded traversal, use the path index or drive
a one-off frontier search from application code when materializing a potentially
dense endpoint relation would not pay for itself.
