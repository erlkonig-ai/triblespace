# The Atreides Family of Worst-case Optimal Join Algorithms

The query engine reasons about data by solving a set of constraints over
variables. Instead of constructing a traditional left-deep or bushy join plan,
it performs a guided depth-first search that binds one variable at a time. The
approach draws on the broader theory of worst-case optimal joins and lets us
navigate the search space directly rather than materialising intermediate
results.

## Constraints as the search frontier

Every constraint implements the [`Constraint`](triblespace::core::query::Constraint) trait,
whose methods shape the search:

1. **`variables`** – returns the set of variables this constraint touches.
2. **`estimate`** – predicts how many candidates remain for a variable under the
   current partial binding, or `None` when the variable is not this
   constraint's business.
3. **`propose`** – enumerates candidate values for a variable, for every
   binding in the current frontier.
4. **`confirm`** – kills candidates proposed by another constraint, without
   re-enumerating them.
5. **`satisfied`** – returns `false` when the constraint has no completion from
   the current binding. Used by `UnionConstraint` to prune dead variants.

Traditional databases rely on a query planner to combine statistics into a join
plan. Atreides instead consults the constraints directly while it searches. Each
constraint can base its estimates on whatever structure it maintains—hash maps,
precomputed counts, or even constant values for predicates that admit at most
one match—so long as it can provide a quick cost quote. Every binding decision
asks for fresh estimates under the binding that exists at that moment. Nothing
is cached, so there is no invalidation protocol to get wrong.

An estimate affects cost ordering only. It cannot change whether a constraint
is relevant, which candidates it proposes, or which rows the query returns. A
constraint that misreports its cardinality by a large factor makes the search
slower; it does not make it wrong.

Because the heuristics are derived entirely from the constraints themselves, we
do not need a separate query planner or multiple join implementations. Any
custom constraint can participate in the same search by providing sensible
estimates, proposal generation, and confirmation.

## A spectrum of Atreides variants

The Atreides "family" refers to the spectrum of heuristics a constraint can use
when implementing [`Constraint::estimate`](triblespace::core::query::Constraint). Each
variant exposes the same guided depth-first search, but with progressively
tighter cardinality guidance. Every binding decision revisits its estimates;
what differs is **what** quantity they approximate:

- **Row-count Join (Jessica)** estimates the remaining search volume for the
  *entire* constraint. If one variable is bound but two others are not, Jessica
  multiplies the candidate counts for the unbound pair (\|b\| × \|c\|) and
  reports that larger product. The number can wildly overshoot the next
  variable's frontier, yet it often tracks the overall work the constraint will
  perform.
- **Distinct-value Join (Paul)** narrows the focus to a single variable at a
  time. It returns the smallest proposal buffer the constraint could produce for
  any still-unbound variable, ignoring later confirmation filters. This is
  what [`Constraint::estimate`](triblespace::core::query::Constraint::estimate)
  reports today, and what an intersection uses to choose each row's proposer
  and to order its confirmers, because a proposal is a set of distinct values.
- **Partial-binding Join (Ghanima)** goes further by measuring the size of the
  actual proposal the composite constraint can deliver for the current binding
  and chosen variable. For an `and` constraint this corresponds to the
  intersection of its children after they have applied their own filtering,
  revealing how many candidates truly survive the local checks.
- **Exact-result Join (Leto)** is an idealised limit where a constraint predicts
  how many of those proposed values extend all the way to full results once the
  remaining variables are also bound. Although no constraint currently achieves
  this omniscience, the interface supports it conceptually.

All four share the same implementation machinery; the difference lies in how
aggressively `estimate` compresses the constraint's knowledge. Even when only
partial information is available the search still functions, but better
estimates steer the traversal directly toward the surviving tuples.

The engine uses two of these rungs at once, for two different decisions.
Which variable to bind next is ordered by Jessica, the `rows` of
[`Constraint::cardinality`](triblespace::core::query::Constraint::cardinality),
with Paul, its `distinct`, breaking ties: a variable with few distinct values but a large fanout
no longer looks cheap. Which constraint proposes is still chosen by Paul. Paul
alone misleads on a join such as `{ ?s @ formerStreamTitle: ?t, rdf_type: ?c }`
over DBLP: rdf:type has only 29 classes over 949,069 tribles, so ?c looked
smallest and every formerStreamTitle subject was re-proposed under every class
(16,853 proposals for 2,048 results). Jessica alone misleads on a lone pattern
`{ ?s @ a: ?o }`, where both variables carry the same row count and the tie no
longer knows which side has fewer values. Ordering by Jessica and breaking ties
with Paul avoids both (measured in the SPARQLoscope DBLP benchmark, 2026-11-14).

Every constraint can decide which rung of this ladder it occupies. Simple
wrappers that only track total counts behave like Jessica, those that surface
their tightest per-variable proposals behave like Paul, and structures capable
of intersecting their children on the fly approach Ghanima's accuracy. The
engine does not need to know which variant it is running—`estimate` supplies
whatever fidelity the data structure can provide.

## Guided depth-first search

At query start, [`Query::new`](triblespace::core::query::Query::new) asks every
variable for an estimate against the empty binding, settles any constraint that
is already fully determined by its constants, and orders the unbound variables.
The solver then repeats one negotiation per binding:

1. Refresh the estimates that the most recent binding could have disturbed —
   the `influence` sets of the variables bound since the last refresh, minus
   the ones already bound.
2. Re-sort the unbound variables and take the most specific one. The ordering
   is by the *bit length* of the volume estimate (smaller first), then by the
   bit length of the distinct-value estimate, so counts in the same
   power-of-two bucket are deliberately treated as equally specific; remaining
   ties go to the variable that influences the most others.
3. Ask the constraint tree to propose for that variable. An intersection lets
   its tightest child propose and runs the remaining children as confirmers
   over that child's output, most selective first, so what reaches the engine
   has already survived every clause.
4. Bind the first surviving candidate and descend.
5. When a level's candidates are exhausted, unbind the variable, return it to
   the unbound set, and continue one level up.

Traditional databases rely on sorted indexes to make the above iteration
tractable. Atreides still performs random lookups when confirming each
candidate, but the cardinality hints let it enumerate the most selective
constraint sequentially and probe only a handful of values in the wider ones.
Because the search is depth-first, the memory footprint stays small and the
engine can stream results as soon as they are found.

Consider a query that relates `?person` to `?parent` and `?city`. The search
begins with all three variables unbound. If `?city` only has a handful of
possibilities and each holds few people, its volume will be the smallest, so the
engine binds `?city` first. (If each of those few cities held millions of
people, the volume would steer the engine to start elsewhere.) Each city candidate is checked against the parent and person constraints
before the search continues, quickly rejecting infeasible branches before the
higher-cardinality relationships are explored.

## Per-variable estimates in practice

Suppose we want to answer the following query:

```
(find [?person ?parent ?city]
  [?person :lives-in ?city]
  [?person :parent ?parent]
  [?parent :lives-in ?city])
```

There are three variables and three constraints. Every constraint can provide a
cardinality hint for each variable it touches, and the combined query records
the tightest estimate for each variable:

| Variable | Contributing constraints (individual estimates) | Stored estimate |
|----------|-------------------------------------------------|-----------------|
| `?person` | `?person :lives-in ?city` (12), `?person :parent ?parent` (40) | 12 |
| `?parent` | `?person :parent ?parent` (40), `?parent :lives-in ?city` (6) | 6 |
| `?city` | `?person :lives-in ?city` (12), `?parent :lives-in ?city` (6) | 6 |

The estimates are scoped to individual variables even when no single constraint
covers the whole tuple. The engine chooses the variable with the tightest bound,
`?parent`, and asks the constraints that mention it for proposals. Each
candidate parent immediately passes through the `?parent :lives-in ?city`
constraint, which usually narrows the possible cities to a handful. Those
cities, in turn, constrain the possible `?person` bindings. If a branch fails —
for example because no child of the selected parent lives in the same city — the
engine backtracks and tries the next parent. The smallest estimated constraints
therefore guide the search towards promising combinations and keep the
depth-first traversal from thrashing through unrelated values.

## Implementation notes

- The search state is a stack of row frontiers over reusable per-variable
  candidate buffers. Retiring a frontier unsets its variable and pops; because
  constraints are stateless, nothing has to be notified or unwound.
- Constraints propose a complete candidate region for each parent batch; they
  do not implement cursors or seek. The engine resumably consumes its own
  buffer into child frontiers whose width ramps through 1, 8, 64, 512, … up to
  the query ceiling. This protects the first result from batching overhead
  while still presenting accelerators with wide regions deeper in the search.
- Highly skewed data still behaves predictably: even if one attribute dominates
  the dataset, the other constraints continue to bound the search space tightly
  and prevent runaway exploration. This is the payoff of re-estimating per
  binding rather than once per query — the popular entity and the rare one take
  different orders through the same query text.
- A uniquely owned per-variable proposal buffer is reused across sibling
  levels, so ordinary backtracking does not reallocate. Rayon clones share a
  published buffer immutably and keep independent cursors; the first clone to
  refill that slot installs a fresh buffer rather than copying data it will
  immediately clear.
- Under the `parallel` feature the same state machine is the rayon producer:
  splitting transfers one whole preferred-variable group (or terminal page)
  to a fenced sibling only when the left side retains another continuation.
  Candidate regions and geometric frontier pages stay intact. Results are the
  same bag of rows in an unspecified order.

## Why worst-case optimal?

"Worst-case optimal" does **not** mean output size plus a constant factor: a
query with an empty result may still need to inspect substantial input. It means
matching, up to implementation and logarithmic factors, the worst-case output
bound implied by the input relation cardinalities (the AGM/fractional-edge-cover
bound), rather than materialising pairwise intermediates that can be
asymptotically larger.

The Atreides family follows the generic-join shape behind that result: choose a
variable, let the tightest participating constraint enumerate its possible
values, and intersect those values through the other constraints before
descending. Dynamic cardinality estimates choose among valid variable orders;
they improve the realised work on skewed data, while the propose/confirm
intersection is the part that avoids oversized binary-join intermediates. The
precise guarantee still depends on participating constraints providing complete
proposals and sound confirmations—the scheduler cannot manufacture those laws
for an arbitrary custom data source.

This combination of simple heuristics, incremental estimates, and a disciplined
search strategy keeps the implementation straightforward while delivering the
performance characteristics we need for real-world workloads.
