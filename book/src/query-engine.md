# Query Engine

Queries describe the patterns you want to retrieve. There is no query planner
and no compiled plan. Every operator and every data source implements the same
[`Constraint`](triblespace::core::query::Constraint) protocol, and the engine
consults those constraints *while* it searches, so binding order is chosen from
the values already found instead of being fixed before evaluation.

This chapter describes that protocol, the search that drives it, the result
semantics that fall out of both, and — just as importantly — the things the
engine deliberately refuses to do. The refusals are load-bearing: each one is
what buys a property the engine does provide.

## The constraint protocol

A constraint restricts the values that query variables may take. It is not a
node in a plan; it is a participant the engine interrogates. The whole
interface is six methods, and the engine calls them in a fixed rhythm:

| Method | Role | Called |
|---|---|---|
| `variables` | Declares which variables the constraint touches. | Once, at query start. |
| `estimate` | Predicts the candidate count for one variable under one binding. | Before each binding decision. |
| `propose` | Enumerates candidate values for a variable, for a whole batch of bindings, into a buffer. | On the tightest constraint for that variable — an intersection picks it among its children. |
| `confirm` | Kills candidates that violate this constraint under their own binding. | On every *other* constraint touching that variable. |
| `satisfied` | Reports whether the constraint is still consistent with the binding. | Once at query start on the whole tree; then by a union before it proposes or confirms, to skip dead arms. |
| `influence` | Names the variables whose estimates go stale when one variable is bound. | Once per variable, at query start. |

`estimate` returns `None` for a variable the constraint does not touch, which
is how "irrelevant" is distinguished from "unknown cost". An estimate is a cost
quote and nothing else: it steers variable ordering, never correctness. A
constraint that lies about its cardinality makes the search slower, not wrong.
Whether the answer is `Some` or `None` must depend only on which variables are
bound, never on their values — a batch shares one bound set, and composites
read relevance off the batch.

Only four of the six need an implementation: `satisfied` defaults to `true` and
`influence` defaults to "every variable I touch except this one". A new data
source therefore joins the engine with `variables`, `estimate`, `propose`, and
`confirm` — iteration and point queries, nothing more. That minimum is what
keeps hash maps, PATCHes, succinct archives and device-resident structures all
admissible; a seek or leapfrog requirement would disqualify half of them.

Composition is by two constraints rather than by an algebra:
[`IntersectionConstraint`](triblespace::core::query::intersectionconstraint::IntersectionConstraint)
(built by [`and!`](triblespace::core::prelude::and)) and
[`UnionConstraint`](triblespace::core::query::unionconstraint::UnionConstraint)
(built by [`or!`](triblespace::core::prelude::or)). Both are ordinary
constraints implementing the same six methods, so a `TribleSet` pattern, a
`HashSet` membership test, and an application predicate mix in one query
without any of them knowing about the others.

## Propose and confirm take a batch

`propose` and `confirm` do not take one binding. They take a
[`Frontier`](triblespace::core::query::Frontier): the whole collection of
parent bindings sitting at one point of the search. A single binding is a
frontier of one, which is exactly the older single-binding protocol.

The reason is measured. With a width-1 frontier only the root level ever
proposes widely; every deeper level asks a source for the candidates of one
parent, and over real data (a region-size census on dblp) that is a median of
1–7 candidates at every scale, p95 around 200. Any batched tier — a GPU
dispatch that pays off at 16 384 candidates, a SIMD probe — therefore engaged
once at the root and never again. Batching the *parents* is what makes a
level's region large at every depth.

A frontier is cheap because bindings are indexes, not values (see below): it is
an index matrix over the shared level buffers plus an exact row selection.
Consecutive selections and their slices are implicit; a genuine permutation
borrows a dense list of row ordinals, so restricting a frontier never copies
an index row and pays four bytes per row only when the order must be explicit.
Correspondingly, the
[`ProposalBuffer`](triblespace::core::query::ProposalBuffer) is *segmented*: a
proposer calls `open(row)` before appending a row's candidates, and every entry
carries that **parent tag**. `Candidates` exposes the tags, so one region can
span a whole batch and a confirmer can still tell whose each candidate is.

Sources split cleanly along that seam. A verdict that does not depend on the
parent binding — set membership, a byte range, a constant — ignores the tags
and filters the whole region in one pass. One that does walks the region with
`Candidates::for_each_parent`, which yields maximal runs of equal tag, so a
per-binding setup is paid once per run instead of once per candidate.

Nothing about the batch changes what the query means. Worst-case optimality is
untouched — expanding *n* prefixes together is the same total work as expanding
them one at a time, and the AGM bound is a statement about output size, not
traversal order.

Batching has two different memory terms. The frontier matrices cost
`O(width × variables × depth)`: depth-first's `O(depth)` frontier traded for a
wide one. A proposal region can dominate that term. A source that proposes
`fanout` candidates for each parent materialises `Θ(width × fanout)` entries
before the level is consumed. Each entry currently carries a 32-byte value, a
four-byte parent tag, and one packed liveness bit — nominally 36.125 bytes,
excluding `Vec` capacity slack. Thus a width of 16,384 and a fanout of 10,000
is nominally about 5.92 GB (5.51 GiB) at one level, even though no frontier ever
contains more than 16,384 rows.

[`FrontierStats::peak_region`](triblespace::core::query::FrontierStats::peak_region)
reports that proposal high-water mark in entries. Choose a lower width with
[`Query::with_frontier_width`](triblespace::core::query::Query::with_frontier_width)
for queries that join against high-fanout sources; this bounds the number of
parents expanded together, but it cannot bound one parent's own fanout.

## Statelessness is the load-bearing choice

Every method receives the current [`Binding`](triblespace::core::query::Binding)
— or a batch of them — as a parameter. A constraint keeps no cursor, no
half-finished enumeration, no record of where the search has been.

That single decision pays for most of the engine's structure:

- **Backtracking is free.** The engine unsets a variable in the binding and
  moves on. There is nothing to notify, unwind, or roll back, because no
  constraint holds state that could be stale.
- **The constraint tree can be cloned.** Parallel execution splits by cloning
  the *engine's* state; the constraint tree is shared behind an `Arc`. If
  constraints held live iterators, a split would have to duplicate or hand off
  those iterators, and a borrowed enumeration would tie the constraint's
  lifetime to the engine's — the self-referential trap that a stateful protocol
  cannot avoid.
- **A level is proposed once.** Because no source is ever asked to resume, a
  level's buffer is written exactly once and never appended to while its
  variable is bound. That makes "a bound variable's buffer is stable for the
  lifetime of its binding" an unconditional invariant, which is what lets a
  binding be an *index* into that buffer instead of a copy of the value.

## Depth-first search with dynamic variable ordering

The ordering is the engine's core performance idea, not an implementation
detail.

[`Query::new`](triblespace::core::query::Query::new) asks every variable for an
estimate against the empty binding. Then the search repeats one step, over a
whole frontier at a time:

1. For each row of the frontier, pick its most specific unbound variable from
   *that row's own* estimates.
2. Partition the frontier by that choice and take the next group.
3. Ask the constraint tree to `propose` candidates for the group's variable,
   over all of the group's rows in one call. An intersection internally lets
   each row's tightest child propose and runs the remaining children as
   confirmers over that output, so the buffer the engine sees has already
   survived every clause.
4. Turn the next chunk of surviving candidates into the child frontier and
   descend. Each child row inherits its parent's estimates and refreshes
   exactly the ones the new binding could have changed — the `influence` set
   of the variable just bound.
5. When a level runs out of live candidates, retire it and continue with the
   next group, then with the next chunk one level up.

### The width is a ceiling, and the frontier ramps from one row

`DEFAULT_FRONTIER_WIDTH` is how wide a chunk may *get*, not how wide the first
one is. A level's first chunk is `INITIAL_FRONTIER_WIDTH` = 1 binding. Later
chunks multiply by `FRONTIER_RAMP_BASE` = 8 until they reach the ceiling. If
the final remainder would be smaller than the chunk before it, the engine
merges that tail early; the caller's ceiling remains a hard bound.

That is what keeps time-to-first-result honest. A caller who stops after one
row — `exists!`, `.next()` — must not pay to build a 16 384-wide frontier it
will never look at, and with a first chunk of one it does exactly the work the
single-binding engine did. Measured on a first-row-only join, a flat
full-width engine is 8.8x slower than the pre-batching engine; one narrow
chunk closes the entire gap.

The base is the latency/throughput trade, not an incidental tuning detail. A
base-2 ramp was measured and rejected: its last chunk is only about half a
drain, so it cut a fixture's useful frontier from 2048 rows to 512 and raised
expansions from 3 to 74. The failure was the base, not geometric growth. At
base 8, the last term is asymptotically seven eighths of the drain and a 16 384
ceiling takes six rungs rather than doubling's fifteen. Across the 100-query
registry on three backings, base 8 retained 99.61% of aggregate widest-frontier
width and 93.30% of GPU-routed candidate work (against 97.46% for the flat
schedule), at 44.7% more expansions. It therefore keeps almost all useful
batch width while avoiding the flat schedule's enormous overshoot for callers
that want only a handful of rows. The first row is protected exactly; larger
short demands pay at most the next base-8 rung.

### A 1:1 descent copies nothing

Step 4 normally builds the child frontier by copying each drawn candidate's
parent row and filling in the newly bound slot. When the draw is **1:1** — one
surviving child per parent row, in order, covering the whole frontier, with
nothing left pending — that copy is pure waste: no row was gained, lost or
reordered, so the child block *is* the parent block with one more slot
written, and the child's estimate rows are bit-identical to the parent's.

The two standing invariants are what make it sound. Confirmers may only kill
candidates, never revive them, so a surviving row keeps its identity. Buffers
are write-once, so the newly bound variable's slot in every row was previously
unwritten and filling it destroys nothing. And because such a draw leaves the
level spent, the parent frontier is never asked for anything again, so its
matrices are handed *down* rather than shared — which is what lets a whole
chain of 1:1 descents run without a single matrix copy instead of only the
first one.

Ownership needs no separate flag. The matrices already sit behind `Arc` so a
rayon split copies refcounts, and `Arc::get_mut` therefore succeeds exactly
when no split or steal holds the other half; when it says no, the copying path
runs. `FrontierStats` counts both paths.

The fast path is gated so that it costs nothing when it cannot fire.
Recognising a 1:1 draw means deferring the child rows until the draw's shape
is known, and that deferral is a second pass — measured at +10% and +20% on
two fixtures when charged to every descent. So the engine asks first, from
what it already knows: a level holding `proposed` candidates for `rows`
parents can only yield one child per parent if `proposed == rows`. Every
fan-out level fails that `O(1)` test and runs the fused single-pass build
exactly as before.

This matters most for the shape batching can never help: a chain with fan-out
one at every level has no sibling parents to widen the frontier with, so it
can only ever be *charged* for the machinery. Removing the per-level row copy
is what brings it back to the single-binding engine's cost.

**A row is never moved onto a variable it did not choose**, however tempting
that is for batch size. `propose` owns candidate support and first-seen order,
and the protocol supplies no cross-variable support-equivalence law, so an
estimate-compatible variable is not an interchangeable action. All the leeway
lives in the bucketing described next — which is exactly why agreement, and so
an unsplit batch, is the common case.
[`FrontierStats`](triblespace::core::query::FrontierStats) counts expansions,
rows and groups, so fragmentation is observed rather than assumed.

The plan is represented with the same economy. Until planning runs there is
no plan allocation. If every row chooses the same variable, the depth stores
only that variable and the rows remain an implicit consecutive selection. If
rows disagree but their stable variable groups are already consecutive, only
the group boundaries are stored. An explicit row-ordinal permutation exists
only when grouping actually changes visitation order. These are different
representations of the same exact row selection, not separate execution
strategies.

Specificity is deliberately coarse. The sort key is the *bit length* of the
estimate (`ilog2(n) + 1`), so counts inside the same power-of-two bucket are
treated as equally specific; the tie-break then prefers the variable with the
largest `influence` set — the one whose binding will sharpen the most other
estimates. Two effects follow. Small differences between two sources' guesses
cannot flip the order, which keeps the search stable when estimates are rough.
And when the engine genuinely cannot tell two variables apart on cardinality,
it picks the one that buys the most information.

Re-sorting on every step is what makes the ordering *dynamic*. A planner
chooses one order from global statistics and lives with it for the whole query;
here each level chooses from the estimates *under the current partial binding*.
On skewed data this is the difference between a good average and a good worst
case: the popular entity and the rare one take different paths through the same
query, because after binding an entity the remaining estimates are no longer
the same numbers. Nothing is cached, so nothing has to be invalidated. See the
[Atreides Join](atreides-join.md) chapter for how estimate fidelity ranks and
why this is worst-case optimal.

## Proposals: one write-once buffer per level

`propose` writes into a
[`ProposalBuffer`](triblespace::core::query::ProposalBuffer) — the engine's
candidate store for one variable at one level. Entries are plain 32-byte
`RawInline` values at fixed stride. Alongside them the buffer keeps a liveness
bit per entry, packed 32 to a `u32`, and a `u32` parent tag naming the frontier
row the entry was proposed for.

Entries are effectively write-once. A proposer may rewrite the region it
appended in the current call before it returns — that is how a union applies
its sort-dedup — but once the caller can see the region, the indices are
frozen, because kills bind to them.

Nothing is ever compacted. A candidate that fails confirmation has its liveness
bit cleared and stays exactly where it was; the engine iterates the live
entries. That costs a scan over dead entries and buys two things: an entry's
index is stable for the lifetime of the level, so a kill can be recorded by
index alone, and no confirmer ever has to agree with another about where a
candidate now lives.

Packing liveness 32 to a word is what makes that scan cheap: `count_live` and
`next_live` fold whole words through `count_ones` and `trailing_zeros` rather
than looking at candidates one at a time. Two things get harder in exchange,
and both are paid for inside the buffer's own module. A kill becomes a
read-modify-write on a word shared with 31 neighbours. And a region no longer
starts on a word boundary — nor does a per-parent run inside one — so its first
and last words carry liveness bits owned by *neighbouring* regions of the same
buffer. The invariant is enforced at the boundary of the type: every write path
masks to the owned bits and every read path zeroes the bits it does not own, so
no caller — the device confirm path included, see below — can reach a
neighbour's liveness.

## Confirmation is kill-only

[`Candidates`](triblespace::core::query::Candidates) is the region handed to
`confirm`: values are read-only, liveness words are killable, and there is no
way to revive an entry or add one.

That restriction is the whole reason confirmation needs no coordination. If a
confirmer can only remove, then several confirmers writing into the same region
compute their conjunction no matter how they are scheduled:

- **Sequentially**, each skipping entries that are already dead — the CPU path.
- **In parallel**, each on its own copy of the liveness words, merged with
  [`and_words`](triblespace::core::query::and_words) — the path a batching
  accelerator takes.

Both schedules are legal, produce identical liveness, and the engine does not
have to choose between them ahead of time. A union inverts the merge: it runs
each live arm on a scratch copy and combines with
[`or_words`](triblespace::core::query::or_words), so a value survives if any
arm accepts it.

This is also what makes an accelerator safe to bolt on. A device that computes
verdicts for a whole region cannot corrupt the search, because the only thing
it can do with its answer is clear bits that the CPU would also have cleared.

## What the engine refuses: resumable narrowing

An earlier design let a source deliver a level in geometrically growing chunks
through a resumable cursor, so a level with a million candidates would not have
to materialize a million before the engine could try the first one. It is
gone, and the reasons are worth recording because the idea recurs.

It was never adopted by a single leaf source, so the machinery only ever ran
its own default. It answers a time-to-first-result question that a pure
conjunctive query does not ask — depth-first already yields the instant the
stack bottoms out, and the measurement bore that out (0.004 ms against 0.017 ms
for the design it was meant to improve). And its one real case, a wide root, is
a lottery on iteration order rather than a saving: chunking helps only if the
surviving candidates happen to sort early.

What did survive is the *geometric* part. The deleted cursor carried an
`INITIAL_CHUNK`/`WIDEN_FACTOR` pair, and the residual engine before it grew its
search width geometrically after negative work; both are the same idea, and
both were attached to the wrong object. Attached to a *level*, growth asks a
source to resume. Attached to the *frontier*, it asks nothing of anyone — the
engine already owns how many parent rows it expands at a time, so
`INITIAL_FRONTIER_WIDTH` and `FRONTIER_RAMP_BASE` buy the time-to-first-result
property the cursor was reaching for with none of its protocol cost.

Narrowing a wide level is still a real problem; galloping intersection is the
standing candidate for it. What the engine will not do is require a *seek* from
sources, because that requirement is what would disqualify half of them.

## Parallel execution

With the `parallel` feature a query is also a rayon producer:
`find!(...).into_par_iter()`. There is no second solver behind it. Splitting
walks the same state machine and transfers a *whole frontier unit* to a sibling:

- Once planning has partitioned a frontier by the rows' preferred next
  variable, one complete group may be transferred. The left producer advances
  its group cursor; the sibling is re-rooted at that frontier and fenced to the
  single group it received. Both share the immutable plan and frontier
  matrices behind `Arc`; proposal buffers are not divided.
- A published proposal buffer is immutable, so sibling binding stores share it
  behind `Arc` and copy only their consumption cursors. If one sibling later
  refills that variable, it installs a fresh empty buffer before proposing;
  the other sibling's indexes keep resolving through the old snapshot. A
  uniquely owned buffer keeps and reuses its allocation.
- A complete terminal page may likewise be transferred as one unit. This is
  how a one-variable query can expose parallel work without slicing its result
  frontier.
- A transfer is admitted only when the left producer has a distinct future:
  another group at this frontier, or an ancestor level with an unconsumed
  candidate suffix. A sole group or page with no such continuation stays in
  place and the producer descends serially; that descent may expose genuinely
  independent groups deeper in the search.
- The sibling owns no ancestor continuation. Once its fenced group or page is
  exhausted it ends instead of unwinding into work still owned by the left
  producer.
- Geometric pages and preferred-variable groups therefore remain intact. A
  split never turns one accelerator-sized proposal/confirmation batch into two
  smaller batches merely to feed rayon.
- A leaf just drives the ordinary sequential `Iterator::next` and folds the
  results. No engine logic is duplicated for the parallel path.

The ownership rule is itself the split bound: every successful split removes
one group or page from the left producer and fences it into the right. Work
cannot be handed back or rediscovered, so rayon's pressure splitter needs no
engine-specific budget or thread-count tuning knob.

The guarantee is the same bag of rows, not the same order. Constraint trees are
shared behind an `Arc`, so a split is a refcount bump rather than a tree clone;
code that wants aggregate observations across shards needs its own
synchronization (an `Arc<AtomicU64>`, say) because clone-local interior state
is not a global counter.

## Bag semantics at the interface

**The engine emits one row per complete binding.** When the unbound set empties,
that assignment is a result. Nothing deduplicates it.

Hidden variables therefore surface as multiplicity. If an entity has *n*
outgoing edges and a query projects only the entity while a `temp!` or `_?`
variable ranges over the target, that entity is emitted *n* times:

```rust
use std::collections::HashSet;

use triblespace::prelude::*;

mod social {
    use triblespace::prelude::*;
    attributes! {
        "C21DE0AA5BA3446AB886C9640BA60244" as friend: inlineencodings::GenId;
    }
}

let mut kb = TribleSet::new();
let alice = ufoid();
let bob = ufoid();
let carol = ufoid();
kb += entity! { &alice @ social::friend: &bob };
kb += entity! { &alice @ social::friend: &carol };

// One row per complete binding: the hidden `_?friend` multiplies `?person`.
let rows: Vec<_> = find!(
    (person: Id),
    pattern!(&kb, [{ ?person @ social::friend: _?friend }])
)
.collect();
assert_eq!(rows.len(), 2);

// Deduplication is the consumer's job.
let distinct: HashSet<_> = find!(
    (person: Id),
    pattern!(&kb, [{ ?person @ social::friend: _?friend }])
)
.collect();
assert_eq!(distinct.len(), 1);
```

This replaced an engine that projected with SET semantics. That engine kept a
claims table: an ordered key derived from the head's raw bytes, claimed before
conversion, so a second binding with the same public identity was discarded.
It was removed because the cost was structural rather than incidental. The
table's memory grows with the *result* set, not with the query; under rayon the
claim domain has to be shared across workers, which puts a synchronization
point on the hot path of an otherwise share-nothing search; and once user code
runs behind a claim, a conversion failure or a panic consumes the key, so
another witness cannot retry it — a rule that is difficult to explain and
easy to trip over. Worst of all, the multiplicity is genuine information about
the data, and the engine was throwing it away on the way out.

Bag semantics is not the absence of a feature so much as the decision about
where the feature belongs. Two idioms cover what the claims table used to do:

- **Collect into a set.** `HashSet<_>` (or `BTreeSet<_>`) after `find!` costs
  memory proportional to the distinct results — the same memory the claims
  table cost — but only when the caller actually wants it, and it deduplicates
  on the converted Rust values rather than on raw bytes.
- **Two queries.** Enumerate the outer variable, and use
  [`exists!`](triblespace::core::prelude::exists) for the inner condition.
  `exists!` stops at the first witness, so the fan-out is never enumerated at
  all. This is usually the faster answer, and it is the one that reads like the
  question being asked: "entities that have a friend", not "entities paired
  with a friend, deduplicated".

The unit head follows the same rule rather than getting an exception:
`find!((), constraint)` yields one `()` per satisfying assignment. Use
`exists!` when the question is existence.

Note that `or!` is a genuine exception at the *binding step*, not at the
interface: a union sorts and deduplicates the candidate values it proposes for
a single variable, so two arms that offer the same value for the same variable
contribute one candidate, not two. That is a property of the candidate buffer
for one level, and it does not extend to complete rows — the same alias
witnessed by two different entities is still two rows.

Candidate uniqueness is scoped to one proposal region and keyed by
`(parent tag, value)`: equal values belonging to different parent bindings are
different members of the relation. Exactness, uniqueness, and physical order
are separate properties—knowing that a producer enumerated its complete input
does not prove that its output is duplicate-free, and neither property promises
an order. When regions over the same parent domain reconverge, as union arms do,
uniqueness must therefore be re-established by deduplication unless their
disjointness is proved.

## Constants live below the variable layer

A pattern position is a [`Term`](triblespace::core::query::Term): either a
`Var` the engine solves for, or a `Const` pinned at construction. The macro
layer folds attribute constants, literal values, and constant entity ids into
`Const` terms.

Constants never enter a `Binding`, are never proposed, and are excluded from
`variables()`. They behave exactly like a variable that was already bound —
`RawTerm::position_value` returns the pinned value where it would return the
binding's value — so every backend's bound/unbound dispatch handles them with
no extra match arms.

Keeping them below the variable layer is what makes `or!` usable. Every arm of
a union must declare the same variable set, because the result schema is flat:
one row binds one variable set exactly once, so a variable that only exists in
some alternatives has nowhere to live. If a literal allocated a hidden
variable, then two arms matching different attributes would declare different
sets and the union would be rejected at construction — which was exactly the
symptom before constants became Term-native. As folded constants they cost no
variable, so an arm on `profile::nickname` and an arm on `profile::display_name`
declare the identical set and compose.

Two more consequences fall out. Literals do not consume the 128-variable
budget, so a pattern with 161 constants allocates zero variables. And a pattern
whose positions are *all* constant has an empty variable set, which the search
would never visit — so `Query::new` settles it once, up front, with a single
`satisfied` call against the empty binding. This is why `satisfied` must be
exact once every variable it touches is bound: for a constant subtree there is
no variable through which the search could later discover failure.

## Where the GPU fits

The optional `triblespace-gpu` crate accelerates one operation:
`WgpuSuccinctArchive` keeps a succinct archive's value universe, per-axis
occupancy boundaries, and six Jerky wavelet matrices resident on the device,
and routes a `confirm` region to a kernel when it has at least
`DEFAULT_MIN_CONFIRM_BATCH` live candidates.

It is not a second engine and not a planner. Estimates, proposals, prefix
walks, and satisfaction checks stay on the CPU; a region below the threshold
and any device error fall through to the canonical CPU arm, which the crate's
parity suite holds to identical liveness words. The substitution is legal
precisely because of the kill-only contract: verdicts computed anywhere merge
back by word-wise AND, and a device can never revive a dead entry.

The packed liveness layout shapes how a kernel writes its verdicts. The flat
index of a verdict kernel is the *bit position* in the region's liveness words
— so candidate `i` sits at bit `bit_offset + i` — and one `plane_ballot` per
32-lane plane produces a whole packed verdict word with every bit already in
place, stored by a single lane. No rotation, no read-modify-write, no atomic.
The AND and the write-back are ordinary word operations, because the device
works on a *private* copy taken through `live_words()` and merged through
`set_live_words()`, and those two mask the neighbouring regions' bits out and
back in. The kernel needs one device property for this — planes exactly 32
lanes wide — which the host checks before dispatching, demoting to the CPU arm
if it does not hold.

The threshold is measured, not guessed. On an Apple M4 Max (Metal via wgpu),
against a 262,135-trible archive with fully live regions, the GPU round trip is
nearly flat at ~1.4–2.2 ms while CPU cost scales linearly — putting the
crossover near 8k live candidates for the range shape (two wavelet ranks per
candidate) and near 22k for the lighter membership shape. 16,384 is the
single-knob compromise between them; the full crossover table lives in the
constant's doc comment. `WgpuSuccinctArchive::stats` exposes dispatch and
fallback counters, so the routing economics stay observable instead of being
hidden inside a heuristic.

## Where regular paths went

Regular path queries — "everyone reachable through a chain of `follows`", "all
ancestors via repeated `parent`" — are no longer part of the engine. The
`path!` macro and its query-time evaluator have been removed.

The reason is the stateless protocol. A triple pattern is a relation over a
fixed set of variables, and the engine can ask it for candidates under any
binding. A regular path is an automaton product traversal: evaluating it inside
the search needs per-activation state — where the frontier is, which automaton
branch produced which value, what has already been visited — and that state
belongs to one live traversal, not to a binding the engine can hand back later.
Every attempt to keep it inside the protocol grew the protocol, and the growth
did not stay confined to paths: pager hooks, activation receipts, and novelty
keys became things *every* constraint had to reason about, including the ones
that only ever wanted to answer "is this triple present".

So paths moved out of query time entirely. The replacement is a materialized
closure **index**: compile the graph edges and an epsilon-free automaton into a
product graph and maintain its reflexive transitive closure, then let queries
read the closure as an ordinary relation. Reachability becomes a lookup rather
than a traversal, which is the right shape for a data model where facts are
only ever added — the closure grows monotonically with the edge set.

The stable implementation lives in the standalone `triblespace-paths` crate.
Its `PathExpr` builder compiles the normal regular-language operations into a
fixed epsilon-free automaton; direct `Automaton` construction remains the
low-level escape hatch. The crate persists unionable direct-product summaries
over exact source collection elements, closes their selected union, and exposes the resulting
endpoint relation through the ordinary two-variable constraint protocol. See
[Regular Path Indexes](regular-path-indexes.md) for the expression API,
lifecycle, freshness boundary, and dense-output trade-off.

## What the engine will not do

Four refusals, and what each one buys:

- **No cost-based optimizer.** There is no plan to compile, no statistics to
  collect, no cardinality model to keep calibrated, and no plan cache to
  invalidate. What replaces it is the per-step ordering above, which sees the
  actual partial binding instead of a summary of the data. The cost is that a
  genuinely bad `estimate` cannot be corrected by anything but a better
  `estimate`; the benefit is that adding a data source means implementing four
  methods, not teaching a planner about a new operator.
- **No negation.** There is no `MINUS`, no `FILTER NOT EXISTS`, no `OPTIONAL`.
  This is a data-model decision reaching up into the engine: the trible model
  is monotonic, and a non-monotonic operator would make a query's answer
  depend on facts *not* being present — which stops being a stable statement
  the moment another replica merges in. Monotonicity is what makes
  `pattern_changes!` sound, what makes distributed merge coordination-free, and
  what makes a query result something you can still believe after a `pull`.
- **No query-time recursion.** See the section above. Recursion returns as a
  maintained index, where the fixpoint is computed once against the data rather
  than repeatedly inside every search.
- **No projection dedup.** Covered above: the multiplicity is real, the
  deduplication has a cost, and the consumer is the one who knows whether it
  wants to pay it.

What the engine does provide in exchange is a short list, but a durable one:
predictable latency, skew resistance, no tuning knobs, and one protocol that a
`TribleSet`, a compressed on-disk archive, a `HashSet`, a search index, and an
application predicate all speak equally well.

## Queries as Schemas

You might notice that trible.space does not define a global ontology or schema
beyond associating attributes with a
[`InlineEncoding`](triblespace::core::inline::InlineEncoding) or
[`BlobEncoding`](triblespace::core::prelude::BlobEncoding). This is deliberate. The semantic web
taught us that per-value typing, while desirable, was awkward in RDF: literal
datatypes are optional, custom types need globally scoped IRIs and there is no
enforcement, so most data degenerates into untyped strings. Trying to regain
structure through global ontologies and class hierarchies made schemas rigid
and reasoning computationally infeasible. Real-world data often arrives with
missing, duplicate or additional fields, which clashes with these global,
class-based constraints.

Our approach is to be sympathetic to edge cases and have the system deal only
with the data it declares capable of handling. These application-specific
schema declarations are exactly the shapes and constraints expressed by our
queries[^1]. Data not conforming to these queries is simply ignored by
definition, as a query only returns data satisfying its constraints.[^2]

## Join Strategy

The query engine uses the Atreides family of worst-case optimal join
algorithms. These algorithms leverage the same cardinality estimates surfaced
through `Constraint::estimate` to guide variable choice over partial bindings,
providing skew-resistant and predictable performance. Estimates are recomputed
from the current binding rather than cached, so there is no invalidation
protocol and no separate planning artifact to maintain.
For a detailed discussion, see the [Atreides Join](atreides-join.md) chapter.

## Query Languages

Instead of a single query language, the engine exposes small composable
constraints that combine with logical operators such as `and` and `or`. These
constraints are simple yet flexible, enabling a wide variety of operators while
still allowing the engine to explore the search space efficiently.

The query engine and data model are flexible enough to support many query
styles, including graph, relational and document-oriented queries. Constraints
may originate from the database itself (such as attribute lookups), from custom
application logic, or from entirely external sources.

For example, the [`pattern!`](triblespace::core::macros::pattern!) and
[`entity!`](triblespace::core::macros::entity!) macros—available at the crate root and re-exported
via [`triblespace::prelude`](triblespace::prelude) (for instance with
`use triblespace::prelude::*;`)—generate constraints for a given trible pattern in
a query-by-example style reminiscent of SPARQL or GraphQL but tailored to a
document-graph data model. It would also be possible to layer a property-graph
language like Cypher or a relational language like Datalog on top of the
engine.[^3]

```rust
use std::collections::HashSet;

use triblespace::core::examples::literature;
use triblespace::core::query::ContainsConstraint;
use triblespace::prelude::*;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::Handle;

fn main() {
    let mut kb = TribleSet::new();

    let author = ufoid();
    let book = ufoid();

    kb += entity! { &author @
        literature::firstname: "Frank",
        literature::lastname: "Herbert",
    };
    kb += entity! { &book @
        literature::author: &author,
        literature::title: "Dune",
    };

    let mut allowed = HashSet::<Inline<Handle<UTF8String>>>::new();
    allowed.insert("Frank".to_inline());

    let results: Vec<_> = find!((title: Inline<_>, firstname: Inline<_>),
        and!(
            allowed.has(firstname),
            pattern!(&kb, [{
                _?person @
                    literature::firstname: ?firstname,
                    literature::lastname: "Herbert",
            }, {
                literature::author: _?person,
                literature::title: ?title,
            }])
        )
    )
    .collect();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "Dune".to_inline());
}
```

The snippet above demonstrates how typed attribute constraints, user-defined
predicates (the `HashSet::has` filter), and reusable namespaces can mix
seamlessly within a single query.

Great care has been taken to ensure that query languages with different styles
and semantics can coexist and even be mixed with other languages and data models
within the same query. For practical examples of the current facilities, see the
[Query Language](query-language.md) chapter.

[^1]: Note that this query-schema isomorphism isn't necessarily true in all
databases or query languages, e.g., it does not hold for SQL.
[^2]: In RDF terminology: We challenge the classical A-Box & T-Box dichotomy by
replacing the T-Box with a "Q-Box", which is descriptive and open rather than
prescriptive and closed. This Q-Box naturally evolves with new and changing
requirements, contexts and applications.
[^3]: SQL would be a bit more challenging, as it is surprisingly imperative
with its explicit JOINs and ORDER BYs, and its lack of a clear declarative
semantics. This makes it harder to implement on top of a constraint-based query
engine tailored towards a more declarative and functional style.
