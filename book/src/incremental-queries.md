# Incremental Queries

The query engine normally evaluates a pattern over one complete relation.
Continuous ingest pipelines often need only the solutions which involve at
least one newly added fact. `pattern_changes!` implements that semi-naive delta
evaluation without tying the query engine to any storage or history model.

## Supply full facts and one delta

Maintain two sets:

- `full`, which contains every fact visible for the current observation; and
- `changed`, the subset added since the previous observation.

`full` must include `changed` before the query runs:

```rust,ignore
let mut full = initial;
let changed = entity! {
    &messiah @
    literature::title: "Dune Messiah",
    literature::author: &herbert,
}.into_facts();
full += &changed;

let new_titles: Vec<String> = find!(
    title: String,
    pattern_changes!(&full, &changed, [
        { _?author @ literature::firstname: "Frank" },
        { _?book @
            literature::author: _?author,
            literature::title: ?title
        }
    ])
)
.collect();
```

The complete runnable version is deliberately storage-independent:

```rust,ignore
{{#include ../../examples/pattern_changes.rs:pattern_changes_example}}
```

Applications may obtain `changed` directly from an importer, an event batch, a
collection-cover difference, or any other source. The query algorithm only
needs the two fact sets.

## How semi-naive evaluation works

For a pattern with several trible constraints, the macro evaluates one variant
per constraint:

1. that constraint reads from `changed`;
2. every other constraint reads from `full`; and
3. the variants are combined with `or!`.

Every returned binding therefore has at least one witness in the delta. Work
scales with the changed set and the number of trible constraints instead of
requiring each constraint to scan the complete dataset.

The union constraint deduplicates proposed candidate values at each search
level, so the same complete binding supported by several variants is enumerated
once per invocation. The usual `find!` projection semantics still apply:
hidden variables can create multiple rows when genuinely distinct complete
bindings project to the same tuple. Collect projected results into a set when
the application wants projection-level uniqueness.

Nothing is remembered between invocations. A later delta may return a tuple
seen earlier when a new fact supplies another proof. Applications that require
global once-only delivery retain the projected tuples they have consumed;
applications interested in witness events should project the witness identity.

## Use foundational support as the continuation token

A `Support` is exactly the `Cover<SimpleArchive>` of distinct foundational
payload handles represented by one immutable collection snapshot. Its
PATCH-backed membership makes a natural storage-level continuation token.
`Cover::additions_since` verifies that the earlier support remains a subset of
the later support and returns only newly observed members:

```rust,ignore
{{#include ../../examples/collection_pattern_changes.rs:collection_pattern_changes_observe}}
```

This computes set difference over immutable payload identities; it does not
walk a parent chain or ask an ambient head what changed. A second signer or
metadata claim over an existing payload is provenance and produces no data
delta. If a previous member is absent, the helper returns
`CoverAdvanceError::ResetRequired`: additions-only maintenance is no longer
sound, so rebuild the accumulated application state from `current`. Advance the
saved cover only after the complete fallible fold succeeds, as the example
does, to make a failed fold retry the same support.

The two pattern inputs need not share a representation. The runnable example
(`cargo run --example collection_pattern_changes`) uses immutable
`CollectionSnapshot<R, E>` values which own the store observation and realized
target cover. Their foundational support is a fallible, lazy provenance query;
their shard-preserving query values are reconstructed separately with `view`.

For a strict extension, compute `changed_support =
current_support.additions_since(previous.support()?)`. Await `ensure_exact` or
`maintain_exact` for that same foundational support through each desired
mapping edge, then ask the returned store snapshot for
`collection_exact(target, &changed_support)`. Do the same for complete
`current_support` to obtain `full`. Every hop receives the same support; no
intermediate physical cover becomes a watermark. Persisted `DERIVE` and
`MERGE` equations make repeated work idempotent and let the complete path reuse
the delta work without unioning temporary views or reconstructing a
`TribleSet`.

Keep the previous collection snapshot until the complete fallible fold
succeeds. A failed consumer therefore retries the same exact delta, while
already completed lattice work is merely rediscovered. If the previous support
is no longer a subset, `CoverAdvanceError::ResetRequired` asks the application
to rebuild from the complete current snapshot. Exact support prevents payloads
first observed after the chosen store watermark from leaking into either query
input merely because their blobs are resident later.

Payload support is deliberately not an exact fact difference. A new payload
may repeat a fact already present, and that new witness may legitimately make a
projected result recur. Consumers requiring global once-only delivery retain
their consumed result identities independently.

When an ingestion API already returns its newly produced fragment, querying
that fragment may still be cheaper than maintaining a changed derived cover.
The collection snapshot path is useful across process boundaries, after
reopening storage, and whenever the derived representation is the normal query
substrate.

The `incremental_collection_queries` benchmark measures this complete
maintenance loop against a full re-query over the same evolving source data:

```text
cargo bench --bench incremental_collection_queries -- \
  --commits 64 --books-per-commit 256 --warmup 1 --iters 4
```

Each observation includes functional Succinct snapshot advancement and
maintaining the application's result set. Publication, cover discovery, and
fixture construction remain outside the timer. The benchmark checks raw row
counts, projection-level set equality, consumer checkpoints, and exact source
covers at every commit; geometric checkpoints affect reporting only, not
observation.
Its fixture projects every query variable and gives every book a unique
binding, so those equality checks do not imply projected-set semantics for
arbitrary queries. The between-observation checks deliberately favor strong
invariants over pristine cache state; read the output as warm-trace maintenance
latency rather than isolated cold-call latency.

## Monotonicity and CALM

Removed results are not tracked. Facts and collection commits are monotone:
new input can add witnesses but does not invalidate a previous conclusion.
This is the [CALM principle](https://arxiv.org/abs/1901.01930) in executable
form—monotone results can be distributed without consensus.

When a domain needs versions or supersession, represent those relationships as
facts and query the explicit DAG. Do not infer a winner from insertion order.

## Trade-offs

- The caller supplies the changed set; the query engine keeps no hidden cursor.
- Each trible constraint adds one query variant, so selective constraints keep
  delta evaluation efficient.
- A changed set which grows without bound loses its advantage; advance the
  continuation after successful consumption.
- A result may recur in a later invocation when the later delta provides a new
  witness.
