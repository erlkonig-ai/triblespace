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

## Use absorbed source payloads as the continuation token

A `Support` is a `Cover` of one collection's own foundations: a root's
distinct committed payload handles, a derived collection's leaf images. Its
PATCH-backed membership makes a natural storage-level continuation token, and
`Cover::additions_since` verifies that the earlier token remains a subset of
the later one and returns only newly observed members.

The token has to name what the queried view answers for, and a derived view
answers for the source payloads that have a leaf in it, not for everything
the source holds. Every writer derives the payloads it wrote, so another
writer's payload is in the source before it is in the view. A token taken
from the source's own support would advance past that payload and never
deliver it. So the example asks each hop's freshness instead: the source
payloads the first view has a leaf for (the source's support minus
`raw.missing_from(&source)`), and only while the second view has caught up
with the first (`accelerated.missing_from(&raw)` is empty). A view that lags
holds the token back:

```rust,ignore
{{#include ../../examples/collection_pattern_changes.rs:collection_pattern_changes_observe}}
```

This computes set difference over immutable payload identities; it does not
walk a parent chain or ask an ambient head what changed. A second signer or
metadata claim over an existing payload is provenance and produces no data
delta. If a previous member is absent, the helper returns
`CoverAdvanceError::ResetRequired`: additions-only maintenance is no longer
sound, so rebuild the accumulated application state from `current`. Advance the
saved token only after the complete fallible fold succeeds, as the example
does, to make a failed fold retry the same delta.

The two pattern inputs need not share a representation. The delta is a set of
source payloads, so it is read from the source by handle through the same
snapshot -- `snapshot.get(member)` for each new member, unioned -- and the
maintained target's `view` answers the `full` side. Supports of two
collections are never compared: a view's support is its own leaf images,
and whether it has caught up with its source is `missing_from`. There is no
way to attach a target for only the delta; the delta is read where it
lives. Persisted `DERIVE` and `MERGE` equations make repeated maintenance
idempotent.

Keep the previous token until the complete fallible fold succeeds. A failed
consumer therefore retries the same delta, while already completed lattice
work is merely rediscovered. Because both inputs come from one snapshot,
payloads first observed later cannot leak into either query input merely
because their blobs are resident by then.

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

## Additive rules over a durable fact collection

`reactive::collection::CollectionEnvironment` connects the experimental native
rule language to one root `Collection<SimpleArchive>`. Observations, immutable
program revisions, execution readings, and published consequences are all
ordinary facts. The adapter has no notification owner, transport, or external
effect worker. An application supplies immutable snapshots, a content reader,
and a writer explicitly.

An immutable reading states `reading_of: environment_anchor` and repeated
`selects` edges naming the exact rule revisions to execute. Readings use
`metadata::supersedes` for their observation DAG. `observe(snapshot)` queries
that snapshot's facts with the existing register and returns `Empty`, `Sole`,
or `Fork`. A fork does not choose a winner or combine the programs. A Sole
reading with no selected revisions explicitly retires execution. Publishing a
new rule revision alone does not select it or replace an explicitly selected
older revision. Resolve a reading fork by publishing a new reading that
supersedes the observed branches and states its intended selection.

```rust,ignore
{{#include ../../triblespace-core/examples/reactive_collection.rs:reactive_collection_run}}
```

Run the complete example with
`cargo run -p triblespace-core --no-default-features --example reactive_collection`.
It uses an in-memory store; a durable store implements the same publication
boundary. `publish` checks writer admission, inserts a native COMMIT, then calls
`flush`. Either failure retains the exact fragment and the attempted signer for
retry. The batch blocks observation and further advancement until settled, so a
new reading cannot silently displace unfinished publication. An inserted record
visible in a snapshot after a flush error does not prove durability. There is
no rollback or exactly-once external effect guarantee.

`advance` retains successful new facts even if a later binding fails; therefore
call `publish` after either evaluation outcome. Report both errors when both
operations fail. Its budget bounds firings only, not search time, memory, or
termination. A missing content blob remains a retryable error. Content arrival
can unblock evaluation without any new fact or change in root support; a later
explicit reader can retry that binding.

Observation requires a complete view of the root's known admitted foundations.
Missing bytes fail instead of quietly presenting a smaller input. The support
cursor names logical foundations, not the physical cover: a resident merge can
replace its input shards without changing the interpretation. The adapter reads
the current cover and unions its native facts directly. Shrinking support
requires explicit reopening, and never erases the existing adapter's held
facts. Observation failures disable advancement until another observation
succeeds. These native snapshots and query cursors are disposable continuation
state, not a second database of domain objects.

Retirement leaves every published consequence available to later rules. If R1
produced `b` from `a`, retiring R1 and selecting R2 (`b` implies `c`) can produce
`c`. This is a history of accepted conclusions, not the current output of R2
over raw `{a}`. A fresh counterfactual interpretation needs an explicitly chosen
input frame excluding earlier conclusions. Output entity cores remain free of
reading IDs and provenance salts. The adapter exposes its observed support and
selected reading for inspection; it does not persist a proof graph.

After reopening a store, construct a new adapter and observe its complete
durable frame. Committed conclusions seed recomputation. Bindings may fire
again; already held consequences add no new publication batch. The memo and
support cursor are not durable receipts. If the reading changed before restart,
uncommitted work from an old reading is not guaranteed to complete. Reopening
also cannot certify continuity with admission or retention evidence no longer
held by that store.

General rules do not implement `CollectionDerivation`. A rule joining a ward
fact in commit A with a fever fact in commit B can produce an alert from
`A union B` although neither separate member produces it. Thus its ordinary
output union is not the foundation-local homomorphism required by DERIVE.
The adapter instead publishes computed conclusions as authored COMMIT facts.


## Author native rules as text

`reactive::text::parse(Bytes)` returns a `Fragment` containing exactly the
asserted content facts, plus blobs explicitly authored with `utf8`. It adds no
exports, schema metafacts, operation defaults, collection readings or execution.
The runnable example mints IDs in its caller, then binds them once in a header:
`alias patient = id"<32 hex digits>";`. Use actual attribute IDs (`attribute.id()`),
not the anchor literals used to define their encodings.

The body is ordinary native clause and term entities expressed more compactly:

```text
{{#include ../../triblespace-core/examples/reactive_text.rs:reactive_text_rule}}
```

This synthetic matching example joins a ward observation and a note from
separate commits, checks exact case-sensitive UTF-8 containment, and publishes
one alert core with descriptive annotations. Two independently authored
revisions and two notes converge on the same core. It demonstrates matching,
not clinical guidance. Run it with:

```text
cargo run -p triblespace-core --no-default-features --example reactive_text
```

Each `matches`, `core` or `emits` statement asserts a revision-to-clause link
and the clause's explicit subject, predicate and object term IDs. `operation
POSITIVE` asserts only that operation; `literal ?term VALUE` asserts only the
term's literal value. `constraint @id STRING_CONTAINS(?container, ?needle)`
asserts the constraint link, operation and its two term references. Empty rule
blocks assert nothing. Repeating any statement unions facts, including literal
alternatives; the parser imposes no schema cardinality rules.

Aliases match `[A-Za-z_][A-Za-z_0-9]*` and must be declared before use. `@name`
and `?name` share a namespace; `?` is a visual term marker. Multiple spellings
for one ID are legal, but rebinding a spelling to a different ID is an error.
`id"<32 hex digits>"` can replace any alias reference. Changing an alias's
spelling changes no facts and persists no label; author `metadata::name` facts
explicitly when labels should survive independently of this projection.

Every statement ends with `;` (a rule block ends with `}`). Whitespace and
`//` line comments are ignored. Four explicit value constructors are available:

| Constructor | Meaning |
| --- | --- |
| `raw32"<64 hex digits>"` | Exactly those 32 bytes, for any encoding or malformed value. |
| `genid(@id)` | Native zero-prefixed 16-byte ID encoding. |
| `handle<UTF8String>"<64 hex digits>"` | A complete handle, without requiring its blob. |
| `utf8("text")` | JSON-escaped UTF-8 text, stored in the returned fragment's blob store. |

`fact @entity @attribute VALUE;` is the universal form, including unknown
operations. Syntax errors return a `TextError` with zero-based byte offset and
one-based line/byte column; no partial fragment is returned. Native evaluator
diagnostics remain separate from text syntax.

`reactive::text::write(&facts, &mut output)` uses deterministic local aliases
and conservative readable clause/constraint shorthand. A field with several
values, malformed bytes or missing data remains raw; every uncovered input fact
is emitted. Unknown annotations and shared IDs survive. The guarantee is
`parse(write(F)).facts() == F` for any supplied finite `TribleSet F`. Literal
encodings are never guessed, and writing needs no blob reader. Existing blob
bodies, exports, metafacts, comments and alias spelling are outside this
fact-set contract; this is not a Fragment or pile archive.

Text import does not edit published revisions in place. Semantic changes need
an explicitly fresh revision and fresh changed semantic nodes, with deliberate
sharing of unchanged nodes and explicit `metadata::supersedes` links. Automatic
fork/remapping and editing unknown graphs are outside this API. Superseding a
revision does not change a collection's selection reading.

## Try a saved edit in one continuing environment

`reactive_live` is a small synchronous command driver. Its `MemoryRepo`, signing
key and one `CollectionEnvironment` live until EOF or `quit`. **Only the source
files survive process exit**; this example does not persist readings, results or
execution progress. A new initialization mints a distinct set of example entity
and program IDs; it reuses the canonical `metadata::name` and
`metadata::description` attributes. It requires a new directory and refuses to
overwrite an existing one.

```text
cargo run -p triblespace-core --no-default-features --example reactive_live -- --init live-demo
cargo run -p triblespace-core --no-default-features --example reactive_live
```

The initializer authors two independent fresh rule templates, `v1.rules` and
`v2.rules`, plus `initial.facts` and `later.facts`. Both templates initially match
names containing `red` and copy those names to descriptions. This is a neutral
label-matching example. Templates contain explicit revision, term, clause and
constraint IDs: the initializer does not clone any published graph.

In the running driver, enter:

```text
load live-demo/v1.rules
load live-demo/initial.facts
select V1 after -
step
show
```

Replace `V1` with the revision ID printed by `load`. `select` prints the new
**reading ID**; keep it as `R1`. `show` prints that reading, its selection and a
query-based demo projection of ordinary `metadata::description` facts. Initially
only `red lantern` appears, although both red and blue input names were loaded.
`load` parses the complete saved document before committing anything; syntax
errors leave the collection unchanged. Loading does not select or execute rules.

Keep the driver running. In another editor, open **the fresh `v2.rules`**, change
`literal ?needle utf8("red");` to `literal ?needle utf8("blue");`, and save it.
Leave the published `v1.rules` unchanged. Then enter:

```text
load live-demo/v2.rules
select V2 after R1
step
show
load live-demo/later.facts
step
show
```

Substitute the second revision ID for `V2`, and the first reading ID for `R1`.
The new revision seeds the already-held inputs, so `blue lantern` now appears.
`red lantern` remains an ordinary consequence of the old revision. Later input
adds `blue comet`, but **not `red comet`**: the retired rule no longer fires.
A semantic edit after a revision has been loaded requires explicitly fresh
revision/changed-node IDs again; reloading changed facts under published IDs
would add alternatives, not replace the old values. There is no automatic edit
or remapping operation here.

`after` always takes **reading IDs, not rule revision IDs**. Selection lists and
predecessor lists are comma-separated; `-` means empty. Save the reading from
the second selection as `R2`. To demonstrate a fork, issue both
`select V1 after R2` and `select V2 after R2`, retaining their printed reading IDs
as `LEFT` and `RIGHT`. `step` refuses this unresolved fork and publishes no new
consequences. Resolve it deliberately with
`select V1 after LEFT,RIGHT`; the next `step` can produce `red comet`. A selection
of `V1,V2` would instead compose both revisions. Nothing picks the last loaded
revision, chooses a winner, or silently merges all known reading heads.

To retire all execution, use `select - after MERGED`, where `MERGED` is the
reading just printed by the explicit resolution. Historical descriptions remain.
`step [BUDGET]` performs one bounded advance (default 16 firings) and publishes
successful facts even when a later evaluation fails. Repeat it for pending work;
the budget bounds firings, not query search time. Publication failure retains
the exact batch; a subsequent `step` retries it before observing new control
facts. `show` observes without executing and refuses observation while publication
is pending. The driver is deliberately an example, not a daemon or an external
effect runner.
