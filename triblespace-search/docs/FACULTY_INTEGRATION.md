# Using triblespace-search from a faculty

This crate is built to be used from the
[faculties](https://github.com/triblespace/faculties)
rust-script ecosystem: small, self-contained scripts with
`rust-script` shebangs that read and write a pile.

The pattern below is the distilled version of what
`cargo run --example compose_bm25_and_pattern` does, rewritten
as a runnable faculty that maintains a BM25 index over wiki
fragments in the caller's pile.

A runnable, self-contained version of the same pattern ships
as `cargo run --example faculty_wiki_search` — it uses a
tempdir pile, seeds a handful of fragments, runs refresh, then
issues a few queries. If the pseudo-code below drifts, that
example is the source of truth.

This chapter deliberately demonstrates the direct native,
rebuild-and-replace API. Collection-native maintenance may instead define a
domain projection into `PortableBM25Blob`, retain exact derivation evidence,
and join its selected cover with `PortableBM25Index::merge`; that is separate
from the `SuccinctBM25Blob` shown below.

## Example: `wiki_search.rs`

```rust,ignore
#!/usr/bin/env -S rust-script
//! Build or refresh a BM25 index over wiki fragments in a pile
//! and answer queries against it. One-shot command:
//!
//!   wiki_search.rs --pile ./self.pile refresh
//!   wiki_search.rs --pile ./self.pile query "quick brown fox"
//!
//! ```cargo
//! [dependencies]
//! triblespace = "0.36"
//! triblespace-search = "0.0"
//! clap = { version = "4", features = ["derive"] }
//! ```

use clap::Parser;
use std::path::PathBuf;

use triblespace::core::and;
use triblespace::core::find;
use triblespace::core::id::Id;
use triblespace::core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use triblespace::macros::pattern;

use triblespace_search::bm25::BM25Builder;
use triblespace_search::succinct::{SuccinctBM25Blob, SuccinctBM25Index};
use triblespace_search::tokens::hash_tokens;

// Assume a `wiki` namespace is already in the pile, providing:
//   wiki::title:   Handle<UTF8String>    (fragment title)
//   wiki::body:    Handle<UTF8String>    (typst body)
//   wiki::index:   Handle<SuccinctBM25Blob>  (current-index handle)
mod wiki { /* ... */ }

#[derive(Parser)]
enum Cmd {
    /// Rebuild the BM25 index from current fragments and replace
    /// the handle stored under `wiki::index`.
    Refresh,
    /// Query the current index and print matching fragments.
    Query { text: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open the pile. (Code that differs only in pile-open
    // plumbing is left as stubs; see other faculties for the
    // real invocation.)
    let (mut pile, kb) = open_pile_and_kb()?;

    match Cmd::parse() {
        Cmd::Refresh => {
            // Walk every (fragment_id, body) pair. No shadow
            // datamodel — the pile is the source of truth.
            //
            // `BM25Builder::new()` gives the default
            // `BM25Builder<GenId, WordHash>` — entity-id doc
            // keys, Blake3-hashed text tokens. Pass `&id` and the
            // `ToEncoded<GenId>` impl handles the conversion;
            // `hash_tokens` returns `Vec<Inline<WordHash>>` so
            // terms are typed end-to-end.
            let mut builder = BM25Builder::new();
            for (id, body) in find!(
                (id: Id, body: String),
                pattern!(&kb, [{ ?id @ wiki::body: ?body }])
            ) {
                builder.insert(&id, hash_tokens(&body));
            }
            // `.build()` goes direct to succinct — no separate
            // naive intermediate.
            let idx = builder.build();
            let handle = pile.put::<SuccinctBM25Blob, _>(&idx)?;
            // Persist the handle as a typed ordinary trible under a
            // well-known anchor id (see below), or derive it through an
            // explicit derived-collection mapping.
            persist_index_handle(&mut pile, handle)?;
        }
        Cmd::Query { text } => {
            let handle = load_current_index_handle(&kb)?;
            let snapshot = pile.snapshot()?;
            // The type annotation on the get line picks the
            // D=GenId, T=WordHash defaults; an index built with
            // different schemas would spell them here too (e.g.
            // `SuccinctBM25Index<Handle<UTF8String>, WordHash>`).
            let idx: SuccinctBM25Index =
                snapshot.get::<SuccinctBM25Index, SuccinctBM25Blob>(handle)?;
            // One engine pass: `matches_text` tokenises the query
            // internally (whitespace + lowercase + Blake3 via
            // `hash_tokens`) and binds `doc` to docs that match at
            // all (score_floor = 0.0). The pattern joins on the
            // shared ?doc to pull the title back out of the KB at
            // the same time. We rescore each survivor via
            // `idx.score_text` afterwards for ranking — same
            // pattern as HNSW's similar_to/recompute split.
            use triblespace_core::inline::ToEncoded;
            let mut rows: Vec<(Id, f32, String)> = find!(
                (doc: Id, title: String),
                and!(
                    idx.matches_text(doc, &text, 0.0),
                    pattern!(&kb, [{ ?doc @ wiki::title: ?title }])
                )
            )
            .map(|(d, t)| (d, idx.score_text(&d.to_inline(), &text), t))
            .collect();
            rows.sort_unstable_by(|left, right| {
                right
                    .1
                    .total_cmp(&left.1)
                    .then_with(|| left.0.cmp(&right.0))
            });
            for (id, score, title) in rows.into_iter().take(10) {
                println!("{score:6.2}  {id}  {title}");
            }
        }
    }
    Ok(())
}
```

## Choosing schemas

`BM25Builder<D, T>` / `SuccinctBM25Index<D, T>` is generic over
the doc-key schema `D` and the term schema `T`. Defaults are
`<GenId, WordHash>` — what the skeleton above uses. Other
shapes are explicit:

| Use case | Type |
|---|---|
| Body-text search (the example) | `BM25Builder<GenId, WordHash>` |
| Title-keyed search | `BM25Builder<Handle<UTF8String>, WordHash>` |
| Phrase search (bigram terms) | `BM25Builder<GenId, BigramHash>` |
| Prefix / fuzzy (n-gram terms) | `BM25Builder<GenId, NgramHash>` |
| Entity co-occurrence ("which docs cite X?") | `BM25Builder<GenId, GenId>` |

Each tokenizer outputs a distinct term schema —
`hash_tokens` → `WordHash`, `bigram_tokens` → `BigramHash`,
`ngram_tokens` → `NgramHash` — so the compiler refuses to feed
the wrong flavour into the wrong index. Indexes that need
multiple tokenizer flavours become multiple indexes joined
via the query engine (`and!` / `or!`); see
`examples/phrase_search.rs` for the two-index pattern.

## Pattern: rebuild and publish, no mutation

triblespace-search indexes are content-addressed and immutable
by design. The `Refresh` command:

1. Reads every fragment from the pile (never pre-materializes
   into a separate store — see the "No shadow datamodels" rule
   in CLAUDE.md).
2. Builds a fresh `SuccinctBM25Index`.
3. `put`s the blob — the returned handle is the index's hash.
4. Publishes the typed handle as an ordinary trible, or records the derivation
   through an explicit derived-collection mapping.

If nothing changed between refreshes, step 3 returns the same
handle because content-addressing: the pile's blob-dedup layer
stores it once. That's free caching.

## Pattern: query-time composition with `find!`

The BM25 constraint plugs into the same `find!` / `and!` /
`pattern!` engine as everything else. On a `WordHash`-keyed index
the tokenisation can collapse into the constraint via
`matches_text`:

```rust,ignore
let docs: Vec<(Id,)> = find!(
    (doc: Id),
    and!(
        idx.matches_text(doc, "typst", 0.0),
        pattern!(&kb, [{ ?doc @ wiki::tag: &some_tag }])
    )
).collect();
```

For other tokenisers (`bigram_tokens`, `ngram_tokens`,
`code_tokens`) or for hand-built term slices, the explicit form
`idx.matches(doc, &terms, 0.0)` accepts any
`&[Inline<T>]` matching the index's term schema.

This is the "find docs with `typst` in the body AND tagged X"
query, running through a single engine pass. The engine picks
the cheaper side to iterate (`estimate()`) — either the BM25
filter set for `typst` or the tag index — and confirms with the
other.

See `examples/compose_bm25_and_pattern.rs` and
`examples/compose_hnsw_and_pattern.rs` for the full runnable
versions with a concrete KB.

## Pattern: rank by post-collect `score`, not by bound variable

Score is **never** a bound query variable. The constraint
filters on a fixed `score_floor` parameter; callers recompute
exact scores afterwards via `idx.score(&doc.to_inline(), terms)`
(or `idx.score_text(&doc.to_inline(), text)` on a `WordHash`-keyed
index, which tokenises internally). Same pattern as HNSW's
`similar_to`/recompute-cosine split:

```rust,ignore
use triblespace_core::inline::ToEncoded;
let mut ranked: Vec<(Id, f32)> = find!(
    (doc: Id),
    idx.matches_text(doc, "typst links", 0.0)
)
.map(|(d,)| (d, idx.score_text(&d.to_inline(), "typst links")))
.collect();
ranked.sort_unstable_by(|left, right| {
    right
        .1
        .total_cmp(&left.1)
        .then_with(|| left.0.cmp(&right.0))
});
```

Two reasons. First: exact term frequencies stay inside the index and BM25
scores are derived there; the engine sees docs only. Second: one less variable
per BM25 clause in the planner, with no Cartesian-blowup dedupe needed.

If you want to filter by relevance (not just presence), pass a
non-zero floor: `idx.matches_text(doc, "typst links", 1.5)`. The
engine proposes only docs whose summed BM25 ≥ 1.5.

For perf-sensitive paths where the same query string is reused
many times, hoist the tokenisation by hand:
`let tokens = hash_tokens("…");` then call the explicit-terms
methods `idx.matches(doc, &tokens, …)` and
`idx.score(&doc, &tokens)`. The text-sugar versions re-tokenise
on every call.

## Open questions for faculty authors

- **Where does the handle live?** Direct callers may publish a typed handle as
  an ordinary trible. Maintained projections should use a derived collection so
  source authority, exact-cover evidence, and artifact lifetime remain explicit
  rather than ambient branch-head state.

- **How big does the index get?** The exact-TF layout is
  corpus-dependent: posting frequency width follows the largest term
  frequency. Run `cargo run --release --example blob_sizes_at_scale` on a
  representative corpus instead of relying on the retired score-layout
  estimate.

- **When to embed?** BM25 is the default for text search. Layer
  in HNSW (`SuccinctHNSWIndex`) only once the caller has an
  embedding schema they're willing to commit to — the
  embeddings are the caller's data, not this crate's.

## Schema-rotation migrations

`triblespace-search` identifies each blob format by a
`BlobEncoding`'s schema id (the hex literal inlined in its
`MetaDescribe::describe` body). A breaking byte-layout change
rotates that ID. Understanding what that *doesn't* do is
important:

### The schema id is metadata, not a runtime type guard

`SuccinctBM25Blob::id()` is used by the describe/introspection
machinery and by derived-id schemas like `Handle<H, T>` (whose
id falls out of `entity!{ blob_encoding: T::id(), hash_schema:
H::id() }.root()`). It is **not** checked by `try_from_blob` —
that dispatches on the Rust type parameter. After an ID
rotation:

- `SuccinctBM25Blob` is the same Rust type with the same
  `TryFromBlob` impl.
- `Blob<SuccinctBM25Blob>` is the same Rust type.
- Bytes in the pile under an old handle are the same bytes.
- `snapshot.get::<SuccinctBM25Index, SuccinctBM25Blob>(h)`
  returns those bytes and happily tries to parse them. If
  the old-format and new-format byte layouts happen to
  alias cleanly, you'll decode wrong values with no error.
  If they don't, you'll get a `TruncatedSection` —
  eventually, at runtime, not at compile time.

So the rotation **doesn't enforce anything on its own.** It's
a signal that old bytes and new code aren't compatible — the
caller has to act on that signal by rotating the identity
that the pile *does* use for dispatch.

### What the caller has to rotate

If you have an attribute whose value type references one of
our blob encodings — e.g.

```rust
struct WikiBm25Handle;
impl MetaDescribe for WikiBm25Handle {
    fn describe() -> Fragment {
        let id: Id = id_hex!("…");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "wiki_bm25_handle",
            metadata::tag:  metadata::KIND_INLINE_ENCODING,
        }
    }
}
// value type: Handle<SuccinctBM25Blob>
```

the attribute's schema id is your stable contract for
"triples under this attribute hold *this* kind of value."
When we rotate `SuccinctBM25Blob::id()`, the Rust type the
attribute's value resolves to has changed underneath, but
the attribute's own ID hasn't — so old triples are still
under the same attribute, silently pointing at blobs whose
bytes no longer match what the code thinks they are.

Migration recipe:

1. `trible genid` → new attribute id, e.g. `wiki::bm25-v2`.
2. Rebuild the index against the new schema, `put` the
   blob, write the handle under the new attribute.
3. Transition readers to the new attribute. The old
   attribute + its stored triples become inert (any binary
   using them would have to keep the old crate version
   pinned anyway, because the old blob encoding doesn't
   survive the rotation).
4. Once no reader references the old attribute, `pile keep`
   sweeps the orphaned blobs at the next consolidation.

Attributes whose value type is a plain `Handle<UTF8String>`,
`GenId`, etc. (anything not parameterized on a
crate-owned `BlobEncoding`) are unaffected by our schema
rotations — only handles to *our* blob types transitively
depend on our IDs.
