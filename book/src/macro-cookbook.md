# Macro Cookbook

This chapter is a quick map of the macro surface. The goal is not to replace
the deeper chapters, but to make the everyday question easy:

> "I know roughly what I want to do. Which macro should I reach for?"

The macros fall into three layers:

- **Encoding definition**: `attributes!`
- **Fact construction**: `entity!`
- **Query construction**: `find!`, `exists!`, `pattern!`, `pattern_changes!`,
  `and!`, `or!`, `temp!`

## Define attributes with `attributes!`

Use [`attributes!`](triblespace::core::macros::attributes) to declare typed attributes once,
then reuse them everywhere else.

```rust
use triblespace::prelude::*;

mod social {
    use triblespace::prelude::*;
    use triblespace::prelude::inlineencodings::{GenId, Handle};

    attributes! {
        /// A person's display name.
        "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;

        /// Another person this person knows.
        pub friend: GenId;
    }
}

assert_ne!(social::name.id(), social::friend.id());
```

The three declaration forms differ in what determines identity:

- `"HEX_ANCHOR" as name: Encoding` derives the id from the stable anchor and
  encoding. This is the safe default for shared schemas: renaming the Rust
  binding is free, while changing the encoding creates a different attribute.
- `name: Encoding` derives the id from the name and encoding. It is convenient
  when the source name itself is the shared identifier.
- `"HEX_ID" unsafe as name: Encoding` uses the literal id without incorporating
  the encoding. Reserve it for compatibility with an already-published id; the
  caller must ensure the type still matches the stored rows.

Reach for this macro when:

- you are defining a namespace or encoding module
- you want attributes with stable ids and inline encodings
- you want doc comments to become attribute metadata

If you already have attributes, you usually do not need `attributes!` in the
rest of the code you are writing.

## Build facts with `entity!`

Use [`entity!`](triblespace::core::macros::entity) when you want to create tribles for one
entity.

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::Handle;
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#     }
# }
let alice = fucid();
let facts = entity! { &alice @
    social::name: "Alice",
};

assert_eq!(facts.root(), Some(alice.id));
assert_eq!(facts.len(), 1);
```

If you omit the entity id, `entity!` derives one deterministically from the
facts. It encodes each fact as a 64-byte `NIL || attribute || value` row,
sorts and deduplicates the rows, hashes their complete contiguous byte
sequence with BLAKE3, and uses the final 16 digest bytes as the entity id.
It then fills that id into every row before constructing the `TribleSet`.
Field order and duplicate repeated values therefore do not affect identity;
an absent optional field contributes no row.

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::Handle;
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#     }
# }
let facts = entity! { _
    @ social::name: "Alice"
};

assert!(facts.root().is_some());
assert_eq!(facts.len(), 1);
```

The macro also supports optional and repeated fields:

```rust,ignore
let aliases = ["Al", "A."];
let maybe_nickname = Some("Ace");

let facts = entity! { &alice @
    social::name: "Alice",
    social::nickname?: maybe_nickname,
    social::alias*: aliases,
};
```

Reach for this macro when:

- you are constructing new data
- you want optional/repeated attribute ergonomics
- you want a deterministic derived id for a value object

## Match facts with `pattern!`

Use [`pattern!`](triblespace::core::macros::pattern) to turn trible-shaped structure into a
query constraint.

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::{GenId, Handle};
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#         "B74AA63539354CDA47F387A4C3A8D54C" as pub friend: GenId;
#     }
# }
# let mut kb = TribleSet::new();
# let alice = fucid();
# let bob = fucid();
# kb += entity! { &alice @ social::friend: &bob };
# kb += entity! { &bob @ social::name: "Bob" };
let results: Vec<Id> = find!(
    friend: Id,
    pattern!(&kb, [
        { alice.id @ social::friend: ?friend },
        { ?friend @ social::name: "Bob" }
    ])
).collect();

assert_eq!(results, vec![bob.id]);
```

Inside a pattern:

- `?name` refers to a query variable from the surrounding query
- `_?name` introduces a local helper variable scoped to that pattern
- literal expressions become equality constraints automatically

Use `pattern!` when you are querying the current contents of a `TribleSet`,
`Checkout`, or another pattern-capable source.

## Query for results with `find!`

Use [`find!`](triblespace::core::macros::find) when you want rows back.

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::Handle;
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#     }
# }
# let mut kb = TribleSet::new();
# let alice = fucid();
# kb += entity! { &alice @ social::name: "Alice" };
let names: Vec<Inline<_>> = find!(
    name: Inline<_>,
    pattern!(&kb, [{ _?person @ social::name: ?name }])
).collect();

// A text value is the content handle of its blob: compare it with the
// handle of a string, or read the text from the blob store that holds it.
assert_eq!(names[0], "Alice".to_inline());
```

There are three common shapes:

- `find!(value, constraint)` for one projected variable as a bare value
- `find!((a, b), constraint)` for tuples
- `find!((), constraint)` when you want to count satisfying assignments
  without projecting any of them (reach for `exists!` if you only need yes/no)

`find!` heads have BAG semantics: one row per complete binding, with the head
selecting which variables come back. Hidden variables introduced by `temp!` or
`_?name` still multiply the result — an entity proved by eight witnesses is
emitted eight times, and the empty head returns one `()` per satisfying
assignment. Deduplicate on your side (`collect::<HashSet<_>>()`), or use
`exists!` for the inner condition so the fan-out is never enumerated.

Typed projections happen in the head:

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::Handle;
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#     }
# }
# let mut kb = TribleSet::new();
# let alice = fucid();
# kb += entity! { &alice @ social::name: "Alice" };
let ids: Vec<_> = find!(
    person: Id,
    pattern!(&kb, [{ ?person @ social::name: "Alice" }])
).collect();

assert_eq!(ids, vec![alice.id]);
```

Use `?` on a projected variable when you want conversion failures as
`Result<T, E>` instead of dropping the row.

## Ask existence questions with `exists!`

Use [`exists!`](triblespace::core::prelude::exists) when you only need yes/no.

```rust
# use triblespace::prelude::*;
# mod social {
#     use triblespace::prelude::*;
#     use triblespace::prelude::inlineencodings::Handle;
#     attributes! {
#         "A74AA63539354CDA47F387A4C3A8D54C" as pub name: Handle<blobencodings::UTF8String>;
#     }
# }
# let mut kb = TribleSet::new();
# let bob = fucid();
# kb += entity! { &bob @ social::name: "Bob" };
let has_bob = exists!(
    pattern!(&kb, [{ _?person @ social::name: "Bob" }])
);

assert!(has_bob);
```

You can also keep the typed-head form when the projection itself matters to the
check:

```rust,ignore
let has_name = exists!(
    (name: Inline<_>),
    pattern!(&kb, [{ ?person @ social::name: ?name }])
);
```

Use `exists!(constraint)` for pure existence checks instead of
`find!((), constraint).next().is_some()`.

## Match only new results with `pattern_changes!`

Use [`pattern_changes!`](triblespace::core::macros::pattern_changes) for incremental
queries: matches are allowed to join against the full current state, but at
least one contributing trible must come from the change set.

```rust,ignore
for (work,) in find!(
    (work: Inline<_>),
    pattern_changes!(&full, &delta, [
        { ?work @ literature::author: &shakespeare }
    ])
) {
    // process only newly introduced matches
}
```

Reach for this macro when:

- you already have `full` and `delta`
- you want monotonic incremental processing
- `pattern!` would re-emit old matches every time

See [Incremental Queries](incremental-queries.md) for the full workflow.

## Combine constraints with `and!` and `or!`

Use [`and!`](triblespace::core::prelude::and) when every clause must hold:

```rust,ignore
find!(
    (friend: Inline<_>),
    and!(
        pattern!(&kb, [{ ?person @ social::name: "Alice" }]),
        pattern!(&kb, [{ ?person @ social::friend: ?friend }])
    )
)
```

Use [`or!`](triblespace::core::prelude::or) when any branch may hold:

```rust,ignore
find!(
    (alias: Inline<_>),
    or!(
        pattern!(&kb, [{ ?person @ social::nickname: ?alias }]),
        pattern!(&kb, [{ ?person @ social::name: ?alias }])
    )
)
```

`or!` branches must mention the same variable set.

## Introduce helpers with `temp!`

Use [`temp!`](triblespace::core::prelude::temp) when you need a fresh variable only inside a
sub-expression.

```rust,ignore
find!(
    (person: Inline<_>),
    temp!((friend), and!(
        pattern!(&kb, [{ ?person @ social::friend: ?friend }]),
        pattern!(&kb, [{ ?friend @ social::name: "Bob" }])
    ))
)
```

This is useful when the helper participates in joins but should not be
projected. When the helper lives entirely within a single `pattern!`, prefer a
`_?var` placeholder: it enforces equality across its occurrences inside that
pattern without being projected.

## Which macro should I use?

If you are:

- defining encodings: use `attributes!`
- building facts for one entity: use `entity!`
- matching trible structure: use `pattern!`
- matching only newly added results: use `pattern_changes!`
- asking for rows back: use `find!`
- asking for a boolean: use `exists!`
- requiring all clauses: use `and!`
- allowing alternatives: use `or!`
- introducing a fresh helper variable: use `temp!` (or `_?var` inside a
  single `pattern!`)

From here, the best next stops are:

- [Query Language](query-language.md) for the execution model
- [Patterns & Recipes](patterns-and-recipes.md) for modeling patterns
- [Incremental Queries](incremental-queries.md) for `pattern_changes!`
