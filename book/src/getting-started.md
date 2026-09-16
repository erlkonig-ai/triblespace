# Getting Started

This chapter publishes and queries a small native collection. It assumes Rust
is installed and you are comfortable running `cargo` commands.

## 1. Add dependencies

```bash
cargo new tribles-demo
cd tribles-demo
cargo add triblespace ed25519-dalek rand
```

`triblespace` supplies the data model, stores, collection operations, and query
macros. `ed25519-dalek` and `rand` create the publishing identity used in this
example.

## 2. Declare attributes

Attributes carry the encoding of their value. Shared attributes should use a
stable explicit anchor; the encoding participates in the resulting identity.
Omit the anchor only for local prototypes whose identity may follow their name.

```rust,ignore
mod literature {
    use triblespace::prelude::*;
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::inlineencodings::{GenId, Handle, ShortString};

    attributes! {
        "A74AA63539354CDA47F387A4C3A8D54C" as pub title: ShortString;
        "6A03BAF6CFB822F04DA164ADAAEB53F6" as pub quote: Handle<UTF8String>;
        "8F180883F9FD5F787E9E0AF0DF5866B9" as pub author: GenId;
        "0DBB530B37B966D137C50B943700EDB2" as pub firstname: ShortString;
        "6BAA463FD4EAF45F6A103DB9433E4545" as pub lastname: ShortString;
        "D2D1B857AC92CEAA45C0737147CA417E" as pub alias: ShortString;
    }
}
```

Use `trible genid` when minting a new published anchor. The literal-pinning
`"HEX_ID" unsafe as ...` spelling is only for preserving an already-published
attribute's exact historical bytes when its old identity cannot be re-derived.

## 3. Register a collection

A root collection is identified by the content handle of its descriptor. The
descriptor carries its UTF-8 name, member encoding, and independent READ and
WRITE admission policies. The encoding itself owns member validation and
defines one canonical member-join operation; a root needs no mapping. The descriptor
is an ordinary self-contained `Fragment`, but applications ask the store to
construct and register it rather than assembling its facts manually. Its
canonical content handle is the collection identity:

```rust,ignore
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use triblespace::core::collection::{AdmissionPolicy, CollectionPolicy};
use triblespace::prelude::*;

let key = SigningKey::generate(&mut OsRng);
let mut storage = MemoryRepo::default();
let root = key.verifying_key();
let library = storage.collection(
    "library",
    CollectionPolicy::new(
        AdmissionPolicy::direct(root),
        AdmissionPolicy::direct(root),
    ),
)?;
```

Each policy is either `Open` or a canonical threshold over capability roots.
`AdmissionPolicy::direct(root)` records one such root. Each signed proof edge
then says whether its recipient may invoke, delegate, or do both. The two
policies are deliberately
independent: a collection can have many writers but few readers, or public
READ with tightly held WRITE. Both policies participate in the descriptor
handle, so there is no ambient team scope or separate reach flag.

Local publication is unconditional: any process may append a structurally
valid self-signed commit to its own store. Reading applies the descriptor's
WRITE policy. Commits by a policy root are admitted directly; other authors
become visible only when the same store snapshot contains enough valid proof
paths for exact `ACTION_WRITE` on this descriptor. Invalid resident evidence
grants nothing.

## 4. Build a self-contained fragment

With no explicit subject prefix, `entity!` derives the entity ID from the
canonical set of emitted fields. `Fragment::root()` returns that exported ID,
which can be referenced by another entity. Long strings become blobs and remain
attached to the fragment automatically.

```rust,ignore
let author = entity! {
    literature::firstname: "Frank",
    literature::lastname: "Herbert",
};
let author_id = author.root().expect("intrinsic author id");

let book = entity! {
    literature::title: "Dune",
    literature::author: &author_id,
    literature::quote: "I must not fear. Fear is the mind-killer.",
};

let mut import = author;
import += book;
```

A fragment has four coordinated channels: facts, descriptive metafacts,
exported IDs, and one shared attachment store. `+=` unions all four, so no
parallel manifest or manual blob-staging step is needed.

## 5. Publish independent commits

```rust,ignore
let first = storage.commit(library, &key, import)?;

// A later fact about the same entity is another independent member.
let second = storage.commit(library, &key, entity! {
    &author_id @ literature::alias: "Francis",
})?;

assert_ne!(first, second);
```

Publication loads and structurally validates the registered descriptor, then writes fragment
attachments, data, and metadata before inserting the signed `COMMIT` record.
It performs no permission check and no implicit flush. The commit is the atomic
assertion. There is no mutable head to advance: both records remain members and
the collection value is their union.

Repeating byte-identical input produces the same exact canonical commit and is
idempotent. Distinct input produces another coexisting member. Application-level
supersession or versioning is represented in the facts when a domain needs it;
append order is never an implicit winner.

## 6. Read one coherent snapshot

```rust,ignore
let snapshot = storage.snapshot()?;
let admitted = library.admitted(&snapshot)?;
let available = admitted.available(&snapshot)?;
let missing = admitted.difference(&available)?;
assert!(missing.is_empty());
let facts = admitted.materialize::<TribleSet, _>(&snapshot)?;
let title = "Dune";

for (first, last, quote) in find!(
    (first: String, last: String, quote),
    pattern!(&facts, [
        { _?author @
            literature::firstname: ?first,
            literature::lastname: ?last
        },
        { _?book @
            literature::title: title,
            literature::author: _?author,
            literature::quote: ?quote
        }
    ])
) {
    let quote: View<str> = snapshot.get(quote)?;
    println!("'{}'\n - from {title} by {first} {last}.", quote.as_ref());
}
```

`storage.snapshot()` freezes blobs, collection records, capability proofs, and
backend state at one coherent known prefix. `library.admitted(&snapshot)` then
applies the descriptor's WRITE policy in that same observation and returns the
exact semantic payload cover. `available` returns the greatest subset of those
same semantic members which has a complete resident realization, so equality
with `admitted` means the full value is local and `difference` names missing
semantic support. `materialize` privately selects a support-equivalent physical
decomposition and constructs the logical value through the same immutable
snapshot. `library.read(&snapshot)` concisely reads the maximal resident
collection view at that same frozen prefix. Snapshots carry no clock: later
proof or content arrivals require a new observation, while an application
evaluates its own time-sensitive rules at an explicit instant.

Provenance for an exact cover is available through `cover.commits(&snapshot)`.
These are strictly verified attestations over its payloads, not necessarily
the authorized claims which admitted them.
Duplicate signed claims for one payload collapse to one cover member; authors,
signatures, and metadata remain provenance rather than payload identity.

## 7. Choose durability explicitly

`store.commit` performs no implicit flush. For a memory store that makes
no difference. For a pile or remote backend, choose the durability boundary
that matches the application:

```rust,ignore
storage.commit(library, &key, batch_a)?;
storage.commit(library, &key, batch_b)?;
storage.flush()?;
```

Amortizing one flush over several commits does not weaken their logical
identity or change merge semantics. Flushing and closing remain operations of
the chosen backend rather than collection policy.

## What to remember

- `entity!` builds intrinsic entities and carries required blobs.
- `Fragment` is the self-contained publication value.
- `Collection<E>` is a descriptor handle statically bound to the
  `CollectionEncoding` which owns its member bytes, validation, and canonical
  physical join operation; the store owns all I/O.
- `store.commit` publishes one signed, independent member without conflating
  local storage with network authorization.
- `store.snapshot` freezes one coherent known-prefix store observation;
  collection admission and materialization are pure reads over it.
- Replicas converge by unioning records; they never elect a branch head.
- Derived indexes are reproducible collection images, not alternate authority.

Continue with [Collection Workflows](repository-workflows.md) for the native
record algebra, exact covers, migration from legacy piles, and derived
collection maintenance.
