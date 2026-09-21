![Crates.io Version](https://img.shields.io/crates/v/triblespace)
![docs.rs](https://img.shields.io/docsrs/triblespace)
![Discord Shield](https://discordapp.com/api/guilds/795317845181464651/widget.png?style=shield)

![The mascot of trible.space, a cute fluffy trible with three eyes.](sticker.png)

# About

> “We need to abolish names and places, and replace them with hashes.”
> — Joe Armstrong, [The Mess We’re In](https://www.youtube.com/watch?v=lKXe3HUG2l4)

**TribleSpace** is an embedded knowledge graph built from immutable facts,
content-addressed blobs, and grow-only collections. It combines the
queryability of a database with the distribution semantics of a join
semilattice, in one append-only file or an S3-compatible endpoint.

TribleSpace is designed from first principles around simple algebra rather than
mutable database machinery. Independent writers publish signed collection
members; replicas combine evidence by set union; reproducible indexes and
rollups are ordinary merge and derivation equations. No mutable branch head,
compare-and-swap retry loop, or query planner is required.

## Features

- **Scales from memory to cloud**: in-memory datasets, local pile files, and
  S3-compatible blob storage share the same collection and blob traits.
- **Distributed by construction**: collection records and trible sets are
  grow-only sets, so concatenation and set union are the merge operation.
- **Predictable queries**: an optimizer-free constraint solver chooses the next
  variable from runtime specificity and can query several data representations
  in one pattern.
- **Datasets as values**: cheap copy-on-write set operations make entire
  datasets straightforward to diff, merge, and compose.
- **Typed schemas and queries**: attribute encodings drive compile-time type
  inference, validation, and completion.
- **Content-addressed provenance**: descriptors, data archives, metadata, and
  attachments all travel under verifiable handles.
- **Serverless**: a pile is a self-contained append-only store; networking and
  background reconciliation remain optional.

## Getting Started

Add the crate to a project:

```bash
cargo add triblespace ed25519-dalek rand
```

The example below publishes one self-contained `Fragment`, freezes one coherent
store snapshot, and queries an admitted collection cover. `entity!` derives the
author and book identifiers from their contents and carries the quoted string
blob with the facts that reference it.

```rust
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use triblespace::core::collection::{AdmissionPolicy, CollectionPolicy};
use triblespace::prelude::*;

mod literature {
    use triblespace::prelude::*;
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::inlineencodings::{GenId, Handle, ShortString};

    attributes! {
        /// The title of a work.
        "A74AA63539354CDA47F387A4C3A8D54C" as pub title: ShortString;
        /// A quote from a work.
        "6A03BAF6CFB822F04DA164ADAAEB53F6" as pub quote: Handle<UTF8String>;
        /// The author of a work.
        "8F180883F9FD5F787E9E0AF0DF5866B9" as pub author: GenId;
        /// The first name of an author.
        "0DBB530B37B966D137C50B943700EDB2" as pub firstname: ShortString;
        /// The last name of an author.
        "6BAA463FD4EAF45F6A103DB9433E4545" as pub lastname: ShortString;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    storage.commit(library, &key, import)?;

    let snapshot = storage.snapshot()?;
    let facts: TribleSet = library.read(&snapshot)?;
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

    Ok(())
}
```

The descriptor's independent READ and WRITE policies participate in collection
identity. Here both are one-root policies. Whether a recipient may extend its
authority is described by the independent delegation-action facts in the
capability definitions signed into its proof prefix, not by a second
collection-policy threshold. Each child may invoke or delegate only actions
its parent permits delegating; the definition handles may differ.
Other strictly verified signers become visible only when
`library.admitted(&snapshot)` observes sufficient root support for exact
`ACTION_WRITE` on this descriptor handle through resident proof and definition
evidence. Collection WRITE authority has no wall-clock expiry.
Identical retries deduplicate by intrinsic record identity, distinct commits
coexist, and `Collection::read` reconstructs every admitted author's union
through the same snapshot. Call
the store's `flush` operation when an application needs an explicit durability
barrier.

The [Getting Started](https://triblespace.github.io/triblespace-rs/getting-started.html)
chapter breaks the example down, while [Collection
Workflows](https://triblespace.github.io/triblespace-rs/repository-workflows.html)
explains descriptors, exact covers, `COMMIT`/`MERGE`/`DERIVE`, and lazy
derived representations.

## Learn More

The [Tribles Book](https://triblespace.github.io/triblespace-rs/) is the best
place to go deeper:

1. [Introduction](https://triblespace.github.io/triblespace-rs/introduction.html)
2. [Getting Started](https://triblespace.github.io/triblespace-rs/getting-started.html)
3. [Architecture](https://triblespace.github.io/triblespace-rs/architecture.html)
4. [Query Language](https://triblespace.github.io/triblespace-rs/query-language.html)
5. [Incremental Queries](https://triblespace.github.io/triblespace-rs/incremental-queries.html)
6. [Collection Workflows](https://triblespace.github.io/triblespace-rs/repository-workflows.html)
7. [Distributed Sync](https://triblespace.github.io/triblespace-rs/distributed-sync.html)
8. [Pile Format](https://triblespace.github.io/triblespace-rs/pile-format.html)

To build the book locally: `cargo install mdbook && ./scripts/build_book.sh`

For development setup, see [Contributing](book/src/contributing.md).

## Community

Questions or ideas? Join the [Discord](https://discord.gg/v7AezPywZS).

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)

at your option.
