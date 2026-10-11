# Importing Other Data Formats

Import pipelines let you bring external datasets into a TribleSpace collection without
hand-writing encodings or entity identifiers every time. This chapter introduces the
`import` namespace, explains how the JSON importers map foreign fields onto
attributes, and outlines how you can extend the same patterns to new formats.

## Import Namespace Overview

The `triblespace_core::import` module collects conversion helpers that translate
structured documents into raw tribles. Today the namespace ships with two
deterministic JSON importers and an N-Triples (RDF) importer:

- `JsonObjectImporter` hashes sorted and deduplicated
  `NIL || attribute || value` rows using the same protocol as `entity!`, so
  identical fact sets reproduce the same entities. It accepts a top-level JSON
  object (or a top-level array of objects). Construct it with a blob sink (e.g.,
  a collection's underlying store or a `MemoryBlobStore`) and an optional 32-byte namespace
  when independently imported corpora must not share identities. Each `import_*` call
  returns a [`Fragment`](../src/trible/fragment.rs) that exports the root entity
  id(s) and contains the emitted facts.
- `JsonTreeImporter` preserves the full JSON structure and ordering by emitting
  explicit node and entry entities (a JSON AST). It derives content-addressed
  identifiers from the JSON values themselves so identical subtrees deduplicate
  across overlapping imports. Unlike the object importer it can represent
  arbitrary JSON roots, including primitives. Each `import_*` call returns a
  rooted `Fragment` for the imported JSON value.
- `ntriples::ingest_ntriples` (and the file-backed `ingest_ntriples_file`
  wrapper) reads the line-oriented N-Triples serialization of an RDF graph
  and emits one trible per statement. URIs become stable entity ids via the
  [`import::rdf_uri`](../src/import/mod.rs) attribute; predicate URIs become
  attribute ids via `Attribute::<S>::from(entity!{ metadata::iri:, metadata::value_encoding: })`
  — the IRI is the canonical identifier; literal values map into the
  appropriate native `InlineEncoding` based on their XSD datatype.

`JsonObjectImporter` uses a fixed mapping for JSON primitives:

- strings → `Handle<UTF8String>`
- numbers → `F64`
- booleans → `Boolean`

Arrays are treated as multi-valued fields; every element becomes its own trible
under the same attribute identifier. Nested objects recurse automatically,
linking parent to child entities through `GenId` attributes derived from the
containing field name. After one or more imports, call `metadata()` to retrieve
metadata as a `Fragment` exporting the derived attribute ids. The fragment
contains attribute descriptors plus multi-value hints (a `metadata::tag` edge
pointing to `metadata::KIND_MULTI`). Use `clear()` when you need a completely
fresh run (drop the per-field attribute caches and multi-value tracking).

## Mapping JSON Fields to Attributes

Attributes are derived through the entity-core mechanism —
`Attribute::<S>::from(entity!{ metadata::name: <field handle>,
metadata::value_encoding: <S as MetaDescribe>::id() })` — which hashes the
sorted and deduplicated canonical `NIL || attribute || value` rows to produce a
stable attribute id from the JSON field name and its fixed `InlineEncoding`.
The importer caches the
resulting `Attribute<S>` per field so the hash only has to be computed once
per run. Arrays are treated as multi-valued fields: every item is
encoded and stored under the same attribute identifier, producing one trible per
element.

After an import completes the importer regenerates metadata from its cached
attribute map. The `import_*` call returns a `Fragment` exporting the root
entity id(s) for the imported document and containing the emitted facts; call
`metadata()` to retrieve a separate `Fragment` exporting the derived attribute
ids and containing attribute descriptors plus multi-value hints (via
`metadata::tag` pointing to `metadata::KIND_MULTI`). Merge those descriptors
publish those descriptors as metadata alongside the imported facts when you want queries to
discover the original JSON field names or project datasets by encoding without
repeating the derivation logic. Field names are stored as `metadata::name`
handles to
UTF8String blobs so arbitrarily long keys survive roundtrips; `metadata::name`
is a general-purpose entity naming attribute, but importers use it for field
names here. Importers intentionally avoid emitting attribute *usage* annotations;
those are reserved for code-defined attributes so each codebase can attach its
own contextual names and descriptions.

You can import multiple documents by merging fragments:

```rust,ignore
let mut all = Fragment::empty();
all += importer.import_str(doc1)?;
all += importer.import_str(doc2)?;
// all.exports() yields the root ids; all.facts() yields the merged tribles.
```

When exporting back to JSON, pass an immutable blob-store snapshot (for example
from `MemoryBlobStore::snapshot`) to `export_to_json` so `UTF8String` blobs can be inlined. If a
blob is missing or unreadable the exporter returns an error with the handle hash
instead of silently emitting a placeholder, keeping roundtrips lossless when
blobs are present. The exporter uses the same fixed mapping in reverse:
`Handle<UTF8String>` → JSON string (via blob lookup), `Boolean` → JSON bool,
`F64` → JSON number, `GenId` → inlined object (unless already visited). Attributes that use other encodings are ignored
so JSON roundtrips stay predictable even when the dataset mixes in
format-specific extensions.

Nested objects recurse automatically. The parent receives a `GenId` attribute
that points at the child entity, allowing the importer to represent the entire
object graph as a connected set of tribles. Because those `GenId` attributes are
also derived from the parent field names they remain stable even when you import
related documents in separate batches.

## Lossless JSON Import

`JsonTreeImporter` trades the compact attribute/value encoding for a
lossless JSON AST representation. Each JSON value becomes a node tagged with a
kind (`json_tree::kind_*`). Objects and arrays emit explicit entry entities
that store field names and indices (`json_tree::field_*` and
`json_tree::array_*`), preserving ordering and allowing repeated keys.
Numbers are stored as raw decimal strings via `Handle<UTF8String>` so
precision is not lost. Array and field indices are stored as `U256BE` to keep
ordering exact even for large collections.

Because node identifiers are derived from the content of each value, identical
subtrees converge automatically when you import overlapping backups. This makes
lossless imports a good archival layer: you can keep full-fidelity raw JSON and
still layer semantic projections on top.

Each `import_*` call returns a rooted, self-contained `Fragment` containing the
JSON AST facts, every referenced string/number/field-name blob, and the fixed
`json_tree::*` schema in its metafacts. The importer also mirrors content blobs
into the backing store supplied at construction. Merge returned fragments when
you ingest multiple documents; their descriptions and attachments converge
under the same set union. `metadata()` remains available when a caller wants to
inspect the schema directly, but persisting an import does not require a
separate metadata step.

## Importing N-Triples (RDF)

The `import::ntriples` module reads the [N-Triples](https://www.w3.org/TR/n-triples/)
serialization of an RDF graph and emits one trible per statement. The
importer is a pure function of its input: it returns self-contained fragments
whose shared blob stores carry every byte referenced by their facts or
metafacts.

```rust,ignore
use std::io::Cursor;
use triblespace::core::import::ntriples::ingest_ntriples;

let data = br#"
<http://example.org/frank> <http://example.org/firstname> "Frank" .
<http://example.org/frank> <http://example.org/birthyear> "1920"^^<http://www.w3.org/2001/XMLSchema#integer> .
"#;
let import = ingest_ntriples(Cursor::new(&data[..]))?;
assert_eq!(import.triples, 2);

// `facts` is the RDF graph and already carries its predicate vocabulary.
let mut facts = import.facts;
// URI↔id annotations are optional queryable content.
facts += import.uri_map;
# Ok::<(), triblespace::core::import::ntriples::IngestError>(())
```

**URI → entity id.** Every subject and URI-valued object gets a stable
triblespace `Id` derived from its URI via the `import::rdf_uri` attribute:
the URI is stored as a `UTF8String` blob, wrapped in an `entity!` fragment
exporting a single `rdf_uri` edge, and the fragment's content-derived root
id becomes the entity id. The same URI always produces the same id across
processes, so repeated imports over the same data reach the same
TribleSet — even across machines. The `rdf_uri` inverse-mapping edges are
returned separately in `NtImport::uri_map`: merge that fragment into the graph
when `pattern!([{ ?e @ rdf_uri: ?uri }])` should recover source URIs, attach it
as metadata when recovery should not affect content queries, or drop it when
URI recovery is unnecessary.

**Orphan blank nodes.** A blank node that is referenced as an object but has no
outgoing facts cannot use the normal intrinsic-entity derivation: every such
factless node would otherwise collapse to the same empty entity. Instead, the
importer retains a separate, domain-separated skolem protocol over the immutable
source-document content hash and the literal blank-node label. Importing the
same byte-identical document repeatedly therefore reproduces the same ids and
converges under set union. Different labels remain distinct, as do labels in
documents with different serialized content. This is deliberately content
addressing of the N-Triples document, not RDF graph canonicalization: changing
comments or whitespace creates a new document scope.

**Predicate → attribute id.** Predicate URIs become attribute ids through
the entity-core derivation exposed as `Attribute::<S>::iri(predicate)`. Because
attribute ids are hashed together with the chosen `InlineEncoding`, the same
predicate used for two different literal types produces two different
attribute ids — which is what you want: `:birthyear "1920"^^xsd:integer`
and `:birthyear "1920"` (untyped string) shouldn't collide. (JSON field
names use the same shape but with `metadata::name` instead of
`metadata::iri`, so the resulting ids are also distinct from
same-spelled IRIs.)

**Literal → native value.** XSD datatypes map into the appropriate
triblespace inline encodings:

| XSD datatype | triblespace encoding |
|---|---|
| `xsd:integer`, `xsd:long`, `xsd:int`, `xsd:short`, `xsd:byte`, `xsd:negativeInteger`, `xsd:nonPositiveInteger` | `I256BE` |
| `xsd:nonNegativeInteger`, `xsd:positiveInteger`, `xsd:unsignedInt`, `xsd:unsignedLong`, `xsd:unsignedShort`, `xsd:unsignedByte` | `U256BE` |
| `xsd:decimal` | `R256BE` (exact rational) |
| `xsd:float`, `xsd:double` | `F64` |
| `xsd:boolean` | `Boolean` |
| `xsd:string`, untyped, language-tagged | `Handle<UTF8String>` |

Unrecognized datatypes fall back to `Handle<UTF8String>` so no
data is lost — the lexical form ships through verbatim. Numeric parse
failures fall back to the string path too.

**Roundtrips and querying.** Because both ids and attribute ids are
derived, you can query the imported graph without inventing a separate
schema:

```rust,ignore
use triblespace::core::attribute::Attribute;
use triblespace::prelude::inlineencodings::I256BE;

let birthyear = Attribute::<I256BE>::iri("http://example.org/birthyear");
for (entity, year) in find!(
    (entity: Id, year: i128),
    pattern!(&facts, [{ ?entity @ birthyear: ?year }])
) {
    println!("{entity} born in {year}");
}
```

**N-Triples only.** The current importer handles the line-oriented
N-Triples format: one statement per line, URIs in angle brackets,
literals in double quotes with optional `^^<datatype>`, and acyclic blank-node
graphs. Turtle-style prefixes and quad/N-Quads are not supported; cyclic
blank-node graphs are rejected rather than assigned arbitrary identities.

## Managing Entity Identifiers

The importer buffers the encoded facts for each object as complete 64-byte
`NIL || attribute || value` rows, sorts and deduplicates them, hashes their
contiguous bytes with BLAKE3, and takes the final 16 digest bytes as the entity
identifier. It passes those same defining rows through the shared intrinsic
entity builder, ensuring identical fact sets produce identical IDs even across
separate runs. You can supply an optional 32-byte namespace via the constructor;
it prefixes the canonical row stream and deliberately prevents identities from
unifying across namespaces. The returned `Fragment` exports the resulting plain
`Id` root and contains exactly the object's defining rows plus any recursively
imported child-object facts.

This hashing step also changes how repeated structures behave. When a JSON
document contains identical nested objects—common in fixtures such as
`citm_catalog` or Twitter exports—the deterministic importer emits the same
identifier for each recurrence. Only the first copy reaches the underlying
`TribleSet`; later occurrences are recognised as duplicates and skipped during
the merge. Even if the hash itself is fast, that deduplication step reduces
workload on datasets with significant repetition.

## Extending the Importers

To support a new external format, implement a module in the `import` namespace
that follows the same pattern: decode the source data, derive attributes with
`Attribute::<S>::iri(...)` for URI-identified predicates or
`Attribute::<S>::named(...)` for display-name origins such as JSON fields,
encode values using the appropriate `InlineEncoding`, and carry the dynamic
attribute fragments in the result's metafacts. If the format supplies stable
identifiers, mix them into the hashing step or salt so downstream systems can
keep imports idempotent.
