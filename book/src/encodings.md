# Encodings

TribleSpace stores data in strongly typed values and blobs. An *encoding*
describes the language‑agnostic byte layout for these types: [`Inline`]s always
occupy exactly 32&nbsp;bytes while [`Blob`]s may be any length. Encodings translate
those raw bytes to concrete application types and decouple persisted data from a
particular implementation. This separation lets you refactor to new libraries or
frameworks without rewriting what's already stored or coordinating live
migrations. The crate ships with a collection of ready‑made encodings located in
[`triblespace::core::inline::encodings`](https://docs.rs/triblespace/latest/triblespace/core/inline/encodings/index.html) and
[`triblespace::core::blob::encodings`](https://docs.rs/triblespace/latest/triblespace/core/blob/encodings/index.html).

When data crosses the FFI boundary or is consumed by a different language, the
encoding is the contract both sides agree on. Consumers only need to understand
the byte layout and identifier to read the data—they never have to link against
your Rust types. Likewise, the Rust side can evolve its internal
representations—add helper methods, change struct layouts, or introduce new
types—without invalidating existing datasets.

### Why 32 bytes?

Storing arbitrary Rust types requires a portable representation. Instead of
human‑readable identifiers like RDF's URIs, Tribles uses a fixed 32‑byte array
for all values. This size provides enough entropy to embed intrinsic
identifiers—typically cryptographic hashes—when a value references data stored
elsewhere in a blob. Keeping the width constant avoids platform‑specific
encoding concerns and makes it easy to reason about memory usage.

### Conversion traits

Conversion goes through the `Encodes<Source>` trait, which lives **on the
encoding** (the encoding is the impl target; the source is the trait parameter).
This is the same direction as std's `From<T>` — and for the same reason: it
trivially satisfies Rust's orphan rule, so you can write
`impl Encodes<SomeForeignType> for MyLocalEncoding` without any "trait
position 0" gymnastics.

The ergonomic source-side methods `.to_inline()` / `.to_blob()` /
`.into_encoded()` are auto-derived blanket implementations — users never
implement them directly, the same way you never implement `Into<T>` in Rust:

```text
User implements:     Auto-derived via blanket:
  Encodes<T> for S     IntoEncoded<S> for T  (+ IntoInline / IntoBlob aliases)
```

For fallible conversions where the error type is part of the contract (parsing
a hex string into a hash, validating a timestamp range, rejecting reserved
bits), use `TryToInline` / `TryFromInline` — kept as separate traits because the
error type is per‑source.

```rust
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{TryFromInline, TryToInline, Inline};

struct Username(String);

impl TryToInline<ShortString> for Username {
    type Error = &'static str;

    fn try_to_inline(self) -> Result<Inline<ShortString>, Self::Error> {
        if self.0.is_empty() {
            Err("username must not be empty")
        } else {
            self.0
                .as_str()
                .try_to_inline()
                .map_err(|_| "username too long or contains NULs")
        }
    }
}

impl TryFromInline<'_, ShortString> for Username {
    type Error = &'static str;

    fn try_from_inline(value: &Inline<ShortString>) -> Result<Self, Self::Error> {
        String::try_from_inline(value)
            .map(Username)
            .map_err(|_| "invalid utf-8 or too long")
    }
}
```

### Encoding identifiers

Every encoding declares a unique 128‑bit identifier, accessible via the
`MetaDescribe::id` method (for example, `ShortString::id()`).
Persisting these IDs keeps serialized data self describing so other tooling can
make sense of the payload without linking against your Rust types. Dynamic
language bindings (like the Python crate) inspect the stored encoding identifier
to choose the correct decoder, while internal metadata stored inside Trible
Space can use the same IDs to describe which encoding governs a value, blob, or
hash protocol.

Identifiers also make it possible to derive deterministic attribute IDs when you
ingest external formats. Wrap the source field name in an entity-core fragment —
`Attribute::<S>::from(entity!{ metadata::name: <name handle>, metadata::value_encoding: <S as MetaDescribe>::id() })` —
to combine the encoding ID with the source field name and produce a stable
attribute so re-importing the same data always targets the same column.
The `attributes!` macro offers three identity origins. Omitting the literal
derives identity from `(name, encoding)`, which is useful for quick experiments
or source-shaped internal attributes. `"HEX_ANCHOR" as name: Encoding` derives
identity from `(anchor, encoding)`, which is the preferred form for attributes
shared across binaries or languages: the Rust name can change freely, while a
type change truthfully creates a different column. The exceptional
`"HEX_ID" unsafe as name: Encoding` form uses the literal bytes verbatim. It is
for preserving an already-published identity and carries the unchecked
obligation that the encoding still agrees with all rows under that id.

## Built‑in inline encodings

The crate provides the following inline encodings out of the box:
- `GenId` &ndash; an abstract 128 bit identifier.
- `ShortString` &ndash; a UTF-8 string up to 32 bytes.
- `U256BE` / `U256LE` &ndash; 256-bit unsigned integers.
- `I256BE` / `I256LE` &ndash; 256-bit signed integers.
- `R256BE` / `R256LE` &ndash; 256-bit rational numbers.
- `ROrd256` &ndash; exact rationals whose bytes sort in numeric order.
- `F64` &ndash; IEEE-754 double-precision floating point number (little-endian).
- `F256BE` / `F256LE` &ndash; 256-bit floating point numbers.
- `Currency<C>` &ndash; an exact monetary amount in the currency `C`, stored as an
  exact rational (see [Monetary amounts](#monetary-amounts)).
- `Hash` and `Handle` &ndash; cryptographic digests and blob handles (see [`hash.rs`](../src/inline/encodings/hash.rs)).
- `ED25519RComponent`, `ED25519SComponent` and `ED25519PublicKey` &ndash; signature fields and keys.
- `NsTAIInterval` to encode time intervals.
- `Boolean` &ndash; all-zero for false, all-0xFF for true.
- `LineLocation` &ndash; a `(start_line, start_col, end_line, end_col)` span encoded as four big-endian u64 values.
- `RangeU128` &ndash; a half-open `(start, end)` range of two big-endian u128 values.
- `RangeInclusiveU128` &ndash; an inclusive `(start, end)` range of two big-endian u128 values.
- `UnknownInline` as a fallback when no specific encoding is known.

```rust
# use triblespace::prelude::*;
use triblespace::core::metadata::MetaDescribe;
use triblespace::core::inline::encodings::shortstring::ShortString;
use triblespace::core::inline::{IntoInline, InlineEncoding};

let v: Inline<ShortString> = "hi".to_inline();
let raw_bytes = v.raw; // Persist alongside the encoding's metadata id.
let encoding_id = ShortString::id(); // derived via describe(&mut scratch).root()
```

## Built‑in blob encodings

The crate also ships with these blob encodings:

- `UTF8String` for arbitrarily long UTF‑8 strings.
- `RawBytes` for opaque file-backed byte payloads.
- `EntityIdSetBlob` for a grow-only set of opaque entity IDs: strictly sorted,
  unique, nonnil 16-byte IDs with no header or padding; empty is zero bytes.
  `EntityIdSet` retains typed views of a cover's members and performs membership
  and ordered set iteration without serializing a temporary union.
- `SimpleArchive` which stores a raw sequence of tribles.
- `SuccinctArchiveBlob` which stores the portable deterministic Ring/wavelet
  data and EOF metadata for a SuccinctArchive set. It has no native query
  indexes. `SuccinctArchiveBlob::build_from_simple_archive` derives this raw
  member without constructing a query runtime, and
  `SuccinctArchiveBlob::merge` computes its canonical set union.
- `Rank9AcceleratedSuccinctArchiveBlob`, an ABI-qualified Merkle root encoding
  for query-ready SuccinctArchive members. Its first 32 bytes name the exact
  portable `SuccinctArchiveBlob` child; the remaining bytes carry canonical
  native Rank9/select data for that child. Separate encoding and mapping ids
  pin pointer width, byte order, the accelerated-root format, and the builder
  epoch. A change that can alter canonical bytes requires a newly minted id.
  This is a complete source-bound accelerated encoding, not a sidecar. Member
  validation follows the embedded handle and requires the raw child to be
  resident. A cover-aware query view then loads that child through its store snapshot
  and attaches the persisted sections with safe bounds and alignment checks.
  It does not reconstruct the raw archive or prove the Rank9 bits against it;
  those are explicit audit operations. A raw archive uses unaccelerated query
  access unless an accelerated member is requested, rather than constructing
  Rank9 merely because someone opened it. The raw and
  accelerated encodings each own a canonical union. An accelerated join
  publishes only the accelerated result, but requires the matching raw union
  to be resident because its header names that exact child. It may consume an
  already-resident immutable raw dependency, but downstream maintenance never
  creates the raw blob or its `MERGE`; callers maintain each mapping hop
  explicitly with the same foundational `Support`. If the dependency is
  absent, target maintenance retains a finer accelerated cover. Ordinary
  support-equivalent cover resolution may reuse any already-derived or joined
  accelerated cover with the same foundation. Resolution first excludes an
  image whose named raw child is unavailable and falls back to a complete finer
  cover; direct typed-view construction retains the same check defensively.
- `WasmCode` for WebAssembly bytecode stored as a blob.
- `UnknownBlob` for data of unknown type.

`BlobEncoding` says what bytes mean. `CollectionEncoding` is the stronger
contract for formats used as collection members: every member is an ordinary
typed `Blob`, and the encoding owns canonical member validation and one
canonical member-join operation. When one blob hits a deterministic geometry
limit, a multi-member `Cover<E>` retains the same logical value, so every
collection remains a full join-semilattice. "Derived" describes provenance
across a join-preserving mapping, not weaker algebraic capability; covers are
lazy physical decompositions of the same join.
Explicit validation and joining share one immutable store snapshot, so Merkle-shaped
encodings can resolve children named by their members without consulting
ambient mutable state.
The maintained collection encodings implement the same contract directly;
there is no separate public artifact or lattice wrapper to pair with them.

Attaching a maintained index is not an audit of its producer. Ordinary readers
retain typed views of the persisted bytes and perform the framing, bounds and
alignment checks needed for safe access. Canonical ordering checks, count
reproofs and reconstruction comparisons belong to explicit audits. Nor should
a reader serialize and hash a new member just to interpret a multi-member cover.
Query work remains query work: for example, a sparse reference summary needs
its gap stream decoded into query scratch for repeated binary-search probes.
Its `query()` method makes that preparation explicit; attaching the summary
itself only retains the original bytes. No wire-format or collection identity
change is needed to keep these operations separate.

```rust
use triblespace::core::metadata::MetaDescribe;
use triblespace::core::blob::encodings::utf8string::UTF8String;
use triblespace::core::blob::{Blob, BlobEncoding, IntoBlob};

let b: Blob<UTF8String> = "example".to_blob();
let encoding_id = UTF8String::id(); // derived via describe(&mut scratch).root()
```

Both value and blob encodings can emit optional discovery metadata. Calling
`MetaDescribe::describe` returns a rooted `Fragment` (exporting the encoding id)
whose facts tag the encoding entity with `metadata::KIND_INLINE_ENCODING` or
`metadata::KIND_BLOB_ENCODING` and may attach a `metadata::name` and
`metadata::description` (UTF8String handles). Persist the description blobs
alongside the metadata tribles if you want the text to remain readable.

### Grow-only entity-ID sets

`blob::encodings::entity_id_set::encode` sorts and deduplicates authored `Id`
values into the portable `EntityIdSetBlob` format. `join` merges two sorted
members into their canonical union. It checks fixed-width framing while doing
new producer work, without running a second canonical audit of its inputs.
`validate_element` is the explicit linear check for framing, nonnil IDs, strict
ordering, and uniqueness.

Ordinary `TryFromBlob` attachment retains an AnyBytes `View<[[u8; 16]]>` and
checks only that the length contains complete rows. `TryFromCover` retains one
such view per resident member. No read rebuilds, hashes, or copies a physical
set. `contains` binary-searches each member; `iter` merges and deduplicates sorted
member streams lazily. Exact `len` is constant-time for one member, but overlaps
require enumerating the logical union. These operations rely on the canonical
ordering contract; they are not replacement audits. Typed iteration never
constructs an invalid nil Rust `Id` from unaudited bytes.

The IDs are opaque set elements, not blob handles or edges that cause dependency
acquisition. This encoding describes an authored grow-only set, not a derivation
of the entities it names. It differs from a flat typed array, whose order and
duplicates are meaningful, and from `LatestBlob`, whose join also tracks
retired states. Generic root-publication support is separate from this encoding
and its logical-cover view; no `SimpleArchive` reinterpretation is involved.

The encoding ID is `0BF639287590CFC9CE0E2B83D9FBC1E3`, minted with the installed
`trible genid` on 2026-09-15. There is no new pile record kind or mapping ID.

## Choosing the right encoding

When defining an attribute, the encoding determines how the 32-byte value slot is
interpreted. Use this decision tree to pick the right one:

```text
What are you storing?
│
├─ A reference to another entity?
│  └─ GenId
│
├─ A tag, category, or enum-like classifier?
│  └─ metadata::tag (GenId) — tags are entities with their own ID.
│     Use metadata::name to give them a human-readable label.
│     ⚠ Do NOT define a separate ShortString tag attribute —
│     use the canonical metadata::tag and mint tag IDs.
│
├─ A short label or display name?
│  ├─ Fits in 32 bytes (≤32 UTF-8 bytes)?
│  │  └─ ShortString
│  └─ Longer text?
│     └─ Handle<UTF8String>  (blob)
│
├─ Money?
│  └─ Currency<C> — an exact rational, one encoding per
│     currency, in ROrd256's order-preserving layout.
│     No decimal scale anywhere: 1.50 is 3/2, so there is
│     no constant to pick now and regret later, and a VAT
│     rate applies without rounding. Bytes sort numerically,
│     so index ranges work. See "Monetary amounts".
│     ⚠ Never F64/F256: binary floats cannot represent 0.1.
│     ⚠ Not a bare rational: the currency belongs in the
│     encoding, so EUR and USD cannot meet in a query.
│
├─ A number?
│  ├─ Integer
│  │  ├─ Fits in 64 bits? → U256BE (zero-extended) or custom u64 encoding
│  │  └─ Needs full 256 bits? → U256BE / I256BE
│  ├─ Floating point
│  │  ├─ Standard double? → F64
│  │  └─ Extended precision? → F256BE
│  └─ Rational? → R256
│     ⚠ Canonical (reduced) but NOT numerically ordered:
│     comparison hits the numerator first, so 1/1 sorts
│     before 2/3. Use a fixed-scale integer if the index
│     has to answer "greater than x" — or ROrd256 if you
│     need exact division AND numeric range queries.
│
├─ A timestamp or time range?
│  └─ NsTAIInterval
│
├─ A cryptographic value?
│  ├─ Content hash? → Hash<Blake3>
│  ├─ Reference to a blob? → Handle<BlobEncoding>
│  └─ Signature? → ED25519RComponent / ED25519SComponent / ED25519PublicKey
│
├─ A file or binary payload?
│  └─ Handle<RawBytes>  (blob)
│
├─ A large structured dataset?
│  └─ Handle<SimpleArchive>  (blob, stores a TribleSet)
│
└─ Something else?
   ├─ Fits in 32 bytes? → define a custom InlineEncoding
   └─ Larger? → define a custom BlobEncoding + use Handle
```

**Rules of thumb:**
- If two values should be joinable (appear in the same query variable), they must
  share an encoding. Choose the most specific encoding that covers both uses.
- Prefer `ShortString` over `UTF8String` when the text fits — inline values avoid
  a blob lookup.
- Use `GenId` for relationships between entities. Never store entity references as
  strings.
- When in doubt between an inline encoding and a blob, ask: "will I ever want to
  query or join on this directly?" If yes, it should be inline. If it's opaque
  content you just retrieve, use a blob handle.

## Exact rationals: `R256` vs `ROrd256`

Indexes compare the 32 stored bytes, so an index range is only a *value* range
when the encoding's byte order matches its numeric order. `R256` does not have
that property. It stores the numerator in the first 16 bytes and the denominator
in the last 16, so bytewise comparison reads the numerator first and `1/1` sorts
below `2/3` even though `1 > 2/3`. Its big-endian variant gives a stable portable
layout, not a numerically meaningful one.

`ROrd256` is the sibling encoding that does sort numerically, while staying
exact and canonical.

**How.** The Stern–Brocot tree is a binary search tree over the rationals, so
its in-order traversal is numerically sorted and a root path (`L`/`R`) with a
terminator sorting between `L` and `R` compares lexicographically in numeric
order. A raw path is not width-bounded — `1/1000000` is 999999 left branches
deep — but the continued fraction `[a0; a1, a2, …]` is exactly the run-length
encoding of that path, so it carries the identical order in O(log min(p,q))
terms. Comparison of continued fractions alternates (`a0` ascending, `a1`
descending, …), so each term is written in a prefix-free order-preserving code
and bit-complemented at odd positions, which turns the alternation back into
plain lexicographic comparison. A terminated fraction behaves like a `+∞` term
at the next position, so the terminator is a run of the pad value that sorts
above every code — and complementing it at odd positions correctly turns that
`+∞` into `−∞`.

**Canonical.** The Euclidean algorithm never emits the alternative `[…, n-1, 1]`
spelling, so exactly one byte string exists per value and intrinsic ids stay
stable. Bytes that claim a trailing `1` are rejected by `validate`.

**Representable subset.** Encoding costs roughly `2·log2(max(|p|, q))` bits and
fails with a typed `OrderedRatioError::OutOfDomain` rather than rounding:

| input | fits |
|---|---|
| any `p/q` with `max(\|p\|, q) ≤ 2^104` | always (guaranteed) |
| any `i128` integer, any `1/n` | always |
| random 96-bit `p` and `q` | always in practice |
| random 120-bit `p` and `q` | ~99% |
| random 127-bit `p` and `q` | ~26% |

The guaranteed bound is set by long continued fractions of small-but-not-one
terms; the smallest value that does *not* fit needs `max(|p|, q) > 2^104.7`.
Counter-intuitively, Fibonacci ratios — the *longest* continued fractions — are
the cheapest, because a term of `1` costs a single bit, so every Fibonacci ratio
representable in `i128` encodes comfortably.

**Cost.** Ordering is free at query time (it is `memcmp` on bytes the index
already compares); you pay for it on write. Encoding runs a Euclidean expansion
and decoding a continuant recurrence, both O(number of terms):

| | `ROrd256` | `R256BE` | `R256LE` |
|---|---|---|---|
| encode, 64-bit `p/q` | 290 ns | 157 ns | 1.6 ns |
| encode, worst case | 850 ns | 270 ns | 1.6 ns |
| decode, 64-bit `p/q` | 176 ns | 157 ns | 157 ns |

`R256LE`'s encode is two `to_le_bytes` and nothing else, so relative to a raw
two-limb store `ROrd256` is two orders of magnitude slower to encode. Against
`R256BE` — which canonicalizes with a gcd — it is under 2× for typical values,
and decoding is comparable either way because `R256`'s own canonicality check
also runs a gcd. Run `cargo bench -p triblespace-core --bench ordered_rational`
to reproduce.

**Choose `ROrd256`** when you need exactness *and* numeric range queries on the
same column: exact empirical rates `k/n` where the denominator varies, exact
probabilities or thresholds, ratios that arise from division and are then
filtered by magnitude. The alternative — an `R256` column plus a parallel `F64`
sort key — needs two attributes that can drift apart, and its range answers are
inexact at the boundary, because the bound itself (`1/3`, say) is not a float.
`ROrd256` makes the index answer the exact answer.

**Choose `R256`** for everything else. It is simpler, encodes in nanoseconds, and
covers the full `i128 × i128` box rather than a subset of it.

**Choose neither for money.** Amounts have a fixed scale, are not divided at
storage, and already sort numerically as scaled integers. Use `Currency<C>`,
which is exactly that.
## Monetary amounts

Money gets its own encoding family — `Currency<C>`, one encoding per currency —
but the *value* it stores is not a money-specific layout at all. It is an exact
rational in [`ROrd256`](#exact-rationals-r256-vs-rord256)'s encoding.

```rust
use triblespace::core::attribute::Attribute;
use triblespace::core::id::Id;
use triblespace::core::id_hex;
use triblespace::core::inline::TryToInline;
use triblespace::core::inline::encodings::money::{Amount, Currency, Euro, UsDollar};

let price = Amount::<Euro>::from_minor(150).expect("valid scale"); // €1.50, from cents
assert_eq!(price.to_string(), "1.50 EUR");
let value = price.try_to_inline().expect("in domain");

// One anchor, one attribute name, one id per currency.
const TOTAL: Id = id_hex!("251C2B673AE7F49F7374866925D4F7D7");
let eur_total = Attribute::<Currency<Euro>>::anchored(TOTAL);
let usd_total = Attribute::<Currency<UsDollar>>::anchored(TOTAL);
assert_ne!(eur_total.id(), usd_total.id());
```

### A rational, because then there is no scale to get wrong

The obvious encoding for money is a fixed-point integer: pick a scale, count
units of `10⁻ˢᶜᵃˡᵉ`. It works, and it hides a decision. Whatever scale you pick
becomes a constant that every stored value depends on. It has to be right for
every currency and every future use — sub-cent unit prices, an eighteen-decimal
crypto denomination — and it cannot be revised without rewriting every amount
ever written, because the same figure at a different scale is a different byte
string and therefore a different intrinsic ID.

A rational has no such constant. €1.50 is `3/2`. €1.505 is `301/200`. A third of
a euro is `1/3`, which no fixed-point encoding can hold at all. The question "is
18 places enough, or 4, or 36?" simply does not arise, and there is no migration
hiding behind a later answer to it.

Canonical form — the property a content-addressed store actually needs — comes
along for free. Every rational is stored reduced, so one amount has exactly one
byte string, and merge, equality and intrinsic IDs all agree. That is the same
guarantee a fixed global scale was buying, obtained from the number itself
rather than from a convention about it.

It also makes rates exact. Applying 19% VAT to €19.99 gives `37981/10000`
exactly — not `3.79`, not `3.80`, not a float. The intermediate keeps its full
value, so rounding happens once, where the invoice is produced, which is the
only place it belongs.

### …and it still sorts

Using `ROrd256` rather than `R256` is what makes the choice free. `R256` stores
numerator and denominator side by side, so its bytes sort by numerator first and
`1/1` lands below `2/3`; an index range over such a column is not a value range.
`ROrd256` stores the canonical continued fraction in an order-preserving code,
so plain bytewise comparison — which is what the indexes do — *is* numeric
comparison. "Invoices over €10,000" is an index range, and the answer is exact
rather than float-keyed.

Worth being honest about: ordering is not why this design won. At the scale of a
working accounting database a linear filter over a hundred thousand rows is
milliseconds, and index acceleration only begins to matter in the millions. If
`R256` were the only exact rational available, exactness would still be the right
trade and the scan would be fine. `ROrd256` simply means there is no trade.

### What it costs

**Encode time.** A continued-fraction expansion, not a byte copy. Measured on
two-decimal amounts across a ±500,000 EUR range (release build, Apple M-series):

| operation | per value |
|---|---|
| encode | ~480 ns |
| decode | ~82 ns |
| validate | ~86 ns |

A 133,000-record ingest therefore spends about **64 ms** encoding money — far
below the cost of reading those rows out of the database. Comparison, which is
what queries do, is a plain byte compare and costs nothing extra.

**A bounded, data-dependent domain.** Encoding costs roughly
`2·log2(max(|p|, q))` bits, so every `p/q` with `max(|p|, q) ≤ 2^104` is
guaranteed to fit, and wider values are **rejected with a typed
`OrderedRatioError::OutOfDomain`, never rounded silently**. Unlike a fixed-scale
integer, whose limit is a fixed magnitude, this limit depends on the *shape* of
the number — so it deserves a real check rather than a shrug.

The check that matters is on the source column, not on today's values. Revolver,
the accounting database this was built for, stores every monetary field as a
PostgreSQL `bigint` at three decimal places (verified against the schema in the
dump; measured earlier: 316,375 non-zero values across 31 currency columns, none
with a digit below the second decimal). The widest value such a column can hold
is `±(2⁶³−1)` at scale 3, which reduces to a numerator below `2⁶⁰` over a
denominator dividing 100 — against a guarantee that runs to `2¹⁰⁴`. That is
**44 bits of margin**, and it cannot be eroded by new data, only by a schema
change. Decimal money is friendly to this encoding in general: a two-decimal
amount is `p/100` at worst, and the numerator would have to reach 10³¹ before
the guarantee stopped applying.

Ingest code should still surface the error rather than unwrap it.

### The currency is in the encoding, not in the value

`Currency<Euro>` and `Currency<UsDollar>` are different encodings with different
IDs. Since an attribute's identity is derived from `(anchor, value_encoding)`,
one anchored attribute name yields a *different attribute* per currency, with
nothing minted per currency.

The objection — that a value should be self-describing — does not survive
contact with the data model. A trible is (entity, attribute, value); the
attribute is always present when the value is. Putting the currency in the
attribute is exactly as self-describing as putting it in the value, and it buys
three things:

1. **Currency confusion becomes structurally impossible.** You cannot sum EUR
   and USD by accident, because they are not the same attribute and do not meet
   in a query — and in Rust, `Amount<Euro> + Amount<UsDollar>` does not compile.
2. **The value stays a plain number**, which is what lets it be an `ROrd256`
   payload unchanged rather than a money-specific layout with a prefix.
3. **No combinatorial minting.** Adding a currency is a four-line marker type,
   not a new attribute ID per (field × currency).

The cost is real: **a query that spans currencies has to name each one**, with
an `or!` across the per-currency attributes. Summing across currencies without a
conversion rate is meaningless anyway, so making it explicit is a feature — but
it is still something you have to write out.

Declaring a currency is the whole extension mechanism:

```rust
use triblespace::core::inline::encodings::money::{Currency, CurrencyUnit};

pub struct NorwegianKrone;
impl CurrencyUnit for NorwegianKrone {
    const CODE: &'static str = "NOK";
    const MINOR_UNITS: u32 = 2;
}
type Nok = Currency<NorwegianKrone>;
```

The encoding's ID is *derived* from `CODE`, so two codebases that independently
declare NOK land on the same encoding ID and the same attribute IDs, and their
data merges — no registry, no coordination. `MINOR_UNITS` is deliberately an
annotation rather than part of that identity: it is a presentation convention,
and a disagreement about one should leave two claims about one currency rather
than fork it into two currencies whose amounts no longer meet. It is what
`Display` pads *to* and never truncates to: `1.50 EUR`, `5 JPY`, but `1.505 EUR`
when the value has more digits, and `1/3 EUR` when it has no finite decimal at
all.

An **unknown currency** is a compile-time absence, not a runtime error: there is
no `Currency<C>` for a currency nobody declared, so no attribute ID exists to
write it under. Reading a pile written by someone else, the code is recoverable
from the encoding entity's `code` fact rather than from the 32 bytes.

**Ingesting a runtime currency column** means dispatching on the code to pick the
monomorphisation:

```rust,ignore
match currency_code {
    "EUR" => set += entity!{ &doc @ total: Amount::<Euro>::from_minor(cents)?.try_to_inline()? },
    "USD" => set += entity!{ &doc @ total_usd: Amount::<UsDollar>::from_minor(cents)?.try_to_inline()? },
    other => return Err(UnknownCurrency(other.to_owned())),
}
```

### Other things this encoding deliberately is not

- **Not a float, at any width.** Binary floats cannot represent `0.1`; extra
  width only moves the discrepancy.
- **Not an interval.** Money that has been through a currency conversion is
  genuinely bounded rather than exact and deserves `[low, high]`. But an ingested
  figure is exact, and a VAT split or an allocation is now exact too — a rational
  times a rate is still a rational. What is left for an interval is narrow, and
  it belongs in an additive sibling encoding under its own anchor.
- **Not a rounding policy.** A rational can carry `19/300` of a euro exactly, but
  the figure legally owed is the rounded one on the invoice. Which way at the
  half, at which scale, on the line or on the total, is a business decision a
  byte layout has no standing to make. The encoding's job is to keep the
  intermediate exact so that decision happens once, deliberately.
- **No ISO-4217 table.** `CODE` is not checked against the registry. That
  registry is mutable (SSP in 2011, VES in 2018, ZWG in 2024), and a table baked
  into the crate would make the validity of already-stored data depend on which
  version of the library reads it — and would make adding a currency a release
  of this crate rather than four lines in yours.

## Defining new encodings

Custom formats implement [`InlineEncoding`] or [`BlobEncoding`]. A unique identifier
serves as the encoding ID. The example below defines a little-endian `u64`
inline encoding and a simple blob encoding for arbitrary bytes.

```rust,ignore
{{#include ../../examples/custom_schema.rs:custom_schema}}
```

See [`examples/custom_schema.rs`](https://github.com/triblespace/triblespace-rs/blob/main/examples/custom_schema.rs) for the full
source.

### Versioning and evolution

Schemas form part of your persistence contract. When evolving them consider the
following guidelines:

1. **Prefer additive changes.** Introduce a new encoding identifier when breaking
   compatibility. Consumers can continue to read the legacy data while new
   writers use the replacement ID.
2. **Annotate data with migration paths.** Store both the encoding ID and a
   logical version number if the consumer needs to know which rules to apply.
   `UnknownInline`/`UnknownBlob` allow you to safely defer decoding until a newer
   binary is available.
3. **Keep validation centralized.** Place invariants in your encoding
   conversions so migrations cannot accidentally create invalid values.

By keeping encoding identifiers alongside stored values and blobs you can roll out
new representations incrementally: ship readers that understand both IDs, update
your import pipelines, and finally switch writers once everything recognizes the
replacement encoding.

## Inline formatters (WASM)

Binary formats are great for portability and performance, but they can be
painful to inspect if you don’t know the encoding ahead of time. TribleSpace
supports an optional encoding-level formatter mechanism: an inline encoding can point
to a small sandboxed WebAssembly module that turns its raw 32 bytes into a
human-readable string.

The formatter is stored as a blob (`blobencodings::WasmCode`) and referenced from
the encoding identifier entity via the metadata attribute `metadata::value_formatter`.

The built-in runner lives behind the `wasm` feature flag (enabled by default in
the `triblespace` facade crate) and uses `wasmi` with tight limits (fuel, memory
pages, output size). Modules must not import anything and use the following
minimal ABI:

- `memory` (linear memory)
- `format(w0: i64, w1: i64, w2: i64, w3: i64) -> i64`

The `format` arguments are the raw 32 bytes split into 4×8-byte chunks
(little-endian). The return value packs the output pointer and output length:

- Success returns `(output_len << 32) | output_ptr` with `output_ptr != 0`.
- Failure returns `(error_code << 32) | 0` (i.e. `output_ptr == 0`).

The core crate can optionally ship built-in formatters for its built-in value
encodings. Enable the `wasm` feature to have
`MetaDescribe::describe` (which is fallible) attach `metadata::value_formatter` entries for the
standard encodings. This feature requires the `wasm32-unknown-unknown` Rust
target at build time because the bundled formatters are compiled to WebAssembly
via the `#[value_formatter]` proc macro.
