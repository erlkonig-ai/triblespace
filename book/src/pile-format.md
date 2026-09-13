# Pile Format

The on-disk pile keeps blobs, native collection records, native capability
proofs, wants, and decodable legacy pin evidence in one
append-only file. The write-ahead log *is*
the database: all indices are
reconstructed from the bytes already stored on disk. This design avoids
background compaction, manifest management, or auxiliary metadata while still
providing a durable content-addressed store for local collections. The pile
file is memory mapped for fast, zero-copy reads and can be safely shared
between threads because existing bytes are never mutated—once data is
validated it remains stable.

While large databases often avoid `mmap` due to pitfalls with partial writes and
page cache thrashing [[1](https://db.cs.cmu.edu/mmap-cidr2022/)], the pile's
narrow usage pattern keeps these failure modes manageable. Appends happen
sequentially and validation walks new bytes before readers observe them, so the
memory map never exposes half-written records.

## Record model: one frame, 256-byte-aligned records

Every record the pile writes begins with the same **64-byte common prefix** and
occupies a **256-byte multiple**. Most fixed records fit in one block; signed
MERGE uses two. Blobs and variable capability proofs also continue after the
first block and are zero-padded to their declared span:

| Offset | Width | Field |
|---:|---:|---|
| `0..28` | 28 | Framing magic `0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B` |
| `28..32` | 4 | Total record span in 256-byte blocks, unsigned little-endian |
| `32..64` | 32 | Record kind: the handle of a description of this record's layout |
| `64..256` | 192 | First kind-specific body block; longer records continue after it |

The magic was minted on 2026-08-20 as two `trible genid` calls,
`0371B249F0626B2ABDDB80E23EA96905` and `9D9656A5EA5A497320351F3BE712CF82`,
concatenated and truncated to 28 bytes. Those widths are chosen so the body
starts at byte 64, and two things follow from that.

**Fixed-record fields and blob payloads align.** A 32-byte digest, handle, or
signature component in a fixed record begins at a multiple of 32 — and because
records themselves begin on 256-byte boundaries, the alignment holds at
absolute file offsets, not merely within the record. The predecessor framing
put a 36-byte prefix in front of the body, which left every such field four
bytes short of a boundary and made each one straddle two. Capability proofs are
the deliberate exception: their compact, length-delimited grammar packs
161-byte edges and promises no internal field alignment.

**The record kind resolves.** 32 bytes is a blob handle, and the handle names a
`SimpleArchive` describing the record kind: its name, the exact byte layout of
its body, and the `KIND_PILE_RECORD` tag. A reader meeting an unfamiliar record
can therefore *resolve* what it is rather than merely failing to recognise it —
the same move the collection layer made when descriptors replaced bare
definition ids. Each description is rooted at the 16-byte id the kind was
already minted under, so widening the field renamed nothing. The handles are
pinned in `triblespace-core/src/repo/pile/record_kind.rs` and a test recomputes
every one of them from its description, so editing a description is a format
change that fails loudly with the new value rather than silently reframing the
pile.

`Pile::publish_record_kind_descriptions` (exposed as
`trible pile migrate <PILE> run record-kind-descriptions`) stores those description
archives for every kind the current binary writes, which makes those kinds
resolvable *there*. Content addressing makes the call idempotent, and the
migration's census distinguishes "already resident" from "left to store" so a
re-run reports honestly instead of repeating its worklist. Retired PEER,
STORE_SCOPE and pile-artifact-offer kinds remain recognized by their pinned
constants and decoder, but fresh piles neither write nor advertise those dead
formats.

The arithmetic works out exactly. A signed commit contains six 32-byte fields,
so `64 + 6 × 32 = 256`: one block, nothing wasted. A one-edge capability
proof is 257 bytes starting at the record-kind field at offset 32, so its
289 unpadded bytes use two blocks. Longer proofs use the minimal additional
whole blocks without changing their canonical body.

A collection descriptor remains an ordinary blob. Capability proofs are
self-contained native records and have no companion claim blobs.
One typed WANT kind stores a grow-only request set; retired assertion,
retraction, and pin records remain structurally readable as explicit migration
input but have no current replay effect.

The span includes the header. Zero is invalid; decoders perform checked
`span * 256` arithmetic and require that the complete record fit in the
observed pile prefix. A header-only record therefore has span 1. A blob has
span `1 + ceil(payload_length / 256)`, and the decoder requires the generic
span and blob-specific byte length to agree exactly. A `u32` block count keeps
the prefix compact while permitting a single record of almost 1&nbsp;TiB.

The common framing is load-bearing:

- **Position independence.** Blob data starts at the constant
  `record_start + 256`; there is no offset-derived padding. A record means
  the same thing at any offset, so records survive relocation and
  `cat a.pile >> b.pile` is a valid merge of two piles.
- **Alignment for free.** Because every newly written record is a 256-byte
  multiple, a pile composed entirely of current 256-byte-framed records stays
  aligned under the atomic lock-free append. Every blob payload in such a pile
  lands on a 256-byte boundary, satisfying GPU storage-buffer binding
  requirements (CUDA / Metal `min_storage_buffer_offset_alignment`) for
  zero-copy aliasing.
- **Cache-friendly headers.** Each header begins on a cache-line boundary and
  admits safe typed views with the `zerocopy` crate.

Reserved kind-body bytes are zeroed and are **not** part of the content hash;
per-record metadata belongs in tribles, not in the header, so identical bytes
never fork into distinct blobs.

Unknown kinds inside a valid frame decode as opaque records. Normal pile replay
semantically skips them and continues with subsequent known records;
`PileRecords` still exposes their exact offset, length, kind, and raw bytes.
This is a forgetful projection: any future kind introduced under this frame
must remain independent of the meaning of known records. In particular, it may
not change the validity or effect of a known record, constrain an old writer's
otherwise-valid append, or make an existing record depend on a companion
record of the new kind. Such an extension—or any other extension whose absence
cannot conservatively mean “no effect”—requires a new frame magic instead.

Concatenation is associative ordered physical composition. Current WANT,
collection, and capability-proof records collapse to order-independent set
union. Decoded legacy pins remain a right-biased log; retired WANT frames and
bounded unknown kinds are inert, so concatenating stale history cannot change
current demand.

### Compatibility surface: v0.46.4, and a reframe for everything else

The last released version is **v0.46.4** (tagged 2026-06-10). Its entire record
vocabulary is three markers — the 64-byte-aligned V1 blob, branch, and
tombstone records — and those are the only records external deployments may
hold. They are read forever.

Everything introduced between that release and the current framing never
shipped: the V3 record family, the three generations of collection records,
the retired WANT logs, retired team state, retired local cells, and the 36-byte
legacy envelope. None of it is a writable compatibility commitment. The
current reader still recognizes each exact historical boundary so old piles
can be inspected or migrated without guessing. `trible pile migrate <pile>
reframe --into <dest>` re-encodes the whole pile into the current framing and
drops only explicitly disposable inert records. Retired unsigned equations are
preserved exactly; genuinely unknown kinds fail a full preflight before any
destination write.

WANT has a cheaper in-place cutover when a whole-file reframe is unnecessary:
before first starting a current binary on a pre-cutover pile, explicitly run
`trible pile migrate <pile> run monotone-wants`. It scans the retired log,
resolves its final active set once, and appends only missing current positives.
The operation is additive and idempotent. It is deliberately excluded from any
implicit migration run because it promotes retired history into live demand;
after cutover, old frames stay inert even if a stale pile is concatenated.

The re-encode is semantic and in source order, which is what makes it faithful:

- Blob payloads are content-addressed, so copying changes no identity, and
  their insertion timestamps are stamped afresh — the old timestamp was a
  local fact about one physical file, not part of the blob identity.
- Legacy pins are replayed in order. Retired WANT state is resolved in order
  once and emitted only as current positive markers; already-current markers
  union with that projection.
- Collection records and capability proofs are grow-only sets, so order is
  irrelevant and re-insertion is idempotent.
- Retired unsigned equations stay inert but retain their exact source frames
  and each independently resident direct blob reference recursively. Reframe
  never turns old unsigned bytes into a receiver-signed endorsement.
- Earlier V3 definition-ID collection frames also survive byte-for-byte. This
  does not add a new interpretation of their historical dependency fields.
- Records that no longer carry retained evidence are dropped and counted:
  retired PEER, STORE_SCOPE and pile-artifact-offer
  state. This includes older retired derivation
  record generations whose old wire shape cannot express the current
  collection algebra. Current native `MERGE` and `DERIVE` records are grow-only
  materialized work and are preserved exactly; like every retained current
  native record, they strongly own each independently resident direct blob
  reference recursively.

Every current collection record's signature covers a domain-separated
transcript over its fields, not its frame. Structural replay and semantic
reframe preserve those exact signed fields without repeating crypto. Explicit
audit verifies the raw records separately, including bad-signature evidence
that a trusted local pile may already contain. Opaque ownership, including
retired local cells, makes semantic reframe fail closed.

### An unknown frame is corruption, not a record from the future

Unknown *kind* and unknown *frame* are different questions and get different
answers. Conflating them would cost one of the two.

An unknown kind inside a valid frame is **forward compatibility**: the frame
states the span, so the record has an exact boundary, and replay crosses it as
an opaque record. Because the kind is a handle, a reader can go and resolve
what it was.

An unknown frame is **corruption**. Nothing about the bytes is trustworthy —
not even where the next record starts — so the decoder fails at exactly that
offset rather than guessing. This is not a limitation to design around; it is
the detection the wide magic buys. 28 bytes is a sentinel, not just an
identifier: a mismatch is 224 bits of evidence that these bytes are not a
record, so a torn write, a truncated file, or a mis-seek is caught where it
happens instead of being read as plausible garbage. The error path must stay
sharp; it is never softened into a skip or a warning.

The two failures are still distinguished. A torn or truncated tail — including
one that is a proper prefix of the magic — reports
`ReadError::CorruptPile { valid_length }`, which is what `amputate` repairs. A
legacy marker this reader no longer decodes reports
`ReadError::UnsupportedRecord { offset, marker }`, which `amputate`
deliberately refuses to truncate: the remedy there is `reframe`, not deletion.

## Design Rationale

This format emphasizes **simplicity** over sophisticated on-disk structures.
Appending new records rather than rewriting existing data keeps corruption
windows small and avoids complicated page management. Storing everything in a
single file makes a pile easy to back up, replicate over simple transports, or
merge by concatenation, while still allowing it to be memory mapped for fast
reads. Internally the pile tracks an `applied_length` watermark; offsets below
this boundary are known-good and only the tail beyond it is rescanned when
refreshing state.

## Operational workflow

1. **Open the file.** `Pile::open` builds the struct around a `File` handle
   and `memmap2` mapping. It does not read any records yet (and it does not
   create missing files — create the file explicitly for a fresh pile).
2. **Load and validate.** `refresh` acquires a shared lock, walks bytes beyond
   `applied_length`, and rebuilds the blob, collection-record,
   capability-proof, WANT, and legacy pin-snapshot indices
   in memory. It **fails loud** on a corrupt or torn record
   (`ReadError::CorruptPile { valid_length }`). It skips bounded unknown
   envelope kinds as opaque records and distinguishes an unknown legacy marker
   as `ReadError::UnsupportedRecord { offset, marker }`. It never mutates the
   file. Callers rarely need to invoke it directly:
   `Pile::snapshot` and collection/WANT/pin-snapshot observations refresh internally
   before observing records, so external writers are visible without a
   standalone scan.
3. **Amputate only when asked to.** `amputate` is the explicit, opt-in repair
   path: it re-runs validation under an exclusive lock and truncates the file
   back to the last valid record, discarding a torn record left by a
   crash. It crosses complete opaque envelopes and may truncate a torn opaque
   tail at its known start. It refuses `UnsupportedRecord` without modifying
   the file because an unknown unenveloped record's boundary is unknowable. It
   is deliberately **not** part of the normal open sequence. The operator CLI
   additionally requires the exact boundary reported by the current reader:
   `trible pile amputate <path> --truncate-to <byte-offset>`. A stale generic
   repair suggestion or a guessed offset therefore cannot trigger truncation.
   The reader compares that offset and calls `set_len` while holding the same
   exclusive file lock, so an intervening repair cannot move the boundary
   between validation and mutation.
4. **Append new records.** `put` (through the `BlobStorePut` trait),
   `CollectionStore::insert`, and `WantStore`
   operations extend the file. Each
   append immediately feeds the bytes back through the record scanner so
   in-memory indices stay synchronised without waiting for a manual `refresh`.
   Blob records use a single `write_vectored` call; fixed-width collection and
   WANT records use one append of their 256-byte frame, and native proof records
   append their complete bounded frame once.
   Records larger than ~1&nbsp;GiB can't be appended in a single atomic
   `writev` because kernel `write_vectored` calls cap at `INT_MAX` bytes on
   macOS and `MAX_RW_COUNT` (~2&nbsp;GiB) on Linux. In that case `put` takes
   an exclusive file lock and issues plain `write_all` calls — still
   append-only, still repairable by an explicit `amputate` if a crash leaves a
   partial tail, but serialised against other writers for the duration of the
   append.
5. **Read through a snapshot.** `SnapshotSource::snapshot` refreshes the pile,
   then clones the memory map and persistent PATCH indices into a
   `PileSnapshot`. Blob bytes, collection records, and capability proofs all
   come from that one immutable prefix and can be read without further locking.

This lifecycle keeps pile usage predictable: open → operate (operations
refresh as they run) → freeze immutable snapshots. If a process wants to scan
for new appends between operations (for example, a background monitor that is
not issuing a snapshot or record enumeration), it can explicitly call `refresh` to pick up
external writers without blocking them for long. If corruption is ever
reported, surface it to the operator; truncating is a decision, not a default.

## Immutability Assumptions

A pile is treated as an immutable append-only log. Once a record sits below a
process's applied offset, its bytes are assumed permanent. The implementation
does not guard against mutations; modifying existing bytes is undefined
behavior. Only the tail beyond the applied offset might hide a partial append
after a crash, so validation and repair only operate on that region. Each
record's validation state is cached for the lifetime of the process under this
assumption, avoiding repeated hash verification for frequently accessed blobs.

Hash verification only happens when blobs are read. Opening even a very large
pile is therefore fast while still catching corruption before data is used.

Every newly written record begins with the generic marker, kind ID, and span
described above. The sections below illustrate each kind-specific body.

## Usage

A pile typically lives as a `.pile` file on disk. Applications open it through
`Pile::open` and load it with `refresh` (directly or via the first operation
that refreshes internally). Multiple threads may share the same handle thanks
to internal synchronisation, making a pile a convenient durable store for
local development. Blob appends use a single `O_APPEND` write. Each handle
remembers the last offset it processed and, after appending, scans any gap left
by concurrent writes before advancing this `applied_length`. Writers may race
and duplicate blobs, but content addressing keeps the data consistent. Each
handle tracks hashes of pending appends separately so repeated writes are
deduplicated until a `refresh`.

```rust,ignore
use std::error::Error;
use std::path::PathBuf;

use anybytes::Bytes;
use triblespace::prelude::*;
use triblespace::core::repo::pile::ReadError;
use triblespace::core::repo::BlobStoreMeta;

fn add_blob(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from("data.pile");
    let mut pile = Pile::open(&path)?;
    // Load and validate the existing records. This FAILS LOUD on a corrupt
    // or torn record and never mutates the file. Unknown envelope kinds are
    // skipped as opaque; unknown legacy markers remain unsupported.
    match pile.refresh() {
        Ok(()) => {}
        Err(err @ ReadError::UnsupportedRecord { .. }) => return Err(err.into()),
        Err(err @ ReadError::CorruptPile { .. }) => return Err(err.into()),
        Err(other) => return Err(other.into()),
    }

    // Insert a blob and obtain a handle pointing at the on-disk bytes.
    let handle = pile.put(Bytes::from_source(bytes.to_vec()))?;

    // One immutable snapshot owns every read capability for this pile prefix.
    let snapshot = pile.snapshot()?;
    if let Some(meta) = snapshot.metadata(handle)? {
        println!("stored {} bytes at {}", meta.length, meta.timestamp);
    }
    drop(snapshot);
    pile.close()?;
    Ok(())
}
```

This pattern illustrates the typical flow: open, load with `refresh`, append
through the storage traits, then hand a `PileSnapshot` to read-only
consumers. `refresh` acquires a shared lock so it cannot race with an explicit
`amputate`, which takes an exclusive lock before truncating a corrupted tail.

Filesystems lacking atomic `write`/`vwrite` appends—such as some network or
FUSE-based implementations—cannot safely host multiple writers for records
below the `~1&nbsp;GiB` atomic-write threshold and are not supported in that
mode. (Records above the threshold use the exclusive-lock fallback and don't
rely on filesystem atomicity.) Using an atomicity-lacking filesystem for
small records risks pile corruption.

## Bounded refresh snapshots

Replay snapshots the observed file length once per pass and decodes exactly
that bounded prefix. A shared-lock writer's single append syscall can expose an
intermediate file length, so a shared replay parse failure is rechecked once
under an exclusive lock with a fresh length. This completion barrier waits for
participating writers; a persistent malformed or unsupported record remains an
error, without truncation or retrying any write. Shared blob-writer preflight
uses the same recheck. Post-write readback instead stops at the completed blob
(or an earlier concurrent duplicate) before a later writer's partial tail.
Appends beyond a successful bounded observation remain for the next refresh.

`PileSnapshot` receives persistent PATCH roots when it is created. Later
refreshes can extend the pile without changing existing snapshots.
Blob replay maintains one segmented PATCH relation keyed by
`hash || offset_be`. It retains every physical occurrence in file order, while
its zero-copy view at the 32-byte segment boundary is the semantic resident-blob
set used for listing, membership, differences, and cover intersection. Reads
walk the offsets for one hash lazily when an earlier payload fails content
validation. The validation byte lives in the persistent occurrence leaf, so
snapshots share cached verdicts without a separate map or per-handle Arc-linked
duplicate chain.
`StoreSnapshot::changes_since` compares the Blob, collection-record, and
capability-proof PATCH roots directly. For Blobs the physical
occurrence root means adding a duplicate fallback or replacing a corrupt
same-handle candidate is visible while unrelated appended records are
not. Classification is therefore constant in the number of semantic
components rather than a scan of either snapshot; component-specific consumers
can reuse unchanged derived state.

Tools that need the raw log rather than the collapsed state—reflogs,
consolidation, forensics—should use
[`PileRecords`](../../src/repo/pile.rs), an iterator over every record in a
pile file in log order. It shares its decoder with the replay path described
above, so it understands every record format ever written; do not hand-roll a
parser against the layouts documented in this chapter. An unknown envelope kind
is yielded as `PileRecordContent::Opaque` with its declared boundary; callers
can preserve its exact bytes through the iterator's raw file view. An unknown
unenveloped marker is reported as `UnsupportedRecord`, while a malformed or
truncated record is reported as `CorruptPile`.

For an operator-facing view of one exact boundary, use
`trible pile diagnose record-at <pile> <offset>`. The command is read-only: it
walks the same canonical decoder from byte zero, rejects offsets that land
inside a record, and prints the physical marker, classification, known span,
next offset, and the fields the current reader can safely decode. In
particular, an unsupported unenveloped marker asks for a newer reader and never
suggests amputation; only a malformed or torn known record presents the
explicit destructive-repair command.

Semantic Pile and Yard reads may continue across opaque records, but destructive
retention is different: `Pile::rewrite_retained_into`, Yard collection,
compaction, and reclaim refuse before mutation when any opaque record is
present. An older reader cannot know whether the unknown kind owns a known
blob, so silently omitting it—or collecting its dependencies—would be unsafe.

The retired V4 collection DERIVE kind is deliberately not opaque. Its former
fields and semantics are known, and a derivation carried neither ownership nor
authoritative state: it is a computation whose artifact is rebuilt under the
current recipe. Replay exposes it as `RetiredCollectionDeriveV4`, projects no
collection record, and semantic rewrites may discard it. This distinction lets
the unknown-kind fence stay strict without letting known inert computations
block semantic compaction forever.

## Blob Records

| Offset | Width | Field |
|---:|---:|---|
| `0..28` | 28 | Framing magic |
| `28..32` | 4 | Total 256-byte-block span, little-endian |
| `32..64` | 32 | Blob kind `01148F301FE56E346D16596A8480532E8B4420C4EFD00C8DFF437D0DF9810ED0`, rooted at `9C33EEB525065A62EAEC4BE43DCC355A` |
| `64..72` | 8 | Timestamp in Unix milliseconds, little-endian |
| `72..80` | 8 | Exact unpadded payload byte length, little-endian |
| `80..96` | 16 | Reserved zeros, rounding the scalars up to a 32-byte boundary |
| `96..128` | 32 | BLAKE3 payload hash |
| `128..256` | 128 | Reserved zeros |
| `256..` | variable | Payload and post-padding to the declared span |

Each blob record carries:

- **Record kind** – identifies blob semantics inside the generic envelope.
- **Timestamp** – milliseconds since the Unix epoch when the append occurred.
- **Payload length** – the unpadded byte length of the blob.
- **Hash** – the digest produced by the pile's hash protocol (BLAKE3 by
  default) and used as the blob handle.
- **Reserved** – zeroed padding to the fixed 256-byte header length; not part
  of the content hash.

The payload follows at `record_start + 256` and is post-padded to the next
256-byte boundary. The [Pile Blob Metadata](./pile-blob-metadata.md) chapter
explains how to query these fields through the `PileSnapshot` API.

## Native Collection Records

`CollectionStore` is a grow-only set of signed typed collection-calculus
records: `COMMIT` assertions and `MERGE` and `DERIVE` equations. The pile stores
them directly as fixed enveloped records: COMMIT and DERIVE occupy 256 bytes;
MERGE occupies 512. COMMIT's signed bytes and kind are unchanged, while signed
equations have new kinds distinct from their unsigned predecessors. They are
**not blob records**, have no following payload, and carry no insertion
timestamp. They are also distinct from operational wants and historical pins:
collection records have no head, tombstone, or
last-writer-wins update. Their exact canonical value is the semantic record; a
collection record is not a trible entity. Physical indexes use a full-width
BLAKE3 fingerprint only as a fixed-width lookup and deduplication key.

The collection itself is identified by a canonical `SimpleArchive` descriptor.
Its 32-byte blob handle is the sole `CollectionHandle`. Records carry this
handle directly; there is no definition record or registry. Consequently a
transferred collection record names the exact descriptor bytes needed to
interpret it, using the ordinary blob store.

The descriptor archive holds a descriptor entity carrying:

- `metadata::tag`, the descriptor kind;
- one anchor — an attached UTF-8 `collection_name` on a root, or
  `collection_source` on a derivation, naming by handle the collection it
  derives from. A reader holding the pile can resolve a root's human-readable
  name without needing the code that minted an opaque id. A derivation carries
  no name of its own: its source already anchors it. Naming the
  source by handle rather than by a shared label means a descriptor cannot claim
  a lineage it does not have;
- repeated `resource_policy` links to self-contained policy entities, each
  naming an exact `capability_handle`. The standard READ and WRITE definitions
  and any application-specific definitions share this relation. An open policy
  needs no proof. A quorum policy
  carries a canonical nonempty set of Ed25519 roots and one semantic quorum
  threshold. The byte-compatible descriptor may still contain the earlier
  optional delegation-threshold fact, but authorization ignores it; a signed
  proof edge's mode alone determines whether its root share can be delegated
  onward. Roots and derivations state both policies independently; source
  walking never supplies authority. Their ordinary facts participate directly
  in the descriptor handle;
- `collection_representation`, naming the canonical member encoding. The
  encoding owns validation and the intra-encoding join;
- on a derivation, `collection_mapping`, linking a concrete mapping entity.
  Canonical builders derive its id, but readers validate the entity's facts
  rather than its minting history. It names one `mapping_algorithm` and carries its concrete
  parameters as ordinary tribles — which attribute an observed set observes,
  which pair a register is ordered by, or the complete automaton a path summary
  uses.

A mapping algorithm id names the reusable computation, while the linked mapping
entity names one parameterization of it. The complete descriptor archive—not a
requirement that the entity id was intrinsically minted—binds those facts into
the target collection identity. The parameters remain queryable rather than
being hidden behind an opaque hash-only API.

The archive may also carry the `describe` fragments of the encoding and mapping
algorithm, so the descriptor states what its bytes and conversion *are* rather
than only naming them. A bare id is legible only to someone who already holds
the code that minted it, which is exactly the reader — a peer receiving a
collection it has never seen — that most needs the answer.

The magic markers below identify the compact pile representation. They are
storage-envelope markers, distinct both from the stable semantic kind IDs used
in fingerprints/signature domains and from the one-byte versioned tags used by
generic dense record stores. There is no equivalent `SimpleArchive` form for
these algebra records.

| Kind | Record kind (rooted at) | Kind-specific byte layout after the common prefix |
|---|---|---|
| Commit | `A1322BB3F5214287C314D42AFCC1A97CB264FACD9A22B4938838BE78DB31AA59` (`CBF2CF97D52A3486E16C12D70D397C66`) | `64..96` descriptor handle, `96..128` data digest, `128..160` metadata handle, `160..192` Ed25519 public key, `192..224` signature R, `224..256` signature S — no reserved bytes |
| Merge | `9D9B962D46FA42168AB3A11FB367AC14692D4F51B5190196F2BDB08D5BC2BA07` (`BC68266A511EC292D815A30C8DFBA82D`) | `64..96` descriptor handle, `96..128` lower input digest, `128..160` higher input digest, `160..192` result digest, `192..224` Ed25519 public key, `224..256` signature R, `256..288` signature S, `288..512` reserved zeros |
| Derive | `B2EE8382C70161379E387D692B822946A60B602A909EED66B7D6DA2A62F36232` (`7FDDB25BB2B40E002A7B0EC40E316232`) | `64..96` target descriptor handle, `96..128` input digest, `128..160` output digest, `160..192` Ed25519 public key, `192..224` signature R, `224..256` signature S — no reserved bytes |

The new MERGE and DERIVE description anchors above were minted with installed
`trible genid` on 2026-09-13. Their signed semantic kind IDs, independently
minted in the same session, are `1E5277B23D177FD692B074FBF0EF28F1` and
`CE6A838612D0AA0812C05A50CCD11DC1`, respectively. COMMIT retains semantic kind
`B34817308188C4515A3C51967A91A603` and its historical version-2 transcript.

Generic stores and collection repair use a one-byte dense tag followed by the
same ordered 32-byte body fields, without native framing or reserved padding:

| Record | Dense tag | Payload bytes | Total dense bytes |
|---|---:|---:|---:|
| COMMIT | 1 | 192 | 193 |
| signed MERGE | 4 | 224 | 225 |
| signed DERIVE | 5 | 192 | 193 |

Tags 2 and 3 are retired unsigned layouts, not aliases for the signed records.
The changed collection wire grammar uses ALPN `/triblespace/pile-sync/25`.
An equation signs its domain bytes (`triblespace.collection.merge.transcript`
or `triblespace.collection.derive.transcript`), the corresponding new semantic
kind ID, author public key, and its ordered collection/operand/result fields.
The newly minted kind versions this grammar; there is no extra equation version
integer. COMMIT's historical domain, kind, version integer, field order, and
signature bytes are unchanged.

Public dense `from_bytes` constructors perform strict signature verification,
including canonical non-weak author keys. Network ingress uses that checked
boundary once. Locally signed constructors build their typed values directly;
typed store inserts, adapters, local repair indexes, and outbound encoding do
not re-verify. Native replay and explicit raw audit decode structurally. The
object-store backend is likewise trusted persistence: it checks canonical
structure and the exact content-addressed key without repeating signatures.
Foreign pile/import bytes need an explicit checked ingress or a user-approved
trusted-source boundary; structural open alone is not an import verifier.

These are the complete native collection-record family: there is no
accelerator-specific fourth variant. A Rank9-accelerated member is an ordinary
blob root plus its portable raw child, related to the raw collection by an
ordinary `DERIVE`. Raw Succinct and Rank9-accelerated collections both own
canonical joins and use the same `MERGE` record kind. The accelerated root's
first 32 bytes name the raw child, so
generic blob traversal can follow the dependency without a special pile index.
An accelerated join may consume the exact raw union when that immutable blob is
already resident, but it never creates the upstream raw blob or `MERGE` record.
Without that dependency, target maintenance retains a finer accelerated cover.
Collection resolution treats a member as physically
available only when its root and required representation closure are resident;
an incomplete compacted root is skipped in favor of a finer exact cover. Typed
materialization then defensively validates the selected raw/index pair.
The unpublished mapping-evidence record kind was clean-cutover removed after a
scan found no live records requiring migration.

Every reserved byte must be zero; a nonzero reserved byte makes replay fail as
corrupt rather than silently assigning meaning to a format extension. Merge
inputs are stored in lexicographic digest order (`low <= high`), so swapping
the two operands cannot create a second representation of the same
commutative equation.

No record ID exists in these headers or in the semantic model. On replay, the
decoder reconstructs the record's exact dense typed payload: 192 bytes for a
commit, 224 bytes for a merge, and 192 bytes for a derive. Where a fixed-width
physical key is required, the store hashes the stable semantic kind ID followed
by every canonical payload byte with BLAKE3 and retains the full 32-byte digest
as a `CollectionRecordFingerprint`. Every current payload includes the
public key and both signature components. The fingerprint is an index key, not
a materialized entity or a substitute for the exact record value.

Pile replay keeps the records in fingerprint order. Re-inserting an identical
record is an idempotent success; a different record producing the same
full-width fingerprint is reported as a collision. Concatenating piles therefore gives set-union
semantics for collection records: append order and duplicate copies do not
change the discovered collection calculus. Current operational WANTs are
likewise a grow-only set. Historical pins remain ordered evidence; retired
WANT logs are only explicit migration input and do not participate in ordinary
replay.

### Retired unsigned equations and reader cutover

The preceding described MERGE kind was
`0CEE320DE0BDA40A6A6F52221C5E4E4D2CE3B165B69C858673FD13D98F655379`, with
collection/low/high/result at `64..192` and zeros through byte 256. DERIVE was
`7ACE1ED10F3EBC632627058CC461DC1CC171CD2E56C52E5DCE60EA4C8DC23C36`, with
target/input/output at `64..160` and zeros through byte 256. Their retired dense
tags 2/3 carry 128/96 payload bytes and retain historical semantic kinds
`5F20FFC64313969B7E046A7677874D39` / `46C621338B6DD5B71C8E1E6DD74B087C`.
The earlier 36-byte-envelope forms, and unenveloped MERGE V4, are recognized
as the same unsigned evidence rather than current equations.

`PileSnapshot::legacy_unsigned_collection_equations()` exposes their exact
equations for explicit migration, separate from `CollectionRead` and ordinary
repair. GC and semantic reframe preserve their raw source frames, and retained
rewrites preserve all resident descriptor/input/output reference closures.
Object-store listing omits these equations from current semantics while leaving
their immutable objects untouched and checking their historical content keys.
An endorsement migration must append a new signature by a writer authorized
for that exact collection (the target for DERIVE). It must not use every
receiver's key or delete unsigned evidence that cannot yet be endorsed.

The explicit same-pile command is:

```bash
trible pile migrate <PILE> endorse-unsigned-equations \
  --collection blake3:<COLLECTION_HANDLE> \
  --signing-key <EXISTING_WRITER_KEY> --dry-run
```

Remove `--dry-run` only to make that writer's new endorsement. The command
freezes WRITE admission and direct-reference residency once, skips absent
dependencies without fetching, and appends only missing identical endorsements.
It does not recompute results, change entity identities, or remove old evidence.
Use `trible pile verify <PILE>` for the separate native-signature audit before
accepting an unfamiliar pile as a trusted local store. That audit does not prove
the mathematical correctness of historical unsigned equations.

An older reader that understands the generic native frame can open a pile with
new signed kinds: it crosses them as opaque, at their declared spans. This is
not rewrite compatibility. Old retained GC refuses opaque ownership, and the
old semantic `reframe` implementation may silently drop unknown records. Do not
use an old installed reframe on signed-equation piles. The new implementation
preflights truly unknown kinds and refuses before writing output; it explicitly
preserves known unsigned evidence.

## Native Capability Proof Records

`CapabilityProofStore` is a second grow-only native set. Each member is the
canonical self-contained prefix-signed proof body

```text
magic32 | resource32 | root32 |
    (capability_handle32 | flags1 | validity32 | delegate32 | signature64)+
```

Its logical key is
`CapabilityProofId = BLAKE3(body)`. The ID is reconstructed during replay and
is not duplicated in the frame.

| Offset | Width | Field |
|---:|---:|---|
| `0..28` | 28 | Framing magic |
| `28..32` | 4 | Minimal total 256-byte-block span, little-endian |
| `32..64` | 32 | PROOF magic / record kind `CF346E81157B2169045EA8574896BAD23976A4A08D7DC70DDCADABA9AFF2442A`, rooted at `D81538DE724347280A6D97F51EDE08F6` |
| `64..96` | 32 | Opaque resource identity |
| `96..128` | 32 | Root Ed25519 public key |
| `128..128+161n` | variable | Delegation edges |
| remainder | variable | Zero padding to the declared span |

There is no proof-specific envelope, inner magic, or separate byte-length field.
The proof starts with the record kind itself. Its header is exactly 96 bytes:

| Body offset | Width | Field |
|---:|---:|---|
| `0..32` | 32 | PROOF magic, the same record-kind handle |
| `32..64` | 32 | Opaque resource identity |
| `64..96` | 32 | Root Ed25519 public key |

Each following edge is exactly 161 bytes:

| Edge offset | Width | Field |
|---:|---:|---|
| `0..32` | 32 | Exact capability-definition `Handle<SimpleArchive>` |
| `32..33` | 1 | Invoke/delegate mode bits plus validity-presence bit |
| `33..65` | 32 | Two signed big-endian 128-bit TAI-nanosecond bounds, or canonical zeros |
| `65..97` | 32 | Delegate Ed25519 public key |
| `97..161` | 64 | Ed25519 signature over the exact body prefix through this delegate |

The body length must be exactly `96 + 161n` for `1 <= n <= 255`. Replay parses
every Ed25519 key, requires a known nonempty mode on each
edge, validates the optional inclusive interval encoding, requires the declared
span to be the smallest span containing the body, and rejects any nonzero
padding byte as corruption. The low two flag bits encode Invoke,
Delegate, or both; bit 2 marks a present interval; all higher bits must be zero.
A one-edge body is 257 bytes, so its pile record occupies two 256-byte blocks.
The generic framing declares only the block span. To recover the exact proof,
the decoder walks fixed-width edges until the zero suffix: a valid edge cannot
be all zero because its mode is nonempty. A bounded scan, the minimal-span
check, and an entirely zero remainder make this unambiguous even when padding
is longer than one edge. Zero bytes at the end of a signature remain part of
the proof. A 128-edge proof fills its blocks exactly and has no padding.

Insertion of identical bytes is idempotent. Different bytes reconstructing to
the same proof ID are a collision and fail. Exact lookup is only by proof ID;
the store does not infer a proof from a key, resource, or request, and record
presence grants no authority. Each signature is last and covers every earlier
body byte through its own delegate, including the record kind and prior signatures.
Generic framing and block padding are excluded. An exact prefix
ending after any signature is therefore a complete proof for that intermediate
delegate.

Conservative rewrites preserve every current canonical proof record and each
resident capability definition it references, without fetching absent blobs
or authoring WANTs. The opaque resource field is not interpreted as a blob
handle by storage. Full semantic verification still
needs the external trust root, expected subject, instant, and exact request;
physical retention grants no authority.

The earlier `K(S,C,K)+` and 145-byte-edge action-ID proof kinds remain
structurally recognizable as inert frames so append-only piles can be traversed
safely. Fresh writers do not emit them, replay projects no authority from them,
and semantic rewrites may drop them. Their signatures cover other grammars and cannot be
mechanically migrated; the relevant private keys must reissue authority.

## Retired Team-Era Records

Earlier network hosts used `PeerStore` as a grow-only set of routing hints.
Each historical PEER member was written as
`PEER(team_public_key, peer_public_key)`. Those names describe the old writer's
intent; the current reader treats both 32-byte fields as uninterpreted
historical bytes. Because the record is inert, replay validates only its fixed
framing, span, kind, and reserved zeros—not whether either field encodes an
Ed25519 point. The historical dense body was the 64-byte concatenation
`team || peer`; its optional physical selector was a domain-separated BLAKE3
identity over that body.

| Offset | Width | Field |
|---:|---:|---|
| `0..28` | 28 | Framing magic |
| `28..32` | 4 | Span `1`, little-endian |
| `32..64` | 32 | Peer kind `327FFCAAA3F5A10424DC2059E3A7A3517F837E7E56A3C850979EFA9F5E3A1ED7`, rooted at `E25B4427F30DCE7B36F3F80BB38E375A` (minted with `trible genid` on 2026-08-26) |
| `64..96` | 32 | Historical team-key field (uninterpreted) |
| `96..128` | 32 | Historical peer-key field (uninterpreted) |
| `128..256` | 128 | Reserved zeros |

The same generation also wrote a fixed STORE_SCOPE record:

| Offset | Width | Field |
|---:|---:|---|
| `0..28` | 28 | Framing magic |
| `28..32` | 4 | Span `1`, little-endian |
| `32..64` | 32 | Scope kind `97C69C746D01741C8012A56F08D2C424E0291B5424EB9CD7637FD4A655C93DFB`, rooted at `EDDEDAF4E20AF86EC63A7F1F044E2D4A` |
| `64..96` | 32 | Historical team-key field (uninterpreted) |
| `96..256` | 160 | Reserved zeros |

Current replay validates both layouts and exposes dedicated retired record
variants to raw inspection, but builds no index or repository state from
either. Current collection-scoped networking does not create, synchronize, or
route from them: bootstrap endpoints, DHT referrals, liveness, and provider
leases are process-local soft state, while collection policy is the sole
admission and disclosure authority. Semantic reframe, retained rewrite, Yard
reclaim, and `trible pile compact` deliberately drop both retired kinds.
Genuinely unknown records remain opaque and still make destructive rewrites
fail closed.

## Retired: Collection Publication Grants

A grant was an author-signed, irrevocable permission to redistribute that
author's commits in one exact collection, stored as a fourth pile record kind
beside the collection calculus. It is gone, and nothing in a pile refers to one:
21.2 GB across six piles were scanned for its record marker before removal, and
the same scan found ordinary commit records, so the absence was the grant's
rather than the scan's.

An intermediate design replaced grants with a `collection_reach` descriptor
attribute. That design is retired too. Current descriptors carry mandatory,
independent READ and WRITE policies; collection-scoped repair proves READ(C),
and commit admission proves WRITE(C). Exact-content provider leases are instead
derived from every served resident H and are independent of collection policy.
There is no ambient full-team inventory or separate durable gossip permission.

The semantic kind ID `9BB5B1F4D6FD8FB850B494C2CF51B5CA` (minted 2026-08-12,
retired 2026-08-21) and its record kind
`5E18D982337466E65CB8278658CF53027FC109385456B49D35C4E66D6E9CE599` are recorded
here and in `collection::records::KIND_COLLECTION_GOSSIP_V1` so neither is
minted a second time. A pile is not expected to contain one; if any did, it
would read as an unknown record rather than a permission.

### Legacy unenveloped V4 collection records

Before the legacy envelope, the same three V4 kind IDs occupied bytes `0..16`,
followed immediately by the semantic fields. These postdate v0.46.4, so they
are read only for `reframe`.

| Kind | Legacy unenveloped byte layout |
|---|---|
| Commit | `0..16` kind, `16..48` descriptor, `48..80` data, `80..112` metadata, `112..144` public key, `144..176` signature R, `176..208` signature S, `208..256` zeros |
| Merge | `0..16` kind, `16..48` descriptor, `48..80` low, `80..112` high, `112..144` result, `144..256` zeros |
| Derive | `0..16` kind, `16..48` source descriptor, `48..80` target descriptor, `80..112` input, `112..144` output, `144..256` zeros |

### Legacy V3 collection records

V3 encoded a collection by a separate definition record with a 16-byte
intrinsic entity ID. Its V1 commit signature transcript and equations therefore
do not identify the current descriptor-handle semantics. The reader recognizes
all four old markers so it can validate record boundaries and preserve their
bytes during conservative rewrites, but treats them as inert physical evidence:
they never enter `CollectionStore`, assert membership, or retain blobs.
Semantic reframe preserves these raw V3 headers too. This narrower historical
guarantee does not reconstruct their definition-ID semantics or add GC roots;
the descriptor-handle unsigned equations above have the stronger direct-reference
retention needed by the signed-equation endorsement transition.

| Legacy kind | V3 magic marker | Exact byte layout |
|---|---|---|
| Definition | `3BE108504E4F5242FB24AA72D6D94CE1` | `0..16` marker, `16..32` scope ID, `32..48` representation ID, `48..64` recipe ID, `64..256` reserved zeros |
| Commit | `BB758AA6F79FBFC4D1958592A8956777` | `0..16` marker, `16..32` definition ID, `32..64` data digest, `64..96` metadata handle, `96..128` Ed25519 public key, `128..160` signature R, `160..192` signature S, `192..256` reserved zeros |
| Merge | `CC0108AC1DF4F335AFA856A529C42BE9` | `0..16` marker, `16..32` definition ID, `32..64` lower input digest, `64..96` higher input digest, `96..128` result digest, `128..256` reserved zeros |
| Derive | `07ECF056F6F015D94389FFF21F851480` | `0..16` marker, `16..32` source definition ID, `32..48` target definition ID, `48..80` input digest, `80..112` output digest, `112..256` reserved zeros |

## Legacy Pin Records (head / tombstone)

| Kind | Record kind (rooted at) | Kind-specific body after the common prefix |
|---|---|---|
| Head | `2BC0B9FE0EFDB0BC53654E17BB9D06E01259F36AF93EEE54AD5D557B12DF706D` (`AC363D04AFE1AF17B39581B1E23021D7`) | `64..80` branch ID, `80..96` reserved zeros, `96..128` hash, `128..256` reserved zeros |
| Tombstone | `8D9F27E76D3620EEC29B781F841E9EF77F2607B40DC702FE3DAED007E9228CA5` (`D0CBA0C8EAAB4C0C73121C3205671E4F`) | `64..80` branch ID, `80..256` reserved zeros |

These historical records map a pin identifier to a blob hash or tombstone that
mapping. Current code decodes them into immutable snapshots for explicit
migration, capability reachability, diagnostics, and byte-preserving retained
rewrites. No current publication API appends, advances, or tombstones a pin.
The legacy encoding never required the referenced blob to be resident locally.

## Retired Local Cell Records

These kinds are never written under the current framing, so they exist only in
the legacy envelope and the unenveloped V3 form:

| Kind | Legacy kind ID | Kind-specific body after the legacy 36-byte prefix |
|---|---|---|
| Replace | `24264FA9EE46A1ACC0E024AE69774B09` | `36..52` cell ID, `52..84` `SimpleArchive` handle, `84..256` reserved zeros |
| Clear | `4FE372AE868D22A44DED7A60D579B651` | `36..52` cell ID, `52..256` reserved zeros |

These markers belonged to an experimental named last-writer-wins value API.
That API and its writers were removed before release: a whole-value replacement
was not invariant under pile concatenation and made independently edited policy
silently order-dependent. The markers are retired permanently and must never be
assigned new meaning.

Current readers recognize both the legacy enveloped form above and the
fixed-width unenveloped V3 form solely to preserve migration evidence. They expose either
form as `PileRecordContent::Opaque`, do not project a value into current
state, and do not treat its referenced archive as a retention root. Raw tooling
through `PileRecords` can still copy or explicitly migrate the exact bytes.
Because their former ownership semantics are no longer interpreted,
`Pile::rewrite_retained_into` and Yard collection/reclaim refuse a destructive
rewrite while any such record remains.

## Want Records

| Kind | Record kind (rooted at) | Kind-specific body after the common prefix |
|---|---|---|
| WANT | `82EE8C72E252AB403C431AA98C9E77C0EA89796A8111DFF8C252ABCDE6F87D6F` (`E6CEE6F8578E3B8DB4C081486A8CBD28`) | `64` request kind, `65..96` reserved zeros, `96..128` field A, `128..160` field B, `160..192` field C, `192..256` reserved zeros |

The root id was minted with `trible genid` on 2026-09-02. One frame is one
element of a grow-only set keyed by the exact canonical 97-byte `WantRequest`
below. Repeating a request is idempotent. There is no timestamp and no
retraction kind: concatenation is set union. Retired frames are inert, so stale
pre-cutover history can neither remove nor resurrect current demand.

| Request | Tag | Field A | Field B | Field C |
|---|---:|---|---|---|
| Blob | 1 | blob handle | zero | zero |
| Merge | 2 | collection descriptor handle | lower input digest | higher input digest |
| Derive | 4 | target descriptor handle | input digest | zero |

The canonical key is `tag || A || B || C`: byte `0` is the versioned tag,
`1..33` is A, `33..65` is B, and `65..97` is C. The Blob and Derive decoders
reject nonzero unused fields. Merge inputs must be in
lexicographic order (`low <= high`), so operand order cannot create a second
request key.

The three request kinds deliberately share durability but not policy.
`Blob(H)` is the sole exact-content fetch/retention intent. `Merge` and
`Derive` are durable questions about reproducible collection work; an answer is
the corresponding native `MERGE` or `DERIVE` receipt already defined by
`CollectionStore`, not mutable state inside the want. The storage format
persists those questions independently of whether a local or remote worker
eventually supplies the receipt.

Forgetting is a physical storage-policy operation. Every retained WANT owns
each independently resident handle named by its request recursively. Yard does
not weaken this edge through a recency or byte budget; a deliberate physical
rewrite may instead omit the WANT and its ownership edges. No negative record
is appended.

Four former current-frame kinds—the blob assertion/retraction pair
`EC1C024C04AF08243DB3AE318C93FA500355C74395C0F553CFFC0AF0A4BA0346` /
`ACCB531FC7489357C40FCEF0DDE8BD9088F2AC1924A652EA211ADD5C30B95B46`
and typed assertion/retraction pair
`65EE9E4279FFE01D263E75A8E2DF6289B6DE403CB4468098A0EAB925F81C28ED` /
`A57C866A83A90635090A947D92464B19D9F898C0C961AB7A91C79A979F9F1483`—plus
their legacy-envelope and unenveloped weak-pin forms are now
retired. Ordinary replay recognizes their exact framing but treats them as
inert. The explicit `monotone-wants` migration and whole-pile reframe are the
only operations that interpret their file order: both resolve the former
per-request LWW log; migration appends missing positive members under the
current kind, while reframe emits that final projection into its destination.
Historical typed tag 3 encoded a derive as `(source, target, input)`; resolution
keeps all three fields in its historical identity, then projects each active
key to current `Derive(target, input)`. The current kind accepts only canonical
tag 4.

## Legacy unenveloped records

The legacy envelope's bodies all began at byte 36, four bytes short of a 32-byte
boundary; the tables above give the current offsets, and the legacy ones are
each exactly 28 lower.

Unenveloped V3 blob, branch, and retired blob-WANT records place their kind ID directly in
`0..16`. Their semantic bodies begin at byte 16 rather than byte 36: a V3 blob
stores timestamp at `16..24`, byte length at `24..32`, and hash at `32..64`;
branch IDs occupy `16..32`; branch values occupy `32..64`; and retired WANT
handles occupy `16..48`. All have a 256-byte header and remain structurally
readable byte-for-byte; retired WANT records have no ordinary replay effect.
The two retired local-cell markers are the one deliberate exception to the
unknown-unenveloped rule: their historical 256-byte boundary is known, so the
reader crosses them and exposes them as opaque migration evidence. Their former
cell ID occupied `16..32`, and a replacement's archive handle occupied
`32..64`. The legacy V3 and V4 collection layouts are listed above.

Piles written before V3 contain 64-byte-aligned V1 records: a 64-byte blob
header (marker, timestamp, length, hash) followed by a payload padded to a
64-byte boundary, and 64-byte branch / tombstone records. The reader recognises
the V1 markers and reads these records byte-identical; they are never rewritten.
V1 had no want records.

## Recovery

`refresh` scans an existing file to ensure every record fits. It does not verify
blob hashes. A malformed or truncated known or enveloped record reports the
number of bytes that were valid so far using `ReadError::CorruptPile`. A
complete unknown envelope kind is structurally accepted and semantically
skipped; an unknown unenveloped marker reports its bytes and offset using
`ReadError::UnsupportedRecord`, since the reader cannot infer that record's
length. The retired cell markers are recognized as fixed 256-byte opaque
records rather than guessed. Both errors leave the file untouched, and the
reader never guesses any other legacy record length.

If the file shrinks between scans into data that has already been applied, the
process aborts immediately. Previously returned `Bytes` handles would dangle
and continuing could cause undefined behavior, so truncation into validated
data is treated as unrecoverable.

`refresh` holds a shared file lock while scanning. This prevents a concurrent
`amputate` call from truncating the file out from under the reader.

The `amputate` helper is the explicit, destructive repair path: it re-runs the
same validation under an exclusive lock and truncates the file to the valid
length if corruption is encountered, discarding incomplete data left by an
interrupted write. It crosses complete opaque envelopes, truncates a torn one
at its start, and propagates `UnsupportedRecord` for unknown unenveloped
markers without truncating. Run it deliberately (e.g. via
`trible pile amputate <path> --truncate-to <byte-offset>`)—never as a routine
part of opening. The CLI refuses a boundary that differs from the current
reader's result. Hash
verification happens lazily only when individual blobs are loaded so that
opening a large pile remains fast.

For more details on interacting with a pile see the [`Pile` struct
documentation](https://docs.rs/triblespace/latest/triblespace/repo/pile/struct.Pile.html).

[1]: https://db.cs.cmu.edu/mmap-cidr2022/ "The Case Against Memory-Mapped I/O"
