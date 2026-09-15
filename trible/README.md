# Trible CLI

Trible CLI is a friendly companion for exploring and managing
[Tribles](https://github.com/triblespace/tribles-rust) and TribleSpace piles
from the command line.

This crate tracks `triblespace` releases (major/minor), and may ship independent patch releases.

## Installation

```bash
cargo install trible
```

Or, for local development:

```bash
cargo install --path .
```

## Quick Start

1. Create a new pile to hold your data:

   ```bash
   trible pile create demo.pile
   ```

2. Add a file as a blob. This command prints a handle for the stored blob:

   ```bash
   echo "hello" > greeting.txt
   trible pile blob put demo.pile greeting.txt
   ```

3. List the blobs in the pile to confirm the handle:

   ```bash
   trible pile blob list demo.pile
   ```

4. Retrieve the blob using its handle:

   ```bash
   trible pile blob get demo.pile <HANDLE> copy.txt
   ```

The file `copy.txt` now contains the original contents of `greeting.txt`.

## Usage

Run `trible <COMMAND>` to invoke a subcommand.

### Generate identifiers

- `genid` — generate a random identifier.

### Generate shell completions

- `completion <SHELL>` — output a completion script for `bash`, `zsh`, or `fish`.

### Work with piles

- `pile create <PATH>` — initialize an empty pile, creating parent directories as needed.
- `pile diagnose check <PILE>` — verify pile integrity.
- `pile diagnose locate-hash <PILE> <HANDLE>` — scan raw pile bytes and report where a handle appears (blob header vs payload references).
- `pile compact <SOURCE> --into <DESTINATION>` — conservatively repack into a
  fresh pile. Every distinct valid blob and every distinct native collection,
  and proof record remains; active WANTs and legacy pins are projected once.
  Blob records receive fresh timestamps, corrupt physical occurrences
  disappear when another occurrence validates, and known semantically inert
  records—including retired PEER and STORE_SCOPE state—are dropped. Opaque
  kinds are refused. Quiesce writers for an exact whole-file result because a
  late append may remain outside the valid observed prefix. On Unix the
  destination starts no broader than mode 0600, then receives the source
  permissions through its open handle after rewriting. On post-create failure
  the command attempts to remove the destination and reports cleanup failure.
- `pile migrate <PILE> list` — list known migrations and whether they are needed for this pile.
- `pile migrate <PILE> run <MIGRATION>` — run one explicitly named migration.
  Pass `--dry-run` to preview changes. In particular, `monotone-wants` is a
  deliberate one-time projection of retired demand history and is never part
  of an implicit run-all operation.

Legacy piles can be migrated directly into native collections:

```bash
trible pile migrate <PILE> branch-to-collection \
  --branch <LEGACY_BRANCH> \
  --collection-name <NAME> \
  [--authority <TRUST_ROOT>] \
  --signing-key <KEY_PATH>
```

This is an explicit compatibility operation over an immutable legacy pin
snapshot. `--authority` selects the direct trust root for both the target's
READ and WRITE policies and defaults to the migration signer. Choosing another
root does not block local publication, but the resulting commits remain
inadmissible until the pile contains an exact WRITE proof for their signer.
The command validates the full frozen legacy closure before registering the
target, preserves every existing fact and metadata entity id, and does not
create, advance, merge, or delete branches.

Historical unsigned equations can be explicitly endorsed for one existing collection:

```bash
trible pile migrate <PILE> endorse-unsigned-equations \
  --collection blake3:<COLLECTION_HANDLE> \
  --signing-key <EXISTING_KEY_PATH> [--dry-run]
```

The signer must have WRITE authority for that exact collection in the command's
frozen snapshot. The command appends signed MERGE/DERIVE records with the same
endpoints, preserving every old byte and identity. It does not recompute the
equations or recover their original authorship: the supplied signer endorses
the historical results. Missing direct references are skipped without fetching;
existing identical endorsements are reported and not appended again. No keys,
descriptors, blobs, or other legacy conversions are created. `--dry-run` leaves
the pile unchanged.

#### Blobs

- `pile blob list [--metadata] <PILE>` — list stored blob handles. Pass `--metadata` to include timestamps and sizes.
- `pile blob put <PILE> <FILE>` — store a file as a blob and print its handle.
- `pile blob get <PILE> <HANDLE> <OUTPUT>` — extract a blob by handle.
- `pile blob inspect <PILE> <HANDLE>` — display metadata for a stored blob.

#### Collections

A collection is identified by the blake3 handle of its canonical descriptor
blob — a `SimpleArchive` naming its root or derived source, independent READ
and WRITE admission policies, representation, and concrete mapping, together
with the encoding and mapping-algorithm descriptions.
`pile blob inspect` sees only the encoded blob; these subcommands decode it.

- `pile collection init <PILE> <NAME> [--key PATH]` — register a canonical
  named `SimpleArchive` descriptor whose direct READ and WRITE root is an
  existing durable signing key, then print its exact handle. It stores no
  synthetic commit and is idempotent.
- `pile collection list [--metadata] <PILE>` — one row per distinct collection the pile's commit / merge / derive records reference, with the decoded name/source anchor, READ and WRITE policies, representation, and mapping algorithm (known representation and algorithm ids are named). Pass `--metadata` for per-collection record counts and the descriptor blob's size and storage timestamp.
- `pile collection show <PILE> <HANDLE>` — decode one descriptor, its anchor,
  READ and WRITE policies, representation, mapping, and referencing record
  counts. The handle is accepted with or without the `blake3:` prefix.
- `pile collection grant-read <PILE> <COLLECTION> <RECIPIENT> [--key PATH]` —
  issue one deterministic invoke-only READ grant from a configured READ
  root to an Ed25519 public key and insert that one self-contained proof;
  replaying the exact command is idempotent and writes no companion blobs.
- `pile collection grant-write <PILE> <COLLECTION> <RECIPIENT> [--key PATH]` —
  issue the symmetric deterministic invoke-only WRITE grant from a configured WRITE
  root to an author key.

#### Background maintenance

`maintain` works on just the selected collections. `maintain-all` also follows
their descriptor source links, preparing upstream collections first:

```sh
trible pile collection maintain self.pile blake3:<TARGET> --key self.key
trible pile collection maintain-all self.pile blake3:<RANK9> blake3:<SEARCH> --key self.key
trible pile collection maintain-all self.pile blake3:<RANK9> blake3:<SEARCH> --key self.key --watch
```

The final command stays in the foreground for a terminal, tmux, or a service
manager to supervise. `--interval-ms` sets the refresh interval (default 1000).
One pile stays open; unchanged snapshots do not rerun maintenance. A pass that
overlaps content changes schedules a catch-up pass at the next interval, so a
concurrent append cannot disappear behind the post-work snapshot. At rest, an
idempotent pass publishes nothing and clears that pending work.
Generic collection authority has no wall-clock expiry; arriving proof or
capability-definition evidence is a content change, not a separate timer.
Ctrl-C closes the pile normally. Independent targets continue when one fails;
watch mode reports that failure and retries when its observed inputs change.

Targets are explicit, not every historical index in a pile. Use an exact
descriptor handle for a newly registered target with no equations yet. A
Rank9 target leads to Succinct maintenance and source ensure; it does not
force merges in the foundational SimpleArchive unless that root was also
explicitly selected. This is scheduling around the normal operations, not a
mapping that secretly emits upstream artifacts.

Self-description supplies parameters, not executable code. The binary must
include the selected encoding and mapping implementation. The default build
includes the current Nomic semantic mapping; execution still obeys its compute
class and target WRITE policy. Application-specific mappings need their own
linked implementation. The local pile must have the required blobs; a separate
sync/custody process may bring them in, after which a watched pass can retry.
Reference-summary maintenance requires the producer's complete blob closure.

Readers can independently attach the resident rollup through
`snapshot.collection(target)?.view()`. They see the support already realized
in that snapshot, not a promise that a background pass has caught up.
The BM25 `collection search` command follows that same rule: new unindexed
source commits do not hide existing search results, and snippets come from
the index's realized support.

### Distributed pile sync

Built on `triblespace-net` (authenticated iroh QUIC, collection-scoped PATCH
anti-entropy, stock-gossip wakeups, and DHT provider lookup). Opening a
transport connection grants no collection authority. Each repair request names
one exact collection and may carry bounded native READ(C) proofs for cold
bootstrap. The server admits only from collection-scoped proof evidence in its
pinned local snapshot before disclosing a manifest or PATCH leaf. A new
self-contained proof lands inertly and can authorize a later retry; it never
changes admission for the immutable current session or creates blob WANTs.

- `pile net identity [--key PATH]` — print this node's iroh identity (auto-generates a key if missing).
- `pile net health <PILE> [--key REPORTING_KEY] [--max-age SECONDS]` — read local
  timestamped health observations without network probes. The reader accepts
  a maximum age of 180 seconds by default; set `--max-age` or
  `TRIBLESPACE_HEALTH_MAX_AGE_SECS` to change it. Future reports stay unknown,
  and any producer expiry annotations are ignored. Add
  `--health-key REPORTING_KEY` to `pile net sync` to publish once a minute.
  This is an existing durable reporting-author key, independent of the
  transport key. The private `swarm-health` collection is not activated for
  replication automatically. Reports distinguish a live host, serving
  snapshot, per-peer collection comparison, and DHT publication; matching
  records do not establish that every referenced blob is available.
- `pile net dashboard <PILE> [--key REPORTING_KEY] [--max-age SECONDS]
  [--sample COUNT] [--tui|--gui]` — freeze one read-only pile snapshot and show
  exact local blob residency, native COMMIT/MERGE/DERIVE readiness, and durable
  WANT completion beside the latest readable observer reports. The terminal
  renderer is the default. `--gui` launches `gorbie-cluster-health` (override
  its path with `TRIBLESPACE_DASHBOARD_GUI`). Missing outputs count as pending
  only when a durable WANT names the work; pairwise record roots remain
  separate from blob availability.
- `pile net sync <PILE> --collection HANDLE [--collection HANDLE ...] [--peers ID_OR_TICKET,...] [--key PATH] [--direction bidirectional|read-only|write-only]` — activate the named collections and run periodic repair. `read-only` pulls but does not serve collection repair, while `write-only` serves admitted readers but does not pull collection repair. Every direction still services ordinary exact-blob WANTs. `--duration SECS` and `--quiescent-for SECS` provide optional process-lifecycle bounds.

The exact repair state is the product of the collection's native-record and
collection-scoped authorization-evidence PATCHes.
Authorization repair carries complete self-contained READ(C)/WRITE(C) proof
records only, with no companion blob acquisition. The record PATCH contains
every valid signed COMMIT(C), while each receiver derives WRITE admission
locally; a later WRITE proof can therefore activate an older commit without
inventing a second synchronization protocol or requiring the publisher to
possess its grant.
Production peers subscribe to stock `iroh-gossip` topics keyed by the
domain-separated image of the collection handle; signed opaque-root
mismatches accelerate ordinary repair, while periodic anti-entropy remains
authoritative.

DHT routing, provider lookup, and direct GET by a known immutable handle are
collection-independent bearer mechanisms. In every repair direction, each
resident blob may publish an opaque KDF(H) lease with an H-bound endpoint
token. Direct GET sends
only that locator: the provider proves H first, the requester second, both
proofs bind the authenticated endpoints, and returned bytes must hash to H.
Collection READ(C) gates only collection anti-entropy, never exact GET. The
network host neither uses nor writes durable team/PEER routing state.

### Work with remote stores

#### Blobs

- `store blob list <URL>` — list objects at a remote store.
- `store blob put <URL> <FILE>` — upload a file to a remote store and print its handle.
- `store blob get <URL> <HANDLE> <OUTPUT>` — download a blob from a remote store.
- `store blob forget <URL> <HANDLE>` — remove an object from a remote store.
- `store blob inspect <URL> <HANDLE>` — display metadata for a remote blob.

See `INVENTORY.md` for notes on possible cleanup and future functionality.

## Development

Command implementations live in `src/cli/`, with pile, collection, migration,
network, and remote-blob modules. Contributions are always welcome!
