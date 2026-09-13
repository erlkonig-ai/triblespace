# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Accept uppercase hexadecimal recipient keys in collection READ/WRITE grants,
  matching the exact public-key spelling emitted by `pile signing-key init`.

### Added

- Add explicit `pile migrate <PILE> endorse-unsigned-equations` with an exact
  `--collection`, an existing `--signing-key`, and optional `--dry-run`. Require
  target WRITE at one frozen instant, skip missing direct references, and
  append deterministic signed equations without rewriting old bytes or
  claiming to recover their original producer. Identical retries append
  nothing and no equation is recomputed.

- Add read-only `pile verify <PILE>` to recheck every physical native
  COMMIT/MERGE/DERIVE signature and AUTH proof's signatures and path-local
  attenuation without resident dependencies, a signing key, clock validity,
  or collection-policy admission. Report unsigned legacy equations and opaque
  records as unchecked; blob hashes and legacy chains remain the separate
  `pile diagnose check` audit.

- Add local `pile net health` and opt-in `pile net sync --health-key` reporting
  as timestamped facts in a private collection. Distinguish missing, stale,
  and future reports from fresh observations without initiating any network
  probe.

- Add explicit `pile net sync --collection HANDLE` activation for
  collection-scoped repair. Repeat `--collection` to activate more than one
  exact descriptor.

### Changed

- Pass the explicitly loaded signing key through collection and local health
  maintenance so newly materialized MERGE/DERIVE equations carry its signature.
- Show MERGE/DERIVE authors in raw record inspection and verify their signatures
  alongside COMMITs in explicit `pile collection log` output.

- Let health readers select `--max-age SECONDS` (default 180, or
  `TRIBLESPACE_HEALTH_MAX_AGE_SECS`). Reports carry only `created_at`;
  legacy producer expiry annotations do not affect freshness.

- Name the new `LATEST_STATES_MAPPING_V1` algorithm in collection inspection,
  replacing the retired unshipped observed-only mapping name.
- Let each repair request carry bounded native READ(C) proofs only as cold
  bootstrap input. Same-session admission uses self-contained
  collection-scoped proof evidence pinned locally; newly supplied proofs land
  inertly and can authorize only a later retry, without companion blob WANTs.
  Direction now governs only collection repair, so all modes continue to
  publish, serve, and acquire exact H-addressed blobs. Signed COMMITs repair
  independently of WRITE admission; receivers derive activation locally and
  publishers need not hold their own grant.

### Removed

- Remove the unshipped `pile net inventory`, `pile net status`, team capability
  command family, team-scoped sync arguments, and blob mirror mode.

### Superseded during development

- Add `pile net inventory <PILE>`, a read-only probe that prints the bound team,
  canonical `/14` inventory generation, and count/root pair for PEER evidence,
  collection records, capability proofs, and blobs. Sampling fails closed if
  any sync-visible component or the team scope changes while the manifest is
  built.

- Add `pile migrate <PILE> seed-artifact-offers [--dry-run]`, an explicit,
  idempotent migration which recovers local OFFER intent from one frozen native
  collection-record and blob observation. It follows resident recursive
  closure only for strictly signed COMMIT dependencies, offers only direct
  MERGE descriptor/result and DERIVE target/output artifacts, skips and counts
  missing references without WANTs, and fails before writing on corrupt
  candidates.

#### Changed

- Keep team bootstrap one-step while separating transport from synchronization
  authority. `team create` now issues distinct CONNECT and SYNC_TEAM founder
  proofs; `team invite` delegates from two explicitly named parents and writes
  one strictly bounded, versioned artifact containing both bundles in fixed
  order; and `team join` verifies both completely before its first append-only
  store write. The artifact marker was minted with `trible genid` as
  `888807EA9891D3187A83408578CDD21B`.
- Port legacy branch migration and collection inspection to immutable,
  independent READ and WRITE policies. `--authority` is the direct root of
  both policies (defaulting to the signer); migration validates before target
  registration and preserves the exact legacy data, metadata, and entity ids.
- Use direct proof IDs throughout `team create`, `invite`, `join`, and `show`.
  Keyless claims hold semantic restrictions, native `K0 (S C K)+` proofs hold
  principal delegation, and invites carry the complete bounded proof bundle.
  Accepted claims and proofs are stored directly and remain exactly selectable
  without an auxiliary retention collection. Team roots live in private,
  durable key files instead of depending on secret material printed once to a
  terminal. `team join` takes the expected team root separately from the
  bundle, so an invitation can never nominate its own trust root.
- `pile net status` and `pile net sync` now require explicit
  `--connect-proof` and `--sync-proof` IDs under one `--team-root`, load both
  exact claim closures, and verify them for the local endpoint before
  networking. `sync` exposes only semantic
  policy—`--direction bidirectional|read-only|write-only` and `--blobs
  demand|mirror`—plus bootstrap routes and lifecycle bounds. Pairwise PATCH
  reconciliation is the epidemic exchange; there is no broadcast wake plane.
- Remove the separate `pile net custody` and `team replica` command families.
  The single team inventory now reconciles PEER evidence, collection records,
  capability proofs, and optionally blobs; durable operation WANTs observe the
  local record union and Demand blob WANTs remain exact authenticated fetches.

## [0.41.4] - 2026-05-17

### Fixed
- **`parse_peers` and `pile net pull <REMOTE>` now normalise
  inbound `EndpointAddr`s** via
  `triblespace_net::dot_stripped_endpoint_addr`. Tickets
  minted by older / unpatched peers can carry the dotted
  FQDN form embedded in their relay URL; we'd otherwise
  hand that dotted URL back to iroh's connect path and
  trip the receiving-side WAF. Pre-strip at the CLI
  boundary so the rest of the stack only ever sees
  HTTP-canonical URLs.

### Notes
- The matching outbound fix (so tickets we *mint* are
  dot-free) and the connection-reuse fix that resolves
  the "connect-loop" perf issue in pulls live in
  `triblespace-net 0.41.4`. See
  `triblespace-net/CHANGELOG.md`.

## [0.41.3] - 2026-05-17

### Fixed
- **Inherits trailing-dot fix from triblespace-net 0.41.3.**
  iroh's default relay hostnames were getting WAF-rejected
  because the trailing FQDN dot propagated into reqwest's
  `Host` header. Sandboxed `pile net sync` / `pile net pull`
  invocations now talk to iroh's default relay infrastructure
  without tripping WAF deny rules. See
  `triblespace-net/CHANGELOG.md` for the full story.

## [0.41.2] - 2026-05-17

### Fixed
- **`pile net sync --peers <EndpointTicket>` now actually
  bypasses discovery** for the supplied tickets. Previously
  (0.41.1) the sync command parsed tickets and threaded
  their `EndpointAddr` through to `PeerConfig.peers`, but
  the gossip / DHT bootstrap path inside `triblespace-net`
  used only the bare `EndpointId` for connect, falling back
  to iroh's discovery to find the addresses. As of 0.41.2,
  the ticket addresses are seeded into iroh's address
  lookup via `triblespace-net`'s new
  `StaticAddressLookup`, so the bootstrap connect resolves
  locally — no pkarr publish or DNS roundtrip needed.

### Notes
- This closes the "tickets work for pull but not sync"
  asymmetry from 0.41.1. Both commands now behave the same
  way w.r.t. ticket addresses.

## [0.41.1] - 2026-05-17

### Added
- **`pile net identity` prints an `EndpointTicket`** in
  addition to the bare pubkey. Carries only the id at
  identity-time (no relay/direct addrs); use the richer
  ticket printed by `pile net sync` at startup for
  direct-dial scenarios.
- **`pile net sync --peers <STR>`** accepts `EndpointTicket`s
  (the rich form, `endpoint…`) in addition to bare hex
  pubkeys. The address info is decoded but only the id is
  threaded into gossip bootstrap for now — address-cache
  seeding for sync's gossip path is a follow-up.
- **`pile net pull <REMOTE>`** accepts an `EndpointTicket` as
  the `<REMOTE>` argument. End-to-end discovery-free: the
  address info is threaded down to iroh's
  `Endpoint::connect`, so the pull works in
  sandbox / corporate-proxy environments where iroh
  discovery is blocked.
- **`pile net sync` prints a rich `EndpointTicket`** to
  stderr once the iroh endpoint is online (from
  triblespace-net's host loop) — id + relay URL + direct
  addresses. This is the form to share with a remote peer
  for direct dial.

### Notes
- `iroh-tickets 0.5` added as a dependency for ticket
  parsing.

## [0.41.0] - 2026-05-16

### Changed
- **Iroh family bumped 0.97 → 0.98** via `triblespace-net`
  0.41.0. Replaces the 0.40.3 Cargo.lock-shipping workaround
  with a real upstream resolution: `iroh-base 0.98` no longer
  pins to the broken `ed25519-dalek 3.0.0-pre.1`. See
  `triblespace-net/CHANGELOG.md` for details.

No surface CLI changes; same commands, same env vars, same
output.

## [0.40.3] - 2026-05-16

### Fixed
- **Ship `Cargo.lock` in the published crate** so
  `cargo install trible --locked` resolves a known-good
  transitive dependency tree. The 0.40.2 publish accidentally
  omitted the lockfile (workspace gitignores it; the publish
  clone had none); fresh resolution then picked
  `ed25519 v3.0.0` (released 2026-05-03) against
  `ed25519-dalek 3.0.0-pre.1` (hard-pinned by
  `iroh-base 0.97` via `=3.0.0-pre.1`), and the pair don't
  compile together — `ed25519::pkcs8::Error::KeyMalformed`
  became a tuple variant in `ed25519 3.0.0` but
  `ed25519-dalek 3.0.0-pre.1` still uses it as a unit
  variant. The shipped lockfile pins a working combination.
- `trible 0.40.2` is yanked from crates.io.

No source changes from 0.40.2 — same TLS-platform-verifier
fix carries through. The iroh upstream pin will eventually be
fixed by a `triblespace-net` bump to `iroh 0.98` or later
(both `iroh-base 0.98` and `1.0.0-rc.0` pin pre.6/pre.7,
which compile against `ed25519 3.0.0`). Deferred since the
lockfile fix is the minimum-disruption resolution.

## [0.40.2] - 2026-05-16

### Added
- **`tracing-subscriber` initialised at `main()` entry**, gated
  on the standard `RUST_LOG` env var via `EnvFilter`. Default
  filter is `warn`, so the CLI is quiet without configuration;
  `RUST_LOG=triblespace_net=info trible pile net sync …` lights
  up the auth handshake + per-op events introduced in
  `triblespace-net` Unreleased. Output goes to stderr so it
  doesn't interleave with command output on stdout. The
  `tracing-subscriber` dep was already declared in
  `Cargo.toml`; this commit wires it through.

## [0.38.0] - 2026-05-07

### Removed (breaking)
- **`pile net sync --topic` flag.** The gossip mesh is now
  identified by `TRIBLE_TEAM_ROOT` directly — every team has
  exactly one gossip mesh, derived from its identity. Users no
  longer pick + coordinate a separate topic string with
  invitees. Migration: drop the `--topic` flag from any sync
  invocation; the mesh topic is now always the team root
  pubkey. Falls back to single-user team-of-one (the node's
  own pubkey) when `TRIBLE_TEAM_ROOT` isn't set.

## [0.37.0] - 2026-05-06

### Added
- `team show <CAP_HEX>` — chain-walk diagnostic for a single
  capability. Prints each level (subject, issuer, scope,
  expiry, sig blob handle, cap blob handle) plus a
  signer-matches-issuer check at every step. Bounded by
  `MAX_DEPTH = 32`; embedded parent sigs at depth `N>0`
  render with `(embedded in level above)` rather than a
  separate handle. Complements `team list`'s summary view —
  use `show` when `list` reports a cap is present but a
  connection still fails.
- `team show --verify <PUBKEY_HEX>` runs `verify_chain`
  against the given team root and prints `✓ VERIFIED` or
  `✗ FAILED — <VerifyError>`. Same code path the relay's
  `OP_AUTH` uses; the result is the local-side rehearsal of
  what a real connection attempt would produce. Reads
  `TRIBLE_TEAM_ROOT` env var by default;
  `--expected-subject` overrides the default leaf-subject
  check for subject-substitution detection.
- `--version` / `-V` flag — basic CLI hygiene; prints the
  binary's `CARGO_PKG_VERSION` and exits.

### Changed
- `team list` now sorts capabilities by expiry
  soonest-first, surfaces `(revoker, target)` pairs for each
  verifiable revocation, and includes branch-scope details
  when a cap was issued with `--branch`.
- `team {create, invite}` echo the cap's expiry timestamp
  in the printed output so the operator sees rotation
  deadlines without an extra `team list` call.
- `pile net {sync, pull}` now read `TRIBLE_TEAM_ROOT` and
  `TRIBLE_TEAM_CAP` env vars consistently; missing-env
  diagnosis goes through `pile net status`.

### Documentation
- `README` documents `pile net` and `team` subcommand groups
  alongside the existing `pile branch` / `pile blob` /
  `store` sections.

## [0.36.0] - 2026-04-28
### Added
- `team` subcommand group for capability-based team management:
  - `team create` mints a fresh team root keypair, signs the founder's
    self-cap with admin scope, prints the team root pubkey + SECRET (to
    archive offline) + cap handles + the cap's expiry timestamp.
  - `team invite` issues a sub-cap to a teammate, delegating from the
    running node's own cap. Optional `--branch <BRANCH_HEX>` (repeatable)
    restricts the cap to specific branches.
  - `team revoke` issues a team-root-signed revocation against a pubkey,
    cascading transitively through any chain involving the revoked key.
  - `team list` audits the pile: per-cap details (issuer → subject,
    PERM_*/branches/expiry — sorted soonest-expiry-first) plus the
    `(revoker, target)` pairs for each verifiable revocation.
  - `team show --cap HEX` walks one chain end-to-end and prints
    each level (subject, issuer, scope, expiry, sig blob handle,
    cap blob handle, signer-matches-issuer check). Bounded by
    `MAX_DEPTH = 32`; embedded parent sigs at depth N>0 render
    with the `(embedded in level above)` label rather than a
    separate handle. The diagnostic deep-dive for "why is this
    cap rejected" — complements `team list`'s summary view.
  - `team show --verify <PUBKEY_HEX>` runs `verify_chain` against
    the given team root and prints `✓ VERIFIED` or `✗ FAILED —
    <VerifyError>`. The same code path the relay's `OP_AUTH`
    uses, so the result mirrors what a real connection attempt
    would see. Reads `TRIBLE_TEAM_ROOT` env var by default;
    `--expected-subject` overrides the default check (leaf cap's
    own subject) for subject-substitution-attack detection.
- `pile net sync` / `pile net pull` now read `TRIBLE_TEAM_ROOT` and
  `TRIBLE_TEAM_CAP` env vars for multi-user team operation; without them,
  fall back to single-user team-of-one (`team_root = signing_key.verifying_key()`).
- `pile net status` diagnostic subcommand: prints the node id, team
  root, and self_cap that the running peer would present on
  `OP_AUTH`, annotated with their source ("from TRIBLE_TEAM_ROOT"
  vs "single-user fallback" vs "NOT SET — remote will reject"). For
  debugging stuck-auth scenarios in one shot.
### Changed
- Pile-sync wire protocol bumped to v4 (`/triblespace/pile-sync/4`):
  every connection's first stream must be `OP_AUTH` presenting the
  caller's cap-sig handle; the server walks the chain back to the
  configured team root and either accepts (subsequent streams gated by
  the verified cap's scope) or rejects. Branch- and blob-level scope
  gates: `OP_LIST` / `OP_HEAD` filter by `granted_branches`, while
  `OP_GET_BLOB` / `OP_CHILDREN` reject blobs outside the reachable set
  from allowed heads (closes the raw-hash bypass).
- `team list`'s revocations section surfaces full `(revoker, target)`
  pairs, not just a count.

## [0.35.0] - 2026-04-18
### Added
- `pile branch reflog` command to list historical branch head updates (including tombstones) stored in a pile file.
- `pile branch journal` command to scan a pile for all branch update/tombstone records and report the latest state per branch id.
- `pile branch set` command to CAS-update a branch head to a specific branch-metadata handle (useful for recovery).
- `pile diagnose locate-hash` to scan raw pile bytes and report where a blob handle appears (header vs payload references).
- `pile net {identity, sync, pull}` subcommands for distributed pile sync over iroh (gossip + DHT + QUIC), built on `triblespace-net`.
### Changed
- `pile diagnose` is now a subcommand group (`check`, `locate-hash`) instead of a single command.
- `pile branch stats` now defaults to a fast path that reports accumulated content bytes and accumulated triple count from blob metadata (`length / 64`) without materializing commit payload tribles.
- `pile branch stats --full` retains the previous deep scan behavior for unique triples/entities/attributes.
- `trible` now lives in the `triblespace-rs` workspace as a first-class member, sharing the `Cargo.lock` with `triblespace-core` / `triblespace-net` / the facade. Dev experience: a single `cargo test --workspace` run exercises CLI, library, and protocol tests together.
### Fixed
- `pile create` now explicitly touches the target path before `Pile::open`. `Pile::open` stopped auto-creating files at triblespace-core 0.32.1 but the CLI hadn't been updated to match; `pile create` on a fresh path returned `No such file or directory`.
- `branch pull` does the same touch-before-open when the local pile is a fresh path.

## [0.12.0] - 2026-02-09
### Changed
- Updated CLI dependencies and replaced `rand` with `getrandom` for generating random ids and ephemeral signing keys.
- `pile branch create` now mints branch ids with `genid` (high-entropy random ids) instead of `ufoid` (time-prefixed ids).

## [0.11.1] - 2026-02-08
### Changed
- `pile branch list` now prints `id head name` for easier column alignment.

## [0.11.0] - 2026-02-08
### Added
- Initial changelog with Let's Changelog format.
- `pile merge` command to merge source branch heads into a target branch.
- Integration tests for `genid` and `pile list-branches` commands.
- `pile create` command to initialize new pile files.
- Note that `touch` on Unix can also create an empty pile file.
- `pile put` command for ingesting a file into a pile.
- `pile put` now memory maps the input for efficient ingestion.
- `pile get` command to extract blobs from a pile by handle.
- `pile blob inspect` command to show blob metadata like timestamp and size.
- `pile list-blobs` command to enumerate blob handles in a pile.
- `pile list-blobs` output now uses built-in `Hash` formatting.
- `pile diagnose` command to check pile integrity.
- `pile diagnose` now verifies that all blob hashes match.
- `pile diagnose` now exits with a nonzero code when corruption is detected.
- `pile migrate` command to apply idempotent pile metadata migrations.
- `pile migrate ... branch-metadata-name` migration to upgrade legacy branch-name metadata to `metadata::name` (LongString handle).
- `store blob list` command to enumerate object store contents.
- `store blob put` command to upload files to object stores.
- `store blob forget` command to remove objects from object stores.
- `store blob inspect` command to display metadata for remote blobs.
- `store blob get` command to download blobs from object stores.
- `store branch list` command to list branches in an object store.
- `pile branch create` command to create a new branch.
- `pile branch delete` command to delete a branch via a tombstone record.
- `branch push` and `branch pull` commands to sync branches with remote stores.
- Tests for branch creation and branch push/pull using a file object store.
- Logged an inventory task to provide a structured command overview in the README.
- Structured command overview in the README.
- Logged inventory tasks for inspection utilities, shell completions, progress reporting, and migrating to the published `tribles` crate.
- Renamed the future `store delete` command to `store forget` in the inventory.
- Step-by-step quick-start example in the README.
- `completion` command to generate shell scripts for bash, zsh, and fish.
- Test ensuring `pile blob list` outputs the exact handle for ingested blobs.
- Optional metadata output for `pile blob list`.
### Changed
- Versioning is now aligned with `triblespace` releases.
- Updated consolidate E2E test commits to pass optional metadata explicitly.
- Renamed `id-gen` command to `genid` to align with the GenID schema.
- Expanded `AGENTS.md` with sections from the Tribles project and a dedicated
  inventory subsection.
- Expanded crate metadata with additional keywords and categories.
- Removed explanatory comment about crate metadata from `Cargo.toml`.
- Increased default maximum pile size to 16 TiB.
- Fixed `pile put` compilation issues when using memmap.
- Renamed `pile pull` to `pile get` to avoid confusion with repository commands.
- Reworded inventory note about import/export commands to clarify blob
  transfers to piles and object stores via dedicated subcommands.
- Simplified `Pile::open` error handling now that `OpenError` implements
  `std::error::Error` upstream.
- `pile list-blobs` output uses lowercase hex instead of uppercase.
- `pile branch list` output now includes name and head commit in addition to the branch id.
- Pile commands reorganized under `branch` and `blob` subcommands.
- Store commands reorganized under `branch` and `blob` subcommands.
- Simplified file ingestion using `anybytes::Bytes::map_file` and removed
  the `memmap2` dependency.
- Split CLI command groups into modules under `src/cli`.
- Organized pile and store command implementations into submodules matching the CLI hierarchy.
- Consolidated pile-only branch commands under the `pile branch` subcommand.
- Rewrote README with a friendlier tone and clarified command list.
- Corrected pile file extension in README quick-start example.
- Deduplicated blob handle parsing across CLI modules.
- `pile blob put` and `store blob put` now print the blob handle after
  ingestion.
- Split CLI integration tests into smaller modules for readability.
- `pile create` now creates parent directories if they do not exist.
- Updated to latest `tribles` crate and imported required store traits.
### Removed
- Completed work entries have been trimmed from `INVENTORY.md` now that they are
  tracked here.
- Removed completed inventory item for crate metadata expansion.
- Removed inventory note for shell completions now that the feature exists.
- Removed note from README suggesting `touch` can create empty piles.
- Removed inventory entry for the old `diagnose` command now that the feature is
  implemented.
- Removed inventory item for the `pile list-blobs` command now that the feature
  exists.
- Removed inventory note for the `store blob forget` command now that the feature
  exists.
- Removed inventory notes for `store blob get` and `store blob inspect` now that those commands are implemented.
- Removed inventory note about `anybytes` helper integration.
- Removed stray `.orig` backup files from `src` and `tests` directories.
- Removed inventory note for a README quick-start example now that the section exists.
- Removed inventory note about offering an option for the `completion` command to write scripts directly to a file.
- Removed inventory entry for enhancing `pile blob list` with optional filtering.
