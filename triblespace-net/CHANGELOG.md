# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add opt-in demand, shallow, and full acquisition policy to the external
  `Reconciler`. Shallow hydrates selected structural collection-record roots;
  full streams their aligned recursive references with bounded speculative
  work and fair rescan passes. Explicit WANTs have their own service turn;
  implicit dependencies create no WANT records, and all bytes use the unchanged
  H-only bearer path.
  Proof possession alone never selects a collection or grants semantic admission.

- Add opt-in `triblespace_net::handoff` tracing across Iroh acceptance,
  socket registration, forwarding, and host dispatch. Stream/opcode events
  require trace level and never include request payloads or blob capabilities.

- Add collection-scoped anti-entropy over one direct stream. Each request
  may carry native READ(C) bootstrap proofs and, once admitted from pinned
  local proof evidence, pins the exact product of the native record and
  collection-scoped authorization-evidence PATCHes. Authorization repair
  carries complete self-contained proof bytes only and collection repair never
  transfers blob bytes. The record PATCH contains signature-valid exact-C
  COMMITs independent of WRITE admission.
- Add stock `iroh-gossip` wake subscriptions keyed by a domain-separated image
  of the collection handle. A 145-byte nonce-v4 signed origin wake carries one
  opaque repair root and accelerates the same bounded participant repair path;
  sampled periodic anti-entropy remains authoritative.
- Service durable `Blob(H)` requests through collection-independent exact
  provider lookup. Discovery uses the full-width domain-separated locator
  KDF(H), while H-bound endpoint tokens reject forged directory entries before
  dialing.

### Changed

- Remove ordinary per-blob and repair-drain disk flushes and the reconciler's
  retained durable-answer mirror. Local put/refresh visibility precedes the
  explicit close persistence boundary; manual flush and close still propagate
  their errors. Keep selected-input readable membership and corrupt-primary /
  valid-duplicate semantics, without changing bearer verification or concurrency.
  Failed snapshot refresh now returns its existing typed error and withdraws
  the serving view; remove obsolete pending-flush health state.

- Preserve the existing `Blob<UnknownBlob>` and its cached handle through
  interactive, descriptor and bulk landing, avoiding reconstruction and a
  second content hash. Bind capability responses to the requested handle;
  wire validation and Pile first-read validation remain unchanged.

- Experiment with authenticated FIND_NODE progress feeding exact-H directory
  and body discovery in a shared ALPHA window. Reserve routing capacity and a
  final-replica directory sweep; bound and deduplicate speculative requests.
  Expiry cancels only routing, while caller cancellation owns all work. No
  wire, cache, authority, receive-limit or live-throughput claim changes.

- Bound exact WANT/direct-root fetching to an experimental four-wide window
  within the current service class and shared deadline. Land each completed
  body through serial local insertion; deadline expiry
  cancels unfinished requests without consuming the unstarted tail. Peer fetch
  futures own network handles and remain inert until polled. Recursive scans
  retain their serial path and sixteen-attempt allowance; no throughput gain
  is claimed before measurement.

- Make `ReconcileDirection` govern collection repair only. Native `Blob(H)`
  discovery, provider publication, exact serving, and durable WANT service are
  orthogonal bearer operations available in every direction.
- Replace team-scoped connection authorization and global inventory with
  immutable per-collection repair overlays. Collection repair discovery
  uses one endpoint-bound KDF(C) lease per active served collection. Exact
  content has a separate global KDF(H) directory populated from resident
  blobs; exact GET consults neither collection identity nor READ(C).
- Move the incompatible direct protocol, including descriptor-defined AUTH
  paths and witness-bound signed equations, to ALPN `/triblespace/pile-sync/26`. Anti-entropy is
  receiver-authorized by READ(C).
  Exact bearer GET instead uses a provider-first, requester-second mutual
  proof of H bound to both authenticated endpoint identities; raw H never
  crosses TLS, and returned bytes must hash to H. Unsigned remote derived
  artifacts are not mirrored.

### Fixed

- Reuse selected collections' fixed repair components and READ bootstrap
  witnesses when their observed raw inputs are unchanged. Missing descriptors
  and definitions remain dependencies; record-only changes preserve authority
  work, and bootstrap shares the existing evidence construction. Every fresh
  host observation still advances its unobserved blob reader for later peer
  requests. Signature, policy, and quorum checks remain unchanged.

- Retain a started full-scan source's finite startup window across new positive
  arrivals and request/deadline yields. Its second word no longer falls behind
  a newer source on every turn. Ordinary rounds and collection rotation remain
  independent; EOF, unavailability or the existing 128-word allowance releases
  the startup position. Partial local-word quanta respect the remaining startup
  allowance. No request quota, deadline or concurrency is increased.

- Let an idle exact-blob body yield the shared scratch buffer to unrelated
  receives. Sixteen admitted body futures share one bounded 1 MiB scratch
  buffer; temporary backing is accounted separately through the final returned
  `Bytes` owner. Configured receive-limit exhaustion fails promptly without
  invalidating the authenticated provider connection. Cancellation and truncation
  release their resources; wire, bearer proof, hash and caller-deadline rules remain.

- Do not hold an already verified blob provider behind a stalled sibling
  `PROVIDER_GET`. Exact-H discovery progressively schedules bounded provider
  attempts as hints arrive, sharing three slots with directory queries and
  retaining a 64-provider total attempt cap. Pending hints are XOR-ranked, but
  the transient attempted subset can depend on reply order; canonical
  collection discovery is unchanged. Three stalled in-flight operations may
  still exhaust the caller deadline. No token, hash, memory or wire rule changes.

- Reserve whole fetch-budget turns for eligible WANTs, newly observed missing
  direct roots, ordinary direct-root rounds, and recursive scans. An existing
  root backlog cannot consume every recursive-scan turn; new roots get one
  first-attempt priority without postponing frozen ordinary rounds indefinitely.
  Re-observation does not renew priority, and all-backed-off classes are skipped.
  The unchanged request deadline means several 30-second quanta may still pass
  before a fresh root or nested body gets service; this is not a latency bound.

- Keep missing subordinate-resource descriptors from hot-looping AUTH repair
  or starving independent collection records. AUTH retains an explicit
  incomplete result and a bounded share of each stream; immediate continuation
  requires actual ingested evidence, otherwise the ordinary periodic repair
  cadence retries. No blob acquisition or WANT is added to repair.

- Reopen a collection's stock-gossip topic through its configured and learned
  bootstrap routes when every repair participant is lost. Recovery shares the
  existing discovery backoff and does not promote generic configured routes to
  collection participants.
- Treat absence of an authenticated remote DHT replica as one topology outage,
  not as an independent failure of every resident provider key. The publisher
  preserves the complete pending set behind one exponentially backed-off probe
  and resumes immediately when a compatible peer appears; authenticated remote
  `PROVIDER_PUT_FULL` rejections retain their bounded per-key retry semantics,
  while a responder disappearing after `FIND_NODE` remains a topology outage.

### Removed

- Remove CONNECT/SYNC_TEAM exchanges, `StoreScope`, durable PEER routing,
  broad blob mirroring, the collection-scoped Full/disclosure forest, inline
  collection-repair blob transfer, and the global PEER/record/proof/blob
  inventory wire protocol from the network host.

### Superseded during development

- Add policy-independent collection-record delta mechanics for the forthcoming
  READ-authorized overlay: strict sparse-record framing and COMMIT signatures,
  collection matching, valued-PATCH intrinsic-id deduplication, and bounded
  monotone PATCH difference. Large gaps return a repair decision instead of
  a full-set flood; MERGE/DERIVE content validation and READ/WRITE decisions
  deliberately remain outside this evidence codec.

- Make both connection authorization phases mutual without another handshake:
  successful CONNECT and SYNC_TEAM responses carry the server's bounded proof,
  verified against the configured team, exact action/resource, current time,
  and expected TLS endpoint before the connection or inventory session is used.
  Startup now rejects local outbound proofs for another endpoint or atom, and
  pooled remote authority is discarded when its effective validity expires.

- Add one SYNC_TEAM-authorized, four-component inventory for a dedicated team
  store. Canonical BLAKE3 PATCH roots cover `PEER(team, peer)` evidence,
  collection records, capability proofs, and resident blobs. Root-pinned node
  requests and bounded blob ranges fail closed when an immutable snapshot is
  unavailable. Record and proof PATCHes authenticate their key sets while
  retaining key-validated canonical bodies as immutable leaf values.
- Add semantic reconciliation QoS. PEER, collection-record, and proof
  inventories always participate in pulls; `BlobReconcileMode::Demand` leaves
  broad blobs out while durable WANTs use authenticated DHT provider lookup
  followed by exact reads, and `Mirror` also traverses and fetches the complete
  blob inventory.

#### Fixed

- Renew the complete provider-key publication set on an eight-hour sweep under
  a 24-hour lease, interleaving additions and retries so neither can starve old
  keys. Local directory acceptance no longer masks failed remote publication.
- Bound exact provider directories to 64 endpoints per key and a provisional
  aggregate soft cap while allowing one endpoint to publish more than 1024
  distinct keys. Exact-key expiry cleanup cannot be blocked by unrelated stale
  memberships.
- Route provider PUT and GET through the full 256-bit derived key instead of
  one of 256 fixed global prefix targets. Provider publication now uses bounded
  exact soft leases and a fair exact-key scheduler over resident handles.
  Replace the prefix
  PROBE/BODY exchange with one exact `PROVIDER_PUT` and move the incompatible
  pile-sync wire protocol forward.

- Keep bearer blob handles out of provider-directory queries. `PROVIDER_GET`
  carries an opaque global locator derived only from the handle; its DHT target
  is global as well. The final provider-facing `GET_BLOB` also sends only that
  locator and exchanges endpoint-bound mutual proofs, never the raw handle.

- Report checked-refresh scope conflicts to nonempty exact-derived attachment
  before ticket discovery or mutation, while preserving the same serving-view
  cleanup as ordinary refresh. All speculative cover-member fetches now share
  one absolute interactive deadline instead of renewing it per member.

- Fail closed when freezing a peer snapshot after a physical store-scope
  conflict, and revalidate the scope before an older snapshot records a WANT
  or lands fetched bytes. An externally concatenated conflicting scope can no
  longer be hidden by the scheduler's lossy refresh surface.

- Reobserve externally appended pile bytes before enumerating any inventory
  component, and expose a replacement serving snapshot only after one batched
  admission flush succeeds. A bounded event queue applies backpressure between
  network walks and the synchronous store.
- Accept normal `InvokeAndDelegate` SYNC_TEAM proofs wherever Invoke is
  requested, while still rejecting delegate-only authority. Exact blob reads
  now require the same connection-local SYNC_TEAM session as inventory reads;
  CONNECT alone discloses nothing.
- Start one direct sweep period immediately on the first installed snapshot,
  then admit at most `K = 20` peers per 30-second period through a stable
  identity cursor with at most eight live walks. Isolate failures per peer,
  respect bounded backoff at period boundaries, bound dial and operation
  deadlines, and evict failed pooled sessions without retaining or repeatedly
  scanning an all-peer pending queue.
- Enforce direction policy at the data boundary: read-only peers neither
  serve local inventory nor blobs; write-only peers never pull, demand-fetch,
  or admit inbound readers as durable PEER evidence.

#### Changed

- Bound the shared outbound connection pool to 64 fully reciprocal
  CONNECT+SYNC_TEAM-authorized sessions. Successful sessions use deterministic
  LRU residency; capacity retirement preserves in-flight shallow connection
  leases, while failure and expiry evict only the exact observed generation.
  CONNECT and SYNC_TEAM now initialize one terminal singleflight session, so a
  canceled second exchange cannot remain cached as a live half-authorized
  connection.

- Build replacement serving snapshots from
  `StoreSnapshot::changes_since`: changed components alone are enumerated,
  unchanged immutable inventory PATCHes are retained before construction, and
  every installed snapshot still carries fresh Blob access. A missing prior
  snapshot forces a conservative full build.

- Make provider-cover directory admission purely aggregate and work-conserving.
  Receivers now bound only live shard count and total live memberships; one
  provider may use all otherwise-free capacity. Replacement admits the exact
  `(directory - old shard + candidate)` weight, including at either boundary.

- Replace collection-evidence gossip, exact receipt RPCs, and the separate
  custody replica protocol with one periodic inventory anti-entropy path.
  Authenticated pairwise PATCH reconciliation is the epidemic exchange; the
  publisherless inventory-generation wake and iroh-gossip side plane are gone.
  Operation WANTs observe matching receipts through the local indexed
  collection-record union after refresh.
- Replace the split peer configuration with `PeerConfig { peers, team,
  connect_proof, sync_proof, qos }`. CONNECT admits the transport, then exactly
  one SYNC_TEAM exchange selects disclosure authority for that connection.
- Move pile sync to ALPN `/triblespace/pile-sync/14` for the incompatible
  reciprocal authorization and provider-cover protocol. Retain exact
  `GET_BLOB`, bounded inventory authorization/manifest/node/blob-range
  operations, and bounded `PROVIDER_PROBE`, `PROVIDER_BODY`, `PROVIDER_GET`,
  and `FIND_NODE`.
- Use configured endpoint addresses only as bootstrap routes. Authorized
  sessions and synchronized monotone PEER evidence add routing candidates but
  never authority, liveness, residency, or retention claims. DHT referrals are
  not periodic anti-entropy targets and become verified routes only after a
  direct authenticated response.
- Replace one soft lease per offered artifact with a canonical team-scoped
  provider cover. Active `OFFER ∩ resident ∩ serving` keys form at most
  256 first-byte PATCH shards; changed roots transfer one strictly validated
  full-key body, while equal roots renew in O(1). Prefix leases replace one
  immutable shard atomically, retain the prior valid shard after rejected
  replacements, and expire when omitted. A bounded rotating prefix scan checks
  exact membership without duplicating every key in an inverse index. Exact
  Demand reads route through the bounded XOR DHT by team and prefix and
  content-check the authenticated transfer. Cover reconstruction now follows
  only OFFER or Blob-component changes, and clearing the serving snapshot
  immediately stops renewal; unrelated inventory churn no longer rehashes the
  full offer set.
- Pipeline up to eight independently authenticated PATCH node reads on the
  existing inventory protocol and admit their out-of-order responses through
  bounded item/byte batches. Empty replicas now overlap each fixed frontier
  window rather than paying one network round trip per node, while one
  synchronous store drain retains one durability barrier and strict
  pinned-root/count checks.
- Cache pinned inventory roots as independent component snapshots and reuse
  unchanged non-blob component `Arc`s plus the Blob component's BLAKE tree.
  Its access-bearing wrapper is refreshed even when the root is unchanged, so
  compacted mmap/Yard generations can retire immediately on snapshot install,
  without waiting for another manifest request. Partial churn no longer retains
  up to 32 whole store snapshots or duplicate Blob access snapshots. History
  is bounded
  independently to eight roots per component, so one hot inventory cannot
  consume nearly the entire cache. Immutable reads no longer cross a global
  snapshot mutex; exact blob service returns `Bytes`, cloning a
  generic non-`Sync` snapshot only under a narrow component-local lock before
  payload lookup and validation. Superseded trees and backend leases are also
  carried outside pointer/cache locks before their potentially recursive drop.

## [0.41.4] - 2026-05-17

### Added
- **`pub fn dot_stripped_endpoint_addr(EndpointAddr) -> EndpointAddr`**
  re-exported at crate root. Strips trailing FQDN dots from
  any `TransportAddr::Relay` entries; pass-through for
  IP/custom entries. Idempotent. Apply at every channel
  boundary that emits or consumes an `EndpointAddr`.

### Fixed
- **Trailing-dot leak in outbound tickets.** 0.41.3
  stripped dots from the RelayMap iroh uses for its own
  connect path, but `ep.addr()` could still return an
  EndpointAddr whose `TransportAddr::Relay` had a dotted
  URL (the relay server reports its canonical URL back
  with the dot, and iroh stores that for self-address
  reporting). The ticket printed by `pile net sync`
  startup now normalises the addr first.

- **`fetch_reachable` opens one connection for the whole
  BFS** instead of one connection per CHILDREN / GET_BLOB
  call. Each `connect_authed` was ~600ms (TLS + QUIC +
  OP_AUTH + verify_chain), so a 30-blob walk hit the
  `pull_branch` 30s deadline before completing. With reuse,
  one auth covers the entire walk. iroh QUIC multiplexes
  streams; our `SnapshotHandler` already accepts multiple
  sequential bi-streams per connection (auth state is
  per-connection). DHT-fallback path in the per-blob
  `fetch_blob` helper is no longer on this hot path — it
  remains available for the single-blob `NetCommand::Fetch`
  RPC.

## [0.41.3] - 2026-05-17

### Fixed
- **Strip trailing dot from default relay hostnames.** iroh's
  `iroh::defaults::prod::default_relay_map()` ships URLs in
  FQDN-absolute form (`"euc1-1.relay.n0.iroh-canary.iroh.link."`)
  which propagates into reqwest's HTTP `Host` header on
  every relay probe. Strict WAFs (Anthropic's web-sandbox
  egress proxy, and likely others) 503 those requests,
  jamming `net_report`. `host.rs` now wraps the default map
  with `dot_stripped_default_relay_map()` and passes via
  `RelayMode::Custom(...)` instead of the preset's
  `RelayMode::Default`. Same upstream relays, HTTP-canonical
  request shape on the wire.

### Added
- `url = "2"` dep (for the host-rewrite transform).

## [0.41.2] - 2026-05-17

### Added
- **`address_lookup::StaticAddressLookup`** — an
  `iroh::address_lookup::AddressLookup` impl backed by a
  fixed `HashMap<EndpointId, EndpointAddr>`. Plugged into
  the endpoint builder via `address_lookup(static_lookup)`
  so iroh's connect path (gossip + DHT bootstrap +
  arbitrary `connect(id, ALPN)` calls) resolves bootstrap
  peers locally — no pkarr publish, no DNS roundtrip — when
  the caller supplied a full `EndpointAddr` (typically via
  an `EndpointTicket`). Layered on top of the N0 preset's
  pkarr+DNS providers, which still cover unknown peers.

### Changed (breaking — public API)
- **`PeerConfig.peers`** is now `Vec<EndpointAddr>` (was
  `Vec<EndpointId>`). Source-compatible for existing
  callers via `EndpointId: Into<EndpointAddr>`. Lets ticket
  addresses flow through to the static address-lookup
  provider above.

### Fixed
- The "sync needs discovery even when `--peers
  <EndpointTicket>`" gap from 0.41.1. Both `pile net pull`
  and `pile net sync` now bypass discovery for known
  ticket peers; unknown peers still fall through to the
  standard pkarr+DNS path.

## [0.41.1] - 2026-05-17

### Changed (breaking — public API)
- **`Peer::{track, pull_branch, list_remote_branches, fetch,
  head_of_remote}` and `resolve_branch_name`** now take
  `impl Into<EndpointAddr>` instead of bare `EndpointId`.
  Source-compatible for `EndpointId` callers via the standard
  `Into<EndpointAddr>` impl; new callers can pass a full
  `EndpointAddr` (with relay URL + direct addresses) to
  bypass iroh's discovery layer in environments where pkarr
  publish / relay probes are blocked.

- **`NetCommand::{Track, ListBranches, HeadOfRemote, Fetch}`**
  carry `EndpointAddr` instead of `EndpointId` on the wire.

- **`connect_authed`** + the private `fetch_blob`,
  `fetch_reachable`, `track_known_head` helpers in `host.rs`
  take `EndpointAddr`, threading address info down to iroh's
  `Endpoint::connect` so it can dial directly without
  resolving via discovery.

### Added
- **Rich `EndpointTicket` print at sync startup.**
  `host_loop` calls `ep.addr()` after `ep.online()` returns
  and writes a `ticket: …` line to stderr containing the
  full `EndpointAddr` (id + relay URL + direct addresses) as
  a standard iroh `EndpointTicket`. This is the form to paste
  into another peer's `--peers` flag for direct dial.

- `iroh-tickets 0.5` dependency for the ticket
  serialization.

## [0.41.0] - 2026-05-16

### Changed (breaking — transitive)
- **Iroh family bumped 0.97 → 0.98** (`iroh`, `iroh-base`,
  `iroh-gossip`) plus `iroh-blobs` 0.99 → 0.100, `irpc` 0.13
  → 0.14, `irpc-iroh` 0.13 → 0.14.

  Replaces the 0.40.3 Cargo.lock-shipping workaround with a
  real fix: `iroh-base 0.97`'s `=3.0.0-pre.1` pin on
  `ed25519-dalek` no longer compiles against
  `ed25519 v3.0.0` (released 2026-05-03 — `KeyMalformed`
  changed from unit to tuple variant). `iroh-base 0.98`
  re-pins to `=3.0.0-pre.6`, which is API-compatible.

  No surface API changes for consumers — `PeerConfig`, the
  `Peer` type, and the protocol handler stay the same.
  Iroh's `Endpoint::builder`, `presets::N0`,
  `CaRootsConfig::system()`, and `ProtocolHandler` all kept
  their shape across the iroh minor bump.

  Verified: 17 lib + 2 + 3 integration tests + the e2e auth
  handshake suite over `TestNetwork` all pass; `cargo install
  trible --locked` from the 0.41.0 workspace succeeds without
  the lockfile workaround.

## [0.40.2] - 2026-05-16

### Fixed
- **TLS roots now come from the OS trust store** via
  `rustls-platform-verifier`, instead of the compiled-in Mozilla
  `webpki-roots` bundle. The `platform-verifier` feature on the
  iroh dep is enabled, and `host.rs` calls
  `Endpoint::builder(...).ca_roots_config(CaRootsConfig::system())`.

  Why: corporate-proxy / sandbox environments (e.g. Anthropic
  web-sandbox egress) present a custom CA at TLS interception.
  webpki-roots is a frozen Mozilla snapshot and ignores the OS
  store, so iroh's relay HTTPS probes and pkarr publish/lookup
  fail with `invalid peer certificate: UnknownIssuer`, discovery
  dies silently, and the QUIC peer handshake never starts.
  Reading the OS store at runtime lets admin-installed roots
  (and the sandbox CA) participate. macOS uses the Security
  framework, Linux reads `/etc/ssl/certs`, Windows reads the
  certificate store. Standard Mozilla roots remain trusted on
  all three since they're already in the OS store.

  Reported and diagnosed by another Claude instance running in
  the Anthropic web sandbox after seeing the
  `WARN [...] UnknownIssuer` lines from the new tracing
  surface — exactly the kind of failure the previous
  Unreleased tracing-instrumentation work was supposed to
  surface, and did.

### Added
- **Tracing instrumentation across the auth handshake and op
  surface.** `SnapshotHandler::accept` opens an `info`-level
  `connection` span (`peer`, `alpn`); each `serve_stream` call
  enters a `debug`-level `stream` span carrying the op name
  (`AUTH`/`LIST`/`HEAD`/`GET_BLOB`/`CHILDREN`). Auth events fire
  at `info` (auth ok, granted-branch count, unrestricted flag)
  or `warn` (auth rejected with the inner `VerifyError` reason,
  peer-pubkey-parse failure). Per-op events log at `debug` for
  normal traffic and `warn` on scope-deny so out-of-scope
  branch / blob requests surface immediately.
- **Stream span duration = op latency** by construction —
  subscribers that record span timings (`tracing-subscriber`'s
  `FmtSpan::CLOSE`, `tracing-flame`, `tracing-opentelemetry`,
  Tokio Console) get per-op latency observability without
  further instrumentation.
- **Client-side `connect_authed` is now a `info`-level span**
  with `peer` field; emits structured `warn` events on
  connect failure and auth-handshake failure with the inner
  error preserved.

### Changed
- The 12 `eprintln!("[net] …")` ad-hoc log calls in
  `host.rs` (gossip neighbor up/down, hash-mismatch warnings,
  fetch errors, the catastrophic bind/connect failures, the
  stream handler error) are converted to `tracing` events at
  appropriate levels (`info` for normal lifecycle,
  `warn` for protocol-level anomalies, `error` for
  thread-fatal failures). The `[net]` prefix is dropped — the
  subscriber handles formatting.
- The two remaining stray `eprintln!`s in `identity.rs` (the
  one-time "generated new node key" notice on first startup)
  and `tracking.rs` (the stale-tracking-update skip
  diagnostic) are also converted to `tracing` events
  (`info` and `debug` respectively). `triblespace-net`'s
  `src/` tree no longer contains any `eprintln!`s — every
  diagnostic surface now flows through the subscriber.

## [0.38.0] - 2026-05-07

### Changed (breaking)
- **`PeerConfig.gossip_topic: Option<String>` →
  `PeerConfig.gossip: bool`.** The gossip topic is now derived
  from `team_root` directly (an ed25519 pubkey is already 32
  uniform bytes — perfect as a `TopicId`, no hashing needed),
  so users no longer pick + coordinate a separate topic
  string. One identifier per team handles both auth (cap
  chain) and rendezvous (gossip mesh) — no way to join the
  right team on the wrong gossip channel and silently see no
  HEAD updates.
  Migration: `gossip_topic: Some(_)` → `gossip: true`,
  `gossip_topic: None` → `gossip: false`.

## [0.37.0] - 2026-05-06

The auth-arc tests-and-polish release. No protocol changes —
pile-sync stays at v4 with the auth model from 0.36.0 — but
the testing surface and the runtime ergonomics matured
substantially.

### Added
- **End-to-end iroh auth tests un-ignored.** Three tests
  (smoke handshake + AUTH_OK + AUTH_REJECTED) pass green over
  real `TestNetwork` endpoints using the
  `/triblespace/pile-sync/4` ALPN. Catches QUIC-stream-level
  regressions that the lib-only tests miss. The lesson saved
  for future test authors: helpers must return `(router,
  endpoint, connection)` — dropping an iroh `Endpoint` tears
  down all its owned `Connection`s silently, so a helper
  returning only the `Connection` produces tests that fail
  for non-obvious reasons.
- **Runnable `Peer` doctest** showing the canonical
  construction shape (`PeerConfig { team_root, self_cap,
  peers, gossip_topic, revoked }`).

### Changed
- **Live revocation pickup** every `Peer::refresh` (auto-called
  on every read or write through the Peer). The update path
  rescans the snapshot for `(rev, sig)` blob pairs signed by
  the configured team root and unions them into the live
  revoked set. A revocation gossiped into the pile is
  therefore picked up on the next snapshot refresh — no
  relay restart.
- **Reachability BFS amortised across `OP_CHILDREN` responses.**
  The blob-level scope gate's reachability scan was previously
  recomputed per request; it's now cached across responses
  within one connection so a peer fetching many children pays
  the BFS once.
- **`PeerConfig` doc surface** points at `Peer::new` and
  records the deliberate "no `Default` impl" rationale (every
  construction site must specify a team root because auth is
  mandatory).

## [0.36.0] - 2026-04-28

The 0.36 line is the **chain-of-trust capability auth** release. Wire
protocol bumps to v4 with mandatory authentication on every connection;
the relay now enforces branch- and blob-level scope gates derived from
the verified cap. See `triblespace-rs/book/src/capability-auth.md` for
the user-facing chapter and the
[`triblespace_core::repo::capability`](https://github.com/triblespace/triblespace-rs/blob/main/triblespace-core/src/repo/capability.rs)
module for the auth-lib design rationale.

### Breaking
- **Pile-sync ALPN bumped to `/triblespace/pile-sync/4`.** Connections
  on `/3` are no longer accepted. v4 requires `OP_AUTH` as the first
  stream of every connection (presenting the caller's cap-sig handle)
  before any other op is served. Pre-v4 peers must upgrade.
- **`PeerConfig` no longer implements `Default`.** Every construction
  site must specify `team_root: VerifyingKey`, `revoked: HashSet<…>`,
  and `self_cap: RawHash`. The CLI's single-user fallback sets
  `team_root = signing_key.verifying_key()` and `self_cap = [0u8; 32]`,
  but library callers must opt in explicitly.

### Added
- **Server-side auth handler** (`SnapshotHandler`): on every incoming
  connection, the first stream is verified via
  `triblespace_core::repo::capability::verify_chain` against the
  configured `team_root`. Subsequent streams inherit the verified
  cap for the connection's lifetime; un-authed streams are silently
  closed.
- **Client-side `connect_authed`**: every outgoing op uses a single
  helper that does `ep.connect(...)` + `op_auth(self_cap)` so the
  auth round-trip is automatic on `Track`, `ListBranches`,
  `HeadOfRemote`, and `Fetch`.
- **Two-tier scope gate** in the protocol handler:
  - **Branch level** (`OP_LIST`, `OP_HEAD`): filtered by the verified
    cap's `granted_branches` set; out-of-scope branches are dropped
    from `OP_LIST` and surface as `NIL_HASH` on `OP_HEAD`.
  - **Blob level** (`OP_GET_BLOB`, `OP_CHILDREN`): a per-op
    reachability set (`reachable_set_for`) is computed once from the
    allowed branch heads via 32-byte-chunk BFS, and each candidate
    hash is checked for `O(1)` HashSet membership. Closes the
    raw-hash bypass that the branch-level gate alone left open.
- **Live revocation propagation**: `NetSender::update_snapshot`
  rescans every new snapshot for `(rev, sig)` blob pairs signed by
  the configured team root and unions them into the live
  `revoked: Arc<RwLock<HashSet<VerifyingKey>>>` shared with the
  handler. A revocation gossiped into the pile takes effect on the
  next snapshot refresh — no restart.
- **17 lib tests** in `host.rs::tests`:
  - Snapshot → verify_chain glue (3 tests)
  - Branch-level scope gating (3 tests, plus 1 admit-nothing edge case)
  - Blob-level reachability gate (3 tests)
  - Runtime revocation pickup (2 tests)
  - **End-to-end QUIC handshake** over iroh's `TestNetwork` custom
    transport (3 tests + 1 smoke echo): valid cap → AUTH_OK; zero
    cap → AUTH_REJECTED; foreign-root cap → AUTH_REJECTED.

### Changed
- `PeerConfig` gains `team_root: VerifyingKey`, `revoked: HashSet<…>`,
  `self_cap: RawHash` fields.
- `NetSender` carries the `team_root` and a shared `Arc<std::sync::RwLock<…>>`
  for the revoked set so `update_snapshot` can extend it from sync code
  while the async handler reads via brief read-clone-drop.
- `AnySnapshot` trait gains `all_simple_archive_blobs()` for the
  revocation rescan path.
- Lock primitive on `revoked` switched from `tokio::sync::RwLock` to
  `std::sync::RwLock` — sync-and-async accesses both safe (the async
  reads are read-clone-drop with no guard held across `.await`).

### Internal
- `dev-dependencies`: added `iroh = { features = ["test-utils",
  "unstable-custom-transports"] }` so the e2e auth handshake tests
  can run two endpoints on iroh's in-memory `TestNetwork` transport
  (no DNS, no relays, no IP). Plus `hifitime` for cap-expiry test
  helpers.
