# triblespace-net

Collection-scoped anti-entropy for TribleSpace over
[iroh](https://www.iroh.computer). A peer retains an immutable semantic repair
overlay for each explicitly active collection. One READ-authorized repair
stream exposes three pinned PATCHes: signature-valid exact-C records, scoped
native authorization proofs, and a positive inventory of locally readable
collection blobs. It transfers no blob bodies. The first two are grow-only
evidence; the inventory is a partial residency observation, not another
replicated collection. Record inclusion is independent of WRITE admission; each
receiver derives its active view locally after records and proofs arrive in
either order.

The user-facing surface is `Peer<S>`, a synchronous store wrapper backed by an
async host. `Peer::refresh` drains verified repair events and replaces the
immutable snapshots served to other peers without flushing the backend.
Successful local puts are visible before persistence; explicit `close` owns
the final persistence boundary, and a caller may still explicitly `flush` at
another chosen boundary. Refresh failures withdraw the serving observation;
`try_refresh` returns the error. There is no global team inventory, remote mutable
head, replica roster, or separate authority database.

## Getting started

Networking is a downstream capability and is consumed directly rather than
through the core TribleSpace facade:

```toml
[dependencies]
triblespace = "0.47"
triblespace-net = "0.47"
```

```rust,ignore
use triblespace_net::peer::{Peer, PeerConfig};

let pile = triblespace::core::repo::pile::Pile::open(path)?;
let mut peer = Peer::new(
    pile,
    signing_key,
    PeerConfig {
        peers: vec![bootstrap_endpoint],
        provider_publication_budget: None,
        bind: None,
    },
)?;
// The pile's sync selection decides whether the collection is peered.
peer.activate_collection(collection_handle);

loop {
    peer.refresh();
    std::thread::sleep(std::time::Duration::from_millis(100));
}
```

Activation is ephemeral process state. It writes no OFFER/GOSSIP marker and
does not create an ambient collection registry.

## Authority and disclosure

The QUIC/TLS connection authenticates endpoint identities but grants no team
or collection authority. Every collection repair request names exactly one
collection. The repair client may present bounded native READ(C) proofs for
cold bootstrap. Same-session admission uses only self-contained
collection-scoped READ proofs and capability definitions already pinned in the
server's local overlay. An unknown proof is ingested inertly and may authorize
a later retry, but it never changes admission for the immutable current session.
Missing definition blobs must become resident through the separate blob layer;
repair does not acquire them. The server verifies the TLS client before revealing a
manifest or PATCH leaf; the publisher itself needs no READ(C). Proofs are
non-secret authorization certificates. A caller without READ(C) receives no
collection manifest, PATCH leaf, record, authorization evidence, blob-inventory
handle, or component root;
merely knowing C grants no disclosure.

The AUTH inventory recognizes roots from every supported capability-policy
binding in the descriptor, not just READ and WRITE. Projection and receipt
check the exact resource, configured root, and signatures without interpreting
capability definitions. Grant handles may differ along a path and need not match
the descriptor's binding handles. Admission separately queries the bound
definition's invocation actions to select the requested action's roots, then
interprets each proof's invocation/delegation action sets. A custom grant does
not substitute for READ(C) unless it actually conveys READ under those roots;
quorum shares never borrow another action's roots. Capability definition blobs
are not fetched by repair.

The subordinate-resource transport candidate extends this overlay to proofs
for R when R's immutable descriptor declares `resource_collection: C` beside
its own policy bindings on the same entity. R's roots authenticate its proof;
READ(C) still gates the repair session, without granting any action on R.
A missing R descriptor defers the proof leaf with explicit incomplete AUTH
state, while collection-record repair continues. Blob arrival enables retry;
repair does not fetch R or require a mutable referencing fact in C.

Each overlay currently owns a repair-collection | proof-hash PATCH whose proof values
share the raw record's byte ownership. This is a validated membership projection,
not validation during Pile replay and not a shared global host index. Summaries
and repair nodes expose only C's fixed prefix; hashes bind the full keys while
wire keys and compressed paths omit that prefix. The three-component manifest
uses repair opcode `0x0E` on `/triblespace/pile-sync/28`; old repair opcode
`0x0D` is rejected before decoding. Generation 27 changed the blob locator,
directory token and exact-GET proofs to one-block constructions; generation 28
exports foundations only (COMMIT and DERIVE, never MERGE) and advertises each
collection's held-blob set, so older peers cannot connect and all nodes switch
together. No AUTH or collection-repair operation transfers
blob bodies or creates WANT; exact H remains the blob read capability.

DHT provider-directory operations use the ordinary blob-locator namespace,
KDF(H). There is no separate collection-participant advertisement. Peering
candidates for C are descriptor policy roots, root/delegate endpoint keys in
validated scoped AUTH evidence, signers of C's records, and providers of the
descriptor blob H=C. A descriptor provider may only cache that blob: it is a
candidate, not a repair source or an authority grant. Each exact-content lease
carries a token derived from H and the provider endpoint, which a requester
who knows H verifies before dialing.

The exact stream never sends H. The authenticated provider proves knowledge of
H first, bound to both TLS endpoint identities; only then does the requester
return its independently domain-separated proof. A false locator advertiser
therefore cannot make the requester disclose H or masquerade as a provider.
Returned bytes are accepted only when they hash to H. READ(C) is not consulted
by exact GET and remains exclusively the collection-repair disclosure boundary.

## Peering and announcements

Hosts reconcile a collection C only while both piles select it in the sync
selection register of their own configuration collection. Each pair of
endpoints keeps one connection, and the dialler's `recon/1` stream carries the
peerings, announcements and pull walks of every collection, and the grant
exchange.

A host asks up to five candidates to peer for each collection it selects:
grant-chain keys and record signers that pass READ under local evidence, then
the other grant-chain keys and signers, then DHT providers of the descriptor
blob H=C, each tier in an order shuffled under a fresh salt. The order is the
only retry state. A refusal, a failed dial or an ended peering is replaced by
the next candidate, and an exhausted order is drawn again at most once a
minute, which also looks up C's providers again. The acceptor admits a key that
passes READ for C, or one that sends and passes WRITE.

Neighbours announce C's root on a randomized timer that grows from two to sixty
seconds and that a local append resets. An equal announcement spares its sender
the next one. A different one starts a pull walk from the announcer and gets one
reply, which starts the reverse pull. A pull walk descends where the two PATCH
digests differ and lands what the store lacks as it goes. A lost announcement is
followed by the next one; nothing else is retried.

There is no local direction policy. A collection flows to a neighbour exactly
when this side admits it to read, and a pile that selects no collection peers
for none; it still publishes and serves resident exact blobs under bearer
handle H and services durable `Blob(H)` WANTs through the ordinary KDF(H) path.

Configured endpoint addresses bootstrap DHT routing only. Repair targets are a
collection's neighbours: candidates that select it and admit the asker.
Exact-content targets come from KDF(H) leases. Unrelated configured peers never
receive C or its proofs.

## Resident inventory and hydration

`Peer::refresh` advances a bounded passive local scan per active collection,
seeded by C and direct record/proof references. It follows an aligned 32-byte
word only when the local snapshot can read that exact H. It retains positive
PATCH state and resumable offsets, never probes absent words through the DHT,
and resets affected closure state when its readable membership may shrink.
This is conservative byte-level reachability, not semantic reference validation,
a completeness certificate, or ciphertext decryption authority.

Local replication remains explicit: `Demand` services WANTs, `Shallow` adds
selected records' direct references, and `Full` also acquires positive resident
handles learned through READ-authorized repair. Known handles share a bounded
four-wide exact-fetch window; ready bodies land before one final serving
refresh. Each collection's 4,096-handle window protects unattempted hints,
then advances past serviced prefixes even when those providers were unavailable.
A completed inventory pass permits wrapping to earlier keys only for its own
supplying peer; unrelated completions cannot reset that cursor. Hints are bounded,
partial and fallible. An empty hint backlog is not
proof of full recursive residency. The former speculative aligned-word network
scan is not part of this acquisition path.

## Exact content

A durable `WantRequest::Blob(H)` asks the reconciler to discover and obtain
those exact bytes through KDF(H). It needs no collection descriptor,
activation, or READ proof. Collection repair has no payload-replication mode:
receiving a record is evidence convergence, not a request to traverse or copy
its referenced blob graph.

All exact requests share the one `Blob(H)` identity. A successful landing
satisfies the durable request locally; failed discovery leaves it pending.
Collection membership, proof state, and admission are irrelevant to that
exact-content operation.

The reconciler retains retries, acquisition cursors and bounded positive hints,
not a second durable-answer set. Each tick derives missing work from its
selected required handles and the
store's readable contents; started futures own the in-flight set. It does not
flush after blob puts or when it first observes a local answer. The existing
selected-input `get` checks remain: a raw physical occurrence may be corrupt,
and Pile's normal read can find a valid later
duplicate. Thus this change removes durability policy/state, not the remaining
first-read validation/hash cost or every per-tick membership lookup.

The full model, wire formats, authorization boundaries, and CLI surface live
in the book's [Distributed Sync](https://docs.rs/triblespace/latest/triblespace/)
chapter.

## Diagnosing connection handoff

For a bounded connection-level investigation, enable:

```sh
export RUST_LOG=warn,triblespace_net=info,triblespace_net::handoff=debug,iroh::_events::conn::connected=debug,iroh::_events::conn::closed=debug
```

Iroh's `connected` event precedes socket-actor registration. The handoff target
distinguishes awaiting connection completion, registration, forwarding, and
host dispatch; an acknowledged QUIC handshake alone does not establish that a
request reached the handler. These events contain transport metadata, not
collection handles, blob capabilities, or request bodies. Per-stream arrival
and opcode events require `triblespace_net::handoff=trace` and are off in the
filter above. Keep the global `warn` fallback so dependency failures remain
visible without enabling broad packet-level tracing.

## Crate layout

- `collection_activation` — per-collection record and authorization-evidence PATCHes
- `walk` / `landing` — pull walks on `recon/1` and the task that lands their values
- `patch_repair` — root-pinned Merkle difference walker
- `peer` — synchronous store wrapper, monotone admission, and local WANT intent
- `reconcile` — durable WANT observation and reproducible-operation fulfillment
- `provider` / `routing` — bounded bearer provider directory and XOR routing
- `protocol` — public direct-operation framing
- `host` — immutable overlays, connection table, DHT client, and scheduler
- `peering` / `announce` / `wake_schedule` — per-collection peering, root announcements and their timer
- `grants` — the grant exchange on `recon/1`
- `transport` — production iroh and deterministic simulation transports
- `identity` — persistent network signing-key handling
