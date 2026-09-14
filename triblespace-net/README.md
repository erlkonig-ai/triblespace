# triblespace-net

Collection-scoped anti-entropy for TribleSpace over
[iroh](https://www.iroh.computer). A peer retains an immutable semantic repair
overlay for each explicitly active collection. One repair stream reconciles
the exact product of two grow-only PATCHes: signature-valid exact-C collection
records and native proofs for exact resource C rooted in its declared policies. It transfers
no blob bytes. Record inclusion is independent of WRITE admission; each
receiver derives its active view locally after records and proofs arrive in
either order.

The user-facing surface is `Peer<S>`, a synchronous store wrapper backed by an
async host. `Peer::refresh` drains verified repair events, crosses one storage
flush barrier, and only then replaces the immutable snapshots served to other
peers. There is no global team inventory, remote mutable head, replica roster,
or separate authority database.

## Getting started

Networking is a downstream capability and is consumed directly rather than
through the core TribleSpace facade:

```toml
[dependencies]
triblespace = "0.47"
triblespace-net = "0.47"
```

```rust,ignore
use triblespace_net::peer::{
    Peer, PeerConfig, ReconcileDirection, ReconcileQos,
};

let pile = triblespace::core::repo::pile::Pile::open(path)?;
let mut peer = Peer::new(
    pile,
    signing_key,
    PeerConfig {
        peers: vec![bootstrap_endpoint],
        qos: ReconcileQos {
            direction: ReconcileDirection::Bidirectional,
            ..ReconcileQos::default()
        },
    },
)?;
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
collection manifest, PATCH leaf, record, authorization evidence, or root;
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
repair does not fetch R or require a mutable referencing fact in C. This is a
source candidate, not a claim of completed validation or deployment.

Each overlay currently owns a repair-collection | proof-hash PATCH whose proof values
share the raw record's byte ownership. This is a validated membership projection,
not validation during Pile replay and not a shared global host index. Summaries
and repair nodes expose only C's fixed prefix; hashes bind the full keys while
wire keys and compressed paths omit that prefix. The changed proof grammar and
AUTH key hashing use `/triblespace/pile-sync/25`. No AUTH or collection-repair
operation requests blobs or creates WANT; exact H remains the blob read capability.

DHT `FIND_NODE` and provider-directory operations use two independent opaque
namespaces. KDF(C) locates participants for READ(C)-authorized collection
repair. KDF(H) locates providers of exact resident content without naming a
collection. Each exact-content lease carries a token derived from H and the
provider endpoint, which a requester who knows H verifies before dialing.

The exact stream never sends H. The authenticated provider proves knowledge of
H first, bound to both TLS endpoint identities; only then does the requester
return its independently domain-separated proof. A false locator advertiser
therefore cannot make the requester disclose H or masquerade as a provider.
Returned bytes are accepted only when they hash to H. READ(C) is not consulted
by exact GET and remains exclusively the collection-repair disclosure boundary.

## Repair and wake

Periodic pairwise repair is authoritative anti-entropy. For each active
collection, the caller opens one bidirectional stream, establishes READ(C),
pins the returned record and authorization-evidence roots, and walks only
missing PATCH nodes. Authorization leaves carry canonical native proof bytes
only; each leaf is a complete signed path. Collection payload blobs never
travel in this stream.

Production iroh peers also subscribe to stock `iroh-gossip` topics keyed by a
domain-separated one-way image of the 32-byte collection handle. A 145-byte
nonce-v4 wake contains only version, signed origin endpoint, one opaque repair
root, and a fresh nonce. A mismatch schedules ordinary
READ-authorized repair from that signed origin; the wake itself carries no
authority or collection state. Missed or lagged wakes are harmless because
bounded sampled anti-entropy through leased signed wake origins remains active.

The host samples exact PATCH repair every 30 seconds. Signed wake origins and
KDF(C)-discovered endpoints receive five-minute participant leases, and every
successful repair—including an already-identical repair—renews the lease.
KDF(C) discovery is therefore a bootstrap and recovery path, not a heartbeat:
one lookup runs on initial activation or process restart, after every candidate
lease expires, or after every still-leased candidate has failed repair. Failed
discovery retries use one in-flight lookup per collection and exponential
backoff from one to 60 seconds. A healthy collection performs no periodic DHT
traversal.

Stock `iroh-gossip` owns neighbor-loss healing and reports lag without closing
the subscription. The host responds to lag by advancing ordinary exact repair,
not by replacing the mesh protocol. Configured endpoints and bounded recent
signed or DHT-discovered origins remain bootstrap candidates if a topic stream
does end and must be subscribed again. Configured iroh relays are transport
paths, not collection participants or rendezvous identities.

Direction is local policy:

- `Bidirectional` pulls active collections and serves admitted readers.
- `ReadOnly` pulls but does not serve local collection state.
- `WriteOnly` serves admitted readers but does not initiate collection repair.

This direction applies only to collection repair. Every mode may publish and
serve resident exact blobs under bearer handle H, and every mode may service a
durable `Blob(H)` WANT through the ordinary KDF(H) path.

Configured endpoint addresses bootstrap gossip and DHT routing only. Repair
targets come from signed wake origins or endpoint-bound KDF(C) leases.
Exact-content targets come from KDF(H) leases. Unrelated configured peers never
receive C or its proofs.

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
- `collection_session` / `collection_wire` — one READ-authorized repair stream
- `patch_repair` — root-pinned Merkle difference walker
- `peer` — synchronous store wrapper, durable admission, and local WANT intent
- `reconcile` — durable WANT observation and reproducible-operation fulfillment
- `provider` / `routing` — bounded bearer provider directory and XOR routing
- `protocol` — public direct-operation framing
- `host` — immutable overlays, connection pool, wake bridge, and scheduler
- `transport` — production iroh and deterministic simulation transports
- `identity` — persistent network signing-key handling
