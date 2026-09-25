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
uses repair opcode `0x0E` on `/triblespace/pile-sync/27`; old repair opcode
`0x0D` is rejected before decoding. Generation 27 changed the blob locator,
directory token and exact-GET proofs to one-block constructions, so
generation-26 peers and installed `Leech` readers cannot connect and all
nodes switch together. No AUTH or collection-repair operation transfers
blob bodies or creates WANT; exact H remains the blob read capability.

DHT provider-directory operations use the ordinary blob-locator namespace,
KDF(H). There is no separate collection-participant advertisement. Collection
gossip bootstraps from descriptor policy roots, root/delegate endpoint keys in
validated scoped AUTH evidence, configured/recent contacts, and providers of
the descriptor blob H=C. A descriptor provider may only cache that blob: it is
a possible gossip contact, not a repair source or an authority grant. Each
exact-content lease carries a token derived from H and the provider endpoint,
which a requester who knows H verifies before dialing.

The exact stream never sends H. The authenticated provider proves knowledge of
H first, bound to both TLS endpoint identities; only then does the requester
return its independently domain-separated proof. A false locator advertiser
therefore cannot make the requester disclose H or masquerade as a provider.
Returned bytes are accepted only when they hash to H. READ(C) is not consulted
by exact GET and remains exclusively the collection-repair disclosure boundary.

## Repair and wake

State-based pairwise repair is authoritative anti-entropy. For each active
collection, the caller opens one bidirectional stream, establishes READ(C),
pins the returned record, authorization-evidence and resident-blob roots, and
walks differing PATCH nodes. Authorization leaves carry complete canonical
proof bytes; resident-blob leaves contain only H with an empty value. Inventory
walks have a separate 128-node allowance and retain a cursor across successful
passes. A changing remote inventory starts fresh Merkle validation above the
last visited handle, then wraps to earlier keys; continuous appends cannot keep
resetting progress to the first leaf. Progress does not depend on downloading
the hinted bodies first. Collection payloads never travel in this stream.

Production iroh peers use stock `iroh-gossip` membership with neighbor-only
messages on a version-isolated per-C topic. A 145-byte
nonce-v4 wake contains only version, signed origin endpoint, one opaque repair
root, and a fresh nonce. A mismatch schedules ordinary READ-authorized repair
from a fresh signed origin advertising that root. Several such origins share
the repair load through randomized selection; the immediate forwarding hop
is not presumed to hold the state. The wake itself grants no authority.

Each topic periodically offers its latest root with a randomized timer: the
interval grows from two to sixty seconds, transmission is in its second half,
and hearing an equal root suppresses that interval's redundant local offer.
Application relaying is separate: `(C, R)` is state identity, while the signed
repair contact and nonce are annotations. At most one latest observation per
origin is retained, with equal roots sharing a forwarding deadline. A receiver
allows repair up to five seconds, then relays the original signed offer if it
cannot serve that root. A published serving snapshot can instead supply its
own contact; a different resulting union root is advertised as that actual root.
Read-only or unauthorized bridges can relay without pretending to serve.

New neighbors force an offer. Retained hints have bounded replay opportunities;
equal evidence suppresses those repeats only when every known direct neighbor
has signed the same root itself. One upstream match cannot silence an unknown
downstream link. Stock gossip does not forward neighbor-scope payloads for us.
The opaque root covers all three PATCH summaries, including the partial resident
inventory; matching it proves neither complete payload closure nor admission.

Signed wake origins receive five-minute leases, renewed by subsequent notices
or successful repair. Healthy peers are not blindly pulled every thirty seconds;
that cadence retries failed repairs under backoff. Equal-root hints skip
unnecessary repair, but a prior failed exchange still gets a confirmation so
its failure is not silently retained as an unrecoverable health alert.

Bootstrap is retried even when a healthy subset remains: every five minutes,
or with one-to-sixty-second backoff without a viable repair source. At most
three descriptor lookups run, one per collection, with fair rotation among
due collections. These are recovery opportunities, not a guaranteed global
convergence deadline. Root keys need not be online; descriptor holders need
not participate. Ordinary gossip and READ admission establish the next step.

Stock `iroh-gossip` owns neighbor-loss healing and reports lag without closing
the subscription. The host responds to lag by advancing recovery and offering its current root,
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
targets come from signed wake origins, never from a descriptor-provider hint alone.
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
scan and reference-summary filtering are not part of this acquisition path.

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
- `collection_blob_inventory` — bounded passive resident-handle PATCH construction
- `collection_session` / `collection_wire` — one READ-authorized repair stream
- `patch_repair` — root-pinned Merkle difference walker
- `peer` — synchronous store wrapper, monotone admission, and local WANT intent
- `reconcile` — durable WANT observation and reproducible-operation fulfillment
- `provider` / `routing` — bounded bearer provider directory and XOR routing
- `protocol` — public direct-operation framing
- `host` — immutable overlays, connection pool, wake bridge, and scheduler
- `wake` / `wake_relay` / `wake_schedule` — signed neighbor offers and state-based relay timing
- `transport` — production iroh and deterministic simulation transports
- `identity` — persistent network signing-key handling
