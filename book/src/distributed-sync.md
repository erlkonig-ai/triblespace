# Distributed Sync

`triblespace-net` synchronizes collections rather than exposing one ambient
store inventory. Its protocol follows the same decomposition as the collection
model:

1. stock `iroh-gossip` announces that an endpoint has a new opaque state for
   one collection;
2. one READ(C)-authorized PATCH walk repairs the exact evidence which can
   change that collection's value; and
3. exact blob handles fetch only the immutable bytes a resolver actually
   chooses through a collection-independent, mutually authenticated bearer
   protocol.

No global team, mutable roster, durable OFFER/GOSSIP bit, or second replicated
inventory is needed. The collection descriptor already states independent
READ and WRITE policy, and iroh authenticates the endpoint key on each direct
connection.

## Four independent capabilities

The boundaries are deliberately small:

```text
know C           -> join C's wake topic and learn (origin, opaque state root)
prove READ(C)    -> receive and repair C's authorization evidence
know H           -> derive its opaque locator, discover providers, and authorize H
satisfy WRITE(C) -> make a signed COMMIT, MERGE, or DERIVE active in C
```

`C` is the exact 32-byte collection descriptor handle. `H` is an exact blob
handle. They name immutable objects but do different jobs: `C` discovers a
collection participant, while `H` is the bearer
capability and private discovery secret for one exact immutable value. The
provider directory sees only separately domain-separated KDF images and
endpoint-bound tokens, never either raw handle.

READ and WRITE are independent `AdmissionPolicy` values embedded in the
descriptor. Each is either `Open` or a canonical quorum over Ed25519 roots with
one semantic threshold. A derived collection chooses its own policies. Source
ancestry, routing knowledge, and possession of a blob do not silently supply
collection authority. Downstream delegation is a restriction signed into each
proof path, not a second descriptor threshold.

Local stores remain permissive grow-only ledgers. They may contain a COMMIT
whose signer does not currently satisfy WRITE(C), or a proof irrelevant to any
resident collection. Admission is applied when a snapshot is observed. Later
proof evidence may activate an old commit without rewriting or retracting it.

## The collection repair product

For one collection, semantic repair derives two independent grow-only sets:

- every structurally valid native collection record naming exact C: signed
  `COMMIT`, `MERGE`, and `DERIVE` records independent of current WRITE(C)
  admission; and
- every signature-valid native proof scoped to exact resource C and beginning
  at a root named by C's supported policy bindings, without requiring its grant
  handles to match those bindings. Subordinate-resource transport
  also includes proofs for R whose immutable descriptor declares C as its repair
  audience, under R's own policy roots.

Each set is represented by an immutable BLAKE3-Merkle PATCH. Collection
records are keyed physically by the full 32-byte fingerprint of their exact
canonical value; authorization evidence uses a `repair_collection | proof_hash` PATCH
whose values share ownership of the original proof bytes. Only C's prefix is
exposed; the wire leaf key is the 32-byte proof hash and its payload is the
complete native proof body. The host currently keeps one such index per
overlay, not a shared global inventory. There is no companion claim blob or
authorization closure to transfer. The opaque semantic repair root
commits to C, both PATCH roots, and both leaf counts under a versioned domain.

The authorization projection authenticates proof bytes rather than taking a
snapshot of who is admitted. Unavailable definitions, delegate-only grants,
and quorum-incomplete paths remain evidence. Admission separately interprets
the definitions' invocation and delegation action sets under the requested
action's policy roots. Generic authority has no clock. Each root path is
evaluated independently; no fixed-point over sibling paths can create
delegation support.

The only initial handoff is the delegation itself: a grantor may give the new
subject the self-contained proof bytes. That is the capability invitation
boundary, not a Secrets-specific delivery channel. Once one collection
participant has the proof, authorization-evidence repair distributes that one
record to READ(C) peers. Interpretation needs any referenced capability
definitions to be resident, but this record-only repair stream neither fetches
nor carries them. An application may use the same proof kernel for another
resource, such as Secrets key delivery, without treating collection READ as
decryption authority.

Subordinate-resource transport reads R's `resource_collection: C`
and its policy bindings from the same descriptor entity, without requiring a
mutable referencing fact in C. It defers a proof when R's descriptor is absent
and marks AUTH repair incomplete, while C's record repair continues. Later
ordinary blob arrival permits retry; AUTH does not fetch R or emit WANT.
The session is still gated by READ(C), not by R's action. A deferred AUTH leaf
does not mark the peer's authorization root reconciled. Open action policies
remain explicitly non-enumerable.

This product matters. Synchronizing only collection records would miss the
case where a newly arrived proof activates an old COMMIT. Synchronizing a whole
proof store would disclose unrelated capability structure. The complete repair
algebra is therefore `Record × AuthorizationEvidence`, with both components
scoped to C. The receiver always derives its admitted view locally; record and
proof arrival therefore commute, and a publisher need not possess or present
its own WRITE grant merely to replicate an inert signed record.

The host also updates these components independently. When a store snapshot
reports unchanged collection records, its existing record PATCH is shared into
the next repair overlay without re-enumeration or Merkle hashing. Blob arrival
still refreshes the authorization observation: a newly resident capability or
subordinate-resource descriptor can enable admission or proof routing without
changing any record. Cold collection activation constructs both components.

Signed MERGE and DERIVE records are input-record-bound endorsements and
first-class members of the exact-C record PATCH and ordinary collection
repair. Once present in a record store, an equation is reusable materialized
LSM work; warm readers do not execute its join or mapping again. A frozen
semantic view admits target producers under WRITE and follows only the exact
native records their witnesses name. That closure establishes foundational
support without rechecking ancestral producer authority or loading ancestral
payloads, metadata, or proof definitions. Materialization needs the selected
output and its encoding-required dependencies, not every historical input.
Missing or mismatched witnesses remain unknown support. READ permission to
participate in repair is not permission to endorse an equation. Signature
verification happens when decoding foreign record bytes, not when rebuilding
the local repair PATCH or observing the local store again.

This combined equation/AUTH-v5 epoch uses `/triblespace/pile-sync/26`. Dense
record tag 6 carries a 288-byte MERGE body and tag 7 a 224-byte DERIVE body;
each wire value has one additional tag byte. MERGE signs two input-record
fingerprints paired with its payloads; DERIVE signs one. Unsigned tags 2/3 and
payload-only signed tags 4/5 are retired, not alternate encodings of the new
endorsement. COMMIT's 192-byte body and signature transcript are unchanged.
Native piles retain historical equations as inert or opaque evidence; an
authorized producer must explicitly issue a witness-bound endorsement before
that historical work participates in the current repair algebra.

Repair still transfers only records naming exact C. A DERIVE's source witness
does not authorize disclosing another collection's records to a READ(C)-only
recipient. The witness fingerprint is not a blob handle and is not fetched
through the blob DHT. A replica lacking that record closure cannot claim exact
support merely because it received the output endorsement; source-record
provisioning remains a separately authorized concern. In particular, the current
protocol does not automatically transport a cross-collection witness closure.

## Opaque wakes over stock gossip

The `iroh-gossip` topic ID is a domain-separated one-way image of the collection
handle. Anyone who knows C can derive and join that topic, while generic gossip
routers do not learn raw C. There is no authorization handshake merely to hear
that something changed. The application payload is fixed width (145 bytes):

```text
version:u8 || endpoint_origin:32 || repair_root:32 || nonce:16 || signature:64
```

The collection handle is not repeated in the envelope, but it is included in
the signature transcript. Replaying identical bytes on another collection
topic therefore fails verification. The origin is the same Ed25519 identity as
the iroh endpoint and tells receivers which peer can answer repair.

A wake contains no record, proof, blob handle, leaf count, component root, or
human-readable collection metadata. It is a latency hint, not durable evidence
and not authorization. The fresh nonce makes repeated change and neighbor
announcements distinct.
Stock gossip supplies bounded duplicate suppression and an efficient
dissemination tree; bounded leased wake-origin sampling supplies eventual
anti-entropy when a wake is delayed or missed.

Neighbor churn stays inside stock gossip: its active and passive views repair a
`NeighborDown`, and a reported `Lagged` event does not end the subscription.
The host treats lag as a reason to advance exact repair, not as a second mesh
algorithm. If the topic stream itself ends, configured endpoints plus a bounded
recent set of signed and DHT-discovered origins seed the replacement
subscription.

## READ(C)-authorized exact repair

After observing a changed wake root—or when periodically sampling live signed
wake origins—a node opens one bidirectional collection-repair stream to that
origin. Its hello names C and may carry a bounded set of self-contained READ
proofs for cold bootstrap. The server admits the TLS-authenticated client only
from READ(C) evidence in its pinned local projection before returning any
manifest. Unknown hello proofs are signature/root checked and stored inertly.
The current session remains rejected; a new coherent snapshot and session can
admit the proof once its capability definitions are also resident. This stream
does not acquire those blobs. For `Open`
READ the bootstrap is empty. A WRITE-only publisher needs no READ authority
merely to serve an authorized replica.

The server loads one immutable repair overlay for C and applies the
descriptor's READ action policy against that frozen evidence. Rejection returns no manifest.
On admission it returns record and authorization-evidence PATCH summaries plus
the same opaque root. The client may then walk only differing prefixes and
receive missing leaf bodies:

- canonical signature-valid `COMMIT`, `MERGE`, and `DERIVE` records naming C,
  whether active or inert;
- native proofs relevant to C's repair audience and their resource's policy roots.

Each proof leaf contains the complete signed path and the handles of its
capability definitions, not those definitions' facts.
Records may land before sufficient WRITE proof evidence and remain harmlessly
inactive until a later snapshot derives admission.

Bounded streams reserve request and response-byte capacity for collection
records even when AUTH has deferred leaves. An incomplete pass continues
immediately only when it adds records or proofs; unchanged deferrals retry on
the ordinary cadence, without claiming convergence or initiating blob fetches.

The exact-repair scheduler samples at a 30-second cadence. Participant leases
last five minutes and every successful repair, including an identical result,
renews the selected peer. KDF(C) lookup is recovery-only: initial activation or
restart, exhaustion of every participant lease, or failure of every leased
candidate. Each collection permits one lookup in flight and retries an empty or
unsuccessful recovery with exponential backoff from one to 60 seconds. This
makes healthy steady-state DHT lookup load zero while preserving bounded
recovery after restarts and partitions.

Every request pins the manifest's expected component root. The server serves
the whole stream from one immutable overlay lease, so responses cannot splice
two moments together and need no historical-root cache. The client validates
node summaries, intrinsic leaf keys, record bodies, canonical proof bytes, and
proof signatures before insertion.

Exact-content GET is not part of this collection stream. An independent
exact-content request is authorized solely by knowledge of H.

Repair is one-way pull. Two peers converge by each eventually pulling after a
wake or periodic sweep. This keeps authorization and failure local to one
stream while set union makes direction irrelevant to the final value. A node
which holds no overlay for C answers unavailable rather than exposing a global
inventory.

## Blob transfer is lazy and bearer-addressed

Activation repair does not fetch descriptor dependencies, payloads, metadata,
attachments, or derived artifacts. It transfers the lattice evidence needed to
decide what exists. A resolver can then select the cheapest resident
support-equivalent cover and request only the missing immutable handles that
matter to that computation.

Knowledge of a full content hash H is the read capability for those exact
bytes and the secret needed to discover them. Publication and lookup derive a
full-width opaque locator under a dedicated domain:

```text
L = BLAKE3-KDF("triblespace.net/blob-locator/v1", H)
```

This is not encryption or protection against guessing the exact blob content.
Someone who can guess those bytes can compute both H and L and confirm a
matching provider token. Confidential low-entropy content needs encryption;
the additional locator hash prevents disclosure of H from a copied L, not
reconstruction of H from already-known or guessed bytes.

Every served resident blob may renew a soft lease at L on nearby XOR-DHT
nodes. The lease contains an independently domain-separated token bound to H
and the provider's authenticated endpoint ID. A requester who knows H rejects
forged candidate entries before dialing; the directory learns neither H nor
collection membership.

For an ordinary `PROVIDER_GET(L)`, the selected DHT node also consults its
already-installed, snapshot-coherent L→H index. If L is resident there, it
returns its own endpoint-bound token without waiting for a `PROVIDER_PUT`.
This deliberately extends the old lease-only answer: one reply slot is reserved
for the resident self hint, any stored self entry is deduplicated, and at most
63 other live leases follow in their existing deterministic peer-ID order.
Without a resident self hint, the usual limit remains 64 leases.

This is a query-time answer, not a new lease or publication attempt. It reads
no payload, creates no WANT or collection authority, and still works with a
zero announcement budget. A missing or withdrawn serving snapshot supplies no
self hint; independently stored leases remain ordinary soft hints. The blob
locator namespace does not synthesize collection-participant hints from a
resident descriptor. Client replica selection, token verification, and the
mutual bearer GET are unchanged: a known holder outside the selected DHT
replicas is not probed as a fallback. Remote publication is still needed when
the holder is not itself one of the selected replicas.

A returned self token therefore does not demonstrate that any publication
occurred. Foreign entries in this host's replies still come from retained
advertisements. The `blob_directory` diagnostic reports valid self and foreign
token counts separately, alongside its existing totals, without logging handles
or tokens. These classify hint sources, not cryptographic publication receipts;
neither category proves that a subsequent GET will succeed.

The direct stream also keeps H off the wire. The requester sends only L. The
provider resolves L in its resident locator index and proves knowledge of H
first, binding the proof to both authenticated endpoint IDs. Only after
verifying that proof does the requester send its role-separated proof of H.
The provider then returns bytes, which the requester hashes and compares with
H. A party which merely copied L therefore cannot learn H from a requester or
successfully serve bytes for it.

Fetching neither asserts collection membership nor activates a commit. It does
not consult C or READ(C), and creates a durable WANT only when the caller asks
the `WantStore` to record `Blob(H)`. Provider leases are bounded soft state and
may disappear without changing semantic data or local retention.

### Directory proof-node reuse experiment

`provider/directory_model.rs` is a wire-free comparison of signed entry leases
and signed immutable inventory roots. Its `shared_proofs.rs` extension retains
the same membership/lease PATCH repair and the same final inclusion verifier.
Only the proof transfer changes: each root-bound membership carries an ordered
list of node digests; a receiver fetches missing native `PatchNode` bodies from
that selected support's proof and retains at most 4,096 validated nodes in a
`PATCH<32>`. It neither asks for a full inventory nor consults a global member
registry. The parent's complete-topology placement oracle remains an explicitly
synthetic comparison, not an implementation of distributed responsibility.

Node presence supplies bytes, never authority. An all-hit proof must still
match the provider, member, signed range, exact inventory root and live lease,
and must pass the entire canonical node walk. The cache is populated only after
successful membership admission. Original signed absolute expiry survives
forwarding and cache reuse; changing the inventory requires new root-to-member
associations. The model assumes one trusted zero-skew absolute clock and
already-selected first-byte responsibility ranges; it does not solve either
clock recovery or dynamic ownership discovery.

The first Stars run (2026-09-07 23:24 UTC, base `d0db6da2`, rustc 1.98.0,
unoptimized tests with debug information disabled) used 256 deterministic opaque
members and then added one member. The partial receiver selected 132 of the
original members, then 133. Both representations produced identical content and
lease roots, active sets, signature counts, repair-request counts and complete
proof-validation work:

| Phase | New root/member bindings | Verified nodes / shared references | Shared node bodies | Shared body bytes | Inline proof bytes | Shared proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold | 256 | 673 | 323 | 46,751 | 1,779,936 | 78,879 |
| Unchanged renewal | 0 | 0 | 0 | 0 | 0 | 0 |
| One-member growth | 257 | 677 | 3 | 7,007 | 1,787,137 | 29,024 |
| Partial cold | 132 | 350 | 168 | 27,587 | 918,474 | 44,295 |
| Partial growth | 133 | 354 | 3 | 7,007 | 925,675 | 18,564 |

These are concrete model field bytes, **not measured network traffic**. Each
visited node contributes its actual key/representative width and fanout using
the existing collection node response field layout; a test cross-checks actual
codec output for its supported 32-byte keys. The model's inventory keys are 64
bytes. Inline paths send one body per verified node. Shared paths send one
32-byte reference per node, one explicit 32-byte request per missing body, and
that body; both include one path-length byte per support. Common signed lease,
root/member, membership/lease repair and transport framing bytes are excluded,
as are latency and any cache-miss request scheduling effects.

Every phase admitted one signed lease. Even unchanged renewal verified that
new signature, though it sent no membership support. Growth still checked
41,806 child summaries across the complete 677-node proofs and stored 257 new
root-bound entries; the three new bodies are a byte-reuse result, not reduced
validation or membership churn. Reconstructing the original independent `Vec`
paths also makes no resident-memory or allocation saving claim. A partial
receiver retains only selected leaf bodies, but branch representatives and
sibling summaries still disclose information outside its responsibility.

Run `cargo test --locked --offline -p triblespace-net --lib
provider::directory_model -- --nocapture` for the eleven focused tests. Lease
expiry despite cache hits, root grafting, malformed miss bodies, eviction, and
the original budget invariants are covered. There is no production wire, host, routing,
persistence, or deployment change in this experiment.

## Routing is process state

`Peer::new(store, key, config)` starts a production host immediately, as a
long-running repair daemon needs. `Peer::lazy(store, key, config)` keeps the same
store API but defers its host until the first absent-handle acquisition, explicit
network fetch, or collection activation. Resident reads, snapshots, local writes,
flush, and close start no thread or endpoint and build no serving/bearer index.
Its snapshots are still exactly the backing store's resident snapshot type.
Acquisition returns local observation errors rather than treating them as misses,
and a host startup failure leaves resident operations usable. Startup is attempted
once per peer; opening a new peer is an explicit retry. Activation logs startup
failures without activating the collection, while acquisition returns the error.

A foreground H-only reader need not activate any collection. It can use a distinct
ephemeral transport key, bootstrap endpoint routes, and a zero provider-publication
budget without borrowing its authorship signer's or a running daemon's endpoint
identity. Network acquisition requires an enabled Tokio runtime at the calling
async boundary; local-only operations need no runtime. `flush` makes local writes
durable, and explicit `close` withdraws host snapshots before closing the backend.
Neither operation starts networking or authors WANT.

Initial endpoint identities come from `PeerConfig` or the CLI. Configured relay
URLs only provide iroh transport paths; they are not collection participants or
KDF(C) rendezvous identities. A verified wake origin and DHT referrals may
become live routing candidates, but there is no synchronized PEER roster and no
durable peer record in the current protocol. Liveness, backoff, connection
pooling, DHT buckets, and provider leases are operational soft state;
restarting may forget them without losing semantic data and deliberately
re-enters KDF(C) discovery for each active collection.

### Restart contact experiment

`routing/warm_start.rs` is a test-only experiment, not enabled host persistence.
It runs the real `RoutingTable` and `IterativeLookup` with synthetic `FIND_NODE`
responses. Its one durable relation is a bounded set of previously authenticated
endpoint identities, canonicalized with `PATCH<32>` and packed into ordinary
`RawBytes`. A temporary-file write, sync, reopen and restore exercise the byte
boundary. The test makes no new pile record, replicated roster, schema identity,
JSON catalog, or provider advertisement. The host currently has no learned-peer
persistence to reuse: configured endpoint addresses seed a fresh route table and
iroh memory lookup; retired PEER records remain inert.

The maximum payload is `256 * K * 32 = 163,840` bytes, before any filesystem
overhead. Parsing reads at most that bound plus one byte and validates the whole
canonical endpoint set before admission. Restore uses ordinary candidate
admission, so self, bucket bounds and existing local failure cooldowns still
apply. Neither an old authenticated contact nor a content-addressed cache blob
is current authentication, honest routing behavior, or collection/blob authority.
Unqueried referrals and failed routes are not exported. Restored candidates do
not re-export themselves as fresh evidence. No H, locator, token, lease deadline,
or process-local monotonic timestamp appears in the packed relation.

Here, "authenticated" follows the table's existing `Verified` state, not a new
serving-longevity claim. The production host also promotes successful inbound
RPC callers, including ephemeral foreground clients. An inbound caller need not
be a useful long-lived DHT server. The experiment does not change that provenance
or silently reinterpret it as evidence that a peer answered our outbound probe.

The adverse fixtures distinguish three things: a dead configured bootstrap can
make cold discovery impossible while surviving hints still find a route; stale
closest-K hints can exclude a healthy configured seed; authenticated peers can
answer successfully while retaining a closed, unhelpful topology. Existing
failure cooldowns help a second lookup only in the dead-peer case and do not
survive another restart. A test-only first wave reserves one configured DHT seed
alongside at most `ALPHA - 1` warm candidates, then admits the deferred closest-K
set into the same lookup. This is DHT discovery, never direct-peer blob fallback.
It adds at most K deferred identities and one admission phase, not durable state.

The first-wave fixture has one configured seed and instantaneous synthetic
responses/failures. It does not settle multi-seed scheduling, the real three- and
ten-second budgets, transport address rediscovery, snapshot replacement cadence,
or handling a crash during replacement. Node churn and warm knowledge must be
measured before selecting those policies. Endpoint IDs alone cannot help when
no address discovery/direct route remains. Provider-directory deadlines and
publication cursors are deliberately excluded: restarting `put` would renew a
lease, and a saved publication cursor does not prove remote leases survived.
An immutable cached answer needs its original expiry and provenance separately;
reusing a serialized `Mono` or snapshot generation as freshness is invalid.

Run the focused tests with `cargo test -p triblespace-net --lib warm_start --
--nocapture`; add `--ignored` after `--` for the 1,024-node, 64-target measurement.
Reported requests and logical waves describe routing work, not elapsed network
latency, successful provider acquisition, or live-network availability.

The first Stars run (2026-09-07 23:04 UTC, base `d0db6da2`, rustc 1.97.1,
unoptimized net/lib tests) trained one client on 32 targets, saved 100 endpoints
in 3,200 bytes, then independently restarted it for each of 64 other targets.
The 1,024-node fixture gives remote peers established XOR-bucket views; only
the measured client restarts. The totals were:

| Restart state | Targets reached | FIND_NODE requests | Logical waves |
| --- | ---: | ---: | ---: |
| Cold, bootstrap live | 64/64 | 1,610 | 601 |
| Warm, closest-K | 64/64 | 1,521 | 529 |
| Warm, bootstrap first wave | 64/64 | 1,528 | 529 |
| Cold, bootstrap dead | 0/64 | 64 | 64 |
| Warm, bootstrap dead, first-wave policy | 64/64 | 1,589 | 549 |

This is a 5.5% request reduction for the healthy closest-K fixture, not a
universal cache speedup. A deliberately sparse 64-node line improved from 64
requests/64 waves to 20/7 with 1,568 saved bytes. Conversely, 20 dead cached
contacts suppressed a healthy seed: cold reached the target in two requests,
whereas warm closest-K failed after 20. The first-wave policy reached it in
wave two but still spent 22 requests/eight waves completing the lookup. Twenty
authenticated closed-view peers also suppressed discovery without any failed
requests; the first-wave policy recovered that fixture in 21 requests/seven
waves. These counterexamples make independent bootstrap opportunity a condition
of future integration, not an optional cache optimization.

### Live request scheduling

One connection pool is shared by collection repair and bearer/DHT operations.
Iroh's transport authentication binds each connection to its endpoint ID.
There is no generic AUTH or SYNC_TEAM exchange: collection evidence is gated by
READ(C). Exact bytes are gated only by the endpoint-bound mutual proof of H.

Pending dial ownership is cancellation-safe: the final departing waiter removes
an uninitialized pool entry, while concurrent callers retain the same shared
dial and can take over its cancelled initializer. The established-connection
LRU remains separate from these live requests. This cleans up abandoned pool
entries, not a new limit on simultaneous requests or detached transport handshakes.

For an explicitly active collection with a missing descriptor, the host owns
one independent bearer fetch until its result reaches the bounded admission
bridge. Repair ticks cannot spawn additional copies while that handoff is
blocked. Removing the interest or dropping the host cancels the pending fetch;
a completed miss or failed attempt permits a later retry. This does not fetch
descriptor dependencies or introduce a durable WANT.

Foreground exact-H acquisition has one end-to-end deadline, normally ten
seconds, including capability readiness, cold bootstrap dialing, DHT lookup,
and bearer GET. Its three-second routing window begins with the first
authenticated replica response, not before the cold bootstrap dial. This lets
a healthy delayed bootstrap connect while a stalled secondary route cannot
consume the whole remaining budget before GET. Background publication and
collection recovery start their three-second lookup window immediately. A
caller's shorter deadline still wins; progress does not reset either deadline,
and no failed lookup starts an unbounded retry loop.
When the routing window expires, issued requests still awaiting a reply count
as failed learned routes. They cannot occupy every slot again on the next
background attempt merely because cancellation preceded the dial deadline.
Unissued candidates and partial authenticated responders are preserved, and
explicitly configured routes remain available for retries. Each routing bucket
also retains at most K local learned-route failures for sixty seconds, separately
from its positive routes. Repeated third-party referrals cannot erase or extend
that cooldown: it gates both seeds and reply candidates even when positive
bucket retention differs from the lookup-local shortlist. Direct authenticated
success clears a cooldown immediately; expiry permits a new probe. This is
bounded, disposable liveness state, not authority or a permanent blacklist.
This does not make a configured-only cold dial longer than three seconds fit
the background window: if each attempt starts equally cold, background retries
can still miss that endpoint. Foreground acquisition retains its separate end-to-end bound.
Diagnostics distinguish a successful lookup with no provider hint from
failure to reach a replica, a provider transport/protocol failure, or exhaustion
of the end-to-end budget. A directory miss is an observation, not proof that H
does not exist. Diagnostics do not log the bearer handle.

## Lattice-aware sparse replication

The network does not force every replica to mirror every blob. Collection
records expose the same lattice known to local maintenance:

```text
COMMIT(C, a)       COMMIT(C, b)
       \             /
        MERGE(C, a, b, c)

DERIVE(D, c, d)
```

A node can repair the small semantic overlay and use its resident exact merge
and derivation results while planning a cover. Missing derived results are
computed by the ordinary live `ensure` path, which may acquire exact missing
dependencies and publishes missing `DERIVE` work only. `maintain` additionally
publishes deterministic size-tiered `MERGE` work. These operations take an
explicit signing key. Newly required derivation work needs target WRITE;
reuse needs no new authority, and optional maintenance without WRITE preserves
the existing finer cover. The signed equations repair as reusable computation
and input-validation endorsements, not new exogenous membership; their
referenced artifact blobs remain separate exact-H content.
Evidence and computation still converge by union; no central scheduler or
query planner is required.

Durable WANT remains orthogonal operational policy.
`WantRequest::Blob(H)` is the sole exact-content request. The reconciler
performs KDF(H) discovery and the mutual bearer proof directly from its coherent
store snapshot; no collection descriptor, repair overlay, or proof is involved. A
successful landing satisfies the request, while a DHT miss or failed proof
leaves it pending. `Merge(C,a,b)` and `Derive(D,input)` let one process state
demand while a network or worker process fulfills it. WANT grants no READ,
WRITE, or collection membership. Retained WANT records do keep their resident
direct blob references alive through the normal record-root GC rules. GC never
fetches missing references merely to retain them; dropping WANT records is an
explicit rewrite/retention-policy choice.

### Local replication policy and reference summaries

`Reconciler::with_replication(mode, collections)` selects local acquisition
work, separately from Peer activation and collection authorization:

| Mode | Blob acquisition |
|---|---|
| `Demand` (default) | Existing explicit WANTs only. |
| `Shallow` | Also the direct blob references of the selected collection records. |
| `Full` | Also recursively scan those roots at aligned 32-byte boundaries. |

The selection is explicit: possessing READ authority does not subscribe a node
to fetching another person's collection. Shallow hydration follows structurally
valid records, including signed but WRITE-inert commits; obtaining bytes does
not admit their claims. Exact WANTs and direct roots run before speculative
recursive reads, sharing one time budget. The walker retains only positively
reached `(root, blob)` pairs and their resumable offsets in a PATCH. Frozen
regular rounds grant one bounded quantum per source, rather than draining one
large blob before serving another. An alternating recent-positive lane gives
new arrivals a bounded startup window; the lane turn survives tick and fetch
deadline exits. Completed parents become eligible again on their own bounded
backoff, independently of large partial sources and subsequent arrivals.
Candidate work and speculative requests remain bounded per pass; at most one
speculative request is issued in a quantum. Absent candidates do not become
WANTs or an ever-growing negative frontier, because a DHT miss does not
establish absence. Full mode does not recursively widen an explicit `WANT(H)`
that lies outside the selected collection roots.

This is service fairness, not a wall-clock hydration guarantee. A large initial
burst cannot all receive immediate service, sustained arrivals can outgrow the
recent lane, and exact WANT/root work may consume the shared fetch deadline.
Recent work never takes away the reserved regular turns, including revisits;
it only accelerates a finite prefix of newly observed positive sources. The
recent lane is newest-first and retains a source for at most 128 aligned words;
regular quanta inspect at most 64 words. For a finite burst of A newcomers, the
last first-service bound is O(A times the startup window), not constant time or
round-robin service within that burst.

Full scans grant sustained quanta round-robin between the explicitly selected
collections, each retaining the regular/recent walk above. A large selection's
root inventory cannot consume a small selection's regular share after its
startup window ends. Exact WANTs, the physical root union, the fetch deadline,
CPU steps and speculative-request allowance remain global. A selected but
unattempted word retains its collection turn across budget exits. Native record
indexes supply each selection's roots; there is no separate membership catalog.
Shared roots have separate positive traversal observations in their actual
selecting collections, but physical acquisition and per-tick negative-request
deduplication remain shared. This trades duplicate traversal of genuinely shared
closures for sustained service without an arbitrary root owner. The selection's
own large closure, resident-child expansion, provider failures and exhausted
exact-demand budgets still prevent a general finite hydration deadline.

When seeding a full scan, ordinary resident record roots are observed before
explicitly selected collection descriptors. A descriptor already present in
both that root set and the durable resident set therefore receives its finite
recent startup window ahead of the bulk inventory. This is ordering only:
selection alone never invents a closure root, repeated snapshots do not reset
offsets or requeue descriptors, and regular turns still progress. Many selected
descriptors, later arrivals, unavailable providers, and exhausted exact-demand
budgets can still delay a descriptor child; no special blob authorization or
publisher priority is implied.

A producer can maintain an ordinary `ReferenceSummaryBlob` collection to make
negative recursive probes cheap. Its mapping scans the complete source blob
closure and projects referenced handles through the same opaque `KDF(H)` used
by discovery. Fixed Bloom geometry lives in the descriptor; member join is
bit-set union. Canonical sparse positive-gap bytes or a shorter dense bit vector
represent the same value, and a lazy cover view probes their logical union.
No Peer subtype, new pile record, or network operation is involved.

```rust,ignore
use triblespace::core::collection::reference_summary::{
    ReferenceSummaryBlob, ReferenceSummaryLayout,
};

let summaries = storage.derive::<ReferenceSummaryBlob>(
    facts,
    ReferenceSummaryLayout::default(),
    summary_policy,
)?;
// Producer only: all recursively reachable attachments were stored before
// the source COMMIT. This scan cannot infer that precondition on a replica.
storage.maintain(summaries, &writer).await?;
```

The source archive's own handle is not automatically inserted: it is a
materialization identity, not part of the referenced closure. Under the
complete-producer precondition, projection therefore distributes over source
union. An incomplete replica cannot distinguish an ordinary inline value from
a missing reference, and **must not derive a replacement summary locally**.

Consumers explicitly select the summary collection alongside its source. The
same shallow acquisition obtains known `DERIVE`/`MERGE` outputs; ordinary
passive collection observation then supplies a resident summary and its support.
Only descendants of a source data root contained in that support may use its
negative answers. An older summary cannot filter a newer, uncovered commit;
the mapping must also read that foundational collection directly, rather than
some intermediate projection which might have discarded references. Chained
summaries remain valid collections, but this walker does not apply their
negatives to the original commit bytes. Likewise,
metadata, descriptors, and unrelated physical artifacts are not covered merely
because they belong to the same collection. Missing summaries mean an unfiltered
walk, not an empty closure. Positive matches still use ordinary exact-H DHT
discovery and mutual bearer proof. Neither filter possession nor a positive
answer is read authority.

From the command line, register and maintain on the complete producer:

```text
trible pile collection derive DATA.pile facts reference-summary --log2-bits 32 --probes 4
trible pile collection maintain DATA.pile SUMMARY_HANDLE
```

Then select both handles on a consumer's existing sync command with
`--replication full`. Merely repairing a source collection does not repair the
separate derived collection's records. These modes change physical residency,
not collection identity, authorization, or the union semantics of repair.

## Wire surface

Protocol version 26 keeps the direct operation set narrow:

| Operation | Code | Meaning |
|---|---:|---|
| `GET_BLOB` | `0x02` | locator-addressed, mutual-proof exact bearer transport |
| `PROVIDER_PUT` | `0x06` | renew this endpoint's opaque provider lease |
| `PROVIDER_GET` | `0x07` | obtain bounded candidates for one opaque key |
| `FIND_NODE` | `0x0C` | iterative XOR-DHT routing step |
| `COLLECTION_REPAIR` | `0x0D` | receiver-authorized record and authorization-evidence PATCH repair |

There is deliberately no store manifest, global inventory authorization,
push-broadcast record, receipt RPC, remote mutable head, or unpublish operation.

The CLI selects explicit collections and bootstrap peers:

```text
trible pile net sync DATA.pile \
    --collection COLLECTION_HANDLE [--collection COLLECTION_HANDLE ...] \
    [--peers ENDPOINT_TICKET ...] [--direction bidirectional|read-only|write-only] \
    [--replication demand|shallow|full]
```

Direction gates only the collection loop: `ReadOnly` pulls collection repair,
`WriteOnly` serves it, and `Bidirectional` does both. Every direction may
announce and serve resident exact blobs under bearer handle H, and may service
durable `Blob(H)` WANTs through KDF(H). These QoS choices do not participate in
collection identity or change which evidence is semantically valid.

## Convergence and failure model

- Concatenation, local insertion, and remote repair all perform set union.
- Duplicate records collapse by their complete canonical value; fixed-width
  indexes and the wire use a full-width BLAKE3 fingerprint of that value.
  Native capability proofs continue to collapse by their cryptographic
  identity.
- A missed wake only adds latency; periodic repair still converges connected
  readers.
- An invalid wake, record, proof, PATCH node, or blob fails that input and
  cannot retract previously accepted evidence.
- Missing selected output/dependency blobs leave that realization unavailable;
  complete finer members remain usable. Missing witness records leave support
  unknown, not empty, and do not authorize cross-collection disclosure.
- A DHT miss says only that no live provider was found; it says nothing about
  whether H or its collection exists.
- Concurrent writers and offline replicas reconverge without preserving pile
  byte order.

The result is two orthogonal elemental loops: gossip plus READ(C)-gated PATCH
repair says *what changed in a collection*, while KDF(H) discovery plus mutual
bearer proof retrieves only the immutable bytes the local lattice resolver
decides to use.

## Observing replica health

`Peer::health()` and `NetSender::health()` expose a bounded immutable sample of
work the host already performs. Sampling does not run a probe or advance the
host's observation clock. Each repair comparison retains the local and remote
record/authorization frontiers pinned when its authenticated manifest arrived.
A comparison stops implying convergence when that sample is stale, the local
frontier has changed, or the serving snapshot has been withdrawn. Receiving
records is progress evidence, not proof they have already become admitted.

The long-running CLI can publish these observations as native facts using
`pile net sync --health-key <existing-author-key>`. The private `swarm-health`
collection is deliberately not activated for replication, so a broken network
cannot prevent the local reader from seeing its own warning. A new report is
published every minute with `created_at` only: freshness is reader policy, not
a producer-asserted lifetime. `pile net health --max-age <SECONDS>` accepts a
maximum sample age (default 180 seconds, also configurable through
`TRIBLESPACE_HEALTH_MAX_AGE_SECS`). Readers use the creation interval's upper
bound plus that duration and ignore any legacy `expires_at` annotations;
future-created reports remain unknown, and zero accepts no arrived sample as
fresh. Conditions use stable episode identities until their state changes; a
reader can acknowledge an alert once without acknowledging each heartbeat.
When the reader's age limit is reached, the report itself supplies an attention
event even when the daemon stops appending entirely.

These reports distinguish unknown, progressing, matching, and stalled work,
with a ten-minute repair/publication grace period. A stale host loop is detected
separately from a fresh reporter. An idle DHT awaiting its ordinary eight-hour
renewal is not a failed availability probe. Publication acknowledgement says
only that a provider advertisement was accepted, not that a remote blob fetch
works. Neither the observed participant set nor a pairwise matching frontier
proves whole-swarm convergence. `pile net health` reads the local observations;
Orient can consume the same maintained facts and presentation ledger.

## Directory representation experiment

The live receiver-local `ProviderDirectory` uses four BTree indexes: membership
values, providers by exact locator, expiry order, and XOR responsibility order.
`provider/patch_directory.rs` is a **test-only** alternative with two PATCHes:

- `!(locator XOR local_endpoint) | !provider`, segmented `32 | 32`, owns the
  deadline/token value. Segment counts answer membership and exact-locator
  cardinalities; the first ordered key identifies the farthest responsibility.
- `deadline_ns | locator | provider` orders expiry. Keeping the original
  locator/provider order here preserves tie-breaking under the bounded prune
  budget, not merely the eventual set of live results.

No wire, lease, trust, publication, persistence or live-directory policy changes.
Differential tests compare every retained value, deadline, capacity decision,
exact-key result and farthest member against the existing implementation across
24,000 deterministic mixed operations and targeted expiry/fanout boundaries.

Stars measurements on 2026-09-07 used exact prototype `512513bf`, rustc 1.98.0,
and fresh processes for each representation. Each table cell is **PATCH / BTree**;
times are seconds. GET traverses every locator once; insert and renewal visit
every locator/provider pair. RSS is the post-insertion minus pre-insertion
process reading, excluding the already-built deterministic input corpus.

| Locators × providers | RSS delta MiB | Insert | GET | Renew |
| --- | ---: | ---: | ---: | ---: |
| 100,000 × 1 | 32.68 / 84.91 | 0.0647 / 0.1291 | 0.0370 / 0.0410 | 0.1752 / 0.0628 |
| 10,000 × 3 | 10.61 / 17.46 | 0.0321 / 0.0235 | 0.00686 / 0.00457 | 0.0512 / 0.00880 |
| 10,000 × 16 | 47.84 / 79.64 | 0.2948 / 0.1488 | 0.0239 / 0.0219 | 0.2679 / 0.0486 |
| 1,000,000 × 1 | 302.55 / 845.20 | 1.0831 / 2.2850 | 0.5901 / 0.7602 | 2.3755 / 1.4508 |

These are single samples, not confidence intervals or full release/network
measurements. Only `triblespace-core` and `triblespace-net` received test-profile
overrides `opt-level=3`, `debug-assertions=false`, `overflow-checks=false`;
dependencies otherwise retained the same test profile. Both compared modes
used those identical settings, eight build jobs, debug information disabled,
incremental off, and no RUSTFLAGS. Debug-only timings were much worse for PATCH
because its invariant audits are intentionally expensive; they are not a sound
basis for the production comparison. Both profiles passed the differential tests.

The memory saving is substantial, but immutable membership replacement and
deadline reindexing make renewal slower, and multi-provider insertion can also
lose. This prototype is retained for evaluation, **not promoted to the live
directory**. A proposed `Cell` lease-value shortcut was rejected before edits:
shared PATCH leaves require `Send + Sync` for cross-thread ownership. Adding an
unsafe ownership promise or per-leaf synchronization just to optimize these
already-fast local operations would add a new tradeoff, not finish this one.

Reproduce with `cargo test --locked --offline -p triblespace-net --lib
--features sim provider::patch_directory`; the ignored
`patch_directory_scale_probe` accepts `TRIBLESPACE_DIRECTORY_REPRESENTATION`
(`patch` or `btree`), `TRIBLESPACE_DIRECTORY_KEYS`, and
`TRIBLESPACE_DIRECTORY_PROVIDERS`. Run each mode in its own process and state the
profile settings with any result. Corpus shape, allocator state, CPU profile,
and fanout matter; this is not a measurement of DHT announcement throughput.
