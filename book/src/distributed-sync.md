# Distributed Sync

`triblespace-net` synchronizes collections rather than exposing one ambient
store inventory. Its protocol follows the same decomposition as the collection
model:

1. stock `iroh-gossip` membership carries neighbor-only opaque root offers,
   with application-controlled relaying;
2. one READ(C)-authorized exchange walks collection records, scoped AUTH and
   a positive resident-blob inventory; and
3. exact blob handles fetch only the immutable bytes a resolver actually
   chooses through a collection-independent, mutually authenticated bearer
   protocol.

No global team, mutable roster, durable OFFER/GOSSIP bit, or second replicated
inventory is needed. Resident inventories are local observations, not durable
claims merged into a collection. The descriptor already states independent
READ and WRITE policy, and iroh authenticates the endpoint key on each direct
connection.

## Four independent capabilities

The boundaries are deliberately small:

```text
know C           -> join C's wake topic and learn (origin, opaque state root)
prove READ(C)    -> receive C's records, scoped proofs and resident-blob handles
know H           -> derive its opaque locator, discover providers, and authorize H
satisfy WRITE(C) -> make a signed COMMIT, MERGE, or DERIVE active in C
```

`C` is the exact 32-byte collection descriptor handle. `H` is an exact blob
handle. Knowing C permits discovery of its ordinary descriptor-blob providers
(H=C), possible contacts for its gossip topic rather than certified collection
participants. H is the bearer capability and private discovery secret for one
exact immutable value. The provider directory sees only blob-locator KDF images
and endpoint-bound tokens, never raw handles or a collection-participant namespace.

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

For one collection, repair pins three independent PATCH components:

- every structurally valid native collection record naming exact C: signed
  `COMMIT`, `MERGE`, and `DERIVE` records independent of current WRITE(C)
  admission;
- every signature-valid native proof scoped to exact resource C and beginning
  at a root named by C's supported policy bindings, without requiring its grant
  handles to match those bindings. Subordinate-resource transport
  also includes proofs for R whose immutable descriptor declares C as its repair
  audience, under R's own policy roots; and
- a positive partial inventory of locally readable blob handles reached from
  C's descriptor and direct record/proof references.

Each set is represented by an immutable BLAKE3-Merkle PATCH. Collection
records are keyed physically by the full 32-byte fingerprint of their exact
canonical value; authorization evidence uses a `repair_collection | proof_hash` PATCH
whose values share ownership of the original proof bytes. Only C's prefix is
exposed; the wire leaf key is the 32-byte proof hash and its payload is the
complete native proof body. The host currently keeps one such index per
overlay, not a shared global inventory. Resident-blob leaves use exact H as
their 32-byte key and have an empty value. There is no companion claim blob or
authorization closure to transfer. The opaque repair root commits to C and all
three PATCH summaries, including their leaf counts, under a versioned domain.

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
definitions to be resident, but this repair stream neither fetches nor carries
their bodies. An application may use the same proof kernel for another
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
evidence algebra remains `Record × AuthorizationEvidence`, scoped to C.
The resident component is different: it observes physical availability and may
shrink or be rebuilt. It does not create semantic membership or change WRITE
admission. The receiver always derives its admitted view locally; record and
proof arrival therefore commute, and a publisher need not possess or present
its own WRITE grant merely to replicate an inert signed record.

The host also updates these components independently. When a store snapshot
reports unchanged collection records, its existing record PATCH is shared into
the next repair overlay without re-enumeration or Merkle hashing. Blob arrival
still refreshes the authorization observation: a newly resident capability or
subordinate-resource descriptor can enable admission or proof routing without
changing any record. Resident-inventory scanning advances in bounded passive
quanta against the same frozen reader; inventory changes can change the wake
root even when records and AUTH are unchanged.

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

The three-component repair epoch uses opcode `0x0E` on
`/triblespace/pile-sync/26`; the retired `0x0D` repair grammar is rejected
before decoding. Unchanged bearer and DHT operations remain compatible with
installed `Leech` readers, which never join collection repair. Dense
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

## Opaque neighbor offers and state-based relaying

Locally, `Peer::refresh()` admits bounded incoming evidence and freezes one
coherent store observation: collection repair overlays, blob serving reader,
and resident provider locators. A latest-value handoff replaces the previous
observation rather than queuing successive snapshots. The host pins the newest
one once per turn and uses PATCH differences against its last processed
observation to update subscriptions and provider publication. Roots and
provider locators therefore cannot come from different store observations.
An unavailable active descriptor still retains its subscription, and a failed
snapshot immediately withdraws serving. An unchanged snapshot requires no
provider reinstallation. Per-topic outgoing root announcements likewise read
the latest value rather than draining intermediate roots.

This coalescing applies to replaceable observations, not new remote evidence:
authenticated incoming records, proofs, and blobs still cross the bounded
admission bridge into the store. It does not discard records or turn a dropped
notification into a lost update; later root announcements and Merkle repair
derive the outstanding work from current state.

The `iroh-gossip` topic ID uses the version-isolated
`triblespace/collection-wake-topic/v2` domain over the collection handle.
Anyone who knows C can derive and join that topic, while generic gossip
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
and not authorization. Its semantic identity is `(C, R)`, not the signed
contact, signature or nonce. Contact annotations can change without becoming
a fresh state event. The wire envelope remains nonce-v4; the separate topic
namespace prevents old automatic Swarm forwarding from mixing with the new
neighbor-only relay rule.

Stock gossip maintains membership and delivers to direct neighbors. It does
not automatically forward these neighbor-scope offers. The application
periodically offers its latest root with a randomized timer:
intervals grow from two to sixty seconds, with transmission in the second half.
Hearing one equal-root offer suppresses this interval's redundant local offer;
disagreement and local changes shorten long intervals. A new neighbor gets one
forced offer. Missed intervals are not replayed as a queue.

The vendored gossip transport carries topic-tagged frames on one ordered
unidirectional stream per connection. Topics still have independent membership
and dissemination; this is transport multiplexing, not a global collection
topic. Upstream's persistent stream per topic exhausted QUIC's default 100
stream credits with the colony's 126–130 collections. Its blocked writer could
then fill the connection queue and stop the shared gossip actor. A regression
joins 130 topics at default limits and 257 topics with only one stream allowed.
The private ALPN
`/triblespace/gossip/C6858FA15B24B264151DB34DAA9C1964` isolates the new framing
from `/iroh-gossip/1`; the anchor was minted with `trible genid`. Collection
topic IDs, wake signatures, and the separate pile-sync ALPN are unchanged.
The shared gossip actor never waits for a full peer output queue: it gives a
healthy writer one scheduling turn, then fails an unavailable connection so
ordinary membership recovery can proceed. Failed send/receive halves close
their connection, while clean EOF preserves the opposite direction: simultaneous
connections can legitimately carry the two directions separately. Both halves
finishing closes the obsolete connection. Pending dial history is bounded by
live subscriptions. Cancelled dials are checked again when their
completed results are consumed, so a late success cannot revive discarded
membership controls.

Relaying retains one latest observation per signed origin, with equal roots
sharing one deadline rather than one event per contact or nonce. A receiver
allows up to five seconds for repair. If its published serving snapshot reaches
the offered root, it can replace the contact with itself. A different union
root is offered as the actual resulting root, never as a claim to serve the old
one. If repair is slow, fails, or is unavailable to a read-only/unauthorized
bridge, the original validated signed offer is forwarded unchanged.

Retained offers have bounded replay opportunities and five-minute lifetimes;
changing annotations cannot renew the root episode or postpone its deadline.
New topology advances forwarding. Repeated equal state suppresses retained
relay only when every known direct neighbor has itself signed that same root.
A forwarded origin's signature does not establish the last hop's state, and
one upstream match does not establish downstream coverage. Equality includes
the partial resident inventory, but is not proof of complete recursive payload
closure or permission to interpret/decrypt its blobs.

Bootstrap contacts come from descriptor policy roots, roots/delegates in
structurally validated scoped AUTH paths, configured/recent endpoints, and
ordinary providers of the descriptor blob H=C. None is an admission decision
or a promise of an online participant. In particular, a descriptor-only cache
never becomes a repair source just by answering the blob directory. A signed
root offer names its origin as a candidate repair source, not the forwarding hop.

Neighbor churn stays inside stock gossip: its active and passive views repair a
`NeighborDown`, and a reported `Lagged` event does not end the subscription.
The host treats lag as a reason to advance recovery and offer its latest root, not as a second mesh
algorithm. If the topic stream itself ends, configured endpoints plus a bounded
recent set of signed and DHT-discovered origins seed the replacement
subscription.

## READ(C)-authorized exact repair

After observing a different wake root, a node selects a fresh signed origin
advertising that root and opens one bidirectional collection-repair stream.
Random selection among equivalent advertised roots spreads repair load; it
does not yet prefer low-latency paths. Its hello names C and may carry a bounded set of self-contained READ
proofs for cold bootstrap. The server admits the TLS-authenticated client only
from READ(C) evidence in its pinned local projection before returning any
manifest. Unknown hello proofs are signature/root checked and stored inertly.
The current session remains rejected; a new coherent snapshot and session can
admit the proof once its capability definitions are also resident. This stream
does not acquire those blobs. For `Open`
READ the bootstrap is empty. A WRITE-only publisher needs no READ authority
merely to serve an authorized replica.

The server loads one immutable repair overlay for C and applies the
descriptor's READ action policy against that frozen evidence. Rejection returns
no manifest. On admission it returns record, authorization-evidence and
resident-blob PATCH summaries plus the same opaque root. The client may then
walk only differing prefixes and
receive missing leaf bodies:

- canonical signature-valid `COMMIT`, `MERGE`, and `DERIVE` records naming C,
  whether active or inert;
- native proofs relevant to C's repair audience and their resource's policy roots;
- exact H keys from the pinned positive resident inventory, without blob bodies.

Each proof leaf contains the complete signed path and the handles of its
capability definitions, not those definitions' facts.
Records may land before sufficient WRITE proof evidence and remain harmlessly
inactive until a later snapshot derives admission.

Bounded streams reserve request and response-byte capacity for collection
records even when AUTH has deferred leaves. An incomplete pass continues
immediately only when it adds records or proofs; unchanged deferrals retry on
the ordinary cadence, without claiming convergence or initiating blob fetches.

Inventory walks have a separate allowance of 128 node requests and 2 MiB of
response bytes per pass. A successful bounded pass retains its authenticated
walk cursor across RPCs for the same collection and remote inventory summary.
A changed summary starts fresh Merkle validation above the last visited handle,
then schedules a later wrap to earlier keys. No proof from an old root is reused
against the new one. This avoids repeatedly enumerating an early missing prefix
while none of its payloads has landed, even during continuous appends. An incomplete
inventory cursor is separate from incomplete semantic evidence and retains
its own continuation opportunity. No absent handle is inferred from an
unfinished walk.

Healthy participants are no longer pulled blindly at a thirty-second cadence.
The periodic tick retries failed work; normal repair follows mismatched roots.
Five-minute participant leases renew on signed notices and successful repair.
Before opening a queued repair, the host checks the latest advertised root
against its current root again. Equality skips redundant work, except that a
previous failed exchange still gets a real confirmation rather than leaving a
permanent failure alert or inventing an RPC comparison from a gossip hint.

Descriptor-provider lookup retries use one-to-sixty-second backoff without a
viable repair source. Even with healthy participants, bootstrap is retried every
five minutes: a healthy subset must not permanently mask a disconnected one.
At most three collection lookups run, one per collection, with fair rotation
among due interests; deactivation cancels outstanding discovery. Root/AUTH and
configured contacts are retried alongside descriptor-provider discovery.
These bounds provide retry opportunities, not a global convergence deadline.

A failed repair keeps its participant's original lease while bounded failure
state records backoff. Periodic repair retries that participant even if another
replica remains healthy: that replica need not have the missing records.
Failure never renews a lease. If every candidate has failed, recovery discovery
and topic reconnection proceed without waiting for expiry. If the bounded
failure table cannot track a peer, its lease is dropped so it cannot falsely
look like a healthy candidate and delay recovery discovery.

Every request pins the manifest's expected component root. The server serves
the whole stream from one immutable overlay lease, so responses cannot splice
two moments together and need no historical-root cache. The client validates
node summaries, intrinsic leaf keys, record bodies, canonical proof bytes, and
proof signatures before insertion.

Exact-content GET is not part of this collection stream. An independent
exact-content request is authorized solely by knowledge of H.

Repair is one-way pull. Two peers converge by each eventually pulling after a
wake or a failed-work retry. This keeps authorization and failure local to one
stream while set union makes direction irrelevant to the final value. A node
which holds no overlay for C answers unavailable rather than exposing a global
inventory.

## Blob transfer is lazy and bearer-addressed

Activation repair does not fetch descriptor dependencies, payloads, metadata,
attachments, or derived artifacts. It transfers lattice evidence and positive
resident-handle observations, not those bytes. A resolver can then select the
cheapest resident
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

An experimental exact-H fetch can query a directory as soon as it directly
answers an authenticated FIND_NODE, rather than waiting for the final routing
barrier. Named referrals remain unverified candidates until they answer in
turn. Early targets come from the current closest authenticated responder set
(including the local endpoint); routing-free local fallback remains available
when lookup completes. No cold lookup starts from a retained local provider
lease before routing progress. Publication and collection discovery still
select their final replica set before directory operations.

FIND_NODE, directory queries and exact provider GETs share three concurrent
request slots. While routing is open, acquisition occupies at most two, leaving
capacity for fresh routing. While unstarted directory queries remain, bodies
normally occupy at most two slots, including after routing finishes. A directory
reply contributing a retained untried hint earns one body turn before the next
directory, so a useful answer need not wait for every remaining directory.
Already-attempted or discarded hints earn no such turn. Subject to these
reservations, a usable provider takes the next free slot ahead of an unstarted
directory query. At most K early directory
attempts are admitted, then a final closest-K sweep supplies unqueried targets;
the total is at most 2K distinct directories, including any local query. This
can spend K more queries than waiting for the final set, and the one reserved
routing slot can reduce acquisition concurrency. Conversely, two progressing
acquisitions leave only one routing slot in the same unchanged routing window;
this is not a proof of equal discovery coverage under every timing pattern.
Empty early hints do not end
a lookup whose routing remains open. At most 64 distinct providers can be
attempted per fetch.
Duplicate hints never spend another attempt. Pending providers are ranked by
XOR distance among the hints received so far, bounded by the remaining attempt
allowance. A later closer hint can replace pending work, not an already-started
request. The transient attempt subset is therefore deliberately arrival-sensitive;
it need not equal the closest 64 in the final reply union. Collection discovery
still waits for its canonical, reply-order-independent union.

This removes routing's final barrier when early evidence is useful, not every
possible head-of-line delay. Three stalled requests can still occupy the shared slots;
in particular, three stalled first directory queries prevent an unstarted
directory from supplying its hint within a shorter caller deadline. An early
large set of valid but unavailable hints can also exhaust the 64-attempt cap
before a later useful hint arrives. Early nonfinal directories can supply those
hints too: reserving the final directory sweep does not reserve body attempts
and does not prove baseline reachability is preserved for every reply order.
The caller's existing end-to-end timeout,
per-operation deadlines, pooled-connection cancellation rules, provider-token
checks, mutual bearer proof, body-receive memory bound, and final hash check
are unchanged. Routing expiry drops only issued routing requests; a progressing
directory/body stream continues within the original caller deadline. Early
verified success or caller cancellation drops all owned futures without
fabricating protocol failures or closing healthy pooled connections. No provider
hint or result is persisted by this scheduling step.

The direct stream also keeps H off the wire. The requester sends only L. The
provider resolves L in its resident locator index and proves knowledge of H
first, binding the proof to both authenticated endpoint IDs. Only after
verifying that proof does the requester send its role-separated proof of H.
The provider then returns bytes, which the requester hashes and compares with
H. A party which merely copied L therefore cannot learn H from a requester or
successfully serve bytes for it.

Exact body reception admits at most sixteen active body futures. They share one
1 MiB scratch buffer, held only for a bounded ready-read batch and its local
write, never while awaiting the network. Each batch also has a read-poll limit
so a stream yielding tiny fragments cannot monopolize one executor turn.
Received bytes grow a temporary file; one immutable mapping backs the completed
`Bytes`. An idle or partial stream therefore does not block a healthy body from
using the scratch buffer.

The existing per-body bound is 64 GiB. A separate process-wide 64 GiB temporary
backing budget accounts in rounded 1 MiB units, including partial files and
completed `Bytes` until their last owner drops. Retaining many tiny completed
bodies can exhaust this budget too. Body-slot and backing-budget exhaustion are
local, immediate errors, not evidence against the provider: they preserve its
pooled connection for a later attempt. Cancellation, truncation and other
failures return their resources. Network waits remain inside the caller's
deadline; synchronous local file writes cannot themselves be preempted by that
async deadline. These limits neither guarantee throughput nor replace the
final comparison of the received bytes' hash with H.

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
async boundary; local-only operations need no runtime. Puts and incoming repair
admissions become visible in a fresh local observation without an automatic disk
flush. Explicit `close` withdraws host snapshots and closes the backend at the
final persistence boundary; manual `flush` remains available at an application's
chosen durability boundary. Neither operation starts networking or authors WANT.
Failure to obtain a fresh store snapshot is returned by `try_refresh` and
withdraws the previous serving observation; existing frozen readers stay frozen.

Initial endpoint identities come from `PeerConfig` or the CLI. Configured relay
URLs only provide iroh transport paths; they are not collection participants or
collection rendezvous identities. A verified wake origin and DHT referrals may
become live routing candidates, but there is no synchronized PEER roster and no
durable peer record in the current protocol. Liveness, backoff, connection
pooling, DHT buckets, and provider leases are operational soft state;
restarting may forget them without losing semantic data and deliberately
re-enters authority/descriptor-provider discovery for each active collection.

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

Inbound RPC streams wait for the existing per-connection and process-wide
request permits. Saturation does not close the connection carrying other
active repairs. Each bounded connection retains at most one accepted waiting
stream, and no handler task is spawned until both permits are held.

One connection pool is shared by collection repair and bearer/DHT operations.
Iroh's transport authentication binds each connection to its endpoint ID.
There is no generic AUTH or SYNC_TEAM exchange: collection evidence is gated by
READ(C). Exact bytes are gated only by the endpoint-bound mutual proof of H.

A valid READ refusal or unavailable-collection reply ends only that repair
stream. It does not evict the shared connection or cancel unrelated requests.
Malformed replies and transport failures still invalidate the pooled connection.

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

### Local residency inventory and replication policy

Each active collection's serving snapshot includes a passive, positive
resident-handle PATCH. Seeds are the collection descriptor and direct blob
references from its structural records and scoped AUTH proofs. A local scan
follows an aligned 32-byte word only when that exact H is readable through the
same passive snapshot. It does not issue network requests, create WANTs, or
remember arbitrary absent words as possible downloads.

Scanning advances with bounded source/word quanta and retained offsets rather
than restarting every payload walk on refresh. Each refresh divides a budget
of 1,024 source reads and 16,384 aligned words across active collections, with
per-collection caps of 64 sources and 1,024 words and at least one of each. Each
source yields after at most 64 words. These bound operations, not the backend's
cost of reading a large body. PATCH clones share structure; no body is pinned
between calls. Additions preserve traversal progress; removed seeds or
readable-membership removals reset the closure
so disconnected descendants are not advertised indefinitely.

This inventory is partial and conservative. A readable aligned word is not a
typed semantic reference; an absent word says nothing about global residency.
Finishing the local scan does not prove that every intended dependency exists.
For encrypted blobs, H identifies the stored ciphertext; neither READ(C), this
inventory, nor the exact-H protocol supplies an application's decryption keys.

`Peer::set_replication(mode, collections)` selects acquisition independently
of activation and authority:

| Mode | Blob acquisition |
|---|---|
| `Demand` (default) | Explicit WANTs only. |
| `Shallow` | Also direct blob references of selected collection records. |
| `Full` | Also positive resident handles learned through selected collections' READ-authorized repair. |

Selecting a collection does not grant READ or WRITE and does not activate it.
Structurally valid but WRITE-inert records can name direct roots; acquiring
their bytes does not admit those records. Full mode no longer sends arbitrary
aligned payload words to the DHT or uses reference-summary Bloom filters to
choose speculative requests. Local aligned-word scanning constructs positive
serving inventory only; remote hydration consumes the resulting known H keys.

The reconciler retains a bounded positive window per selected collection
(currently 4,096 handles), pruning locally readable entries as bodies arrive.
Unattempted handles cannot be evicted by later offers. Once that finite cohort
has received an actual acquisition attempt or become locally readable, later
offers advance the window beyond its serviced prefix. Progress and pass
completion are scoped to the supplying peer: a small peer's completed inventory
cannot reset a larger peer's cursor. A completed pass from that source permits
wrapping to earlier keys, including after its inventory shrinks. At most 128
source cursors are retained per collection; fully serviced, least-recently
observed sources can be replaced, while protected work defers new admissions.
This keeps unavailable early handles from permanently excluding later ones;
it does not make a remote positive hint a guarantee of current availability.
These windows,
bounded remote inventory passes and unavailable providers prevent a promise
that `Full` has reached complete closure. An empty acquisition backlog is not
a completeness certificate. Hints create no durable WANT and do not widen the
explicit collection selection.

Exact WANTs, direct roots and positive hints use the existing KDF(H) discovery,
mutual bearer proof and final hash verification. A shared four-wide fetch
window serves one eligible class's finite round under its original deadline.
Ready verified bodies land individually, without a per-body flush or serving
rebuild; `Peer::reconcile()` publishes one snapshot after the completed batch.
Cancellation drops owned network futures, leaving already landed bytes for
the next refresh. Unstarted work is not falsely fulfilled, and failed exact
requests retain bounded retry backoff.

Missing work is derived from known required handles and the current readable
snapshot, not a retained mirror of durable answers. A raw physical occurrence
alone is insufficient: ordinary reads retain corruption detection and valid
duplicate fallback. Explicit close remains the persistence boundary. None of
these scheduling bounds is a measured throughput or end-to-end completion
guarantee.

## Wire surface

The `/triblespace/pile-sync/26` ALPN keeps the direct operation set narrow;
collection repair has its own new opcode rather than changing unchanged
bearer/DHT framing:

| Operation | Code | Meaning |
|---|---:|---|
| `GET_BLOB` | `0x02` | locator-addressed, mutual-proof exact bearer transport |
| `PROVIDER_PUT` | `0x06` | renew this endpoint's opaque provider lease |
| `PROVIDER_GET` | `0x07` | obtain bounded candidates for one opaque key |
| `FIND_NODE` | `0x0C` | iterative XOR-DHT routing step |
| `COLLECTION_REPAIR` | `0x0E` | READ-gated record, authorization-evidence and resident-blob PATCH walks |

Opcode `0x0D` is no longer served. Mixed-generation collection repair is not
supported: deploy the new repair cohort together. Per-collection topic v2
separates its root advertisements from the previous forwarding protocol.

There is deliberately no store manifest, global inventory authorization,
push-broadcast record, receipt RPC, remote mutable head, or unpublish operation.

The CLI selects explicit collections and bootstrap peers:

```text
trible pile net sync DATA.pile \
    [--key EXISTING_SELF_KEY] \
    --collection COLLECTION_HANDLE [--collection COLLECTION_HANDLE ...] \
    [--peers ENDPOINT_TICKET ...] [--direction bidirectional|read-only|write-only] \
    [--replication demand|shallow|full]
```

The long-running daemon uses one existing durable key for its authenticated
endpoint, signed wakes, health reports and telemetry. Key resolution is
`--key`, then `TRIBLESPACE_KEY`, then `self.key` beside the pile's lexical path.
There is no independently configured network or reporting key. Maintenance
uses that same local key for its work and telemetry; worker labels distinguish
processes, not identities. This CLI convention does not change the separate
ephemeral H-only foreground-reader use described above or grant any authority.

Direction gates only the collection loop: `ReadOnly` pulls collection repair,
`WriteOnly` serves it, and `Bidirectional` does both. Every direction may
announce and serve resident exact blobs under bearer handle H, and may service
durable `Blob(H)` WANTs through KDF(H). These QoS choices do not participate in
collection identity or change which evidence is semantically valid.

Before opening the writable pile or starting its peer, `pile net sync` registers
Unix SIGINT and SIGTERM handlers; other platforms retain Ctrl-C handling. Stop
drops in-flight awaited reconciliation or the idle wait, then withdraws the
serving observation and explicitly closes the backend. It does not change
request deadlines, QoS or the application's clocks. Synchronous work and close
are not preemptible, so this cooperative boundary is not a shutdown-time bound.

## Convergence and failure model

- Concatenation, local insertion, and remote semantic repair perform set union;
  resident inventories remain replaceable local observations.
- Duplicate records collapse by their complete canonical value; fixed-width
  indexes and the wire use a full-width BLAKE3 fingerprint of that value.
  Native capability proofs continue to collapse by their cryptographic
  identity.
- A missed wake does not consume the only opportunity: periodic latest-root
  offers and bootstrap retries can re-establish repair between connected readers.
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
repair says *what changed in a collection* and which blob handles a peer has
positively observed, while KDF(H) discovery plus mutual
bearer proof retrieves only the immutable bytes the local lattice resolver
decides to use.

## Observing replica health

`Peer::health()` and `NetSender::health()` expose a bounded immutable sample of
work the host already performs. Sampling does not run a probe or advance the
host's observation clock. Each repair comparison retains the local and remote
record/AUTH frontiers and composite opaque root pinned when its authenticated
manifest arrived. Semantic health compares record and AUTH evidence, not blob
cache equality: Demand and Full peers can legitimately cache different bytes.
The composite root still schedules repair, including inventory-only changes;
cache churn neither creates semantic stalls nor extends their progress grace.
A comparison stops implying convergence when that sample is stale, the local
semantic frontier has changed, or the serving snapshot has been withdrawn. Receiving
records is progress evidence, not proof they have already become admitted.

The long-running CLI can publish these observations as native facts using
`pile net sync --health`. Reports use the same key as the endpoint. An explicit
`--health-collection <HANDLE>` also enables reporting into an existing admitted
source collection; otherwise the node's private `swarm-health` collection is
used. The health
collection is deliberately not activated for replication, so a broken network
cannot prevent the local reader from seeing its own warning. A new report is
published every minute with `created_at` only: freshness is reader policy, not
a producer-asserted lifetime. `pile net health --max-age <SECONDS>` accepts a
maximum sample age (default 180 seconds, also configurable through
`TRIBLESPACE_HEALTH_MAX_AGE_SECS`). Readers use the creation interval's upper
bound plus that duration and ignore any legacy `expires_at` annotations;
future-created reports remain unknown, and zero accepts no arrived sample as
fresh. Conditions use stable episode identities until their state or attached
quantitative evidence changes; a reader can acknowledge an unchanged alert
once without acknowledging each heartbeat.
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

### Colony work telemetry

`pile net dashboard` reads explicit resident telemetry collections and the
private local health fallback. Terminal and embedded GORBIE views share that
observation; neither scans the blob/native-record inventory, probes links,
acquires missing bodies, maintains a target nor appends a descriptor. GUI
refresh retains one sampler with explicit stop/join/close ownership. A read
failure remains visible; it is not replaced with an empty healthy colony.
Reader failures cross into the display as fixed categories, never backend error
text or source chains: those may contain a full bearer blob handle. Control
stripping and truncation alone do not redact a read capability.

The sampler retains its final display projection while every contributing
collection observation remains dependency-current in a newly refreshed pile
snapshot. It then ages a copy instead of querying historical report headers
again. This is not a report catalogue or an alternative index: changed inputs
run the same queries again. Wall time remains a separate dependency. Moving
before the original projection time or reaching a previously future worker
sample triggers a query, because either may enable a rate omitted earlier.
Rate expiry also clears its prior-sample metadata; the original result stays
unchanged so an in-range clock correction can restore a valid interval.

Partial or failed inputs never qualify for reuse and keep being retried.
This first cut is deliberately all-source: an unreadable selected health
collection also prevents telemetry reuse. A missing key disables the optional
health source instead and does not have that effect. Scoped dependency checks,
snapshot refresh, frame aging and rendering still cost work on unchanged ticks;
no idle-CPU or whole-pile performance claim follows from skipping the queries.

Aggregate telemetry is ordinary relational data, not an external metrics
database. `triblespace_net::telemetry` describes a **subject** (endpoint,
operator worker label, role, optional stage/target/peer) and timestamped samples
linked to it. Use an opaque subject ID; readers never recompute or validate it.
For example, selection, certification, mapping and joining are separate stage
subjects, so a slow unchanged-target pass cannot be mislabelled a slow mapping.
Actual runtime-selected backend is a sample annotation, not a claim inferred
from compiled features. Configured parallelism, active operations, process CPU
and operation wall time are different measurements.
`parallel_compiled` explicitly records whether the relevant parallel path is
in this binary; `compiled_backend` records available build capabilities. A
lazy pool with one observed thread cannot tell disabled code from unused code.
Keep successful passes that publish no equations: their nonzero elapsed time
can expose the cost of proving that there is no new work. They are not the same
as skipped polls, failed observations, or zero computation.

Each sample carries a process session, explicit wall observation time and
monotonic nanoseconds since that session began. Producers use `entity!` at the
existing work boundary, then the normal signed collection commit:

```rust,ignore
use triblespace_net::{health_record as h, telemetry as t};

let subject = entity! {
    h::attrs::endpoint: node,
    t::attrs::worker: "rollups",
    t::attrs::role: "maintenance",
    t::attrs::stage: "mapping",
    h::attrs::collection: target,
};
let sample = entity! {
    metadata::tag: &t::KIND_SAMPLE,
    t::attrs::subject*: subject,
    h::attrs::session: &session,
    metadata::created_at: (now, now).try_to_inline()?,
    t::attrs::elapsed_ns: session_started.elapsed().as_nanos(),
    t::attrs::active: 1_u64,
    t::attrs::completed: completed_in_this_session,
    t::attrs::backend: "cuda",
};
store.commit(telemetry_collection, reporting_key, sample)?;
```

This example is a producer seam, not automatic instrumentation. Do not publish
zero-filled counters after a failed observation. Counters describe completed
work in that session, not distinct blob coverage; queued work describes the
observed selection, not all unknown descendants. Received bytes count verified
payload successfully landed, while sent bytes count payload successfully sent;
neither includes transport overhead. A peer-scoped link sample reports an
actually observed path and RTT, not a DHT candidate or an invented link speed.
Process CPU nanoseconds are reported once in a process scope. `work_ns` sums
completed operation wall durations; concurrent durations can overlap, so its
rate is not CPU cores. Never duplicate process CPU across target rows and add
them together.

The reader keeps two recent header witnesses per subject and queries metrics
where needed. Unknown facts coexist; multiple observed values remain visible
without invalidating the whole collection. A rate needs two fresh, distinct
samples in the same session, increasing monotonic time and nondecreasing
counters. Restart, reset, clock skew, missing or ambiguous data yields an
unknown rate, not zero. The wall clock establishes sample age; it is not the
rate denominator. Reported throughput is an interval average, not physical
bandwidth capacity or proof that background hydration is keeping up.

Publication uses an **explicit operator-selected collection and authority**.
The dashboard's `--telemetry-collection` may name one shared authorized source
or separate node sources. Merely naming an endpoint in a sample is not a proof
that endpoint authored it; trust comes from the selected collection's admitted
writers. This feature issues no grant, activates no shared sync selection and
changes no service. The private local health stream stays independent so broken
telemetry replication cannot hide its own warning. Coverage is only the
observed participants, never an implicit roster of the whole colony.

Sampling is aggregate and deliberately coarser than packet/operation tracing.
The existing facade `telemetry` feature remains the explicit per-span profiling
sink. Neither facility invents a retention policy for append-only evidence.
No raw H bearer capability, payload, locator-to-H inventory or bearer proof
belongs in these colony observations.

#### Sync producer

`pile net sync` opts in with `--telemetry-collection <H>`, optionally
`--telemetry-worker <NAME>`. The node's existing key signs the samples and its
public key identifies their endpoint. The destination
must already be a resident SimpleArchive **source** collection admitting that
writer. A derived SimpleArchive is not a source: its reader ignores root
COMMITs. Reporting never creates a descriptor, key, grant, derived index or
replication selection. To replicate these samples the operator separately
selects their collection through the existing mechanisms.

The producer attempts an ordinary signed append every sixty seconds at the
existing sync-loop boundary. Five subjects distinguish the measurements:

- `hydration`: successful verified reconciler puts and their payload bytes;
  one landing shared by a WANT, selected root or positive hint counts once.
  Local hits and failed puts add no received bytes. `queued` counts distinct
  unreadable known handles from exact WANTs, selected direct roots and retained
  positive hints at the end of that tick's acquisition window. It excludes
  unknown descendants and is not a global blob inventory. A failed exact-set
  observation leaves it absent.
- `serve`: actual accepted inbound GET exchanges in flight, successfully
  sent payloads/bytes and interrupted or failed exchanges. A payload counts
  only after its write and stream shutdown succeed, not merely after lookup.
  This is not a remote landing or persistence acknowledgement.
- `repair`: currently executing collection-peer repair exchanges already
  recorded by host health, not configured concurrency.
- `publication`: active and completed provider-advertisement operations,
  separate from body transfer; acknowledgement is not blob availability.
- `process`: one cumulative user-plus-system CPU observation across all
  process threads, absent if unsupported or unavailable. Core's compiled
  parallel-path bit is separate from runtime pool size or actual CPU effort.

These are boundary observations, not a new timer task inside an awaited
hydration tick. A long tick delays sampling; only returned ticks contribute
their landing counters and completed wall duration. Direct foreground reader
acquisitions are outside the hydration subject. Unmeasured hydration in-flight
counts, transport path/RTT and internal stage timings stay absent. Stale host
health contributes no invented activity zeros. `work_ns` sums completed or
interrupted GET durations in the serving scope and returned-tick durations in
hydration, never CPU time. Reporting errors discard backend cause chains and
leave older samples to age. No reporting append flushes the pile; the owner's
existing close remains its persistence boundary. Same-pile writes remain real
changes: scoped disjoint reads ignore them, while broad name lookup can still
observe the new records.

#### Maintenance producer

`pile collection maintain` and `maintain-all` can opt in with
`--telemetry-collection HANDLE --telemetry-worker LABEL`.
The existing maintenance key signs samples and its public key identifies the
local endpoint, matching the daemon's durable identity. Neither the endpoint
nor the telemetry signer has a separate override. The collection must already
exist as a SimpleArchive source and
admit that writer; a derived view ignores root COMMITs and is rejected. This
option does not create keys, descriptors, grants, maintenance targets or sync
selections. After configuration is validated, publication errors use finite,
payload-free categories and do not turn successful maintenance into a failure.
Choose distinct worker labels for simultaneously running processes on one
endpoint; restarting the same worker keeps its scope identity but starts a
new session, so a rate never bridges that restart.

Four scopes keep distinct quantities separate: process CPU, maintenance hops,
passes, and successful passes with no merge/derive publication calls. Hop
configuration reports outer-loop concurrency, not the size of a lazy Rayon
pool; Core's compiled parallel-path capability is reported separately. The
merge/derive counters increment after a local equation insertion succeeds.
They include idempotent successful calls and multiple witness equations for
one output. They are **not** counts of new physical records, unique outputs,
kernel invocations, or changes in the collection census. Successful
publications remain counted even if a later part of the pass fails.

Sampling uses existing loop/hop boundaries, with a shared attempt limit of
60 seconds by default (`--telemetry-interval-secs`) and one final close sample.
There is no detached heartbeat or extra observer thread. A long synchronous
hop can therefore leave a stale report; freshness must not be manufactured.
Known merge/derive backlog and separate selection/certification/mapping/join
timings are left absent until those operations provide measured seams.

Appending telemetry never advances or filters the maintenance baseline.
Disjoint exact-collection interests ignore the append. Broad name/all-record
interests may wake once after an emission; all boundary attempts, including
failed publications, share the rate limit. Do not hide such a wake by moving
the baseline across the write: concurrent source changes must remain visible.
An unchanged-file poll which never enters a pass must not increment pass or
no-publication counters, and must still reach the telemetry cadence check.

Schema anchors were minted with `trible genid` on 2026-09-16; their exact values
and field meanings are pinned in `triblespace-net/src/telemetry.rs`.

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
