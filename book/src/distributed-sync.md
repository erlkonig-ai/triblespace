# Distributed Sync

`triblespace-net` synchronizes collections rather than exposing one ambient
store inventory. Its protocol follows the same decomposition as the collection
model:

1. one QUIC connection per peer pair carries typed streams: one long-lived
   `recon/1` stream for the grant exchange and for every collection's
   peering, announcements and pull walks, and short `dht/1` and `blob/1`
   request streams;
2. for each collection both sides select, peered neighbours announce the
   collection's record root to each other, and a side that hears a different
   root pulls what it lacks with Merkle walks over the collection's foundation
   records and scoped AUTH (and, between two Full neighbours, its held blobs),
   landing what arrives as it goes; and
3. exact blob handles fetch only the immutable bytes a resolver actually
   chooses through a collection-independent, mutually authenticated bearer
   protocol.

No global team, mutable roster, gossip topic, durable OFFER/GOSSIP bit, or
second replicated inventory is needed, and no list of peers. Which collections
a host syncs is a register in its own pile, and whom it syncs them with comes
from the same pile: the keys its records and grants name. Held sets are local
observations, not durable claims merged into a collection. The descriptor
already states independent READ and WRITE policy, and iroh authenticates the
endpoint key on each direct connection.

## Four independent capabilities

The boundaries are deliberately small:

```text
know C           -> find holders of C's descriptor and ask them to peer for C
prove READ(C)    -> be sent C's announcements, records, scoped proofs and held set
know H           -> derive its opaque locator, discover providers, and fetch H
satisfy WRITE(C) -> make a signed COMMIT or DERIVE active in C, and send C to a reader
```

`C` is the exact 32-byte collection descriptor handle. `H` is an exact blob
handle. Knowing C permits discovery of its ordinary descriptor-blob providers
(H=C). They are peering candidates, not certified collection participants, and
a peering request tells them only that the asker selects C and which
credentials it holds for C. H is the bearer capability and private discovery
secret for one exact immutable value. The provider directory sees only
blob-locator KDF images and endpoint-bound tokens, never raw handles or a
collection-participant namespace.

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
WRITE never activates a MERGE: each store believes only the MERGEs its own
host key signed, so another host's MERGEs stay in the ledger and fold into
nothing.

## The collection repair product

For one collection, sync compares three PATCH components:

- every structurally valid foundation record naming exact C: signed `COMMIT`
  and `DERIVE` records independent of current WRITE(C) admission. A collection
  is a set of foundations; a `MERGE` is its signing host's own lattice node,
  is never served, and a `MERGE` value fails the walk that received it;
- every signature-valid native proof scoped to exact resource C and beginning
  at a root named by C's supported policy bindings, without requiring its grant
  handles to match those bindings. Subordinate-resource transport
  also includes proofs for R whose immutable descriptor declares C as its repair
  audience, under R's own policy roots; and
- C's held-blob set: the resident blobs reachable from C's descriptor, its
  foundations' direct references and its proofs' capability definitions (see
  *Held blobs* below). Only a host that replicates C in full keeps one.

Each set is represented by an immutable BLAKE3-Merkle PATCH. Collection
records are keyed physically by the full 32-byte fingerprint of their exact
canonical value; authorization evidence uses a `repair_collection | proof_hash` PATCH
whose values share ownership of the original proof bytes. Only C's prefix is
exposed; the wire leaf key is the 32-byte proof hash and its value is the
complete native proof body. The host keeps one such index per collection
overlay, not a shared global inventory. Resident-blob leaves use exact H as
their 32-byte key and have an empty value. There is no companion claim blob or
authorization closure to transfer.

The record root (`record_root`) commits to C and to the record and
authorization-evidence summaries, including their leaf counts, under a
versioned domain (version 4). It discloses no record, proof, count or
component root. The held set is not part of it: the held set's Merkle root,
all zeros when the set is empty, is the held digest, which only two neighbours
that both replicate C in full exchange.

The authorization projection authenticates proof bytes rather than taking a
snapshot of who is admitted. Unavailable definitions, delegate-only grants,
and quorum-incomplete paths remain evidence. Admission separately interprets
the definitions' invocation and delegation action sets under the requested
action's policy roots. Generic authority has no clock. Each root path is
evaluated independently; no fixed-point over sibling paths can create
delegation support.

A grant reaches its subject through the grant exchange (below): any connected
holder of a proof naming a key hands it to that key, and the host whose key
signed a grant dials its subject. That is the capability delivery boundary,
not a Secrets-specific channel. Once one collection participant has the proof,
the authorization walk distributes that one record to READ(C) peers.
Interpretation needs any referenced capability definitions to be resident;
walks carry proof bytes, never definition bodies, which travel by hash over
`blob/1`. An application may use the same proof kernel for another resource,
such as Secrets key delivery, without treating collection READ as decryption
authority.

Subordinate-resource transport reads R's `resource_collection: C`
and its policy bindings from the same descriptor entity, without requiring a
mutable referencing fact in C. When R's descriptor is not resident, the
authorization walk fetches it by hash from the peer it pulls from, over
`blob/1` and at most 1 MiB. If that descriptor routes the proof to C, both
land; otherwise the proof stays deferred and the pull does not count as
completed, so the next announcement of the same root pulls again. C's record
walk continues either way, and no WANT is emitted. The walk is still served by
the responder's decision to send C to the puller, not by R's action. Open
action policies remain explicitly non-enumerable.

This product matters. Synchronizing only collection records would miss the
case where a newly arrived proof activates an old COMMIT. Synchronizing a whole
proof store would disclose unrelated capability structure. The complete repair
evidence algebra remains `Record × AuthorizationEvidence`, scoped to C.
The held component is different: it observes physical availability and may
shrink or be rebuilt. It does not create semantic membership or change WRITE
admission. The receiver always derives its admitted view locally; record and
proof arrival therefore commute, and a publisher need not possess or present
its own WRITE grant merely to replicate an inert signed record.

The host also updates these components independently. When a store snapshot
reports unchanged collection records, its existing record PATCH is shared into
the next overlay without re-enumeration or Merkle hashing. Changed
collections apply selected record additions and removals to that retained PATCH.
Native stores obtain the difference from persistent indexes; cold activation
still constructs the initial full overlay. Blob arrival
still refreshes the authorization observation: a newly resident capability or
subordinate-resource descriptor can enable admission or proof routing without
changing any record. The held set comes from the store's own index, fixed by
the same snapshot; it can change the held digest, never the record root.

A DERIVE is a foundation of its derived collection and is pulled like a COMMIT.
A MERGE never replicates: each host builds its own merge lattice over the
foundations it holds, and believes only the MERGEs its own key signed.
Another host's MERGE records may sit inert in a pile, but they are neither
exported nor accepted, and their result blobs are never held for sync.
Signature verification happens when decoding foreign record bytes, not when
rebuilding the local PATCH or observing the local store again. Dense record
tag 7 carries a 224-byte DERIVE body; each wire value has one additional tag
byte. COMMIT's 192-byte body and signature transcript are unchanged.

A record pull still transfers only records naming exact C. A DERIVE's source
witness does not authorize disclosing another collection's records to a
READ(C)-only recipient. The witness fingerprint is not a blob handle and is not
fetched through the blob DHT. A replica lacking that record closure cannot
claim exact support merely because it received the output endorsement;
source-record provisioning remains a separately authorized concern. In
particular, the current protocol does not automatically transport a
cross-collection witness closure.

## Choosing what to sync

A host syncs exactly the collections its pile selects. The selection is one
register per collection in the pile's own configuration collection: the
collection named `config` under `private_policy` of the pile's signing key.
Its handle is a function of that key (`selection::config_handle`), so nothing
has to remember it, and a pile that was never configured reads as an empty
configuration in which nothing is selected.

A register state names its collection (`sync_collection`) and says whether it
is selected (`sync_selected`). States are ordered by `metadata::supersedes`:
every write mints a fresh id and supersedes every head it saw, so a change
needs no clock and the history stays readable. `sync_selection` reports the
heads rather than choosing among them: heads that agree give their value, heads
that disagree give `Conflicted`, and a head the reader cannot decode is
skipped. Only `Selected` selects; an unset, unselected or conflicted register
selects nothing. The schema lives in `triblespace_core::collection::selection`,
so the daemon and every program that writes the selection share it. Its
anchors were minted with `trible genid` on 2026-10-05:
`99D9A2B7C5636FEFDE482DB3A6D01EE6` for `sync_collection` and
`24EB46425226C0025A3C85D34F8919CE` for `sync_selected`.

An operator writes and reads it with the CLI, under the daemon's key
resolution:

```text
trible pile net select DATA.pile [--key KEY] COLLECTION_HANDLE [COLLECTION_HANDLE ...]
trible pile net unselect DATA.pile [--key KEY] COLLECTION_HANDLE [COLLECTION_HANDLE ...]
trible pile net selection DATA.pile [--key KEY]
```

`select` and `unselect` write one state per handle that supersedes every head,
so they also settle a conflict between earlier writers. Unselecting is a state,
not a removal, and a later select supersedes it. Each line names the handle and
the collection's name, or says that no descriptor is resident yet: the
selection stands and applies once the descriptor arrives. `selection` lists
every collection the configuration names with its value (`selected`,
`unselected`, `unset`, or `conflicted between N heads`) and its name; it
writes nothing and probes nothing.

The host reads the register from each serving snapshot, so peering follows a
change at the next store observation. `pile net sync` also reads it at startup
and before each reconcile pass, about once a second, to activate newly selected
collections. An unselected collection stays active until the process exits,
but its peerings end with UNPEER frames and it is no longer announced. A
selected collection whose descriptor is not resident is fetched by its handle
through the DHT (the descriptor warmup under *Live request scheduling*), and
peering for it begins once the descriptor validates. A node that does not
select C never asks to peer for C and refuses every request for it.

### Where the sync daemon listens

The same configuration holds one more register per endpoint key: the
addresses the sync daemon running as that key is bound to. A state names the
endpoint (`sync_endpoint`) and lists every address (`sync_address`, a
`SocketAddress`); a state that lists none says the endpoint is bound to
nothing. States supersede each other like selection states, with a fresh id
per write. `pile net sync` writes the register
(`selection::write_sync_addresses`) on its first pass and whenever the sockets
its endpoint is bound to change, unless the register already holds exactly
them. A socket bound on every interface is recorded as loopback, because the
reader is a process on the same machine that opens the same pile. A reader
(`selection::sync_addresses`) takes every head's addresses: they are hints for
a dial, so heads that disagree are tried together rather than reported as a
conflict. The anchors were minted with `trible genid` on 2026-10-06:
`0F1FE7641D8246229EDAB3C2FF3E152C` for `sync_endpoint` and
`55C20BF071C57CAA74D0481ED4C3077A` for `sync_address`.

This register is where the daemon's endpoint ticket went. Nothing copies a
ticket from one daemon into another's command line any more: a process reaches
its own pile's daemon through the pile, and every other peer through the
pile's content (*Where peers come from*).

## One connection per peer

A `ConnectionTable` holds the connections of both directions, keyed by the
remote's TLS-authenticated endpoint key. Every connection, dialled or
accepted, runs one accept loop, and the first byte of every stream is its type
tag, read before any permit is taken:

| Tag | Stream | Carries |
|---:|---|---|
| `0x10` | `recon/1` | the connection's one long-lived stream: grant exchange, and every collection's peering, announcements and pull walks |
| `0x11` | `dht/1` | one DHT operation byte and its exchange: `FIND_VALUE` or `PROVIDER_PUT` |
| `0x02` | `blob/1` | one locator-addressed bearer exact GET |

An unknown tag, or an unknown `dht/1` operation, resets only its own stream
(`RESET_UNKNOWN`), and a stream that sends no tag within ten seconds is
dropped. `recon/1` takes no permit. A request stream (`dht/1` or `blob/1`)
does: an opener keeps at most 16 open per connection, the accepting side holds
at most 32 per connection and resets the rest (`RESET_BUSY`), and at most 16
are served at once across the host, each within 300 seconds. A stream on a
connection that carries no peering first takes one of 8 permits that every
such connection shares, and then one of the host's; a stream on a neighbour
connection takes only the host's. Keys cost nothing, so a share per key or
per connection would bound nothing: strangers that hold their requests open
until their deadline, on however many connections, occupy at most half the
host, and the other half stays for the peers it syncs a collection with.

The dialler opens `recon/1` as it connects, and its first frame, OPEN, carries
the dialler's sequence number. The counter starts at the wall clock in
nanoseconds, so a restarted node's dials outrank the ones it made before. When
a pair holds two connections, both sides keep the same one: of crossed dials,
the one dialled by the lower key; of two dials by one side, the one with the
higher sequence number. The loser drains: nothing new is opened on it, and it
closes once no request stream is in flight on it and no frame has crossed it
for two seconds. What this side had asked to peer for on it, it asks for again
on the connection kept.

A connection closes after 120 seconds without a frame on any of its streams,
sent or received. Announcement timers cap at 60 seconds, so a connection that
carries a peering does not go idle. Above 64 connections in one direction the
least recently used one is evicted, draining and unused connections first. A
neighbour connection, one that carries a peering, is never evicted.

A connection carries exactly one `recon/1` stream, the dialler's. One opened
by the accepting side, or a second one, is a protocol violation and closes
the connection. Frames go both ways at once, and both directions are read
concurrently. When the stream ends, for any reason, the connection closes with
it: the peer finished or reset it, it failed, or a writer waited 60 seconds
for stream credit because the peer stopped reading. Every walk and every
peering on the connection ends, frames still queued for it are dropped, and
nothing is reopened on it. What replaces it is a later dial, which the
candidate order governs (see *Neighbours*): a peer whose stream ended comes
back only through a fresh dial when a collection's order next reaches it. A
peer that ends every stream as it arrives therefore costs a collection one
dial per redraw of its order, at most one a minute, rather than a loop of
streams.

A connection's frame queue refuses no frame, so what it holds is bounded by
what is put on it. A walk responder, and a side asked to peer, leave a request
unanswered while the connection already queues 1,024 frames, at most 64 KiB
each, and the grant exchange answers one proof request per digest it sent; a
peer that asks faster than it reads therefore stops being answered rather than
growing the queue.
The walk it asked for ends at its own deadline, and an unanswered peering
request waits until the stalled stream's end closes the connection. A puller
keeps at most 256 walk requests in flight per connection, a quarter of that
bound, since the responder's queue also holds its own requests and other
frames, so a puller that reads is always answered.

A `recon/1` frame is its kind (one byte), a big-endian `u32` payload length,
and a payload of at most 64 KiB. Every frame about a collection starts with the
collection's 32-byte handle, so the frames of every collection share the
stream:

| Kind | Frame | Payload |
|---:|---|---|
| `0x01` | OPEN | dialler sequence number, `u64` |
| `0x02` | PROOF_DIGEST | digest of the sender's proofs naming the receiver |
| `0x03` | PROOF_REQUEST | empty |
| `0x04` | PROOFS | proofs naming the receiver |
| `0x05` | PROOFS_END | empty |
| `0x10` | PEER_REQUEST | collection, flags, credentials |
| `0x11` | PEER_ACCEPT | collection, flags |
| `0x12` | PEER_REFUSE | collection |
| `0x13` | PEER_FLAGS | collection, flags |
| `0x14` | CREDENTIAL | collection, credentials |
| `0x15` | UNPEER | collection |
| `0x20` | ANNOUNCE | collection, root, flags, held digest |
| `0x30` | WALK_REQUEST | collection, walk, request |
| `0x31` | WALK_RESPONSE | collection, walk, response |
| `0x32` | WALK_END | collection, walk, side, reason |

Peering flags are one byte: bit 0 is the send flag, bit 1 the full flag, and
in a PEER_REQUEST bit 2 marks an invitation. An ANNOUNCE has its own flags byte
after the root: bit 0 marks a reply, and bit 1 says the sender's 32-byte held
digest follows. A proof digest is a presence byte, a Merkle root (zeros for
the empty set) and a big-endian `u64` count. Credentials, like the proofs of a
PROOFS frame, are a big-endian `u16` count followed by that many proofs, each a
big-endian `u16` length and its bytes. A reader skips a frame kind it does not
know and a proof whose bytes do not decode; a known frame whose payload does
not parse is a protocol violation and closes the connection.

## Peering

Peering for C is two keys' wish to sync C over the one connection between
them, and C is the unit of everything that follows: each collection has its
own neighbours, announcements and timer, multiplexed on the connection. A
side asks a key to peer for C only if it selects C. The PEER_REQUEST names C
and carries the asker's flags and credentials:

- the send flag says the asker admits the peer, which passes READ for C under
  the asker's evidence;
- the full flag says the asker replicates C in full; and
- the credentials are the asker's own proofs for C naming itself, truncated at
  its prefix, READ and WRITE alike, at most 1,024 of them. Those that do not
  fit the request travel first in CREDENTIAL frames.

Apart from the grant exchange, which hands a key only the proofs naming that
key, these credentials are the only collection data a side sends before it is
admitted. Its other frames before admission carry only handles, hashes, flags
and digests.

The key asked accepts only if it has C active with its descriptor resident,
selects C, and has room for the peering (at most 16 per collection that others
asked for or that it invited, unless this connection is already peered for C),
and only if the asker passes READ for C under its evidence and the presented
credentials, or the asker set its send flag and passes WRITE. PEER_ACCEPT
carries the acceptor's own flags. C flows only in a direction whose sender set
its send flag. A writer that cannot read therefore asks a reader with its send
flag set, the reader accepts with its own flag unset, and records flow from the
writer to the reader only.
A refusal is a PEER_REFUSE frame; `recon/1` stays open.

Admission is evaluated again whenever its inputs change: a store observation
that changes C's evidence or brings a missing definition, a CREDENTIAL frame,
a change of replication mode. A peering's send flag follows READ admission and
its full flag the replication mode; a changed flag goes out as PEER_FLAGS, and
a peering whose two send flags are both unset ends. When a node's own proofs for
C change, it sends CREDENTIAL frames to C's neighbours and to keys that refused
it. Credentials a peer presents are kept only if they name the peer and are
evidence for C. Unselecting C sends UNPEER to each of C's neighbours, and a
closed connection ends its peerings.

Two Full neighbours are the two sides of a peering in which both set the full
flag and each counts the other as a reader or writer of C: this side sends C
to the peer, or the peer passes WRITE under this side's evidence. Only they
compare held sets. A DHT provider that may neither read nor write C is never
a Full neighbour, whatever its flag says, so it cannot make this side fetch
the blobs it names and pass them on; changed evidence re-evaluates which
peerings count.

A side remembers, per connection, the requests it refused and the capability
definitions whose arrival could admit them: admission names missing
definitions (`QuorumOutcome::Undefined`) rather than collapsing to a refusal.
Those definitions are fetched over `blob/1` from the asker, then from its
credentials' root and delegated keys among connected peers. When a
credential, a fetched definition, a new proof or the refuser's own selection
admits a refused request, the refuser sends an invitation: a PEER_REQUEST with
the invitation bit, which counts against the receiver's room for inbound
peerings. The asker never asks again on its own.

### Neighbours

Each selected collection has up to five neighbours this side asked for, plus
the peerings others asked for. The candidates come in three tiers:

1. grant-chain keys (C's policy roots and the roots and delegates of its
   retained proofs) and owners (signers of C's records who pass WRITE) that
   pass READ under local evidence;
2. the other grant-chain keys and owners; and
3. DHT providers of `blob_locator(C)`, the holders of C's descriptor blob.

Within a tier keys are ranked by `blake3(salt || key)` under a salt drawn
fresh for each order. Readers come first because a signer that cannot read
does not relay; free DHT keys come last. The position in that order is the
only retry state: a refusal, a failed dial or an ended peering (its
connection closed, as it does when its `recon/1` ends) moves on to the next
candidate. A key that refused is not asked again on that connection, and
the others come round again only when the order is redrawn. Reaching the end
redraws it with a new salt, no sooner than 60 seconds after the last draw
unless the candidates changed. A redraw that is not merely of changed
candidates also looks up C's DHT providers again, at most three such lookups
at once per host, each with a three-second lookup window. Neighbour sets are
refilled every second.

Every ten minutes, when a collection's five asked-for places are full and
another candidate is available, one healthy asked-for neighbour chosen at
random is unpeered and replaced by the next candidate, so neighbour groups that
formed separately during a partition meet again after it heals.

`HealthSnapshot::peerings` lists every peering on an open connection: its
collection and peer, whether this side asked for it, whether both sides
accepted, which way C flows, and which side refused the other.

## Announcements

An announcement says "my root for C is R", where R is C's record root. It goes
only to C's neighbours, and only to those this side sends C to. Between two
neighbours that both replicate C in full it also carries the sender's held
digest; other neighbours get none.

Each selected collection has one announcement timer (`WakeSchedule`), in the
style of Trickle: intervals of two to sixty seconds, doubling while C is quiet,
with one transmit opportunity in each interval's second half. At that
opportunity the side announces C to each neighbour it sends to, except one that
announced an equal state during the interval. Announcements are unicast and
nobody overhears them, so this suppression is per neighbour. A neighbour that
this side newly sends to is offered the state within two minimum intervals.

When C's root changes while no record pull of C runs, as after a local append,
C's timer restarts at its two-second interval. A root that changes while a
record pull of C runs is that pull landing and resets nothing; the pull resets
the timer once when it completes, so the merged root goes out once instead of
every intermediate root of a long pull. An announcement already due during the
pull may still carry the earlier root. A changed held set resets nothing
either: the next announcement carries it, so it reaches a Full neighbour within
about two maximum intervals.

An announcement whose root, and held digest where both sides carry one, equal
this side's ends the comparison and suppresses this interval's announcement to
its sender. Otherwise:

- a root that differs, and is not the root of the last record pull from that
  neighbour that completed, starts a record pull from it;
- a held digest that differs, and is not the one the last completed reference
  pull from that neighbour walked, starts a reference pull; and
- if a pull starts, this side sends C to the announcer, and the announcement is
  not itself a reply, this side answers at once with its own state, flagged as
  a reply, from which the announcer pulls in turn. The reply counts as this
  interval's announcement to that neighbour and is never answered.

An announcement heard while a pull of C from its sender runs waits: the latest
replaces earlier ones, and it is heard once every pull of C from that sender
has ended. A heard root is never forwarded: each side announces only its own
state.

The last completed pull per neighbour is what keeps a one-way peering quiet.
A writer that cannot read keeps announcing a root the reader never equals; the
reader pulls it once and then treats it as equal. A pull counts as completed
only when it landed everything it requested without a failed insert and left no
proof deferred, so an incomplete pull is retried by the next announcement of
the same root.

The load is per collection and neighbour. A test runs 130 collections between
two quiet neighbours on one `recon/1` stream over 20 minutes of virtual time on
the simulated transport; one run heard 2,598 announcements in both directions
together, about one per collection and minute between the two.

## Pull walks

Each side pulls what it lacks with its own walks, so two pulls on one
`recon/1`, one in each direction whose sender sends, reconcile both sides. A
record pull is two walks of one peer's PATCHes of C, its records and its
authorization evidence, and completes when both do. A reference pull, only
between two Full neighbours, is one walk of the peer's held set of C.

A walk is named by its collection, its kind (records `0`, authorization `1`,
references `2`) and a `u16` number the puller counts per peer, collection and
kind. A side runs at most one walk per peer, collection and kind. A walk ends
by completing, by failing, or after 60 seconds without progress while something
is owed to it, and its number
retires: a frame, landing acknowledgement or blob fetch of an ended walk is
dropped and touches no successor.

| Frame | Payload after the collection, kind (`u8`) and number (`u16`) |
|---|---|
| WALK_REQUEST | `0` open; `1` node: prefix; `2` value: key |
| WALK_RESPONSE | `0` summary: root, count; `1` branch; `2` leaf; `3` value: key, bytes |
| WALK_END | side (`0` puller, `1` responder), reason (`0` done, `1` refused, `2` failed) |

A branch is its prefix (a length byte and the bytes), digest, leaf count,
representative, end depth and children, each an edge byte, a digest and a leaf
count. A leaf is its prefix, digest and key: a value travels only when the
puller asks for it. Every key is 32 bytes relative to its kind's base, and
integers are big-endian.

At the walk's open the responder pins its current serving snapshot of C,
provided it sends C to the puller: its peering for C sends to the puller, or
the puller passes READ under the pinned evidence. It answers with that PATCH's
root and leaf count, or ends the walk as refused. A new open replaces the
puller's earlier walk of that kind. Every node and value then comes from the
pinned snapshot, so responses cannot splice two moments together and need no
historical-root cache; a requested prefix or value absent from it ends the
walk as failed. The responder leaves a request unanswered while the
connection already queues 1,024 frames for the puller (*One connection per
peer*); a puller that reads again is answered again.

The puller compares each child digest with its own PATCH at that prefix, fixed
when the walk starts, and requests only the children that differ. Whether a
leaf's value is needed is checked against the live store instead, so a value
another walk landed meanwhile is not fetched again; a duplicate fetch is
harmless under union. A walk keeps at most 64 node requests, value requests and
blob fetches in flight and hands at most 1,024 values to landing ahead of their
acknowledgement; while that queue is full it requests no further nodes. The
walks on one connection keep at most 256 requests in flight together, opens
included, and the walk with the fewest in flight gets the next one that frees.
A walk waiting for that budget is owed nothing, so its 60-second deadline
starts only when it sends. The
puller validates node summaries against the requests they answer, so every node
hash-chains to the pinned root. A record value must decode, with its
signature, to a COMMIT or DERIVE naming C under the fingerprint it was
requested by. A proof value must match its id, verify its signatures and be
evidence for C before it lands; a proof over a subordinate resource whose
descriptor is missing waits for that descriptor, as described above.

A reference walk's leaves are held handles. A handle missing from the local
held set joins it: one resident here is noted held as it is, and another is
fetched by hash from the same peer over `blob/1` and lands with its note. A
failed fetch leaves the pull incomplete, and the blob stays in the next
difference. Because a held set is a flat closure, one reference pull exposes
the missing frontier at every depth.

A walk completes when its count proof closes, every value it requested and
every blob it fetched landed without a failed insert, and no proof stayed
deferred. Only then does the pull's root become the neighbour's last completed
one. A failed or abandoned walk keeps what landed, and the next walk skips the
subtrees that now match. The puller's requests disclose where it differs from
the responder, which is one more reason walks are served only to peers the
responder sends C to.

### Landing

One landing task per host lands the values of every walk in arrival order. It
takes up to 4,096 waiting values at a time, inserts them in one pass, publishes
one serving snapshot, and then tells each walk how many of its values landed
and how many inserts failed. A group whose snapshot cannot be published counts
as failed and withdraws serving. Later leaves of every walk are therefore
checked against what already landed. The task also reobserves the store every
two seconds, so appends by other processes reach the serving snapshot, and
from there announcements. Landing does not flush: explicit close remains the
persistence boundary.

Serving snapshots are a latest-value handoff. The peering, announcement and
walk tasks each read the newest observation, never a queue of them. Evidence
that arrives outside walks (proofs from the grant exchange, fetched
definitions, descriptor warmups) crosses the bounded admission bridge and lands
at the next `Peer::refresh`, which also reobserves the store at once.

## Grant exchange

A grant notifies its subject. On every connection, and whenever it changes,
each side sends on `recon/1` a PROOF_DIGEST of the proofs it holds naming the
other side: the subject-truncated prefixes its collections' evidence indexes
under that key. A side whose own proofs naming itself differ sends one
PROOF_REQUEST per digest and connection; the answer is PROOFS frames closed by
PROOFS_END and holds only the proofs naming the asker's TLS-authenticated key,
at most `MAX_PROOFS_PER_EXCHANGE` (1,024). The sender answers once per digest
it sent on that connection, and a request before any digest goes unanswered.
The answer reflects what is held when it is sent, so an asker whose request
crossed a newer digest already has the newer state. A received proof, like a
peer's credential, is kept only if it names the receiver or the sender.
It lands when its held descriptor validates it, waits in memory while the
descriptor is missing (`HealthSnapshot::available` lists its collection), and
is dropped otherwise. Waiting proofs are bounded: one sender keeps at most 256
of them and every sender together at most 1,024, and the rest are dropped
before their signatures are checked and fetch nothing. A sender's waiting
proofs are dropped when its last connection closes, so keys that came and went
do not keep the bound full. A proof that is
evidence under a held descriptor never waits, so these bounds keep none of
those out. A proof for a collection that is not active is validated against
the resident blob at its resource, which is taken for a descriptor only up to
1 MiB and decoded at most once per store observation, not once per proof.

The definitions a proof names are fetched over `blob/1` from the sender, then
from its root and delegated keys among connected peers, as are those a refused
peering request waits for. Definitions are policy metadata and are fetched
under the same 1 MiB bound as descriptors, so a key cannot make a node store a
blob of its choosing by signing a proof whose capability handle names it. A
host also dials the subject of every grant its own key signed, once per grant
and process, so a grant written while the subject is unknown still reaches it.

## Blob transfer is lazy and bearer-addressed

A record pull does not fetch descriptor dependencies, payloads, metadata,
attachments, or derived artifacts. It transfers lattice evidence, not those
bytes; only a reference pull between two Full neighbours fetches blobs, and
only those the peer holds in that collection. The separate bounded host
metadata warmup described below is not part of a walk. A resolver can then
select the cheapest resident support-equivalent cover and request only the
missing immutable handles that matter to that computation.

Knowledge of a full content hash H is the read capability for those exact
bytes and the secret needed to discover them. Publication and lookup derive a
full-width opaque locator under a random 32-byte context key:

```text
L = BLAKE3(LOCATOR_CONTEXT || H)
```

The input is exactly one 64-byte BLAKE3 block, so a locator costs one
compression. Until generation 27 it was a `derive_key` over a context string,
which cost two; the locator is computed for every resident blob on every
index build, so the difference is paid many times.

This is not encryption or protection against guessing the exact blob content.
Someone who can guess those bytes can compute both H and L and confirm a
matching provider token. Confidential low-entropy content needs encryption;
the additional locator hash prevents disclosure of H from a copied L, not
reconstruction of H from already-known or guessed bytes.

Every served resident blob may renew a soft lease at L on nearby XOR-DHT
nodes. The lease carries the token `keyed(provider; H || TOKEN_CONTEXT)`: keyed
by the provider's authenticated endpoint ID, over H and a random 32-byte
context, one block. A requester who knows H rejects
forged candidate entries before dialing; the directory learns neither H nor
collection membership.

An exact GET sends only L. The provider first proves knowledge of H with
`keyed(provider; H || requester)`; only then does the requester answer with
`keyed(requester; provider || H)`, and only then do bytes flow, checked
against H on arrival. Each proof is one block and binds both authenticated
endpoints. H sits on opposite sides of the two messages, so while H is secret a
requester that knows only L cannot echo the provider's proof back, and the proof
a provider hands out is not the requester proof of the reversed connection. The
separation rests on H being secret, not on algebra: an H equal to an endpoint
identity would make the swapped pair coincide, but such an H is public anyway.
An exchange whose two endpoints are the same identity authenticates nothing and
is refused.

When a DHT node answers `FIND_VALUE(L)`, it also consults its
already-installed, snapshot-coherent L→H index. If L is resident there, it
returns its own endpoint-bound token without waiting for a `PROVIDER_PUT`.
This deliberately extends the old lease-only answer: one reply slot is reserved
for the resident self hint and any stored self entry is deduplicated. At most
63 other live leases follow in peer-ID order; when 64 are available, one chosen
uniformly at random makes room. Without a resident self hint, the usual limit
remains 64 leases.

Each directory node keeps a bottom-k sample of every key's publishers rather
than its first arrivals. It ranks each (key, provider) pair by BLAKE3 keyed
with a salt it draws once at start-up and never sends. A key may store an even
share of the remaining membership budget, never less than one 64-entry reply
and never more than 1024, which bounds what one request walks. A newcomer to
a key at that cap is kept only if it ranks below the key's largest-ranked
member, which it replaces. A shrinking cap trims a key's largest-ranked members
when the key is next touched. A renewal keeps its place.
Arrival order therefore does not decide membership, renewals cause no churn,
and the K replicas of a key keep independent samples. Because the salt is
secret, a publisher cannot choose identities that rank well. A key storing
more than 64 members answers each request with a fresh uniform sample of 64,
so repeated requests reach every member.

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

A lookup is one `FIND_VALUE(L)` per hop. Each authenticated reply carries the
responder's K closest verified routes and its hints for L, so no directory
round follows routing: every replica the lookup reaches has already answered
with its hints. Named referrals remain unverified candidates until they answer
in turn. The requester checks every token and drops a hint whose token does not
prove knowledge of H before any dial. The local directory answers like a
replica's when the first authenticated reply, or the closed lookup, places this
endpoint among the key's closest K; no cold lookup starts from a retained local
provider lease before routing progress. Publication runs the whole lookup and
puts to the closest K responders, ignoring their hints. Collection discovery,
which supplies the last tier of a collection's peering candidates under the
descriptor's own locator `blob_locator(C)`, runs the whole lookup and takes
the union of every verified hint.

An exact-H fetch starts a verified provider as soon as a reply names it, rather
than waiting for the lookup to finish. Lookup requests and exact provider GETs
share three concurrent request slots. While routing is open, provider GETs
occupy at most two, leaving capacity for fresh routing; a usable provider takes
the next such slot. Two progressing acquisitions leave only one routing slot in
the same unchanged routing window; this is not a proof of equal discovery
coverage under every timing pattern. Empty early hints do not end
a lookup whose routing remains open. At most 64 distinct providers can be
attempted per fetch.
Duplicate hints never spend another attempt. Pending providers are ranked
among the hints received so far, bounded by the remaining attempt allowance,
by `keyed(salt; L || provider)` under a salt the requester draws once and never
sends; collection discovery ranks its union the same way. A public rank such as
the provider's XOR distance from L would let a provider grind an identity that
every requester tries first. A later better-ranked hint can replace pending
work, not an already-started request. The transient attempt subset is therefore deliberately arrival-sensitive;
it need not equal the closest 64 in the final reply union. Collection discovery
still waits for its canonical, reply-order-independent union.

This removes routing's final barrier when early evidence is useful, not every
possible head-of-line delay. Three stalled requests can still occupy the shared
slots; in particular, two stalled provider GETs and a stalled lookup request
keep a later replica's hint from arriving within a shorter caller deadline. An
early large set of valid but unavailable hints can also exhaust the 64-attempt
cap before a later useful hint arrives. The caller's existing end-to-end
timeout, per-operation deadlines, pooled-connection cancellation rules,
provider-token checks, mutual bearer proof, body-receive memory bound, and
final hash check are unchanged. Routing expiry drops only issued lookup
requests; their hints are then unknown, so a fetch that found no verified hint
reports the lookup incomplete rather than the blob absent. A progressing body
continues within the original caller deadline. Early
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
long-running sync daemon needs. `Peer::lazy(store, key, config)` keeps the same
store API but defers its host until the first absent-handle acquisition, explicit
network fetch, or collection activation. Resident reads, snapshots, local writes,
flush, and close start no thread or endpoint and build no serving/bearer index.
Its snapshots are still exactly the backing store's resident snapshot type.
Acquisition returns local observation errors rather than treating them as misses,
and a host startup failure leaves resident operations usable. Startup is attempted
once per peer; opening a new peer is an explicit retry. Activation logs startup
failures without activating the collection, while acquisition returns the error.

A foreground H-only reader need not activate any collection. It can use a
distinct ephemeral transport key, its pile daemon's key as its first contact
(`PeerConfig::daemon`), and a zero provider-publication budget without
borrowing its authorship signer's or the running daemon's endpoint identity.
Network acquisition requires an enabled Tokio runtime at the calling async
boundary; local-only operations need no runtime. Puts and landed walk values
become visible in a fresh local observation without an automatic disk flush.
Explicit `close` withdraws host snapshots and closes the backend at the final
persistence boundary; manual `flush` remains available at an application's
chosen durability boundary. Neither operation starts networking or authors
WANT. Failure to obtain a fresh store snapshot is returned by `try_refresh` and
withdraws the previous serving observation; existing frozen readers stay
frozen.

### Where peers come from

A host's peers come from its pile, never from configuration; there is no list
of peers to give it. The keys a selected collection's content names, the
signers of its records and its grant-chain keys, are its first peering
candidates (tiers 1 and 2 under *Neighbours*), dialled by key through iroh's
address discovery. TLS authenticates every connection, so each connection a
host dials makes the key it dialled a verified DHT route, and the provider
lookup at the collection's next draw has a contact: a host whose only route is
the signer of a record it holds finds the collection's other providers, tier
3, through that signer. A connection a host accepts makes no route, by
opening or by the requests it carries: anybody can dial with a fresh key, as a
process that asks its pile's daemon with a key per call does.

A process whose pile names no peer, such as a foreground reader, has one first
contact: the pile's sync daemon. `PeerConfig::daemon` names it by its key, the
key the pile's configuration is written under; the daemon itself leaves it
unset. The host notes that key as a candidate route and teaches its endpoint
the addresses the daemon recorded (*Where the sync daemon listens*), which
`Peer::new` reads at once and a lazy peer reads when its host starts; with no
addresses recorded, iroh's discovery finds the daemon by key. From there the
daemon's DHT replies lead on.

Endpoint addresses and relay URLs only provide iroh transport paths; they are
not peering candidates, collection participants or collection rendezvous
identities. DHT referrals and the peers a host reaches itself may become live
routing candidates, but there is no synchronized PEER roster and no durable peer
record in the current protocol. Liveness, connections, peerings, candidate
orders, DHT buckets, and provider leases are operational soft state; restarting
may forget them without losing semantic data, and each selected collection
draws its candidate order afresh. The pile already holds what a restart needs
to find its peers again: the keys its content names and, for a process beside
the daemon, the daemon's addresses.

### Restart contact experiment

`routing/warm_start.rs` is a test-only experiment, not enabled host
persistence. It runs the real `RoutingTable` and `IterativeLookup` with
synthetic lookup responses. Its one durable relation is a bounded set of
previously authenticated endpoint identities, canonicalized with `PATCH<32>`
and packed into ordinary `RawBytes`. A temporary-file write, sync, reopen and
restore exercise the byte boundary. The test makes no new pile record,
replicated roster, schema identity, JSON catalog, or provider advertisement.
The host currently has no learned-peer persistence to reuse: a fresh route
table holds at most the pile daemon's key and grows from the connections the
pile's content opens; retired PEER records remain inert. The experiment's
fixtures still seed the table with a fixed bootstrap identity, which stands for
whichever first contact a restart has.

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
serving-longevity claim. The production host promotes only peers it reached
itself, a key it dialled or one that answered its request, and never an inbound
caller such as an ephemeral foreground client. The experiment does not change
that provenance.

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

Inbound request streams wait for the process-wide permit while their
connection holds them, within the per-connection bound of *One connection per
peer*. Saturation resets only the excess stream and never closes the
connection, whose `recon/1` stream and other requests carry on.

The one connection per peer carries collection sync and bearer/DHT operations
alike. Iroh's transport authentication binds each connection to its endpoint
ID. There is no generic AUTH or SYNC_TEAM exchange: collection evidence goes
only to a peer that passes READ(C) under the sender's evidence, and WRITE(C)
only lets a writer that cannot read have its peering accepted so it can
deliver. Exact bytes are gated only by the endpoint-bound mutual proof of H.

A refused peering or a refused walk is a frame. It ends only that request or
walk, not the connection, and cancels nothing unrelated. A malformed `recon/1`
frame closes the connection. A failed request stream invalidates the
connection unless the failure stayed on that stream: the peer reset or stopped
it, or the connection was already lost.

Concurrent callers for one peer share a single dial. Pending dial ownership is
cancellation-safe: the final departing waiter removes a dial nobody completed,
while the others keep it and can take over its cancelled initializer. This
cleans up abandoned dials, not a new limit on simultaneous requests or detached
transport handshakes.

For an active collection with a missing descriptor, the host owns one
independent bearer fetch until its result reaches the bounded admission
bridge. Later warmup rounds cannot spawn additional copies while that handoff
is blocked. Removing the interest or dropping the host cancels the pending fetch;
a completed miss or failed attempt permits a later retry.

That same owner performs best-effort metadata warmup for active collections,
even before their descriptor is admitted and when they have no records. From a
descriptor of at most 1 MiB it queries only UTF-8 name handles on tagged
descriptor entities and typed definition handles linked by their
resource-policy bindings. The warmup does not interpret the binding's authority
or require it to be supported by this consumer. Unknown annotations, source
descriptors, mapping parameters, proof paths, and record payloads are not
traversed. This is acquisition, not
READ or WRITE authority, and introduces no durable WANT.

At most four collection attempts run at once, in round-robin order over the
active collections. Each warmup round examines at most 256 of them; ready
resident-only attempts release their slot immediately instead of waiting for
the next 30-second round, and a newly activated collection starts a round at
once.
Each owns a 30-second end-to-end deadline including admission-channel handoff;
the descriptor read gets at most ten seconds. Extraction examines at most 256
typed rows and admits at most 64 distinct direct dependencies, with names
first. Up to four children per owner run concurrently (sixteen child requests
across these owners), each with a one-second end-to-end deadline. Every remote
response is limited to 1 MiB **before** receiving its body; resident descriptor
bytes are also size-checked before decoding. Existing exact receive-slot and
global staging quotas still apply.

These are warmup limits, not schema validity rules or assertions of absence.
An oversized descriptor or dependency, excess fanout, slow provider, or blocked
handoff can leave metadata unprepared. No completion catalogue is retained;
later rounds reobserve the store and retry. Ordinary foreground
exact-H acquisition retains its existing larger byte allowance and deadline,
and passive snapshots and resident-only stores do not acquire anything.

Foreground exact-H acquisition has one end-to-end deadline, normally ten
seconds, including capability readiness, the cold dial of a first contact such
as the pile's daemon, DHT lookup, and bearer GET. Its three-second routing
window begins with the first authenticated replica response, not before that
cold dial. This lets a healthy delayed first contact connect while a stalled
secondary route cannot consume the whole remaining budget before GET.
Background publication, collection provider lookups and descriptor warmups
start their three-second lookup window immediately. A caller's shorter deadline
still wins; progress does not reset either deadline, and no failed lookup
starts an unbounded retry loop. When the routing window expires, issued
requests still awaiting a reply count as failed learned routes. They cannot
occupy every slot again on the next background attempt merely because
cancellation preceded the dial deadline. Unissued candidates and partial
authenticated responders are preserved; the daemon's route fails like any
other. Each routing bucket also retains at most K local learned-route failures
for sixty seconds, separately from its positive routes. Repeated third-party
referrals cannot erase or extend that cooldown: it gates both seeds and reply
candidates even when positive bucket retention differs from the lookup-local
shortlist. Direct authenticated success clears a cooldown immediately; expiry
permits a new probe. This is bounded, disposable liveness state, not authority
or a permanent blacklist. This does not make a cold dial to a sole first
contact that takes longer than three seconds fit the background window: if each
attempt starts equally cold, background retries can still miss that endpoint.
Foreground acquisition retains its separate end-to-end bound. Diagnostics
distinguish a successful lookup with no provider hint from failure to reach a
replica, a provider transport/protocol failure, or exhaustion of the end-to-end
budget. A directory miss is an observation, not proof that H does not exist.
Diagnostics do not log the bearer handle.

## Lattice-aware sparse replication

The network does not force every replica to mirror every blob. Record pulls
carry foundations only; each host joins them into its own lattice:

```text
COMMIT(C, a)       COMMIT(C, b)       replicated
       \             /
        MERGE(C, a, b, c)             this host's own node, never replicated

DERIVE(D, x, d)                       replicated: a foundation of D
```

A node pulls the small semantic overlay and plans covers over its own
resident merge results. Missing derived results are computed by the ordinary
live `ensure` path, which may acquire exact missing dependencies and publishes
missing `DERIVE` work only. `maintain` additionally writes this host's
size-tiered `MERGE` work, which stays local. These operations take an
explicit signing key; newly required derivation work needs target WRITE.
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

### Held blobs and replication policy

A collection replicated in full has a held set: a positive PATCH of resident
handles, kept by the store itself (`triblespace_core::collection::held`) for
the collections `Peer::set_replication` puts in `Full` mode. A host that
replicates on demand or shallowly keeps none. Seeds are the blobs C's
replicated records name -- the descriptor, each COMMIT's data and metadata
archive, each DERIVE's output -- and the capability definitions named by the
proofs C's authorization evidence keeps. That is the predicate AUTH applies
(`descriptor::validate_proof_evidence`): a proof over C from one of C's policy
roots, or over a resource whose immutable descriptor entity both routes to C
and declares the proof's root, whether or not that resource is tracked as
well. A valid proof irrelevant to C seeds nothing. A descriptor that arrives
after its proof lets the proof be judged on arrival; one that is resident but
cannot be read judges nothing. A MERGE result is never a seed, and neither is
a blob no record names. Reachability is conservative: an aligned 32-byte word
is a child when that exact H is resident. It issues no network request,
creates no WANT and remembers no absent word.

Each blob is scanned once, when first reached, and its edges to the children
resident at that moment enter one edge cache shared by every collection. A new
seed, edge or membership then extends a held set without reading bytes again;
an already scanned blob shared with another collection joins it for free. A
seed whose bytes arrive after its record is scanned on arrival. The late
child -- resident only after its parent was scanned -- is caught two ways:

- it is itself a seed of some collection; or
- a Full neighbour holds it in C: the reference pull notes it held in C here
  too, however it arrived, and fetches it first when it is not resident. A
  note is routing evidence kept in memory: a reopened store forgets it unless
  one of C's records reaches H, and a note of a blob that is not resident when
  the next snapshot is taken is dropped.

Otherwise it stays out of held(C) until the index resets or the store is
reopened, though it stays readable by its hash. That is a stated limitation:
there is no periodic rescan. Between two Full neighbours, a late child that
one side holds through a seed or a note reaches the other side's held set by
its next reference pull.

Every snapshot carries the held sets as they stood when it was taken, and they
never change afterwards. Taking a snapshot first extends the sets by the
closures of what arrived since the previous one -- every seed of a new record
(one another record already named included), seeds whose bytes arrived, notes
from reference pulls -- computed against that snapshot. That is the
publication barrier: an observation is never handed out ahead of its new
records' closures. A held set is closed under the edge cache for readable
children: a blob joins only once every child the cache names for it has
joined. A blob that cannot be read, absent or resident and failing to read, is
unknown on every path, and nothing above it joins. When a collection is first
tracked, its existing closure is computed by the next snapshot, which reads
every blob it reaches once; nothing here starts a thread. A collection whose
records the store cannot select stays unsettled -- absent from the held sets,
never published short -- and is selected again at the next observation. A
snapshot that lost a blob its predecessor had resets the index, and every
collection is recomputed as if newly tracked. Short-lived readers of the same
pile track nothing.

Two Full neighbours compare like with like: the held digests in their
announcements, and on a difference, a reference pull of the remote held set
against the local one under Merkle pruning.

This set is partial and conservative. A readable aligned word is not a
typed semantic reference; an absent word says nothing about global residency.
For encrypted blobs, H identifies the stored ciphertext; neither READ(C), this
set, nor the exact-H protocol supplies an application's decryption keys.

`Peer::set_replication(mode, collections)` selects acquisition independently
of activation and authority. `pile net sync --replication` applies one mode to
every selected collection:

| Mode | Blob acquisition |
|---|---|
| `Demand` (default) | Explicit WANTs only. No held sets are kept, and peerings carry an unset full flag. |
| `Shallow` | Also direct blob references of the named collections' foundations. |
| `Full` | Also everything a Full neighbour holds in each named collection, by reference pull. This side keeps held sets for them and peers with the full flag set. |

These reconciler modes are separate from the bounded metadata warmup of
active descriptors described above. Demand still does not hydrate record
payloads without an exact WANT.

Naming a collection for replication does not grant READ or WRITE and does not
activate it. Structurally valid but WRITE-inert records can name direct roots;
acquiring their bytes does not admit those records. Full mode never sends
aligned payload words to the DHT to choose speculative requests. Local
aligned-word scanning builds the positive held set only, and a reference pull
fetches only handles a Full neighbour holds, directly from that neighbour.
Unavailable neighbours and failed fetches prevent a promise that `Full` has
reached complete closure, and an equal held digest says only that two
neighbours hold the same set.

Exact WANTs and direct roots use the existing KDF(H) discovery, mutual
bearer proof and final hash verification. A shared eight-wide fetch
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

The ALPN is `/triblespace/pile-sync/29`. Generation 27 replaced the bearer
locator, directory token and exact-GET proofs with one-block constructions, so
a generation-26 peer cannot connect at all; generation 28 exports foundations
only, so collection sync never carries a MERGE; generation 29 replaces the
gossip wake plane and the `repair/0` session with `recon/1`, so a generation-28
peer is refused at the handshake. Within the ALPN, each stream's first byte
selects its layout (*One connection per peer*), and all collection sync runs on
`recon/1`. Bytes that opened earlier layouts are not accepted: `0x0E` was the
collection repair session that walks on `recon/1` replaced, `0x0D` its
record/AUTH-only predecessor, and `0x06`, `0x07` and `0x0C` the DHT operations
now under `dht/1`. A stream that opens with one of them is reset as an unknown
tag. Mixed-version collection sync is not supported: deploy a cohort together.

| Operation | Stream | Byte | Meaning |
|---|---|---:|---|
| `FIND_VALUE` | `dht/1` | `0x0F` | one iterative XOR-DHT lookup step: the K closest verified routes and bounded provider hints for one opaque key |
| `PROVIDER_PUT` | `dht/1` | `0x06` | renew this endpoint's opaque provider lease; the answer says stored (`0x00`) or not stored (`0x01`) |
| exact GET | `blob/1` | | locator-addressed, mutual-proof exact bearer transport |

`FIND_VALUE` answers in one reply what `FIND_NODE` and `PROVIDER_GET` (`0x0C`
and `0x07`) answered in two rounds. Every `recon/1` frame, including the walk
frames, is listed in *One connection per peer*.

There is deliberately no store manifest, global inventory authorization,
push-broadcast record, receipt RPC, remote mutable head, or unpublish operation.

The CLI names local policy only. The collections come from the pile's
selection (*Choosing what to sync*) and the peers from the pile's content
(*Where peers come from*):

```text
trible pile net sync DATA.pile \
    [--key EXISTING_SELF_KEY] \
    [--replication demand|shallow|full] [--bind IP:PORT] \
    [--provider-publication-budget ATTEMPTS] \
    [--health] [--health-collection HANDLE] \
    [--telemetry-collection HANDLE] [--telemetry-worker NAME] \
    [--duration SECS] [--quiescent-for SECS]
```

There is no `--peers` or `--collection` flag, and no direction flag: which way
a collection flows between two keys follows the send flags of their peering,
which follow admission. At startup the daemon prints its node id, its bound
sockets and the number of selected collections, and prints that number again
whenever the selection changes.

`--bind` binds the endpoint to exactly that local socket instead of iroh's
default sockets. At startup the daemon prints `bound: <ip:port>[ <ip:port>...]`
on stderr, the sockets it actually bound, and prints the line again whenever
they change. It records the same sockets in the pile's configuration (*Where
the sync daemon listens*) on its first pass and after every change, so a
process that opens the pile and names the daemon's key reaches it with nothing
copied by hand. `trible pile net identity --key KEY` prints `node: <endpoint
id>`; there is no ticket to print, since nothing takes one. After each pass the
daemon prints one plain line on stderr per peer with which at least one record
pull ended without a failed or timed-out walk since the previous pass:
`reconciled with peer <endpoint id hex>: <n> collections`.

The long-running daemon uses one existing durable key for its authenticated
endpoint, the configuration that holds its sync selection and its addresses,
health reports and telemetry. Key resolution is `--key`, then
`TRIBLESPACE_KEY`, then `self.key` beside the pile's lexical path; `select`,
`unselect` and `selection` resolve the key the same way. There is no
independently configured network or reporting key. Maintenance uses that same
local key for its work and telemetry; worker labels distinguish processes, not
identities. This CLI convention does not change the separate ephemeral H-only
foreground-reader use described above or grant any authority.

Whatever a node selects, it may publish provider leases for and serve resident
exact blobs under bearer handle H, and may service durable `Blob(H)` WANTs
through KDF(H). The
replication mode does not participate in collection identity or change which
evidence is semantically valid.

Before opening the writable pile or starting its peer, `pile net sync` registers
Unix SIGINT and SIGTERM handlers; other platforms retain Ctrl-C handling. Stop
drops in-flight awaited reconciliation or the idle wait, then withdraws the
serving observation and explicitly closes the backend. It does not change
request deadlines or the application's clocks. Synchronous work and close
are not preemptible, so this cooperative boundary is not a shutdown-time bound.

## Convergence and failure model

- Concatenation, local insertion, and landing from pull walks perform set
  union; held sets remain replaceable local observations.
- Duplicate records collapse by their complete canonical value; fixed-width
  indexes and the wire use a full-width BLAKE3 fingerprint of that value.
  Native capability proofs continue to collapse by their cryptographic
  identity.
- A missed announcement does not consume the only opportunity: in every
  interval of at most a minute, each collection's timer offers its current
  root to each neighbour it sends to that did not announce the same state, and
  a pull that did not complete is retried by the next announcement of the
  same root. A neighbour lost to a failure is replaced by the next candidate
  in the collection's order.
- An invalid record, proof, PATCH node, or blob fails its walk or fetch and
  cannot retract previously accepted evidence; a malformed `recon/1` frame
  closes its connection.
- Missing selected output/dependency blobs leave that realization unavailable;
  complete finer members remain usable. Missing witness records leave support
  unknown, not empty, and do not authorize cross-collection disclosure.
- A DHT miss says only that no live provider was found; it says nothing about
  whether H or its collection exists.
- Concurrent writers and offline replicas reconverge without preserving pile
  byte order.

The result is two orthogonal elemental loops: per-collection announcements
plus admission-gated pull walks say *what changed in a collection* and,
between two Full neighbours, which blobs a peer holds in it, while KDF(H)
discovery plus mutual bearer proof retrieves only the immutable bytes the local
lattice resolver decides to use.

## Observing replica health

`Peer::health()` and `NetSender::health()` expose a bounded immutable sample of
work the host already performs. Sampling does not run a probe or advance the
host's observation clock. Each record pull retains, as its comparison, the
local record/AUTH frontier when it started and the remote frontier and record
root its walks pinned. Semantic health compares record and AUTH evidence, not
blob cache equality: Demand and Full peers can legitimately cache different
bytes, and held sets are not part of the record root. Held-set churn neither
creates semantic stalls nor extends their progress grace.
A comparison stops implying convergence when that sample is stale, the local
semantic frontier has changed, or the serving snapshot has been withdrawn. Receiving
records is progress evidence, not proof they have already become admitted.
`HealthSnapshot::peerings` lists every peering on an open connection, and
`HealthSnapshot::available` the collections named by proofs naming this node
that wait in memory for their descriptor.

The long-running CLI can publish these observations as native facts using
`pile net sync --health`. Reports use the same key as the endpoint. An explicit
`--health-collection <HANDLE>` also enables reporting into an existing admitted
source collection; otherwise the node's private `swarm-health` collection is
used. The health
collection is deliberately not activated for sync, so a broken network
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
selects their collection with `trible pile net select`.

The producer attempts an ordinary signed append every sixty seconds at the
existing sync-loop boundary. Five subjects distinguish the measurements:

- `hydration`: successful verified reconciler puts and their payload bytes;
  one landing shared by a WANT and a selected root counts once. Blobs a
  reference pull lands are not reconciler puts and are not counted. Local hits
  and failed puts add no received bytes. `queued` counts distinct unreadable
  known handles from exact WANTs and selected direct roots at the end of that
  tick's acquisition window. It excludes unknown descendants and is not a
  global blob inventory. A failed exact-set observation leaves it absent.
- `serve`: actual accepted inbound GET exchanges in flight, successfully
  sent payloads/bytes and interrupted or failed exchanges. A payload counts
  only after its write and stream shutdown succeed, not merely after lookup.
  This is not a remote landing or persistence acknowledgement.
- `repair`: record pulls currently in flight, as host health already records
  them, not configured concurrency.
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
values, member counts by exact locator, expiry order, and XOR responsibility
then rank order. `provider/patch_directory.rs` is a **test-only** alternative
with two PATCHes:

- `!(locator XOR local_endpoint) | !rank`, segmented `32 | 32`, owns the
  provider/deadline/token value. Segment counts answer membership and
  exact-locator cardinalities; the first ordered key identifies the farthest
  responsibility's largest-ranked member, and a locator's first suffix its own.
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
