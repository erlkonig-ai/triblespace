# Resource Capability Proofs

TribleSpace authorization is a self-contained, prefix-signed path. A proof
names one opaque resource and carries one trust root's authority through one
or more delegates:

```text
magic | resource | root |
    (capability handle | mode/validity flags | validity | delegate | signature)+
```

The 32-byte magic is the handle of this grammar's SimpleArchive description.
It is also the native Pile record kind: there is one format identity, not an
outer kind wrapping a separately tagged proof. An incompatible grammar gets a
new description and magic rather than a version branch inside the decoder. `resource`
is an uninterpreted 32-byte identity: collections use their descriptor handle,
while another subsystem may give the same kernel a different kind of resource.
`root` and every delegate are canonical, non-weak Ed25519 public keys. This
makes each exact 32-byte value one usable principal rather than allowing
multiple encodings of the same curve point to count as distinct quorum roots.

Each edge contains one exact 256-bit capability-definition handle, an invocation/delegation mode, an
optional inclusive TAI interval, the next delegate, and a signature by the
current issuer. The signature comes last and signs every preceding byte of the
proof through that delegate. It therefore covers the magic, resource, root,
all earlier edges including their signatures, and the current restrictions.
Edges cannot be reordered, grafted onto another path, or moved to another
resource without invalidating a signature.

Every exact byte prefix ending after a signature is itself a complete proof.
A valid longer proof consequently also provides evidence for its intermediate
delegates. Truncating at any other byte is malformed. A stored value with a
malformed or invalid tail is inert as a whole; a sender that wants to publish
the valid prefix publishes those exact prefix bytes under their own content
identity.

## Canonical wire value

The proof header is 96 bytes:

| bytes | field |
|---:|---|
| 32 | grammar magic, also the Pile record kind |
| 32 | opaque resource identity |
| 32 | root public key |

Every edge is 161 bytes:

| bytes | field |
|---:|---|
| 32 | exact `Handle<SimpleArchive>` capability definition |
| 1 | mode and validity-presence flags |
| 32 | signed inclusive validity bounds, or canonical zeros when absent |
| 32 | delegate public key |
| 64 | Ed25519 signature over the complete preceding prefix |

There is no count, padding, parent pointer, claim handle, or alternate field
order in the proof body. Its exact length determines the nonzero edge count,
which is bounded at 255. Decoding rejects unknown flag bits,
malformed, noncanonical, or weak keys, inverted intervals, nonzero
absent-validity bytes, trailing bytes, and overlong paths. Signature
verification is strict. The proof ID is BLAKE3 over the exact canonical body.

The old `K(S,C,K)+` format put per-hop restrictions into claim blobs. The
current definition handle instead names a stable operation and its parameters;
per-hop attenuation is inline. Signatures and attenuation can be verified
without loading any definition. A resource descriptor fixes the finite
vocabulary it recognizes, and consumers query definitions for operations they
understand. Unsupported definitions remain uninterpreted, not invalid.

Definitions must not contain the resource descriptor's handle when that
descriptor names their handles: that would be a content-address cycle. The
proof already binds the exact resource separately.

## Attenuation is a meet

The three nonempty modes are `Invoke`, `Delegate`, and
`InvokeAndDelegate`. Effective authority is the meet of every edge:

- the capability handle must remain exactly equal;
- mode bits combine by intersection;
- validity intervals combine by inclusive intersection; and
- every non-final issuer must still have effective `Delegate` authority.

A syntactically wider child is harmless: it cannot restore a mode bit or time
range removed by an ancestor. An empty mode or interval intersection rejects
the path. Verification additionally receives the expected trust root, subject,
instant, resource/capability request, and required mode; the proof cannot nominate
those boundary values on the verifier's behalf.

`CapabilityProof::issue_root` creates the first signed edge.
`CapabilityProof::extend` appends an edge only when the supplied signing key is
the current leaf and the effective prefix still delegates. A
`VerifiedCapability` reports the subject and effective restrictions and can be
used as the same extension boundary.

## Quorum is independent root paths

One proof carries exactly one root's share. For a policy with roots
`{r1, r2, ...}` and threshold `t`, a subject is admitted when at least `t`
distinct configured roots independently provide a valid prefix for that
subject and request at the chosen instant. Two paths from one root never count
twice. A configured root inherently supplies its own share.

There is no fixed-point authority forest and no way for one sibling proof to
lend delegation support to another. If a threshold-authorized delegate wants
to delegate onward, it extends each independently rooted proof path it holds.
The edge's signed mode states whether that particular share remains
delegable; the descriptor needs no second delegation threshold.

This path-local rule makes proof arrival order irrelevant. Set union of proofs
is the only synchronization operation, and evaluating the same set at the same
instant produces the same authority.

## Storage and lifetime

`CapabilityProofStore` is a grow-only set of canonical proof values. It offers
insertion, deterministic enumeration, and exact lookup by proof ID. Storage is
evidence, not authority: callers still choose roots, request, subject, and
instant when verifying it.

A proof is a native record. Conservative collection retains its resident
capability definition blobs and its record-kind description, but never treats
the opaque resource as a blob reference and never fetches absent definitions.
Repair exchanges proofs only and does not emit WANTs. Re-inserting identical
proof bytes is idempotent. Pile indexes hold shared owning `anybytes::View`
values; parsing and replay do not verify signatures or assign authority.

In a Pile, the generic framing magic and block count precede those same
canonical proof bytes. The record kind is the proof's first field, not an
additional wrapper. Generic framing and zero block padding are outside the
signed and hashed value. Every edge has a nonzero mode, so whole zero edges and
a zero short remainder can only be padding; the decoder also requires the
minimal block span. The network sends the exact unpadded proof unchanged.

The proof grammar and Pile kind share one compatibility identity; the transport
protocol has its own boundary. Historical live proof kinds remain recognizable
as inert so old append-only piles can still be crossed safely. Old signatures cannot be
mechanically migrated because they signed different bytes. Delegated authority
must be reissued by the relevant private keys.

## Collections consume authority

A resource descriptor links capability-policy bindings. Each names an exact
capability handle and an open policy or a quorum over a canonical root set.
Collections interpret two standard definition blobs:

```text
READ(C)  = read_capability()  over resource C
WRITE(C) = write_capability() over resource C
```

Here `C` is the exact descriptor handle. The generic capability kernel does not
know what a collection, team, secret, or query is. Collection admission merely
interprets its own resource and recognized capability definitions. The existing
READ/WRITE operation IDs are facts inside those stable definition blobs, not
special cases in the proof grammar. Extra capabilities use the same binding
relation without changing the kernel.

WRITE admission decides which signed COMMIT records contribute membership and
which signed MERGE/DERIVE records may be reused as computation evidence. An
equation uses the WRITE policy of its target collection; permission to write
its source alone is insufficient. A signature identifies the producer, not a
mathematical proof of the result. Readers trust authorised producers rather
than routinely repeating their computation.

Local typed insertion remains unconditional: an inactive record may arrive
before its proof and become visible when enough valid proof paths arrive.
Admission uses the snapshot's frozen instant, including validity intervals.
Foreign collection-record decoding verifies signatures once; trusted native
replay does not recheck them. AUTH path verification remains a separate check.
READ admission decides which authenticated peers may participate in that
collection's repair session. Exact blob retrieval remains orthogonal;
knowledge of a blob handle is the read capability for those bytes.

The common root-grant helpers are:

```text
grant_collection_read(&mut store, collection, &root, recipient)
grant_collection_write(&mut store, collection, &root, recipient)
grant_collection_capability(&mut store, collection, capability, &root, recipient)
```

They validate the descriptor and matching root against one snapshot, create an
unbounded `Invoke` proof, and insert that one proof record. Open policies need
no proof. Under a threshold policy, each participating root issues its own
proof. More elaborate delegation uses the capability API directly.

`collection_read_audience(&snapshot, collection)` evaluates every stored proof
at the snapshot's frozen instant and
returns the finite restricted audience in canonical key order, including valid
intermediate delegates. It returns `Open` for an open READ policy because no
finite key list describes that audience.

Secrets uses a distinct key-delivery capability on its source resource.
Collection READ authorizes encrypted replication, not decryption-key delivery.
Envelope creation and maintenance enumerate the current key-delivery audience;
expiry can stop new deliveries but cannot revoke possession of a key already
delivered. Adding that binding to an immutable descriptor changes its handle:
existing data needs an explicit additive transition, never a name-based alias
or automatic fallback from key delivery to READ.

## Repair and discovery

Authorization repair exchanges proof records only. There are no claim blobs,
proof bundles, claim-specific WANTs, or hidden out-of-band closure. A collection
session projects proofs for every descriptor-declared capability, not just
READ and WRITE. Relevance checks the exact resource, capability handle, and
configured root before verifying the signed path. The receiver still applies
the recognized READ policy before disclosing a repair manifest; transporting
an unknown operation's proof does not grant access to the collection.

This leaves the layers deliberately independent:

- proof presence is not authority;
- routing, gossip, and DHT presence are not authority;
- collection repair moves records, not payload closure;
- WANT records local durable demand, not protocol bookkeeping; and
- blob residency is not semantic validity.

Validity bounds are monotone restrictions, not mutable revocation. Ending
unexpired authority requires changing the trusted policy epoch or another
explicit application-level act; ordinary expiry merely makes the same durable
proof inactive after its signed upper bound.
