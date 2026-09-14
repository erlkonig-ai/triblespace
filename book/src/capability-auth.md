# Resource Capability Proofs

TribleSpace authorization uses prefix-signed paths. A proof names one opaque
resource and carries one trust root's authority through one or more delegates:

```text
magic | resource | root | (capability handle | delegate | signature)+
```

The 32-byte magic is the handle of this grammar's SimpleArchive description.
It is also the native Pile record kind: there is one format identity, not an
outer kind wrapping a separately tagged proof. An incompatible grammar gets a
new description and magic rather than a version byte inside the decoder.
`resource` is an uninterpreted 32-byte identity. Collections use their descriptor
handle, but the capability kernel does not require the resource to be a
collection or even a blob. The root and delegates are canonical, non-weak
Ed25519 public keys; alternate encodings of one principal cannot count as
different quorum roots.

Every signature covers the complete preceding proof prefix through its own
delegate, including the magic, resource, root, capability handles, and earlier
signatures. Edges cannot be reordered, grafted onto another path, or moved to
another resource without invalidating a signature. The signature authenticates
the definition handle; interpreting its actions requires the definition blob.

Every exact prefix ending after a signature is itself a complete proof. An
intermediate subject's authority depends only on that prefix: a later invalid
signature, unavailable definition, or invalid attenuation cannot revoke an
earlier valid grant. This does not make malformed framing acceptable, and a
store's signature-checking ingress can reject an invalid whole proof before
retaining any of it. Publishing the exact shorter prefix remains possible.

## Canonical wire value

The proof header is 96 bytes:

| bytes | field |
|---:|---|
| 32 | grammar magic, also the Pile record kind |
| 32 | opaque resource identity |
| 32 | root public key |

Every edge is 128 bytes:

| bytes | field |
|---:|---|
| 32 | `Handle<SimpleArchive>` capability definition |
| 32 | delegate public key |
| 64 | Ed25519 signature over the complete preceding prefix |

There is no count, mode, flag, validity interval, parent pointer, or alternate
field order in the proof body. Its exact length determines the nonzero edge
count, bounded at 255. Decoding checks the magic, length, and canonical keys;
signature verification is a separate strict check. The proof ID is BLAKE3 over
the exact unpadded body.

The current grammar is `pile-auth-proof-v5`, with descriptor handle
`9E00F6EB8D63E5EB1A3ECFA284118F157B2F08CBDC95ECCEB8C2392AD794069D`.
Its anchor `C7116B04EE6DA4BADFDE77D79692AEFF` was minted with `trible genid` on
2026-09-14. The grammar change does not change existing collection descriptors
or their canonical READ/WRITE capability definitions. Old proof signatures
cannot be converted to the new wire value without signing the new bytes.

## Invocation and delegation are independent action sets

A capability definition is an immutable SimpleArchive. Its ordinary facts
describe two finite sets of opaque action IDs:

```text
I(P) = actions named by capability_action
D(P) = actions named by capability_delegate_action
```

`I` permits invocation. `D` permits granting invocation or onward delegation.
There is no implicit rule that being allowed to invoke an action permits
delegating it. A child definition `Q` may follow `P` exactly when:

```text
I(Q) ∪ D(Q) ⊆ D(P)
```

The handles need not be equal. For example, `I(P) = {READ, WRITE}` and
`D(P) = {READ}` lets the subject read and write, but delegate only READ. A
delegate-only grant, `I(P) = {}` and `D(P) = {READ}`, can confer READ without
allowing its own subject to read. A child with `I(Q) = {READ}` and `D(Q) = {}`
can read but cannot pass that grant onward. This is not an intersection of
invocation bits along the path.

The existing `capability_action` attribute and standard one-action READ/WRITE
blobs keep their exact identities. The new `capability_delegate_action` anchor
is `628AB41154C8BAE6F985591B58487374`, minted with `trible genid` on 2026-09-14.
Unknown annotations are ignored by the generic action interpreter. They may
be meaningful to the consumer of a particular action.

The construction and interpretation boundaries are deliberately separate:

```rust,ignore
let proof = CapabilityProof::new(resource, &root, grant_handle, intermediary);
let proof = proof.delegate(&intermediary_key, narrower_handle, recipient)?;
proof.verify_signatures()?; // bytes only; no definition acquisition
proof.verify(
    &snapshot,
    root.verifying_key(),
    recipient,
    CapabilityRequest::new(resource, ACTION_READ),
)?;
```

`new` signs a root grant. `delegate` checks the signing key is the current leaf
and signs an extension; it does not fetch definitions or promise that the child
is authorized. `verify` interprets the prefix to the requested subject through
the supplied reader. `validate_delegation` checks the complete path when that
is the operation required. Definition reads are shared by handle within one
quorum operation, rather than loading a catalog of the store.

## Policies select roots per action

A request is `(resource, action)`, not `(resource, grant handle)`. Resource
descriptors still use their existing `resource_policy` links and exact
`capability_handle` bindings. A consumer reads the bound definition's invocation
actions to select the applicable policy. A compound bound definition can apply
the same policy to several actions; different grants implementing an action do
not need entries of their own in the resource descriptor.

Consequently, changing a grant's descriptor does not change the resource's
identity. A root configured only for READ cannot grant effective WRITE by
signing a definition that mentions both actions: a WRITE request uses the
WRITE policy's roots, not the grant's choice of root.

For roots `{r1, r2, ...}` and threshold `t`, a subject needs valid prefixes from
at least `t` distinct configured roots for the requested action. Two paths from
one root count once. A configured root supplies its own share, not an exemption
from a multi-root threshold. Supported alternative policies are evaluated
independently; shares from different alternatives cannot be pooled.

Sibling paths cannot lend delegation support to each other. To delegate a
quorum's authority onward, a subject extends the independently rooted paths
whose definitions allow that delegation. No second delegation threshold or
fixed-point authority forest is needed. Arrival order and wall-clock time do
not affect generic authority over the same proof and definition set.

## Storage and interpretation

`CapabilityProofStore` is a grow-only set of canonical proof values, with
insertion, deterministic enumeration, and exact lookup by proof ID. Presence
is evidence, not authority. The caller supplies policy roots, subject, request,
and a reader for the referenced capability definitions.

Native Pile and MemoryRepo insertion verify proof signatures. Trusted native
replay and `CapabilityProof::from_bytes` check structure without repeating
cryptography. The generic authorization kernel still verifies the signatures
of the prefixes it consumes; structural decoding alone is not its trust
boundary. Pile indexes retain shared owning `anybytes::View` values.

The generic Pile framing magic and block span precede the canonical proof.
Framing and zero padding are outside its signatures and hash. A zero padding
edge cannot be a valid edge because its delegate key would be weak. Minimal
framing is required; a one-edge proof plus framing occupies one 256-byte block.
The network sends the exact unpadded proof.

Conservative collection retains resident capability-definition blobs and the
record-kind description. It does not interpret the opaque resource as a blob
reference or fetch missing definitions. A proof can therefore be retained and
transported before its definitions are resident. It confers no interpreted
action through an unavailable definition.

## Collections consume authority

Collections interpret the standard action IDs as:

```text
READ(C)  = request(resource C, ACTION_READ)
WRITE(C) = request(resource C, ACTION_WRITE)
```

WRITE admission decides which signed COMMITs contribute membership and which
signed MERGE/DERIVE equations may be reused. An equation needs WRITE on its
target; source WRITE alone is insufficient. Its signature identifies a
producer, not a mathematical proof. Readers do not replay the computation.
This is still record-level equation admission and lineage discovery, not a
claim that independent cover-level endorsements have been implemented.

Local publication can retain an inactive record before a suitable proof
arrives. Later proof or definition residency can activate it. Generic WRITE
membership does not expire as the clock advances. READ separately controls
which authenticated peers may receive a collection's repair stream; it is not
a precondition for interpreting local data. Exact blob retrieval remains
orthogonal: knowledge of a blob handle is the read capability for those bytes.

`grant_collection_read` and `grant_collection_write` issue the unchanged
invoke-only standard definitions. `grant_collection_capability` accepts an
already stored definition, which may combine invocation and delegation. The
helpers inspect the resource policy and insert one root's proof; open policies
need no proof, and each root contributes independently to a quorum.
`collection_read_audience` enumerates the finite authorized audience, including
valid intermediate subjects, or returns `Open` when no finite list suffices.

## Application restrictions and resource discovery

Generic proofs and collection admission have no clock. An action such as
Secrets key delivery may interpret additional facts in a capability definition,
including a deadline. The quorum APIs ending in `_if` expose each validated
subject prefix to a predicate **before** counting that root's share. The
consumer must inspect restrictions in every ancestor definition on that prefix;
changing the child handle cannot erase an ancestor's restriction. A rejected
later prefix does not cancel a previously acceptable earlier prefix.

Key-delivery expiry can stop future delivery, not revoke possession of a key
already delivered. It does not expire COMMIT membership or collection READ.
Secrets-specific delivery grants need not be listed in collection descriptors:
a separate immutable resource may have its own delivery policy.

Ordinary collection facts can reference such a resource with `resource_handle`;
the immutable resource can declare its repair audience with `resource_collection`.
This names the collection whose READ-authorized peers may exchange the resource's
proofs; it does not inherit that collection's authority. Their anchors, minted
with `trible genid` on 2026-09-14, are respectively
`5059416BAF824B364FF52F56A0D1CF9F` and `62E951EC3ABB7F9B7F123BB7DE2F9F99`.
The resource's own policy roots still decide its actions.

## Repair and discovery

For proofs naming exact resource C, collection AUTH repair uses C's declared
policy roots. It no longer filters by grant-handle equality:
different definitions can delegate the same action. This byte-local relevance
check does not interpret the definitions or confer READ. Session admission
separately interprets the requested READ action using resident definitions and
the frozen proof set before disclosing a repair manifest.

Repair transfers records only, not capability-definition blobs, payload closure,
or WANT bookkeeping. The blob layer handles demand for definition bytes.

The subordinate-resource transport candidate also routes proofs naming R when
R's immutable descriptor contains `resource_collection: C` and `resource_policy`
on the same entity. It checks R's policy roots and signatures, while the repair
session remains gated by READ(C). No mutable fact in C can create or revoke the
route. A missing R descriptor defers that proof leaf and leaves the AUTH component
explicitly incomplete without blocking C's collection-record repair. Ordinary
blob arrival permits a later retry; AUTH repair does not fetch R. This extension
is a source candidate, not a claim of completed validation or live deployment.

The boundaries remain independent: proof presence is not authority; routing,
gossip, and DHT presence are not authority; WANT records durable local demand;
and blob residency is not semantic validity.
