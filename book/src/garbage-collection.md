# Garbage Collection and Forgetting

Stores grow as signed commits, derived artifacts, authorization evidence, and
user blobs accumulate. Because every blob is content addressed and immutable,
nothing is overwritten in place. A node periodically _forgets_ local bytes
which no retained record or explicit policy root owns.

Forgetting is deliberately conservative. It removes only a local copy, so
later synchronization or an explicit fetch may restore it. An assertion is not
semantically retracted merely because one node drops physical bytes.

## Structural Ownership

Lifetime is a property of stored structure, not semantic trust. Every retained
current native record other than a `BLOB` strongly owns each blob handle it
names directly:

| Record | Direct blob references |
|---|---|
| `COMMIT` | collection descriptor, data, metadata |
| `MERGE` | collection descriptor, low input, high input, result |
| `DERIVE` | target descriptor, input, output |
| authorization proof | each capability-definition handle in its signed path |
| `WANT Blob(H)` | `H` |

Each direct reference is an independent recursive ownership edge. If the
referenced blob is resident, collection retains it and every resident child
found by the ordinary conservative blob walk. If it is absent, collection does
not fetch it, manufacture a subordinate WANT, fail, or withhold any resident
sibling. A blob record does not own itself merely because its bytes occur in a
store; it survives only when some retained record, legacy strong pin, or
explicit policy root reaches it.

This rule deliberately does not verify a commit or proof signature, perform
collection admission, or decide whether an equation is algebraically useful.
Those are semantic questions for a reader. Physical preservation must remain
stable when later evidence changes what a record means, and it must not let an
authorization bug silently destroy bytes. Conversely, retaining bytes grants
no authority. A retained proof owns its resident capability-definition closure,
but its opaque resource bytes do not become a lifetime edge even when an
application interprets them as a collection descriptor handle.

Witness-bound MERGE and DERIVE also name actual native input records through
`record_references()`. Those fingerprints are record identities, not blob
handles: do not feed them into the conservative blob walker or the DHT. The
retained native ledger preserves the referenced records independently of whether
their payloads are resident. Exact witness closure remains necessary to recover
`Support`; eviction must not silently replace a missing record with another
record producing the same payload.

The typed reference enumeration lives on the records themselves. MemoryRepo,
Pile rewrites, and Yard collection all consume the same enumeration rather
than maintaining backend-specific interpretations of record fields.

## Explicit Policy Roots

`RetentionRoots` supplements structural record ownership for callers with
local policy. It distinguishes:

- a **direct** root, which retains exactly the named blob; and
- a **recursive** root, which retains the blob and every resident descendant
  found by conservative traversal.

Explicit roots may describe application policy which is not represented by a
native record. Unlike an absent structural reference, an explicitly requested
blob missing during a retained Pile rewrite remains a transfer error: the
caller asked for that exact copy and silently weakening the request would be
incorrect.

There is no collection-specific retention planner. In particular, admission
results do not select lifetime roots and `MERGE` or `DERIVE` records
are not treated as weaker cache hints. A retained MERGE owns its resident
descriptor, result, and inputs, and a retained DERIVE its resident target
descriptor and output, exactly as a retained commit owns its resident
descriptor, data, and metadata. A DERIVE's source locator is a one-way image
of a handle, not a handle, so it owns nothing. Naming the descriptor matters
most for a derived collection: it holds no COMMIT, so its MERGEs and DERIVEs
are the only records that keep the descriptor every one of its records needs
to be decided.

This ownership rule is deliberately stronger than read-time dependency
selection. An authorized witness-bound output can be read without historical
input payloads or metadata; nevertheless, if those blobs are already resident,
the retained equation or COMMIT still owns them. Cheaper attachment is not an
implicit permission to discard historical bytes or records.

Known retired unsigned equations remain inert in semantic readers, but their
direct references still retain resident blobs. Reframing preserves their exact
bytes. Unknown opaque kinds cannot safely define a smaller live set because
their ownership edges are unknown. A retained Pile rewrite instead preserves
their bytes and every resident blob; semantic reframe and Yard reclamation
still refuse them.

The retired equation kinds -- the unsigned forms and the later witness-bound
signed forms -- are opaque to ordinary replay. Retained Pile copying carries
their frames and all resident blobs under the same opaque rule; Yard and
semantic reframe refuse them. No shipped command restates them any more: the
migration that once re-signed them under a current writer's key was applied
to the live piles and then removed with the record kinds it produced. Ordinary
GC never deletes the historical frames.

## Backend Boundaries

`MemoryRepo::keep`, `Pile::rewrite_retained_into`, and Yard collection apply
the same law:

1. freeze one coherent resident view;
2. enumerate every retained native record;
3. add each independently resident direct reference as a recursive root;
4. add caller-selected direct and recursive policy roots;
5. recursively mark resident candidate handles; and
6. rewrite or evict everything outside that conservative live set while
   preserving the retained record ledger.

Pile rewriting exposes an explicit choice to preserve or drop WANT records.
Preserving a WANT preserves its ownership edges; dropping it omits the record
and therefore those edges. Yard's grow-only WANT set has no recency or byte
budget: while a WANT record is retained, its resident references are ordinary
strong roots. Physical removal belongs at an explicit rewrite/eviction
boundary rather than to a hidden in-memory weakening of the record.

For migration safety, a retained Pile rewrite also recreates the exact
immutable legacy strong-pin snapshot it observed. A resident pin head remains
a recursive root; a dangling pin remains dangling. Legacy collection headers
whose old identities cannot express the current algebra are inert evidence and
own no current blobs.

Opaque records form a harder boundary. Their span may be known while their
ownership semantics are not. `Pile::rewrite_retained_into` carries each
byte-distinct opaque frame unchanged and widens retention to every blob in its
observed resident snapshot, even when the caller selected fewer roots. This
allows `trible pile compact` to remove redundant copies without interpreting
or discarding unknown ownership. Repeating a copy does not append an opaque
frame whose BLAKE3 digest is already present; this is set preservation, not
preservation of physical offsets or duplicate occurrences.

Yard collection, compaction, and reclaim still refuse before changing physical
state when an opaque record is present. They cannot infer a safe eviction set
from unknown ownership. Semantic `reframe` likewise retains its unknown-kind
preflight refusal; it is a different operation from retained Pile copying.

## Conservative Reachability

Canonical archives contain fixed 64-byte tribles whose value half is one
32-byte inline value. The generic walker treats aligned 32-byte chunks as
candidate handles and follows those which name resident blobs. This may keep
an accidental extra blob, but it cannot plausibly discard a real reference.
Opaque attachments normally behave as leaves because their chunks do not name
another resident object.

This asymmetry is the safety rule: uncertainty keeps resident bytes. Missing
bytes remain missing without turning collection into acquisition, and no
semantic rejection is allowed to erase structural ownership.

## Operational Tips

- Schedule forgetting after meaningful imports or merges so one walk amortizes
  many writes.
- Budget headroom for synchronization, which may restore locally forgotten
  copies.
- When application policy is uncertain, add an explicit recursive root;
  conservative extra retention costs space, while an omitted true root costs
  recoverability.
