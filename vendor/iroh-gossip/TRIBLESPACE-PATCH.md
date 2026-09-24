# TribleSpace transport patch

Imported from the crates.io `iroh-gossip` 0.101.0 source archive, unchanged
except for the patch described here. Both upstream licenses are retained.

- Upstream repository: https://github.com/n0-computer/iroh-gossip
- Upstream revision from `.cargo_vcs_info.json`:
  `2ce78afe09d89d41d123f28eac19bdc831609cc8`
- crates.io archive checksum from the enclosing workspace lockfile:
  `4e1dc4b05f73e7a1b9e83b531eb63c3fd671b0af3aeb13b59c546dd7ca747515`
- Import source: the local Cargo registry's exact 0.101.0 package. Only the
  `.cargo-ok` installation marker was omitted.

The transport uses one ordered unidirectional stream per connection direction.
Each length-prefixed postcard frame encodes the original `ProtoMessage`, including
its topic. Collection topics, membership state, and mesh behavior remain separate
and unchanged. This removes the fixed stream-credit ceiling on concurrent topics
without reordering a topic's membership controls across independent streams.
The frame limit adds 32 bytes for the topic and preserves the existing inner
message allowance. A topic disconnect no longer closes the shared stream.

This wire format uses the private ALPN
`/triblespace/gossip/C6858FA15B24B264151DB34DAA9C1964`, never `/iroh-gossip/1`.
The identifier was minted with the installed `trible genid` on 2026-09-23 for
this patch; it isolates the new framing from unpatched peers.

The shared actor no longer waits for a peer's full output queue. After one
cooperative scheduling yield, an unavailable writer fails that connection;
ordinary disconnect handling updates the mesh instead of silently dropping a
membership frame. Failed send/receive halves close the connection so the other
half cannot hide their failure. Clean EOF preserves the opposite send leg:
upstream deliberately permits simultaneous connections to carry a peer's two
directions separately. Both halves completing ends the obsolete connection.
A cancelled dial remains cancelled when its completed result
is consumed, including when success won the race inside the task.
Pending dial queues have a burst allowance
proportional to live topic membership; overflow cancels that dial and reports
the disconnection. These are bounded transport failure policies, not a queue of
collection-state changes.

The vendored development manifest additionally enables Iroh's custom test
transports for deterministic connection-lifecycle regressions. Runtime
dependency features are unchanged.

Validation belongs to the enclosing workspace. This provenance note records
the source change, not a deployment or test-pass claim.
