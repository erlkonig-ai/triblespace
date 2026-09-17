# Known-positive blob throughput probe

This example diagnoses real Iroh bearer GET throughput. It does not change
production scheduling, request windows, protocol limits, Pile behavior, or
installed services. Its clean source base is Core
`e7115be76e0ce7b95cf2ba1264fdc63b0372a219`; record the example patch digest and
actual executable SHA alongside every result. No performance result is implied
by the source-only preparation.

## Build and safety boundary

After an explicitly allocated Stars slot, stage this example into an isolated
normal-layout cohort with the exact eight repository revisions and three
lockfiles from the already validated message-habit cohort. Do not build in the
donor, copy target directories, regenerate locks, or use sibling symlinks that
create duplicate workspace identities. Run the existing GB10 lock preflight,
acquire a unique lease with heartbeat/trap release, check parent build drivers
and GPU activity, use the reviewed expendable rustc wrapper, 4 jobs, Rayon 4,
`CARGO_INCREMENTAL=0`, and the authorized target. Only these scoped commands are
needed for this example (no workspace, CUDA or feature-matrix build):

```sh
cargo test --locked --offline -p triblespace-net --example blob_throughput_probe -j 4
cargo build --locked --offline --release -p triblespace-net --example blob_throughput_probe -j 4
```

Both commands must use the same pinned source/lock cohort and
`RUSTFLAGS='-C target-cpu=native'` when reusing an existing target with that ABI.
Release the build lease before any separately approved measurement. Installing
the executable or changing a live service is unnecessary.

The example accepts no existing Pile or key. Its server generates fresh random,
non-sensitive payloads with an eight-byte unique ordinal in MemoryRepo and an
ephemeral endpoint identity. The client uses an empty MemoryRepo or a new
temporary Pile. It uses the native
endpoint-bound provider-first bearer protocol: only L/KDF and proofs go over the
wire, not raw H. Raw H exists only in the explicitly requested mode-0600 manifest
and protected stdin; never put it in arguments, logs, or shell tracing.

Use a fresh mode-0700 experiment directory on each host. Set `TMPDIR` to its
dedicated receive directory **before process start**. Allow at least 2 GiB free
disk and 4 GiB available memory on each host; the invocation owner should retain
the existing bounded process/resource supervisor (4 GiB RSS ceiling). Do not
drop global caches. These are memory-backed-provider / warm-OS-cache measurements,
not cold-disk-provider measurements. Do not run concurrently with another
benchmark, build, or heavy live maintenance experiment.

## Explicit fixture and one arm

Commands below are a plan, not an unattended runner. `PROBE` is the verified
example binary. `RUN` is a newly created private directory on the executing
host; all named files must be new. A controller owns the bounded server process
and waits for `fixture=ready` before fetching. Do not background a live daemon.

For a 128 MiB fixture on Sky:

```sh
umask 077
mkdir "$RUN/receive"
TMPDIR="$RUN/receive" "$PROBE" serve-fixture \
  10.55.0.2:0 1048576 128 600 "$RUN/handles" >"$RUN/provider.log" 2>&1
```

This prints the ephemeral public endpoint ID and the actual bound UDP socket,
not handles. Copy only the protected manifest through the approved SSH/SCP
channel, keeping mode 0600 on the receiver; never print it. `PEER_ID` and
`PEER_SOCKET` below must come from this fixture's log, not the running custody
daemon's endpoint or historical UDP port. `RECEIVER_RUN` is the Stars experiment
directory and already contains its private `receive` directory and manifest:

```sh
TMPDIR="$RECEIVER_RUN/receive" "$PROBE" fetch \
  10.55.0.1:0 "$PEER_ID" "$PEER_SOCKET" \
  direct close-only 4 1048576 30 "$RECEIVER_RUN" \
  <"$RECEIVER_RUN/handles" >"$RECEIVER_RUN/direct-close-only-c4.log" 2>&1
```

Replace `direct` with `discovery` to use the unchanged normal DHT/provider
selection path over the explicit bootstrap endpoint/socket. It has no direct-GET
fallback. The server's resident self-provider hint works with proactive
publication budget zero. `direct` establishes and retains one connection before
the timed arm, then calls the same native `op_get_blob`; no lookup or hash
shortcut is substituted. Both arms use `presets::Minimal`, explicit IP binding,
and relays disabled; this compares **content-provider discovery**, not public
DNS/relay address discovery.

Landing choices:

- `network-only`: no destination Pile writes. The **native receive path still
  writes anonymous temporary files**, hashes once, and retains file-backed Bytes
  until they are dropped. This is not a disk-free network speed test.
- `close-only`: put each already verified Blob, refresh the Peer after each put,
  no per-operation flush; Pile close at the end is the sole durability barrier.
- `flush-each`: the comparison arm explicitly flushes after every put, then
  refreshes, and closes at the end. It is not a recommended policy.

The client keeps at most `1`, `4`, or `16` request futures in flight. Like the
current reconciliation driver, the coordinating runtime polls these futures;
synchronous put/flush/refresh temporarily stops polling its other acquisition
futures. The independent two-worker host runtime continues running Iroh, serving
and routing. Host tick count/max gap make a stopped host observable, but do not
prove every in-flight acquisition progressed during a put. This deliberately
exposes the existing serialization boundary; it is not a pipelined landing patch.

## Finite matrix and attribution

Run one arm at a time; first verify one small direct/network-only success. Then
use concurrency 1/4/16 for direct and discovery, first network-only and close-only;
add flush-each only as the explicit durability comparison. Suggested independent
size rows (all Hs distinct; no duplicate-put arm):

| Blob bytes | Count | Total |
|---:|---:|---:|
| 65,536 | 512 | 32 MiB |
| 1,048,576 | 128 | 128 MiB |
| 16,777,216 | 16 | 256 MiB |

Reuse the same fixture within a row. Repeat a row with arm order reversed if
warmup seems material, rather than claiming a cold-cache comparison. Reverse the
hosts for the second direction with a new fixture; no live/private handles.

Capture route evidence before/after the approved experiment:

```sh
# Stars:
ip route get 10.55.0.2
ethtool enp1s0f0np0
# Sky:
ip route get 10.55.0.1
ethtool enp1s0f1np1
```

The known interface/link reports say 200,000 Mb/s full duplex, but that is not an
achieved throughput claim. Each direct arm reports its established selected
path, and both modes report actual selected paths for up to 32 dialed connections
at arm end. Inspect local/remote sockets and `direct=true`; missing path evidence
is not proof of fabric use. A single explicit bind plus peer socket avoids
assuming endpoint-ID discovery chose the fabric. Path snapshots do not constitute
a complete path-change history for the arm.

Stage counters are count plus **sum of elapsed lifetimes**, not disjoint wall
time. Concurrent RPC sums can exceed total arm time:

- `fetch_e2e`: selected request future through verified Blob/failure; includes
  readiness/discovery as applicable and coordinator scheduling delays.
- `dial_including_setup`: handshakes, including direct preconnection and any
  host bootstrap dials. Setup is separately printed; do not subtract overlapping
  lifetimes to invent a pure routing cost.
- `get_stream_receive_and_hash`: stream open through native receiver completion
  and its single `Blob::new`/requested-H comparison (or error/cancellation). This
  includes provider proof, body reception, temporary-file IO and hash together.
- `directory_routing_control_stream`: other outgoing RPC lifetimes, including
  startup control. It does not contain H or decoded content.
- `pile_put`, `pile_explicit_flush`, `peer_refresh`, `destination_close`: scoped
  synchronous work. Destination Pile's own validation/locator work remains in
  those real paths; the example adds no readback hash. Through-close wall time
  also includes closing checks and deleting the disposable directory.

Only `complete == requested`, zero errors and zero cap failures make an arm
successful. Network `None` is **indeterminate** in discovery mode because the
existing API combines absence, readiness, deadline and transport failures.
Direct `None`, direct errors and deadline outcomes are counted separately.
Arbitrary nested error messages are suppressed to avoid logging bearer handles;
the example does not convert them into empty successful results. The public seam
cannot separately time the native receive hash without production instrumentation.

## Caps, cleanup and limitations

- Fixture blobs are at least eight bytes, so their ordinal guarantees distinct
  payloads even in tiny controls; random collisions never turn a fixture into
  duplicate-Pile work.
- One arm per client process, at most 4,096 unique Hs, 64 MiB each, 256 MiB total
  requested; exact expected blob size is mandatory.
- At most 60 seconds timed acquisition; an independent owned-process watchdog
  exits after that budget plus 30 seconds for input/setup/close. Async deadlines
  alone cannot interrupt synchronous flush. A server serves at most 600 seconds
  plus 30 seconds setup/shutdown allowance.
- Before returning the announced length to the native receiver, an example-only
  stream wrapper checks exact fixture size and a **512 MiB aggregate announced
  receive budget**, counting retries too. It does not reinterpret bearer proofs
  or skip native bounds, EOF, hash or requested-H validation. Native framing's
  unavailable sentinel remains unavailable. Anonymous receive backing is bounded
  by this budget plus at most one native 1 MiB allocation quantum per in-flight
  receive; the fresh destination is at most 256 MiB plus framing. Fixture storage
  is at most 256 MiB in MemoryRepo. No server request-limit constants are changed.
- Existing inbound global/per-connection caps and native receive-body cap are
  16. Discovery also uses control request slots; report saturation/errors rather
  than silently increasing those limits.
- Success closes/deletes the fresh destination and shuts down/join-drains the
  owned host. Early failure or watchdog exit may leave its printed disposable
  directory or manifest for owner cleanup. Never remove an unverified path or
  an installed/live pile. The manifest is intentionally not automatically deleted
  by the server because later arms use it; delete it after the bounded experiment.
- Counters and header wrapping add measurement overhead. This measures the real
  file-backed body pipeline over an otherwise empty provider/client, not a
  populated custody refresh, collection authorization, or disk-cold scan. It
  cannot explain all live-cohort CPU cost and makes no change to production APIs.
