# TribleSpace GPU

`triblespace-gpu` is the opt-in accelerator companion for TribleSpace. The
default `triblespace-core` remains GPU-free: it owns the structural
`SuccinctArchive` merge, canonical section order, output validation, and the
whole constraint protocol. This crate adds two device paths on top:

* a CubeCL implementation of core's `WaveletMatrixFreezeBackend` seam for
  structural archive merges, and
* batched device evaluation of the succinct-archive constraint's
  `confirm` calls.

Enable exactly the runtime you need:

```toml
[dependencies]
triblespace-core = { version = "0.47", default-features = false }
triblespace-gpu = { version = "0.47", default-features = false, features = ["wgpu"] }
```

The facade crate also exposes the companion as `triblespace::gpu` when its
`gpu` feature is enabled. That convenience feature selects WGPU and the Rayon
query executor together:

```toml
[dependencies]
triblespace = { version = "0.47", features = ["gpu"] }
```

`triblespace-gpu` requires Rust 1.92, matching CubeCL 0.10's declared MSRV.
Consequently the facade's `gpu` feature also requires Rust 1.92. This does not
raise the GPU-free `triblespace-core` crate's Rust 1.89 MSRV.

## Batched confirm

The engine's `Constraint::confirm` protocol is kill-only: a confirmer receives
one candidate region — read-only 32-byte values plus killable `u32` liveness
words — and may only zero words. Verdicts computed anywhere therefore merge
back by word-wise AND, which is exactly what makes batched device evaluation a
legal schedule: the device can never revive a dead entry, and parallel lanes
never contend.

With the `wgpu` feature, `WgpuSuccinctArchive` wraps a CPU `SuccinctArchive`
and keeps the structures its confirm probes touch resident on the default
CubeCL WGPU device: the value universe as big-endian `u32` words (so word-wise
comparison equals byte-lexicographic order), one occupancy boundary table per
axis, and the six Ring wavelet matrices in one Jerky compatibility domain. It
implements the same `TriblePattern` interface as the wrapped archive;
estimates, proposals, prefix walks, and satisfaction checks stay on the CPU.

A `confirm` region with at least `min_confirm_batch` live candidates
(default `DEFAULT_MIN_CONFIRM_BATCH = 16_384`, measured — see below) uploads
its candidate values and liveness words and computes one verdict word per
candidate on the device:

* **Unbound membership** (no other pattern position bound; the confirmed
  variable is E, A, or V): one fused kernel binary-searches each candidate in
  the resident universe and checks the axis boundary table — the CPU arm's
  `base_range(..).is_empty().not()` — then a single readback ANDs the
  verdicts into the region.
* **Range restriction** (one or two other positions bound): the fixed row
  range is computed once on the CPU from the bound values; a probe-fill
  kernel resolves candidates to universe codes, Jerky's batched wavelet rank
  answers `rank(r.start, d)` / `rank(r.end, d)` for all candidates in one
  dispatch, and a fold kernel emits the verdicts — the CPU arm's
  `restrict_range(..).is_empty().not()` with the shared `select1` base offset
  cancelled. All three launches are enqueued back-to-back with a single
  readback.

That covers all twelve confirm arms of the canonical constraint. Regions
below the threshold, non-confirm protocol methods, and any device error fall
through to the canonical CPU constraint, and the parity suite
(`tests/batch_confirm_parity.rs`) holds both paths to bit-identical liveness
words across every arm, pre-killed entries, and duplicate candidate values.

```rust,no_run
# use triblespace_core::blob::encodings::succinctarchive::{OrderedUniverse, SuccinctArchive};
# #[cfg(feature = "wgpu")]
# use triblespace_gpu::WgpuSuccinctArchive;
# #[cfg(feature = "wgpu")]
# fn wrap(archive: SuccinctArchive<OrderedUniverse>) {
let gpu = WgpuSuccinctArchive::new(archive).expect("prepare succinct archive on WGPU");
// `pattern!(&gpu, ..)` routes fat confirm regions through the device kernels.
// `gpu.stats()` reports device confirms, threshold fallbacks, and errors.
# let _ = gpu;
# }
```

The threshold is measured, not guessed. The ignored `confirm_crossover_sweep`
benchmark sweeps fully-live regions of 1k/4k/16k/64k candidates over a
262k-trible synthetic archive; on an Apple M4 Max (Metal, release profile,
best of 5) the GPU round trip is nearly flat (~1.4–2.2 ms) while CPU confirm
scales linearly, crossing at ~8k live candidates for the range shape and ~22k
for the lighter membership shape. `16_384` is the single-knob compromise; use
`with_min_confirm_batch(0)` to force every routed confirm through the device
(parity measurements) and `set_min_confirm_batch` for local calibration.

```sh
cargo test -p triblespace-gpu --release --test batch_confirm_parity -- --ignored --nocapture confirm_crossover_sweep
```

## Experimental structural merge backend

Core exposes the stateless `WaveletMatrixFreezeBackend` trait and
`merge_ordered_archives_with_backend` experiment seam. Domain remapping, the
canonical EAV union, the other Ring rotations, prefix vectors, section order,
and Rank9 attachment remain in Core; a backend only freezes the six wavelet
matrices. Successful output is byte-identical to the canonical CPU builder.

Core cheaply validates plane shape, every all-zero plane before the sequence's
highest set bit, that first informative plane pointwise, and zero tail padding.
For an all-zero sequence it requires every plane to be zero. It does not
recompute subsequent stable partitions on the CPU; after an implementation
returns `Ok(())`, deeper interior ordering remains inside the backend trust
boundary. This CubeCL backend explicitly synchronizes queued commands before
readback so device validation errors are returned rather than mistaken for zero
or stale output.

There is deliberately no high-level adaptive rollup wrapper. The removed
`AcceleratedSuccinctRollup` mixed CPU and device execution behind a row
threshold and a process-local circuit breaker in the former branch-index
lifecycle. Current Apple M4 end-to-end measurement showed no useful benefit
from retaining that policy surface.

The exact Succinct collection lattice is instead blob-native and does not call
a branch-index merge. `SuccinctArchiveBlob` owns the canonical derivation from
`SimpleArchive` and consumes and produces canonical collection blobs directly.
Its `build_from_simple_archive_with_backend` and `merge_with_backend` entry
points share the CPU writer's domain preparation and portable layout. Only the
six wavelet matrices use the backend. One reusable `u64` plane allocation is
serialized explicitly into the little-endian raw bytes; no native query arena
or Rank9 accelerator is built as a bridge.

`BackendSuccinctMapping<B>` selects this execution route through the existing
`ensure_with`/`maintain_with` APIs. Its descriptor is the ordinary canonical
mapping descriptor, not a GPU-specific collection. Both DERIVE and horizontal
target MERGE use the backend; Rank9 remains CPU work. Returned backend errors
or invalid prefix/tail output retry the canonical CPU operation, with a warning.
Descriptor binding is device-free: a per-binding `OnceLock` initializes the
backend only for an actual map or join. A no-op maintenance pass therefore does
not initialize CUDA; `new(backend)` can reuse an explicitly supplied backend.
Device initialization, allocation failures, runtime panics and OOM are not
caught, and no partial failed output is published.

The CLI's optional `succinct-cuda` build feature enables
`--succinct-backend cuda` for `pile collection maintain` and `maintain-all`.
The command default stays `cpu`, even in a CUDA-capable build. This flag is not
a reservation: a Spark launcher must reserve its device/shared-memory workload
before each bounded maintenance pass and release while idle. Do not compete
with a model job or hold a device for a watcher's entire lifetime. There is no
internal scheduler, memory-budget oracle, global backend registry or persistent
rollup lifecycle here.

Repository builds patch CubeCL 0.10's runtime and WGPU crates to the project's
fork, which exposes immutable external-buffer registration for mmap-to-Metal
aliasing. Cargo patches are root-local, so application workspaces that need the
aliasing seam must select the same fork themselves. The current compaction
backend still uploads a newly materialized `u32` rotation and reads the packed
planes back; merely selecting the fork does not make that transient path
zero-copy.

## Validation and benchmark

CPU-only validation does not compile CubeCL:

```sh
cargo test -p triblespace-gpu --no-default-features --lib
```

The WGPU parity gate and full structural benchmark are opt-in:

```sh
cargo test -p triblespace-gpu --features wgpu --test batch_confirm_parity
cargo run --release -p triblespace-gpu --features wgpu --example archive_merge -- 100000
```

WGPU has historical runtime parity coverage on Apple Metal. The new direct-raw
CUDA path must pass its explicit hardware gate before a deployment selects it
by default. CPU-only plumbing and hardware tests are separate; the hardware
gate refuses to turn a CUDA error into a successful CPU fallback:

```sh
cargo test -p triblespace-gpu --no-default-features --test raw_mapping
cargo test -p triblespace-gpu --no-default-features --features cuda --test raw_mapping -- --ignored --test-threads=1
cargo run --release -p triblespace-gpu --no-default-features --features cuda --example raw_succinct_cuda -- 65536 3
```

The counted collection test proves that actual signed target MERGEs, not just
DERIVEs, use the backend, that binding does not construct a backend, and that
repeat maintenance neither initializes nor executes a backend. Raw
parity covers padding/block/alphabet boundaries, overlap, duplicates, input
order, varied entity/attribute codes, and exact canonical bytes and hashes.
The benchmark includes raw domain
and rotation preparation, canonical input checks and hashing; it alternates CPU
and GPU order and deliberately caps rows and repetitions.

For `N` rows and `W` wavelet levels, the backend's main device buffers require
roughly `8N + W*N/8` bytes per rotation, plus block scratch and readback, on top
of the CPU domain/rows/sort scratch and final output. Allocator-retained scratch
can increase this. Rotations run sequentially; model and construction memory
must be budgeted together on a unified-memory Spark. Synchronization errors are
recoverable, but this estimate is not an OOM guarantee.

`archive_merge` is deliberately a low-level backend benchmark. It compares the
same canonical structural merge with CPU and device wavelet freezing; it is
not an exact-collection benchmark or a production admission policy. The
`raw_succinct_cuda` example measures the direct-raw path used by the companion
mapping instead.
