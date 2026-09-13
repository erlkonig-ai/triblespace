# Formal Verification Roadmap

This roadmap captures the initial strategy for driving the `triblespace` crates
toward comprehensive formal verification.  It unifies model checking, symbolic
execution, fuzzing, and deterministic simulation so we can reason about both the
low-level data structures and high-level collection workflows with stronger
correctness guarantees.

## Verification Stack Overview

- **Model checking with Kani** explores bounded but exhaustive state spaces for
  invariants that must never be violated.
- **Symbolic execution with Miri** exposes undefined behaviour (UB) and
  aliasing issues across regular unit tests without requiring new harnesses.
- **Coverage-guided fuzzing** stresses APIs with randomized input sequences to
  uncover emergent behaviours that formal proofs might miss.
- **Deterministic simulations** replay realistic collection and storage workflows so we can
  audit higher-level semantics and regression-test subtle interplays between
  subsystems.

Each technique complements the others; together they provide layered
assurance that keeps regressions from reaching downstream users.

## Goals

- Protect the fundamental algebraic properties of `TribleSet`, `PATCH`, and the
  native collection ledger.
- Exercise serialization, deserialization, and zero-copy data views under
  adversarial inputs.
- Detect behavioural regressions in query heuristics, constraint solving, and
  collection resolution before they reach downstream users.
- Integrate the tooling into CI so proofs and regression checks run
  automatically for every change.
- Preserve a contributor-friendly workflow where verification steps are
  discoverable, well documented, and quick to reproduce locally.

## Current Foundation

- `proofs/` already contains Kani harnesses for query, value, and variable-set
  behaviour.  They provide examples of bounded nondeterministic data generation
  (`kani::any`, `Inline::new`) and assume/guarantee reasoning that new harnesses
  can reuse.
- `./scripts/preflight.sh` is the aggregation point for formatting and tests;
  adding verification steps here keeps contributor workflows consistent.

## Invariant Catalogue

The roadmap anchors future work around the following invariants.  Each row
tracks the subsystem we care about, the guarantees we want to encode, and a
rough sketch of how to exercise them in Kani, Miri, or fuzzing harnesses.

| Area | Key invariants | Candidate harness or check |
| --- | --- | --- |
| `TribleSet` (`src/trible/tribleset.rs`) | Union/intersection/difference maintain canonical ordering across all six PATCH indexes; iterators only yield deduplicated `Trible`s; `insert` never drops an ordering. | Extend the existing `variableset` harnesses with nondeterministic inserts, and add a dedicated `tribleset_harness.rs` validating round-trips across every ordering. |
| `PATCH` & `ByteTable` (`src/patch/*.rs`) | Cuckoo displacement respects `MAX_RETRIES` without losing entries; `Branch::modify_child` grows tables when required and preserves `leaf_count`/`segment_count`; `table_grow` copies every occupant exactly once. | Introduce a `patch_harness.rs` that stress-tests `plan_insert`, `table_insert`, and `Branch::grow`, plus a micro-fuzzer that drives inserts/removals across random table sizes. |
| Inline encodings (`src/inline/encodings/*.rs`) | Encoders respect declared byte widths; `TryFromInline` conversions and `InlineEncoding::validate` reject truncated buffers; zero-copy views stay aligned. | Reuse `value_harness.rs`, adding per-encoding helpers plus a Miri regression suite that loads slices at every alignment. |
| Query engine (`src/query/*.rs`) | Constraint solver never aliases conflicting bindings; the depth-first search enumerates every complete binding exactly once, and never twice, across backtracking and rayon splits; confirmation is kill-only, so any confirmer order yields identical liveness; and a frontier's width is semantically inert — the same bag of rows comes out at width 1 and at any wider batch. | Expand `proofs/query_harness.rs` with minimal counterexamples, and fuzz constraint graphs via `cargo fuzz`. |
| Collection algebra (`src/collection/*.rs`) | Every representable member join is associative, commutative, and idempotent, while finer covers preserve the total logical join across capacity boundaries; record insertion is idempotent; foundational `Support` is exactly `Cover<SimpleArchive>` and remains invariant across every explicit mapping hop; each target-owned `CollectionDerivation` and explicit `CollectionMapping` is a join homomorphism; substituting an intrinsic mapping-entity id with an extrinsic one does not change meaning; read-only attachment executes no acquisition, joins, or mappings; root `ensure` acquires support without publishing equations, while derived `ensure` publishes only missing `DERIVE` work for one hop; `maintain` additionally reaches a deterministic target size-tier normal form without computing upstream blobs or publishing upstream equations; every successful target `MERGE` or `DERIVE` is persisted even if later work fails; store-level ensure and maintain operations return a fresh `StoreSnapshot`, from which an immutable `CollectionSnapshot` can select frozen support and a realized cover; only Yard/GC removes materializations; COMMIT membership and equation reuse require each producer's target WRITE admission at the frozen snapshot instant; a producer signature endorses computation but does not prove its mathematics. | Add bounded record-set generators plus deterministic simulations over resident target results, support-equivalent physical covers, capacity-terminal nodes, and explicitly missing join dependencies. Compare every accepted `Cover<E>` and snapshot-owned logical view with direct source reconstruction, permute record insertion order, inject late failures after successful work, assert that ensure emits no `MERGE`, assert that downstream maintenance never computes upstream artifacts or publishes upstream equations, assert deterministic tiered maintenance, instrument warm paths to prove zero algebra; reject READ-only equation producers, accept delayed WRITE evidence without reinsertion, and check foreign signatures exactly at ingress. Keep direct reconstruction as an offline oracle rather than a production read step. |
| Storage primitives (`src/blob`, `src/repo`, `src/patch/leaf.rs`) | Blob handles stay reference counted; pile headers remain within reserved capacity; concatenation preserves native record meaning; byte slices from archives stay valid for the life of the store. | Combine Miri tests for aliasing with nightly fuzzers that replay pile and collection-sync transcripts. |

## Expansion Plan

### Phase 1 – Harden the Existing Kani Coverage

1. Catalogue crate-level invariants and map them to concrete Kani harnesses.
   Start with:
   - `TribleSet` operations preserving canonical ordering and deduplication.
    - Join heuristics in `atreides` ensuring variable bindings never alias
      conflicting values.
   - Collection resolution preserving explicit payload support under alternate covers.
2. Extract shared helpers for generating bounded arbitrary data (e.g.
   `Vec::bounded_any`) so harnesses remain expressive without exploding the
   search space.
3. Adopt a per-module harness layout (`proofs/<module>_harness.rs`) registered
   from `proofs/mod.rs` to make maintenance predictable.
4. Configure `scripts/verify.sh` to run targeted `cargo kani --harness <name>`
   invocations in parallel, then wire it into CI with caching to keep runtimes
   manageable.

### Phase 2 – Symbolic Execution with Miri

1. Enable `cargo miri test` for the default test suite to surface undefined
   behaviour (UB) and aliasing bugs that regular tests may miss.
2. Gate flaky or unsupported tests with `cfg(miri)` guards so the suite stays
   deterministic under the interpreter.
3. Document the workflow in `scripts/preflight.sh` and optionally expose a
   dedicated `scripts/miri.sh` for local runs when developers need deeper
   debugging.

### Contributor Workflow

1. Run `./scripts/preflight.sh` before every commit; it aggregates formatting,
   testing, and (eventually) targeted verification checks.
2. Use `cargo kani --harness <NAME>` locally when iterating on a new proof.
   Start from the harness templates in `proofs/` so generators and assumptions
   stay consistent.
3. Execute `cargo miri test` after modifying unsafe code, pointer logic, or
   concurrency primitives; it catches UB bugs that normal tests cannot
   surface.
4. Kick off fuzz targets with `cargo fuzz run <TARGET>` when touching boundary
   code (deserializers, planners, collection sync). Store new corpus inputs in
   version control if they expose bugs or tricky behaviours.
5. Record findings, gaps, and future work in `INVENTORY.md` so the roadmap
   evolves alongside the implementation effort.

### Phase 3 – Fuzzing and Property Testing

1. Introduce a `cargo fuzz` workspace targeting:
   - PATCH encoders/decoders with binary corpus seeds generated from integration
     tests.
   - Join-order heuristics to explore combinations of constraint graphs and filter
     predicates.
   - Collection sync workflows by fuzzing unions of commits, merges,
     derivations, missing blobs, and WANTs.
2. Reuse structured generators from `proptest` where deterministic shrinking is
   valuable, and bridge them into fuzz harnesses when possible to keep the state
   space constrained.
3. Automate nightly or on-demand fuzz campaigns via CI artifacts, storing any
   found counterexamples alongside minimised reproducers.

### Phase 4 – Deterministic Simulation Testing

1. Model collection replication scenarios with deterministic event queues to
   explore sparse evidence, garbage collection, and concurrent writers.
2. Encode the simulations as regular unit tests backed by recorded execution
   traces so they can double as documentation for expected behaviour.
3. Capture simulation scenarios discovered during fuzzing to prevent
   regressions.

### Milestones & Reporting

- Track coverage for each invariant in a shared dashboard (CI summary or
  `INVENTORY.md`) so contributors can quickly spot gaps.
- Celebrate major wins—like a new harness landing or a bug found via
  verification—in the CHANGELOG to reinforce the value of the effort.
- Review and refresh this roadmap at least once per release cycle to keep the
  guidance aligned with the architecture.

## Tooling Integration

- Track verification status in CI badges and documentation so contributors know
  which guarantees currently hold.
- Extend `INVENTORY.md` with follow-up work items whenever new invariants or
  subsystems are identified.
- Keep verification-specific configuration (Kani property files, fuzz corpora,
  deterministic seeds) under version control to make runs reproducible.

## Next Steps

1. Break the invariant catalogue into GitHub issues that reference the planned
   harness files (`proofs/tribleset_harness.rs`, `proofs/patch_harness.rs`, etc.).
2. Prototype the PATCH harness that drives `Branch::modify_child` through
   insertion/growth cycles so we can assert the displacement planner and
   `table_grow` never drop entries; wire the run into `scripts/verify.sh`.
3. Evaluate CI capacity to determine how frequently Kani proofs, `cargo miri`,
   and fuzzers can run without blocking contributors, documenting the cadence
   directly in `INVENTORY.md`.

This roadmap should evolve alongside the codebase—update it whenever new
verification opportunities or obstacles appear.
