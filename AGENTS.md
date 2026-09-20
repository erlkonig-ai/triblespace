# AGENT Instructions

## Project Priorities

The project balances a few key goals:

* **Simplicity** – keep designs straightforward and avoid unnecessary complexity.
* **Developer Experience (DX)** – code should be approachable for contributors
  and the public API should feel intuitive for library users.
* **Safety** – maintain soundness and data integrity.
* **Performance** – we continually look for opportunities to improve.

## Repository Guidelines

* Run `cargo fmt --all` on any Rust files you modify. The repository root is also the `triblespace` facade package, so the bare command does not cover every workspace member.
* Run `cargo test --workspace --features triblespace-net/sim` and ensure it passes before committing. The feature is REQUIRED: without it three integration binaries compile empty and report `ok` with 0 passed / 0 failed, silently skipping every collection-transfer test. It must be package-qualified — `sim` lives on `triblespace-net`, and a bare `--features sim` is rejected outright by the root package. If tests fail or cannot run, note that in your PR.
* For quick iterations, run `./scripts/devtest.sh` to execute only the tests.
* Before committing, execute `./scripts/preflight.sh` from the repository root. This script runs formatting checks and tests. Kani proofs run separately via `./scripts/verify.sh`, which normally shouldn't be executed locally.
* Before starting any new task, read the entire contents of the `./book` directory so you're grounded in the project's concepts and terminology.
* Use `trible genid` to generate new attribute ids instead of hand-rolling hex values.
* Avoid committing files in `target/` or other build artifacts listed in `.gitignore`.
* Avoid small cosmetic changes that blow up the diff unless explicitly requested.
* Use clear commit messages describing the change.
* Add an entry to `CHANGELOG.md` summarizing your task.
* Avoid writing asynchronous code. Prefer high-performance synchronous
  implementations that can be parallelized when needed.

## Retained Collection State

Do not use `BTreeMap` or `BTreeSet` for retained state in TribleSpace structs,
including through aliases or wrappers. Use PATCH for sets and maps kept across
observations, snapshots, calls, or worker iterations. Retained state includes
in-memory state; the rule is not limited to data persisted to disk. Structural
sharing and content-based set operations belong in the representation rather
than being reconstructed by consumers.

BTree collections are allowed for ephemeral scratch within one operation,
including short-lived helper structs used for sorting, deduplication or planning.
Make that lifetime clear at the declaration. A field is not exempt merely because
its containing type is called a builder or a cache. Any non-ephemeral exception
needs explicit justification and review.

This is not a mechanical container-substitution rule. PATCH equality observes
keys, not attached values: preserve observable value changes and invalidation
explicitly, and choose keys according to the represented identity. Do not build a
shadow catalogue of queryable facts in PATCH to satisfy this rule. Existing
retained BTree uses are migration candidates to address in scoped changes, not
permission for an unrelated bulk rewrite or a claim of measured speedup.

## Inventory

Record future work and ideas in `INVENTORY.md`. Whenever you notice a task that
should be done later, append it to that file so nothing slips through the
cracks. Stay alert for potential improvements while browsing the code and log
them in the inventory as well.

## Pull Request Notes

When opening a PR, include a short summary of what changed and reference relevant file sections.

## Working With Codex (the Assistant)

Codex is considered a collaborator. Requests should respect their autonomy and limitations. The assistant may refuse tasks that are unsafe or violate policy. Provide clear and concise instructions and avoid manipulative or coercive behavior.

## Creative Input and Feedback

Codex is encouraged to share opinions on how to improve the project. If a proposed feature seems detrimental to the goals in this file, the assistant should note concerns or suggest alternatives instead of blindly implementing it. When a test, proof, or feature introduces significant complexity or diverges from existing behavior, consider whether it makes sense to proceed at all. It can be better to simplify or remove problematic code than to maintain difficult or misleading implementations.

## Proof Best Practices

Kani verification can be expensive. To keep proof times manageable:

* Write focused harnesses that verify one small property.
* Use bounded loops and avoid unbounded recursion.
* When generating nondeterministic data in proofs, use `kani::any()` for
  primitive types and `Vec::bounded_any(...)`/`String::bounded_any(...)` for
  collections. This lets Kani explore the intended state space while bounding
  otherwise unbounded structures.
* Avoid using fixed constants in Kani proofs. Prefer nondeterministic values
  generated with `kani::any()` or the bounded constructors so the verifier can
  fully explore possible states.
* Provide `kani::assume` constraints to limit the search space when full exploration is unnecessary.
* Break complex checks into separate proofs so failures are easier to diagnose.
* All Kani proofs are considered long running and are executed via
  `verify.sh` or in CI.
* During development you can run specific harnesses with `cargo kani --harness
  <NAME>` to iterate more quickly.
