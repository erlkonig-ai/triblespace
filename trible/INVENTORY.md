# Inventory

## Potential Removals
- None at the moment.

## Desired Functionality
- Inspection utilities for listing entities, attributes, and relations, with optional filtering.
- Progress reporting for blob transfers and other long-running operations.
- Custom maximum pile size when creating piles.
- Consolidate shared blob-handling logic across `pile` and `store` commands.

## Discovered Issues
- `pile collection migrate` carries COMMIT records only. MERGE and DERIVE
  equations are counted and left behind on the assumption that the target's own
  maintenance re-derives its own; that is believed correct because a merge is an
  equation between a collection's own members, but it has not been demonstrated
  on a source with a deep merge chain.
- `pile collection reconcile` and `migrate --siblings` find same-named siblings
  through the collections this pile *references*, so a generation that holds no
  records is invisible to sibling discovery. That is the right domain for a
  carry — an empty sibling has nothing to move — but a handle-level worklist is
  still the only way to reach a collection nothing names.
- Neither command detects the physical duplication a `cat a.pile >> b.pile`
  merge leaves behind: `Pile` keys records by fingerprint, so duplicates are
  invisible to the record stream. `pile diagnose` counts them from the raw log
  and `pile compact` reclaims them; `migrate` only says so.
- Object store operations rely on an async runtime; consider synchronous alternatives.
- Preflight script and test suite take an unusually long time to run; investigate ways to reduce build and execution time.
