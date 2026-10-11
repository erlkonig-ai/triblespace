//! Subject-side measurement material, vendored from
//! `june-on-tip/benches/portable_bench.rs` (working tree of
//! 2026-07-27) and adapted to the `subject` dependency (the engine
//! under test). Everything in this module runs against the SUBJECT:
//! imports go through `subject::core::…` / the core prelude, whose
//! macros expand to `$crate` or `::triblespace_core` paths — both
//! resolve to the subject's core, never to the results ledger.
//!
//! Vendored pieces:
//! - `quiet_catch` — panics are an outcome, not a crash.
//! - the Harkonnen R1 adversarial fixtures (`Ids`, `r1_schema`,
//!   `build_chain`/`build_oasis`/`build_khop`/`build_diamond`; minted
//!   attribute ids from 2026-07-19 preserved byte-for-byte). The
//!   path-shaped fixtures F1/F2/F4 (chain, ring, k-hop) are
//!   `rpq`-gated like the transitive-path queries: without a
//!   regular-path constraint on the subject they cannot be queried,
//!   so their builders compile only under `--features rpq` and the
//!   runner records SKIP outcomes for their measures.
//! - the F3 (oasis-last) and F5 (two-route diamond) fixture queries.
//! - `commit_chain` + `pile_checkout` — the ladder phase: immutable
//!   materialization of the first k commits of a dataset pile's legacy data
//!   branch, where k is derived from a cumulative-trible rung target.
//!
//! Native to this crate (not vendored):
//! - the Harkonnen R2 white-box fixtures F6..F15 (attribute ids minted
//!   2026-07-27). Each one isolates ONE engine decision changed in the
//!   Term-native / propose-confirm work of this week, so a regression
//!   gets a name instead of a vibe. None is path-shaped, so none is
//!   rpq-gated; only F10 (which reads the GPU routing threshold out of
//!   `triblespace-gpu`) is feature-gated.

#![cfg_attr(feature = "legacy-repository", allow(deprecated))]

use std::time::Instant;

#[cfg(feature = "legacy-repository")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "legacy-repository")]
use rand::rngs::OsRng;

use subject::core::blob::encodings::simplearchive::SimpleArchive;
use subject::core::blob::encodings::succinctarchive::{OrderedUniverse, SuccinctArchive};
use subject::core::blob::encodings::utf8string::UTF8String;
use subject::core::inline::encodings::hash::Handle;
use subject::core::metadata;
use subject::core::prelude::inlineencodings::GenId;
use subject::core::prelude::*;
// Raw engine protocol surface — needed only by the R2 fixtures: F11's
// hand-written `Constraint` wrapper, F12's programmatic chain, and F13's
// hand-rolled variable context.
#[cfg(feature = "protocol-v2")]
use subject::core::query::{Binding, ProposalBuffer, VariableId, VariableSet};
use subject::core::query::{Constraint, VariableContext};
// `ProposeCursor` is the resumable-narrowing cursor; it exists only on
// subjects between the chunked-propose era and engine/batched-frontier.
#[cfg(all(feature = "protocol-v2", not(feature = "frontier")))]
use subject::core::query::ProposeCursor;
// `Candidates` is the post-owned-mask confirm region; only F11's hand-written
// Constraint impl names it, and it does not exist on older subjects.
#[cfg(feature = "protocol-v2")]
use subject::core::query::Candidates;
// `Frontier` is the batch of parent bindings propose/confirm take from
// engine/batched-frontier onward.
#[cfg(feature = "frontier")]
use subject::core::query::Frontier;
use subject::core::repo;
use subject::core::repo::pile::Pile;
#[cfg(not(feature = "legacy-repository"))]
use subject::core::repo::PinSnapshotSource;
#[cfg(feature = "legacy-repository")]
use subject::core::repo::{PinStore, Repository};

// ---------------------------------------------------------------------------
// Crash isolation
// ---------------------------------------------------------------------------

/// `catch_unwind` with the default panic hook silenced around the call
/// (expected panics at hostile subject revs must not spam stderr — hook
/// saved and restored) and the payload reduced to the first line of its
/// message.
pub fn quiet_catch<R>(f: impl FnOnce() -> R) -> Result<R, String> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(hook);
    out.map_err(|payload| {
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.as_str()
        } else {
            "non-string panic payload"
        };
        msg.lines().next().unwrap_or("").to_owned()
    })
}

// ---------------------------------------------------------------------------
// Harkonnen R1 adversarial fixtures (vendored; ids minted 2026-07-19,
// never invented).
// ---------------------------------------------------------------------------

mod r1_schema {
    // mp/msrc/khop keep their minted ids although the path!-based
    // fixtures that consume them (F1/F2/F4) are rpq-gated.
    #![allow(dead_code)]
    use subject::core::prelude::*;

    attributes! {
        // metronome / ring edge
        "277A42231FD9D42DD50D789D8F9E8661" unsafe as mp: inlineencodings::GenId;
        // multi-source marker (K>1 eager-cohort control)
        "0F64BC179033DB2703C65E7DBBAA9AD3" unsafe as msrc: inlineencodings::GenId;
        // oasis: type marker, p edge, q edge
        "A0C25A0F02E2D5232269F274761B2AB1" unsafe as otype: inlineencodings::GenId;
        "831EA731FB6C91252CDDC4FC399DC975" unsafe as op: inlineencodings::GenId;
        "2B3A5EF282FED1F652A2C182E116C28C" unsafe as oq: inlineencodings::GenId;
        // thin k-hop functional chain edge
        "EE09E63B176F818960267C5041CA6C92" unsafe as khop: inlineencodings::GenId;
        // diamond (reconvergence-capture) route attributes
        "E73DC5D12C49394D3C6D883A152E57C9" unsafe as da: inlineencodings::GenId;
        "C41A8C9EC883E09D34C86F87C15EA965" unsafe as db: inlineencodings::GenId;
    }
}

/// Default fixture sizes (the portable_bench defaults; F5's expected
/// row count derives from `DIAMOND_N`).
pub const OASIS_K: usize = 4_000;
pub const OASIS_FAN: usize = 32;
pub const OASIS_DEATHS: usize = 20;
pub const DIAMOND_N: usize = 256;

/// F3's expected total row count: exactly one complete op->oq path
/// (the oasis).
pub const F3_EXPECTED_ROWS: usize = 1;

/// F5's expected total row count: per entity pair (one per route),
/// route 0 contributes 1 da-edge x 4 db-edges = 4 rows and route 1
/// contributes 1 x 2 = 2 rows (the three same-target da inserts
/// dedupe), so 6 rows per `n_per_route` step.
pub const F5_EXPECTED_ROWS: usize = 6 * DIAMOND_N;

/// Deterministic UFOID-shaped ids (shared locality prefix, splitmix
/// suffix) so succinct-backend value order — and therefore exploration
/// order — is reproducible across runs and machines.
struct Ids {
    next: u64,
}

impl Ids {
    fn new() -> Self {
        Self { next: 1 }
    }

    fn splitmix64(mut v: u64) -> u64 {
        v = v.wrapping_add(0x9E37_79B9_7F4A_7C15);
        v = (v ^ (v >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        v = (v ^ (v >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        v ^ (v >> 31)
    }

    fn mint(&mut self) -> ExclusiveId {
        let c = self.next;
        self.next += 1;
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(&0xD46B_0001u32.to_be_bytes());
        raw[4..12].copy_from_slice(&Self::splitmix64(c).to_be_bytes());
        raw[12..].copy_from_slice(&Self::splitmix64(c ^ 0xD1B5_4A32).to_be_bytes()[..4]);
        ExclusiveId::force(Id::new(raw).expect("nonzero prefix"))
    }

    /// Mint with a chosen leading suffix byte so a fixture can pin
    /// where a value lands in sorted-universe order.
    fn mint_ordered(&mut self, order: u8) -> ExclusiveId {
        let c = self.next;
        self.next += 1;
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(&0xD46B_0001u32.to_be_bytes());
        raw[4] = order;
        raw[5..12].copy_from_slice(&Self::splitmix64(c).to_be_bytes()[..7]);
        raw[12..].copy_from_slice(&Self::splitmix64(c ^ 0x5EED_5EED).to_be_bytes()[..4]);
        ExclusiveId::force(Id::new(raw).expect("nonzero prefix"))
    }
}

/// F1/F2 — metronome chain and ring. rpq-gated: the fixture queries
/// are transitive closures, inexpressible without a regular-path
/// constraint on the subject.
#[cfg(feature = "rpq")]
pub fn build_chain(n: usize, ring: bool, sources: usize) -> (TribleSet, Id) {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let nodes: Vec<ExclusiveId> = (0..n).map(|_| ids.mint()).collect();
    for w in nodes.windows(2) {
        set += entity! { &w[0] @ r1_schema::mp: &w[1] };
    }
    if ring {
        set += entity! { &nodes[n - 1] @ r1_schema::mp: &nodes[0] };
    }
    for s in nodes.iter().take(sources.max(1)) {
        set += entity! { s @ r1_schema::msrc: s };
    }
    let start: Id = *nodes[0];
    (set, start)
}

/// F3 — oasis-last: `k` typed entities; the single oasis (order byte
/// 0x00, explored LAST) owns the only complete op->oq path; the first
/// `deaths` entities in exploration order have no `op` edge (cheap
/// deaths); every other entity fans `fan` junk op-edges (expensive
/// depth-2 refutations).
pub fn build_oasis(k: usize, fan: usize, deaths: usize) -> (TribleSet, Id) {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let oasis = ids.mint_ordered(0x00);
    let y_star = ids.mint_ordered(0x01);
    let z = ids.mint_ordered(0x02);
    set += entity! { &oasis @ r1_schema::otype: &oasis };
    set += entity! { &oasis @ r1_schema::op: &y_star };
    set += entity! { &y_star @ r1_schema::oq: &z };
    for i in 0..k {
        let order = 0xFF - ((i % 0x80) as u8);
        let e = ids.mint_ordered(order.max(0x03));
        set += entity! { &e @ r1_schema::otype: &e };
        if i >= deaths {
            for _ in 0..fan {
                let junk = ids.mint_ordered(0x7F);
                set += entity! { &e @ r1_schema::op: &junk };
            }
        }
    }
    let start: Id = *oasis;
    (set, start)
}

/// F4 — thin functional k-hop chain from a constant. rpq-gated like
/// F1/F2.
#[cfg(feature = "rpq")]
pub fn build_khop(k: usize) -> (TribleSet, Id) {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let nodes: Vec<ExclusiveId> = (0..=k).map(|_| ids.mint()).collect();
    for w in nodes.windows(2) {
        set += entity! { &w[0] @ r1_schema::khop: &w[1] };
    }
    let start: Id = *nodes[0];
    (set, start)
}

/// F5 — two-route diamond for reconvergence capture: two populations
/// prefer opposite orders of (da, db) then share identical
/// continuations; the eager solver merges them maximally, a width-1
/// sprint historically reenters.
pub fn build_diamond(n_per_route: usize) -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    for route in 0..2usize {
        for _ in 0..n_per_route {
            let e = ids.mint();
            let x = ids.mint();
            let y = ids.mint();
            let (fat, thin) = if route == 0 { (3usize, 1usize) } else { (1, 3) };
            for _ in 0..thin {
                set += entity! { &e @ r1_schema::da: &x };
            }
            for _ in 0..fat {
                let alt = ids.mint();
                set += entity! { &e @ r1_schema::db: &alt };
            }
            set += entity! { &e @ r1_schema::db: &y };
        }
    }
    set
}

// ---------------------------------------------------------------------------
// F3/F5 fixture queries (the pattern!-join measures; TTFR = first-row
// latency via `.next()`, total = full drain via `.count()`).
// ---------------------------------------------------------------------------

/// F3 arm-to-first-row: rows drained (0 or 1).
pub fn f3_ttfr(oasis: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>, y: Inline<GenId>, z: Inline<GenId>),
        and!(
            pattern!(oasis, [{ ?e @ r1_schema::otype: ?e }]),
            pattern!(oasis, [{ ?e @ r1_schema::op: ?y }]),
            pattern!(oasis, [{ ?y @ r1_schema::oq: ?z }]),
        )
    )
    .next()
    .map_or(0, |_| 1)
}

/// F3 full drain: total row count (expected [`F3_EXPECTED_ROWS`]).
pub fn f3_total(oasis: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>, y: Inline<GenId>, z: Inline<GenId>),
        and!(
            pattern!(oasis, [{ ?e @ r1_schema::otype: ?e }]),
            pattern!(oasis, [{ ?e @ r1_schema::op: ?y }]),
            pattern!(oasis, [{ ?y @ r1_schema::oq: ?z }]),
        )
    )
    .count()
}

/// F5 arm-to-first-row: rows drained (0 or 1).
pub fn f5_ttfr(diamond: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>, x: Inline<GenId>, y: Inline<GenId>),
        and!(
            pattern!(diamond, [{ ?e @ r1_schema::da: ?x }]),
            pattern!(diamond, [{ ?e @ r1_schema::db: ?y }]),
        )
    )
    .next()
    .map_or(0, |_| 1)
}

/// F5 full drain: total row count (expected [`F5_EXPECTED_ROWS`]).
pub fn f5_total(diamond: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>, x: Inline<GenId>, y: Inline<GenId>),
        and!(
            pattern!(diamond, [{ ?e @ r1_schema::da: ?x }]),
            pattern!(diamond, [{ ?e @ r1_schema::db: ?y }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// Arch phase: RAM succinct-archive build.
// ---------------------------------------------------------------------------

/// One `SuccinctArchive<OrderedUniverse>` build from the checked-out
/// set (the `arch/build_ram` measure).
pub fn build_archive(set: &TribleSet) -> SuccinctArchive<OrderedUniverse> {
    set.into()
}

// ---------------------------------------------------------------------------
// Ladder phase: legacy pile materialization (rung -> k mapping + union).
// ---------------------------------------------------------------------------

type CommitHandle = Inline<Handle<SimpleArchive>>;

/// Walk a linear branch parents-first (oldest-first). Uses only
/// `repo::parent` facts.
fn commit_chain(
    snapshot: &impl BlobStoreGet,
    head: CommitHandle,
) -> Vec<(CommitHandle, TribleSet)> {
    let mut chain = Vec::new();
    let mut cursor = Some(head);
    while let Some(handle) = cursor {
        let meta: TribleSet = snapshot.get(handle).expect("read commit metadata");
        let parents: Vec<CommitHandle> = find!(
            (p: Inline<Handle<SimpleArchive>>),
            pattern!(&meta, [{ repo::parent: ?p }])
        )
        .map(|(p,)| p)
        .collect();
        chain.push((handle, meta));
        cursor = match parents[..] {
            [] => None,
            [p] => Some(p),
            _ => panic!("merge commit in data branch (expected a linear chain)"),
        };
    }
    chain.reverse();
    chain
}

/// Order-independent content digest of a trible set: each trible's 64
/// bytes folded to a `u64` (FNV-1a over its eight words) and the fold
/// XOR-accumulated across the set.
///
/// Exists because SIZE is not identity. The rung machinery carves a
/// fixed-length sorted prefix out of the checked-out set, which pins
/// the size to the rung target no matter what the checkout returned —
/// so a size-only gate reports identity even when the workload has
/// changed underneath it. Observed on this suite (2026-07-27): two
/// runs at rung 1M, same pile, same commit, identical checked-out size
/// of 4 064 802 tribles, produced 1M-trible prefixes that answered
/// `join_2_largest_result` 1 091 725 and 1 091 741. Recording the
/// digest makes that drift a fact in the pile instead of a discrepancy
/// someone notices between two report tables.
///
/// XOR is chosen over a sequential hash deliberately: it digests the
/// SET, not the iteration order, so an order change alone never trips
/// the gate. A `TribleSet` holds no duplicates, so nothing cancels.
fn set_digest(set: &TribleSet) -> u64 {
    let mut accumulator: u64 = 0;
    for trible in set.iter() {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for word in trible.data.chunks_exact(8) {
            hash ^= u64::from_le_bytes(word.try_into().expect("eight-byte word"));
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        accumulator ^= hash;
    }
    accumulator
}

/// Open the pile, resolve the data branch, map the rung to k commits,
/// and measure materialization of those commits — one span per warmed
/// iteration, timestamps against `base`. Current subjects use a strictly
/// observational pin snapshot; the `legacy-repository` adapter exists only
/// so the history sweep can compile subjects from before that API existed.
///
/// Returns the checked-out set (prefix-carved for sub-first-chunk
/// rungs), the per-iteration spans as `(begin_ns, duration_ns)`, the
/// identity trible count, and the set's content digest (see
/// [`set_digest`] — the count alone cannot identify a carved
/// workload). `Err` = workload-identity gate failure; panics (API
/// drift at hostile revs) escape to the caller's [`quiet_catch`].
pub fn pile_checkout(
    path: &std::path::Path,
    branch: Option<&str>,
    rung: usize,
    iters: usize,
    warmup: usize,
    base: &Instant,
) -> Result<(TribleSet, Vec<(u64, u64)>, usize, u64), String> {
    let mut pile = Pile::open(path).expect("open pile");
    pile.refresh().expect("load pile records");
    #[cfg(not(feature = "legacy-repository"))]
    let pins = pile
        .snapshot_pin_heads()
        .expect("snapshot legacy branch pins");
    #[cfg(feature = "legacy-repository")]
    let snapshot = pile.reader().expect("pile reader");
    #[cfg(not(feature = "legacy-repository"))]
    let snapshot = pile.snapshot().expect("pile snapshot");

    // Resolve branches by metadata::name. With `branch`, exact match;
    // else auto-pick the single branch not named "manifest".
    let mut named: Vec<(Id, String, TribleSet)> = Vec::new();
    #[cfg(feature = "legacy-repository")]
    let legacy_heads: Vec<(Id, Inline<Handle<SimpleArchive>>)> = pile
        .pins()
        .expect("list branches")
        .collect::<Result<Vec<_>, _>>()
        .expect("list branches")
        .into_iter()
        .filter_map(|id| pile.head(id).ok().flatten().map(|head| (id, head)))
        .collect();
    #[cfg(not(feature = "legacy-repository"))]
    let legacy_heads: Vec<(Id, Inline<Handle<SimpleArchive>>)> = pins
        .iter_ordered()
        .map(|raw| {
            let id = Id::new(*raw).expect("legacy pin snapshot contains a nil id");
            let head = *pins.get(raw).expect("iterated legacy pin has a head");
            (id, head)
        })
        .collect();
    for (id, meta_handle) in legacy_heads {
        let Ok(meta): Result<TribleSet, _> = snapshot.get(meta_handle) else {
            continue;
        };
        let handles: Vec<Inline<Handle<UTF8String>>> = find!(
            (n: Inline<Handle<UTF8String>>),
            pattern!(&meta, [{ metadata::name: ?n }])
        )
        .map(|(n,)| n)
        .collect();
        let [h] = handles[..] else { continue };
        let Ok(name): Result<anybytes::View<str>, _> = snapshot.get(h) else {
            continue;
        };
        named.push((id, name.as_ref().to_owned(), meta));
    }
    let (_branch_id, branch_name, branch_meta) = match branch {
        Some(want) => named
            .into_iter()
            .find(|(_, n, _)| n == want)
            .unwrap_or_else(|| panic!("no branch named {want:?} in pile")),
        None => {
            let mut data: Vec<_> = named
                .into_iter()
                .filter(|(_, n, _)| n != "manifest")
                .collect();
            match data.len() {
                1 => data.remove(0),
                n => panic!(
                    "cannot auto-pick a data branch ({n} non-manifest branches: {:?}) — pass --branch",
                    data.iter().map(|(_, n, _)| n.clone()).collect::<Vec<_>>()
                ),
            }
        }
    };

    let heads: Vec<CommitHandle> = find!(
        (c: Inline<Handle<SimpleArchive>>),
        pattern!(&branch_meta, [{ repo::head: ?c }])
    )
    .map(|(c,)| c)
    .collect();
    let [head] = heads[..] else {
        panic!("branch {branch_name:?} has no unique head commit")
    };
    let chain = commit_chain(&snapshot, head);

    // Rung -> k: one walk, per-commit tribles = SimpleArchive blob
    // length / 64.
    let mut handles: Vec<CommitHandle> = Vec::new();
    let mut cum: Vec<usize> = Vec::new();
    let mut total = 0usize;
    for (handle, meta) in &chain {
        let contents: Vec<CommitHandle> = find!(
            (c: Inline<Handle<SimpleArchive>>),
            pattern!(meta, [{ repo::content: ?c }])
        )
        .map(|(c,)| c)
        .collect();
        let [content] = contents[..] else { continue }; // skip empty commits
        let blob: Blob<SimpleArchive> = snapshot.get(content).expect("read content blob");
        total += blob.bytes.len() / 64;
        handles.push(*handle);
        cum.push(total);
    }
    assert!(
        !handles.is_empty(),
        "branch {branch_name:?} has no content commits"
    );
    let (k, carve) = if rung < cum[0] {
        (1, Some(rung))
    } else {
        match cum.iter().position(|&c| c >= rung) {
            Some(idx) => (idx + 1, None),
            None => {
                println!(
                    "note     : rung {rung} exceeds pile total ~{total} tribles; using the full chain"
                );
                (handles.len(), None)
            }
        }
    };
    println!(
        "rung     : target {rung} -> k={k}/{} commits (~{} cumulative tribles{}) on branch {branch_name:?}",
        handles.len(),
        cum[k - 1],
        carve.map(|n| format!(", carving a {n}-trible sorted prefix")).unwrap_or_default()
    );

    // Immutable prefix materialization, one span per warmed iteration. The
    // old-subject adapter retains Workspace::checkout solely for historical
    // compilation; current subjects never author or advance a pin here.
    #[cfg(feature = "legacy-repository")]
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .expect("create repository view");
    #[cfg(feature = "legacy-repository")]
    let mut ws = repo.pull(_branch_id).expect("pull branch");
    let mut spans: Vec<(u64, u64)> = Vec::new();
    let mut out: Option<TribleSet> = None;
    // (checked-out size, carved size, carved content digest). The
    // carved size ALONE is a vacuous gate: carving to a fixed `n`
    // makes it exactly `n` no matter what came out of the checkout, so
    // a checkout that returned a different set would slide the cut
    // point and silently change the workload while the gate reported
    // identity. All three gate cross-iteration identity; the caller durably
    // publishes the carved size and content digest before announcing them, so
    // the measured workload remains comparable across runs.
    let mut ident: Option<(usize, usize, u64)> = None;
    let mut gate: Option<String> = None;
    for i in 0..(warmup + iters) {
        let recording = i >= warmup;
        let begin_ns = base.elapsed().as_nanos() as u64;
        let t = Instant::now();
        #[cfg(feature = "legacy-repository")]
        let mut set = ws.checkout(&handles[..k]).expect("checkout").into_facts();
        #[cfg(not(feature = "legacy-repository"))]
        let mut set = {
            let mut set = TribleSet::new();
            for handle in &handles[..k] {
                let meta: TribleSet = snapshot.get(*handle).expect("read legacy commit metadata");
                let contents: Vec<CommitHandle> = find!(
                    (c: Inline<Handle<SimpleArchive>>),
                    pattern!(&meta, [{ repo::content: ?c }])
                )
                .map(|(c,)| c)
                .collect();
                let [content] = contents[..] else { continue };
                let content: TribleSet = snapshot.get(content).expect("read legacy commit content");
                set += content;
            }
            set
        };
        let checked_out = set.len();
        if let Some(n) = carve {
            let mut prefix = TribleSet::new();
            for t in set.iter().take(n) {
                prefix.insert(t);
            }
            set = prefix;
        }
        if recording {
            spans.push((begin_ns, t.elapsed().as_nanos() as u64));
        }
        let seen = (checked_out, set.len(), set_digest(&set));
        match ident {
            None => ident = Some(seen),
            Some(expected) if expected != seen => {
                gate = Some(format!(
                    "checkout-identity: iter {i} saw {seen:?}, expected {expected:?}"
                ));
            }
            _ => {}
        }
        out = Some(set);
    }
    #[cfg(feature = "legacy-repository")]
    drop(ws);
    #[cfg(feature = "legacy-repository")]
    repo.close().expect("close pile");
    #[cfg(not(feature = "legacy-repository"))]
    pile.close().expect("close pile");
    if let Some(g) = gate {
        return Err(g);
    }
    let (_, carved, digest) = ident.unwrap_or((0, 0, 0));
    Ok((out.expect("at least one iteration"), spans, carved, digest))
}

// ---------------------------------------------------------------------------
// Harkonnen R2 white-box fixtures (F6..F15).
//
// R1 (F1..F5) probed the engine as a black box: adversarial *shapes*
// whose cost profile exposed whatever the solver did. R2 is the
// complement — each fixture isolates exactly ONE engine decision changed
// in this week's Term-native / propose-confirm work, with a deterministic
// construction and an EXACT expected row count derived from the
// construction (never a magic number). A regression then gets a name.
//
// Every builder is deterministic: fixed anchors, `Ids`' splitmix walk,
// no RNG. Sizes are deliberately modest — the whole suite must stay
// inside seconds on a machine that is already busy — and each fixture's
// doc records what its size buys.
// ---------------------------------------------------------------------------

mod r2_schema {
    use subject::core::prelude::*;

    attributes! {
        // F6 — the eight `or!` arm attributes (k = F6_ARMS).
        "84AAEA2CDB0F31C9926D5BA55DCB646B" unsafe as u0: inlineencodings::GenId;
        "A784BFAFA148EFF689FA757C2A95EA2C" unsafe as u1: inlineencodings::GenId;
        "2AAB1B3A425B16D9680BF525CB0A9496" unsafe as u2: inlineencodings::GenId;
        "1A6306A5E7A469266D3F6BC3B4F0F830" unsafe as u3: inlineencodings::GenId;
        "5478E2F71D3C8FA4FCFD72D653C2F050" unsafe as u4: inlineencodings::GenId;
        "595533D46DA73D4D9EDAE23C69DA8B28" unsafe as u5: inlineencodings::GenId;
        "BBB163B3E6F55B2040940AD229F012D7" unsafe as u6: inlineencodings::GenId;
        "B358920E7B50BC2334BDBA2B9EE95D44" unsafe as u7: inlineencodings::GenId;
        // F7 — hub skew: in-edge (source -> node) and out-edge (node -> target).
        "0E64D47BDE5A9CCE0F41C6384BC7935F" unsafe as hs: inlineencodings::GenId;
        "D88DE6AC745F82E035551D9D2625F976" unsafe as ht: inlineencodings::GenId;
        // F8 — witness multiplicity: the two hidden-variable fans.
        "52A53A202DFC13F7074E0A697ABAB30C" unsafe as wa: inlineencodings::GenId;
        "236FC28BA8AA72FDE8E5723B403A0BD2" unsafe as wb: inlineencodings::GenId;
        // F9 — mask density: proposer side and confirmer side.
        "8DC793B45ADE8B81ADE789E8313BF974" unsafe as ma: inlineencodings::GenId;
        "B0E12EFD7CF941497603F09DEDF89760" unsafe as mb: inlineencodings::GenId;
        // F10 — GPU confirm-batch threshold: proposer side and confirmer side.
        "3573F33EBA6E94CBAFFD27FFBAA4A0F8" unsafe as ga: inlineencodings::GenId;
        "3E9767FEE8A1EE68C58F0419817D5140" unsafe as gb: inlineencodings::GenId;
        // F11 — lying estimates: the small source and the large source.
        "7503DE9B6CA70780D9096223E4DD1A08" unsafe as la: inlineencodings::GenId;
        "EE3CC3EBE8F1E540DBC396C985E282F2" unsafe as lb: inlineencodings::GenId;
        // F12 — deep chain: the single functional hop edge.
        "7A7F3D3A4EBFB4FC617D063261FB592C" unsafe as hop: inlineencodings::GenId;
        // F13 — constant pressure: five string-valued slots per entity.
        "FCE112E22C1592CC487EF5320D9E25D7" as c0: inlineencodings::Handle<blobencodings::UTF8String>;
        "B57751A976F6908E53938CF80A615DCC" as c1: inlineencodings::Handle<blobencodings::UTF8String>;
        "8C72F6255184F8FA9BDBD15574F540A8" as c2: inlineencodings::Handle<blobencodings::UTF8String>;
        "ED5816955F19EFA0C6BBA2C2F7BA77ED" as c3: inlineencodings::Handle<blobencodings::UTF8String>;
        "61C46CDF6E77A00A3B566C5157F57EFB" as c4: inlineencodings::Handle<blobencodings::UTF8String>;
        // F14 — widening ramp: the wide root and the selective confirmer.
        "6389E8FE7CA25BE81A2BAFEF79C8EDBC" unsafe as w1: inlineencodings::GenId;
        "ED3F65982ED22D4008A510A19D4798A8" unsafe as w2: inlineencodings::GenId;
        // F15 — union dedup pressure: the two overlapping arms.
        "32697C0766C902A3A6BEA17656631E5F" unsafe as ua: inlineencodings::GenId;
        "CBF362B65F450B457B32C05C5198868F" unsafe as ub: inlineencodings::GenId;
    }
}

/// Locality prefix of every R2 *anchor* — a well-known id a builder and
/// its query both name without plumbing a value through a return type.
/// Distinct from `Ids`' bulk prefix (`0xD46B0001`) so anchors can never
/// collide with generated filler.
const ANCHOR_TAG: u32 = 0xD46B_0002;

/// The anchor registry (`n` -> role). Keeping every anchor in ONE
/// numbering makes accidental reuse across fixtures impossible to write
/// by mistake:
///
/// | `n`      | role |
/// |----------|------|
/// | 0..=7    | F6 arm hub value (the literal each arm matches) |
/// | 8..=15   | F6 arm decoy value (same attribute, wrong literal) |
/// | 16, 17   | F9 proposer root, confirmer probe |
/// | 18, 19   | F10 below-threshold root, probe |
/// | 20, 21   | F10 above-threshold root, probe |
/// | 22, 23   | F11 small source root, large source root |
/// | 24, 25   | F14 wide root, selective probe |
/// | 26       | F15 shared hub value |
/// | 100..    | F13 constant-pressure entities (`100 + i`) |
fn anchor(n: u64) -> ExclusiveId {
    let mut raw = [0u8; 16];
    raw[..4].copy_from_slice(&ANCHOR_TAG.to_be_bytes());
    raw[4..12].copy_from_slice(&Ids::splitmix64(n).to_be_bytes());
    raw[12..].copy_from_slice(&Ids::splitmix64(n ^ 0xA5A5_5A5A).to_be_bytes()[..4]);
    ExclusiveId::force(Id::new(raw).expect("nonzero prefix"))
}

// ---------------------------------------------------------------------------
// F6 — union fan.
//
// INTERROGATES: the `or!` aligned-arms path, and dead-variant gating.
//
// Before the Term-native fold every attribute constant and literal value
// became a fresh hidden variable, so two structurally identical
// `pattern!` invocations never declared the same variable set and
// `UnionConstraint::new` panicked — the documented `or!(pattern!(..),
// pattern!(..))` form was dead code. The fold makes constants Terms
// below the variable layer, so all k arms here declare exactly `{e}`
// even though each carries a DIFFERENT attribute constant AND a
// DIFFERENT literal value. This is the synthetic twin of sparqloscope
// q3.
//
// Dead-variant gating: with `?e` the only variable, every arm's
// `satisfied()` is exact the moment `?e` binds (entity, attribute and
// value all pinned), so k-1 arms are *provably* dead at confirm time.
// The decoy entities below make the literal load-bearing: they carry the
// right attribute with the wrong value and must contribute no rows.
// ---------------------------------------------------------------------------

/// F6: number of `or!` arms — one per minted arm attribute.
pub const F6_ARMS: usize = 8;
/// F6: matching entities per arm.
pub const F6_PER_ARM: usize = 256;
/// F6: decoy entities per arm (right attribute, wrong literal).
pub const F6_DECOYS_PER_ARM: usize = 32;

/// F6 expected rows. Each of the `F6_ARMS * F6_PER_ARM` matching
/// entities carries exactly one arm edge, so it satisfies exactly one
/// arm and yields exactly one binding of the single query variable
/// `?e`; the `F6_ARMS * F6_DECOYS_PER_ARM` decoys satisfy no arm.
/// 8 * 256 = 2048.
pub const F6_EXPECTED_ROWS: usize = F6_ARMS * F6_PER_ARM;

/// The literal value arm `j` matches.
fn f6_hub(j: usize) -> ExclusiveId {
    anchor(j as u64)
}

/// The literal value arm `j`'s decoys carry instead.
fn f6_decoy(j: usize) -> ExclusiveId {
    anchor(8 + j as u64)
}

/// One arm-`j` edge. The attribute must be a literal constant at each
/// call site (that is the whole point of the fixture), so the arm index
/// is dispatched rather than indexed.
fn f6_edge(j: usize, e: &ExclusiveId, v: &ExclusiveId) -> Fragment {
    match j {
        0 => entity! { e @ r2_schema::u0: v },
        1 => entity! { e @ r2_schema::u1: v },
        2 => entity! { e @ r2_schema::u2: v },
        3 => entity! { e @ r2_schema::u3: v },
        4 => entity! { e @ r2_schema::u4: v },
        5 => entity! { e @ r2_schema::u5: v },
        6 => entity! { e @ r2_schema::u6: v },
        7 => entity! { e @ r2_schema::u7: v },
        _ => unreachable!("F6 has exactly {F6_ARMS} arms"),
    }
}

/// F6 builder: per arm, `F6_PER_ARM` entities pointing at that arm's hub
/// value and `F6_DECOYS_PER_ARM` entities pointing at its decoy value.
pub fn build_union_fan() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    for j in 0..F6_ARMS {
        let hub = f6_hub(j);
        let decoy = f6_decoy(j);
        for _ in 0..F6_PER_ARM {
            let e = ids.mint();
            set += f6_edge(j, &e, &hub);
        }
        for _ in 0..F6_DECOYS_PER_ARM {
            let e = ids.mint();
            set += f6_edge(j, &e, &decoy);
        }
    }
    set
}

/// F6 full drain: total row count (expected [`F6_EXPECTED_ROWS`]).
pub fn f6_total(set: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>),
        or!(
            pattern!(set, [{ ?e @ r2_schema::u0: &f6_hub(0) }]),
            pattern!(set, [{ ?e @ r2_schema::u1: &f6_hub(1) }]),
            pattern!(set, [{ ?e @ r2_schema::u2: &f6_hub(2) }]),
            pattern!(set, [{ ?e @ r2_schema::u3: &f6_hub(3) }]),
            pattern!(set, [{ ?e @ r2_schema::u4: &f6_hub(4) }]),
            pattern!(set, [{ ?e @ r2_schema::u5: &f6_hub(5) }]),
            pattern!(set, [{ ?e @ r2_schema::u6: &f6_hub(6) }]),
            pattern!(set, [{ ?e @ r2_schema::u7: &f6_hub(7) }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F7 — hub skew.
//
// INTERROGATES: cardinality-estimate robustness and dynamic variable
// ordering under an extreme degree distribution.
//
// `IntersectionConstraint` picks its proposer by minimum estimate and
// re-sorts the unbound variables whenever a binding invalidates an
// estimate (`push_next_variable`). A single node with a 20 000x degree
// makes the *average* estimate a lie: any plan chosen from global
// cardinality alone is wrong for one of the two populations. The row
// count is invariant under every legal plan, so it gates correctness
// while the spans record what the skew cost.
// ---------------------------------------------------------------------------

/// F7: uniform nodes (in-degree 1, out-degree 1).
pub const F7_UNIFORM: usize = 1_000;
/// F7: out-degree of the single hub node (in-degree 1).
pub const F7_HUB_FANOUT: usize = 20_000;

/// F7 expected rows. The join `?x -hs-> ?h -ht-> ?y` yields, per middle
/// node, in-degree x out-degree rows: the hub contributes
/// `1 * F7_HUB_FANOUT`, each uniform node `1 * 1`.
/// 20 000 + 1 000 = 21 000.
pub const F7_EXPECTED_ROWS: usize = F7_HUB_FANOUT + F7_UNIFORM;

/// F7 builder: one hub with `F7_HUB_FANOUT` out-edges plus `F7_UNIFORM`
/// degree-1 nodes; every middle node has exactly one in-edge, so the
/// skew lives entirely in the out-degree.
pub fn build_hub_skew() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();

    let hub = ids.mint();
    let hub_src = ids.mint();
    set += entity! { &hub_src @ r2_schema::hs: &hub };
    for _ in 0..F7_HUB_FANOUT {
        let y = ids.mint();
        set += entity! { &hub @ r2_schema::ht: &y };
    }

    for _ in 0..F7_UNIFORM {
        let h = ids.mint();
        let x = ids.mint();
        let y = ids.mint();
        set += entity! { &x @ r2_schema::hs: &h };
        set += entity! { &h @ r2_schema::ht: &y };
    }
    set
}

/// F7 full drain: total row count (expected [`F7_EXPECTED_ROWS`]).
pub fn f7_total(set: &TribleSet) -> usize {
    find!(
        (x: Inline<GenId>, h: Inline<GenId>, y: Inline<GenId>),
        and!(
            pattern!(set, [{ ?x @ r2_schema::hs: ?h }]),
            pattern!(set, [{ ?h @ r2_schema::ht: ?y }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F8 — witness multiplicity.
//
// INTERROGATES: the bag-semantics contract.
//
// The engine is a bag of COMPLETE bindings: `Query::next` emits a row
// every time the unbound set empties, with no projection dedup, so
// hidden (`temp!`) variables multiply the visible head. Dedup belongs to
// the consumer. This fixture pins both halves of that contract at once
// with the two-query idiom — the same constraint drained as a bag and
// collected into a set — and is the fixture that fails loudly if head
// dedup is ever reintroduced inside the engine (the bag measure would
// collapse onto the distinct one).
// ---------------------------------------------------------------------------

/// F8: entities carrying both fans.
pub const F8_ENTITIES: usize = 256;
/// F8: `wa` out-degree per entity (hidden witness `?m`).
pub const F8_WA_DEG: usize = 8;
/// F8: `wb` out-degree per entity (hidden witness `?n`).
pub const F8_WB_DEG: usize = 8;

/// F8 expected BAG rows: per entity every `(?m, ?n)` pair is a distinct
/// complete binding, so `F8_WA_DEG * F8_WB_DEG` = 64 rows per entity.
/// 256 * 8 * 8 = 16 384 — exactly 64x the projected-distinct count.
pub const F8_EXPECTED_BAG_ROWS: usize = F8_ENTITIES * F8_WA_DEG * F8_WB_DEG;

/// F8 expected DISTINCT rows: the head is `?e` alone and every entity
/// has both fans, so the client-side set has one member per entity.
/// 256.
pub const F8_EXPECTED_DISTINCT_ROWS: usize = F8_ENTITIES;

/// F8 builder: `F8_ENTITIES` entities, each with `F8_WA_DEG` `wa` edges
/// and `F8_WB_DEG` `wb` edges to fresh targets.
pub fn build_witness_multiplicity() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    for _ in 0..F8_ENTITIES {
        let e = ids.mint();
        for _ in 0..F8_WA_DEG {
            let m = ids.mint();
            set += entity! { &e @ r2_schema::wa: &m };
        }
        for _ in 0..F8_WB_DEG {
            let n = ids.mint();
            set += entity! { &e @ r2_schema::wb: &n };
        }
    }
    set
}

/// F8 bag drain: one row per complete `(e, m, n)` binding, projected to
/// `?e` (expected [`F8_EXPECTED_BAG_ROWS`]).
pub fn f8_bag(set: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>),
        temp!(
            (m, n),
            and!(
                pattern!(set, [{ ?e @ r2_schema::wa: ?m }]),
                pattern!(set, [{ ?e @ r2_schema::wb: ?n }]),
            )
        )
    )
    .count()
}

/// F8 client-side distinct: the SAME constraint, deduplicated by the
/// consumer (expected [`F8_EXPECTED_DISTINCT_ROWS`]).
pub fn f8_distinct(set: &TribleSet) -> usize {
    let seen: std::collections::HashSet<[u8; 32]> = find!(
        (e: Inline<GenId>),
        temp!(
            (m, n),
            and!(
                pattern!(set, [{ ?e @ r2_schema::wa: ?m }]),
                pattern!(set, [{ ?e @ r2_schema::wb: ?n }]),
            )
        )
    )
    .map(|(e,)| e.raw)
    .collect();
    seen.len()
}

// ---------------------------------------------------------------------------
// F9 — mask density extremes.
//
// INTERROGATES: the engine-owned liveness design (`ProposalBuffer` +
// `Candidates`), generalizing the F5 lesson.
//
// Confirmers kill entries in place and nothing is ever compacted, so the
// engine scans over dead entries. That is a deliberate trade: no
// compaction cost, no index invalidation, one word per entry writable
// without contention. Its two worst cases are the two variants here — a
// mask that kills nearly everything (a long scan over corpses to reach
// each survivor) and a mask that kills nothing (pure overhead on the
// liveness words).
//
// Both variants are built so the two sides carry IDENTICAL cardinality
// (`F9_REGION` entries each). That matters: `IntersectionConstraint`
// always lets the *lowest*-estimate child propose, so a merely-small
// confirmer would simply become the proposer and the mask would never
// run. Equal estimates force a genuine mask over a full-size region and
// make selectivity a property of the data, not of the plan.
// ---------------------------------------------------------------------------

/// F9: candidates on each side of both variants.
pub const F9_REGION: usize = 20_000;
/// F9 sparse: every `F9_SPARSE_STRIDE`-th candidate survives.
pub const F9_SPARSE_STRIDE: usize = 1_000;

/// F9 sparse expected rows: the confirmer shares exactly the candidates
/// at CONSTRUCTION indices `0, F9_SPARSE_STRIDE, 2*F9_SPARSE_STRIDE,
/// ...` — `Ids::mint`'s splitmix suffix scatters those through the
/// proposal's value order, so the survivors are spread across the region
/// rather than clustered, which is what makes this a density test and
/// not a prefix test. 20 000 / 1 000 = 20 survivors (a 99.9% kill
/// rate).
pub const F9_SPARSE_EXPECTED_ROWS: usize = F9_REGION / F9_SPARSE_STRIDE;

/// F9 dense expected rows: both sides carry the same `F9_REGION` values,
/// so the mask kills nothing. 20 000.
pub const F9_DENSE_EXPECTED_ROWS: usize = F9_REGION;

/// F9 proposer root (the `ma` side).
fn f9_root() -> ExclusiveId {
    anchor(16)
}

/// F9 confirmer probe (the `mb` side).
fn f9_probe() -> ExclusiveId {
    anchor(17)
}

/// F9 sparse builder: both sides hold `F9_REGION` values but only every
/// `F9_SPARSE_STRIDE`-th one coincides.
pub fn build_mask_sparse() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let root = f9_root();
    let probe = f9_probe();
    for i in 0..F9_REGION {
        let v = ids.mint();
        set += entity! { &root @ r2_schema::ma: &v };
        if i % F9_SPARSE_STRIDE == 0 {
            set += entity! { &probe @ r2_schema::mb: &v };
        } else {
            let miss = ids.mint();
            set += entity! { &probe @ r2_schema::mb: &miss };
        }
    }
    set
}

/// F9 dense builder: both sides hold exactly the same `F9_REGION`
/// values, so no candidate is ever killed.
pub fn build_mask_dense() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let root = f9_root();
    let probe = f9_probe();
    for _ in 0..F9_REGION {
        let v = ids.mint();
        set += entity! { &root @ r2_schema::ma: &v };
        set += entity! { &probe @ r2_schema::mb: &v };
    }
    set
}

/// F9 full drain (either variant): total row count.
pub fn f9_total(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f9_root() @ r2_schema::ma: ?v }]),
            pattern!(set, [{ &f9_probe() @ r2_schema::mb: ?v }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F10 — GPU confirm-batch threshold boundary.
//
// INTERROGATES: routing hysteresis around `DEFAULT_MIN_CONFIRM_BATCH`,
// and threshold rot.
//
// `triblespace-gpu` routes a confirm region to the device only when it
// holds at least `DEFAULT_MIN_CONFIRM_BATCH` live candidates; smaller
// regions run the canonical CPU probes. The threshold is a MEASURED
// crossover (an M4 Max sweep recorded in its doc comment), which means
// it is exactly the kind of constant that silently rots. This fixture
// straddles it: two runs whose only difference is one candidate on
// either side of the boundary. The constant is READ from the engine
// (never copied here), so moving it moves the fixture.
//
// Gate on ROWS only — the answer must be the region size on both sides,
// which is the property routing may never change. Timings across the
// boundary are the interesting signal but are not a gate.
//
// !!! SIZING CAVEAT. The confirm region `IntersectionConstraint` hands
// its siblings is the whole level, so a level of `F10_BELOW` /
// `F10_ABOVE` candidates straddles the threshold exactly. This holds on
// both protocol eras but for different reasons: before
// engine/batched-frontier because a proposer shipped the level in one
// call, and after it because the region spans the whole frontier — here
// a frontier of one, since the fixture's root level has no parent. Any
// future change that makes a level arrive in pieces (a chunk schedule, a
// width cap below the level size) would leave both sides under the
// routing boundary and the fixture would silently stop straddling
// anything: re-derive `F10_BELOW` / `F10_ABOVE` from whatever bounds the
// region then, not from the level size.
// ---------------------------------------------------------------------------

/// F10: the routing threshold, read from the engine so this fixture
/// cannot drift away from it.
#[cfg(feature = "gpu")]
pub const F10_THRESHOLD: usize = subject::gpu::DEFAULT_MIN_CONFIRM_BATCH;

/// F10: candidates just BELOW the routing threshold (CPU probes).
#[cfg(feature = "gpu")]
pub const F10_BELOW: usize = F10_THRESHOLD - 1;

/// F10: candidates just ABOVE the routing threshold (device confirm).
#[cfg(feature = "gpu")]
pub const F10_ABOVE: usize = F10_THRESHOLD + 1;

/// F10 root of the region of size `n`.
#[cfg(feature = "gpu")]
fn f10_root(above: bool) -> ExclusiveId {
    anchor(if above { 20 } else { 18 })
}

/// F10 probe of the region of size `n`.
#[cfg(feature = "gpu")]
fn f10_probe(above: bool) -> ExclusiveId {
    anchor(if above { 21 } else { 19 })
}

/// F10 builder: a fully-live region of exactly `n` candidates —
/// proposer and confirmer carry the same `n` values, so every candidate
/// survives and the region handed to `confirm` is `n` entries wide.
#[cfg(feature = "gpu")]
pub fn build_gpu_boundary(above: bool, n: usize) -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let root = f10_root(above);
    let probe = f10_probe(above);
    for _ in 0..n {
        let v = ids.mint();
        set += entity! { &root @ r2_schema::ga: &v };
        set += entity! { &probe @ r2_schema::gb: &v };
    }
    set
}

/// F10 full drain: total row count, expected to equal the region size
/// (`F10_BELOW` / `F10_ABOVE`) on both sides of the boundary.
#[cfg(feature = "gpu")]
pub fn f10_total(above: bool, set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f10_root(above) @ r2_schema::ga: ?v }]),
            pattern!(set, [{ &f10_probe(above) @ r2_schema::gb: ?v }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F11 — lying estimates.
//
// INTERROGATES: graceful degradation of dynamic variable ordering and of
// the propose/confirm role choice when `Constraint::estimate` is wrong.
//
// The trait explicitly licenses inexact estimates ("the estimate need
// not be exact — it guides variable ordering, not correctness"). This
// fixture cashes that promise: the SAME query is run three times, once
// honestly and twice through a wrapper whose `estimate` is wrong by
// `F11_LIE_FACTOR` in each direction, forwarding every other method
// verbatim. Both lies flip which side proposes and which side confirms.
// All three must produce the same rows; only the spans may differ.
// ---------------------------------------------------------------------------

/// Test-only [`Constraint`] wrapper that scales the wrapped estimate by
/// `mul / div` and forwards every other method unchanged. This is the
/// only place in the suite that implements `Constraint` by hand; it
/// exists so a fixture can hand the planner a known-wrong number.
#[cfg(feature = "protocol-v2")]
pub struct LyingEstimate<C> {
    inner: C,
    mul: usize,
    div: usize,
}

#[cfg(feature = "protocol-v2")]
impl<C> LyingEstimate<C> {
    /// Report `factor`x MORE candidates than the wrapped constraint has.
    pub fn over(inner: C, factor: usize) -> Self {
        Self {
            inner,
            mul: factor,
            div: 1,
        }
    }

    /// Report `factor`x FEWER candidates than the wrapped constraint has.
    pub fn under(inner: C, factor: usize) -> Self {
        Self {
            inner,
            mul: 1,
            div: factor,
        }
    }
}

#[cfg(feature = "protocol-v2")]
impl<'a, C: Constraint<'a>> Constraint<'a> for LyingEstimate<C> {
    fn variables(&self) -> VariableSet {
        self.inner.variables()
    }

    /// The lie. Clamped to at least 1 so the planner's `ilog2` bucketing
    /// still sees a well-formed magnitude.
    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.inner
            .estimate(variable, binding)
            .map(|e| (e.saturating_mul(self.mul) / self.div).max(1))
    }

    #[cfg(not(feature = "frontier"))]
    fn propose(&self, variable: VariableId, binding: &Binding, proposals: &mut ProposalBuffer) {
        self.inner.propose(variable, binding, proposals)
    }

    #[cfg(not(feature = "frontier"))]
    fn propose_chunk(
        &self,
        variable: VariableId,
        binding: &Binding,
        cursor: &mut ProposeCursor,
        budget: usize,
        proposals: &mut ProposalBuffer,
    ) -> bool {
        self.inner
            .propose_chunk(variable, binding, cursor, budget, proposals)
    }

    #[cfg(not(feature = "frontier"))]
    fn confirm(&self, variable: VariableId, binding: &Binding, cands: &mut Candidates<'_>) {
        self.inner.confirm(variable, binding, cands)
    }

    /// Batched protocol: the wrapper only ever lies about estimates, so
    /// both methods forward the frontier verbatim.
    #[cfg(feature = "frontier")]
    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        self.inner.propose(variable, frontier, proposals)
    }

    #[cfg(feature = "frontier")]
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        self.inner.confirm(variable, frontier, cands)
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        self.inner.satisfied(binding)
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        self.inner.influence(variable)
    }
}

/// F11: candidates on the small (honest proposer) side.
pub const F11_SMALL: usize = 200;
/// F11: candidates on the large side.
pub const F11_LARGE: usize = 10_000;
/// F11: how far the wrapper's estimate is off, in each direction.
#[cfg(feature = "protocol-v2")]
pub const F11_LIE_FACTOR: usize = 100;

/// F11 expected rows (identical for all three plans): the small side's
/// values are a subset of the large side's, so the intersection is the
/// small side. 200.
pub const F11_EXPECTED_ROWS: usize = F11_SMALL;

/// F11 small source root (`la`).
fn f11_small_root() -> ExclusiveId {
    anchor(22)
}

/// F11 large source root (`lb`).
fn f11_large_root() -> ExclusiveId {
    anchor(23)
}

/// F11 builder: the large side holds `F11_LARGE` values of which the
/// first `F11_SMALL` are exactly the small side's.
///
/// Honest estimates: 200 vs 10 000, so the small side proposes.
/// `over` (small x100 = 20 000 > 10 000) and `under` (large /100 = 100 <
/// 200) both hand the proposer role to the large side instead.
pub fn build_lying_estimates() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let small = f11_small_root();
    let large = f11_large_root();
    for i in 0..F11_LARGE {
        let v = ids.mint();
        set += entity! { &large @ r2_schema::lb: &v };
        if i < F11_SMALL {
            set += entity! { &small @ r2_schema::la: &v };
        }
    }
    set
}

/// F11 honest plan: the true estimates, small side proposes.
pub fn f11_truth(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f11_small_root() @ r2_schema::la: ?v }]),
            pattern!(set, [{ &f11_large_root() @ r2_schema::lb: ?v }]),
        )
    )
    .count()
}

/// F11 over-estimate plan: the small side claims `F11_LIE_FACTOR`x MORE
/// candidates than it has.
#[cfg(feature = "protocol-v2")]
pub fn f11_over(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            LyingEstimate::over(
                pattern!(set, [{ &f11_small_root() @ r2_schema::la: ?v }]),
                F11_LIE_FACTOR
            ),
            pattern!(set, [{ &f11_large_root() @ r2_schema::lb: ?v }]),
        )
    )
    .count()
}

/// F11 under-estimate plan: the large side claims `F11_LIE_FACTOR`x
/// FEWER candidates than it has.
#[cfg(feature = "protocol-v2")]
pub fn f11_under(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f11_small_root() @ r2_schema::la: ?v }]),
            LyingEstimate::under(
                pattern!(set, [{ &f11_large_root() @ r2_schema::lb: ?v }]),
                F11_LIE_FACTOR
            ),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F12 — deep chain.
//
// INTERROGATES: search-stack depth and the approach to the 128-variable
// ceiling.
//
// `Binding` is a fixed `[RawInline; 128]`, `VariableContext` asserts
// `next_index < 128`, and the search stack / unbound list are
// `ArrayVec<_, 128>`. A 60-hop chain allocates 61 variables — just under
// half the budget, deep enough that every level of the DFS stack is
// exercised and cheap enough to stay in the suite's time envelope. The
// chain is built programmatically through `TriblePattern::pattern` (not
// 60 lines of `pattern!`), which keeps the hop count a knob.
// ---------------------------------------------------------------------------

/// F12: hops in each chain (variables allocated = `F12_HOPS + 1`).
pub const F12_HOPS: usize = 60;
/// F12: complete chains of exactly `F12_HOPS` edges.
pub const F12_CHAINS: usize = 2;
/// F12: decoy chains, half the required length — they force the search
/// to unwind from deep in the stack without ever completing.
pub const F12_DECOYS: usize = 8;

/// F12 expected rows: a `hop` edge is functional (out-degree 1) and the
/// chains are disjoint, so a path of exactly `F12_HOPS` edges exists
/// once per complete chain, starting at its head; the decoy chains are
/// `F12_HOPS / 2` edges long and complete none. 2.
pub const F12_EXPECTED_ROWS: usize = F12_CHAINS;

/// F12 builder: `F12_CHAINS` disjoint chains of `F12_HOPS` edges plus
/// `F12_DECOYS` half-length chains.
pub fn build_deep_chain() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let chain = |set: &mut TribleSet, ids: &mut Ids, edges: usize| {
        let mut prev = ids.mint();
        for _ in 0..edges {
            let next = ids.mint();
            *set += entity! { &prev @ r2_schema::hop: &next };
            prev = next;
        }
    };
    for _ in 0..F12_CHAINS {
        chain(&mut set, &mut ids, F12_HOPS);
    }
    for _ in 0..F12_DECOYS {
        chain(&mut set, &mut ids, F12_HOPS / 2);
    }
    set
}

/// F12 full drain: total row count (expected [`F12_EXPECTED_ROWS`]).
///
/// The head projects the two ends of the chain; the `F12_HOPS - 1`
/// interior variables are allocated from the `find!` context inside the
/// constraint expression, exactly as `temp!` would, so the query really
/// does carry `F12_HOPS + 1` variables.
pub fn f12_total(set: &TribleSet) -> usize {
    find!(
        (head: Inline<GenId>, tail: Inline<GenId>),
        {
            let hop: Inline<GenId> = IntoInline::to_inline(r2_schema::hop.id());
            let mut constraints: Vec<Box<dyn Constraint + Send + Sync>> = Vec::new();
            let mut prev: Variable<GenId> = head;
            for i in 0..F12_HOPS {
                let next: Variable<GenId> = if i + 1 == F12_HOPS {
                    tail
                } else {
                    __local_find_context!().next_variable()
                };
                constraints.push(Box::new(set.pattern(prev, hop, next)));
                prev = next;
            }
            std::sync::Arc::new(IntersectionConstraint::new(constraints))
        }
    )
    .count()
}

// ---------------------------------------------------------------------------
// F13 — constant pressure.
//
// INTERROGATES: the Term-native payoff, directly.
//
// Under the old desugar every attribute constant and literal value took
// a fresh hidden variable plus a `ConstantConstraint`. The pattern below
// carries `F13_CONSTANTS` = 161 constants, so it would have blown the
// 128-variable budget at CONSTRUCTION time — `VariableContext::
// next_variable` panics past 128 — long before the query could run.
// Folded as constant `Term`s they cost ZERO variables and the pattern is
// a pure existence check.
//
// The gate is the variable count itself: `harkonnen/F13/vars` records
// `VariableContext::next_index` after expanding the pattern in a
// hand-rolled context (the same technique the engine's
// `many_literals_do_not_consume_the_variable_budget` test uses), so the
// number lands in the results pile as a first-class observation rather
// than as an assertion nobody can see.
// ---------------------------------------------------------------------------

/// F13: entities named by constant id in the pattern.
pub const F13_ENTITIES: usize = 26;
/// F13: literal-valued attribute slots per entity.
pub const F13_ATTRS: usize = 5;

/// F13: total constants in the pattern — `F13_ENTITIES` constant entity
/// ids + `F13_ATTRS` attribute constants + `F13_ENTITIES * F13_ATTRS`
/// literal values. 26 + 5 + 130 = 161, i.e. 33 more than the whole
/// variable budget.
pub const F13_CONSTANTS: usize = F13_ENTITIES + F13_ATTRS + F13_ENTITIES * F13_ATTRS;

/// The constants outnumber the whole variable budget — the property
/// that makes F13's zero-variable result meaningful instead of trivial.
/// If this ever stops holding, the fixture has been shrunk below the
/// thing it is supposed to prove.
const _: () = assert!(F13_CONSTANTS > 128);

/// F13 expected variables: constants live below the variable layer, so
/// 161 of them allocate none. 0.
pub const F13_EXPECTED_VARS: usize = 0;

/// F13 expected rows: a pattern with an empty variable set is settled by
/// one `satisfied()` check at query start, and every fact it names is
/// present, so `find!((), _)` yields its single unit row. 1.
pub const F13_EXPECTED_ROWS: usize = 1;

/// F13 entity `i`.
fn f13_entity(i: usize) -> ExclusiveId {
    anchor(100 + i as u64)
}

/// F13 builder: `F13_ENTITIES` entities, each carrying `F13_ATTRS`
/// distinct string literals (`v<i>_<k>`) the query then names verbatim.
pub fn build_constant_pressure() -> TribleSet {
    let mut set = TribleSet::new();
    for i in 0..F13_ENTITIES {
        let e = f13_entity(i);
        set += entity! { &e @
            r2_schema::c0: format!("v{i}_0").as_str(),
            r2_schema::c1: format!("v{i}_1").as_str(),
            r2_schema::c2: format!("v{i}_2").as_str(),
            r2_schema::c3: format!("v{i}_3").as_str(),
            r2_schema::c4: format!("v{i}_4").as_str(),
        };
    }
    set
}

/// F13 probe: expands the 161-constant pattern in a hand-rolled variable
/// context, then runs it. Returns `(variables allocated, rows)`.
///
/// One function so the pattern is written exactly once; the two measures
/// are thin projections of it.
fn f13_probe(set: &TribleSet) -> (usize, usize) {
    let mut ctx = VariableContext::new();
    macro_rules! __local_find_context {
        () => {
            &mut ctx
        };
    }
    let constraint = pattern!(set, [
        { &f13_entity(0) @ r2_schema::c0: "v0_0", r2_schema::c1: "v0_1", r2_schema::c2: "v0_2", r2_schema::c3: "v0_3", r2_schema::c4: "v0_4" },
        { &f13_entity(1) @ r2_schema::c0: "v1_0", r2_schema::c1: "v1_1", r2_schema::c2: "v1_2", r2_schema::c3: "v1_3", r2_schema::c4: "v1_4" },
        { &f13_entity(2) @ r2_schema::c0: "v2_0", r2_schema::c1: "v2_1", r2_schema::c2: "v2_2", r2_schema::c3: "v2_3", r2_schema::c4: "v2_4" },
        { &f13_entity(3) @ r2_schema::c0: "v3_0", r2_schema::c1: "v3_1", r2_schema::c2: "v3_2", r2_schema::c3: "v3_3", r2_schema::c4: "v3_4" },
        { &f13_entity(4) @ r2_schema::c0: "v4_0", r2_schema::c1: "v4_1", r2_schema::c2: "v4_2", r2_schema::c3: "v4_3", r2_schema::c4: "v4_4" },
        { &f13_entity(5) @ r2_schema::c0: "v5_0", r2_schema::c1: "v5_1", r2_schema::c2: "v5_2", r2_schema::c3: "v5_3", r2_schema::c4: "v5_4" },
        { &f13_entity(6) @ r2_schema::c0: "v6_0", r2_schema::c1: "v6_1", r2_schema::c2: "v6_2", r2_schema::c3: "v6_3", r2_schema::c4: "v6_4" },
        { &f13_entity(7) @ r2_schema::c0: "v7_0", r2_schema::c1: "v7_1", r2_schema::c2: "v7_2", r2_schema::c3: "v7_3", r2_schema::c4: "v7_4" },
        { &f13_entity(8) @ r2_schema::c0: "v8_0", r2_schema::c1: "v8_1", r2_schema::c2: "v8_2", r2_schema::c3: "v8_3", r2_schema::c4: "v8_4" },
        { &f13_entity(9) @ r2_schema::c0: "v9_0", r2_schema::c1: "v9_1", r2_schema::c2: "v9_2", r2_schema::c3: "v9_3", r2_schema::c4: "v9_4" },
        { &f13_entity(10) @ r2_schema::c0: "v10_0", r2_schema::c1: "v10_1", r2_schema::c2: "v10_2", r2_schema::c3: "v10_3", r2_schema::c4: "v10_4" },
        { &f13_entity(11) @ r2_schema::c0: "v11_0", r2_schema::c1: "v11_1", r2_schema::c2: "v11_2", r2_schema::c3: "v11_3", r2_schema::c4: "v11_4" },
        { &f13_entity(12) @ r2_schema::c0: "v12_0", r2_schema::c1: "v12_1", r2_schema::c2: "v12_2", r2_schema::c3: "v12_3", r2_schema::c4: "v12_4" },
        { &f13_entity(13) @ r2_schema::c0: "v13_0", r2_schema::c1: "v13_1", r2_schema::c2: "v13_2", r2_schema::c3: "v13_3", r2_schema::c4: "v13_4" },
        { &f13_entity(14) @ r2_schema::c0: "v14_0", r2_schema::c1: "v14_1", r2_schema::c2: "v14_2", r2_schema::c3: "v14_3", r2_schema::c4: "v14_4" },
        { &f13_entity(15) @ r2_schema::c0: "v15_0", r2_schema::c1: "v15_1", r2_schema::c2: "v15_2", r2_schema::c3: "v15_3", r2_schema::c4: "v15_4" },
        { &f13_entity(16) @ r2_schema::c0: "v16_0", r2_schema::c1: "v16_1", r2_schema::c2: "v16_2", r2_schema::c3: "v16_3", r2_schema::c4: "v16_4" },
        { &f13_entity(17) @ r2_schema::c0: "v17_0", r2_schema::c1: "v17_1", r2_schema::c2: "v17_2", r2_schema::c3: "v17_3", r2_schema::c4: "v17_4" },
        { &f13_entity(18) @ r2_schema::c0: "v18_0", r2_schema::c1: "v18_1", r2_schema::c2: "v18_2", r2_schema::c3: "v18_3", r2_schema::c4: "v18_4" },
        { &f13_entity(19) @ r2_schema::c0: "v19_0", r2_schema::c1: "v19_1", r2_schema::c2: "v19_2", r2_schema::c3: "v19_3", r2_schema::c4: "v19_4" },
        { &f13_entity(20) @ r2_schema::c0: "v20_0", r2_schema::c1: "v20_1", r2_schema::c2: "v20_2", r2_schema::c3: "v20_3", r2_schema::c4: "v20_4" },
        { &f13_entity(21) @ r2_schema::c0: "v21_0", r2_schema::c1: "v21_1", r2_schema::c2: "v21_2", r2_schema::c3: "v21_3", r2_schema::c4: "v21_4" },
        { &f13_entity(22) @ r2_schema::c0: "v22_0", r2_schema::c1: "v22_1", r2_schema::c2: "v22_2", r2_schema::c3: "v22_3", r2_schema::c4: "v22_4" },
        { &f13_entity(23) @ r2_schema::c0: "v23_0", r2_schema::c1: "v23_1", r2_schema::c2: "v23_2", r2_schema::c3: "v23_3", r2_schema::c4: "v23_4" },
        { &f13_entity(24) @ r2_schema::c0: "v24_0", r2_schema::c1: "v24_1", r2_schema::c2: "v24_2", r2_schema::c3: "v24_3", r2_schema::c4: "v24_4" },
        { &f13_entity(25) @ r2_schema::c0: "v25_0", r2_schema::c1: "v25_1", r2_schema::c2: "v25_2", r2_schema::c3: "v25_3", r2_schema::c4: "v25_4" },
    ]);
    let vars = ctx.next_index;
    let rows = find!((), constraint).count();
    (vars, rows)
}

/// F13 variable count: variables allocated for `F13_CONSTANTS`
/// constants (expected [`F13_EXPECTED_VARS`]).
pub fn f13_vars(set: &TribleSet) -> usize {
    f13_probe(set).0
}

/// F13 full drain: rows of the fully-constant existence check (expected
/// [`F13_EXPECTED_ROWS`]).
pub fn f13_total(set: &TribleSet) -> usize {
    f13_probe(set).1
}

// ---------------------------------------------------------------------------
// F14 — widening ramp.
//
// INTERROGATES: time-to-first-result at a very wide level.
//
// A proposer ships the whole level in one call, so TTFR at a wide level
// costs a full enumeration. The resumable-narrowing machinery that once
// promised otherwise (`propose_chunk`, `ProposeCursor`, a geometric
// widen) was deleted in engine/batched-frontier: it was dormant, and
// depth-first already yields the instant the stack bottoms out, so pure
// conjunctive queries never had the problem it solved. The fixture keeps
// its shape because the measurement is still the interesting one — the
// survivors are minted with order byte 0x00 so they sort FIRST in the
// proposer's value order, which is what any future narrowing scheme
// (galloping intersection is the standing candidate) would have to
// exploit. `ttfr` and `total` are recorded separately precisely so that
// gap becomes visible if it ever opens.
//
// As in F9, both sides carry identical cardinality so the selectivity
// cannot be laundered into the plan.
// ---------------------------------------------------------------------------

/// F14: candidates at the wide root level.
pub const F14_REGION: usize = 250_000;
/// F14: surviving candidates, all sorted to the front.
pub const F14_SURVIVORS: usize = 16;

/// F14 expected rows: the confirmer shares exactly the first
/// `F14_SURVIVORS` values with the root and nothing else, and `?v` is
/// the only variable. 16.
pub const F14_EXPECTED_ROWS: usize = F14_SURVIVORS;

/// F14 wide root (`w1`).
fn f14_root() -> ExclusiveId {
    anchor(24)
}

/// F14 selective probe (`w2`).
fn f14_probe() -> ExclusiveId {
    anchor(25)
}

/// F14 builder: `F14_REGION` root candidates of which the first
/// `F14_SURVIVORS` (order byte 0x00, so first in value order) are also
/// on the probe side; the probe carries `F14_REGION` values too, so the
/// two estimates tie.
pub fn build_widening_ramp() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let root = f14_root();
    let probe = f14_probe();
    for i in 0..F14_REGION {
        if i < F14_SURVIVORS {
            let v = ids.mint_ordered(0x00);
            set += entity! { &root @ r2_schema::w1: &v };
            set += entity! { &probe @ r2_schema::w2: &v };
        } else {
            let v = ids.mint_ordered(0x40 + (i % 0xBF) as u8);
            let miss = ids.mint_ordered(0x20);
            set += entity! { &root @ r2_schema::w1: &v };
            set += entity! { &probe @ r2_schema::w2: &miss };
        }
    }
    set
}

/// F14 arm-to-first-row: rows drained (0 or 1).
pub fn f14_ttfr(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f14_root() @ r2_schema::w1: ?v }]),
            pattern!(set, [{ &f14_probe() @ r2_schema::w2: ?v }]),
        )
    )
    .next()
    .map_or(0, |_| 1)
}

/// F14 full drain: total row count (expected [`F14_EXPECTED_ROWS`]).
pub fn f14_total(set: &TribleSet) -> usize {
    find!(
        (v: Inline<GenId>),
        and!(
            pattern!(set, [{ &f14_root() @ r2_schema::w1: ?v }]),
            pattern!(set, [{ &f14_probe() @ r2_schema::w2: ?v }]),
        )
    )
    .count()
}

// ---------------------------------------------------------------------------
// F15 — union dedup pressure.
//
// INTERROGATES: the cost of `UnionConstraint`'s sort-dedup under heavy
// arm overlap.
//
// `UnionConstraint::propose` collects every satisfied variant's
// proposals into one region, then sorts, dedups and calls
// `ProposalBuffer::rewrite_region` — legal only because a proposer may
// still rewrite the region it just appended, before indices freeze. The
// pathological input is arms that agree: the sort sees the full
// concatenation and the dedup throws most of it away. Here the arms
// overlap by exactly `F15_BOTH / (F15_BOTH + F15_ONLY)` = 90%.
// ---------------------------------------------------------------------------

/// F15: entities carrying BOTH arm attributes.
pub const F15_BOTH: usize = 18_000;
/// F15: entities carrying only one arm attribute (per arm).
pub const F15_ONLY: usize = 2_000;

/// F15 expected rows: `?e` is the only variable, so the row count is
/// `|A u B|` = `(F15_BOTH + F15_ONLY) + (F15_BOTH + F15_ONLY) -
/// F15_BOTH` = `F15_BOTH + 2 * F15_ONLY`. Each arm proposes 20 000
/// entities and 18 000 of those (90%) are proposed twice.
/// 18 000 + 4 000 = 22 000.
pub const F15_EXPECTED_ROWS: usize = F15_BOTH + 2 * F15_ONLY;

/// F15 shared hub value both arms match against.
fn f15_hub() -> ExclusiveId {
    anchor(26)
}

/// F15 builder: `F15_BOTH` entities on both arms plus `F15_ONLY` on each
/// arm alone.
pub fn build_union_dedup() -> TribleSet {
    let mut ids = Ids::new();
    let mut set = TribleSet::new();
    let hub = f15_hub();
    for _ in 0..F15_BOTH {
        let e = ids.mint();
        set += entity! { &e @ r2_schema::ua: &hub };
        set += entity! { &e @ r2_schema::ub: &hub };
    }
    for _ in 0..F15_ONLY {
        let e = ids.mint();
        set += entity! { &e @ r2_schema::ua: &hub };
    }
    for _ in 0..F15_ONLY {
        let e = ids.mint();
        set += entity! { &e @ r2_schema::ub: &hub };
    }
    set
}

/// F15 full drain: total row count (expected [`F15_EXPECTED_ROWS`]).
pub fn f15_total(set: &TribleSet) -> usize {
    find!(
        (e: Inline<GenId>),
        or!(
            pattern!(set, [{ ?e @ r2_schema::ua: &f15_hub() }]),
            pattern!(set, [{ ?e @ r2_schema::ub: &f15_hub() }]),
        )
    )
    .count()
}
