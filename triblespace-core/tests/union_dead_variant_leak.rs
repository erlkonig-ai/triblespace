//! Regression: `UnionConstraint` must skip variants that are dead for a row.
//!
//! `UnionConstraint::propose`/`confirm` ask each variant whether it is
//! [`satisfied`](triblespace_core::query::Constraint::satisfied) for every
//! frontier row and drop the contribution of the rows where it is not. The
//! obvious reading of the Term-native lowering — a constant lives below the
//! variable layer, so a non-matching arm simply looks nothing up — says that
//! check is dead machinery. It is not.
//!
//! The gap is a *multi-clause* arm. `pattern!` lowers to an
//! `IntersectionConstraint` with one `TribleSetConstraint` per triple, and
//! `IntersectionConstraint::propose` only consults the children that return
//! `Some` from `estimate` for the variable being proposed. So in an arm like
//! `{ ?p @ nickname: "Ali", city: ?out }` the `nickname` clause is completely
//! absent from the `?out` pass: it neither proposes nor confirms. When `?p` is
//! already bound to an entity whose nickname is *not* `"Ali"`, that arm is
//! logically dead, yet its `city` clause happily proposes the entity's city —
//! and, since a union ORs the per-variant survivors, the arm then confirms its
//! own proposal and the row escapes.
//!
//! The arm's own `satisfied` *does* see it: `TribleSetConstraint::satisfied`
//! evaluates `(e, a, v)` as soon as all three positions have a value, and
//! constant Terms count as values — so the fully-pinned `nickname: "Ali"`
//! clause returns `false` the moment `?p` is bound to the wrong entity, and
//! `IntersectionConstraint::satisfied` conjoins that to kill the arm. The
//! union's liveness gate is the only thing that acts on it.
//!
//! Nothing here is exotic: two arms that gate on one attribute and read a
//! different one is the ordinary shape of "if it's an A give me its city,
//! if it's a B give me its display name".

use std::collections::HashSet;
use triblespace_core::id::rngid;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;

/// A text value as stored: the raw content handle of its blob.
fn text(value: &str) -> [u8; 32] {
    let handle: Inline<Handle<UTF8String>> = value.to_inline();
    handle.raw
}

mod profile {
    use triblespace_core::prelude::*;
    attributes! {
        "F1A2B3C4D5E6F708192A3B4C5D6E7F01" as pub nickname: inlineencodings::Handle<blobencodings::UTF8String>;
        "F1A2B3C4D5E6F708192A3B4C5D6E7F02" as pub display_name: inlineencodings::Handle<blobencodings::UTF8String>;
        "F1A2B3C4D5E6F708192A3B4C5D6E7F03" as pub city: inlineencodings::Handle<blobencodings::UTF8String>;
        "F1A2B3C4D5E6F708192A3B4C5D6E7F04" as pub alias: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

/// The world both tests query.
struct World {
    /// The set the `or!` arms read.
    dataset: TribleSet,
    /// A separate catalogue used only by the confirm-path test: it offers
    /// bob both `"Robert"` (arm B accepts it) and `"Arrakis"` (only the
    /// dead arm A would).
    catalog: TribleSet,
    alice: Inline<GenId>,
    bob: Inline<GenId>,
}

/// * `alice` — nickname `"Ali"`, city `"Caladan"` → matches arm A only.
/// * `bob` — nickname `"Bob"`, display name `"Robert"`, city `"Arrakis"`
///   → matches arm B only. `"Arrakis"` is the bait: it is reachable *only*
///   through arm A's `city` clause, and arm A is dead for `bob`.
///
/// The filler entities carry a city and nothing else. They are never
/// bindable (neither arm's nickname gate proposes them) but they inflate
/// arm A's `?out` estimate so the engine reliably binds `?p` first — which
/// is the order that exercises the liveness gate. Both tests are
/// deterministic: `rngid` only randomises entity ids, and every estimate
/// the planner reads here is a count.
fn world() -> World {
    let alice = rngid();
    let bob = rngid();

    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @
        profile::nickname: "Ali",
        profile::city: "Caladan",
    };
    dataset += entity! { &bob @
        profile::nickname: "Bob",
        profile::display_name: "Robert",
        profile::city: "Arrakis",
    };

    let mut catalog = TribleSet::new();
    catalog += entity! { &alice @ profile::alias: "Caladan" };
    catalog += entity! { &bob @ profile::alias: "Robert" };
    catalog += entity! { &bob @ profile::alias: "Arrakis" };

    for i in 0..8 {
        let filler = rngid();
        let city = format!("Filler{i}");
        dataset += entity! { &filler @ profile::city: city.as_str() };
        // Mirrored into the catalogue so that `?out` is the *expensive*
        // variable globally (11 aliases vs 2 gate-matching entities) and
        // the engine binds `?p` first — the order under which a dead arm
        // can be asked to vote. Per bound `?p` the catalogue is the cheap
        // side again, so it proposes and the union only confirms.
        catalog += entity! { &filler @ profile::alias: city.as_str() };
    }

    World {
        dataset,
        catalog,
        alice: (&alice).to_inline(),
        bob: (&bob).to_inline(),
    }
}

fn rows(dataset: &TribleSet) -> HashSet<([u8; 32], [u8; 32])> {
    find!(
        (p: Inline<GenId>, out: Inline<_>),
        or!(
            // Arm A: gate on nickname "Ali", read the city.
            pattern!(dataset, [{ ?p @ profile::nickname: "Ali", profile::city: ?out }]),
            // Arm B: gate on nickname "Bob", read the display name.
            pattern!(dataset, [{ ?p @ profile::nickname: "Bob", profile::display_name: ?out }])
        )
    )
    .map(|(p, out)| (p.raw, out.raw))
    .collect()
}

/// An arm whose gate clause fails for the row must contribute nothing —
/// not even through a sibling clause that does not mention the gate.
#[test]
fn dead_union_variant_must_not_propose_through_a_sibling_clause() {
    let World {
        dataset,
        alice: alice_val,
        bob: bob_val,
        ..
    } = world();

    let expected: HashSet<([u8; 32], [u8; 32])> = [
        (alice_val.raw, text("Caladan")),
        (bob_val.raw, text("Robert")),
    ]
    .into_iter()
    .collect();

    let got = rows(&dataset);

    // The leak, spelled out: bob's city reached through arm A, whose
    // `nickname: "Ali"` gate bob fails.
    assert!(
        !got.contains(&(bob_val.raw, text("Arrakis"))),
        "dead arm leaked (bob, \"Arrakis\"): arm A gates on nickname \"Ali\", \
         which bob does not have, but its `city` clause proposed anyway. \
         Got: {got:?}"
    );
    assert_eq!(got, expected);
}

/// The same query as an explicit oracle: `or!` must equal the set-union of
/// its arms run separately. This states the property without naming the
/// leaked row, so it also catches a leak in the other direction.
#[test]
fn or_of_gated_arms_equals_the_union_of_the_arms() {
    let dataset = world().dataset;

    let arm_a: HashSet<([u8; 32], [u8; 32])> = find!(
        (p: Inline<GenId>, out: Inline<_>),
        pattern!(&dataset, [{ ?p @ profile::nickname: "Ali", profile::city: ?out }])
    )
    .map(|(p, out)| (p.raw, out.raw))
    .collect();
    let arm_b: HashSet<([u8; 32], [u8; 32])> = find!(
        (p: Inline<GenId>, out: Inline<_>),
        pattern!(&dataset, [{ ?p @ profile::nickname: "Bob", profile::display_name: ?out }])
    )
    .map(|(p, out)| (p.raw, out.raw))
    .collect();

    let oracle: HashSet<_> = arm_a.union(&arm_b).cloned().collect();
    assert_eq!(
        rows(&dataset),
        oracle,
        "or! must equal the set-union oracle"
    );
}

/// The same leak reached through `UnionConstraint::confirm` instead of
/// `propose`: a cheaper sibling of the enclosing `and!` owns the proposal
/// for `?out`, so the union only gets to vote. A dead arm that is allowed
/// to vote confirms the candidate its own clause matches, and because the
/// union ORs per-variant survivors, one dead arm's vote is enough to keep
/// a row alive that no live arm accepts.
#[test]
fn dead_union_variant_must_not_vote_in_confirm() {
    let World {
        dataset,
        catalog,
        alice: alice_val,
        bob: bob_val,
    } = world();

    let got: HashSet<([u8; 32], [u8; 32])> = find!(
        (p: Inline<GenId>, out: Inline<_>),
        and!(
            pattern!(&catalog, [{ ?p @ profile::alias: ?out }]),
            or!(
                pattern!(&dataset, [{ ?p @ profile::nickname: "Ali", profile::city: ?out }]),
                pattern!(&dataset, [{ ?p @ profile::nickname: "Bob", profile::display_name: ?out }])
            )
        )
    )
    .map(|(p, out)| (p.raw, out.raw))
    .collect();

    let expected: HashSet<([u8; 32], [u8; 32])> = [
        (alice_val.raw, text("Caladan")),
        (bob_val.raw, text("Robert")),
    ]
    .into_iter()
    .collect();

    assert!(
        !got.contains(&(bob_val.raw, text("Arrakis"))),
        "dead arm voted in confirm and kept (bob, \"Arrakis\") alive. Got: {got:?}"
    );
    assert_eq!(got, expected);
}
