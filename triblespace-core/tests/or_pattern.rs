//! `or!` over `pattern!` arms — the constant-folding (Term-native) fix.
//!
//! `UnionConstraint::new` requires every variant to declare the same
//! variable set. The macro layer used to allocate a FRESH hidden variable
//! (plus a `ConstantConstraint`) for every attribute constant and literal
//! value, so two separate `pattern!` invocations — even structurally
//! identical ones — never declared equal sets and the documented
//! `or!(pattern!(..), pattern!(..))` form deterministically panicked.
//!
//! The fix folds attribute constants, literal values, and constant entity
//! ids into the pattern constraint as constant `Term`s: they behave like
//! positions the engine has already bound but never appear in the
//! variable set, so union arms compare only the query variables the
//! caller actually wrote. A side effect is that a fully-constant pattern
//! has an EMPTY variable set; the engine settles those with one exact
//! `satisfied()` check at query start (they are "fully bound" with zero
//! variables), which the `fully_constant_*` tests below pin down.
//!
//! Resurrected from 6c346e04 for the June-protocol engine (bag-of-
//! complete-bindings: one row per witness of the declared variables,
//! dedup belongs to the consumer). None of the original expected counts
//! change: with the fold there are no hidden variables to surface
//! multiplicity through, every test datum below yields distinct
//! (entity, alias) witnesses, and the set-collecting tests are
//! multiplicity-insensitive by construction.

use proptest::prelude::*;
use std::collections::HashSet;
use triblespace_core::id::rngid;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;
use triblespace_core::query::{Constraint, VariableContext, VariableSet};

/// The sorted raw content handles of some texts, as a query over a
/// `Handle<UTF8String>` attribute projects them.
fn texts(values: &[&str]) -> Vec<[u8; 32]> {
    let mut raw: Vec<[u8; 32]> = values
        .iter()
        .map(|value| {
            let handle: Inline<Handle<UTF8String>> = (*value).to_inline();
            handle.raw
        })
        .collect();
    raw.sort_unstable();
    raw
}

mod profile {
    use triblespace_core::prelude::*;
    attributes! {
        "CC00000000000000DD00000000000001" as pub nickname: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000002" as pub display_name: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000003" as pub city: inlineencodings::Handle<blobencodings::UTF8String>;
        // Budget-test attributes (see
        // many_literals_do_not_consume_the_variable_budget).
        "CC00000000000000DD00000000000010" as pub m0: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000011" as pub m1: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000012" as pub m2: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000013" as pub m3: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000DD00000000000014" as pub m4: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

/// The book's own `or!` example (query-language.md, "Alternatives"):
/// nickname vs display_name arms use DIFFERENT attributes. This is the
/// exact shape that used to trip the union's variable-set assertion.
///
/// Bag-semantics note: rows are one per (entity, alias) witness. Every
/// witness below has a distinct alias, so the projected list matches the
/// old SET-gate expectation unchanged.
#[test]
fn book_nickname_display_name_example() {
    let alice = rngid();
    let bob = rngid();
    let carol = rngid();

    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @ profile::nickname: "Ali" };
    dataset += entity! { &bob @
        profile::nickname: "Bobby",
        profile::display_name: "Robert",
    };
    dataset += entity! { &carol @ profile::city: "Caladan" };

    let mut aliases: Vec<[u8; 32]> = find!(
        (alias: Inline<_>),
        temp!(
            (entity),
            or!(
                pattern!(&dataset, [{ ?entity @ profile::nickname: ?alias }]),
                pattern!(&dataset, [{ ?entity @ profile::display_name: ?alias }])
            )
        )
    )
    .map(|(alias,)| alias.raw)
    .collect();
    aliases.sort_unstable();

    // Bob has both attributes and yields two rows; Carol has neither
    // and yields none.
    assert_eq!(aliases, texts(&["Ali", "Bobby", "Robert"]));
}

/// Arms with the same attribute but different literal values.
#[test]
fn or_arms_with_different_literals() {
    let alice = rngid();
    let bob = rngid();
    let carol = rngid();

    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @ profile::nickname: "Ali" };
    dataset += entity! { &bob @ profile::nickname: "Bobby" };
    dataset += entity! { &carol @ profile::nickname: "Caro" };

    let people: HashSet<[u8; 32]> = find!(
        (person: Inline<GenId>),
        or!(
            pattern!(&dataset, [{ ?person @ profile::nickname: "Ali" }]),
            pattern!(&dataset, [{ ?person @ profile::nickname: "Bobby" }])
        )
    )
    .map(|(person,)| person.raw)
    .collect();

    let alice_val: Inline<GenId> = (&alice).to_inline();
    let bob_val: Inline<GenId> = (&bob).to_inline();
    let expected: HashSet<[u8; 32]> = [alice_val.raw, bob_val.raw].into_iter().collect();
    assert_eq!(people, expected);
}

/// Arms over different datasets (each `pattern!` invocation is separate,
/// so this also used to panic even with identical attributes).
#[test]
fn or_arms_over_different_sets() {
    let alice = rngid();
    let bob = rngid();

    let mut set_a = TribleSet::new();
    set_a += entity! { &alice @ profile::nickname: "Ali" };
    let mut set_b = TribleSet::new();
    set_b += entity! { &bob @ profile::nickname: "Bobby" };

    let mut names: Vec<[u8; 32]> = find!(
        (person: Inline<GenId>, name: Inline<_>),
        or!(
            pattern!(&set_a, [{ ?person @ profile::nickname: ?name }]),
            pattern!(&set_b, [{ ?person @ profile::nickname: ?name }])
        )
    )
    .map(|(_, name)| name.raw)
    .collect();
    names.sort_unstable();

    assert_eq!(names, texts(&["Ali", "Bobby"]));
}

/// Mixed leaf/composite arms: a single pattern vs an `and!` of two
/// patterns. Both arms mention exactly `{person}`.
#[test]
fn or_arms_mixed_leaf_and_composite() {
    let ali_only = rngid();
    let full_profile = rngid();
    let display_only = rngid();

    let mut dataset = TribleSet::new();
    dataset += entity! { &ali_only @ profile::nickname: "Ali" };
    dataset += entity! { &full_profile @
        profile::nickname: "Bobby",
        profile::display_name: "Robert",
    };
    dataset += entity! { &display_only @ profile::display_name: "Carola" };

    let query = |flipped: bool| -> HashSet<[u8; 32]> {
        let leaf_first = find!(
            (person: Inline<GenId>),
            or!(
                pattern!(&dataset, [{ ?person @ profile::nickname: "Ali" }]),
                and!(
                    pattern!(&dataset, [{ ?person @ profile::nickname: "Bobby" }]),
                    pattern!(&dataset, [{ ?person @ profile::display_name: "Robert" }])
                )
            )
        );
        let composite_first = find!(
            (person: Inline<GenId>),
            or!(
                and!(
                    pattern!(&dataset, [{ ?person @ profile::nickname: "Bobby" }]),
                    pattern!(&dataset, [{ ?person @ profile::display_name: "Robert" }])
                ),
                pattern!(&dataset, [{ ?person @ profile::nickname: "Ali" }])
            )
        );
        if flipped {
            composite_first.map(|(p,)| p.raw).collect()
        } else {
            leaf_first.map(|(p,)| p.raw).collect()
        }
    };

    let ali_val: Inline<GenId> = (&ali_only).to_inline();
    let full_val: Inline<GenId> = (&full_profile).to_inline();
    let expected: HashSet<[u8; 32]> = [ali_val.raw, full_val.raw].into_iter().collect();

    assert_eq!(query(false), expected, "or!(leaf, composite)");
    assert_eq!(
        query(true),
        expected,
        "or!(composite, leaf) — arm order must not matter"
    );
}

/// The lowering emits NO variables for attribute constants, literal
/// values, or constant entity ids: after expanding a pattern that uses
/// all three kinds of constants alongside one query variable, the
/// context has allocated exactly that one variable and the constraint's
/// visible set contains nothing else.
#[test]
fn pattern_constants_allocate_no_helper_variables() {
    let alice = rngid();
    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @
        profile::nickname: "Ali",
        profile::city: "Caladan",
    };

    let mut ctx = VariableContext::new();
    macro_rules! __local_find_context {
        () => {
            &mut ctx
        };
    }
    let name = ctx.next_variable::<Handle<UTF8String>>();
    let constraint = pattern!(&dataset, [{ &alice @
        profile::nickname: ?name,
        profile::city: "Caladan",
    }]);

    assert_eq!(
        constraint.variables(),
        VariableSet::new_singleton(name.index),
        "constants must not appear in the constraint's variable set"
    );
    assert_eq!(
        ctx.next_index, 1,
        "no hidden variables may be allocated for constants \
         (entity id, attribute constants, literal value)"
    );
}

/// Constants stay below the variable layer at RUNTIME too: a query whose
/// pattern mixes a constant entity id, attribute constants, and a literal
/// value with one real variable binds exactly that variable — constants
/// never enter the [`Binding`](triblespace_core::query::Binding).
#[test]
fn constants_never_enter_binding() {
    use triblespace_core::query::{Binding, Query};

    let alice = rngid();
    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @
        profile::nickname: "Ali",
        profile::city: "Caladan",
    };

    let mut ctx = VariableContext::new();
    macro_rules! __local_find_context {
        () => {
            &mut ctx
        };
    }
    let name = ctx.next_variable::<Handle<UTF8String>>();
    let constraint = pattern!(&dataset, [{ &alice @
        profile::nickname: ?name,
        profile::city: "Caladan",
    }]);

    let bound_sets: Vec<VariableSet> =
        Query::new(constraint, |binding: &Binding| Some(binding.bound)).collect();

    assert_eq!(bound_sets.len(), 1, "exactly one witness row expected");
    assert_eq!(
        bound_sets[0],
        VariableSet::new_singleton(name.index),
        "the result binding must contain the real variable and nothing else"
    );
}

/// Literals no longer consume the 128-variable budget. This pattern
/// carries 161 constants (26 entity ids + 5 attribute constants + 130
/// distinct literal values) — under the old hidden-variable desugar it
/// would have needed 161 helper variables and panicked the 128-variable
/// budget before the query could even be constructed. Folded as constant
/// terms it allocates ZERO variables and is a pure existence check.
#[test]
fn many_literals_do_not_consume_the_variable_budget() {
    let ids: Vec<_> = (0..26).map(|_| rngid()).collect();
    let mut dataset = TribleSet::new();
    for (i, id) in ids.iter().enumerate() {
        dataset += entity! { id @
            profile::m0: format!("v{}_0", i).as_str(),
            profile::m1: format!("v{}_1", i).as_str(),
            profile::m2: format!("v{}_2", i).as_str(),
            profile::m3: format!("v{}_3", i).as_str(),
            profile::m4: format!("v{}_4", i).as_str(),
        };
    }

    let mut ctx = VariableContext::new();
    macro_rules! __local_find_context {
        () => {
            &mut ctx
        };
    }
    let constraint = pattern!(&dataset, [
        { &ids[0] @ profile::m0: "v0_0", profile::m1: "v0_1", profile::m2: "v0_2", profile::m3: "v0_3", profile::m4: "v0_4" },
        { &ids[1] @ profile::m0: "v1_0", profile::m1: "v1_1", profile::m2: "v1_2", profile::m3: "v1_3", profile::m4: "v1_4" },
        { &ids[2] @ profile::m0: "v2_0", profile::m1: "v2_1", profile::m2: "v2_2", profile::m3: "v2_3", profile::m4: "v2_4" },
        { &ids[3] @ profile::m0: "v3_0", profile::m1: "v3_1", profile::m2: "v3_2", profile::m3: "v3_3", profile::m4: "v3_4" },
        { &ids[4] @ profile::m0: "v4_0", profile::m1: "v4_1", profile::m2: "v4_2", profile::m3: "v4_3", profile::m4: "v4_4" },
        { &ids[5] @ profile::m0: "v5_0", profile::m1: "v5_1", profile::m2: "v5_2", profile::m3: "v5_3", profile::m4: "v5_4" },
        { &ids[6] @ profile::m0: "v6_0", profile::m1: "v6_1", profile::m2: "v6_2", profile::m3: "v6_3", profile::m4: "v6_4" },
        { &ids[7] @ profile::m0: "v7_0", profile::m1: "v7_1", profile::m2: "v7_2", profile::m3: "v7_3", profile::m4: "v7_4" },
        { &ids[8] @ profile::m0: "v8_0", profile::m1: "v8_1", profile::m2: "v8_2", profile::m3: "v8_3", profile::m4: "v8_4" },
        { &ids[9] @ profile::m0: "v9_0", profile::m1: "v9_1", profile::m2: "v9_2", profile::m3: "v9_3", profile::m4: "v9_4" },
        { &ids[10] @ profile::m0: "v10_0", profile::m1: "v10_1", profile::m2: "v10_2", profile::m3: "v10_3", profile::m4: "v10_4" },
        { &ids[11] @ profile::m0: "v11_0", profile::m1: "v11_1", profile::m2: "v11_2", profile::m3: "v11_3", profile::m4: "v11_4" },
        { &ids[12] @ profile::m0: "v12_0", profile::m1: "v12_1", profile::m2: "v12_2", profile::m3: "v12_3", profile::m4: "v12_4" },
        { &ids[13] @ profile::m0: "v13_0", profile::m1: "v13_1", profile::m2: "v13_2", profile::m3: "v13_3", profile::m4: "v13_4" },
        { &ids[14] @ profile::m0: "v14_0", profile::m1: "v14_1", profile::m2: "v14_2", profile::m3: "v14_3", profile::m4: "v14_4" },
        { &ids[15] @ profile::m0: "v15_0", profile::m1: "v15_1", profile::m2: "v15_2", profile::m3: "v15_3", profile::m4: "v15_4" },
        { &ids[16] @ profile::m0: "v16_0", profile::m1: "v16_1", profile::m2: "v16_2", profile::m3: "v16_3", profile::m4: "v16_4" },
        { &ids[17] @ profile::m0: "v17_0", profile::m1: "v17_1", profile::m2: "v17_2", profile::m3: "v17_3", profile::m4: "v17_4" },
        { &ids[18] @ profile::m0: "v18_0", profile::m1: "v18_1", profile::m2: "v18_2", profile::m3: "v18_3", profile::m4: "v18_4" },
        { &ids[19] @ profile::m0: "v19_0", profile::m1: "v19_1", profile::m2: "v19_2", profile::m3: "v19_3", profile::m4: "v19_4" },
        { &ids[20] @ profile::m0: "v20_0", profile::m1: "v20_1", profile::m2: "v20_2", profile::m3: "v20_3", profile::m4: "v20_4" },
        { &ids[21] @ profile::m0: "v21_0", profile::m1: "v21_1", profile::m2: "v21_2", profile::m3: "v21_3", profile::m4: "v21_4" },
        { &ids[22] @ profile::m0: "v22_0", profile::m1: "v22_1", profile::m2: "v22_2", profile::m3: "v22_3", profile::m4: "v22_4" },
        { &ids[23] @ profile::m0: "v23_0", profile::m1: "v23_1", profile::m2: "v23_2", profile::m3: "v23_3", profile::m4: "v23_4" },
        { &ids[24] @ profile::m0: "v24_0", profile::m1: "v24_1", profile::m2: "v24_2", profile::m3: "v24_3", profile::m4: "v24_4" },
        { &ids[25] @ profile::m0: "v25_0", profile::m1: "v25_1", profile::m2: "v25_2", profile::m3: "v25_3", profile::m4: "v25_4" },
    ]);

    assert_eq!(
        ctx.next_index, 0,
        "161 constants must allocate zero query variables"
    );
    assert_eq!(
        constraint.variables(),
        VariableSet::new_empty(),
        "a fully-constant pattern has an empty variable set"
    );
    assert!(
        exists!(constraint),
        "the fully-constant pattern must verify as an existence check"
    );
}

/// A fully-constant pattern has an empty variable set; its truth is
/// settled by the engine's satisfied() check at query start.
#[test]
fn fully_constant_pattern_is_an_existence_check() {
    let alice = rngid();
    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @ profile::nickname: "Ali" };

    assert!(exists!(
        pattern!(&dataset, [{ &alice @ profile::nickname: "Ali" }])
    ));
    assert!(!exists!(
        pattern!(&dataset, [{ &alice @ profile::nickname: "Bobby" }])
    ));
    assert!(!exists!(
        pattern!(&dataset, [{ &alice @ profile::display_name: "Ali" }])
    ));
}

/// A dead fully-constant pattern inside `and!` kills the whole
/// conjunction even though the search never proposes for it.
#[test]
fn fully_constant_pattern_composes_with_and() {
    let alice = rngid();
    let bob = rngid();
    let mut dataset = TribleSet::new();
    dataset += entity! { &alice @ profile::nickname: "Ali" };
    dataset += entity! { &bob @ profile::nickname: "Bobby" };

    let live: Vec<_> = find!(
        (person: Inline<GenId>),
        and!(
            pattern!(&dataset, [{ ?person @ profile::nickname: "Bobby" }]),
            pattern!(&dataset, [{ &alice @ profile::nickname: "Ali" }])
        )
    )
    .collect();
    assert_eq!(live.len(), 1, "a satisfied constant pattern is a tautology");

    let dead: Vec<_> = find!(
        (person: Inline<GenId>),
        and!(
            pattern!(&dataset, [{ ?person @ profile::nickname: "Bobby" }]),
            pattern!(&dataset, [{ &alice @ profile::nickname: "NotAli" }])
        )
    )
    .collect();
    assert!(
        dead.is_empty(),
        "a failed constant pattern must empty the conjunction"
    );
}

/// Genuinely different query variables across arms still panic — the
/// union's variable-set requirement is about visible variables, and
/// that contract stays.
#[test]
#[should_panic(expected = "must mention the same query variables")]
fn or_panics_when_arms_mention_different_variables() {
    let dataset = TribleSet::new();

    let _ = find!(
        (alias: Inline<_>),
        temp!(
            (x, y),
            or!(
                pattern!(&dataset, [{ ?x @ profile::nickname: ?alias }]),
                pattern!(&dataset, [{ ?y @ profile::display_name: ?alias }])
            )
        )
    )
    .count();
}

proptest! {
    /// Oracle check: `or!` over two attributes equals the set-union of
    /// the two single-attribute queries, on random data, in both arm
    /// orders (mirrors the style of union_soundness.rs). Collected into
    /// HashSets on both sides, so the check is insensitive to the bag
    /// engine's row multiplicity by construction.
    #[test]
    fn or_equals_union_oracle(
        assignments in proptest::collection::vec(
            (0usize..6, prop_oneof![Just(0u8), Just(1u8)], 0usize..4),
            0..24,
        )
    ) {
        let entities: Vec<_> = (0..6).map(|_| rngid()).collect();
        let values = ["v0", "v1", "v2", "v3"];

        let mut dataset = TribleSet::new();
        for (e, which, v) in &assignments {
            let entity = &entities[*e];
            dataset += match which {
                0 => entity! { entity @ profile::nickname: values[*v] },
                _ => entity! { entity @ profile::display_name: values[*v] },
            };
        }

        let nick_rows: HashSet<([u8; 32], [u8; 32])> = find!(
            (person: Inline<GenId>, alias: Inline<_>),
            pattern!(&dataset, [{ ?person @ profile::nickname: ?alias }])
        )
        .map(|(p, a)| (p.raw, a.raw))
        .collect();
        let disp_rows: HashSet<([u8; 32], [u8; 32])> = find!(
            (person: Inline<GenId>, alias: Inline<_>),
            pattern!(&dataset, [{ ?person @ profile::display_name: ?alias }])
        )
        .map(|(p, a)| (p.raw, a.raw))
        .collect();
        let oracle: HashSet<_> = nick_rows.union(&disp_rows).copied().collect();

        let forward: HashSet<([u8; 32], [u8; 32])> = find!(
            (person: Inline<GenId>, alias: Inline<_>),
            or!(
                pattern!(&dataset, [{ ?person @ profile::nickname: ?alias }]),
                pattern!(&dataset, [{ ?person @ profile::display_name: ?alias }])
            )
        )
        .map(|(p, a)| (p.raw, a.raw))
        .collect();
        let backward: HashSet<([u8; 32], [u8; 32])> = find!(
            (person: Inline<GenId>, alias: Inline<_>),
            or!(
                pattern!(&dataset, [{ ?person @ profile::display_name: ?alias }]),
                pattern!(&dataset, [{ ?person @ profile::nickname: ?alias }])
            )
        )
        .map(|(p, a)| (p.raw, a.raw))
        .collect();

        prop_assert_eq!(&forward, &oracle, "or! must equal the set-union oracle");
        prop_assert_eq!(&backward, &oracle, "or! must be arm-order independent");
    }
}
