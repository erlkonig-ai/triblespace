//! A line re-presented under a new opening, as positive rules.
//!
//! When a header changes, the archive importer places every node of the
//! line again after the new opening: each copy holds what its original
//! holds, after the copy of the original's previous node, and a copy of a
//! node a record held recalls that node. Here a re-presentation is an
//! event `e` naming the old opening's last node, the new one, and the
//! line's tail. The rules walk up from the tail to find the line, then down
//! from the old opening, building a correspondence `old -> new` per event.
//!
//! - Only nodes on the event's line are copied, never a branch that shares
//!   its prefix: the walk down needs `e covers x`.
//! - A correspondence names its event, so two events' mappings of one old
//!   node never pair with each other's children.
//! - "The node its record held" needs no negation: a held node is its own
//!   original, a copy inherits its original's original, and every copy
//!   recalls that original. An unheld gap has none, so its copy recalls
//!   nothing.
//!
//! Every expected relationship is written out by hand.

use std::collections::BTreeSet;

use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema, Environment, Progress};
use triblespace_core::trible::{build_intrinsic_entity, IntrinsicEntityRow, Trible, TribleSet};

/// The vocabulary. `previous` and `holds` are the node's, shared with
/// `reactive_rollback.rs`; the rest was minted with `trible genid` on
/// 2026-11-05.
mod v {
    use super::*;
    attributes! {
        "029B1B04B30C87E31B8083351B8457DB" as pub previous: GenId;
        "0738945C1F8BEC5D81385FD12545EFC3" as pub holds: GenId;
        "34BB0041C1CF362E7553D1B3F46545D9" as pub from_root: GenId;
        "9408C920B83F240640A0D1A21FE2EFC3" as pub to_root: GenId;
        "56F52968FE808D94F026B264DDE0F2B1" as pub tip: GenId;
        "19FFCB46D4F88D598BDF33761EB93E7C" as pub covers: GenId;
        "9443B3FA5281F34FE826D84687DFF0DB" as pub map_in: GenId;
        "A5904BA090CF7F9229A04005C153985A" as pub old: GenId;
        "1EA71968CCC492313F362C9293345702" as pub new: GenId;
        "AC88A98460C2B63BCA9A794D600744DD" as pub original: GenId;
        "9FEEBE269C685B5BF2766027FB6A27A0" as pub recalls: GenId;
        "33CD622FF57177DFF90020E98F025516" as pub held_by: GenId;
    }
}

fn id() -> Id {
    *rngid()
}

fn raw(id: Id) -> Inline<GenId> {
    id.to_inline()
}

fn put(facts: &mut TribleSet, e: Id, a: Id, v: Id) {
    facts.insert(&Trible::force(&e, &a, &raw(v)));
}

/// A rule term: a rule-local variable by name, or a constant entity.
#[derive(Clone, Copy)]
enum T {
    Var(&'static str),
    #[allow(dead_code)]
    Lit(Id),
}
use T::Var;

type Clause = (T, Id, T);

/// One rule revision as facts: `operation`, and its `matches`, `core` and
/// `emits` clauses over fresh rule-local terms.
fn rule(program: &mut TribleSet, matches: &[Clause], core: &[Clause], emits: &[Clause]) -> Id {
    let revision = id();
    put(program, revision, schema::operation.id(), schema::POSITIVE);
    let mut terms: Vec<(&'static str, Id)> = Vec::new();
    let mut term = |program: &mut TribleSet, t: T| -> Id {
        match t {
            Var(name) => {
                if let Some((_, at)) = terms.iter().find(|(n, _)| *n == name) {
                    return *at;
                }
                let at = id();
                terms.push((name, at));
                at
            }
            T::Lit(value) => {
                let at = id();
                let literal: Inline<UnknownInline> = Inline::new(raw(value).raw);
                program.insert(&Trible::force(&at, &schema::literal.id(), &literal));
                at
            }
        }
    };
    for (relation, clauses) in [
        (schema::matches.id(), matches),
        (schema::core.id(), core),
        (schema::emits.id(), emits),
    ] {
        for &(subject, predicate, object) in clauses {
            let clause = id();
            put(program, revision, relation, clause);
            let (s, o) = (term(program, subject), term(program, object));
            put(program, clause, schema::subject.id(), s);
            put(program, clause, schema::predicate.id(), predicate);
            put(program, clause, schema::object.id(), o);
        }
    }
    revision
}

/// The re-presentation (rules L0, L1, M0, M1, O0, RC).
fn reheader(program: &mut TribleSet) -> Vec<Id> {
    let (e, t, x, p, o, n, f, m, y, z) = (
        Var("e"),
        Var("t"),
        Var("x"),
        Var("p"),
        Var("o"),
        Var("n"),
        Var("f"),
        Var("m"),
        Var("y"),
        Var("z"),
    );
    vec![
        // L0: the event's line ends at its tip.
        rule(
            program,
            &[(e, v::tip.id(), t)],
            &[],
            &[(e, v::covers.id(), t)],
        ),
        // L1: and holds everything before a node it holds.
        rule(
            program,
            &[(e, v::covers.id(), x), (x, v::previous.id(), p)],
            &[],
            &[(e, v::covers.id(), p)],
        ),
        // M0: the old opening corresponds to the new one.
        rule(
            program,
            &[(e, v::from_root.id(), o), (e, v::to_root.id(), n)],
            &[
                (m, v::map_in.id(), e),
                (m, v::old.id(), o),
                (m, v::new.id(), n),
            ],
            &[],
        ),
        // M1: a node of the line after a node with a copy is copied after
        // that copy.
        rule(
            program,
            &[
                (Var("m0"), v::map_in.id(), e),
                (Var("m0"), v::old.id(), o),
                (Var("m0"), v::new.id(), n),
                (x, v::previous.id(), o),
                (x, v::holds.id(), f),
                (e, v::covers.id(), x),
            ],
            &[
                (y, v::previous.id(), n),
                (y, v::holds.id(), f),
                (m, v::map_in.id(), e),
                (m, v::old.id(), x),
                (m, v::new.id(), y),
            ],
            &[],
        ),
        // O0: a node a record holds is its own original.
        rule(
            program,
            &[(x, v::held_by.id(), Var("r"))],
            &[],
            &[(x, v::original.id(), x)],
        ),
        // RC: a copy has its original's original, and recalls it.
        rule(
            program,
            &[
                (m, v::old.id(), x),
                (m, v::new.id(), y),
                (x, v::original.id(), z),
            ],
            &[],
            &[(y, v::original.id(), z), (y, v::recalls.id(), z)],
        ),
    ]
}

/// The node holding `fact` after `previous`.
fn node(previous: Id, fact: Id) -> Id {
    build_intrinsic_entity(vec![
        IntrinsicEntityRow::new(v::previous.id(), raw(previous).raw),
        IntrinsicEntityRow::new(v::holds.id(), raw(fact).raw),
    ])
    .0
}

/// Place the node holding `fact` after `previous` in `facts`.
fn place(facts: &mut TribleSet, previous: Id, fact: Id) -> Id {
    let (at, rows) = build_intrinsic_entity(vec![
        IntrinsicEntityRow::new(v::previous.id(), raw(previous).raw),
        IntrinsicEntityRow::new(v::holds.id(), raw(fact).raw),
    ]);
    *facts += rows;
    at
}

fn event(facts: &mut TribleSet, from: Id, to: Id, tip: Id) {
    let e = id();
    put(facts, e, v::from_root.id(), from);
    put(facts, e, v::to_root.id(), to);
    put(facts, e, v::tip.id(), tip);
}

fn run(facts: &TribleSet) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = reheader(&mut program);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the re-presentation did not quiesce");
}

fn nodes(facts: &TribleSet) -> BTreeSet<Id> {
    find!(n: Id, pattern!(facts, [{ ?n @ v::holds: _?f }])).collect()
}

fn recalled(facts: &TribleSet) -> BTreeSet<(Id, Id)> {
    find!(
        (copy: Id, of: Id),
        pattern!(facts, [{ ?copy @ v::recalls: ?of }])
    )
    .collect()
}

/// Two lines share a prefix (A, an unheld gap G, a) and branch: one goes on
/// with B, b, the other with X. Re-presenting the first under R1 copies its
/// own nodes only; re-presenting the second under R2 copies its own; and
/// re-presenting the R1 copy under R3 makes copies of copies, which recall
/// the nodes the records held, never the copies in between.
#[test]
fn a_new_opening_re_presents_exactly_the_line_and_copies_recall_the_held_nodes() {
    let [fa, fg, fa2, fb, fb2, fx] = [id(); 6].map(|_| id());
    let (r0, r1, r2, r3) = (id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let na = place(&mut facts, r0, fa);
    let ng = place(&mut facts, na, fg);
    let na2 = place(&mut facts, ng, fa2);
    let nb = place(&mut facts, na2, fb);
    let nb2 = place(&mut facts, nb, fb2);
    let nx = place(&mut facts, na2, fx);
    for held in [na, na2, nb, nb2, nx] {
        put(&mut facts, held, v::held_by.id(), id());
    }
    event(&mut facts, r0, r1, nb2);
    event(&mut facts, r0, r2, nx);
    // The copies under R1, by hand.
    let a1 = node(r1, fa);
    let g1 = node(a1, fg);
    let a21 = node(g1, fa2);
    let b1 = node(a21, fb);
    let b21 = node(b1, fb2);
    event(&mut facts, r1, r3, b21);
    let facts = run(&facts);

    let a2 = node(r2, fa);
    let g2 = node(a2, fg);
    let a22 = node(g2, fa2);
    let x2 = node(a22, fx);
    let a3 = node(r3, fa);
    let g3 = node(a3, fg);
    let a23 = node(g3, fa2);
    let b3 = node(a23, fb);
    let b23 = node(b3, fb2);
    assert_eq!(
        nodes(&facts),
        BTreeSet::from([
            na, ng, na2, nb, nb2, nx, // the old lines
            a1, g1, a21, b1, b21, // under R1: no X
            a2, g2, a22, x2, // under R2: no B, b
            a3, g3, a23, b3, b23, // under R3, copies of copies
        ])
    );
    // The gap's copies recall nothing; copies of copies recall the held
    // node, not the copy they were made from.
    assert_eq!(
        recalled(&facts),
        BTreeSet::from([
            (a1, na),
            (a21, na2),
            (b1, nb),
            (b21, nb2),
            (a2, na),
            (a22, na2),
            (x2, nx),
            (a3, na),
            (a23, na2),
            (b3, nb),
            (b23, nb2),
        ])
    );
}

/// Two events re-presenting one line under one new opening build one set
/// of copies: identity is the core, so they converge.
#[test]
fn two_events_under_one_opening_converge_on_one_copy() {
    let [fa, fb] = [id(), id()];
    let (r0, r1) = (id(), id());
    let mut facts = TribleSet::new();
    let na = place(&mut facts, r0, fa);
    let nb = place(&mut facts, na, fb);
    event(&mut facts, r0, r1, nb);
    event(&mut facts, r0, r1, nb);
    let facts = run(&facts);
    let a1 = node(r1, fa);
    assert_eq!(nodes(&facts), BTreeSet::from([na, nb, a1, node(a1, fb)]));
}
