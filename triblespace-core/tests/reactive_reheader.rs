//! A line re-presented under a new opening, as positive rules.
//!
//! Nodes are structural: their core is only (previous node, held fact).
//! The line being re-presented is a chain of item cells, each carrying its
//! node, its own/original held node (or an explicit empty sentinel), and
//! its preceding item. That whole tuple is the cell's core. Two histories
//! can share a structural node while keeping different own nodes.
//!
//! An event names old and new opening cells and the old line's tip cell.
//! Rules walk the item chain up from that tip, then copy only those items
//! down from the opening. Event-scoped correspondences map items, never
//! structural nodes. A copied item keeps its own node, so copies of copies
//! recall the ultimate held original; gaps keep the empty sentinel.
//! Recall annotations on shared structural outputs may union, but they
//! are outputs only: later copies read the item cell, never that union.
//!
//! This is a small native-rule model of line re-presentation, not importer
//! integration or proof of production equivalence. Input cells represent
//! already-correlated line state; the empty sentinel is not a held node.
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
/// `reactive_rollback.rs`, as is the item-chain `rest`; the rest was minted
/// with `trible genid` on 2026-11-05.
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
        "E84DBA5FB453BB4964C03F7ED68C7CE3" as pub rest: GenId;
        "D85AAC30FE1A4A6C29753F60134B3934" as pub item_node: GenId;
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

/// The re-presentation (rules L0, L1, M0, M1, RC).
fn reheader(program: &mut TribleSet) -> Vec<Id> {
    let (e, t, x, p, o, n, f, m, y, z, c, d) = (
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
        Var("c"),
        Var("d"),
    );
    vec![
        // L0/L1: cover only the event's item chain, not node branches.
        rule(
            program,
            &[(e, v::tip.id(), t)],
            &[],
            &[(e, v::covers.id(), t)],
        ),
        rule(
            program,
            &[(e, v::covers.id(), x), (x, v::rest.id(), p)],
            &[],
            &[(e, v::covers.id(), p)],
        ),
        // M0: the opening cells correspond.
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
        // M1: copy the item after its copied predecessor. The structural
        // node y has no context salt; c retains the correlated line state.
        rule(
            program,
            &[
                (Var("m0"), v::map_in.id(), e),
                (Var("m0"), v::old.id(), o),
                (Var("m0"), v::new.id(), n),
                (x, v::rest.id(), o),
                (x, v::item_node.id(), d),
                (x, v::original.id(), z),
                (d, v::holds.id(), f),
                (n, v::item_node.id(), p),
                (e, v::covers.id(), x),
            ],
            &[
                (y, v::previous.id(), p),
                (y, v::holds.id(), f),
                (c, v::rest.id(), n),
                (c, v::item_node.id(), y),
                (c, v::original.id(), z),
                (m, v::map_in.id(), e),
                (m, v::old.id(), x),
                (m, v::new.id(), c),
            ],
            &[],
        ),
        // RC: output recalls from this copied item's own held original.
        // The empty sentinel has no held_by fact, so gaps recall nothing.
        rule(
            program,
            &[
                (m, v::map_in.id(), e),
                (m, v::new.id(), c),
                (c, v::item_node.id(), y),
                (c, v::original.id(), z),
                (z, v::held_by.id(), Var("r")),
            ],
            &[],
            &[(y, v::recalls.id(), z)],
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

fn event(facts: &mut TribleSet, from: Id, to: Id, tip: Id) -> Id {
    let e = id();
    put(facts, e, v::from_root.id(), from);
    put(facts, e, v::to_root.id(), to);
    put(facts, e, v::tip.id(), tip);
    e
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

/// Construct fixture input, not an interpreter: one intrinsic line item.
fn item(facts: &mut TribleSet, rest: Id, node: Id, own: Id) -> Id {
    let cell = entity! { v::rest: rest, v::item_node: node, v::original: own };
    let at = cell.root().expect("one item root");
    *facts += cell;
    at
}

/// Read a consequence through its relations, without recomputing an id.
fn mapped(facts: &TribleSet, event: Id, old: Id) -> Id {
    let found: BTreeSet<Id> = find!(
        new: Id,
        pattern!(facts, [{ _?m @ v::map_in: event, v::old: old, v::new: ?new }])
    )
    .collect();
    assert_eq!(found.len(), 1, "fixture has one mapped item");
    *found.first().unwrap()
}

/// Two lines share A, an unheld gap G, a, then branch to B,b or X.
/// Copies of copies recall ultimate originals; no unrelated branch copies.
#[test]
fn a_new_opening_re_presents_exactly_the_line_and_copies_recall_the_held_nodes() {
    let [fa, fg, fa2, fb, fb2, fx] = [id(); 6].map(|_| id());
    let (r0, r1, r2, r3, nil) = (id(), id(), id(), id(), id());
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
    let i0 = item(&mut facts, nil, r0, nil);
    let i1 = item(&mut facts, nil, r1, nil);
    let i2 = item(&mut facts, nil, r2, nil);
    let i3 = item(&mut facts, nil, r3, nil);
    let ia = item(&mut facts, i0, na, na);
    let ig = item(&mut facts, ia, ng, nil);
    let ia2 = item(&mut facts, ig, na2, na2);
    let ib = item(&mut facts, ia2, nb, nb);
    let ib2 = item(&mut facts, ib, nb2, nb2);
    let ix = item(&mut facts, ia2, nx, nx);
    let e1 = event(&mut facts, i0, i1, ib2);
    event(&mut facts, i0, i2, ix);
    let mut facts = run(&facts);
    let tip1 = mapped(&facts, e1, ib2);
    event(&mut facts, i1, i3, tip1);
    let facts = run(&facts);
    let a1 = node(r1, fa);
    let g1 = node(a1, fg);
    let a21 = node(g1, fa2);
    let b1 = node(a21, fb);
    let b21 = node(b1, fb2);
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
            na, ng, na2, nb, nb2, nx, // old lines
            a1, g1, a21, b1, b21, // under R1: no X
            a2, g2, a22, x2, // under R2: no B,b
            a3, g3, a23, b3, b23, // under R3: copies of copies
        ])
    );
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

#[test]
fn two_events_under_one_opening_converge_on_one_copy() {
    let [fa, fb] = [id(), id()];
    let (r0, r1, nil) = (id(), id(), id());
    let mut facts = TribleSet::new();
    let na = place(&mut facts, r0, fa);
    let nb = place(&mut facts, na, fb);
    let i0 = item(&mut facts, nil, r0, nil);
    let i1 = item(&mut facts, nil, r1, nil);
    let ia = item(&mut facts, i0, na, nil);
    let ib = item(&mut facts, ia, nb, nil);
    let e1 = event(&mut facts, i0, i1, ib);
    let e2 = event(&mut facts, i0, i1, ib);
    let facts = run(&facts);
    let a1 = node(r1, fa);
    assert_eq!(nodes(&facts), BTreeSet::from([na, nb, a1, node(a1, fb)]));
    assert_eq!(mapped(&facts, e1, ib), mapped(&facts, e2, ib));
}

/// Hand counterexample to node-level original propagation: z1=(R0,F)
/// and z2=(R9,F) are held in distinct lines. Both reheaders under R1
/// produce x=(R1,F), with different own originals. Only the first item's
/// reheader under R2 produces y=(R2,F): it must recall z1 alone. The old
/// O0/RC rules let x union z1,z2 and wrongly pass both to y.
#[test]
fn shared_structural_copy_keeps_the_line_items_original() {
    let (r0, r9, r1, r2, f, nil) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let z1 = place(&mut facts, r0, f);
    let z2 = place(&mut facts, r9, f);
    put(&mut facts, z1, v::held_by.id(), id());
    put(&mut facts, z2, v::held_by.id(), id());
    let i0 = item(&mut facts, nil, r0, nil);
    let i9 = item(&mut facts, nil, r9, nil);
    let i1 = item(&mut facts, nil, r1, nil);
    let i2 = item(&mut facts, nil, r2, nil);
    let iz1 = item(&mut facts, i0, z1, z1);
    let iz2 = item(&mut facts, i9, z2, z2);
    let e1 = event(&mut facts, i0, i1, iz1);
    let e2 = event(&mut facts, i9, i1, iz2);
    let mut facts = run(&facts);
    let (x1, x2) = (mapped(&facts, e1, iz1), mapped(&facts, e2, iz2));
    assert_ne!(x1, x2, "one structural node, two line items");
    event(&mut facts, i1, i2, x1);
    let facts = run(&facts);
    let (x, y) = (node(r1, f), node(r2, f));
    assert_eq!(nodes(&facts), BTreeSet::from([z1, z2, x, y]));
    assert_eq!(
        recalled(&facts),
        BTreeSet::from([(x, z1), (x, z2), (y, z1)])
    );
}

/// A gap and a held item may even share the same input and output nodes.
/// The gap's second reheader must not pick up the held item's original.
#[test]
fn a_gap_sharing_a_structural_node_stays_a_gap_when_copied_again() {
    let (r0, r1, r2, f, nil) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let z = place(&mut facts, r0, f);
    put(&mut facts, z, v::held_by.id(), id());
    let i0 = item(&mut facts, nil, r0, nil);
    let i1 = item(&mut facts, nil, r1, nil);
    let i2 = item(&mut facts, nil, r2, nil);
    let held = item(&mut facts, i0, z, z);
    let gap = item(&mut facts, i0, z, nil);
    event(&mut facts, i0, i1, held);
    let eg = event(&mut facts, i0, i1, gap);
    let mut facts = run(&facts);
    let copied_gap = mapped(&facts, eg, gap);
    event(&mut facts, i1, i2, copied_gap);
    let facts = run(&facts);
    let (x, y) = (node(r1, f), node(r2, f));
    assert_eq!(nodes(&facts), BTreeSet::from([z, x, y]));
    assert_eq!(recalled(&facts), BTreeSet::from([(x, z)]));
}
