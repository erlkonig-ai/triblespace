//! The calls a result could answer, as positive rules: candidate
//! enumeration, and a reading proposed beside it.
//!
//! The Codex importer selects the latest call with its id in file order,
//! then refuses the unit when that call no longer stands on her line (X4).
//! This file does not reproduce that policy. Its rules derive the candidate
//! set: every node on the result's line before it holding a call with the
//! id the result names.
//!
//! A proposed uniqueness reading would answer exactly one candidate, name
//! multiple candidates ambiguous, and refuse when there are none. The
//! existing importer cannot be implemented from this candidate set alone:
//! its globally latest call can be off-line even when an older on-line
//! candidate exists, as counterexample 2 shows.
//!
//! Neither policy is implemented in the rules. The two cases where they
//! differ are hand-stated below as counterexamples.
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
        "3AC519524F9B79513439BEC75FDBC877" as pub reaches: GenId;
        "1B00573EE08881E8468429019D6F204C" as pub candidate: GenId;
        "D6B7E3147C78D3442526A18BB7D23FB6" as pub call_id: GenId;
        "143EF1707337DD44501A7A71D400C13E" as pub answers: GenId;
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

/// The candidates (rules W0, W1, C).
fn candidates(program: &mut TribleSet) -> Vec<Id> {
    let (n, g, k, p, x, f) = (Var("n"), Var("g"), Var("k"), Var("p"), Var("x"), Var("f"));
    vec![
        // W0: a result reaches the node before it.
        rule(
            program,
            &[
                (n, v::holds.id(), g),
                (g, v::answers.id(), k),
                (n, v::previous.id(), p),
            ],
            &[],
            &[(n, v::reaches.id(), p)],
        ),
        // W1: and everything before a node it reaches.
        rule(
            program,
            &[(n, v::reaches.id(), x), (x, v::previous.id(), p)],
            &[],
            &[(n, v::reaches.id(), p)],
        ),
        // C: a node it reaches that holds a call with the id it answers is
        // a candidate.
        rule(
            program,
            &[
                (n, v::holds.id(), g),
                (g, v::answers.id(), k),
                (n, v::reaches.id(), x),
                (x, v::holds.id(), f),
                (f, v::call_id.id(), k),
            ],
            &[],
            &[(n, v::candidate.id(), x)],
        ),
    ]
}

/// Place the node holding `fact` after `previous`.
fn place(facts: &mut TribleSet, previous: Id, fact: Id) -> Id {
    let (at, rows) = build_intrinsic_entity(vec![
        IntrinsicEntityRow::new(v::previous.id(), raw(previous).raw),
        IntrinsicEntityRow::new(v::holds.id(), raw(fact).raw),
    ]);
    *facts += rows;
    at
}

/// A call fact with id `k`.
fn call(facts: &mut TribleSet, k: Id) -> Id {
    let f = id();
    put(facts, f, v::call_id.id(), k);
    f
}

/// A result fact answering id `k`.
fn result(facts: &mut TribleSet, k: Id) -> Id {
    let g = id();
    put(facts, g, v::answers.id(), k);
    g
}

fn run(facts: &TribleSet) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = candidates(&mut program);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the candidate rules did not quiesce");
}

fn candidates_of(facts: &TribleSet, node: Id) -> BTreeSet<Id> {
    find!(c: Id, pattern!(facts, [{ node @ v::candidate: ?c }])).collect()
}

/// One call with the id, on the line: one candidate, which every reading
/// takes. A call with another id is no candidate.
#[test]
fn a_result_s_candidate_is_the_call_with_its_id_on_its_line() {
    let (k, other) = (id(), id());
    let mut facts = TribleSet::new();
    let root = id();
    let fc = call(&mut facts, k);
    let fo = call(&mut facts, other);
    let c = place(&mut facts, root, fc);
    let o = place(&mut facts, c, fo);
    let fr = result(&mut facts, k);
    let r = place(&mut facts, o, fr);
    let facts = run(&facts);
    assert_eq!(candidates_of(&facts, r), BTreeSet::from([c]));
}

/// Counterexample 1: two calls with one id on one line. Both are
/// candidates. Latest would answer the later one (c2); uniqueness names the
/// result ambiguous; neither is a fact these rules derive.
#[test]
fn two_calls_with_one_id_on_the_line_are_both_candidates() {
    let k = id();
    let mut facts = TribleSet::new();
    let root = id();
    let f1 = call(&mut facts, k);
    let f2 = call(&mut facts, k);
    let c1 = place(&mut facts, root, f1);
    let c2 = place(&mut facts, c1, f2);
    let fr = result(&mut facts, k);
    let r = place(&mut facts, c2, fr);
    let facts = run(&facts);
    assert_eq!(candidates_of(&facts, r), BTreeSet::from([c1, c2]));
}

/// Counterexample 2: the latest call with the id stands on another line (a
/// branch, as a rollback leaves one: the rolled-back turn's nodes stay,
/// off the line the file goes on with). The importer opens calls in file
/// order, so its latest is the branch's c2, which is not on the result's
/// line, and it refuses the unit. Here the candidate is c1, the one on the
/// line; uniqueness would answer it.
#[test]
fn a_call_off_the_result_s_line_is_no_candidate() {
    let k = id();
    let mut facts = TribleSet::new();
    let root = id();
    let f1 = call(&mut facts, k);
    let c1 = place(&mut facts, root, f1);
    let f2 = call(&mut facts, k);
    let _c2 = place(&mut facts, c1, f2);
    let after = id();
    let a = place(&mut facts, c1, after);
    let fr = result(&mut facts, k);
    let r = place(&mut facts, a, fr);
    let facts = run(&facts);
    assert_eq!(candidates_of(&facts, r), BTreeSet::from([c1]));
}

/// No call with the id on the line: no candidate. The importer and
/// uniqueness both refuse (the call is outside her window).
#[test]
fn a_result_with_no_call_on_its_line_has_no_candidate() {
    let k = id();
    let mut facts = TribleSet::new();
    let root = id();
    let fc = call(&mut facts, k);
    let _off = place(&mut facts, root, fc);
    let other = id();
    let o = place(&mut facts, root, other);
    let fr = result(&mut facts, k);
    let r = place(&mut facts, o, fr);
    let facts = run(&facts);
    assert!(candidates_of(&facts, r).is_empty());
}
