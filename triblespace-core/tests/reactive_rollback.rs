//! A fold over a file, as positive rules: Codex's line, turns and rollback.
//!
//! The archive importer keeps the line it builds in a vector, the turns as
//! positions in it, and a rollback truncates both. Here the same fold is
//! state per record position: `before(r)` and `after(r)` carry the line's
//! tail and the turn stack, and the stack is a chain of content-addressed
//! cells, like the node chain itself. Nothing is retracted: a rolled-back
//! node stays, and is simply no one's tail. Numbers are entities with
//! observed `predecessor` edges, so the rollback's countdown is bounded by
//! data rather than computed.
//!
//! A state's identity is the whole tuple (record, tail, stack), not the
//! record alone: two states that reach one record stay two, each with its
//! own tail and stack, rather than one state whose tails and stacks could
//! be paired across readings. Cells and nodes are shared by content and
//! name no record.
//!
//! The expected nodes are written out by hand from the importer's fixture
//! (faculties `codex_a_rollback_removes_the_latest_turns`).

use std::collections::BTreeSet;

use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema, Environment, Progress};
use triblespace_core::trible::{build_intrinsic_entity, IntrinsicEntityRow, Trible, TribleSet};

/// The fold's vocabulary, minted with `trible genid` on 2026-11-05.
mod v {
    use super::*;
    attributes! {
        "684BFFE4F0B8AB92572296CA7DECDD3C" as pub first: GenId;
        "29CC24CA0E1E4EE87F04EC7669DF87BF" as pub next: GenId;
        "7D7411B444AB619FB95BE30DBDC4668F" as pub opening: GenId;
        "46DDEBBB8CCBD1E7AAE04EAA96F23ABE" as pub kind: GenId;
        "8AFA11FFB27C2AACFEB5ABF6042DEAA4" as pub item: GenId;
        "AA39305BC059D7EE7A72AAB581D92145" as pub count: GenId;
        "624BAD2B1E5C7C3E9EBCDDCA0FC1A0BA" as pub predecessor: GenId;
        "DD7D8C8AFA79C77A0A0F78D16D23FE01" as pub state_before: GenId;
        "FC774E48BFD7CF7676DBBC7DB09B6CC5" as pub state_after: GenId;
        "AAA621716F9E5FF8D1FF54022E7D7447" as pub tail: GenId;
        "77536E109C7572AC06040045FD098254" as pub stack: GenId;
        "029B1B04B30C87E31B8083351B8457DB" as pub previous: GenId;
        "0738945C1F8BEC5D81385FD12545EFC3" as pub holds: GenId;
        "18330554EAFB844CDC37822F7742B869" as pub top: GenId;
        "E84DBA5FB453BB4964C03F7ED68C7CE3" as pub rest: GenId;
        "4FBD5005D2FEE54D67489193D227C7A6" as pub pop_of: GenId;
        "51498E40D2D4542FAE4DA086BAE29E1A" as pub at: GenId;
        "834E2A0D8B55D872FB158193194F4351" as pub left: GenId;
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
    Lit(Id),
}
use T::{Lit, Var};

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
            Lit(value) => {
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

/// The constants the rules name.
struct Words {
    turn: Id,
    content: Id,
    rollback: Id,
    nil: Id,
    zero: Id,
    one: Id,
}

/// The fold (the paper rules B, S, C, T, R0, R1, R2, R3).
fn fold(program: &mut TribleSet, w: &Words) -> Vec<Id> {
    let (r, b, a, t, s, f, x, c, q, k, j, i) = (
        Var("r"),
        Var("b"),
        Var("a"),
        Var("t"),
        Var("s"),
        Var("f"),
        Var("x"),
        Var("c"),
        Var("q"),
        Var("k"),
        Var("j"),
        Var("i"),
    );
    vec![
        // B: the first record starts on the opening, with no turns.
        rule(
            program,
            &[
                (Var("u"), v::first.id(), r),
                (Var("u"), v::opening.id(), Var("n0")),
            ],
            &[
                (b, v::state_before.id(), r),
                (b, v::tail.id(), Var("n0")),
                (b, v::stack.id(), Lit(w.nil)),
            ],
            &[],
        ),
        // S: each record starts where its predecessor ended.
        rule(
            program,
            &[
                (Var("p"), v::next.id(), r),
                (a, v::state_after.id(), Var("p")),
                (a, v::tail.id(), t),
                (a, v::stack.id(), s),
            ],
            &[
                (b, v::state_before.id(), r),
                (b, v::tail.id(), t),
                (b, v::stack.id(), s),
            ],
            &[],
        ),
        // C: a content record's item extends the line.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.content)),
                (r, v::item.id(), f),
                (b, v::state_before.id(), r),
                (b, v::tail.id(), t),
                (b, v::stack.id(), s),
            ],
            &[
                (x, v::previous.id(), t),
                (x, v::holds.id(), f),
                (a, v::state_after.id(), r),
                (a, v::tail.id(), x),
                (a, v::stack.id(), s),
            ],
            &[],
        ),
        // T: a turn record pushes the tail it starts at.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.turn)),
                (b, v::state_before.id(), r),
                (b, v::tail.id(), t),
                (b, v::stack.id(), s),
            ],
            &[
                (c, v::top.id(), t),
                (c, v::rest.id(), s),
                (a, v::state_after.id(), r),
                (a, v::tail.id(), t),
                (a, v::stack.id(), c),
            ],
            &[],
        ),
        // R0: a rollback starts popping at the stack it finds.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.rollback)),
                (r, v::count.id(), k),
                (b, v::state_before.id(), r),
                (b, v::stack.id(), s),
            ],
            &[
                (q, v::pop_of.id(), r),
                (q, v::at.id(), s),
                (q, v::left.id(), k),
            ],
            &[],
        ),
        // R1: one cell down while more than one turn is left to remove
        // (j has a predecessor: j is positive).
        rule(
            program,
            &[
                (q, v::pop_of.id(), r),
                (q, v::at.id(), c),
                (q, v::left.id(), k),
                (c, v::rest.id(), s),
                (k, v::predecessor.id(), j),
                (j, v::predecessor.id(), i),
            ],
            &[
                (Var("q2"), v::pop_of.id(), r),
                (Var("q2"), v::at.id(), s),
                (Var("q2"), v::left.id(), j),
            ],
            &[],
        ),
        // R2: the last turn removed: the line ends where it started.
        rule(
            program,
            &[
                (q, v::pop_of.id(), r),
                (q, v::at.id(), c),
                (q, v::left.id(), Lit(w.one)),
                (c, v::top.id(), t),
                (c, v::rest.id(), s),
            ],
            &[
                (a, v::state_after.id(), r),
                (a, v::tail.id(), t),
                (a, v::stack.id(), s),
            ],
            &[],
        ),
        // R3: a rollback of no turns changes nothing.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.rollback)),
                (r, v::count.id(), Lit(w.zero)),
                (b, v::state_before.id(), r),
                (b, v::tail.id(), t),
                (b, v::stack.id(), s),
            ],
            &[
                (a, v::state_after.id(), r),
                (a, v::tail.id(), t),
                (a, v::stack.id(), s),
            ],
            &[],
        ),
    ]
}

/// A unit's records, in order: (kind, item or count).
struct Unit {
    facts: TribleSet,
    records: Vec<Id>,
    opening: Id,
    words: Words,
    /// Number entities 0..=3.
    numbers: Vec<Id>,
}

enum Record {
    Turn,
    Content(Id),
    Rollback(usize),
}

fn unit(records: &[Record]) -> Unit {
    let words = Words {
        turn: id(),
        content: id(),
        rollback: id(),
        nil: id(),
        zero: id(),
        one: id(),
    };
    let numbers = vec![words.zero, words.one, id(), id()];
    let mut facts = TribleSet::new();
    for pair in numbers.windows(2) {
        put(&mut facts, pair[1], v::predecessor.id(), pair[0]);
    }
    let (u, opening) = (id(), id());
    put(&mut facts, u, v::opening.id(), opening);
    let mut ids = Vec::new();
    for record in records {
        let r = id();
        match record {
            Record::Turn => put(&mut facts, r, v::kind.id(), words.turn),
            Record::Content(item) => {
                put(&mut facts, r, v::kind.id(), words.content);
                put(&mut facts, r, v::item.id(), *item);
            }
            Record::Rollback(n) => {
                put(&mut facts, r, v::kind.id(), words.rollback);
                put(&mut facts, r, v::count.id(), numbers[*n]);
            }
        }
        match ids.last() {
            None => put(&mut facts, u, v::first.id(), r),
            Some(&p) => put(&mut facts, p, v::next.id(), r),
        }
        ids.push(r);
    }
    Unit {
        facts,
        records: ids,
        opening,
        words,
        numbers,
    }
}

/// Run the fold to quiescence; the environment's facts.
fn run(unit: &Unit) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = fold(&mut program, &unit.words);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(&unit.facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the fold did not quiesce");
}

/// The importer's node: the one holding `fact` after `previous`.
fn node(previous: Id, fact: Id) -> Id {
    build_intrinsic_entity(vec![
        IntrinsicEntityRow::new(v::previous.id(), raw(previous).raw),
        IntrinsicEntityRow::new(v::holds.id(), raw(fact).raw),
    ])
    .0
}

fn nodes(facts: &TribleSet) -> BTreeSet<Id> {
    find!(n: Id, pattern!(facts, [{ ?n @ v::holds: _?f }])).collect()
}

/// The tail after record `r`, each value once.
fn tails_after(facts: &TribleSet, r: Id) -> BTreeSet<Id> {
    find!(
        t: Id,
        pattern!(facts, [{ _?a @ v::state_after: r, v::tail: ?t }])
    )
    .collect()
}

#[test]
fn a_rollback_removes_the_latest_turn_and_the_line_goes_on_from_before_it() {
    let [fa, fa2, fb, fb2, fc, fc2] = [id(), id(), id(), id(), id(), id()];
    let unit = unit(&[
        Record::Turn,
        Record::Content(fa),
        Record::Content(fa2),
        Record::Turn,
        Record::Content(fb),
        Record::Content(fb2),
        Record::Rollback(1),
        Record::Content(fc),
        Record::Content(fc2),
    ]);
    let facts = run(&unit);
    let n0 = unit.opening;
    let na = node(n0, fa);
    let na2 = node(na, fa2);
    let nb = node(na2, fb);
    let nb2 = node(nb, fb2);
    // C follows a, not b: the rollback removed the second turn.
    let nc = node(na2, fc);
    let nc2 = node(nc, fc2);
    assert_eq!(nodes(&facts), BTreeSet::from([na, na2, nb, nb2, nc, nc2]));
    assert_eq!(tails_after(&facts, unit.records[5]), BTreeSet::from([nb2]));
    assert_eq!(tails_after(&facts, unit.records[6]), BTreeSet::from([na2]));
    assert_eq!(tails_after(&facts, unit.records[8]), BTreeSet::from([nc2]));
    let _ = unit.numbers;
}

/// A rollback of more turns than the line holds derives no state after it,
/// and nothing after it is derived: the importer refuses such a unit, and
/// here it is an absence a reading over the complete unit can name.
#[test]
fn a_rollback_of_more_turns_than_the_line_holds_derives_nothing_after_it() {
    let [fa, fb, fc] = [id(), id(), id()];
    let unit = unit(&[
        Record::Turn,
        Record::Content(fa),
        Record::Turn,
        Record::Content(fb),
        Record::Rollback(3),
        Record::Content(fc),
    ]);
    let facts = run(&unit);
    let na = node(unit.opening, fa);
    let nb = node(na, fb);
    assert_eq!(nodes(&facts), BTreeSet::from([na, nb]));
    assert!(tails_after(&facts, unit.records[4]).is_empty());
    assert!(tails_after(&facts, unit.records[5]).is_empty());
}

/// Identity is the core: a second environment, and the same rules selected
/// twice under other revision ids, converge on the same nodes.
#[test]
fn the_fold_converges_across_environments_and_duplicate_rules() {
    let [fa, fb] = [id(), id()];
    let unit = unit(&[Record::Turn, Record::Content(fa), Record::Content(fb)]);
    let once = run(&unit);
    let again = run(&unit);
    assert_eq!(nodes(&once), nodes(&again));

    let mut program = TribleSet::new();
    let mut rules = fold(&mut program, &unit.words);
    rules.extend(fold(&mut program, &unit.words));
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(&unit.facts);
    env.select(rules);
    while env.advance(1_000).expect("runs").progress == Progress::Pending {}
    assert_eq!(nodes(env.facts()), nodes(&once));
    let na = node(unit.opening, fa);
    assert_eq!(nodes(&once), BTreeSet::from([na, node(na, fb)]));
}

/// The cell a turn pushes: `top` on `rest`.
fn cell(top: Id, rest: Id) -> Id {
    build_intrinsic_entity(vec![
        IntrinsicEntityRow::new(v::top.id(), raw(top).raw),
        IntrinsicEntityRow::new(v::rest.id(), raw(rest).raw),
    ])
    .0
}

/// Two states reaching one record stay correlated. A forked unit: two first
/// records, one extending the line with A and one starting a turn, both
/// followed by one turn record. That record pushes each predecessor's own
/// tail onto that predecessor's own stack, never one's tail onto the
/// other's stack (which a state identified by its record alone would allow).
#[test]
fn two_states_reaching_one_record_keep_their_tails_and_stacks_apart() {
    let fa = id();
    let mut unit = unit(&[Record::Content(fa)]);
    let (p2, r, r0) = (id(), id(), unit.records[0]);
    let first: Vec<Id> = find!(u: Id, pattern!(&unit.facts, [{ ?u @ v::first: r0 }])).collect();
    assert_eq!(first.len(), 1);
    put(&mut unit.facts, first[0], v::first.id(), p2);
    put(&mut unit.facts, p2, v::kind.id(), unit.words.turn);
    put(&mut unit.facts, r0, v::next.id(), r);
    put(&mut unit.facts, p2, v::next.id(), r);
    put(&mut unit.facts, r, v::kind.id(), unit.words.turn);
    let facts = run(&unit);
    let (n0, nil) = (unit.opening, unit.words.nil);
    let na = node(n0, fa);
    let c0 = cell(n0, nil);
    let cells: BTreeSet<Id> =
        find!(c: Id, pattern!(&facts, [{ ?c @ v::top: _?t, v::rest: _?s }])).collect();
    assert_eq!(cells, BTreeSet::from([c0, cell(na, nil), cell(n0, c0)]));
    assert!(
        !cells.contains(&cell(na, c0)),
        "A's tail on the turn's stack"
    );
}
