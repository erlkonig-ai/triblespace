//! When a dropped copy is backed, as positive rules.
//!
//! An archive table drops some values as mirrors: copies of something the
//! unit already holds (Codex's event copies of her messages, a client log
//! line repeating a kept item). Dropping one loses nothing only if what it
//! copies is retained somewhere in the same unit. The rules here derive
//! `backed_by` witnesses for that; refusing a dropped copy with no witness
//! is a reading over the complete unit (an absence), kept outside the rules
//! and stated in the tests.
//!
//! - A witness names an occurrence in the same unit: identical content in
//!   another unit discharges nothing.
//! - It ends at a retained occurrence. A dropped copy can be backed through
//!   other dropped copies, but only along a path that reaches a retained
//!   one. A dropped cycle derives no backing without a retained witness;
//!   these positive rules do not impose disjoint retained/dropped dispositions.
//! - A witness is its own entity whose identity is the whole reading it
//!   proves: the copy, the unit, the content value it matched, and the
//!   retained original it ends at. Passing a witness on joins on that same
//!   unit and value, so an occurrence with two content values, or in two
//!   units, never lends a backing it has under one reading to a copy that
//!   matched it under another. `backed_by` is only a projection of it.
//! - Equality is equality of the occurrences' canonical content, a value
//!   each occurrence carries, never a join on derived entity ids. A copy
//!   whose content equals its original only after a conversion is a
//!   different canonical value here, unless a rule states the conversion.
//!
//! This is a proposed rule example, not production importer integration.
//! Every expected relationship is written out by hand.

use std::collections::BTreeSet;

use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema, Environment, Progress};
use triblespace_core::trible::{Trible, TribleSet};

/// The vocabulary, minted with `trible genid` on 2026-11-05.
mod v {
    use super::*;
    attributes! {
        "468BA16AFC8866E7FC1B393184BCAB04" as pub in_unit: GenId;
        "84E998676F9AC74BF66C406952F4D040" as pub at_path: GenId;
        "780B89E1CFFBD2590A07943F4BB52458" as pub canonical: GenId;
        "5A9EF6F85C20A5BC26BFED1F2216263E" as pub retained: GenId;
        "7537EFAF355D6189C83F0A84E6BFB7C0" as pub mirrors: GenId;
        "A4EA8E3C9B5692302C5FF1C6C7A9726F" as pub from_path: GenId;
        "53DFCA1D4892C54AF19C59D0840CF384" as pub backed_by: GenId;
        "3A81DEC378E8FF6D5A57B8F7D842E782" as pub backs: GenId;
        "0BF004DD155D5491DB7EBD51C6C52170" as pub in_witness_unit: GenId;
        "48264F29BE3B32DFCFE981545F16E963" as pub witness_value: GenId;
        "19B592F61B10D8C09738CA41924CF059" as pub original_of: GenId;
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

/// The backing rules: B1 (a retained original backs a copy), B2 (a copy
/// backed under the same unit and value passes its original on), and the
/// `backed_by` projection.
fn backing(program: &mut TribleSet) -> Vec<Id> {
    let (c, m, p, u, h, o, w) = (
        Var("c"),
        Var("m"),
        Var("p"),
        Var("u"),
        Var("h"),
        Var("o"),
        Var("w"),
    );
    // A copy, the paths its mirror names, its unit and content; and an
    // occurrence at one of those paths, in the same unit, with the same
    // content.
    let candidate = [
        (c, v::mirrors.id(), m),
        (m, v::from_path.id(), p),
        (c, v::in_unit.id(), u),
        (c, v::canonical.id(), h),
        (o, v::in_unit.id(), u),
        (o, v::at_path.id(), p),
        (o, v::canonical.id(), h),
    ];
    let k = Var("k");
    let witness = |original: T| {
        [
            (k, v::backs.id(), c),
            (k, v::in_witness_unit.id(), u),
            (k, v::witness_value.id(), h),
            (k, v::original_of.id(), original),
        ]
    };
    let mut b1 = candidate.to_vec();
    b1.push((o, v::retained.id(), Var("t")));
    let mut b2 = candidate.to_vec();
    b2.extend([
        (Var("k0"), v::backs.id(), o),
        (Var("k0"), v::in_witness_unit.id(), u),
        (Var("k0"), v::witness_value.id(), h),
        (Var("k0"), v::original_of.id(), w),
    ]);
    vec![
        rule(program, &b1, &witness(o), &[]),
        rule(program, &b2, &witness(w), &[]),
        // The projection, for reading only.
        rule(
            program,
            &[(k, v::backs.id(), c), (k, v::original_of.id(), w)],
            &[],
            &[(c, v::backed_by.id(), w)],
        ),
    ]
}

/// An occurrence of content `h` at `path` in `unit`.
fn occurrence(facts: &mut TribleSet, unit: Id, path: Id, h: Id) -> Id {
    let o = id();
    put(facts, o, v::in_unit.id(), unit);
    put(facts, o, v::at_path.id(), path);
    put(facts, o, v::canonical.id(), h);
    o
}

fn retained(facts: &mut TribleSet, o: Id) {
    put(facts, o, v::retained.id(), id());
}

/// A mirror spec naming the paths a copy may copy.
fn mirror(facts: &mut TribleSet, paths: &[Id]) -> Id {
    let m = id();
    for p in paths {
        put(facts, m, v::from_path.id(), *p);
    }
    m
}

fn dropped(facts: &mut TribleSet, o: Id, m: Id) {
    put(facts, o, v::mirrors.id(), m);
}

fn run(facts: &TribleSet) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = backing(&mut program);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the backing rules did not quiesce");
}

fn witnesses(facts: &TribleSet, copy: Id) -> BTreeSet<Id> {
    find!(w: Id, pattern!(facts, [{ copy @ v::backed_by: ?w }])).collect()
}

/// A copy of a retained message in the same unit is backed by it. The
/// same content retained only in another unit backs nothing: the reading
/// refuses that unit.
#[test]
fn a_copy_is_backed_by_a_retained_original_in_its_own_unit_only() {
    let (u1, u2, text, event, h) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let m = mirror(&mut facts, &[text]);
    let original = occurrence(&mut facts, u1, text, h);
    retained(&mut facts, original);
    let copy = occurrence(&mut facts, u1, event, h);
    dropped(&mut facts, copy, m);
    let elsewhere = occurrence(&mut facts, u2, event, h);
    dropped(&mut facts, elsewhere, m);
    let facts = run(&facts);
    assert_eq!(witnesses(&facts, copy), BTreeSet::from([original]));
    assert!(
        witnesses(&facts, elsewhere).is_empty(),
        "no cross-unit discharge"
    );
}

/// Two dropped copies of each other back nothing; once one of them has a
/// retained original, both are backed by it, the other through it.
#[test]
fn copies_of_each_other_need_a_path_to_a_retained_original() {
    let (u, pa, pb, pc, h) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let ma = mirror(&mut facts, &[pb]);
    let mb = mirror(&mut facts, &[pa]);
    let a = occurrence(&mut facts, u, pa, h);
    let b = occurrence(&mut facts, u, pb, h);
    dropped(&mut facts, a, ma);
    dropped(&mut facts, b, mb);
    let alone = run(&facts);
    assert!(witnesses(&alone, a).is_empty(), "circular reassurance");
    assert!(witnesses(&alone, b).is_empty(), "circular reassurance");

    // Now b may also copy pc, where the content is retained.
    let mb2 = mirror(&mut facts, &[pc]);
    dropped(&mut facts, b, mb2);
    let kept = occurrence(&mut facts, u, pc, h);
    retained(&mut facts, kept);
    let facts = run(&facts);
    assert_eq!(witnesses(&facts, b), BTreeSet::from([kept]));
    assert_eq!(witnesses(&facts, a), BTreeSet::from([kept]));
}

/// Equality is of canonical content: an occurrence at the right path whose
/// content differs (say, the same text before a rendering) backs nothing,
/// nor does equal content at a path the mirror does not name.
#[test]
fn a_copy_needs_equal_content_at_a_path_its_mirror_names() {
    let (u, text, other, event, h, rendered) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let m = mirror(&mut facts, &[text]);
    let before = occurrence(&mut facts, u, text, rendered);
    retained(&mut facts, before);
    let wrong_path = occurrence(&mut facts, u, other, h);
    retained(&mut facts, wrong_path);
    let copy = occurrence(&mut facts, u, event, h);
    dropped(&mut facts, copy, m);
    let facts = run(&facts);
    assert!(witnesses(&facts, copy).is_empty());
}

/// An occurrence with two content values is backed under one of them only:
/// a copy that matches it under the other inherits nothing.
#[test]
fn a_backing_under_one_content_value_does_not_back_another() {
    let (u, pw, po, pc, h1, h2) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let w = occurrence(&mut facts, u, pw, h2);
    retained(&mut facts, w);
    let o = occurrence(&mut facts, u, po, h2);
    put(&mut facts, o, v::canonical.id(), h1);
    let mo = mirror(&mut facts, &[pw]);
    dropped(&mut facts, o, mo);
    let c = occurrence(&mut facts, u, pc, h1);
    let mc = mirror(&mut facts, &[po]);
    dropped(&mut facts, c, mc);
    let facts = run(&facts);
    assert_eq!(
        witnesses(&facts, o),
        BTreeSet::from([w]),
        "o is backed under h2"
    );
    assert!(witnesses(&facts, c).is_empty(), "no retained h1 anywhere");
}

/// An occurrence in two units is backed in one of them only: a copy in the
/// other inherits nothing.
#[test]
fn a_backing_in_one_unit_does_not_back_a_copy_in_another() {
    let (u1, u2, pw, po, pc, h) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let w = occurrence(&mut facts, u2, pw, h);
    retained(&mut facts, w);
    let o = occurrence(&mut facts, u2, po, h);
    put(&mut facts, o, v::in_unit.id(), u1);
    let mo = mirror(&mut facts, &[pw]);
    dropped(&mut facts, o, mo);
    let c = occurrence(&mut facts, u1, pc, h);
    let mc = mirror(&mut facts, &[po]);
    dropped(&mut facts, c, mc);
    let facts = run(&facts);
    assert_eq!(
        witnesses(&facts, o),
        BTreeSet::from([w]),
        "o is backed in u2"
    );
    assert!(witnesses(&facts, c).is_empty(), "nothing retained in u1");
}
