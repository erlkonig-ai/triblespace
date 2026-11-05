//! A dropped list copy of earlier items, as positive rules.
//!
//! Codex's review history copies her earlier items into a later record
//! (`Mirror::Earlier`). The importer drops the copy when its elements, in
//! order, equal values at the named paths in strictly earlier records of
//! the same unit, as an increasing subsequence, matched greedily earliest
//! first (which finds an assignment exactly when one exists). The one
//! declared copy form (`WithoutEmptyOutputText`) applies to the earlier
//! values only: an earlier value matches either as it stands or in that
//! form; the copy's elements compare as they stand.
//!
//! Here a match is a chain: element 1 matched to an earlier occurrence,
//! each next element to an occurrence after the previous match. The order
//! of records and of occurrences is the closure of their successor
//! observations. A candidate is its own entity, naming the copy, the
//! earlier occurrence, the unit, the copy's record (the boundary "earlier"
//! is relative to) and the mirror spec it was found under; a match state
//! carries the same unit, boundary and spec, and each step joins them, so
//! one chain never mixes readings (a copy in two units, or under two
//! specs). Within one spec, each element may match at any of its paths.
//! Each match also names the value it matched.
//!
//! A match state is the endpoint of a reachable prefix (copy, element,
//! occurrence, value, reading), shared by every chain that reaches it: a
//! state at the last element proves that some complete chain exists, not
//! which one; full-chain provenance would cost a path per chain. An empty
//! copy is backed vacuously, by its own rule, since a chain has nothing to
//! start from.
//! Refusing an unbacked copy is a reading over the complete unit.
//! The conversion is supplied as a `converted` value of the earlier
//! occurrence, so equivalence after it is a separate, stated fact, never
//! inferred from equality.
//!
//! This proposed rule example does not integrate the production importer or
//! implement its refusal reading. Every expected relationship is written out
//! by hand.

use std::collections::BTreeSet;

use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema, Environment, Progress};
use triblespace_core::trible::{Trible, TribleSet};

/// The vocabulary. `in_unit`, `at_path`, `canonical`, `mirrors` and
/// `from_path` are shared with `reactive_mirror_backing.rs`; the rest was
/// minted with `trible genid` on 2026-11-05.
mod v {
    use super::*;
    attributes! {
        "468BA16AFC8866E7FC1B393184BCAB04" as pub in_unit: GenId;
        "84E998676F9AC74BF66C406952F4D040" as pub at_path: GenId;
        "780B89E1CFFBD2590A07943F4BB52458" as pub canonical: GenId;
        "7537EFAF355D6189C83F0A84E6BFB7C0" as pub mirrors: GenId;
        "A4EA8E3C9B5692302C5FF1C6C7A9726F" as pub from_path: GenId;
        "DC21495A33E0F1CCB0C69C6571FE9979" as pub in_record: GenId;
        "BE79D37708F2FE43D54B1ED99DC0440F" as pub record_next: GenId;
        "23033149A9E6B22B3613F085877F2E4D" as pub record_before: GenId;
        "A1A7B9DBEF96D0F3FF38D5BF2D4A60E2" as pub occ_next: GenId;
        "37F4A1B5CB925A1E9F07F5FA3B360E59" as pub occ_before: GenId;
        "9FE5693FFB9F18FF1ADD7D7BA6CE7D59" as pub first_elem: GenId;
        "A41B7126D30D1C3E1B0B3613B441DD75" as pub next_elem: GenId;
        "26E7D367BA89AEDB8FC7B4879D3C2D09" as pub last_elem: GenId;
        "7EAC1E50C11B292E438727257FB99FDC" as pub match_of: GenId;
        "D4EDB3191C00B75744E8CA746A7332F6" as pub elem: GenId;
        "E64A1D973F6859B9EF8B45720485C389" as pub matched_at: GenId;
        "6276B094AD326DAB453C9C9F087DC162" as pub converted: GenId;
        "4AC7432D2D8EE324A234A9A0F6D0FA36" as pub comparable: GenId;
        "526BCA4C87E3B4CD98C2B70311FDA9A8" as pub earlier_backed: GenId;
        "B7DDA47C4A9F2CCF1CA65F23115C4F1F" as pub empty_list: GenId;
        "AB098D36FCD2ABEF2D63E66D5884600E" as pub matched_value: GenId;
        "28EC2E6E929DAC539D0CEA4A53845522" as pub cand_copy: GenId;
        "C240DBAFFCA1E01EE91752BC8DA0B161" as pub cand_occ: GenId;
        "910840FB6630CF5ECB06AFA543804747" as pub cand_unit: GenId;
        "B2A07F29E691F38D25D52507F442BA18" as pub cand_bound: GenId;
        "753AA0535BA0A6ACE6A1C0C20948FADF" as pub cand_spec: GenId;
        "BE826CD71397EEFE7E0A52AAF461012D" as pub match_unit: GenId;
        "EFF63F06F2AFBE3356396CFB91043026" as pub match_bound: GenId;
        "7AD9B332550DE85AE2F3B111F0E253A5" as pub match_spec: GenId;
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

/// The rules: order closures (RB, OB), comparable values (CMP), earlier
/// candidates under one reading (EF), the match states (E0, E1), and the
/// witnesses (DONE, EMPTY).
fn earlier(program: &mut TribleSet) -> Vec<Id> {
    let (r, r2, r3, o, o2, o3, h) = (
        Var("r"),
        Var("r2"),
        Var("r3"),
        Var("o"),
        Var("o2"),
        Var("o3"),
        Var("h"),
    );
    let (c, m, p, u, rc, ro, e, e2, q) = (
        Var("c"),
        Var("m"),
        Var("p"),
        Var("u"),
        Var("rc"),
        Var("ro"),
        Var("e"),
        Var("e2"),
        Var("q"),
    );
    vec![
        // RB: record order.
        rule(
            program,
            &[(r, v::record_next.id(), r2)],
            &[],
            &[(r, v::record_before.id(), r2)],
        ),
        rule(
            program,
            &[
                (r, v::record_before.id(), r2),
                (r2, v::record_next.id(), r3),
            ],
            &[],
            &[(r, v::record_before.id(), r3)],
        ),
        // OB: occurrence order.
        rule(
            program,
            &[(o, v::occ_next.id(), o2)],
            &[],
            &[(o, v::occ_before.id(), o2)],
        ),
        rule(
            program,
            &[(o, v::occ_before.id(), o2), (o2, v::occ_next.id(), o3)],
            &[],
            &[(o, v::occ_before.id(), o3)],
        ),
        // CMP: an occurrence compares as it stands, or as converted.
        rule(
            program,
            &[(o, v::canonical.id(), h)],
            &[],
            &[(o, v::comparable.id(), h)],
        ),
        rule(
            program,
            &[(o, v::converted.id(), h)],
            &[],
            &[(o, v::comparable.id(), h)],
        ),
        // EF: an occurrence at a named path, in the same unit, in a record
        // strictly before the copy's.
        rule(
            program,
            &[
                (c, v::mirrors.id(), m),
                (m, v::from_path.id(), p),
                (c, v::in_unit.id(), u),
                (c, v::in_record.id(), rc),
                (o, v::at_path.id(), p),
                (o, v::in_unit.id(), u),
                (o, v::in_record.id(), ro),
                (ro, v::record_before.id(), rc),
            ],
            &[
                (Var("k"), v::cand_copy.id(), c),
                (Var("k"), v::cand_occ.id(), o),
                (Var("k"), v::cand_unit.id(), u),
                (Var("k"), v::cand_bound.id(), rc),
                (Var("k"), v::cand_spec.id(), m),
            ],
            &[],
        ),
        // E0: the first element matched to an earlier occurrence.
        rule(
            program,
            &[
                (c, v::first_elem.id(), e),
                (e, v::canonical.id(), h),
                (Var("k"), v::cand_copy.id(), c),
                (Var("k"), v::cand_occ.id(), o),
                (Var("k"), v::cand_unit.id(), u),
                (Var("k"), v::cand_bound.id(), rc),
                (Var("k"), v::cand_spec.id(), m),
                (o, v::comparable.id(), h),
            ],
            &[
                (q, v::match_of.id(), c),
                (q, v::elem.id(), e),
                (q, v::matched_at.id(), o),
                (q, v::matched_value.id(), h),
                (q, v::match_unit.id(), u),
                (q, v::match_bound.id(), rc),
                (q, v::match_spec.id(), m),
            ],
            &[],
        ),
        // E1: the next element matched to an occurrence after it.
        rule(
            program,
            &[
                (Var("q0"), v::match_of.id(), c),
                (Var("q0"), v::elem.id(), e),
                (Var("q0"), v::matched_at.id(), o),
                (Var("q0"), v::match_unit.id(), u),
                (Var("q0"), v::match_bound.id(), rc),
                (Var("q0"), v::match_spec.id(), m),
                (e, v::next_elem.id(), e2),
                (e2, v::canonical.id(), h),
                (Var("k"), v::cand_copy.id(), c),
                (Var("k"), v::cand_occ.id(), o2),
                (Var("k"), v::cand_unit.id(), u),
                (Var("k"), v::cand_bound.id(), rc),
                (Var("k"), v::cand_spec.id(), m),
                (o2, v::comparable.id(), h),
                (o, v::occ_before.id(), o2),
            ],
            &[
                (q, v::match_of.id(), c),
                (q, v::elem.id(), e2),
                (q, v::matched_at.id(), o2),
                (q, v::matched_value.id(), h),
                (q, v::match_unit.id(), u),
                (q, v::match_bound.id(), rc),
                (q, v::match_spec.id(), m),
            ],
            &[],
        ),
        // DONE: a chain that reaches the last element backs the copy.
        rule(
            program,
            &[
                (q, v::match_of.id(), c),
                (q, v::elem.id(), e),
                (c, v::last_elem.id(), e),
            ],
            &[],
            &[(c, v::earlier_backed.id(), q)],
        ),
        // EMPTY: an empty copy is backed vacuously.
        rule(
            program,
            &[(c, v::empty_list.id(), Var("t"))],
            &[],
            &[(c, v::earlier_backed.id(), c)],
        ),
    ]
}

/// One unit, built in file order.
struct File {
    facts: TribleSet,
    unit: Id,
    last_record: Option<Id>,
    last_occ: Option<Id>,
    /// The mirror spec copies use, naming `path`.
    mirror: Id,
    path: Id,
}

impl File {
    fn new() -> Self {
        let (mirror, path) = (id(), id());
        let mut facts = TribleSet::new();
        put(&mut facts, mirror, v::from_path.id(), path);
        File {
            facts,
            unit: id(),
            last_record: None,
            last_occ: None,
            mirror,
            path,
        }
    }

    fn record(&mut self) -> Id {
        let r = id();
        if let Some(p) = self.last_record {
            put(&mut self.facts, p, v::record_next.id(), r);
        }
        self.last_record = Some(r);
        r
    }

    /// An occurrence of content `h` at the named path in record `r`.
    fn value(&mut self, r: Id, h: Id) -> Id {
        let unit = self.unit;
        self.value_in(r, h, unit)
    }

    /// [`File::value`], in `unit`.
    fn value_in(&mut self, r: Id, h: Id, unit: Id) -> Id {
        let o = id();
        put(&mut self.facts, o, v::in_unit.id(), unit);
        put(&mut self.facts, o, v::in_record.id(), r);
        put(&mut self.facts, o, v::at_path.id(), self.path);
        put(&mut self.facts, o, v::canonical.id(), h);
        if let Some(p) = self.last_occ {
            put(&mut self.facts, p, v::occ_next.id(), o);
        }
        self.last_occ = Some(o);
        o
    }

    /// A dropped copy in record `r` whose elements have contents `elems`.
    fn copy(&mut self, r: Id, elems: &[Id]) -> Id {
        let c = id();
        put(&mut self.facts, c, v::in_unit.id(), self.unit);
        put(&mut self.facts, c, v::in_record.id(), r);
        put(&mut self.facts, c, v::mirrors.id(), self.mirror);
        if elems.is_empty() {
            put(&mut self.facts, c, v::empty_list.id(), id());
        }
        let mut previous: Option<Id> = None;
        for h in elems {
            let e = id();
            put(&mut self.facts, e, v::canonical.id(), *h);
            match previous {
                None => put(&mut self.facts, c, v::first_elem.id(), e),
                Some(p) => put(&mut self.facts, p, v::next_elem.id(), e),
            }
            previous = Some(e);
        }
        if let Some(e) = previous {
            put(&mut self.facts, c, v::last_elem.id(), e);
        }
        c
    }

    fn backed(&self, c: Id) -> bool {
        let facts = run(&self.facts);
        exists!(pattern!(&facts, [{ c @ v::earlier_backed: _?w }]))
    }
}

fn run(facts: &TribleSet) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = earlier(&mut program);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the earlier rules did not quiesce");
}

#[test]
fn a_copy_of_earlier_items_in_order_is_backed_even_with_gaps() {
    let (x, y, z) = (id(), id(), id());
    let mut f = File::new();
    let r1 = f.record();
    f.value(r1, x);
    let r2 = f.record();
    f.value(r2, z);
    let r3 = f.record();
    f.value(r3, y);
    let r4 = f.record();
    let c = f.copy(r4, &[x, y]);
    assert!(f.backed(c), "x then y, with z between");
}

#[test]
fn a_copy_of_earlier_items_out_of_order_is_not_backed() {
    let (x, y) = (id(), id());
    let mut f = File::new();
    let r1 = f.record();
    f.value(r1, y);
    let r2 = f.record();
    f.value(r2, x);
    let r3 = f.record();
    let c = f.copy(r3, &[x, y]);
    assert!(!f.backed(c));
}

/// Earlier means a strictly earlier record: a value in the copy's own
/// record does not back it.
#[test]
fn a_value_in_the_copy_s_own_record_is_not_earlier() {
    let (x, y) = (id(), id());
    let mut f = File::new();
    let r1 = f.record();
    f.value(r1, x);
    let r2 = f.record();
    f.value(r2, y);
    let c = f.copy(r2, &[x, y]);
    assert!(!f.backed(c));
}

/// Repeated equal elements need two distinct, strictly ordered values.
#[test]
fn repeated_elements_need_as_many_earlier_values() {
    let x = id();
    let mut once = File::new();
    let r1 = once.record();
    once.value(r1, x);
    let r2 = once.record();
    let c = once.copy(r2, &[x, x]);
    assert!(!once.backed(c), "one x cannot be matched twice");

    let mut twice = File::new();
    let r1 = twice.record();
    twice.value(r1, x);
    let r2 = twice.record();
    twice.value(r2, x);
    let r3 = twice.record();
    let c = twice.copy(r3, &[x, x]);
    assert!(twice.backed(c));
}

/// An empty copy holds nothing to lose: backed vacuously, as the
/// importer's loop over no elements is.
#[test]
fn an_empty_copy_is_backed_vacuously() {
    let mut f = File::new();
    let r1 = f.record();
    let c = f.copy(r1, &[]);
    assert!(f.backed(c));
}

/// The declared copy form applies to earlier values: an earlier value
/// whose converted form equals the element backs it. A copy element in the
/// converted form does not make an earlier value in another form match.
#[test]
fn the_copy_form_applies_to_earlier_values_only() {
    let (full, without_empty) = (id(), id());
    let mut f = File::new();
    let r1 = f.record();
    let o = f.value(r1, full);
    put(&mut f.facts, o, v::converted.id(), without_empty);
    let r2 = f.record();
    let c = f.copy(r2, &[without_empty]);
    assert!(
        f.backed(c),
        "the earlier value matches in its converted form"
    );

    // The other way round: the earlier value is the converted text, the
    // copy holds the full one; no rule converts a copy.
    let mut g = File::new();
    let r1 = g.record();
    g.value(r1, without_empty);
    let r2 = g.record();
    let c = g.copy(r2, &[full]);
    assert!(!g.backed(c));
}

/// The occurrences and matched values of copy `c`'s reachable-prefix states.
fn matched(facts: &TribleSet, c: Id) -> BTreeSet<(Id, Id)> {
    find!(
        (o: Id, h: Id),
        pattern!(facts, [{ _?q @ v::match_of: c, v::matched_at: ?o, v::matched_value: ?h }])
    )
    .collect()
}

/// A copy element with two content values: each match witness names the
/// value it matched. The chain re-checks every element against its own
/// occurrence, so leaving the value out of a match could not back a copy
/// wrongly; what it would lose is which reading the witness proves. Here
/// the element carries h1 and h2 and the earlier value h1 and h3: exactly
/// one match, naming h1. With the earlier value carrying h1 and h2, two
/// matches, one per value.
#[test]
fn a_match_names_the_value_it_matched() {
    let (h1, h2, h3) = (id(), id(), id());
    let mut f = File::new();
    let r1 = f.record();
    let o = f.value(r1, h1);
    put(&mut f.facts, o, v::canonical.id(), h3);
    let r2 = f.record();
    let c = f.copy(r2, &[h1]);
    let first: Vec<Id> = find!(e: Id, pattern!(&f.facts, [{ c @ v::first_elem: ?e }])).collect();
    put(&mut f.facts, first[0], v::canonical.id(), h2);
    let facts = run(&f.facts);
    assert_eq!(matched(&facts, c), BTreeSet::from([(o, h1)]));

    put(&mut f.facts, o, v::canonical.id(), h2);
    let facts = run(&f.facts);
    assert_eq!(matched(&facts, c), BTreeSet::from([(o, h1), (o, h2)]));
}

/// A copy in two units is backed only by a chain within one of them: x is
/// earlier in u1 only and y in u2 only, so [x, y] has no single-unit
/// reading, though the occurrence order connects x to y. (Found by Sol's
/// worker against the version whose candidates named no unit.) With both
/// in one unit, a second unit on the copy does not undo that reading.
#[test]
fn a_chain_never_mixes_units() {
    let (x, y) = (id(), id());
    let mut f = File::new();
    let (u1, u2) = (f.unit, id());
    let r1 = f.record();
    f.value_in(r1, x, u1);
    let r2 = f.record();
    f.value_in(r2, y, u2);
    let r3 = f.record();
    let c = f.copy(r3, &[x, y]);
    put(&mut f.facts, c, v::in_unit.id(), u2);
    assert!(!f.backed(c));

    let mut g = File::new();
    let g1 = g.record();
    g.value(g1, x);
    let g2 = g.record();
    g.value(g2, y);
    let g3 = g.record();
    let c = g.copy(g3, &[x, y]);
    put(&mut g.facts, c, v::in_unit.id(), id());
    assert!(g.backed(c));
}
