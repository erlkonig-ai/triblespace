//! Claims that wait for the next node, as positive rules.
//!
//! A Codex record that holds no node can still claim something (a header
//! line's id, a settings header that records no settings). The archive
//! importer keeps such claims pending and gives each to the next node the
//! file places, as an occurrence of its own; a file that ends while claims
//! still wait, after it has placed a node, is refused (X19).
//!
//! "The next node" reads like "the first one after", which would need
//! negation. Here it is threaded through the state instead: each record's
//! state carries the bundles still waiting, as a chain of content-addressed
//! cells (like the turn stack in `reactive_rollback.rs`). A record that
//! claims and holds nothing pushes its bundle; a record that places a node
//! hands every waiting bundle to it and leaves nothing waiting.
//!
//! A handing-over is a delivery, whose identity includes the record that
//! placed the node: a node is shared by its content across units and
//! placements, so a delivery known only by its node would union what
//! different records handed it. The archive occurrence each delivery makes
//! is (node, claims) and names no record, so two deliveries of the same
//! claims to the same node converge on one occurrence. What still
//! waits after the last record is derived as the unit's `leftover`; refusing
//! a non-empty leftover is a reading over the complete unit (an inequality
//! between bound ids, `leftover != nil`), kept outside the rules and
//! checked in the tests.
//!
//! Record kinds come from the construction half: NODE (places a node,
//! `first_node` names it), CLAIMS (holds nothing, `claims` names its
//! bundle), NOTHING (neither). Record ids are fresh within each unit, so
//! position states remain unit-scoped. These rules model delivery witnesses
//! and occurrences; production importer integration and refusal remain outside
//! this fixture. Every expected relationship is written out by hand.

use std::collections::BTreeSet;

use triblespace_core::id::{rngid, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema, Environment, Progress};
use triblespace_core::trible::{Trible, TribleSet};

/// The vocabulary. `first`, `next`, `kind`, `state_before`, `state_after`,
/// `top`, `rest` and `at` are shared with `reactive_rollback.rs`; the rest
/// was minted with `trible genid` on 2026-11-05.
mod v {
    use super::*;
    attributes! {
        "684BFFE4F0B8AB92572296CA7DECDD3C" as pub first: GenId;
        "29CC24CA0E1E4EE87F04EC7669DF87BF" as pub next: GenId;
        "46DDEBBB8CCBD1E7AAE04EAA96F23ABE" as pub kind: GenId;
        "DD7D8C8AFA79C77A0A0F78D16D23FE01" as pub state_before: GenId;
        "FC774E48BFD7CF7676DBBC7DB09B6CC5" as pub state_after: GenId;
        "18330554EAFB844CDC37822F7742B869" as pub top: GenId;
        "E84DBA5FB453BB4964C03F7ED68C7CE3" as pub rest: GenId;
        "51498E40D2D4542FAE4DA086BAE29E1A" as pub at: GenId;
        "7B69BEF124D2340BA1A157B6CE1F0A51" as pub last: GenId;
        "BB9E03C3083CF7D35F85DC03745BD45E" as pub first_node: GenId;
        "8B29D41A48255A1A6179E190CA1E604E" as pub claims: GenId;
        "324BA0CBB65E81D7CA8C6F5113D831FC" as pub waiting: GenId;
        "37E4FE5958F3A63DF029134693046719" as pub deliver_to: GenId;
        "82E522D332940C5F2CC40EC9F61017B4" as pub deliver_by: GenId;
        "75A2FEC8DBA6F51C3F284C1CBE30F05D" as pub delivered_by: GenId;
        "E462CCAFB3E7C95662E8731C1133E2E3" as pub delivered_node: GenId;
        "9CF5B30AF7044306140A2CA0C6D16CD7" as pub delivered_bundle: GenId;
        "32030F0FE7DA7E8595221D406544743F" as pub occurrence_of: GenId;
        "D2B17EBA425E236097D0335B06EBBF41" as pub with_claims: GenId;
        "65D78E875830E0D6754E088A05CF240B" as pub leftover: GenId;
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
    node: Id,
    claims: Id,
    nothing: Id,
    nil: Id,
}

/// The rules B, S, Q, P, D0, D1, O, L.
fn pending(program: &mut TribleSet, w: &Words) -> Vec<Id> {
    let (r, b, a, s, c, x, d, k) = (
        Var("r"),
        Var("b"),
        Var("a"),
        Var("s"),
        Var("c"),
        Var("x"),
        Var("d"),
        Var("k"),
    );
    vec![
        // B: nothing waits before the first record.
        rule(
            program,
            &[(Var("u"), v::first.id(), r)],
            &[
                (b, v::state_before.id(), r),
                (b, v::waiting.id(), Lit(w.nil)),
            ],
            &[],
        ),
        // S: each record starts with what waited after its predecessor.
        rule(
            program,
            &[
                (Var("p"), v::next.id(), r),
                (a, v::state_after.id(), Var("p")),
                (a, v::waiting.id(), s),
            ],
            &[(b, v::state_before.id(), r), (b, v::waiting.id(), s)],
            &[],
        ),
        // Q: a record that claims and holds nothing pushes its bundle.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.claims)),
                (r, v::claims.id(), Var("w")),
                (b, v::state_before.id(), r),
                (b, v::waiting.id(), s),
            ],
            &[
                (c, v::top.id(), Var("w")),
                (c, v::rest.id(), s),
                (a, v::state_after.id(), r),
                (a, v::waiting.id(), c),
            ],
            &[],
        ),
        // P: a record that does neither passes on what waits.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.nothing)),
                (b, v::state_before.id(), r),
                (b, v::waiting.id(), s),
            ],
            &[(a, v::state_after.id(), r), (a, v::waiting.id(), s)],
            &[],
        ),
        // D0: a record that places a node starts handing what waits to it,
        // and leaves nothing waiting.
        rule(
            program,
            &[
                (r, v::kind.id(), Lit(w.node)),
                (r, v::first_node.id(), x),
                (b, v::state_before.id(), r),
                (b, v::waiting.id(), s),
            ],
            &[
                (d, v::deliver_by.id(), r),
                (d, v::deliver_to.id(), x),
                (d, v::at.id(), s),
                (a, v::state_after.id(), r),
                (a, v::waiting.id(), Lit(w.nil)),
            ],
            &[],
        ),
        // D1: each waiting bundle is delivered to the node by the record,
        // one cell at a time.
        rule(
            program,
            &[
                (d, v::deliver_by.id(), r),
                (d, v::deliver_to.id(), x),
                (d, v::at.id(), c),
                (c, v::top.id(), Var("w")),
                (c, v::rest.id(), s),
            ],
            &[
                (Var("d2"), v::deliver_by.id(), r),
                (Var("d2"), v::deliver_to.id(), x),
                (Var("d2"), v::at.id(), s),
                (Var("q"), v::delivered_by.id(), r),
                (Var("q"), v::delivered_node.id(), x),
                (Var("q"), v::delivered_bundle.id(), Var("w")),
            ],
            &[],
        ),
        // O: a delivery makes the occurrence (node, claims), which names no
        // record.
        rule(
            program,
            &[
                (Var("q"), v::delivered_node.id(), x),
                (Var("q"), v::delivered_bundle.id(), Var("w")),
            ],
            &[
                (Var("o"), v::occurrence_of.id(), x),
                (Var("o"), v::with_claims.id(), Var("w")),
            ],
            &[],
        ),
        // L: what waits after the last record is the unit's leftover.
        rule(
            program,
            &[
                (Var("u"), v::last.id(), r),
                (a, v::state_after.id(), r),
                (a, v::waiting.id(), k),
            ],
            &[],
            &[(Var("u"), v::leftover.id(), k)],
        ),
    ]
}

enum Record {
    /// Places a node.
    Node,
    /// Places this node (a node shared by content with another placement).
    NodeAt(Id),
    /// Holds nothing, claims a bundle.
    Claims,
    /// Neither.
    Nothing,
}

/// A unit's records in order; the facts, the records, the node or bundle
/// each names (if any), the unit entity and the words.
struct Unit {
    facts: TribleSet,
    named: Vec<Option<Id>>,
    unit: Id,
    words: Words,
}

fn unit(records: &[Record]) -> Unit {
    let words = Words {
        node: id(),
        claims: id(),
        nothing: id(),
        nil: id(),
    };
    unit_with(records, words)
}

fn unit_with(records: &[Record], words: Words) -> Unit {
    let mut facts = TribleSet::new();
    let u = id();
    let mut previous: Option<Id> = None;
    let mut named = Vec::new();
    for record in records {
        let r = id();
        match record {
            Record::Node | Record::NodeAt(_) => {
                let x = match record {
                    Record::NodeAt(x) => *x,
                    _ => id(),
                };
                put(&mut facts, r, v::kind.id(), words.node);
                put(&mut facts, r, v::first_node.id(), x);
                named.push(Some(x));
            }
            Record::Claims => {
                let w = id();
                put(&mut facts, r, v::kind.id(), words.claims);
                put(&mut facts, r, v::claims.id(), w);
                named.push(Some(w));
            }
            Record::Nothing => {
                put(&mut facts, r, v::kind.id(), words.nothing);
                named.push(None);
            }
        }
        match previous {
            None => put(&mut facts, u, v::first.id(), r),
            Some(p) => put(&mut facts, p, v::next.id(), r),
        }
        previous = Some(r);
    }
    if let Some(r) = previous {
        put(&mut facts, u, v::last.id(), r);
    }
    Unit {
        facts,
        named,
        unit: u,
        words,
    }
}

fn run(unit: &Unit) -> TribleSet {
    let mut program = TribleSet::new();
    let rules = pending(&mut program, &unit.words);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(&unit.facts);
    env.select(rules);
    for _ in 0..100 {
        if env.advance(1_000).expect("the program runs").progress == Progress::Quiescent {
            return env.facts().clone();
        }
    }
    panic!("the pending-claims rules did not quiesce");
}

/// The claims of the occurrences of `node`.
fn extras(facts: &TribleSet, node: Id) -> BTreeSet<Id> {
    find!(
        w: Id,
        pattern!(facts, [{ _?o @ v::occurrence_of: node, v::with_claims: ?w }])
    )
    .collect()
}

/// The deliveries to `node`: (record, bundle).
fn deliveries(facts: &TribleSet, node: Id) -> BTreeSet<(Id, Id)> {
    find!(
        (r: Id, w: Id),
        pattern!(facts, [{
            _?q @ v::delivered_by: ?r, v::delivered_node: node, v::delivered_bundle: ?w
        }])
    )
    .collect()
}

fn leftover(facts: &TribleSet, unit: Id) -> BTreeSet<Id> {
    find!(k: Id, pattern!(facts, [{ unit @ v::leftover: ?k }])).collect()
}

fn named(unit: &Unit, at: usize) -> Id {
    unit.named[at].expect("the record names a node or bundle")
}

/// G0's shape: a header line's claims (w0) go to the first node; two
/// claiming records in a row (w1, w2), with a record of neither between
/// them, both go to the next node; nothing is left waiting.
#[test]
fn waiting_claims_go_to_the_next_node_placed() {
    let unit = unit(&[
        Record::Claims,
        Record::Node,
        Record::Claims,
        Record::Nothing,
        Record::Claims,
        Record::Node,
    ]);
    let facts = run(&unit);
    let (w0, x1, w1, w2, x2) = (
        named(&unit, 0),
        named(&unit, 1),
        named(&unit, 2),
        named(&unit, 4),
        named(&unit, 5),
    );
    assert_eq!(extras(&facts, x1), BTreeSet::from([w0]));
    assert_eq!(extras(&facts, x2), BTreeSet::from([w1, w2]));
    // The reading: nothing is left over, so the unit stands.
    assert_eq!(
        leftover(&facts, unit.unit),
        BTreeSet::from([unit.words.nil])
    );
}

/// X19: claims after the last node wait beyond the end of the file. The
/// rules derive the leftover; the reading refuses the unit, since it has
/// placed a node and its leftover is not nil.
#[test]
fn claims_after_the_last_node_are_left_over() {
    let unit = unit(&[Record::Node, Record::Claims]);
    let facts = run(&unit);
    let x = named(&unit, 0);
    let w = named(&unit, 1);
    assert!(
        extras(&facts, x).is_empty(),
        "a claim never goes back to an earlier node"
    );
    let left = leftover(&facts, unit.unit);
    assert_eq!(left.len(), 1);
    let cell = *left.iter().next().unwrap();
    assert_ne!(
        cell, unit.words.nil,
        "the reading refuses: claims still wait"
    );
    let tops: BTreeSet<Id> = find!(t: Id, pattern!(&facts, [{ cell @ v::top: ?t }])).collect();
    assert_eq!(tops, BTreeSet::from([w]));
}

/// One node, shared by its content, placed in two units: each unit's record
/// delivers its own waiting claims, and the deliveries keep apart which
/// record delivered which. The occurrences name no record: a bundle
/// delivered to the node by two records is one occurrence, with two
/// deliveries.
#[test]
fn deliveries_to_one_shared_node_keep_their_records_apart() {
    let x = id();
    let shared = Words {
        node: id(),
        claims: id(),
        nothing: id(),
        nil: id(),
    };
    let words = || Words {
        node: shared.node,
        claims: shared.claims,
        nothing: shared.nothing,
        nil: shared.nil,
    };
    let one = unit_with(&[Record::Claims, Record::NodeAt(x)], words());
    let two = unit_with(&[Record::Claims, Record::NodeAt(x)], words());
    let (w1, w2) = (named(&one, 0), named(&two, 0));
    let record_at = |unit: &Unit, k: usize| -> Id {
        let node = named(unit, k);
        let found: Vec<Id> = find!(
            r: Id,
            pattern!(&unit.facts, [{ ?r @ v::first_node: node }])
        )
        .collect();
        assert_eq!(found.len(), 1);
        found[0]
    };
    let (r1, r2) = (record_at(&one, 1), record_at(&two, 1));
    let mut both = Unit {
        facts: one.facts.clone(),
        named: Vec::new(),
        unit: one.unit,
        words: words(),
    };
    both.facts += two.facts.clone();
    let facts = run(&both);
    assert_eq!(deliveries(&facts, x), BTreeSet::from([(r1, w1), (r2, w2)]));
    assert_eq!(extras(&facts, x), BTreeSet::from([w1, w2]));

    // The same bundle delivered by both records: two deliveries, one
    // occurrence.
    let mut same = both.facts.clone();
    let rp1: Vec<Id> = find!(r: Id, pattern!(&one.facts, [{ ?r @ v::claims: w1 }])).collect();
    let rp2: Vec<Id> = find!(r: Id, pattern!(&two.facts, [{ ?r @ v::claims: w2 }])).collect();
    let w = id();
    for r in rp1.into_iter().chain(rp2) {
        same.insert(&Trible::force(&r, &v::claims.id(), &raw(w)));
    }
    let facts = run(&Unit {
        facts: same,
        named: Vec::new(),
        unit: one.unit,
        words: words(),
    });
    let delivered_w: BTreeSet<Id> = find!(
        r: Id,
        pattern!(&facts, [{
            _?q @ v::delivered_by: ?r, v::delivered_node: x, v::delivered_bundle: w
        }])
    )
    .collect();
    assert_eq!(delivered_w, BTreeSet::from([r1, r2]));
    let occurrences: Vec<Id> = find!(
        o: Id,
        pattern!(&facts, [{ ?o @ v::occurrence_of: x, v::with_claims: w }])
    )
    .collect();
    assert_eq!(occurrences.len(), 1, "one occurrence of (x, w)");
}
