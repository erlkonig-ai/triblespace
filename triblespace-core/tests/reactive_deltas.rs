// Compile the exact production source with its private cfg(test) counter.
// This keeps the lean integration closure independent of unrelated library
// unit modules that require optional proptest, without adding a public metric.
pub use triblespace_core::{collection, id, id_hex, import, inline, macros, metadata, prelude, query, repo, trible};
#[path = "../src/reactive.rs"]
#[allow(dead_code)]
mod native_under_test;

use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema as r, Environment, Error, Progress};
use triblespace_core::trible::Trible;

fn id() -> Id {
    *genid()
}
fn put(facts: &mut TribleSet, e: Id, a: Id, value: Inline<UnknownInline>) {
    facts.insert(&Trible::force(&e, &a, &value));
}
fn edge(facts: &mut TribleSet, e: Id, a: Id, v: Id) {
    let value: Inline<inlineencodings::GenId> = v.to_inline();
    put(facts, e, a, value.transmute());
}
fn clause(facts: &mut TribleSet, rule: Id, relation: Id, s: Id, a: Id, o: Id) {
    let c = id();
    edge(facts, rule, relation, c);
    edge(facts, c, r::subject.id(), s);
    edge(facts, c, r::predicate.id(), a);
    edge(facts, c, r::object.id(), o);
}
fn rule(facts: &mut TribleSet) -> Id {
    let rule = id();
    edge(facts, rule, r::operation.id(), r::POSITIVE);
    rule
}
fn copy_rule(facts: &mut TribleSet, input: Id, output: Id) -> Id {
    let rule = rule(facts);
    let (x, y) = (id(), id());
    clause(facts, rule, r::matches.id(), x, input, y);
    clause(facts, rule, r::emits.id(), x, output, y);
    rule
}
fn contains(facts: &TribleSet, e: Id, a: Id, v: Id) -> bool {
    exists!(facts.pattern::<inlineencodings::GenId>(e.to_inline(), a.to_inline(), v.to_inline()))
}

#[test]
fn either_join_position_can_supply_delta_and_all_branches_keep_alternatives() {
    let (a, b, out, x, y, z, w) = (id(), id(), id(), id(), id(), id(), id());
    let mut program = TribleSet::new();
    let revision = rule(&mut program);
    let (s, middle, o) = (id(), id(), id());
    clause(&mut program, revision, r::matches.id(), s, a, middle);
    clause(&mut program, revision, r::matches.id(), middle, b, o);
    clause(&mut program, revision, r::emits.id(), s, out, o);
    let mut env = Environment::new();
    env.extend(&program);
    env.select([revision]);
    assert_eq!(env.advance(20).unwrap().progress, Progress::Quiescent);
    let mut data = TribleSet::new();
    edge(&mut data, x, a, y);
    env.extend(&data);
    assert!(env.advance(20).unwrap().firings.is_empty());
    edge(&mut data, y, b, z); // second clause is the only new witness
    env.extend(&data);
    assert_eq!(env.advance(20).unwrap().firings.len(), 1);
    edge(&mut data, w, a, y); // first clause is the only new witness
    env.extend(&data);
    assert_eq!(env.advance(20).unwrap().firings.len(), 1);
    assert!(contains(env.facts(), w, out, z));
    let (u, v) = (id(), id());
    edge(&mut data, u, a, y);
    edge(&mut data, y, b, v); // both branches; (u,v) must appear only once
    env.extend(&data);
    let run = env.advance(20).unwrap();
    assert_eq!(run.firings.len(), 4); // u-z, u-v, x-v, w-v
    assert_eq!(
        run.firings
            .iter()
            .map(|f| &f.binding)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
}

#[test]
fn one_fact_can_witness_several_clauses_without_losing_cross_product_bindings() {
    let (a, out, x, y, z) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, left, right) = (id(), id(), id());
    clause(&mut facts, revision, r::matches.id(), s, a, left);
    clause(&mut facts, revision, r::matches.id(), s, a, right);
    clause(&mut facts, revision, r::emits.id(), s, out, right);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    env.advance(20).unwrap();
    edge(&mut facts, x, a, y);
    env.extend(&facts);
    assert_eq!(env.advance(20).unwrap().firings.len(), 1);
    edge(&mut facts, x, a, z);
    env.extend(&facts);
    let run = env.advance(20).unwrap();
    assert_eq!(run.firings.len(), 3); // y-z, z-y, z-z; y-y is old
    assert_eq!(
        run.firings
            .iter()
            .map(|f| &f.binding)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}

#[test]
fn pending_seed_and_delta_batches_resume_and_include_later_observations() {
    let (a, out, x) = (id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = copy_rule(&mut facts, a, out);
    let values: Vec<_> = (0..9).map(|_| id()).collect();
    for &v in &values[..3] {
        edge(&mut facts, x, a, v);
    }
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    let mut count = env.advance(1).unwrap().firings.len();
    for &v in &values[3..6] {
        edge(&mut facts, x, a, v);
    }
    env.extend(&facts); // while seed batch is pending
    for _ in 0..3 {
        count += env.advance(1).unwrap().firings.len();
    }
    for &v in &values[6..] {
        edge(&mut facts, x, a, v);
    }
    env.extend(&facts); // while the first delta batch is pending
    loop {
        let run = env.advance(1).unwrap();
        count += run.firings.len();
        if run.progress == Progress::Quiescent {
            break;
        }
        assert!(count <= values.len());
    }
    assert_eq!(count, values.len());
    for v in values {
        assert!(contains(env.facts(), x, out, v));
    }
}

#[test]
fn recursive_transitive_closure_matches_fresh_seed_at_each_extension() {
    let (edge_attr, reach) = (id(), id());
    let mut program = TribleSet::new();
    let seed = copy_rule(&mut program, edge_attr, reach);
    let recursive = rule(&mut program);
    let (s, m, o) = (id(), id(), id());
    clause(&mut program, recursive, r::matches.id(), s, reach, m);
    clause(&mut program, recursive, r::matches.id(), m, reach, o);
    clause(&mut program, recursive, r::emits.id(), s, reach, o);
    let nodes: Vec<_> = (0..6).map(|_| id()).collect();
    let mut data = TribleSet::new();
    let mut env = Environment::new();
    env.extend(&program);
    env.select([seed, recursive]);
    env.advance(100).unwrap();
    for i in 0..5 {
        edge(&mut data, nodes[i], edge_attr, nodes[i + 1]);
        env.extend(&data);
        assert_eq!(env.advance(200).unwrap().progress, Progress::Quiescent);
        // A new environment full-seeds the same rules and source observations.
        let mut from_scratch = Environment::new();
        from_scratch.extend(&program);
        from_scratch.extend(&data);
        from_scratch.select([seed, recursive]);
        assert_eq!(
            from_scratch.advance(200).unwrap().progress,
            Progress::Quiescent
        );
        assert_eq!(env.facts(), from_scratch.facts());
        assert_eq!(find!((s: Id, o: Id), env.facts().pattern::<inlineencodings::GenId>(s, reach.to_inline(), o)).count(), (i+1)*(i+2)/2);
        for start in 0..=i {
            for end in start + 1..=i + 1 {
                assert!(contains(env.facts(), nodes[start], reach, nodes[end]));
            }
        }
    }
}

#[test]
fn newly_selected_rule_seeds_old_facts_and_reselection_catches_missed_facts() {
    let (a, b, c, x, y, z, w) = (id(), id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let first = copy_rule(&mut facts, a, b);
    let second = copy_rule(&mut facts, b, c);
    edge(&mut facts, x, a, y);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([first]);
    env.advance(20).unwrap();
    env.select([first, second]);
    assert_eq!(env.advance(20).unwrap().firings.len(), 1);
    env.select([]);
    edge(&mut facts, x, a, z);
    env.extend(&facts);
    assert!(env.advance(20).unwrap().firings.is_empty());
    env.select([first, second]);
    let paused = env.advance(1).unwrap();
    assert_eq!(paused.firings.len(), 1);
    env.select([]); // discard a pending batch, but preserve completed firing memo
    edge(&mut facts, x, a, w);
    env.extend(&facts);
    env.select([first, second]);
    assert_eq!(env.advance(20).unwrap().firings.len(), 3);
    for v in [y, z, w] {
        assert!(contains(env.facts(), x, c, v));
    }
}

#[test]
fn empty_and_constant_rules_quiesce_after_the_seed_even_with_new_unrelated_facts() {
    let mut facts = TribleSet::new();
    let empty = rule(&mut facts);
    let constant = rule(&mut facts);
    let (s, o, x, y, z, out) = (id(), id(), id(), id(), id(), id());
    clause(&mut facts, constant, r::emits.id(), s, out, o);
    edge(&mut facts, s, r::literal.id(), x);
    edge(&mut facts, o, r::literal.id(), y);
    edge(&mut facts, o, r::literal.id(), z);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([empty, constant]);
    let mut count = 0;
    for _ in 0..5 {
        let run = env.advance(1).unwrap();
        count += run.firings.len();
        if run.progress == Progress::Quiescent {
            break;
        }
    }
    assert_eq!(count, 3);
    assert_eq!(env.advance(10).unwrap().progress, Progress::Quiescent);
    edge(&mut facts, id(), id(), id());
    env.extend(&facts);
    assert!(env.advance(10).unwrap().firings.is_empty());
    env.extend(&facts); // duplicate-only extension has an empty native difference
    assert_eq!(env.advance(10).unwrap().progress, Progress::Quiescent);
    assert!(contains(env.facts(), x, out, y));
    assert!(contains(env.facts(), x, out, z));
}

#[test]
fn rule_round_robin_counts_available_firings_not_empty_delta_positions() {
    let (a, b, c, d, x, y) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let first = copy_rule(&mut facts, a, b);
    let second = copy_rule(&mut facts, c, d);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([first, second]);
    env.advance(10).unwrap();
    for _ in 0..8 {
        edge(&mut facts, id(), a, id());
    }
    edge(&mut facts, x, c, y);
    env.extend(&facts);
    let run = env.advance(2).unwrap();
    assert_eq!(run.firings.len(), 2);
    assert!(run.firings.iter().any(|f| f.revision == second));
    assert!(contains(env.facts(), x, d, y));
}

#[test]
fn failed_binding_remains_pending_without_replaying_completed_firings() {
    let (input, out, x, y) = (id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let good = copy_rule(&mut facts, input, out);
    let bad = rule(&mut facts);
    let (s, o, missing) = (id(), id(), id());
    clause(&mut facts, bad, r::matches.id(), s, input, o);
    clause(&mut facts, bad, r::emits.id(), s, out, missing);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([good, bad]);
    env.advance(10).unwrap(); // seed has no matches, so incomplete output is inert
    edge(&mut facts, x, input, y);
    env.extend(&facts);
    let error = env.advance(10).unwrap_err();
    assert!(matches!(error, Error::UnresolvedTerms { revision, .. } if revision == bad));
    assert_eq!(env.advance(10).unwrap_err(), error);
    env.select([good]);
    env.advance(10).unwrap();
    assert!(contains(env.facts(), x, out, y));
    assert!(env.advance(10).unwrap().firings.is_empty());
}

#[test]
fn delta_branches_preserve_self_equality_and_literal_alternatives() {
    let (a, b, out, x, y, z, other) = (id(), id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, revision, r::matches.id(), s, a, o);
    clause(&mut facts, revision, r::matches.id(), o, b, o);
    clause(&mut facts, revision, r::emits.id(), s, out, o);
    for value in [y, z] {
        edge(&mut facts, o, r::literal.id(), value);
    }
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    env.advance(10).unwrap();
    for value in [y, z, other] {
        edge(&mut facts, x, a, value);
    }
    edge(&mut facts, y, b, y);
    edge(&mut facts, z, b, y);
    edge(&mut facts, other, b, other);
    env.extend(&facts);
    assert_eq!(env.advance(10).unwrap().firings.len(), 1);
    assert!(contains(env.facts(), x, out, y));
    assert!(!contains(env.facts(), x, out, z));
    assert!(!contains(env.facts(), x, out, other));
    edge(&mut facts, z, b, z);
    env.extend(&facts);
    assert_eq!(env.advance(10).unwrap().firings.len(), 1);
    assert!(contains(env.facts(), x, out, z));
}
