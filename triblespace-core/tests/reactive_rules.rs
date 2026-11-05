use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema as r, Environment, Error, Progress};
use triblespace_core::trible::{build_intrinsic_entity, IntrinsicEntityRow, Trible};

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
fn new_rule_sees_old_observations_new_observation_sees_rule_and_rules_compose() {
    let (a, b, c, x, y, z) = (id(), id(), id(), id(), id(), id());
    let mut env = Environment::new();
    let mut data = TribleSet::new();
    edge(&mut data, x, a, y);
    env.extend(&data);
    assert_eq!(env.advance(10).unwrap().progress, Progress::Quiescent);
    let mut program = TribleSet::new();
    let first = copy_rule(&mut program, a, b);
    let second = copy_rule(&mut program, b, c);
    env.extend(&program);
    env.select([first, second]);
    let run = env.advance(10).unwrap();
    assert_eq!(run.progress, Progress::Quiescent);
    assert_eq!(run.firings.len(), 2);
    assert!(contains(env.facts(), x, c, y));
    edge(&mut data, x, a, z);
    env.extend(&data);
    let run = env.advance(10).unwrap();
    assert_eq!(run.firings.len(), 2);
    assert!(contains(env.facts(), x, c, z));
}

#[test]
fn full_bindings_survive_equal_clause_coverage_and_duplicates_annotations() {
    let (a, b, x, y, z) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = copy_rule(&mut facts, a, b);
    edge(&mut facts, x, a, y);
    edge(&mut facts, x, a, z);
    edge(&mut facts, revision, id(), id()); // unrelated open-world annotation
    let mut env = Environment::new();
    env.select([revision]);
    env.extend(&facts);
    env.extend(&facts);
    let run = env.advance(10).unwrap();
    assert_eq!(run.firings.len(), 2);
    assert_ne!(run.firings[0].binding, run.firings[1].binding);
    assert!(contains(env.facts(), x, b, y));
    assert!(contains(env.facts(), x, b, z));
    env.extend(&facts);
    assert!(env.advance(10).unwrap().firings.is_empty());
}

#[test]
fn native_join_and_same_term_positions_retain_equality() {
    let (a, b, out, x, y, z) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, revision, r::matches.id(), s, a, o);
    clause(&mut facts, revision, r::matches.id(), o, b, o);
    clause(&mut facts, revision, r::emits.id(), s, out, o);
    edge(&mut facts, x, a, y);
    edge(&mut facts, x, a, z);
    edge(&mut facts, y, b, y);
    edge(&mut facts, z, b, y);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    assert_eq!(env.advance(10).unwrap().firings.len(), 1);
    assert!(contains(env.facts(), x, out, y));
    assert!(!contains(env.facts(), x, out, z));
}

#[test]
fn literal_alternatives_are_native_values_not_cardinality_errors() {
    let (a, out, x, y, z, other) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, revision, r::matches.id(), s, a, o);
    clause(&mut facts, revision, r::emits.id(), s, out, o);
    for v in [y, z] {
        edge(&mut facts, o, r::literal.id(), v);
    }
    for v in [y, z, other] {
        edge(&mut facts, x, a, v);
    }
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    assert_eq!(env.advance(10).unwrap().firings.len(), 2);
    assert!(!contains(env.facts(), x, out, other));
}

#[test]
fn dag_forks_are_visible_and_execution_reading_is_explicit() {
    let (a, old_out, left_out, right_out, x, y) = (id(), id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let base = copy_rule(&mut facts, a, old_out);
    let left = copy_rule(&mut facts, a, left_out);
    let right = copy_rule(&mut facts, a, right_out);
    edge(
        &mut facts,
        left,
        triblespace_core::metadata::supersedes.id(),
        base,
    );
    edge(
        &mut facts,
        right,
        triblespace_core::metadata::supersedes.id(),
        base,
    );
    edge(&mut facts, x, a, y);
    let mut env = Environment::new();
    env.extend(&facts);
    assert_eq!(
        env.heads([base, left, right]),
        [left, right].into_iter().collect()
    );
    assert!(env.advance(10).unwrap().firings.is_empty());
    env.select([left]);
    env.advance(10).unwrap();
    assert!(contains(env.facts(), x, left_out, y));
    assert!(!contains(env.facts(), x, right_out, y));
    env.select([right]);
    env.advance(10).unwrap();
    assert!(contains(env.facts(), x, left_out, y));
    assert!(contains(env.facts(), x, right_out, y));
    // A historical reading is explicit too, not made invisible by supersession.
    env.select([base]);
    env.advance(10).unwrap();
    assert!(contains(env.facts(), x, old_out, y));
}

#[test]
fn content_core_converges_across_rules_and_restart_annotations_do_not_salt_it() {
    let (input, field, annotation, x, y) = (id(), id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let mut revisions = Vec::new();
    for _ in 0..2 {
        let revision = rule(&mut facts);
        revisions.push(revision);
        let (s, value, output, marker) = (id(), id(), id(), id());
        clause(&mut facts, revision, r::matches.id(), s, input, value);
        clause(&mut facts, revision, r::core.id(), output, field, value);
        clause(
            &mut facts,
            revision,
            r::emits.id(),
            output,
            annotation,
            marker,
        );
        edge(&mut facts, marker, r::literal.id(), id());
    }
    edge(&mut facts, x, input, y);
    let (expected, _) = build_intrinsic_entity(vec![IntrinsicEntityRow::new(
        field,
        IntoInline::<inlineencodings::GenId>::to_inline(y).raw,
    )]);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select(revisions.clone());
    let run = env.advance(10).unwrap();
    assert_eq!(run.firings.len(), 2);
    for firing in run.firings {
        assert_eq!(
            firing.constructed.values().copied().collect::<Vec<_>>(),
            vec![expected]
        );
    }
    let mut reopened = Environment::new();
    reopened.extend(env.facts());
    reopened.select(revisions);
    reopened.advance(10).unwrap();
    assert_eq!(reopened.facts(), env.facts());
}

#[test]
fn finite_budget_reports_pending_and_resumes_even_for_divergent_construction() {
    let (link, start, end) = (id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o, new) = (id(), id(), id());
    clause(&mut facts, revision, r::matches.id(), s, link, o);
    clause(&mut facts, revision, r::core.id(), new, link, s);
    edge(&mut facts, start, link, end);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    assert_eq!(env.advance(0).unwrap().progress, Progress::Pending);
    for _ in 0..3 {
        let run = env.advance(2).unwrap();
        assert_eq!(run.progress, Progress::Pending);
        assert_eq!(run.firings.len(), 2);
    }
    assert_eq!(
        find!((s: Id, o: Id), env.facts().pattern(s, link.to_inline(), o)).count(),
        7
    );
}

#[test]
fn unsupported_selected_operation_is_explicit_unselected_rule_harmless() {
    let mut facts = TribleSet::new();
    let revision = id();
    let unknown = id();
    edge(&mut facts, revision, r::operation.id(), unknown);
    let mut env = Environment::new();
    env.extend(&facts);
    assert_eq!(env.advance(1).unwrap().progress, Progress::Quiescent);
    env.select([revision]);
    assert_eq!(
        env.advance(1).unwrap_err(),
        Error::UnsupportedOperation {
            revision,
            operation: unknown
        }
    );
}

#[test]
fn prebound_cycle_is_data_unresolved_content_cycle_is_selected_diagnostic() {
    let (link, x) = (id(), id());
    let mut facts = TribleSet::new();
    let copy = copy_rule(&mut facts, link, id());
    edge(&mut facts, x, link, x);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([copy]);
    assert_eq!(env.advance(10).unwrap().firings.len(), 1);
    let bad = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, bad, r::core.id(), s, link, o);
    clause(&mut facts, bad, r::core.id(), o, link, s);
    env.extend(&facts);
    env.select([bad]);
    assert_eq!(
        env.advance(1).unwrap_err(),
        Error::UnresolvedTerms {
            revision: bad,
            terms: [s, o].into_iter().collect()
        }
    );
}

#[test]
fn full_width_native_values_copy_byte_exactly_and_match_literal_alternatives() {
    let (input, output, source) = (id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, revision, r::matches.id(), s, input, o);
    clause(&mut facts, revision, r::emits.id(), s, output, o);
    // Nonzero in both halves, deliberately not a padded GenId.
    let raw = Inline::<UnknownInline>::new(std::array::from_fn(|i| i as u8 + 1));
    let other = Inline::<UnknownInline>::new([0xa5; 32]);
    put(&mut facts, o, r::literal.id(), raw);
    put(&mut facts, source, input, raw);
    put(&mut facts, source, input, other);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    assert_eq!(env.advance(10).unwrap().firings.len(), 1);
    assert!(exists!(env.facts().pattern::<UnknownInline>(
        source.to_inline(),
        output.to_inline(),
        raw
    )));
    assert!(!exists!(env.facts().pattern::<UnknownInline>(
        source.to_inline(),
        output.to_inline(),
        other
    )));
}

#[test]
fn core_construction_never_validates_or_replaces_a_prebound_opaque_id() {
    let (input, field, source, value) = (id(), id(), id(), id());
    let mut facts = TribleSet::new();
    let revision = rule(&mut facts);
    let (s, o) = (id(), id());
    clause(&mut facts, revision, r::matches.id(), s, input, o);
    clause(&mut facts, revision, r::core.id(), s, field, o);
    edge(&mut facts, source, input, value);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([revision]);
    assert_eq!(
        env.advance(10).unwrap_err(),
        Error::BoundCore { revision, term: s }
    );
    assert_eq!(env.facts(), &facts);
}
