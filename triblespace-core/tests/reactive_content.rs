use triblespace_core::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema as r, Environment, Error, Progress, ReadAdvanceError};
use triblespace_core::trible::Trible;

fn id() -> Id {
    *genid()
}
fn edge(f: &mut TribleSet, e: Id, a: Id, v: Id) {
    let v: Inline<GenId> = v.to_inline();
    f.insert(&Trible::force(&e, &a, &v));
}
fn value(f: &mut TribleSet, e: Id, a: Id, v: Inline<Handle<UTF8String>>) {
    f.insert(&Trible::force(&e, &a, &v));
}
fn clause(f: &mut TribleSet, rule: Id, relation: Id, s: Id, a: Id, o: Id) {
    let c = id();
    edge(f, rule, relation, c);
    edge(f, c, r::subject.id(), s);
    edge(f, c, r::predicate.id(), a);
    edge(f, c, r::object.id(), o);
}
struct Fixture {
    facts: TribleSet,
    rule: Id,
    constraint: Id,
    container: Id,
    needle: Id,
    input: Id,
    sought: Id,
    output: Id,
}
impl Fixture {
    fn new() -> Self {
        let mut f = Self {
            facts: TribleSet::new(),
            rule: id(),
            constraint: id(),
            container: id(),
            needle: id(),
            input: id(),
            sought: id(),
            output: id(),
        };
        let subject = id();
        edge(&mut f.facts, f.rule, r::operation.id(), r::POSITIVE);
        clause(
            &mut f.facts,
            f.rule,
            r::matches.id(),
            subject,
            f.input,
            f.container,
        );
        clause(
            &mut f.facts,
            f.rule,
            r::matches.id(),
            subject,
            f.sought,
            f.needle,
        );
        clause(
            &mut f.facts,
            f.rule,
            r::emits.id(),
            subject,
            f.output,
            f.container,
        );
        edge(&mut f.facts, f.rule, r::constraints.id(), f.constraint);
        edge(
            &mut f.facts,
            f.constraint,
            r::operation.id(),
            r::STRING_CONTAINS,
        );
        edge(&mut f.facts, f.constraint, r::container.id(), f.container);
        edge(&mut f.facts, f.constraint, r::needle.id(), f.needle);
        f
    }
    fn pair(
        &mut self,
        container: Inline<Handle<UTF8String>>,
        needle: Inline<Handle<UTF8String>>,
    ) -> Id {
        let subject = id();
        value(&mut self.facts, subject, self.input, container);
        value(&mut self.facts, subject, self.sought, needle);
        subject
    }
    fn env(&self) -> Environment {
        let mut env = Environment::new();
        env.extend(&self.facts);
        env.select([self.rule]);
        env
    }
    fn emitted(&self, env: &Environment, subject: Id) -> bool {
        exists!(temp!(
            (v),
            env.facts().pattern::<Handle<UTF8String>>(
                subject.to_inline(),
                self.output.to_inline(),
                v
            )
        ))
    }
}
fn text(store: &mut MemoryBlobStore, s: &str) -> Inline<Handle<UTF8String>> {
    store.put(s).unwrap()
}

#[test]
fn exact_utf8_contains_empty_and_case_without_normalization() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let cases = [
        ("a🦊é中z", "🦊é中", true),
        ("", "", true),
        ("hello", "", true),
        ("", "a", false),
        ("Hello", "hello", false),
        ("café", "cafe\u{301}", false),
        ("abc", "d", false),
    ];
    let subjects: Vec<_> = cases
        .iter()
        .map(|(a, b, expected)| (f.pair(text(&mut store, a), text(&mut store, b)), *expected))
        .collect();
    let mut env = f.env();
    let result = env
        .advance_with_reader(20, &store.snapshot().unwrap())
        .unwrap();
    assert_eq!(result.progress, Progress::Quiescent);
    assert_eq!(result.firings.len(), 3);
    for (subject, expected) in subjects {
        assert_eq!(f.emitted(&env, subject), expected);
    }
}

#[test]
fn absent_reader_then_missing_content_retries_same_binding_with_new_snapshot() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let needle = text(&mut store, "needle");
    let subject = f.pair("hay needle hay".to_inline(), needle);
    let mut env = f.env();
    assert_eq!(
        env.advance(1).unwrap_err(),
        Error::MissingContentReader {
            revision: f.rule,
            constraint: f.constraint
        }
    );
    for _ in 0..2 {
        let error = env
            .advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap_err();
        assert!(triblespace_core::repo::is_missing_blob(&error));
        assert!(matches!(error, ReadAdvanceError::Content { term, .. } if term==f.container));
    }
    assert!(!f.emitted(&env, subject));
    text(&mut store, "hay needle hay");
    assert_eq!(
        env.advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    assert!(f.emitted(&env, subject));
    assert_eq!(env.advance(10).unwrap().progress, Progress::Quiescent);
}

#[test]
fn empty_needle_does_not_hide_missing_container_or_needle() {
    for missing_container in [true, false] {
        let mut f = Fixture::new();
        let mut store = MemoryBlobStore::new();
        if missing_container {
            text(&mut store, "");
        } else {
            text(&mut store, "container");
        }
        f.pair("container".to_inline(), "".to_inline());
        let error = f
            .env()
            .advance_with_reader(10, &store.snapshot().unwrap())
            .unwrap_err();
        assert!(
            matches!(error,ReadAdvanceError::Content {term,..} if term == if missing_container {f.container} else {f.needle})
        );
    }
}

#[test]
fn invalid_utf8_is_a_typed_error_and_remains_retryable() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let raw: Inline<Handle<RawBytes>> = store.put(vec![0xff_u8]).unwrap();
    let needle = text(&mut store, "");
    let subject = f.pair(raw.transmute(), needle);
    let mut env = f.env();
    for _ in 0..2 {
        let error = env
            .advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap_err();
        assert!(!triblespace_core::repo::is_missing_blob(&error));
        match error {
            ReadAdvanceError::Content { source, .. } => {
                assert!(std::error::Error::source(&source)
                    .unwrap()
                    .is::<anybytes::view::ViewError>());
            }
            _ => panic!("expected UTF-8 decoding error"),
        }
    }
    assert!(!f.emitted(&env, subject));
}

#[test]
fn failed_seed_and_delta_keep_frontier_while_new_observations_arrive() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let needle = text(&mut store, "yes");
    let first = f.pair("first yes".to_inline(), needle);
    let mut env = f.env();
    assert!(env
        .advance_with_reader(1, &store.snapshot().unwrap())
        .is_err());
    let second = f.pair(text(&mut store, "second yes"), needle);
    env.extend(&f.facts);
    text(&mut store, "first yes");
    assert_eq!(
        env.advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    assert_eq!(
        env.advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    assert_eq!(
        env.advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap()
            .progress,
        Progress::Quiescent
    );
    let third = f.pair("third yes".to_inline(), needle);
    env.extend(&f.facts);
    assert!(env
        .advance_with_reader(1, &store.snapshot().unwrap())
        .is_err());
    let fourth = f.pair(text(&mut store, "fourth yes"), needle);
    env.extend(&f.facts);
    text(&mut store, "third yes");
    let mut count = 2;
    loop {
        let a = env
            .advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap();
        count += a.firings.len();
        if a.progress == Progress::Quiescent {
            break;
        }
        assert!(count <= 4);
    }
    assert_eq!(count, 4);
    for subject in [first, second, third, fourth] {
        assert!(f.emitted(&env, subject));
    }
}

#[test]
fn completed_binding_needs_no_blobs_when_reselection_rediscovers_it() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let v = text(&mut store, "same");
    let subject = f.pair(v, v);
    // Reselection seeds old facts but retains the complete-binding memo.
    let mut env = f.env();
    assert_eq!(
        env.advance_with_reader(10, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    env.select([]);
    env.select([f.rule]);
    let mut empty = MemoryBlobStore::new();
    assert_eq!(
        env.advance_with_reader(10, &empty.snapshot().unwrap())
            .unwrap()
            .progress,
        Progress::Quiescent
    );
    assert!(f.emitted(&env, subject));
}

#[test]
fn literal_only_same_term_predicate_and_unknown_annotations_are_valid() {
    let (rule, c, t) = (id(), id(), id());
    let mut facts = TribleSet::new();
    edge(&mut facts, rule, r::operation.id(), r::POSITIVE);
    edge(&mut facts, rule, r::constraints.id(), c);
    edge(&mut facts, c, r::operation.id(), r::STRING_CONTAINS);
    edge(&mut facts, c, r::container.id(), t);
    edge(&mut facts, c, r::needle.id(), t);
    edge(&mut facts, c, id(), id());
    let mut store = MemoryBlobStore::new();
    value(&mut facts, t, r::literal.id(), text(&mut store, "same"));
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([rule]);
    assert_eq!(
        env.advance_with_reader(10, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    edge(&mut facts, id(), id(), id());
    env.extend(&facts);
    assert_eq!(env.advance(10).unwrap().progress, Progress::Quiescent);
}

#[test]
fn every_complete_content_tuple_is_a_conjunct() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let n2 = id();
    value(
        &mut f.facts,
        n2,
        r::literal.id(),
        text(&mut store, "missing"),
    );
    edge(&mut f.facts, f.constraint, r::needle.id(), n2);
    f.pair(text(&mut store, "has needle"), text(&mut store, "needle"));
    assert!(f
        .env()
        .advance_with_reader(10, &store.snapshot().unwrap())
        .unwrap()
        .firings
        .is_empty());
}

#[test]
fn selected_program_errors_do_not_become_predicate_false() {
    let mut f = Fixture::new();
    let unknown = id();
    edge(&mut f.facts, f.constraint, r::operation.id(), unknown);
    assert!(
        matches!(f.env().advance(1),Err(Error::UnsupportedConstraint {operation,..}) if operation==unknown)
    );
    let mut f = Fixture::new();
    let incomplete = id();
    edge(&mut f.facts, f.rule, r::constraints.id(), incomplete);
    assert_eq!(
        f.env().advance(1).unwrap_err(),
        Error::IncompleteConstraint {
            revision: f.rule,
            constraint: incomplete
        }
    );
    let mut f = Fixture::new();
    let unbound = id();
    edge(&mut f.facts, f.constraint, r::needle.id(), unbound);
    assert_eq!(
        f.env().advance(1).unwrap_err(),
        Error::UnboundContentTerm {
            revision: f.rule,
            constraint: f.constraint,
            term: unbound
        }
    );
}

#[test]
fn rules_without_content_need_no_reader_even_when_one_is_supplied() {
    let rule = id();
    let mut facts = TribleSet::new();
    edge(&mut facts, rule, r::operation.id(), r::POSITIVE);
    let mut env = Environment::new();
    env.extend(&facts);
    env.select([rule]);
    assert_eq!(env.advance(1).unwrap().firings.len(), 1);
    let mut empty = MemoryBlobStore::new();
    assert_eq!(
        env.advance_with_reader(1, &empty.snapshot().unwrap())
            .unwrap()
            .progress,
        Progress::Quiescent
    );
}

// A backend detects content-address corruption before constructing a Blob.
// This injects that trust-boundary error; it does not test a pile's validator.
struct CorruptReader;
impl BlobStoreGet for CorruptReader {
    type GetError<E: std::error::Error + Send + Sync + 'static> = std::io::Error;
    fn get<T, S>(&self, _handle: Inline<Handle<S>>) -> Result<T, Self::GetError<T::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: triblespace_core::inline::InlineEncoding,
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "content hash mismatch",
        ))
    }
}

#[test]
fn backend_corruption_error_is_preserved_and_can_retry_with_valid_reader() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    let subject = f.pair(text(&mut store, "contains"), text(&mut store, "tain"));
    let mut env = f.env();
    let error = env.advance_with_reader(1, &CorruptReader).unwrap_err();
    assert!(!triblespace_core::repo::is_missing_blob(&error));
    match error {
        ReadAdvanceError::Content { source, .. } => {
            assert_eq!(source.kind(), std::io::ErrorKind::InvalidData)
        }
        _ => panic!("expected backend corruption error"),
    }
    assert!(!f.emitted(&env, subject));
    assert_eq!(
        env.advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap()
            .firings
            .len(),
        1
    );
    assert!(f.emitted(&env, subject));
}

#[test]
fn failed_output_keeps_accepted_binding_without_requiring_content_again() {
    let mut f = Fixture::new();
    let mut store = MemoryBlobStore::new();
    f.pair(text(&mut store, "contains"), text(&mut store, "tain"));
    clause(
        &mut f.facts,
        f.rule,
        r::core.id(),
        f.container,
        id(),
        f.needle,
    );
    let mut env = f.env();
    let expected = Error::BoundCore {
        revision: f.rule,
        term: f.container,
    };
    assert!(
        matches!(env.advance_with_reader(1,&store.snapshot().unwrap()),Err(ReadAdvanceError::Program(ref e)) if *e==expected)
    );
    assert_eq!(env.advance(1).unwrap_err(), expected);
}
