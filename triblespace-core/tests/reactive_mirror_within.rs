//! Within mirrors, expressed as positive rule data using native STRING_CONTAINS.
//!
//! A dropped string is backed by a readable string at an allowed path in the
//! same unit, if that container is retained or positively backed under that
//! SAME unit/content reading. No line order is involved. Contains is exact,
//! case-sensitive UTF-8 substring matching, without normalization. Non-string
//! values have no equality fallback. Refusal of a complete unit with an
//! unbacked dropped reading belongs to its consumer, never to these rules.
//!
//! A witness's core records the current correlated step: copy, unit, copy text,
//! mirror spec, allowed path, container, container text and retained original.
//! Recursive support joins the container's unit AND text; the core records
//! spec/path context so different readings cannot manufacture each other's
//! proof. It does not include the preceding witness id: proofs terminate at
//! retained originals, and cycles cannot mint infinitely many proof chains.
//! This is existential rooted support, not a full proof history: alternative
//! intermediate supports or root-content readings may collapse once they
//! establish the same current step and retained-root occurrence.
//!
//! This bounded example is not production importer wiring. Expectations below
//! are hand-stated; no second matching interpreter computes the expected set.

use std::collections::BTreeSet;
use triblespace_core::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace_core::prelude::inlineencodings::{GenId, Handle, U256BE};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema as r, Environment, Progress, ReadAdvanceError};
use triblespace_core::trible::Trible;

type Text = Inline<Handle<UTF8String>>;

// Minted with the installed `trible genid`, 2026-11-05; transcript retained
// in reactive-within-minted-20261105.json alongside the review receipt.
mod v {
    use super::*;
    attributes! {
        "CF20595C20337DDB1005C6971B4F4F28" as pub in_unit: GenId;
        "1C541789CFA408722474B5723A93A12C" as pub at_path: GenId;
        "31F0525CF7448D2FEB0731316972F3E4" as pub text: Handle<UTF8String>;
        "85B94F2BEB18B7E67A60F98FEB15F094" as pub retained: GenId;
        "270A32C777C03EC72D586C60D3C6CFC3" as pub within: GenId;
        "8CB9C9DC3DF1A185E61AF4EBE7413416" as pub witness_spec: GenId;
        "A5C663F83E3F80B002BB00195F66C3F1" as pub from_path: GenId;
        "970FE3A89AB3D7D929F7E4B8A4BAEC74" as pub backs: GenId;
        "59164A5936548FFED1D02A29BF569F48" as pub container: GenId;
        "DA7CF1315BCDA8A22F7EADA6E755A86F" as pub container_text: Handle<UTF8String>;
        "51BA0ED8D96311B4E3FE46404A50861F" as pub original: GenId;
        "B316ACD8695CE594CDFEC02E3754B989" as pub number: U256BE;
    }
}

fn id() -> Id {
    *genid()
}
fn edge(f: &mut TribleSet, e: Id, a: Id, value: Id) {
    let value: Inline<GenId> = value.to_inline();
    f.insert(&Trible::force(&e, &a, &value));
}
fn text(f: &mut TribleSet, e: Id, value: Text) {
    f.insert(&Trible::force(&e, &v::text.id(), &value));
}

// This helper only serializes clauses. Matching, joins, content reads and
// intrinsic witness construction all belong to Environment's native rules.
fn rule(f: &mut TribleSet, matches: &[(&str, Id, &str)], core: &[(&str, Id, &str)]) -> Id {
    let revision = id();
    edge(f, revision, r::operation.id(), r::POSITIVE);
    let mut terms = std::collections::BTreeMap::new();
    for (relation, clauses) in [(r::matches.id(), matches), (r::core.id(), core)] {
        for &(s, a, o) in clauses {
            let s = *terms.entry(s).or_insert_with(id);
            let o = *terms.entry(o).or_insert_with(id);
            let clause = id();
            edge(f, revision, relation, clause);
            edge(f, clause, r::subject.id(), s);
            edge(f, clause, r::predicate.id(), a);
            edge(f, clause, r::object.id(), o);
        }
    }
    let constraint = id();
    edge(f, revision, r::constraints.id(), constraint);
    edge(f, constraint, r::operation.id(), r::STRING_CONTAINS);
    edge(f, constraint, r::container.id(), terms["hay"]);
    edge(f, constraint, r::needle.id(), terms["needle"]);
    revision
}

fn backing(f: &mut TribleSet) -> Vec<Id> {
    let candidate = [
        ("copy", v::within.id(), "spec"),
        ("spec", v::from_path.id(), "path"),
        ("copy", v::in_unit.id(), "unit"),
        ("copy", v::text.id(), "needle"),
        ("container", v::in_unit.id(), "unit"),
        ("container", v::at_path.id(), "path"),
        ("container", v::text.id(), "hay"),
    ];
    let witness = |original| {
        [
            ("proof", v::backs.id(), "copy"),
            ("proof", v::in_unit.id(), "unit"),
            ("proof", v::text.id(), "needle"),
            ("proof", v::witness_spec.id(), "spec"),
            ("proof", v::from_path.id(), "path"),
            ("proof", v::container.id(), "container"),
            ("proof", v::container_text.id(), "hay"),
            ("proof", v::original.id(), original),
        ]
    };
    let mut retained = candidate.to_vec();
    retained.push(("container", v::retained.id(), "kept"));
    let mut recursive = candidate.to_vec();
    recursive.extend([
        ("support", v::backs.id(), "container"),
        ("support", v::in_unit.id(), "unit"),
        ("support", v::text.id(), "hay"),
        ("support", v::original.id(), "original"),
    ]);
    vec![
        rule(f, &retained, &witness("container")),
        rule(f, &recursive, &witness("original")),
    ]
}

fn occurrence(f: &mut TribleSet, unit: Id, path: Id, value: Text) -> Id {
    let o = id();
    edge(f, o, v::in_unit.id(), unit);
    edge(f, o, v::at_path.id(), path);
    text(f, o, value);
    o
}
fn retained(f: &mut TribleSet, o: Id) {
    edge(f, o, v::retained.id(), id());
}
fn mirror(f: &mut TribleSet, copy: Id, paths: &[Id]) -> Id {
    let spec = id();
    edge(f, copy, v::within.id(), spec);
    for &p in paths {
        edge(f, spec, v::from_path.id(), p);
    }
    spec
}
fn environment(f: &TribleSet) -> Environment {
    let mut program = TribleSet::new();
    let rules = backing(&mut program);
    let mut env = Environment::new();
    env.extend(&program);
    env.extend(f);
    env.select(rules);
    env
}
fn finish(env: &mut Environment, store: &mut MemoryBlobStore) {
    for _ in 0..100 {
        if env
            .advance_with_reader(100, &store.snapshot().unwrap())
            .unwrap()
            .progress
            == Progress::Quiescent
        {
            return;
        }
    }
    panic!("bounded Within rules did not quiesce");
}
fn blob(store: &mut MemoryBlobStore, s: &str) -> Text {
    store.put(s).unwrap()
}

// Read only complete witnesses for this reading; never use an uncorrelated
// `copy -> original` projection to discharge another unit/content/spec.
fn proofs(
    f: &TribleSet,
    copy: Id,
    unit: Id,
    needle: Text,
    spec: Id,
) -> BTreeSet<(Id, Id, Text, Id)> {
    find!((path: Id, container: Id, hay: Text, original: Id), pattern!(f, [{
        _?proof @ v::backs: copy, v::in_unit: unit, v::text: needle,
        v::witness_spec: spec, v::from_path: ?path, v::container: ?container,
        v::container_text: ?hay, v::original: ?original
    }]))
    .collect()
}

#[test]
fn exact_substrings_are_unit_wide_case_sensitive_and_not_normalized() {
    for (hay, needle, expected) in [
        ("before 🦊é中 after", "🦊é中", true),
        ("same", "same", true),
        ("nonempty", "", true),
        ("", "", true),
        ("", "a", false),
        ("Hello", "hello", false),
        ("café", "cafe\u{301}", false),
        ("ab cd", "abcd", false),
    ] {
        let (unit, path) = (id(), id());
        let mut f = TribleSet::new();
        let mut store = MemoryBlobStore::new();
        let (h, n) = (blob(&mut store, hay), blob(&mut store, needle));
        // Copy is observed first. A later retained container is equally valid.
        let copy = occurrence(&mut f, unit, id(), n);
        let spec = mirror(&mut f, copy, &[path]);
        let mut env = environment(&f);
        finish(&mut env, &mut store);
        assert!(proofs(env.facts(), copy, unit, n, spec).is_empty());
        let kept = occurrence(&mut f, unit, path, h);
        retained(&mut f, kept);
        env.extend(&f);
        finish(&mut env, &mut store);
        let expected = if expected {
            BTreeSet::from([(path, kept, h, kept)])
        } else {
            BTreeSet::new()
        };
        assert_eq!(proofs(env.facts(), copy, unit, n, spec), expected);
    }
}

#[test]
fn wrong_unit_path_or_unretained_container_backs_nothing() {
    let (unit, path, other) = (id(), id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    let (h, n) = (blob(&mut store, "hay needle"), blob(&mut store, "needle"));
    let copy = occurrence(&mut f, unit, id(), n);
    let spec = mirror(&mut f, copy, &[path]);
    for (u, p, keep) in [
        (other, path, true),
        (unit, other, true),
        (unit, path, false),
    ] {
        let c = occurrence(&mut f, u, p, h);
        if keep {
            retained(&mut f, c);
        }
    }
    let mut env = environment(&f);
    finish(&mut env, &mut store);
    assert!(proofs(env.facts(), copy, unit, n, spec).is_empty());
}

#[test]
fn dropped_cycles_need_a_retained_root_and_then_propagate() {
    let (unit, pa, pb, root_path) = (id(), id(), id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    let h = blob(&mut store, "needle");
    let a = occurrence(&mut f, unit, pa, h);
    let b = occurrence(&mut f, unit, pb, h);
    let ma = mirror(&mut f, a, &[pb]);
    let mb = mirror(&mut f, b, &[pa, root_path]);
    let mut env = environment(&f);
    finish(&mut env, &mut store);
    assert!(proofs(env.facts(), a, unit, h, ma).is_empty());
    assert!(proofs(env.facts(), b, unit, h, mb).is_empty());
    let rh = blob(&mut store, "outer needle outer");
    let root = occurrence(&mut f, unit, root_path, rh);
    retained(&mut f, root);
    env.extend(&f);
    finish(&mut env, &mut store);
    assert_eq!(
        proofs(env.facts(), a, unit, h, ma),
        BTreeSet::from([(pb, b, h, root)])
    );
    assert_eq!(
        proofs(env.facts(), b, unit, h, mb),
        BTreeSet::from([(pa, a, h, root), (root_path, root, rh, root)])
    );
}

#[test]
fn recursive_proof_cannot_cross_a_multivalued_unit_or_text_reading() {
    for wrong_unit in [true, false] {
        let (unit, other_unit, root_path, middle_path) = (id(), id(), id(), id());
        let mut f = TribleSet::new();
        let mut store = MemoryBlobStore::new();
        let good = blob(&mut store, "good");
        let bad = blob(&mut store, "bad");
        let root = occurrence(&mut f, unit, root_path, good);
        retained(&mut f, root);
        let middle = occurrence(&mut f, unit, middle_path, good);
        let ms = mirror(&mut f, middle, &[root_path]);
        let (u, n) = if wrong_unit {
            edge(&mut f, middle, v::in_unit.id(), other_unit);
            (other_unit, good)
        } else {
            text(&mut f, middle, bad);
            (unit, bad)
        };
        let copy = occurrence(&mut f, u, id(), n);
        let spec = mirror(&mut f, copy, &[middle_path]);
        let mut env = environment(&f);
        finish(&mut env, &mut store);
        assert_eq!(
            proofs(env.facts(), middle, unit, good, ms),
            BTreeSet::from([(root_path, root, good, root)])
        );
        assert!(proofs(env.facts(), copy, u, n, spec).is_empty());
    }
}

#[test]
fn witness_identity_preserves_specs_paths_and_both_content_readings() {
    let (unit, p1, p2, forbidden) = (id(), id(), id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    let (h1, h2, n1, n2) = (
        blob(&mut store, "alpha"),
        blob(&mut store, "beta"),
        blob(&mut store, "alp"),
        blob(&mut store, "bet"),
    );
    let kept = occurrence(&mut f, unit, p1, h1);
    edge(&mut f, kept, v::at_path.id(), p2);
    text(&mut f, kept, h2);
    retained(&mut f, kept);
    let copy = occurrence(&mut f, unit, id(), n1);
    text(&mut f, copy, n2);
    let s1 = mirror(&mut f, copy, &[p1]);
    let s2 = mirror(&mut f, copy, &[p2]);
    let s3 = mirror(&mut f, copy, &[forbidden]);
    let mut env = environment(&f);
    finish(&mut env, &mut store);
    for (spec, path) in [(s1, p1), (s2, p2)] {
        assert_eq!(
            proofs(env.facts(), copy, unit, n1, spec),
            BTreeSet::from([(path, kept, h1, kept)])
        );
        assert_eq!(
            proofs(env.facts(), copy, unit, n2, spec),
            BTreeSet::from([(path, kept, h2, kept)])
        );
    }
    assert!(proofs(env.facts(), copy, unit, n1, s3).is_empty());
    assert!(proofs(env.facts(), copy, unit, n2, s3).is_empty());
    let count = find!(proof: Id, pattern!(env.facts(), [{ ?proof @ v::backs: copy }])).count();
    assert_eq!(count, 4, "each correlated reading has its own witness");
}

// This proves absence of positive backing. A complete-unit consumer would
// refuse the dropped nonstring reading; that refusal is not implemented here.
#[test]
fn nonstring_values_have_no_equality_fallback() {
    let (unit, path, copy, kept) = (id(), id(), id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    for o in [copy, kept] {
        edge(&mut f, o, v::in_unit.id(), unit);
        edge(&mut f, o, v::at_path.id(), path);
        let number: Inline<U256BE> = 42_u64.to_inline();
        f.insert(&Trible::force(&o, &v::number.id(), &number));
    }
    retained(&mut f, kept);
    mirror(&mut f, copy, &[path]);
    let mut env = environment(&f);
    finish(&mut env, &mut store);
    assert!(!exists!(
        pattern!(env.facts(), [{ _?proof @ v::backs: copy }])
    ));
}

#[test]
fn missing_container_with_empty_needle_retries_exact_frontier() {
    let (unit, path) = (id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    let n = blob(&mut store, "");
    let h: Text = "missing container".to_inline();
    let copy = occurrence(&mut f, unit, id(), n);
    let spec = mirror(&mut f, copy, &[path]);
    let kept = occurrence(&mut f, unit, path, h);
    retained(&mut f, kept);
    let mut env = environment(&f);
    for _ in 0..2 {
        let error = env
            .advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap_err();
        assert!(triblespace_core::repo::is_missing_blob(&error));
        assert!(matches!(error, ReadAdvanceError::Content { .. }));
        assert!(proofs(env.facts(), copy, unit, n, spec).is_empty());
    }
    // A distinct reading arrives while the failed binding is pending.
    let later = occurrence(&mut f, unit, path, blob(&mut store, "later"));
    retained(&mut f, later);
    env.extend(&f);
    blob(&mut store, "missing container");
    let first = env
        .advance_with_reader(1, &store.snapshot().unwrap())
        .unwrap();
    assert_eq!(first.firings.len(), 1);
    assert_eq!(
        proofs(env.facts(), copy, unit, n, spec),
        BTreeSet::from([(path, kept, h, kept)])
    );
    finish(&mut env, &mut store);
    assert_eq!(
        proofs(env.facts(), copy, unit, n, spec),
        BTreeSet::from([
            (path, kept, h, kept),
            (path, later, "later".to_inline(), later)
        ])
    );
}

#[test]
fn unreadable_utf8_is_an_error_not_a_negative_backing_answer() {
    let (unit, path) = (id(), id());
    let mut f = TribleSet::new();
    let mut store = MemoryBlobStore::new();
    let raw: Inline<Handle<RawBytes>> = store.put(vec![0xff_u8]).unwrap();
    let n = blob(&mut store, "");
    let copy = occurrence(&mut f, unit, id(), n);
    let spec = mirror(&mut f, copy, &[path]);
    let kept = occurrence(&mut f, unit, path, raw.transmute());
    retained(&mut f, kept);
    let mut env = environment(&f);
    for _ in 0..2 {
        let error = env
            .advance_with_reader(1, &store.snapshot().unwrap())
            .unwrap_err();
        assert!(!triblespace_core::repo::is_missing_blob(&error));
        match error {
            ReadAdvanceError::Content { source, .. } => assert!(std::error::Error::source(&source)
                .unwrap()
                .is::<anybytes::view::ViewError>()),
            _ => panic!("expected typed UTF-8 decoding failure"),
        }
        assert!(proofs(env.facts(), copy, unit, n, spec).is_empty());
    }
}
