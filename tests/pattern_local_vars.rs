use crate::{entity, pattern, pattern_changes};
use triblespace::prelude::*;
use trybuild::TestCases;

pub mod names {
    use triblespace::prelude::*;

    attributes! {
        "D02189E4C5A74E84B0FCBFDE3C533A0B" as first: inlineencodings::Handle<blobencodings::UTF8String>;
        "8F2E5E6A6D9C42F2A4BF6471C5FBF5E0" as last: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

mod social {
    use triblespace::prelude::*;

    attributes! {
        "C2C8D4D6E3E5479EA6F4D71D979CD3CE" unsafe as friend: inlineencodings::GenId;
        "E2175D85AC9F4A09BB52A0F7971D7569" unsafe as best_friend: inlineencodings::GenId;
    }
}

mod library {
    use triblespace::prelude::*;

    attributes! {
        "6E7843FC4D9C428EBF5C9C86CB8C33C4" as title: inlineencodings::Handle<blobencodings::UTF8String>;
        "3E51B9E2E4C14D2DA0DC6B0ACB5CBF56" as subtitle: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

#[test]
fn pattern_local_variables_compile() {
    let t = TestCases::new();
    t.pass("tests/trybuild/pattern_local_variables.rs");
}

#[test]
fn pattern_local_variables_enforce_equality() {
    let mut kb = TribleSet::new();

    let same = ufoid();
    kb += entity! { &same @ names::first: "Same", names::last: "Same" };

    let different = ufoid();
    kb += entity! { &different @ names::first: "Alice", names::last: "Smith" };

    let results: Vec<_> = find!(
        (person: Inline<_>),
        pattern!(&kb, [
            { ?person @ names::first: _?name, names::last: _?name }
        ])
    )
    .collect();

    assert_eq!(results, vec![(same.to_inline(),)]);
}

#[test]
fn pattern_changes_local_variables_track_deltas() {
    let base = TribleSet::new();
    let mut updated = base.clone();

    let same = ufoid();
    updated += entity! { &same @ names::first: "Same", names::last: "Same" };

    let delta = updated.difference(&base);

    let results: Vec<_> = find!(
        (person: Inline<_>),
        pattern_changes!(&updated, &delta, [
            { ?person @ names::first: _?name, names::last: _?name }
        ])
    )
    .collect();

    assert_eq!(results, vec![(same.to_inline(),)]);
}

#[test]
fn pattern_local_vars_require_no_external_binding() {
    let mut set = TribleSet::new();
    let alice = ufoid();
    let bob = ufoid();
    let carol = ufoid();

    set += entity! {
        &alice @
        social::friend: &bob,
        social::best_friend: &bob
    };

    set += entity! {
        &carol @
        social::friend: &bob,
        social::best_friend: &alice
    };

    let results: Vec<_> = find!((person: Inline<_>), pattern!(&set, [
        { ?person @ social::friend: _?buddy },
        { ?person @ social::best_friend: _?buddy }
    ]))
    .collect();

    assert_eq!(results, vec![(alice.to_inline(),)]);
}

#[test]
fn pattern_changes_local_vars_are_scoped_to_invocation() {
    let base = TribleSet::new();
    let mut updated = base.clone();
    let alice = ufoid();
    let bob = ufoid();
    let delta_friend = ufoid();

    updated += entity! {
        &alice @
        social::friend: &bob,
        social::best_friend: &bob
    };

    updated += entity! {
        &delta_friend @
        social::friend: &alice,
        social::best_friend: &bob
    };

    let delta = updated.difference(&base);

    let results: Vec<_> = find!((person: Inline<_>), pattern_changes!(&updated, &delta, [
        { ?person @ social::friend: _?buddy },
        { ?person @ social::best_friend: _?buddy }
    ]))
    .collect();

    assert_eq!(results, vec![(alice.to_inline(),)]);
}

#[test]
fn pattern_local_vars_infer_value_schema_from_usage() {
    let mut set = TribleSet::new();
    let highlighted = ufoid();
    let ignored = ufoid();

    set += entity! {
        &highlighted @
        library::title: "Rust Patterns",
        library::subtitle: "Rust Patterns"
    };

    set += entity! {
        &ignored @
        library::title: "Query Guide",
        library::subtitle: "Second Edition"
    };

    let results: Vec<_> = find!((book: Inline<_>), pattern!(&set, [
        { ?book @ library::title: _?label, library::subtitle: _?label }
    ]))
    .collect();

    assert_eq!(results, vec![(highlighted.to_inline(),)]);
}
