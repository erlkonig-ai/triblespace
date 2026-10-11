use crate::entity;
use crate::pattern_changes;
use triblespace::prelude::*;

/// A title as stored: the content handle of its text.
type Text = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;

pub mod literature {
    use triblespace::prelude::*;

    attributes! {
        "8F180883F9FD5F787E9E0AF0DF5866B9" unsafe as author: inlineencodings::GenId;
        "0DBB530B37B966D137C50B943700EDB2" as firstname: inlineencodings::Handle<blobencodings::UTF8String>;
        "6BAA463FD4EAF45F6A103DB9433E4545" as lastname: inlineencodings::Handle<blobencodings::UTF8String>;
        "A74AA63539354CDA47F387A4C3A8D54C" as title: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

#[test]
fn pattern_changes_finds_new_inserts() {
    let base = TribleSet::new();

    let mut updated = base.clone();
    let shakespeare = ufoid();
    let hamlet = ufoid();
    updated += entity! { &shakespeare @ literature::firstname: "William", literature::lastname: "Shakespeare" };
    updated += entity! { &hamlet @ literature::title: "Hamlet", literature::author: &shakespeare };

    let delta = updated.difference(&base);

    let results: Vec<_> = find!(
        (author: Inline<_>, book: Inline<_>, title: Inline<_>),
        pattern_changes!(&updated, &delta, [
            { ?author @ literature::firstname: "William", literature::lastname: "Shakespeare" },
            { ?book @ literature::author: ?author, literature::title: ?title }
        ])
    )
    .collect();

    assert_eq!(
        results,
        vec![(
            shakespeare.to_inline(),
            hamlet.to_inline(),
            "Hamlet".to_inline(),
        )]
    );
}

#[test]
fn pattern_changes_empty_delta_returns_no_matches() {
    let mut kb = TribleSet::new();
    let shakespeare = ufoid();
    kb += entity! { &shakespeare @ literature::firstname: "William", literature::lastname: "Shakespeare" };

    let delta = TribleSet::new();

    let results: Vec<_> = find!(
        (a: Inline<_>),
        pattern_changes!(&kb, &delta, [
            { ?a @ literature::lastname: "Shakespeare" }
        ])
    )
    .collect();

    assert!(results.is_empty());
}

/// Regression: pattern_changes with a multi-entity join should only return
/// results involving at least one trible from the delta. When the delta adds
/// a new book by an existing author, only the new book's title should appear,
/// not the existing book's title.
#[test]
fn pattern_changes_multi_entity_delta_only_new_results() {
    let shakespeare = ufoid();
    let hamlet = ufoid();
    let macbeth = ufoid();

    // Base: Shakespeare + Hamlet
    let mut base = TribleSet::new();
    base += entity! { &shakespeare @ literature::firstname: "William", literature::lastname: "Shakespeare" };
    base += entity! { &hamlet @ literature::title: "Hamlet", literature::author: &shakespeare };

    // Delta: only Macbeth (references existing shakespeare entity)
    let mut delta = TribleSet::new();
    delta += entity! { &macbeth @ literature::title: "Macbeth", literature::author: &shakespeare };

    // Full = base + delta
    let full = base + delta.clone();

    // Should find only Macbeth — Hamlet has no tribles in delta.
    let results: Vec<Text> = find!(
        title: Text,
        pattern_changes!(&full, &delta, [
            { _?author @ literature::firstname: "William" },
            { _?book @ literature::author: _?author, literature::title: ?title }
        ])
    )
    .collect();

    assert_eq!(
        results,
        vec!["Macbeth".to_inline()],
        "expected only new book, got: {results:?}"
    );
}

#[test]
fn pattern_changes_yields_one_row_per_witness() {
    // Bag semantics (2026-07-27): the engine yields one row per complete
    // binding; hidden-variable witnesses surface as multiplicity and
    // deduplication belongs to the consumer. Two distinct books with the
    // same title are two witnesses in the first delta, one in the second.
    let first = ufoid();
    let second = ufoid();
    let third = ufoid();

    let mut first_delta = TribleSet::new();
    first_delta += entity! { &first @ literature::title: "Shared" };
    first_delta += entity! { &second @ literature::title: "Shared" };
    let first_full = first_delta.clone();

    let first_results = find!(
        title: Text,
        pattern_changes!(&first_full, &first_delta, [
            { _?book @ literature::title: ?title }
        ])
    )
    .collect::<Vec<_>>();
    assert_eq!(
        first_results,
        vec!["Shared".to_inline(), "Shared".to_inline()]
    );

    let mut second_delta = TribleSet::new();
    second_delta += entity! { &third @ literature::title: "Shared" };
    let second_full = first_full + second_delta.clone();

    let second_results = find!(
        title: Text,
        pattern_changes!(&second_full, &second_delta, [
            { _?book @ literature::title: ?title }
        ])
    )
    .collect::<Vec<_>>();
    assert_eq!(second_results, vec!["Shared".to_inline()]);
}
