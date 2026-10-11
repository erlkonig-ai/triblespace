use triblespace::prelude::*;

mod ns {
    use triblespace::prelude::*;
    attributes! {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" as name: inlineencodings::Handle<blobencodings::UTF8String>;
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" unsafe as score: inlineencodings::U256BE;
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" unsafe as friend: inlineencodings::GenId;
    }
}

#[test]
fn bare_single_variable_returns_value() {
    let mut set = TribleSet::new();
    let e = fucid();
    set += entity! { &e @ ns::name: "alice" };

    let names: Vec<Inline<_>> = find!(
        v: Inline<inlineencodings::Handle<blobencodings::UTF8String>>,
        pattern!(&set, [{ e.id @ ns::name: ?v }])
    )
    .collect();

    assert_eq!(names.len(), 1);
    assert_eq!(names[0], "alice".to_inline());
}

#[test]
fn bare_single_variable_with_id() {
    let mut set = TribleSet::new();
    let a = fucid();
    let b = fucid();
    set += entity! { &a @ ns::friend: &b };

    let friends: Vec<Id> = find!(
        friend: Id,
        pattern!(&set, [{ a.id @ ns::friend: ?friend }])
    )
    .collect();

    assert_eq!(friends, vec![b.id]);
}

#[test]
fn bare_vs_tuple_same_results() {
    let mut set = TribleSet::new();
    let a = fucid();
    let b = fucid();
    let c = fucid();
    set += entity! { &a @ ns::friend: &b };
    set += entity! { &a @ ns::friend: &c };

    // Bare form: yields Id directly.
    let mut bare: Vec<Id> = find!(
        f: Id,
        pattern!(&set, [{ a.id @ ns::friend: ?f }])
    )
    .collect();
    bare.sort();

    // Tuple form: yields (Id,).
    let mut tuple: Vec<Id> = find!(
        (f: Id),
        pattern!(&set, [{ a.id @ ns::friend: ?f }])
    )
    .map(|(id,)| id)
    .collect();
    tuple.sort();

    assert_eq!(bare, tuple);
}

#[test]
fn bare_fallible_returns_result() {
    let mut set = TribleSet::new();
    let e = fucid();
    set += entity! { &e @ ns::score: 7u64 };

    // The ? form yields Result<T, E> without filtering.
    let results: Vec<Result<u64, _>> = find!(
        v: u64?,
        pattern!(&set, [{ e.id @ ns::score: ?v }])
    )
    .collect();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].as_ref().ok(), Some(&7));
}

#[test]
fn bare_filter_semantics() {
    // The filter semantics silently skip rows where conversion fails.
    // With bare find!(v: u64, ...) the narrowing conversion from U256BE
    // can fail on a value above u64::MAX, which would filter the row.
    // Since we store a small value here, we verify filter semantics by checking
    // that the ? variant returns Ok while the non-? variant also returns 1 result.
    let mut set = TribleSet::new();
    let a = fucid();
    set += entity! { &a @ ns::score: 7u64 };

    // Non-fallible: filter on conversion failure (but this succeeds).
    let bare: Vec<u64> = find!(
        v: u64,
        pattern!(&set, [{ a.id @ ns::score: ?v }])
    )
    .collect();
    assert_eq!(bare.len(), 1);

    // Fallible: always yields, wraps in Result.
    let fallible: Vec<Result<u64, _>> = find!(
        v: u64?,
        pattern!(&set, [{ a.id @ ns::score: ?v }])
    )
    .collect();
    assert_eq!(fallible.len(), 1);
    assert!(fallible[0].is_ok());
}

#[test]
fn bare_with_exists_pattern() {
    let mut set = TribleSet::new();
    let a = fucid();
    let b = fucid();
    set += entity! { &a @ ns::friend: &b };

    // Use bare find with .next() for Option<Id>.
    let first: Option<Id> = find!(
        f: Id,
        pattern!(&set, [{ a.id @ ns::friend: ?f }])
    )
    .next();

    assert_eq!(first, Some(b.id));
}
