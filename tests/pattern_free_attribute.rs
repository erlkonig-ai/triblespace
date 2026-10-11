//! Free-attribute support in `pattern!` (`{ ?e @ ?attr: ?val }`).
//!
//! When the predicate slot of a pattern is a query variable, the
//! macro can't apply an attribute-specific schema cast to the
//! value. To prevent users from accidentally misinterpreting the
//! result bytes, the macro requires the value variable to be
//! typed `Variable<UnknownInline>` and emits a compile-time type
//! assertion that fails to compile if the user picks any other
//! schema. The bytes come back as opaque 32-byte handles; turning
//! them into something typed is an explicit
//! `try_from_inline::<RealSchema>()` step the receiver makes
//! at the use site, where they know which predicate's bytes
//! they're holding.
//!
//! This is the building block for SPB-style
//! `?cw ?pred ?value` projections (Q3 / Q4 outer CONSTRUCT) and
//! for general-purpose schema-erased iteration over an entity.

use std::collections::HashSet;
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

mod ns {
    use triblespace::prelude::*;
    attributes! {
        "1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A" as name: inlineencodings::Handle<blobencodings::UTF8String>;
        "2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B" unsafe as friend: inlineencodings::GenId;
        "3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C" as nickname: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

#[test]
fn free_attribute_enumerates_predicates_for_fixed_entity() {
    // Build a tiny graph: alice has name + friend + nickname.
    // Bob is the friend target.
    let mut set = TribleSet::new();
    let alice = fucid();
    let bob = fucid();
    set += entity! { &alice @
        ns::name:     "alice",
        ns::friend:   &bob,
        ns::nickname: "ali",
    };

    // Free-attribute pattern: ask for every (predicate, value) on
    // alice. The receiver gets the predicate Id and an opaque
    // UnknownInline for each pair.
    let mut seen: HashSet<Id> = HashSet::new();
    for (attr, _val) in find!(
        (attr: Id, val: Inline<UnknownInline>),
        pattern!(&set, [{ alice.id @ ?attr: ?val }])
    ) {
        seen.insert(attr);
    }

    assert!(seen.contains(&ns::name.id()));
    assert!(seen.contains(&ns::friend.id()));
    assert!(seen.contains(&ns::nickname.id()));
    assert_eq!(seen.len(), 3);
}

#[test]
fn free_attribute_filters_with_external_predicate_check() {
    // Same graph, but exclude the `friend` predicate at the user
    // level — same shape as SPB Q3's
    // FILTER (?pred NOT IN (cwork:tag, cwork:about, cwork:mention)).
    let mut set = TribleSet::new();
    let alice = fucid();
    let bob = fucid();
    set += entity! { &alice @
        ns::name:     "alice",
        ns::friend:   &bob,
        ns::nickname: "ali",
    };

    let excluded = [ns::friend.id()];
    let kept: Vec<Id> = find!(
        (attr: Id, val: Inline<UnknownInline>),
        pattern!(&set, [{ alice.id @ ?attr: ?val }])
    )
    .map(|(attr, _val)| attr)
    .filter(|a| !excluded.contains(a))
    .collect();

    let kept_set: HashSet<Id> = kept.into_iter().collect();
    assert_eq!(kept_set.len(), 2);
    assert!(kept_set.contains(&ns::name.id()));
    assert!(kept_set.contains(&ns::nickname.id()));
    assert!(!kept_set.contains(&ns::friend.id()));
}

#[test]
fn free_attribute_with_free_entity_enumerates_full_index() {
    // Two entities, three (e, a, v) tribles total. With both
    // entity and attribute free we should enumerate every trible
    // in the set.
    let mut set = TribleSet::new();
    let alice = fucid();
    let bob = fucid();
    set += entity! { &alice @ ns::name: "alice", ns::nickname: "ali" };
    set += entity! { &bob   @ ns::name: "bob" };

    let triples: Vec<(Id, Id)> = find!(
        (e: Id, a: Id, v: Inline<UnknownInline>),
        pattern!(&set, [{ ?e @ ?a: ?v }])
    )
    .map(|(e, a, _v)| (e, a))
    .collect();

    assert_eq!(triples.len(), 3);
}

#[test]
fn free_attribute_value_is_byte_addressable() {
    // The value comes back as `Inline<UnknownInline>` — 32 raw
    // bytes. We can compare bytes with a known schema value to
    // confirm the lookup is faithful.
    let mut set = TribleSet::new();
    let alice = fucid();
    set += entity! { &alice @ ns::name: "alice" };

    let expected: Inline<Handle<UTF8String>> =
        Handle::<UTF8String>::inline_from("alice".to_string());
    let mut found: Option<Inline<UnknownInline>> = None;
    for (_attr, val) in find!(
        (attr: Id, val: Inline<UnknownInline>),
        pattern!(&set, [{ alice.id @ ?attr: ?val }])
    ) {
        found = Some(val);
    }
    let val = found.expect("one binding");
    assert_eq!(val.raw, expected.raw);
}

#[test]
fn local_free_attribute_with_projected_value() {
    // `_?attr` (pattern-local) in the attribute slot is supported
    // when the value is a projected `Variable<UnknownInline>`.
    // Local helper vars in the value slot of a free-attr pattern
    // are not supported (no schema can be inferred); use `?val`
    // (a find!-projected Variable<UnknownInline>) instead.
    let mut set = TribleSet::new();
    let alice = fucid();
    let bob = fucid();
    set += entity! { &alice @ ns::name: "alice", ns::friend: &bob };

    let rows: Vec<Inline<UnknownInline>> = find!(
        (val: Inline<UnknownInline>),
        pattern!(&set, [{ alice.id @ _?a: ?val }])
    )
    .map(|(v,)| v)
    .collect();
    // Should see two rows (one per attribute on alice).
    assert_eq!(rows.len(), 2);
    let _ = bob;
}
