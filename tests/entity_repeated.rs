use triblespace::core::metadata;
use triblespace::prelude::*;

fn entity_id(set: &TribleSet) -> triblespace::core::id::Id {
    *set.iter().next().expect("non-empty set").e()
}

#[test]
fn entity_repeated_order_and_duplicates_are_ignored() {
    let tags_ab = entity! { _ @
        metadata::tag*: [metadata::KIND_MULTI, metadata::KIND_INLINE_ENCODING],
    };

    let tags_ba = entity! { _ @
        metadata::tag*: [metadata::KIND_INLINE_ENCODING, metadata::KIND_MULTI],
    };

    let tags_dup = entity! { _ @
        metadata::tag*: [
            metadata::KIND_MULTI,
            metadata::KIND_INLINE_ENCODING,
            metadata::KIND_MULTI,
        ],
    };

    assert_eq!(tags_ab, tags_ba);
    assert_eq!(entity_id(&tags_ab), entity_id(&tags_ba));
    assert_eq!(tags_ab, tags_dup);
    assert_eq!(entity_id(&tags_ab), entity_id(&tags_dup));
}

#[test]
fn entity_repeated_empty_is_ignored() {
    let names: Vec<&'static str> = Vec::new();

    let base = entity! { _ @
        metadata::tag: metadata::KIND_MULTI,
    };

    let with_empty = entity! { _ @
        metadata::tag: metadata::KIND_MULTI,
        metadata::name*: names,
    };

    assert_eq!(base, with_empty);
    assert_eq!(entity_id(&base), entity_id(&with_empty));
}

#[test]
fn entity_repeated_affects_id_and_insertions() {
    let base = entity! { _ @
        metadata::tag: metadata::KIND_MULTI,
    };

    let with_tags = entity! { _ @
        metadata::tag*: [metadata::KIND_MULTI, metadata::KIND_INLINE_ENCODING],
    };

    assert_ne!(entity_id(&base), entity_id(&with_tags));
    assert_eq!(base.len() + 1, with_tags.len());
}
