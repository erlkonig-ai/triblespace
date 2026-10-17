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

#[test]
fn entity_repeated_bundle_works_through_the_facade_prelude() {
    use blobencodings::RawBytes;
    use inlineencodings::Handle;
    use triblespace::core::blob::Bytes;

    let body = Attribute::<Handle<RawBytes>>::named("facade_bundle_body");
    let root: Blob<RawBytes> = b"facade payload".as_slice().to_blob();
    let bundle = Bundle::new(root, MemoryBlobStore::new());
    let handle = bundle.root();

    let fragment = entity! { body*: bundle };

    assert_eq!(fragment.facts().len(), 1);
    assert_eq!(
        fragment.iter().next().unwrap().v::<Handle<RawBytes>>(),
        &handle
    );
    let mut blobs = fragment.blobs().clone();
    let bytes: Bytes = blobs.snapshot().unwrap().get(handle).unwrap();
    assert_eq!(&*bytes, b"facade payload");
}
