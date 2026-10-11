use triblespace_core::metadata;
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::{
    attributes, entity, find, pattern, Attribute, Id, Inline, IntoInline,
};

attributes! {
    "11111111111111111111111111111111" unsafe as pub fixed: GenId;
    pub derived: Handle<UTF8String>;
    private: Handle<UTF8String>;
}

#[test]
fn attributes_macro_accepts_hex_and_derived_ids() {
    let expected_fixed = Id::from_hex("11111111111111111111111111111111").expect("valid hex id");
    assert_eq!(fixed.id(), expected_fixed);

    let expected_derived = Attribute::<Handle<UTF8String>>::named("derived");
    assert_eq!(derived.id(), expected_derived.id());

    let expected_private = Attribute::<Handle<UTF8String>>::named("private");
    assert_eq!(private.id(), expected_private.id());
}

#[test]
fn attributes_macro_works_in_entity_macro() {
    let val: Inline<Handle<UTF8String>> = "hello".to_inline();
    let entity = triblespace_core::id::fucid();
    let tribles = entity! { &entity @ derived: val };

    let attr = &*derived;
    let entries: Vec<_> = tribles.iter().collect();
    assert_eq!(entries.len(), 1);
    let t = entries[0];
    assert_eq!(*t.e(), *entity);
    assert_eq!(*t.a(), attr.id());
    assert_eq!(*t.v::<Handle<UTF8String>>(), val);
}

#[test]
fn attributes_macro_emits_usage_metadata() {
    // Per-attribute `.describe()` returns identity + schema spread
    // only. Usage facts (rust identifier, module path, doc comment)
    // are emitted by the macro-generated top-level `describe()`
    // function at the attributes!{} declaration site.
    let meta = describe();
    let attr_id = fixed.id();
    let usage_count = find!(
        (usage: Id),
        pattern!(&meta, [{ ?usage @ metadata::attribute: attr_id }])
    )
    .count();
    assert!(usage_count > 0, "expected attribute usage metadata");
}
