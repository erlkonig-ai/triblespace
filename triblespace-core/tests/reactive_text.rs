use std::fmt;

use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::{GenId, Handle};
use triblespace_core::prelude::*;
use triblespace_core::reactive::{schema as r, text, Environment, Error};
use triblespace_core::trible::Trible;

fn parse(source: &str) -> Result<Fragment, text::TextError> {
    text::parse(source.as_bytes().to_vec().into())
}
fn render(facts: &TribleSet) -> String {
    let mut out = String::new();
    text::write(facts, &mut out).unwrap();
    out
}
fn raw(facts: &mut TribleSet, entity: Id, attribute: Id, bytes: [u8; 32]) {
    facts.insert(&Trible::force(
        &entity,
        &attribute,
        &Inline::<UnknownInline>::new(bytes),
    ));
}

#[test]
fn sugar_equals_hand_written_native_facts_without_implicit_channels() {
    let (rev, clause, core, emits, constraint, s, a, o, needle) = (
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
    );
    let source = format!(
        r#"
        alias revision = id"{rev:x}";
        alias clause = id"{clause:x}";
        alias s = id"{s:x}";
        alias a = id"{a:x}";
        alias o = id"{o:x}";
        rule @revision {{
          operation POSITIVE;
          matches @clause (?s @a ?o);
          core id"{core:x}" (?s @a ?o);
          emits id"{emits:x}" (?s @a ?o);
          literal ?o genid(@a);
          literal id"{needle:x}" utf8("f\u0065ver 🦊\n\"\\");
          constraint id"{constraint:x}" STRING_CONTAINS(?o, id"{needle:x}");
        }}
    "#
    );
    let actual = parse(&source).unwrap();
    let mut expected = entity! { ExclusiveId::force_ref(&rev) @ r::operation: r::POSITIVE,
    r::matches: &clause, r::core: &core, r::emits: &emits, r::constraints: &constraint };
    for c in [&clause, &core, &emits] {
        expected +=
            entity! { ExclusiveId::force_ref(c) @ r::subject: &s, r::predicate: &a, r::object: &o };
    }
    expected += entity! { ExclusiveId::force_ref(&constraint) @ r::operation: r::STRING_CONTAINS,
    r::container: &o, r::needle: &needle };
    let id_value: Inline<GenId> = (&a).to_inline();
    expected +=
        entity! { ExclusiveId::force_ref(&o) @ r::literal: id_value.transmute::<UnknownInline>() };
    let string = "fever 🦊\n\"\\";
    let handle: Inline<Handle<UTF8String>> = string.to_inline();
    expected += entity! { ExclusiveId::force_ref(&needle) @ r::literal: handle.transmute::<UnknownInline>() };
    assert_eq!(actual.facts(), expected.facts());
    assert_eq!(actual.exports().count(), 0);
    assert!(actual.metafacts().is_empty());
    let mut blobs = actual.blobs().clone();
    let stored: anybytes::View<str> = blobs.snapshot().unwrap().get(handle).unwrap();
    assert_eq!(&*stored, string);
    let rendered = render(actual.facts());
    assert!(rendered.contains("matches @"));
    assert!(rendered.contains("constraint @"));
    assert!(rendered.contains("(?n"));
    assert_eq!(parse(&rendered).unwrap().facts(), actual.facts());
    assert_eq!(render(&parse(&rendered).unwrap()), rendered);
}

#[test]
fn alias_spelling_is_not_identity_and_duplicate_binding_must_be_unambiguous() {
    let (e, a, v, other) = (*genid(), *genid(), *genid(), *genid());
    let source = format!(
        r#"alias entity = id"{e:x}"; alias attribute = id"{a:x}";
        alias value = id"{v:x}"; fact @entity @attribute genid(?value);"#
    );
    assert_eq!(
        parse(&source).unwrap(),
        parse(&source.replace("entity", "renamed")).unwrap()
    );
    let same = format!("{source} alias entity = id\"{e:x}\"; alias another = @entity;");
    assert_eq!(parse(&source).unwrap(), parse(&same).unwrap());
    assert!(parse(&format!("{source} alias entity = id\"{other:x}\";"))
        .unwrap_err()
        .message
        .contains("ambiguous"));
    assert!(parse("fact @later @later genid(@later); alias later = id\"bad\";").is_err());
}

#[test]
fn empty_and_partial_rule_add_no_default_operation_or_selection() {
    let (rev, c, s, a, o) = (*genid(), *genid(), *genid(), *genid(), *genid());
    let empty = parse(&format!("rule id\"{rev:x}\" {{}} // no defaults\n")).unwrap();
    assert!(empty.facts().is_empty());
    let partial = parse(&format!(
        "rule id\"{rev:x}\" {{ matches id\"{c:x}\" (id\"{s:x}\" id\"{a:x}\" id\"{o:x}\"); }}"
    ))
    .unwrap();
    assert_eq!(partial.facts().len(), 4);
    let mut env = Environment::new();
    env.extend(&partial);
    env.select([rev]);
    assert_eq!(env.advance(1).unwrap_err(), Error::MissingOperation(rev));
    let rendered = render(&partial);
    assert!(!rendered.contains("operation POSITIVE"));
    assert_eq!(parse(&rendered).unwrap().facts(), partial.facts());
}

#[test]
fn raw_fallback_preserves_unknown_partial_multivalued_and_shared_graphs() {
    let (r1, r2, c, s, a, o, incomplete, unknown) = (
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
        *genid(),
    );
    let mut f = entity! { ExclusiveId::force_ref(&r1) @ r::matches*: [&c, &incomplete], r::operation: &unknown };
    f += entity! { ExclusiveId::force_ref(&r2) @ r::matches: &c, r::emits: &c };
    f += entity! { ExclusiveId::force_ref(&c) @ r::subject: &s, r::predicate: &a, r::object: &o };
    f += entity! { ExclusiveId::force_ref(&incomplete) @ r::subject: &s };
    // Sharing stays explicit even when a complete clause is displayed twice.
    let rendered = render(&f);
    assert_eq!(parse(&rendered).unwrap().facts(), f.facts());
    assert!(rendered.contains("matches @"));
    // A second valid and one malformed subject value force conservative fallback.
    f += entity! { ExclusiveId::force_ref(&c) @ r::subject: &o };
    raw(f.facts_mut(), c, r::subject.id(), [0xff; 32]);
    // Nil GenId, arbitrary full-width values, and a NaN payload are still facts.
    raw(f.facts_mut(), o, r::literal.id(), [0; 32]);
    raw(f.facts_mut(), o, r::literal.id(), [0xff; 32]);
    let mut nan = [0; 32];
    nan[..8].copy_from_slice(&0x7ff8000000000042u64.to_le_bytes());
    raw(f.facts_mut(), s, unknown, nan);
    let rendered = render(&f);
    assert!(!rendered.contains("matches @"));
    assert!(!rendered.contains("emits @"));
    assert_eq!(parse(&rendered).unwrap().facts(), f.facts());
}

#[test]
fn constructors_are_exact_and_missing_blobs_do_not_block_export() {
    let (e, a, id) = (*genid(), *genid(), *genid());
    let digest = [0xa5; 32];
    let source = format!(
        r#"
      fact id"{e:x}" id"{a:x}" handle<UTF8String>"{}";
      fact id"{e:x}" id"{a:x}" raw32"{}";
      fact id"{e:x}" id"{a:x}" genid(id"{id:x}");
    "#,
        hex::encode(digest),
        hex::encode(digest)
    );
    let f = parse(&source).unwrap();
    assert_eq!(f.facts().len(), 2);
    let native: Inline<GenId> = (&id).to_inline();
    let mut expected = TribleSet::new();
    raw(&mut expected, e, a, digest);
    raw(&mut expected, e, a, native.raw);
    assert_eq!(f.facts(), &expected);
    assert_eq!(parse(&render(&f)).unwrap().facts(), f.facts());
    let mut blobs = f.blobs().clone();
    assert!(blobs
        .snapshot()
        .unwrap()
        .get::<anybytes::View<str>, _>(Inline::<Handle<UTF8String>>::new(digest))
        .is_err());
}

#[test]
fn all_value_bytes_survive_without_typed_decoding() {
    let (e, a) = (*genid(), *genid());
    let mut facts = TribleSet::new();
    for byte in 0..=255u8 {
        let mut raw_value = [byte; 32];
        raw_value[31] = byte.wrapping_add(1);
        raw(&mut facts, e, a, raw_value);
    }
    assert_eq!(parse(&render(&facts)).unwrap().facts(), &facts);
    assert_eq!(render(&TribleSet::new()), "");
}

#[test]
fn syntax_errors_are_located_and_return_no_partial_fragment() {
    let (e, a) = (*genid(), *genid());
    let good = format!("fact id\"{e:x}\" id\"{a:x}\" utf8(\"é\");\n");
    let error = parse(&(good.clone() + "wat")).unwrap_err();
    assert_eq!((error.offset, error.line, error.column), (good.len(), 2, 1));
    for bad in [
        "rule id\"00000000000000000000000000000000\" {}".to_owned(),
        "rule id\"zz\" {}".to_owned(),
        format!("rule id\"{e:x}\" {{ operation POSITIVE;"),
        format!("fact id\"{e:x}\" id\"{a:x}\" raw32\"00\";"),
        format!("fact id\"{e:x}\" id\"{a:x}\" utf8(\"\\uD800\");"),
        format!("fact id\"{e:x}\" id\"{a:x}\" \"implicit string\";"),
        format!("fact id\"{e:x}\" id\"{a:x}\" utf8(\"x\")"),
    ] {
        let error = parse(&(good.clone() + &bad)).unwrap_err();
        assert!(error.offset >= good.len());
        assert!(error.line >= 2);
    }
    let mut invalid_utf8 = good.into_bytes();
    invalid_utf8.extend_from_slice(format!("fact id\"{e:x}\" id\"{a:x}\" utf8(\"").as_bytes());
    invalid_utf8.extend_from_slice(&[0xff, b'"', b')', b';']);
    assert!(text::parse(invalid_utf8.into()).is_err());
}

#[test]
fn formatter_propagates_output_failure() {
    struct Fail;
    impl fmt::Write for Fail {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    let e = *genid();
    let f = entity! { ExclusiveId::force_ref(&e) @ r::operation: r::POSITIVE };
    assert!(text::write(&f, &mut Fail).is_err());
}

#[path = "../examples/reactive_text.rs"]
mod example;

#[test]
fn text_collection_join_contains_core_and_emit_converge_across_commits_and_revisions() {
    example::run(false).unwrap();
}
