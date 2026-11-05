use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, IntoBlob, MemoryBlobStore, MemoryBlobStoreSnapshot};
use triblespace_core::id::Id;
use triblespace_core::import::json_tree::{self, JsonTreeImporter};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::{attributes, entity};
use triblespace_core::prelude::*;
use triblespace_core::trible::{Fragment, TribleSet};
use std::sync::Arc;

use triblespace_cxg::{Anchor, Category, Constituent, Construction, Count, Grammar, Problem, PathStep, Role, Step, Unit};

type Name = Inline<Handle<UTF8String>>;

mod out {
    use super::*;
    attributes! {
        "93CB7D894B6279B6E6578A9AB1645416" as pub said: Handle<UTF8String>;
        "1BAA34CCBDA04B3BC13A0337D0795F02" as pub item: GenId;
        "6BE70E273624C95D8517E2CF07661590" as pub tool: Handle<UTF8String>;
        "6153F3719C1EEED7A78DC69643EFA971" as pub body: GenId;
    }
}

struct Doc {
    fragment: Fragment,
    root: Id,
    blobs: MemoryBlobStoreSnapshot,
}

fn unit(json: &str) -> Doc {
    let mut store = MemoryBlobStore::new();
    let fragment = JsonTreeImporter::<_>::new(&mut store, None)
        .import_str(json)
        .expect("json imports");
    let root = fragment.root().expect("rooted import");
    let blobs = fragment.blobs().clone().snapshot().expect("snapshot");
    Doc {
        fragment,
        root,
        blobs,
    }
}

impl Doc {
    fn view(&self) -> Unit<'_> {
        Unit::new(self.fragment.facts(), &self.blobs)
    }
}

fn handle(text: &str) -> Name {
    let blob: Blob<UTF8String> = text.to_blob();
    blob.get_handle()
}

fn string_of(facts: &TribleSet, node: Id) -> Option<Name> {
    find!((h: Name), pattern!(facts, [{ node @ json_tree::string: ?h }]))
        .map(|(h,)| h)
        .next()
}

/// An object anchor: the object has a field `type` whose value is the
/// string `kind`.
fn typed<C: 'static>(kind: &'static str) -> Anchor<C> {
    let type_name = handle("type");
    let wanted = handle(kind);
    Box::new(move |unit: &Unit, e, _| {
        let facts = unit.facts;
        exists!(pattern!(facts, [
            { e @ json_tree::object_field: _?field },
            { _?field @ json_tree::field_name: type_name, json_tree::field_value: _?value },
            { _?value @ json_tree::string: wanted },
        ]))
    })
}

fn kind_is<C: 'static>(kind: Id) -> Anchor<C> {
    Box::new(move |unit: &Unit, e, _| exists!(pattern!(unit.facts, [{ e @ json_tree::kind: kind }])))
}

fn string() -> Construction<&'static str> {
    Construction {
        name: "string",
        category: "str",
        anchor: kind_is(json_tree::kind_string),
        constituents: vec![],
        emit: Box::new(|inst| {
            let h = string_of(inst.unit.facts, inst.anchor).expect("a string node has its text");
            entity! { _ @ out::said: h }
        }),
    }
}

fn text_message() -> Construction<&'static str> {
    Construction {
        name: "text_message",
        category: "msg",
        anchor: typed("text"),
        constituents: vec![
            Constituent::new(Step::Field("type"), Role::Drop("discriminant")),
            Constituent::new(Step::Field("text"), Role::Child("str")),
        ],
        emit: Box::new(|inst| {
            let text = inst.children(1).next().expect("text child");
            entity! { _ @ out::body: text }
        }),
    }
}

fn tool_message() -> Construction<&'static str> {
    Construction {
        name: "tool_message",
        category: "msg",
        anchor: typed("tool"),
        constituents: vec![
            Constituent::new(Step::Field("type"), Role::Drop("discriminant")),
            Constituent::new(Step::Field("name"), Role::Value),
            Constituent::optional(Step::Field("input"), Role::Value),
        ],
        emit: Box::new(|inst| {
            let name = inst.values(1).next().expect("name value");
            let h = string_of(inst.unit.facts, name).expect("tool name is a string");
            entity! { _ @ out::tool: h }
        }),
    }
}

fn list() -> Construction<&'static str> {
    Construction {
        name: "list",
        category: "list",
        anchor: kind_is(json_tree::kind_array),
        constituents: vec![Constituent::new(Step::Each, Role::Child("msg"))],
        emit: Box::new(|inst| {
            let items: Vec<Id> = inst.children(0).collect();
            entity! { _ @ out::item*: items }
        }),
    }
}

fn grammar(constructions: Vec<Construction<&'static str>>) -> Grammar<&'static str> {
    Grammar::new(constructions).expect("grammar passes its static checks")
}

fn standard() -> Vec<Construction<&'static str>> {
    vec![string(), text_message(), tool_message(), list()]
}

fn said(image: &Fragment) -> Vec<Name> {
    let mut out: Vec<Name> = find!((h: Name), pattern!(image.facts(), [{ _?e @ out::said: ?h }]))
        .map(|(h,)| h)
        .collect();
    out.sort();
    out
}

#[test]
fn a_well_formed_unit_has_exactly_one_cover() {
    let u = unit(r#"[{"type":"text","text":"hi"},{"type":"tool","name":"exec","input":{"cmd":"ls"}}]"#);
    let g = grammar(standard());
    assert_eq!(g.count(u.view(), u.root, &"list"), Count::One);
    let image = g
        .cover(u.view(), u.root, &"list")
        .expect("one cover");
    assert_eq!(said(&image), vec![handle("hi")]);
    let items = find!((i: Id), pattern!(image.facts(), [{ _?l @ out::item: ?i }])).count();
    assert_eq!(items, 2);
}

#[test]
fn an_unclaimed_member_fails_the_unit_and_is_named() {
    let u = unit(r#"[{"type":"text","text":"hi"},{"type":"text","text":"yo","extra":1}]"#);
    let g = grammar(standard());
    let findings = g
        .cover(u.view(), u.root, &"list")
        .expect_err("the extra member is not understood");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].path, "/1");
    assert_eq!(
        findings[0].problem,
        Problem::Unclaimed {
            construction: "text_message",
            members: vec!["extra".to_owned()],
        }
    );
}

#[test]
fn an_unknown_shape_is_reported_where_it_is() {
    let u = unit(r#"[{"type":"image","url":"x"}]"#);
    let findings = grammar(standard())
        .cover(u.view(), u.root, &"list")
        .expect_err("no construction for images");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].path, "/0");
    assert_eq!(findings[0].category, "msg");
    assert_eq!(findings[0].problem, Problem::NoConstruction);
}

#[test]
fn a_missing_required_member_means_the_construction_does_not_apply() {
    let u = unit(r#"[{"type":"tool"}]"#);
    let findings = grammar(standard())
        .cover(u.view(), u.root, &"list")
        .expect_err("a tool message needs a name");
    assert_eq!(
        findings[0].problem,
        Problem::Missing {
            construction: "tool_message",
            step: "Field(\"name\")".to_owned(),
        }
    );
}

#[test]
fn two_covering_constructions_are_an_ambiguity_not_a_choice() {
    let mut cs = standard();
    let mut twin = text_message();
    twin.name = "text_message_twin";
    cs.push(twin);
    let u = unit(r#"[{"type":"text","text":"hi"}]"#);
    let g = grammar(cs);
    assert_eq!(g.count(u.view(), u.root, &"list"), Count::Many);
    let findings = g
        .cover(u.view(), u.root, &"list")
        .expect_err("ambiguous");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].path, "/0");
    assert_eq!(
        findings[0].problem,
        Problem::Ambiguous {
            constructions: vec!["text_message", "text_message_twin"],
        }
    );
}

#[test]
fn an_anchor_whose_child_fails_is_not_an_alternative() {
    // Sol, 2026-11-04: two matching anchors need not be two covers.
    let mut cs = standard();
    cs.push(Construction {
        name: "text_as_number",
        category: "msg",
        anchor: typed("text"),
        constituents: vec![
            Constituent::new(Step::Field("type"), Role::Drop("discriminant")),
            Constituent::new(Step::Field("text"), Role::Child("num")),
        ],
        emit: Box::new(|_| unreachable!("never the single cover")),
    });
    let u = unit(r#"[{"type":"text","text":"hi"}]"#);
    let g = grammar(cs);
    assert_eq!(g.count(u.view(), u.root, &"list"), Count::One);
    g.cover(u.view(), u.root, &"list")
        .expect("the other analysis has no cover");
}

#[test]
fn shared_subtrees_are_counted_at_every_path() {
    // Sol, 2026-11-04: two slots sharing one memo key still count twice.
    // Both entries are the same json_tree entity. With two analyses each,
    // the list has four covers, so it is ambiguous, and with one each it
    // has one cover that emits the shared message once.
    let u = unit(r#"[{"type":"text","text":"hi"},{"type":"text","text":"hi"}]"#);
    let g = grammar(standard());
    let image = g
        .cover(u.view(), u.root, &"list")
        .expect("one cover");
    let items = find!((i: Id), pattern!(image.facts(), [{ _?l @ out::item: ?i }])).count();
    assert_eq!(items, 1, "the same message at two paths is one emitted entity");

    let mut cs = standard();
    let mut twin = text_message();
    twin.name = "text_message_twin";
    cs.push(twin);
    assert_eq!(grammar(cs).count(u.view(), u.root, &"list"), Count::Many);
}

#[test]
fn one_entity_under_two_categories_emits_two_roots() {
    // Sol, 2026-11-04: emitted once per (entity, category), not per content.
    let u = unit(r#"{"type":"pair","speech":"exec","tool":"exec"}"#);
    let speech_string = string();
    let mut tool_string = string();
    tool_string.name = "tool_string";
    tool_string.category = "tool_name";
    tool_string.emit = Box::new(|inst| {
        let h = string_of(inst.unit.facts, inst.anchor).expect("text");
        entity! { _ @ out::tool: h }
    });
    let pair = Construction {
        name: "pair",
        category: "pair",
        anchor: typed("pair"),
        constituents: vec![
            Constituent::new(Step::Field("type"), Role::Drop("discriminant")),
            Constituent::new(Step::Field("speech"), Role::Child("str")),
            Constituent::new(Step::Field("tool"), Role::Child("tool_name")),
        ],
        emit: Box::new(|inst| {
            let speech = inst.children(1).next().expect("speech");
            let tool = inst.children(2).next().expect("tool");
            assert_ne!(speech, tool);
            entity! { _ @ out::body: speech, out::item: tool }
        }),
    };
    let g = grammar(vec![speech_string, tool_string, pair]);
    let image = g
        .cover(u.view(), u.root, &"pair")
        .expect("one cover");
    assert_eq!(said(&image), vec![handle("exec")]);
}

#[test]
fn empty_containers_are_accounted_for() {
    let g = grammar(standard());
    let u = unit("[]");
    let image = g
        .cover(u.view(), u.root, &"list")
        .expect("an empty list has one cover");
    assert!(image.root().is_some());

    let u = unit(r#"[{"type":"tool","name":"exec","input":{}}]"#);
    g.cover(u.view(), u.root, &"list")
        .expect("an empty input object is consumed as a value");
}

#[test]
fn the_image_does_not_depend_on_construction_order() {
    let u = unit(r#"[{"type":"text","text":"a"},{"type":"tool","name":"exec"},{"type":"text","text":"b"}]"#);
    let forward = grammar(standard())
        .cover(u.view(), u.root, &"list")
        .expect("one cover");
    let mut reversed = standard();
    reversed.reverse();
    let backward = grammar(reversed)
        .cover(u.view(), u.root, &"list")
        .expect("one cover");
    assert_eq!(forward.facts(), backward.facts());
    assert_eq!(forward.root(), backward.root());
}

#[test]
fn overlapping_constituents_are_refused_when_the_grammar_is_built() {
    let mut c = list();
    c.constituents.push(Constituent::new(Step::Index(0), Role::Value));
    assert!(Grammar::new(vec![c]).is_err());
    let mut c = text_message();
    c.constituents.push(Constituent::new(Step::Field("text"), Role::Value));
    assert!(Grammar::new(vec![c]).is_err());
}

#[test]
fn a_cycle_written_by_a_bug_terminates_and_is_reported() {
    // Content-derived ids cannot form a cycle, but a merge can bring one:
    // here an extra fact makes an array its own entry.
    let u = unit(r#"[[]]"#);
    let mut facts = u.fragment.facts().clone();
    let bogus = entity! { _ @
        json_tree::array_parent: u.root,
        json_tree::array_index: ethnum::U256::new(1),
        json_tree::array_value: u.root,
    };
    facts += bogus.facts().clone();
    let nested = Construction {
        name: "nested",
        category: "tree",
        anchor: kind_is(json_tree::kind_array),
        constituents: vec![Constituent::new(Step::Each, Role::Child("tree"))],
        emit: Box::new(|inst| {
            let items: Vec<Id> = inst.children(0).collect();
            entity! { _ @ out::item*: items }
        }),
    };
    let g = grammar(vec![nested]);
    assert_eq!(g.count(Unit::new(&facts, &u.blobs), u.root, &"tree"), Count::Zero);
    let findings = g
        .cover(Unit::new(&facts, &u.blobs), u.root, &"tree")
        .expect_err("a cycle has no finite cover");
    assert!(findings.iter().any(|f| f.problem == Problem::Cycle), "{findings:?}");
}

#[test]
fn an_id_keyed_object_is_covered_member_by_member() {
    // An object whose member names are ids, not a vocabulary.
    let by_id = Construction {
        name: "by_id",
        category: "by_id",
        anchor: kind_is(json_tree::kind_object),
        constituents: vec![Constituent::new(Step::EachField, Role::Child("msg"))],
        emit: Box::new(|inst| {
            let items: Vec<Id> = inst.children(0).collect();
            entity! { _ @ out::item*: items }
        }),
    };
    let mut cs = standard();
    cs.push(by_id);
    let g = grammar(cs);
    let u = unit(r#"{"ab12":{"type":"text","text":"x"},"cd34":{"type":"text","text":"y"}}"#);
    let image = g
        .cover(u.view(), u.root, &"by_id")
        .expect("one cover");
    assert_eq!(said(&image), {
        let mut v = vec![handle("x"), handle("y")];
        v.sort();
        v
    });
    let u = unit(r#"{"ab12":{"type":"text","text":"x"},"cd34":{"type":"image"}}"#);
    let findings = g
        .cover(u.view(), u.root, &"by_id")
        .expect_err("one member has no construction");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].path, "/cd34");

    let mut c = text_message();
    c.constituents.push(Constituent::new(Step::EachField, Role::Value));
    assert!(Grammar::new(vec![c]).is_err(), "EachField overlaps a named field");
}

/// A compiler's category: a family (the path) and the context its parent
/// decided, here whether the enclosing record's thinking is summarized.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Cat {
    path: &'static str,
    summarized: bool,
}

impl Category for Cat {
    type Family = &'static str;
    fn family(&self) -> &'static str {
        self.path
    }
}

fn context_grammar(with_own: bool) -> Grammar<Cat> {
    let model_name = handle("model");
    let summarized_prefix = "claude-4";
    let record = Construction::<Cat> {
        name: "record",
        category: "record",
        anchor: kind_is(json_tree::kind_object),
        constituents: vec![
            Constituent::new(Step::Field("model"), Role::Drop("read by the content's category")),
            Constituent::new(
                Step::Field("thinking"),
                Role::Within(Arc::new(move |unit: &Unit, e: Id, _: &Cat, _: &PathStep| {
                    let facts = unit.facts;
                    let model = find!(
                        (h: Name),
                        pattern!(facts, [
                            { e @ json_tree::object_field: _?field },
                            { _?field @ json_tree::field_name: model_name, json_tree::field_value: _?value },
                            { _?value @ json_tree::string: ?h },
                        ])
                    )
                    .map(|(h,)| h)
                    .next();
                    Cat {
                        path: "thinking",
                        summarized: model
                            .and_then(|h| unit.text(h))
                            .is_some_and(|text| text.starts_with(summarized_prefix)),
                    }
                })),
            ),
        ],
        emit: Box::new(|inst| {
            let thinking = inst.children(1).next().expect("thinking");
            entity! { _ @ out::body: thinking }
        }),
    };
    let summary = Construction::<Cat> {
        name: "summary",
        category: "thinking",
        anchor: Box::new(|unit: &Unit, e, cat: &Cat| {
            let facts = unit.facts;
            cat.summarized && exists!(pattern!(facts, [{ e @ json_tree::kind: json_tree::kind_string }]))
        }),
        constituents: vec![],
        emit: Box::new(|inst| {
            let h = string_of(inst.unit.facts, inst.anchor).expect("text");
            entity! { _ @ out::tool: h }
        }),
    };
    let own = Construction::<Cat> {
        name: "own_thinking",
        category: "thinking",
        anchor: Box::new(|unit: &Unit, e, cat: &Cat| {
            let facts = unit.facts;
            !cat.summarized && exists!(pattern!(facts, [{ e @ json_tree::kind: json_tree::kind_string }]))
        }),
        constituents: vec![],
        emit: Box::new(|inst| {
            let h = string_of(inst.unit.facts, inst.anchor).expect("text");
            entity! { _ @ out::said: h }
        }),
    };
    let records = Construction::<Cat> {
        name: "records",
        category: "records",
        anchor: kind_is(json_tree::kind_array),
        constituents: vec![Constituent::new(
            Step::Each,
            Role::Child(Cat {
                path: "record",
                summarized: false,
            }),
        )],
        emit: Box::new(|inst| {
            let items: Vec<Id> = inst.children(0).collect();
            entity! { _ @ out::item*: items }
        }),
    };
    let mut cs = vec![records, record, summary];
    if with_own {
        cs.push(own);
    }
    Grammar::new(cs).expect("grammar")
}

#[test]
fn a_parent_passes_context_down_in_the_category() {
    let g = context_grammar(true);
    let start = Cat {
        path: "record",
        summarized: false,
    };

    // The same thinking string, under two records whose model differs, is
    // classified by the context the record passed down.
    let u = unit(r#"{"model":"claude-4-opus","thinking":"hmm"}"#);
    let image = g.cover(u.view(), u.root, &start).expect("one cover");
    assert!(said(&image).is_empty());
    assert_eq!(
        find!((h: Name), pattern!(image.facts(), [{ _?e @ out::tool: ?h }])).count(),
        1,
        "a summarized record's thinking is a summary"
    );
    let u = unit(r#"{"model":"claude-3-7-sonnet","thinking":"hmm"}"#);
    let image = g.cover(u.view(), u.root, &start).expect("one cover");
    assert_eq!(said(&image), vec![handle("hmm")], "otherwise it is her own");
}

#[test]
fn one_shared_subtree_under_two_contexts_in_one_unit_is_counted_and_emitted_per_context() {
    // Sol, 2026-11-04: the full computed category must be the memo key, or a
    // subtree shared under two record conditions mixes. Both visit orders.
    for json in [
        r#"[{"model":"claude-4-opus","thinking":"hmm"},{"model":"claude-3-7-sonnet","thinking":"hmm"}]"#,
        r#"[{"model":"claude-3-7-sonnet","thinking":"hmm"},{"model":"claude-4-opus","thinking":"hmm"}]"#,
    ] {
        let g = context_grammar(true);
        let u = unit(json);
        let start = Cat {
            path: "records",
            summarized: false,
        };
        let image = g.cover(u.view(), u.root, &start).expect("one cover");
        assert_eq!(said(&image), vec![handle("hmm")], "{json}: her own, once");
        assert_eq!(
            find!((h: Name), pattern!(image.facts(), [{ _?e @ out::tool: ?h }])).count(),
            1,
            "{json}: the summary, once"
        );
        // Without a construction for her own thinking, the unsummarized
        // context has no cover, whichever context the walk reaches first.
        let findings = context_grammar(false)
            .cover(u.view(), u.root, &start)
            .expect_err("one context has no construction");
        assert_eq!(findings.len(), 1, "{json}: {findings:?}");
        assert_eq!(findings[0].problem, Problem::NoConstruction, "{json}");
    }
}

#[test]
fn every_unit_has_its_own_run() {
    let a = unit("[]");
    let b = unit("[]");
    assert_ne!(a.view().run(), b.view().run());
    let view = a.view();
    assert_eq!(view.run(), view.run(), "a copy keeps its run");
}
