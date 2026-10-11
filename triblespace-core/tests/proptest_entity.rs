use proptest::collection::vec;
use proptest::prelude::*;
use triblespace_core::id::rngid;
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;

/// A name as stored: the content handle of its text.
type Text = Inline<Handle<UTF8String>>;

fn text(name: &str) -> Text {
    name.to_inline()
}

mod test_ns {
    use triblespace_core::prelude::*;
    attributes! {
        "CC00000000000000CC00000000000001" as pub name: inlineencodings::Handle<blobencodings::UTF8String>;
        "CC00000000000000CC00000000000002" unsafe as pub link: inlineencodings::GenId;
        "CC00000000000000CC00000000000003" unsafe as pub count: inlineencodings::U256BE;
    }
}

proptest! {
    // ── entity! query round-trip ───────────────────────────────────────

    #[test]
    fn entity_name_queryable(name in "[a-z]{1,8}") {
        let e = rngid();
        let set: TribleSet = entity! { &e @ test_ns::name: name.as_str() }.into();

        let results: Vec<Text> = find!(
            n: Text,
            pattern!(&set, [{ test_ns::name: ?n }])
        ).collect();

        prop_assert_eq!(results.len(), 1);
        prop_assert_eq!(results[0], text(&name));
    }

    #[test]
    fn entity_link_queryable(_dummy in 0..1u8) {
        let src = rngid();
        let dst = rngid();
        let set: TribleSet = entity! { &src @ test_ns::link: &dst }.into();

        let results: Vec<Inline<_>> = find!(
            target: Inline<_>,
            pattern!(&set, [{ test_ns::link: ?target }])
        ).collect();

        prop_assert_eq!(results.len(), 1);
        prop_assert_eq!(results[0], (&dst).to_inline());
    }

    #[test]
    fn entity_multiple_attrs_queryable(name in "[a-z]{1,8}") {
        let e = rngid();
        let other = rngid();
        let set: TribleSet = entity! { &e @
            test_ns::name: name.as_str(),
            test_ns::link: &other
        }.into();

        // Query name
        let names: Vec<Text> = find!(
            n: Text,
            pattern!(&set, [{ test_ns::name: ?n }])
        ).collect();
        prop_assert_eq!(names.len(), 1);
        prop_assert_eq!(names[0], text(&name));

        // Query link
        let links: Vec<Inline<_>> = find!(
            target: Inline<_>,
            pattern!(&set, [{ test_ns::link: ?target }])
        ).collect();
        prop_assert_eq!(links.len(), 1);
        prop_assert_eq!(links[0], (&other).to_inline());
    }

    #[test]
    fn entity_union_preserves_all(
        names in vec("[a-z]{1,6}", 2..8),
    ) {
        let mut set = TribleSet::new();
        for name in &names {
            let e = rngid();
            set += entity! { &e @ test_ns::name: name.as_str() };
        }

        let results: Vec<Text> = find!(
            n: Text,
            pattern!(&set, [{ test_ns::name: ?n }])
        ).collect();

        // Bag semantics: one row per complete binding, so each entity is a
        // witness even when names collide; deduplication belongs to the
        // consumer.
        let expected: std::collections::BTreeSet<Text> = names.iter().map(|n| text(n)).collect();
        let actual: std::collections::BTreeSet<Text> = results.iter().copied().collect();
        prop_assert_eq!(&actual, &expected);
        prop_assert_eq!(results.len(), names.len());
    }

    // ── Multi-entity join ──────────────────────────────────────────────

    #[test]
    fn join_finds_linked_names(
        src_name in "[a-z]{1,6}",
        dst_name in "[a-z]{1,6}",
    ) {
        let src = rngid();
        let dst = rngid();
        let mut set = TribleSet::new();
        set += entity! { &src @ test_ns::name: src_name.as_str(), test_ns::link: &dst };
        set += entity! { &dst @ test_ns::name: dst_name.as_str() };

        // Join: find names of entities linked from src
        let results: Vec<Text> = find!(
            name: Text,
            pattern!(&set, [
                { _?source @ test_ns::name: src_name.as_str(), test_ns::link: _?target },
                { _?target @ test_ns::name: ?name }
            ])
        ).collect();

        prop_assert_eq!(results.len(), 1);
        prop_assert_eq!(results[0], text(&dst_name));
    }

    // ── Fragment root ──────────────────────────────────────────────────

    #[test]
    fn entity_fragment_has_root(name in "[a-z]{1,8}") {
        let e = rngid();
        let frag = entity! { &e @ test_ns::name: name.as_str() };
        prop_assert_eq!(frag.root(), Some(*e));
    }

    #[test]
    fn entity_fragment_facts_match_tribleset(name in "[a-z]{1,8}") {
        let e = rngid();
        let frag = entity! { &e @ test_ns::name: name.as_str() };
        let set: TribleSet = frag.clone().into();
        prop_assert_eq!(frag.facts(), &set);
    }

    // ── temp! creates variables scoped to the expression ───────────────

    #[test]
    fn temp_enforces_join_without_projecting(
        src_name in "[a-z]{1,6}",
        dst_name in "[a-z]{1,6}",
    ) {
        let src = rngid();
        let dst = rngid();
        let decoy = rngid();

        let mut set = TribleSet::new();
        set += entity! { &src @ test_ns::name: src_name.as_str(), test_ns::link: &dst };
        set += entity! { &dst @ test_ns::name: dst_name.as_str() };
        // Decoy: has a name but isn't linked from src
        set += entity! { &decoy @ test_ns::name: "decoy" };

        // temp! creates a join variable that doesn't leak into results
        let results: Vec<Text> = find!(
            name: Text,
            temp!((target), pattern!(&set, [
                { _?source @ test_ns::name: src_name.as_str(), test_ns::link: ?target },
                { ?target @ test_ns::name: ?name }
            ]))
        ).collect();

        // Should find dst_name but not "decoy"
        prop_assert_eq!(results.len(), 1);
        prop_assert_eq!(results[0], text(&dst_name));
    }

    // ── _? local variables enforce equality ────────────────────────────

    #[test]
    fn self_referencing_entity_via_desugaring(
        names in vec("[a-z]{1,6}", 2..6),
    ) {
        let mut set = TribleSet::new();
        let mut self_linker = None;

        for (i, name) in names.iter().enumerate() {
            let e = rngid();
            set += entity! { &e @ test_ns::name: name.as_str() };
            if i == 0 {
                set += entity! { &e @ test_ns::link: &e };
                self_linker = Some(name.clone());
            } else {
                let other = rngid();
                set += entity! { &e @ test_ns::link: &other };
            }
        }

        // _?e in both entity and value positions — the macro now
        // desugars this to a fresh variable + EqualityConstraint.
        let results: Vec<Text> = find!(
            name: Text,
            pattern!(&set, [
                { _?e @ test_ns::name: ?name, test_ns::link: _?e }
            ])
        ).collect();

        prop_assert_eq!(results.len(), 1,
            "expected 1 self-linker, got {:?}", results);
        prop_assert_eq!(results[0], text(self_linker.as_ref().unwrap()));
    }

    #[test]
    fn self_referencing_projected_variable(
        names in vec("[a-z]{1,6}", 2..6),
    ) {
        let mut set = TribleSet::new();
        let mut self_linker_id = None;

        for (i, name) in names.iter().enumerate() {
            let e = rngid();
            set += entity! { &e @ test_ns::name: name.as_str() };
            if i == 0 {
                set += entity! { &e @ test_ns::link: &e };
                self_linker_id = Some(e);
            } else {
                let other = rngid();
                set += entity! { &e @ test_ns::link: &other };
            }
        }

        // ?e in both entity and value positions (projected variable)
        let results: Vec<(Inline<_>, Text)> = find!(
            (e: Inline<_>, name: Text),
            pattern!(&set, [
                { ?e @ test_ns::name: ?name, test_ns::link: ?e }
            ])
        ).collect();

        prop_assert_eq!(results.len(), 1,
            "expected 1 self-linker, got {:?}", results);
        let expected_id = (&self_linker_id.unwrap()).to_inline();
        prop_assert_eq!(results[0].0, expected_id);
    }

    // ── Fragment spread composition ──────────────────────────────────

    #[test]
    fn fragment_spread_accumulates_child_facts(
        parent_name in "[a-z]{1,6}",
        child_names in vec("[a-z]{1,6}", 1..4),
    ) {
        // Build child fragments
        let mut children = triblespace_core::trible::Fragment::default();
        let mut child_ids = Vec::new();
        for name in &child_names {
            let child = rngid();
            let frag = entity! { &child @ test_ns::name: name.as_str() };
            child_ids.push(child);
            children += frag;
        }

        // Spread children into parent via *=
        let parent = rngid();
        let mut set = TribleSet::new();
        set += entity! { &parent @ test_ns::name: parent_name.as_str() };
        // Add link from parent to each child
        for child_id in &child_ids {
            set += entity! { &parent @ test_ns::link: child_id };
        }
        // Add child facts
        set += children.into_facts();

        // All child names should be queryable
        for name in &child_names {
            let found = find!(
                n: Text,
                pattern!(&set, [{ test_ns::name: ?n }])
            ).any(|n| n == text(name));
            prop_assert!(found, "child name {:?} not found", name);
        }
    }

    // ── entity! content-addressed IDs ──────────────────────────────────

    #[test]
    fn entity_intrinsic_id_deterministic(
        name in "[a-z]{1,8}",
    ) {
        // entity! without explicit ID derives it from content
        let frag1 = entity! { test_ns::name: name.as_str() };
        let frag2 = entity! { test_ns::name: name.as_str() };

        prop_assert_eq!(frag1.root(), frag2.root(),
            "same content should produce same intrinsic ID");
        prop_assert_eq!(frag1.facts(), frag2.facts());
    }

    #[test]
    fn entity_intrinsic_id_differs_for_different_content(
        name1 in "[a-z]{1,4}",
        name2 in "[m-z]{1,4}",
    ) {
        prop_assume!(name1 != name2);
        let frag1 = entity! { test_ns::name: name1.as_str() };
        let frag2 = entity! { test_ns::name: name2.as_str() };

        prop_assert_ne!(frag1.root(), frag2.root(),
            "different content should produce different intrinsic IDs");
    }

    #[test]
    fn local_var_enforces_join_across_entities(
        names in vec("[a-z]{1,6}", 2..6),
    ) {
        let mut set = TribleSet::new();
        let hub = rngid();
        set += entity! { &hub @ test_ns::name: "hub" };

        // Create entities that link to hub
        for name in &names {
            let e = rngid();
            set += entity! { &e @ test_ns::name: name.as_str(), test_ns::link: &hub };
        }
        // Create a decoy that links to something else
        let decoy = rngid();
        let other = rngid();
        set += entity! { &decoy @ test_ns::name: "decoy", test_ns::link: &other };

        // _?target joins across two entity clauses
        let results: Vec<Text> = find!(
            name: Text,
            pattern!(&set, [
                { _?source @ test_ns::name: ?name, test_ns::link: _?target },
                { _?target @ test_ns::name: "hub" }
            ])
        ).collect();

        // Should find all names that link to hub, but not "decoy"
        for name in &names {
            prop_assert!(results.contains(&text(name)),
                "missing {:?} from join results", name);
        }
        prop_assert!(!results.contains(&text("decoy")),
            "decoy should not appear in results");
    }
}
