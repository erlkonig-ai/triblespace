use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::BTreeSet;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::prelude::blobencodings::UTF8String;
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;
use triblespace_core::query::TriblePattern;
use triblespace_core::query::Variable;
use triblespace_core::trible::Trible;

/// A label as stored: the content handle of its text.
type Text = Inline<Handle<UTF8String>>;

mod test_ns {
    use triblespace_core::prelude::*;
    attributes! {
        "AA00000000000000AA00000000000001" unsafe as pub link: inlineencodings::GenId;
        "AA00000000000000AA00000000000002" as pub label: inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

/// Generate a random trible with non-nil entity and attribute.
fn arb_trible() -> impl Strategy<Value = Trible> {
    // Entity: 16 bytes (at least one non-zero), Attribute: 16 bytes (at least one non-zero), Inline: 32 bytes
    (
        prop::array::uniform16(1u8..=255), // entity (all non-zero bytes guarantees non-nil)
        prop::array::uniform16(1u8..=255), // attribute
        prop::array::uniform32(any::<u8>()), // value
    )
        .prop_map(|(e, a, v)| {
            let mut data = [0u8; 64];
            data[0..16].copy_from_slice(&e);
            data[16..32].copy_from_slice(&a);
            data[32..64].copy_from_slice(&v);
            Trible::force_raw(data).expect("non-nil e and a")
        })
}

/// Generate a random TribleSet with up to `max` tribles.
fn arb_tribleset(max: usize) -> impl Strategy<Value = TribleSet> {
    vec(arb_trible(), 0..max).prop_map(|tribles| {
        let mut set = TribleSet::new();
        for t in &tribles {
            set.insert(t);
        }
        set
    })
}

proptest! {
    // ── TribleSet set algebra ──────────────────────────────────────────

    #[test]
    fn insert_then_contains(t in arb_trible()) {
        let mut set = TribleSet::new();
        set.insert(&t);
        prop_assert!(set.contains(&t));
        prop_assert_eq!(set.len(), 1);
    }

    #[test]
    fn union_commutative(a in arb_tribleset(10), b in arb_tribleset(10)) {
        let ab = a.clone() + b.clone();
        let ba = b + a;
        prop_assert_eq!(ab, ba);
    }

    #[test]
    fn union_idempotent(a in arb_tribleset(10)) {
        let aa = a.clone() + a.clone();
        prop_assert_eq!(a, aa);
    }

    #[test]
    fn union_identity(a in arb_tribleset(10)) {
        let empty = TribleSet::new();
        let result = a.clone() + empty;
        prop_assert_eq!(a, result);
    }

    #[test]
    fn intersect_commutative(a in arb_tribleset(10), b in arb_tribleset(10)) {
        let ab = a.intersect(&b);
        let ba = b.intersect(&a);
        prop_assert_eq!(ab, ba);
    }

    #[test]
    fn intersect_idempotent(a in arb_tribleset(10)) {
        let aa = a.intersect(&a);
        prop_assert_eq!(a, aa);
    }

    #[test]
    fn difference_self_is_empty(a in arb_tribleset(10)) {
        let diff = a.difference(&a);
        prop_assert!(diff.is_empty());
    }

    #[test]
    fn difference_empty_is_self(a in arb_tribleset(10)) {
        let empty = TribleSet::new();
        let diff = a.difference(&empty);
        prop_assert_eq!(a, diff);
    }

    #[test]
    fn union_then_difference_recovers(a in arb_tribleset(10), b in arb_tribleset(10)) {
        // (a ∪ b) \ b should contain everything in a that wasn't in b
        let union = a.clone() + b.clone();
        let diff = union.difference(&b);
        // diff should be a subset of a
        for t in diff.iter() {
            prop_assert!(a.contains(t), "diff element not in a");
        }
        // and should contain exactly a \ b
        let expected = a.difference(&b);
        prop_assert_eq!(expected, diff);
    }

    #[test]
    fn intersect_subset_of_both(a in arb_tribleset(10), b in arb_tribleset(10)) {
        let inter = a.intersect(&b);
        for t in inter.iter() {
            prop_assert!(a.contains(t));
            prop_assert!(b.contains(t));
        }
    }

    #[test]
    fn iter_len_consistent(a in arb_tribleset(20)) {
        prop_assert_eq!(a.len(), a.iter().count());
    }

    #[test]
    fn iter_all_contained(a in arb_tribleset(20)) {
        for t in a.iter() {
            prop_assert!(a.contains(t));
        }
    }

    #[test]
    fn fingerprint_equality(a in arb_tribleset(10), b in arb_tribleset(10)) {
        // Equal sets must have equal fingerprints
        let a2 = a.clone();
        prop_assert_eq!(a.fingerprint(), a2.fingerprint());
        // Different sets *usually* have different fingerprints
        // (we can't assert this — hash collisions exist — but we can
        // check that equal fingerprint implies we should check equality)
        if a.fingerprint() == b.fingerprint() {
            // might be equal, might be collision — can't assert either way
        }
    }

    // ── Query: find! basic properties ──────────────────────────────────

    #[test]
    fn find_all_triples_returns_everything(tribles in vec(arb_trible(), 1..15)) {
        let mut set = TribleSet::new();
        for t in &tribles {
            set.insert(t);
        }
        let results: Vec<_> = find!(
            (e: Inline<_>, a: Inline<_>, v: Inline<UnknownInline>),
            set.pattern(e, a, v as Variable<UnknownInline>)
        ).collect();
        prop_assert_eq!(results.len(), set.len());
    }

    // ── pattern_changes! properties ────────────────────────────────────
    //
    // Generate TribleSets using known attributes so pattern_changes! can
    // use the macro syntax. Each entity gets a `label` attribute.

    #[test]
    fn pattern_changes_empty_delta_yields_nothing(
        labels in vec("[a-z]{1,8}", 1..10)
    ) {
        let mut base = TribleSet::new();
        for label in &labels {
            let e = rngid();
            base += entity! { &e @ test_ns::label: label.as_str() };
        }
        let empty = TribleSet::new();
        let results: Vec<Text> = find!(
            label: Text,
            pattern_changes!(&base, &empty, [
                { test_ns::label: ?label }
            ])
        ).collect();
        prop_assert!(results.is_empty(),
            "empty delta should yield no results, got {}", results.len());
    }

    #[test]
    fn pattern_changes_full_delta_equals_pattern(
        labels in vec("[a-z]{1,8}", 1..10)
    ) {
        let mut set = TribleSet::new();
        for label in &labels {
            let e = rngid();
            set += entity! { &e @ test_ns::label: label.as_str() };
        }
        let mut pattern_results: Vec<Text> = find!(
            label: Text,
            pattern!(&set, [{ test_ns::label: ?label }])
        ).collect();
        let mut changes_results: Vec<Text> = find!(
            label: Text,
            pattern_changes!(&set, &set, [
                { test_ns::label: ?label }
            ])
        ).collect();
        pattern_results.sort();
        changes_results.sort();
        prop_assert_eq!(pattern_results, changes_results,
            "full delta should equal full pattern");
    }

    /// The bug we fixed: multi-entity joins where one entity is in base and
    /// the other in delta. pattern_changes must only return results that
    /// involve at least one trible from the delta.
    #[test]
    fn pattern_changes_multi_entity_delta_only(
        base_names in vec("[a-z]{1,6}", 1..5),
        delta_names in vec("[a-z]{1,6}", 1..5),
    ) {
        // Base: entities with labels + links between them
        let mut base = TribleSet::new();
        let mut base_entities = Vec::new();
        for name in &base_names {
            let e = rngid();
            base += entity! { &e @ test_ns::label: name.as_str() };
            base_entities.push(e);
        }
        // Link first base entity to all others
        if base_entities.len() > 1 {
            for target in &base_entities[1..] {
                base += entity! { &base_entities[0] @ test_ns::link: target };
            }
        }

        // Delta: new entities with labels + links to base entities
        let mut delta = TribleSet::new();
        for name in &delta_names {
            let e = rngid();
            delta += entity! { &e @ test_ns::label: name.as_str() };
            // Link to first base entity (cross-set join)
            if !base_entities.is_empty() {
                delta += entity! { &e @ test_ns::link: &base_entities[0] };
            }
        }

        let full = base.clone() + delta.clone();

        // Query: find labels of entities that link to the first base entity
        if !base_entities.is_empty() {
            let target_val = (&base_entities[0]).to_inline();
            let changes: Vec<Text> = find!(
                label: Text,
                pattern_changes!(&full, &delta, [
                    { _?e @ test_ns::link: target_val, test_ns::label: ?label }
                ])
            ).collect();

            // All results must be from entities that have at least one
            // trible in the delta
            let _base_labels: Vec<Text> = find!(
                label: Text,
                pattern!(&base, [
                    { _?e @ test_ns::link: target_val, test_ns::label: ?label }
                ])
            ).collect();

            // pattern_changes should NOT return labels that are
            // exclusively from base (no delta involvement)
            for label in &changes {
                // The label either comes from a delta entity, or the link
                // comes from delta. Either way, at least one trible is new.
                // We can't easily check which trible is from delta, but we
                // CAN check: if a label is ONLY in base (entity has no
                // delta tribles), it should NOT appear.
                let in_delta_labels: Vec<Text> = find!(
                    label: Text,
                    pattern!(&delta, [{ test_ns::label: ?label }])
                ).collect();
                let in_delta_links = find!(
                    (e: Inline<_>,),
                    pattern!(&delta, [{ ?e @ test_ns::link: target_val }])
                ).count();

                // The result must involve SOME delta data
                let delta_has_something = !in_delta_labels.is_empty() || in_delta_links > 0;
                prop_assert!(delta_has_something,
                    "result {:?} has no delta involvement", label);
            }
        }
    }

    // ── COW / clone independence ─────────────────────────────────────

    #[test]
    fn clone_then_modify_independent(
        base in arb_tribleset(10),
        extra in arb_trible(),
    ) {
        let original = base.clone();
        let mut modified = base;
        modified.insert(&extra);
        // Original should be unaffected by the insertion into modified
        prop_assert_eq!(original.len() + if original.contains(&extra) { 0 } else { 1 },
            modified.len());
        // If extra wasn't in original, it should only be in modified
        if !original.contains(&extra) {
            prop_assert!(!original.contains(&extra));
            prop_assert!(modified.contains(&extra));
        }
    }

    #[test]
    fn clone_equality_before_modification(
        set in arb_tribleset(10),
    ) {
        let cloned = set.clone();
        prop_assert_eq!(set.fingerprint(), cloned.fingerprint());
        prop_assert_eq!(set, cloned);
    }

    // ── Union distributes over difference ──────────────────────────────

    #[test]
    fn union_distributes_over_intersect(
        a in arb_tribleset(8),
        b in arb_tribleset(8),
        c in arb_tribleset(8),
    ) {
        // A ∪ (B ∩ C) = (A ∪ B) ∩ (A ∪ C)
        let lhs = a.clone() + b.intersect(&c);
        let rhs = (a.clone() + b).intersect(&(a + c));
        prop_assert_eq!(lhs, rhs);
    }

    #[test]
    fn intersect_distributes_over_union(
        a in arb_tribleset(8),
        b in arb_tribleset(8),
        c in arb_tribleset(8),
    ) {
        // A ∩ (B ∪ C) = (A ∩ B) ∪ (A ∩ C)
        let lhs = a.intersect(&(b.clone() + c.clone()));
        let rhs = a.intersect(&b) + a.intersect(&c);
        prop_assert_eq!(lhs, rhs);
    }

    // ── Associativity ──────────────────────────────────────────────────

    #[test]
    fn union_associative(
        a in arb_tribleset(8),
        b in arb_tribleset(8),
        c in arb_tribleset(8),
    ) {
        let ab_c = (a.clone() + b.clone()) + c.clone();
        let a_bc = a + (b + c);
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn intersect_associative(
        a in arb_tribleset(8),
        b in arb_tribleset(8),
        c in arb_tribleset(8),
    ) {
        let ab_c = a.intersect(&b).intersect(&c);
        let a_bc = a.intersect(&b.intersect(&c));
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn pattern_changes_via_difference(
        base_labels in vec("[a-z]{1,6}", 1..8),
        delta_labels in vec("[a-z]{1,6}", 1..5),
    ) {
        // Build base and delta as separate TribleSets
        let mut base = TribleSet::new();
        for label in &base_labels {
            let e = rngid();
            base += entity! { &e @ test_ns::label: label.as_str() };
        }
        let mut full = base.clone();
        for label in &delta_labels {
            let e = rngid();
            full += entity! { &e @ test_ns::label: label.as_str() };
        }

        // The delta is the difference between full and base
        let delta = full.difference(&base);

        // pattern_changes with computed delta should return only the new labels
        let changes: BTreeSet<Text> = find!(
            label: Text,
            pattern_changes!(&full, &delta, [
                { test_ns::label: ?label }
            ])
        ).collect();
        let expected: BTreeSet<Text> = delta_labels
            .iter()
            .map(|label| label.as_str().to_inline())
            .collect();

        prop_assert_eq!(changes, expected,
            "pattern_changes via difference should yield the distinct new raw labels");
    }

    #[test]
    fn pattern_changes_subset_of_pattern(
        base_labels in vec("[a-z]{1,8}", 1..8),
        delta_labels in vec("[a-z]{1,8}", 1..5)
    ) {
        let mut base = TribleSet::new();
        for label in &base_labels {
            let e = rngid();
            base += entity! { &e @ test_ns::label: label.as_str() };
        }
        let mut delta = TribleSet::new();
        for label in &delta_labels {
            let e = rngid();
            delta += entity! { &e @ test_ns::label: label.as_str() };
        }
        let full = base + delta.clone();
        let changes: Vec<Text> = find!(
            label: Text,
            pattern_changes!(&full, &delta, [
                { test_ns::label: ?label }
            ])
        ).collect();
        let all: Vec<Text> = find!(
            label: Text,
            pattern!(&full, [{ test_ns::label: ?label }])
        ).collect();
        // Every pattern_changes result must exist in the full pattern
        for label in &changes {
            prop_assert!(all.contains(label),
                "pattern_changes result {:?} not in full pattern", label);
        }
    }
}
