use proptest::collection::vec;
use proptest::prelude::*;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::prelude::*;
use triblespace_core::query::TriblePattern;
use triblespace_core::query::Variable;
use triblespace_core::trible::Trible;

fn arb_trible() -> impl Strategy<Value = Trible> {
    (
        prop::array::uniform16(1u8..=255),
        prop::array::uniform16(1u8..=255),
        prop::array::uniform32(any::<u8>()),
    )
        .prop_map(|(e, a, v)| {
            let mut data = [0u8; 64];
            data[0..16].copy_from_slice(&e);
            data[16..32].copy_from_slice(&a);
            data[32..64].copy_from_slice(&v);
            Trible::force_raw(data).expect("non-nil e and a")
        })
}

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
    // ── SimpleArchive round-trip ───────────────────────────────────────

    #[test]
    fn simple_archive_roundtrip(set in arb_tribleset(20)) {
        let blob = set.clone().to_blob();
        let restored: TribleSet = blob.try_from_blob()
            .expect("valid archive should deserialize");
        prop_assert_eq!(set, restored);
    }

    #[test]
    fn simple_archive_preserves_len(set in arb_tribleset(20)) {
        let blob = set.clone().to_blob();
        let restored: TribleSet = blob.try_from_blob().unwrap();
        prop_assert_eq!(set.len(), restored.len());
    }

    #[test]
    fn simple_archive_empty_roundtrip(_dummy in 0..1u8) {
        let empty = TribleSet::new();
        let blob = empty.clone().to_blob();
        let restored: TribleSet = blob.try_from_blob().unwrap();
        prop_assert_eq!(empty, restored);
    }

    #[test]
    fn simple_archive_ref_roundtrip(set in arb_tribleset(20)) {
        // Test the &TribleSet -> blob path too
        let blob = (&set).to_blob();
        let restored: TribleSet = blob.try_from_blob().unwrap();
        prop_assert_eq!(set, restored);
    }

    #[test]
    fn simple_archive_union_then_serialize(
        a in arb_tribleset(10),
        b in arb_tribleset(10),
    ) {
        let union = a.clone() + b.clone();
        let blob = union.clone().to_blob();
        let restored: TribleSet = blob.try_from_blob().unwrap();
        prop_assert_eq!(union.clone(), restored);

        // Also verify union of deserialized parts equals deserialized union
        let a_blob = a.clone().to_blob();
        let b_blob = b.clone().to_blob();
        let a_restored: TribleSet = a_blob.try_from_blob().unwrap();
        let b_restored: TribleSet = b_blob.try_from_blob().unwrap();
        let parts_union = a_restored + b_restored;
        prop_assert_eq!(union, parts_union);
    }

    // ── Trible raw round-trip ──────────────────────────────────────────

    #[test]
    fn trible_force_raw_roundtrip(t in arb_trible()) {
        let raw = *t.as_raw();
        let restored = Trible::force_raw(raw).expect("valid trible");
        prop_assert_eq!(t, restored);
    }

    #[test]
    fn trible_accessors_consistent(t in arb_trible()) {
        // e(), a(), v() should reconstruct the original data
        let e = t.e();
        let a = t.a();
        prop_assert_eq!(&t.as_raw()[0..16], &e[..]);
        prop_assert_eq!(&t.as_raw()[16..32], &a[..]);
    }

    // ── TribleSet deterministic serialization ──────────────────────────

    #[test]
    fn simple_archive_deterministic(set in arb_tribleset(15)) {
        let blob1: Blob<SimpleArchive> = set.clone().to_blob();
        let blob2: Blob<SimpleArchive> = set.to_blob();
        prop_assert_eq!(blob1.bytes.as_ref(), blob2.bytes.as_ref(),
            "same set should produce identical archive bytes");
    }

    // ── SuccinctArchive query consistency ──────────────────────────────

    #[test]
    fn succinct_archive_iter_matches_tribleset(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        // Iter should produce the same tribles
        let mut from_set: Vec<[u8; 64]> = set.iter().map(|t| *t.as_raw()).collect();
        let mut from_archive: Vec<[u8; 64]> = archive.iter().map(|t| *t.as_raw()).collect();
        from_set.sort();
        from_archive.sort();
        prop_assert_eq!(from_set, from_archive,
            "succinct archive iter should match tribleset iter");
    }

    #[test]
    fn succinct_archive_preserves_len(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        prop_assert_eq!(set.len(), archive.iter().count());
    }

    #[test]
    fn succinct_archive_empty(_dummy in 0..1u8) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        let empty = TribleSet::new();
        let archive: SuccinctArchive<OrderedUniverse> = (&empty).into();
        prop_assert_eq!(archive.iter().count(), 0);
    }

    #[test]
    fn succinct_archive_blob_roundtrip(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::{SuccinctArchive, SuccinctArchiveBlob};
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let blob: triblespace_core::blob::Blob<SuccinctArchiveBlob> = archive.to_blob();
        let restored: SuccinctArchive<OrderedUniverse> = blob.try_from_blob()
            .expect("succinct archive blob should round-trip");

        let mut from_original: Vec<[u8; 64]> = set.iter().map(|t| *t.as_raw()).collect();
        let mut from_restored: Vec<[u8; 64]> = restored.iter().map(|t| *t.as_raw()).collect();
        from_original.sort();
        from_restored.sort();
        prop_assert_eq!(from_original, from_restored);
    }

    // ── SuccinctArchive query consistency ──────────────────────────────
    //
    // The Ring index must return the same results as a TribleSet query.

    #[test]
    fn succinct_archive_full_scan_matches(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        // Full scan: query all (e, a, v) triples
        let mut set_results: Vec<_> = find!(
            (e: Inline<_>, a: Inline<_>, v: Inline<UnknownInline>),
            set.pattern(e, a, v as Variable<UnknownInline>)
        ).collect();

        let mut archive_results: Vec<_> = find!(
            (e: Inline<_>, a: Inline<_>, v: Inline<UnknownInline>),
            archive.pattern(e, a, v as Variable<UnknownInline>)
        ).collect();

        set_results.sort();
        archive_results.sort();
        prop_assert_eq!(set_results, archive_results,
            "full scan should match between TribleSet and SuccinctArchive");
    }

    #[test]
    fn succinct_archive_entity_scan_matches(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        if set.is_empty() { return Ok(()); }

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        // Pick the first entity and query just its triples
        let first_trible = set.iter().next().unwrap();
        let entity_val = {
            let mut v = [0u8; 32];
            v[16..32].copy_from_slice(&first_trible.as_raw()[0..16]);
            Inline::<inlineencodings::GenId>::new(v)
        };

        let mut set_results: Vec<_> = find!(
            (a: Inline<_>, v: Inline<UnknownInline>),
            temp!((e), and!(e.is(entity_val), set.pattern(e, a, v as Variable<UnknownInline>)))
        ).collect();

        let mut archive_results: Vec<_> = find!(
            (a: Inline<_>, v: Inline<UnknownInline>),
            temp!((e), and!(e.is(entity_val), archive.pattern(e, a, v as Variable<UnknownInline>)))
        ).collect();

        set_results.sort();
        archive_results.sort();
        prop_assert_eq!(set_results, archive_results,
            "entity scan should match between TribleSet and SuccinctArchive");
    }

    #[test]
    fn succinct_archive_attribute_scan_matches(set in arb_tribleset(15)) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchive;
        use triblespace_core::blob::encodings::succinctarchive::OrderedUniverse;

        if set.is_empty() { return Ok(()); }

        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        // Pick the first trible's attribute
        let first = set.iter().next().unwrap();
        let attr_val = {
            let mut v = [0u8; 32];
            v[16..32].copy_from_slice(&first.as_raw()[16..32]);
            Inline::<inlineencodings::GenId>::new(v)
        };

        // Query with bound attribute
        let mut set_results: Vec<_> = find!(
            (e: Inline<_>, v: Inline<UnknownInline>),
            temp!((a), and!(a.is(attr_val), set.pattern(e, a, v as Variable<UnknownInline>)))
        ).collect();

        let mut archive_results: Vec<_> = find!(
            (e: Inline<_>, v: Inline<UnknownInline>),
            temp!((a), and!(a.is(attr_val), archive.pattern(e, a, v as Variable<UnknownInline>)))
        ).collect();

        set_results.sort();
        archive_results.sort();
        prop_assert_eq!(set_results, archive_results,
            "attribute-bound scan should match");
    }
}
