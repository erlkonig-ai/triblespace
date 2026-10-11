//! End-to-end test: use our Constraints via the real `find!`
//! macro. Exercises the full propose / confirm / satisfied
//! protocol through the engine's own join machinery, producing
//! typed Rust tuples as output.
//!
//! This is the test that proves "yes, you can drop these
//! constraints into a normal triblespace query and get rows
//! back" — distinct from the unit tests (individual methods) and
//! the IntersectionConstraint tests (manual composition without
//! the macro).

use std::collections::HashSet;

use triblespace_core::find;
use triblespace_core::id::Id;
use triblespace_core::inline::IntoInline;

use triblespace_search::bm25::BM25Builder;
use triblespace_search::succinct::SuccinctBM25Index;
use triblespace_search::tokens::hash_tokens;

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn sample_index() -> SuccinctBM25Index {
    let mut b: BM25Builder = BM25Builder::new();
    b.insert(id(1), hash_tokens("the quick brown fox"));
    b.insert(id(2), hash_tokens("the lazy brown dog"));
    b.insert(id(3), hash_tokens("quick silver fox jumps"));
    b.build()
}

/// Single-variable find!: enumerate every doc that mentions
/// "fox". Expect two rows (docs 1 and 3).
#[test]
fn find_matches_term() {
    let idx = sample_index();
    let fox = hash_tokens("fox");

    let rows: Vec<(Id,)> = find!(
        (doc: Id),
        idx.matches(doc, &fox, 0.0)
    )
    .collect();

    let set: HashSet<Id> = rows.into_iter().map(|(d,)| d).collect();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&id(1)));
    assert!(set.contains(&id(3)));
}

/// `matches` + post-collect `score` recompute reproduces the
/// BM25 ranking pattern. Three docs that share posting-list
/// membership but have different lengths should rank by their
/// per-doc summed scores after `score()` is applied.
#[test]
fn find_matches_then_score_for_ranking() {
    let mut b: BM25Builder = BM25Builder::new();
    // Two same-length, same-tf "fox" docs (identical scores) +
    // one length-7 doc (lower per-term score because of length
    // normalisation).
    b.insert(id(1), hash_tokens("the quick fox"));
    b.insert(id(2), hash_tokens("another fox book"));
    b.insert(id(3), hash_tokens("quick brown fox jumps high today!"));
    b.insert(id(4), hash_tokens("unrelated content only"));
    let idx = b.build();
    let fox = hash_tokens("fox");

    // Filter through the engine.
    let docs: Vec<Id> = find!(
        (doc: Id),
        idx.matches(doc, &fox, 0.0)
    )
    .map(|(d,)| d)
    .collect();
    assert_eq!(docs.len(), 3);

    // Rescore precisely after, mirroring how a faculty would
    // present ranked results.
    let mut ranked: Vec<(Id, f32)> = docs
        .into_iter()
        .map(|d| (d, idx.score(&d.to_inline(), &fox)))
        .collect();
    ranked.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });

    // Length-3 docs (1, 2) outrank the length-7 doc (3).
    assert_eq!(ranked[0].0, id(1));
    assert_eq!(ranked[1].0, id(2));
    assert_eq!(ranked[2].0, id(3));
    assert!((ranked[0].1 - ranked[1].1).abs() < 1e-5);
    assert!(ranked[0].1 > ranked[2].1);
}

/// `find!` with no projection — pure existence check, matches
/// the `exists!` pattern. Here "quick" appears in two docs, so
/// the query has at least one row.
#[test]
fn find_no_projection_is_existence() {
    let idx = sample_index();
    let quick = hash_tokens("quick");
    let count = find!(
        (doc: Id),
        idx.matches(doc, &quick, 0.0)
    )
    .count();
    assert_eq!(count, 2);
}

/// Two `matches` clauses in an `and!`: docs that contain BOTH
/// "fox" AND "quick". Only docs 1 and 3 match in the tiny
/// sample. Verifies that two BM25 constraints sharing a variable
/// intersect correctly through the macro.
#[test]
fn find_intersection_of_two_terms() {
    use triblespace_core::and;

    let idx = sample_index();
    let fox = hash_tokens("fox");
    let quick = hash_tokens("quick");

    let rows: Vec<(Id,)> = find!(
        (doc: Id),
        and!(
            idx.matches(doc, &fox, 0.0),
            idx.matches(doc, &quick, 0.0)
        )
    )
    .collect();

    let set: HashSet<Id> = rows.into_iter().map(|(d,)| d).collect();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&id(1)));
    assert!(set.contains(&id(3)));
}

/// Score-floor parameter actually filters: a floor between two
/// docs' summed scores excludes the lower one from the engine's
/// proposal set.
#[test]
fn find_matches_with_floor_drops_low_scoring_docs() {
    let mut b: BM25Builder = BM25Builder::new();
    b.insert(id(1), hash_tokens("fox quick brown jumps"));
    b.insert(id(2), hash_tokens("only fox here, nothing else"));
    b.insert(id(3), hash_tokens("unrelated"));
    let idx = b.build();
    let terms = hash_tokens("fox quick brown jumps");
    let s1 = idx.score(&id(1).to_inline(), &terms);
    let s2 = idx.score(&id(2).to_inline(), &terms);
    assert!(s1 > s2);

    let rows: Vec<(Id,)> = find!(
        (doc: Id),
        idx.matches(doc, &terms, (s1 + s2) / 2.0)
    )
    .collect();
    let set: HashSet<Id> = rows.into_iter().map(|(d,)| d).collect();
    assert_eq!(set.len(), 1);
    assert!(set.contains(&id(1)));
    assert!(!set.contains(&id(2)));
}

/// Succinct index plugs into `find!` identically to the naive
/// one. `sample_index()` already returns a SuccinctBM25Index —
/// kept as a distinct test alongside `find_matches_term` so a
/// future change that separates the naive and succinct engine
/// paths doesn't silently drop coverage.
#[test]
fn find_matches_term_on_succinct() {
    let idx = sample_index();
    let fox = hash_tokens("fox");

    let rows: Vec<(Id,)> = find!(
        (doc: Id),
        idx.matches(doc, &fox, 0.0)
    )
    .collect();

    let set: HashSet<Id> = rows.into_iter().map(|(d,)| d).collect();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&id(1)));
    assert!(set.contains(&id(3)));
}

/// The succinct HNSW view plugs into `find!` via the unary
/// [`SimilarTo`] snapshot. Pin the probe at construction, let the engine
/// enumerate the frozen HNSW result set, and cross-check against the direct
/// `candidates_above` API.
///
/// [`SimilarTo`]: triblespace_search::constraint::SimilarTo
#[test]
fn find_hnsw_similar_to_on_succinct() {
    use triblespace_core::blob::MemoryBlobStore;
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::SnapshotSource;
    use triblespace_search::hnsw::HNSWBuilder;
    use triblespace_search::schemas::{put_embedding, Embedding};

    let mut store = MemoryBlobStore::new();
    let mut b = HNSWBuilder::new(4).with_seed(23);
    let mut handles = Vec::new();
    for i in 1..=16u8 {
        let f = i as f32;
        let v = vec![f.sin(), f.cos(), (f * 0.5).sin(), (f * 0.3).cos()];
        let h = put_embedding::<_>(&mut store, v.clone()).unwrap();
        b.insert(h, v).unwrap();
        handles.push(h);
    }
    let succinct = b.build();
    let snapshot = store.snapshot().unwrap();
    let succinct_view = succinct.attach(&snapshot);
    let probe = handles[0];
    let floor = 0.4f32;

    let rows: Vec<(Inline<Handle<Embedding>>,)> = find!(
        (neighbour: Inline<Handle<Embedding>>),
        succinct_view.similar_to(probe, neighbour, floor)
    )
    .collect();
    let got: HashSet<_> = rows.into_iter().map(|(h,)| h).collect();

    let expected: HashSet<_> = succinct_view
        .candidates_above(probe, floor)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(got, expected);
}

/// `idx.score` (rescore helper) and `idx.matches` (engine
/// constraint) operate on the same posting lists, so for any
/// query the docs the constraint binds must be exactly the docs
/// whose `score()` exceeds the floor.
#[test]
fn matches_set_equals_score_threshold_set() {
    let mut b: BM25Builder = BM25Builder::new();
    b.insert(id(1), hash_tokens("the quick brown fox jumps"));
    b.insert(id(2), hash_tokens("a fox and a cat and a dog"));
    b.insert(id(3), hash_tokens("quick silver fox"));
    b.insert(id(4), hash_tokens("entirely unrelated"));
    let idx = b.build();

    for query in [
        "quick fox",
        "the brown fox",
        "unrelated",
        "fox dog cat",
        "nothing here",
    ] {
        let terms = hash_tokens(query);

        // Engine path — collected via find! at floor 0.0.
        let engine: HashSet<Id> = find!(
            (doc: Id),
            idx.matches(doc, &terms, 0.0)
        )
        .map(|(d,)| d)
        .collect();

        // Reference: every doc with score > 0.0 must be in the
        // engine set, and the engine set must contain only such
        // docs.
        let mut expected = HashSet::new();
        for byte in 1u8..=4 {
            let d = id(byte);
            if idx.score(&d.to_inline(), &terms) > 0.0 {
                expected.insert(d);
            }
        }
        assert_eq!(
            engine, expected,
            "matches set diverged from score>0 set on query {query:?}"
        );
    }
}

/// Headline story: BM25 lexical search composed with a `pattern!`
/// over a real TribleSet, in a single `find!`. "Find books whose
/// title mentions 'fox' AND are authored by the known author X."
#[test]
fn find_bm25_composed_with_pattern() {
    use triblespace_core::and;
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::examples::literature;
    use triblespace_core::id::ExclusiveId;
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::Inline;
    use triblespace_core::macros::{entity, pattern};
    use triblespace_core::repo::{BlobStoreGet, SnapshotSource};
    use triblespace_core::trible::Fragment;

    let target_author = id(10);
    let other_author = id(11);
    let book_a = id(20);
    let book_b = id(21);
    let book_c = id(22);
    let book_d = id(23);

    // A fragment keeps the title blobs beside the facts that reference them.
    let mut kb = Fragment::empty();
    kb += entity! { ExclusiveId::force_ref(&target_author) @
        literature::firstname: "Target",
        literature::lastname: "Author",
    };
    kb += entity! { ExclusiveId::force_ref(&other_author) @
        literature::firstname: "Other",
        literature::lastname: "Author",
    };
    kb += entity! { ExclusiveId::force_ref(&book_a) @
        literature::title: "The Quick Fox",
        literature::author: &target_author,
    };
    kb += entity! { ExclusiveId::force_ref(&book_b) @
        literature::title: "Another Fox Book",
        literature::author: &target_author,
    };
    kb += entity! { ExclusiveId::force_ref(&book_c) @
        literature::title: "Fox Adventure",
        literature::author: &other_author,
    };
    kb += entity! { ExclusiveId::force_ref(&book_d) @
        literature::title: "Unrelated",
        literature::author: &target_author,
    };

    let blobs = kb.blobs().clone().snapshot().unwrap();
    let kb = kb.facts();
    let titles: Vec<(Id, Inline<Handle<UTF8String>>)> = find!(
        (b: Id, title: Inline<Handle<UTF8String>>),
        pattern!(kb, [{ ?b @ literature::title: ?title }])
    )
    .collect();
    let mut bm25 = BM25Builder::new();
    for (b, title) in &titles {
        let title: anybytes::View<str> = blobs.get(*title).unwrap();
        bm25.insert(*b, hash_tokens(title.as_ref()));
    }
    let idx = bm25.build();

    // Compose: "books that mention 'fox' AND are by target_author".
    let fox = hash_tokens("fox");
    let rows: Vec<(Id,)> = find!(
        (book: Id),
        and!(
            idx.matches(book, &fox, 0.0),
            pattern!(kb, [{ ?book @ literature::author: &target_author }])
        )
    )
    .collect();

    let books: HashSet<Id> = rows.into_iter().map(|(b,)| b).collect();
    assert_eq!(
        books.len(),
        2,
        "expected 2 fox books by target author, got {}",
        books.len()
    );
    assert!(books.contains(&book_a));
    assert!(books.contains(&book_b));
    assert!(!books.contains(&book_c), "should exclude wrong author");
    assert!(!books.contains(&book_d), "should exclude no-fox title");
}
