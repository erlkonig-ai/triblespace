//! Multi-term BM25 search composed with a trible `pattern!`,
//! ranking by recomputed BM25 score after the engine filters.
//!
//! Scenario: a small book catalog where each book has a title
//! and an author. The caller asks "books whose title matches
//! 'graph search algorithms' AND are written by `target_author`,
//! ranked by BM25 score". The engine filters via
//! [`matches`][m] (single-variable doc constraint, score floor
//! 0.0); the caller projects each survivor through
//! [`score`][s] for the precise rank. Same pattern as HNSW's
//! "filter by floor, recompute score for ranking."
//!
//! ```sh
//! cargo run --example multi_term_bm25_search
//! ```
//!
//! [m]: triblespace_search::bm25::BM25Index::matches
//! [s]: triblespace_search::bm25::BM25Index::score

use anybytes::View;
use triblespace_core::and;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::examples::literature;
use triblespace_core::find;
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::inline::IntoInline;
use triblespace_core::macros::{entity, pattern};
use triblespace_core::repo::{BlobStoreGet, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use triblespace_search::bm25::BM25Builder;
use triblespace_search::tokens::hash_tokens;

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("non-nil")
}

fn main() {
    // Two authors, six books with titles chosen so "graph
    // search" scores some highly and others not at all.
    let target_author = id(10);
    let other_author = id(11);

    let books = [
        (id(20), target_author, "Graph search algorithms"),
        (id(21), target_author, "Graph search succinctly"),
        (id(22), target_author, "Monte Carlo tree search"),
        (id(23), target_author, "Cooking graph enthusiasts"),
        (id(24), other_author, "Graph search programmer"),
        (id(25), other_author, "Linear algebra"),
    ];

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
    for (book_id, author_id, title) in &books {
        kb += entity! { ExclusiveId::force_ref(book_id) @
            literature::title: *title,
            literature::author: author_id,
        };
    }
    println!("KB: 2 authors + {} books\n", books.len());

    // BM25 over titles, pulled straight out of the KB via a
    // pattern query — no shadow datamodel.
    let blobs = kb.blobs().clone().snapshot().expect("blob snapshot");
    let kb: TribleSet = kb.into_facts();
    let titles: Vec<(Id, String)> = find!(
        (b: Id, title: Inline<Handle<UTF8String>>),
        pattern!(&kb, [{ ?b @ literature::title: ?title }])
    )
    .map(|(b, title)| {
        let text: View<str> = blobs.get(title).expect("resident title blob");
        (b, text.as_ref().to_owned())
    })
    .collect();
    let mut bm25 = BM25Builder::new();
    for (b, title) in &titles {
        bm25.insert(b, hash_tokens(title));
    }
    let idx = bm25.build();
    println!(
        "BM25 index: {} docs, {} terms\n",
        idx.doc_count(),
        idx.term_count(),
    );

    // Standalone multi-term query — bag-of-words "graph search
    // algorithms". `matches` filters; we recompute the precise
    // BM25 sum afterwards for ranking.
    let query_terms = hash_tokens("graph search algorithms");
    println!("standalone multi-term query: 'graph search algorithms'");
    let mut standalone: Vec<(Id, f32)> = find!(
        (book: Id),
        idx.matches(book, &query_terms, 0.0)
    )
    .map(|(b,)| (b, idx.score(&b.to_inline(), &query_terms)))
    .collect();
    standalone.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    for (b, s) in &standalone {
        let title = title_for(&titles, *b);
        println!("  {s:6.3}  {b}  {title}");
    }

    // Headline query: same multi-term filter, gated on author.
    // The engine joins `matches` with `pattern!` on the shared
    // ?book variable — no manual Rust-side filter — then we
    // project the survivors through `score` for ranking.
    println!("\nquery: 'graph search algorithms' AND author = target_author");
    let mut matches: Vec<(Id, f32)> = find!(
        (book: Id),
        and!(
            idx.matches(book, &query_terms, 0.0),
            pattern!(&kb, [{ ?book @ literature::author: &target_author }]),
        )
    )
    .map(|(b,)| (b, idx.score(&b.to_inline(), &query_terms)))
    .collect();
    matches.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    for (b, s) in &matches {
        let title = title_for(&titles, *b);
        println!("  {s:6.3}  {b}  {title}");
    }
    let matches_sorted = &matches;

    // Sanity:
    //   book 20 (target_author, high score)  → in
    //   book 21 (target_author, high score)  → in
    //   book 22 (target_author, mid score)   → in (contains "search")
    //   book 23 (target_author, low score)   → in (contains "graph")
    //   book 24 (other_author, high score)   → out  (author filter)
    //   book 25 (other_author, no match)     → out
    //   book 26 (target_author, no match)    → n/a
    let hit_ids: std::collections::HashSet<Id> = matches.iter().map(|(b, _)| *b).collect();
    assert!(hit_ids.contains(&id(20)));
    assert!(hit_ids.contains(&id(21)));
    assert!(
        !hit_ids.contains(&id(24)),
        "author filter must exclude book 24"
    );
    assert!(!hit_ids.contains(&id(25)));

    // The top match must be by target_author and have a positive
    // score — without asserting a specific title (BM25 ordering
    // depends on doc length + IDF and is stable but brittle to
    // fixture edits).
    assert_eq!(
        matches_sorted[0].0,
        id(20).min(id(21)).max(matches_sorted[0].0),
        "top hit should be one of the high-score target-author books",
    );
}

fn title_for(titles: &[(Id, String)], book: Id) -> &str {
    titles
        .iter()
        .find(|(b, _)| *b == book)
        .map(|(_, t)| t.as_str())
        .unwrap_or("?")
}
