//! Headline-story demo: BM25 lexical search *composed* with a
//! `pattern!` over a `TribleSet` in a single `find!`.
//!
//! Scenario: a tiny literature KB with authors + books (titles +
//! author link). We build a BM25 index over titles, then ask the
//! query engine for "books whose title mentions 'fox' AND are
//! authored by the target author". The BM25 constraint and the
//! tribles constraint join through the shared `?book` variable —
//! no manual filtering in Rust, just one `find!` / `and!`.
//!
//! ```sh
//! cargo run --example compose_bm25_and_pattern
//! ```

use anybytes::View;
use triblespace_core::and;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::examples::literature;
use triblespace_core::find;
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::{entity, pattern};
use triblespace_core::repo::{BlobStoreGet, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use triblespace_search::bm25::BM25Builder;
use triblespace_search::tokens::hash_tokens;

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("non-nil")
}

fn main() {
    // ─ Seed the KB with authors and books ─
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

    println!("KB: {} authors + {} books", 2, 4);

    // ─ Build a BM25 index over titles, keyed by book entity id ─
    // Query the KB for (book, title) pairs; feed them straight
    // into BM25Builder. No shadow datamodel — titles stay in the
    // KB as the source of truth.
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
        bm25.insert(*b, hash_tokens(title));
    }
    let idx = bm25.build();
    println!(
        "BM25 index built: {} docs, {} terms, avg_doc_len = {:.2}",
        idx.doc_count(),
        idx.term_count(),
        idx.avg_doc_len()
    );

    // ─ The headline query ─
    // "Books whose title mentions 'fox' AND are authored by
    // `target_author`." BM25 gives us lexical filtering; the
    // pattern! clause adds the author relationship. The engine
    // joins through the shared ?book variable.
    let fox = hash_tokens("fox");

    println!("\nquery: title contains 'fox' AND author = target_author");
    let matched: Vec<(Id,)> = find!(
        (book: Id),
        and!(
            idx.matches(book, &fox, 0.0),
            pattern!(&kb, [{ ?book @ literature::author: &target_author }])
        )
    )
    .collect();
    println!("  {} rows:", matched.len());
    for (b,) in &matched {
        let title = titles
            .iter()
            .find(|(id, _)| id == b)
            .map(|(_, t)| t.as_str())
            .unwrap_or("?");
        println!("    {b}  {title}");
    }

    // Sanity: doc_c ("Fox Adventure") has fox in the title but
    // wrong author — excluded. doc_d ("Unrelated") has right
    // author but no fox — excluded. doc_a + doc_b survive.
    assert_eq!(matched.len(), 2, "expected 2 surviving books");

    // ─ Bonus: filter through the engine, score precisely after ─
    println!("\nscored variant: title 'fox' with BM25 scores:");
    use triblespace_core::inline::IntoInline;
    let mut scored: Vec<(Id, f32)> = find!(
        (book: Id),
        idx.matches(book, &fox, 0.0)
    )
    .map(|(b,)| (b, idx.score(&b.to_inline(), &fox)))
    .collect();
    scored.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    for (b, s) in &scored {
        let title = titles
            .iter()
            .find(|(id, _)| id == b)
            .map(|(_, t)| t.as_str())
            .unwrap_or("?");
        println!("    {b}  score={s:.3}  {title}");
    }
}
