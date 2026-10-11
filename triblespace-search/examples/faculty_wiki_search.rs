//! End-to-end runnable version of the skeleton in
//! `docs/FACULTY_INTEGRATION.md`.
//!
//! This isn't a real faculty (those live in the sibling
//! `faculties` repo and ship as `rust-script` shebangs) — it's
//! the same refresh/query loop wired up as a normal cargo
//! example so the integration doc is verified, not aspirational.
//!
//! What it demonstrates:
//! - A `wiki` namespace with a title + body + index attribute,
//!   ids minted via `trible genid`.
//! - A stable anchor id that carries the "current index" handle
//!   in a single trible — the option the doc recommends as the
//!   default.
//! - Refresh: walk the KB for `(fragment, body)` pairs, build a
//!   `SuccinctBM25Index`, `put` the blob, overwrite the anchor's
//!   `wiki::index` trible with the new handle.
//! - Query: follow the anchor to the handle, load the index from
//!   the pile, then run a single `find!` that joins
//!   `bm25_query(?doc, ?score, tokens)` with a title
//!   `pattern!` clause — one engine pass, `(doc, score, title)`
//!   rows out. Sort + truncate in Rust after `.collect()`.
//!
//! The pile lives in a tempdir so the example is self-cleaning.
//!
//! ```sh
//! cargo run --example faculty_wiki_search
//! ```

use std::error::Error;

use tempfile::tempdir;

use anybytes::View;
use triblespace_core::find;
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::{entity, pattern};
use triblespace_core::prelude::blobencodings;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use triblespace_core::trible::TribleSet;

use triblespace_search::bm25::BM25Builder;
use triblespace_search::succinct::{SuccinctBM25Blob, SuccinctBM25Index};
use triblespace_search::tokens::hash_tokens;

// ─ namespace ─ ids minted with `trible genid` on 2026-04-21.
mod wiki {
    use triblespace_core::macros::attributes;
    use triblespace_core::prelude::*;
    use triblespace_search::succinct::SuccinctBM25Blob;

    attributes! {
        "F27792C7AF218F1BAE047650DF560B95"
            as pub title: inlineencodings::Handle<blobencodings::UTF8String>;
        "512F2ABC687A4E42916C19E6A552B285"
            as pub body: inlineencodings::Handle<blobencodings::UTF8String>;
        // `index` rotated again 2026-08-03 alongside the
        // `SuccinctBM25Blob` schema id rotation from score postings
        // (`DA527A8FF09A3709B2AC6425CD5AF7A8`) to exact raw term
        // frequencies (`DAFEEEC9350D072B83E32DBBBBB66039`). Old triples
        // under attribute id `EBDECCC621ABA8DA8C81D48A9B19347C`
        // cannot be loaded by the current code; the rotation makes that
        // incompatibility explicit at the trible level. See
        // `docs/FACULTY_INTEGRATION.md` § "What the caller has to
        // rotate" for the migration recipe.
        "75C8930CB8E9C3E8D2CAC2C8DE6489A4"
            as pub index: inlineencodings::Handle<SuccinctBM25Blob>;
    }

    // Single stable id every faculty reader agrees on as the
    // place to look for "the current wiki bm25 index". Minted
    // alongside the attributes; lives in its own constant so
    // the refresh path can write the trible and the query path
    // can read it.
    pub const INDEX_ANCHOR: triblespace_core::id::Id =
        triblespace_core::id::id_hex!("5C6F102420709DBB910B197D4B91E83E");
}

fn fragment_id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("non-nil")
}

/// Seed step — stands in for "whatever populated the pile with
/// wiki fragments". A real faculty wouldn't have this; it would
/// inherit whatever the caller committed.
fn seed(pile: &mut Pile) -> Result<TribleSet, Box<dyn Error>> {
    let docs = [
        (
            fragment_id(1),
            "The Quick Brown Fox",
            "The quick brown fox jumps over the lazy dog. \
             A pangram from typography.",
        ),
        (
            fragment_id(2),
            "Silver Foxes",
            "Silver foxes are melanistic coat variants of the \
             common red fox.",
        ),
        (
            fragment_id(3),
            "Lazy Dogs",
            "The lazy dog is a classic placeholder phrase; \
             no actual dogs involved.",
        ),
        (
            fragment_id(4),
            "Typography Notes",
            "Pangrams are useful for previewing typefaces. \
             Many famous pangrams feature a fox.",
        ),
    ];

    let mut kb = TribleSet::new();
    for (id, title, body) in &docs {
        let title_handle = pile.put::<blobencodings::UTF8String, _>(title.to_string())?;
        let body_handle = pile.put::<blobencodings::UTF8String, _>(body.to_string())?;
        kb += entity! { ExclusiveId::force_ref(id) @
            wiki::title: title_handle,
            wiki::body: body_handle,
        };
    }
    Ok(kb)
}

/// Refresh: query the KB for `(id, body)`, load each body blob,
/// hash-tokenize, build a SuccinctBM25Index, put it, overwrite
/// the anchor trible with the new handle.
fn refresh(
    pile: &mut Pile,
    kb: &mut TribleSet,
) -> Result<Inline<Handle<SuccinctBM25Blob>>, Box<dyn Error>> {
    let body_handles: Vec<(Id, Inline<Handle<blobencodings::UTF8String>>)> = find!(
        (id: Id, body: Inline<Handle<blobencodings::UTF8String>>),
        pattern!(&*kb, [{ ?id @ wiki::body: ?body }])
    )
    .collect();

    let snapshot = pile.snapshot()?;
    let mut builder: BM25Builder = BM25Builder::new();
    for (id, handle) in &body_handles {
        let body: View<str> = snapshot.get::<View<str>, blobencodings::UTF8String>(*handle)?;
        builder.insert(*id, hash_tokens(body.as_ref()));
    }
    let idx: SuccinctBM25Index = builder.build();
    let handle = pile.put::<SuccinctBM25Blob, _>(&idx)?;

    // Option A from the design doc: store the current index
    // handle in a single trible under a stable anchor id. The
    // anchor lives in-crate so every reader finds the same
    // place. Rebuild-and-replace: overwrite any previous value.
    *kb += entity! { ExclusiveId::force_ref(&wiki::INDEX_ANCHOR) @
        wiki::index: handle,
    };
    Ok(handle)
}

fn query(
    pile: &mut Pile,
    kb: &TribleSet,
    text: &str,
    top_k: usize,
) -> Result<Vec<(Id, f32, String)>, Box<dyn Error>> {
    use triblespace_core::and;

    // Resolve the anchor → handle.
    let anchor = wiki::INDEX_ANCHOR;
    let handles: Vec<(Inline<Handle<SuccinctBM25Blob>>,)> = find!(
        (h: Inline<Handle<SuccinctBM25Blob>>),
        pattern!(kb, [{ &anchor @ wiki::index: ?h }])
    )
    .collect();
    let handle = handles
        .first()
        .ok_or("no wiki::index trible under the anchor — run refresh first")?
        .0;

    let snapshot = pile.snapshot()?;
    let idx: SuccinctBM25Index = snapshot.get::<SuccinctBM25Index, SuccinctBM25Blob>(handle)?;

    // One engine pass: `matches` filters by score floor 0.0, the
    // trible pattern joins on the shared `?doc` to pick the
    // title up at the same time. Ranking is operational — score
    // each row through `idx.score` after collecting, then sort.
    use triblespace_core::inline::IntoInline;
    let tokens = hash_tokens(text);
    let mut rows: Vec<(Id, f32, String)> = Vec::new();
    for (doc, title) in find!(
        (doc: Id, title: Inline<Handle<blobencodings::UTF8String>>),
        and!(
            idx.matches(doc, &tokens, 0.0),
            pattern!(kb, [{ ?doc @ wiki::title: ?title }])
        )
    ) {
        let title: View<str> = snapshot.get(title)?;
        rows.push((doc, idx.score(&doc.to_inline(), &tokens), title.to_string()));
    }
    rows.sort_unstable_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    rows.truncate(top_k);
    Ok(rows)
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let pile_path = dir.path().join("wiki.pile");
    std::fs::File::create(&pile_path)?;

    let mut pile = Pile::open(&pile_path)?;
    pile.refresh()?;

    let mut kb = seed(&mut pile)?;
    let n_seeded = find!(
        (id: Id, h: Inline<Handle<blobencodings::UTF8String>>),
        pattern!(&kb, [{ ?id @ wiki::body: ?h }])
    )
    .count();
    println!("seeded {} fragments into {}", n_seeded, pile_path.display(),);

    let handle = refresh(&mut pile, &mut kb)?;
    pile.flush()?;
    println!("built index, handle = {handle:?}");

    for q in &["fox", "lazy dog", "typography pangram"] {
        println!("\nquery: {q:?}");
        let rows = query(&mut pile, &kb, q, 3)?;
        if rows.is_empty() {
            println!("  (no matches)");
        }
        for (id, score, title) in rows {
            println!("  {id}  score={score:6.3}  {title}");
        }
    }

    pile.close()?;
    Ok(())
}
