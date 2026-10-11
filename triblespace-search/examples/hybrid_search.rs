//! BM25 + HNSW composed in a single `find!`.
//!
//! Scenario: a tiny catalog of papers where each paper has a
//! title (suitable for lexical search) and an embedding handle
//! (suitable for semantic similarity). We build a BM25 index
//! over the titles, put each paper's embedding handle in a
//! TribleSet under an example attribute, and build an HNSW
//! index over every embedding handle. Then one question asks
//! both: *"papers whose title mentions 'graph' AND whose
//! embedding is close to the query vector."*
//!
//! The BM25 side binds `?paper` (entity id), the trible pattern
//! joins each paper to its embedding handle, and the HNSW
//! [`SimilarTo`][s] constraint gates on one frozen HNSW retrieval bag.
//!
//! ```sh
//! cargo run --example hybrid_search
//! ```
//!
//! [s]: triblespace_search::constraint::SimilarTo

use triblespace_core::and;
use triblespace_core::blob::MemoryBlobStore;
use triblespace_core::find;
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::macros::attributes;
use triblespace_core::macros::{entity, pattern};
use triblespace_core::query::temp;
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::TribleSet;

use triblespace_search::bm25::BM25Builder;
use triblespace_search::hnsw::HNSWBuilder;
use triblespace_search::schemas::{put_embedding, Embedding};
use triblespace_search::tokens::hash_tokens;

// Example-local attribute id — minted with `trible genid`. The
// title stays in the local `papers` vector; the KB only needs the
// paper→embedding link.
mod attrs {
    use super::*;

    attributes! {
        "03712511F65DCC9B1C45FE04184F1B44" unsafe as pub paper_embedding: Handle<Embedding>;
    }
}

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).expect("non-nil")
}

fn main() {
    // Seed a handful of papers with titles + embeddings. 4-D
    // toy vectors keep the arithmetic inspectable.
    let papers: Vec<(Id, &str, Vec<f32>)> = vec![
        (
            id(1),
            "Graph neural networks for node classification",
            vec![0.95, 0.1, 0.05, 0.0],
        ),
        (
            id(2),
            "Succinct data structures for graph search",
            vec![0.90, 0.15, 0.10, 0.0],
        ),
        (
            id(3),
            "Graph kernels compared to transformer pooling",
            vec![0.0, 0.0, 1.0, 0.0],
        ),
        (
            id(4),
            "Efficient k-NN search with inverted files",
            vec![0.92, 0.08, 0.0, 0.0],
        ),
        (
            id(5),
            "Monte Carlo tree search for game playing",
            vec![0.0, 0.1, 0.0, 1.0],
        ),
    ];

    println!("Corpus: {} papers\n", papers.len());
    for (pid, title, _) in &papers {
        println!("  {pid}  {title}");
    }

    // One MemoryBlobStore holds every embedding blob. Put them
    // up front so both the HNSW index and the TribleSet can
    // reference the same handles.
    let mut store = MemoryBlobStore::new();
    let mut handles: std::collections::HashMap<Id, Inline<Handle<Embedding>>> =
        std::collections::HashMap::new();
    for (pid, _title, vec) in &papers {
        let h = put_embedding::<_>(&mut store, vec.clone()).unwrap();
        handles.insert(*pid, h);
    }

    // KB: each paper's embedding handle as a trible attribute.
    let mut kb = TribleSet::new();
    for (pid, _title, _) in &papers {
        kb += entity! { ExclusiveId::force_ref(pid) @
            attrs::paper_embedding: handles[pid],
        };
    }

    // Build the BM25 index over titles and the HNSW index over
    // embedding handles. Both key on the same corpus of papers.
    let mut bm25_b = BM25Builder::new();
    let mut hnsw_b = HNSWBuilder::new(4).with_seed(42);
    for (pid, title, vec) in &papers {
        bm25_b.insert(pid, hash_tokens(title));
        hnsw_b.insert(handles[pid], vec.clone()).unwrap();
    }
    let bm25 = bm25_b.build();
    let hnsw = hnsw_b.build();

    // Put the query vector into the store as the fixed ANN probe.
    let query_handle = put_embedding::<_>(&mut store, vec![1.0, 0.0, 0.0, 0.0]).unwrap();
    let snapshot = store.snapshot().unwrap();
    let hnsw_view = hnsw.attach(&snapshot);

    // The headline query: title contains "graph" AND embedding
    // close to [1,0,0,0] (cos ≥ 0.8). One `find!`, three
    // constraints joined on `?paper` and `?emb`. `matches_text`
    // tokenises "graph" internally — no `hash_tokens` ceremony
    // for a one-shot query like this.
    let floor = 0.8f32;
    println!("\nQuery: title contains 'graph' AND embedding close to [1,0,0,0] (cos ≥ {floor})");

    let hits: Vec<(Id,)> = find!(
        (paper: Id),
        temp!(
            (emb),
            and!(
                bm25.matches_text(paper, "graph", 0.0),
                pattern!(&kb, [{ ?paper @ attrs::paper_embedding: ?emb }]),
                hnsw_view.similar_to(query_handle, emb, floor)
            )
        )
    )
    .collect();

    println!("  {} rows:", hits.len());
    for (pid,) in &hits {
        let title = papers
            .iter()
            .find(|(x, _, _)| x == pid)
            .map(|(_, t, _)| *t)
            .unwrap_or("?");
        println!("    {pid}  {title}");
    }

    // Expected survivors:
    //   Paper 1: "graph" ✓  +  close ✓  → in
    //   Paper 2: "graph" ✓  +  close ✓  → in
    //   Paper 3: "graph" ✓  +  far    ✗  → out (semantic filter)
    //   Paper 4: "graph" ✗  +  close ✓  → out (lexical filter)
    //   Paper 5: "graph" ✗  +  far    ✗  → out
    let got: std::collections::HashSet<Id> = hits.iter().map(|(p,)| *p).collect();
    assert!(got.contains(&id(1)));
    assert!(got.contains(&id(2)));
    assert!(!got.contains(&id(3)), "paper 3 must be excluded by HNSW");
    assert!(!got.contains(&id(4)), "paper 4 must be excluded by BM25");
    assert!(!got.contains(&id(5)));

    println!("\n✓ hybrid AND works — neither constraint alone is sufficient");
}
