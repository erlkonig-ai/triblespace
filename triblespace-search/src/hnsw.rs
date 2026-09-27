//! Approximate nearest-neighbour search over caller-supplied
//! embeddings.
//!
//! [`HNSWIndex`] is the naive layered-graph implementation
//! (Malkov & Yashunin 2018). It's the builder + in-memory
//! representation; convert to [`crate::succinct::SuccinctHNSWIndex`]
//! and use `SuccinctHNSWBlob` for the content-addressed on-pile
//! form.
//!
//! [`FlatIndex`] is the brute-force exact cosine baseline — useful
//! for ≤ 100k docs, for ground-truth recall checks, and for
//! doctest examples without the graph build overhead.
//!
//! # Build and query
//!
//! ```
//! # use triblespace_core::blob::MemoryBlobStore;
//! # use triblespace_core::repo::SnapshotSource;
//! # use triblespace_core::inline::encodings::hash::Blake3;
//! # use triblespace_search::hnsw::FlatBuilder;
//! # use triblespace_search::schemas::put_embedding;
//! let mut store = MemoryBlobStore::new();
//! let h1 = put_embedding::<_>(&mut store, vec![1.0, 0.0, 0.0, 0.0]).unwrap();
//! let h2 = put_embedding::<_>(&mut store, vec![0.0, 1.0, 0.0, 0.0]).unwrap();
//! let h3 = put_embedding::<_>(&mut store, vec![0.9, 0.1, 0.0, 0.0]).unwrap();
//!
//! let mut b = FlatBuilder::new(4);
//! b.insert(h1);
//! b.insert(h2);
//! b.insert(h3);
//! let idx = b.build();
//!
//! // Fixed-probe retrieval is explicit; exact pair filtering lives in the
//! // separate `cosine_at_least(a, b, floor)` predicate.
//! let snapshot = store.snapshot().unwrap();
//! let view = idx.attach(&snapshot);
//! let hits = view.candidates_above(h1, 0.8).unwrap();
//! assert!(hits.contains(&h1));
//! assert!(hits.contains(&h3));
//! assert!(!hits.contains(&h2));
//! ```

use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::query::Variable;

use crate::schemas::{EmbHandle, Embedding};

// ── HNSW blob byte format ────────────────────────────────────────────
//
// No magic bytes, no version field: the blob-level type
// (a typed `BlobEncoding` / handle on the pile side, or the
// `HNSWIndex::try_from_bytes` entry point itself) is the
// identity. A breaking format change mints a new schema ID
// and therefore a new type, so the compiler polices it.

// ── Proper HNSW graph (layered, approximate k-NN) ─────────────────

/// Per-node state during build: vector lives inline so graph
/// construction can compute distances without touching a blob
/// store. `build()` strips the vector and produces
/// [`HNSWIndexNode`].
#[derive(Debug)]
struct HNSWNode {
    vector: Vec<f32>,
    level: u8,
    neighbors: Vec<Vec<u32>>,
}

/// Post-build per-node state. No vector — queries resolve
/// embeddings through a caller-supplied blob store via the
/// parallel `handles` table.
#[derive(Debug)]
struct HNSWIndexNode {
    level: u8,
    neighbors: Vec<Vec<u32>>,
}

/// Builder for a proper layered-graph HNSW index.
///
/// Implements the incremental insert from Malkov & Yashunin
/// (2018) with the standard level-sampling + ef-search + simple
/// neighbour-selection heuristic. Parameters follow the paper's
/// defaults unless overridden on the builder.
pub struct HNSWBuilder {
    dim: usize,
    m: u16,
    m0: u16,
    ef_construction: u16,
    /// Level-sampling multiplier `m_L = 1 / ln(M)`.
    level_mult: f32,
    /// SplitMix64 state for deterministic level sampling.
    rng: u64,
    /// Per-node state, inclusive of the inline vector used for
    /// graph-construction distance computations. The vectors
    /// get stripped when `build()` consumes the builder —
    /// they don't survive into `HNSWIndex`.
    nodes: Vec<HNSWNode>,
    /// Content-addressed handle for each node's embedding.
    /// Parallel-indexed with `nodes`; the final [`HNSWIndex`]
    /// keeps this table for query-time resolution.
    ///
    /// Nodes are identified by their embedding handles, not by
    /// any caller-supplied doc key — the mapping from a caller's
    /// document to an embedding is a trible the caller owns, not
    /// something the index duplicates.
    handles: Vec<Inline<Handle<Embedding>>>,
    entry_point: Option<u32>,
    max_level: u8,
}

impl HNSWBuilder {
    /// Create a fresh builder with `dim`-dimensional vectors and
    /// default HNSW parameters (`M = 16`, `M0 = 2*M = 32`,
    /// `ef_construction = 200`). The deterministic PRNG seed
    /// starts at `0xC0FFEE_HNSW`; override via
    /// [`with_seed`][Self::with_seed] for reproducible but
    /// differently-ordered builds.
    pub fn new(dim: usize) -> Self {
        assert!(dim > 0, "HNSWBuilder: dim must be > 0");
        let m = 16u16;
        Self {
            dim,
            m,
            m0: m * 2,
            ef_construction: 200,
            level_mult: 1.0 / (m as f32).ln(),
            rng: 0xC0FFEEu64,
            nodes: Vec::new(),
            handles: Vec::new(),
            entry_point: None,
            max_level: 0,
        }
    }

    /// Override `M` (max neighbours on non-zero layers). `M0`
    /// defaults to `2 * M` unless overridden separately.
    pub fn m(mut self, m: u16) -> Self {
        assert!(m >= 2, "HNSWBuilder: M must be ≥ 2");
        self.m = m;
        self.m0 = m * 2;
        self.level_mult = 1.0 / (m as f32).ln();
        self
    }

    /// Override `M0` (max neighbours on layer 0). Must be ≥ M.
    pub fn m0(mut self, m0: u16) -> Self {
        assert!(m0 >= self.m, "HNSWBuilder: M0 must be ≥ M");
        self.m0 = m0;
        self
    }

    /// Override `ef_construction` (search width during insert).
    pub fn ef_construction(mut self, ef: u16) -> Self {
        assert!(ef >= 1, "HNSWBuilder: ef_construction must be ≥ 1");
        self.ef_construction = ef;
        self
    }

    /// Override the level-sampling PRNG seed for reproducibility
    /// across runs.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = seed;
        self
    }

    /// Sample a new node level from `⌊-ln(U) * m_L⌋`.
    fn sample_level(&mut self) -> u8 {
        // SplitMix64 step.
        self.rng = self.rng.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        // Map to uniform (0, 1] so `ln` is defined.
        let u = ((z >> 11) as f64 / (1u64 << 53) as f64).max(f64::MIN_POSITIVE);
        let l = (-u.ln() * self.level_mult as f64).floor() as i32;
        l.clamp(0, u8::MAX as i32) as u8
    }

    /// Insert an embedding into the graph by its
    /// content-addressed `handle` and the raw `vec` used for
    /// build-time distance computations. The builder keeps the
    /// vector in RAM during graph construction and strips it at
    /// [`build`][Self::build]; the final [`HNSWIndex`] only
    /// carries the handle, so embeddings live in the pile's
    /// blob store and dedupe across indexes.
    ///
    /// The vector is L2-normalized in place before distance
    /// computation, so the index treats its metric as cosine
    /// similarity; the stored `handle` is expected to point at
    /// an already-normalized embedding (the [`put_embedding`]
    /// helper normalizes before put).
    ///
    /// Note: the index stores handles only — the caller's
    /// mapping from doc / entity to embedding handle is a
    /// trible the caller owns, not something the index
    /// duplicates.
    ///
    /// [`put_embedding`]: crate::schemas::put_embedding
    pub fn insert(
        &mut self,
        handle: Inline<Handle<Embedding>>,
        mut vec: Vec<f32>,
    ) -> Result<(), DimMismatch> {
        if vec.len() != self.dim {
            return Err(DimMismatch {
                expected: self.dim,
                got: vec.len(),
            });
        }
        normalize(&mut vec);
        let new_level = self.sample_level();
        let new_idx = self.nodes.len() as u32;

        // Descend from entry_point down to new_level + 1 using
        // greedy 1-step search.
        let mut curr = self.entry_point;
        if let Some(mut cnode) = curr {
            for lvl in ((new_level + 1)..=self.max_level).rev() {
                cnode = self.greedy_search_layer(&vec, cnode, lvl);
            }
            curr = Some(cnode);
        }

        // Allocate the new node before connecting so neighbour
        // indexes are stable.
        self.nodes.push(HNSWNode {
            vector: vec.clone(),
            level: new_level,
            neighbors: vec![Vec::new(); new_level as usize + 1],
        });
        self.handles.push(handle);

        // Connect from new_level down to 0.
        if let Some(start) = curr {
            let mut entry = start;
            for lvl in (0..=new_level.min(self.max_level)).rev() {
                let cap = if lvl == 0 { self.m0 } else { self.m } as usize;
                let candidates = self.search_layer(&vec, entry, self.ef_construction as usize, lvl);
                let selected = Self::select_neighbours(&candidates, cap);

                // Bidirectional edges.
                for &n in &selected {
                    self.nodes[new_idx as usize].neighbors[lvl as usize].push(n);
                    self.nodes[n as usize].neighbors[lvl as usize].push(new_idx);
                }
                // Prune the new node's layer-list and the new
                // neighbours' lists to the layer cap.
                self.prune_neighbours(new_idx, lvl, cap);
                for &n in &selected {
                    self.prune_neighbours(n, lvl, cap);
                }

                // Pick the best candidate as entry for the next
                // (lower) layer.
                if let Some((best, _)) = candidates
                    .iter()
                    .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                {
                    entry = *best;
                }
            }
        }

        if new_level > self.max_level || self.entry_point.is_none() {
            self.max_level = new_level;
            self.entry_point = Some(new_idx);
        }
        Ok(())
    }

    /// Consume the builder and produce a succinct HNSW index,
    /// ready to `put` into a pile or query directly. This is
    /// the production path — the naive in-memory [`HNSWIndex`]
    /// is kept only as a reference oracle (see
    /// [`build_naive`][Self::build_naive]).
    #[cfg(feature = "succinct")]
    pub fn build(self) -> crate::succinct::SuccinctHNSWIndex {
        crate::succinct::SuccinctHNSWIndex::from_naive(&self.build_naive())
            .expect("from_naive cannot fail on a valid HNSWIndex built by HNSWBuilder")
    }

    /// Naive layered-graph reference index. Strips the inline
    /// build-time vectors — only the handles survive; embeddings
    /// are resolved at query time through the caller-supplied
    /// blob store. Kept public as a correctness oracle for tests
    /// validating the succinct form, and as an intermediate when
    /// callers already hold a naive index and want
    /// [`SuccinctHNSWIndex::from_naive`][crate::succinct::SuccinctHNSWIndex::from_naive]
    /// directly. Most callers want [`build`][Self::build].
    pub fn build_naive(self) -> HNSWIndex {
        let nodes: Vec<HNSWIndexNode> = self
            .nodes
            .into_iter()
            .map(|n| HNSWIndexNode {
                level: n.level,
                neighbors: n.neighbors,
            })
            .collect();
        HNSWIndex {
            dim: self.dim,
            m: self.m,
            m0: self.m0,
            nodes,
            handles: self.handles,
            entry_point: self.entry_point,
            max_level: self.max_level,
        }
    }

    // ── HNSW primitives (shared with the immutable index) ────────

    /// Walk greedily to the node with minimum distance to `q` on
    /// `layer` starting from `entry`. O(neighbours_on_layer)
    /// per step. Used for intermediate layers during both insert
    /// and search.
    fn greedy_search_layer(&self, q: &[f32], entry: u32, layer: u8) -> u32 {
        let mut curr = entry;
        let mut curr_dist = cosine_dist(q, &self.nodes[curr as usize].vector);
        loop {
            let mut changed = false;
            let node = &self.nodes[curr as usize];
            let Some(neigh) = node.neighbors.get(layer as usize) else {
                return curr;
            };
            for &n in neigh {
                let d = cosine_dist(q, &self.nodes[n as usize].vector);
                if d < curr_dist {
                    curr_dist = d;
                    curr = n;
                    changed = true;
                }
            }
            if !changed {
                return curr;
            }
        }
    }

    /// Standard HNSW layer ef-search. Returns a list of
    /// `(node_idx, distance)` pairs, up to `ef` of them.
    fn search_layer(&self, q: &[f32], entry: u32, ef: usize, layer: u8) -> Vec<(u32, f32)> {
        use std::collections::BinaryHeap;

        let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
        visited.insert(entry);
        let d0 = cosine_dist(q, &self.nodes[entry as usize].vector);
        let mut candidates: BinaryHeap<MinDist> = BinaryHeap::new();
        candidates.push(MinDist {
            idx: entry,
            dist: d0,
        });
        let mut results: BinaryHeap<MaxDist> = BinaryHeap::new();
        results.push(MaxDist {
            idx: entry,
            dist: d0,
        });
        while let Some(c) = candidates.pop() {
            let farthest = results.peek().map(|r| r.dist).unwrap_or(f32::INFINITY);
            if c.dist > farthest && results.len() >= ef {
                break;
            }
            let node = &self.nodes[c.idx as usize];
            let Some(neigh) = node.neighbors.get(layer as usize) else {
                continue;
            };
            for &n in neigh {
                if !visited.insert(n) {
                    continue;
                }
                let d = cosine_dist(q, &self.nodes[n as usize].vector);
                let farthest = results.peek().map(|r| r.dist).unwrap_or(f32::INFINITY);
                if d < farthest || results.len() < ef {
                    candidates.push(MinDist { idx: n, dist: d });
                    results.push(MaxDist { idx: n, dist: d });
                    if results.len() > ef {
                        results.pop();
                    }
                }
            }
        }
        results.into_iter().map(|m| (m.idx, m.dist)).collect()
    }

    /// Pick the `cap` closest candidates. The paper's simple
    /// heuristic — good enough for typical embedding spaces and
    /// the simplest thing to unit-test. The "extended" heuristic
    /// that considers inter-candidate distances can swap in
    /// later behind the same function signature.
    fn select_neighbours(candidates: &[(u32, f32)], cap: usize) -> Vec<u32> {
        let mut sorted: Vec<&(u32, f32)> = candidates.iter().collect();
        sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        sorted.into_iter().take(cap).map(|&(i, _)| i).collect()
    }

    /// Trim `node`'s layer-`layer` neighbour list to `cap`
    /// entries, keeping the closest by distance.
    fn prune_neighbours(&mut self, node: u32, layer: u8, cap: usize) {
        // Borrow-checker dance: snapshot the neighbour ids and
        // the node's vector so we can score against `self.nodes`
        // without holding a mut-borrow on the list.
        let list_snapshot: Vec<u32> = self.nodes[node as usize].neighbors[layer as usize].clone();
        if list_snapshot.len() <= cap {
            // Already small enough; just dedupe in place.
            let list = &mut self.nodes[node as usize].neighbors[layer as usize];
            list.sort_unstable();
            list.dedup();
            return;
        }
        let q = self.nodes[node as usize].vector.clone();
        let mut scored: Vec<(u32, f32)> = list_snapshot
            .iter()
            .map(|&n| (n, cosine_dist(&q, &self.nodes[n as usize].vector)))
            .collect();
        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        let list = &mut self.nodes[node as usize].neighbors[layer as usize];
        list.clear();
        list.extend(scored.into_iter().take(cap).map(|(i, _)| i));
        list.sort_unstable();
        list.dedup();
    }
}

/// Naive layered-graph HNSW index — reference / oracle form.
/// The canonical path is [`crate::testing::HNSWIndex`];
/// `#[doc(hidden)]` here so the blessed path is the only one
/// in rendered docs.
///
/// Produce via [`HNSWBuilder::build_naive`]. Query performance
/// is sub-linear in corpus size (O(log n · degree) typical) —
/// the trade-off is a larger up-front build cost than
/// [`FlatIndex`] and slightly approximate recall. For persistence
/// and production queries use
/// [`crate::succinct::SuccinctHNSWIndex`] instead.
#[doc(hidden)]
pub struct HNSWIndex {
    dim: usize,
    m: u16,
    m0: u16,
    /// Post-build per-node state. Neighbour lists survive; the
    /// vectors were stripped — distance evaluations resolve
    /// handles through a caller-supplied blob store.
    nodes: Vec<HNSWIndexNode>,
    /// Embedding handle per node. The node IS the handle — the
    /// index doesn't know or care about any caller-level doc
    /// identity. The caller's doc-to-embedding mapping lives
    /// as tribles in the pile.
    handles: Vec<Inline<Handle<Embedding>>>,
    entry_point: Option<u32>,
    max_level: u8,
}

impl std::fmt::Debug for HNSWIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HNSWIndex")
            .field("n_nodes", &self.handles.len())
            .field("dim", &self.dim)
            .field("max_level", &self.max_level)
            .finish()
    }
}

impl HNSWIndex {
    /// Vector dimensionality configured at build time.
    pub fn dim(&self) -> usize {
        self.dim
    }
    /// Number of nodes in the graph.
    pub fn doc_count(&self) -> usize {
        self.handles.len()
    }
    /// Max neighbours per non-zero layer.
    pub fn m(&self) -> u16 {
        self.m
    }
    /// Max neighbours on layer 0.
    pub fn m0(&self) -> u16 {
        self.m0
    }
    /// Highest layer a node was inserted at.
    pub fn max_level(&self) -> u8 {
        self.max_level
    }

    /// Level node `i` was sampled into.
    pub fn node_level(&self, i: usize) -> Option<u8> {
        self.nodes.get(i).map(|n| n.level)
    }

    /// Neighbours of node `i` on `layer`. Empty slice if the
    /// node wasn't inserted at that layer.
    pub fn node_neighbours(&self, i: usize, layer: u8) -> &[u32] {
        self.nodes
            .get(i)
            .and_then(|n| n.neighbors.get(layer as usize))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// The stored embedding-handle table. `handles()[i]` is the
    /// content-addressed pointer to the embedding blob for node
    /// `i`.
    pub fn handles(&self) -> &[Inline<Handle<Embedding>>] {
        &self.handles
    }

    /// Current entry-point node index (the last inserted node
    /// at `max_level`), or `None` if the index is empty.
    pub fn entry_point(&self) -> Option<u32> {
        self.entry_point
    }

    /// Attach a blob store to this index, returning a queryable
    /// view. The view owns a [`BlobCache`][c] over the store,
    /// keyed on `Handle<Embedding>`, so repeat visits
    /// to the same node during graph walks deserialize each
    /// embedding at most once per view lifetime.
    ///
    /// [c]: triblespace_core::blob::BlobCache
    pub fn attach<'a, B>(&'a self, store: &B) -> AttachedHNSWIndex<'a, B>
    where
        B: triblespace_core::repo::BlobStoreGet + Clone,
    {
        AttachedHNSWIndex {
            index: self,
            cache: triblespace_core::blob::BlobCache::new(store.clone()),
            ef_search: 200,
        }
    }

    /// Theoretical size of the naive flat-array serialization in
    /// bytes — kept as a baseline to regression-check that the
    /// succinct HNSW blob actually saves space.
    ///
    /// Layout: 24 B header + `n_nodes × 32 B` handles + `n_nodes
    /// × 1 B` levels + per-node offset table
    /// (`(max_level + 2) × 4 B` stride) + total neighbours × 4 B.
    pub fn byte_size(&self) -> usize {
        let n = self.nodes.len();
        let entries_per_node = (self.max_level as usize) + 2;
        let total_neighbours: usize = self
            .nodes
            .iter()
            .map(|n| n.neighbors.iter().map(|l| l.len()).sum::<usize>())
            .sum();
        24 + n * 32 + n + n * entries_per_node * 4 + total_neighbours * 4
    }
}

/// A [`HNSWIndex`] paired with the blob store its handles
/// resolve against — produced by [`HNSWIndex::attach`]. All
/// `similar_*` methods live here; the bare [`HNSWIndex`] only
/// exposes metadata and the blob format. Canonical path:
/// [`crate::testing::AttachedHNSWIndex`].
///
/// The view owns a [`BlobCache`][c] over the provided store,
/// specialized to `(Embedding, View<[f32]>)`. HNSW graph walks
/// revisit neighbour nodes repeatedly — the cache collapses
/// those into a single blob-fetch + deserialize per node per
/// view lifetime.
///
/// [c]: triblespace_core::blob::BlobCache
#[doc(hidden)]
pub struct AttachedHNSWIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    index: &'a HNSWIndex,
    cache: triblespace_core::blob::BlobCache<B, Embedding, anybytes::View<[f32]>>,
    ef_search: usize,
}

impl<'a, B> AttachedHNSWIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    /// The inner index (back-reference for metadata queries).
    pub fn index(&self) -> &HNSWIndex {
        self.index
    }

    /// Override the search-beam width used when the similarity
    /// constraint walks the graph. Larger values trade compute
    /// for recall on high-threshold queries. Default 200.
    pub fn with_ef_search(mut self, ef: usize) -> Self {
        self.ef_search = ef;
        self
    }

    /// Build an exact symmetric cosine predicate over two handle variables.
    /// This is filter-only: other constraints source both domains. Use
    /// [`Self::similar_to`] for directional HNSW retrieval.
    pub fn cosine_at_least(
        &self,
        a: Variable<EmbHandle>,
        b: Variable<EmbHandle>,
        score_floor: f32,
    ) -> crate::constraint::CosineAtLeast<'_, Self, Embedding> {
        crate::constraint::CosineAtLeast::new(self, a, b, score_floor)
    }

    /// Convenience wrapper for the common
    /// "search from a known handle" case. Freezes one directional ANN walk
    /// rather than pretending it is an exact binary predicate; see
    /// [`crate::constraint::SimilarTo`].
    ///
    /// Walks the index once at construction and caches the
    /// result — subsequent engine `propose` / `confirm` calls
    /// iterate the cached list.
    ///
    /// [`Self::candidates_above`] can repeat a handle (see its docs), so
    /// the collapse inside
    /// [`SimilarTo::from_candidates`][crate::constraint::SimilarTo::from_candidates]
    /// is load-bearing on this path, not defensive.
    pub fn similar_to(
        &self,
        probe: Inline<EmbHandle>,
        var: Variable<EmbHandle>,
        score_floor: f32,
    ) -> crate::constraint::SimilarTo<EmbHandle> {
        let candidates = self
            .candidates_above(probe, score_floor)
            .map(|v| v.into_iter().map(|h| h.raw).collect())
            .unwrap_or_default();
        crate::constraint::SimilarTo::from_candidates(var, candidates)
    }

    /// Leaf graph-walk primitive used by [`Self::similar_to`]. Surfaced for tests
    /// (correctness oracles) and benchmarks (timing the walk in
    /// isolation from engine overhead). **Production callers
    /// should use the engine path** —
    /// [`Self::similar_to`] inside a
    /// `find!` / `pattern!` / `and!` query — so the result
    /// composes with other constraints (BM25, pattern, range)
    /// in one engine pass instead of materialising a Vec just
    /// to feed the next stage.
    ///
    /// Bound by the view's `ef_search` (default 200) — callers
    /// pushing lots of above-threshold results need a wider
    /// beam via [`with_ef_search`][Self::with_ef_search].
    ///
    /// **Not distinct.** The graph walk dedups by *node index*, then maps
    /// node → handle through [`HNSWIndex::handles`], which stores one
    /// entry per [`HNSWBuilder::insert`] call with no collapse. Handles
    /// are content-addressed, so two entities embedding to the same vector
    /// share one handle and both nodes surface it. Callers that need a set
    /// must collapse — [`SimilarTo::from_candidates`]
    /// does so before the candidates enter the query engine.
    #[doc(hidden)]
    pub fn candidates_above(
        &self,
        from_handle: Inline<EmbHandle>,
        score_floor: f32,
    ) -> Result<Vec<Inline<EmbHandle>>, B::GetError<crate::schemas::EmbeddingError>> {
        let Some(entry) = self.index.entry_point else {
            return Ok(Vec::new());
        };
        let from = self.cache.get(from_handle)?;
        let query: Vec<f32> = from.as_ref().as_ref().to_vec();
        if query.len() != self.index.dim {
            return Ok(Vec::new());
        }
        // The stored vectors are pre-normalised, and embeddings
        // that land here came from `put_embedding` which also
        // L2-normalises, so the query is unit-length already.
        let mut curr = entry;
        for lvl in (1..=self.index.max_level).rev() {
            curr = self.greedy_search_layer(&query, curr, lvl)?;
        }
        let candidates = self.search_layer(&query, curr, self.ef_search, 0)?;
        Ok(candidates
            .into_iter()
            .filter(|(_, dist)| 1.0 - dist >= score_floor)
            .map(|(i, _)| self.index.handles[i as usize])
            .collect())
    }

    fn dist_to(&self, q: &[f32], i: u32) -> Result<f32, B::GetError<crate::schemas::EmbeddingError>> {
        let handle = self.index.handles[i as usize];
        let view = self.cache.get(handle)?;
        Ok(cosine_dist(q, view.as_ref().as_ref()))
    }

    fn greedy_search_layer(
        &self,
        q: &[f32],
        entry: u32,
        layer: u8,
    ) -> Result<u32, B::GetError<crate::schemas::EmbeddingError>> {
        let mut curr = entry;
        let mut curr_dist = self.dist_to(q, curr)?;
        loop {
            let mut changed = false;
            let node = &self.index.nodes[curr as usize];
            let Some(neigh) = node.neighbors.get(layer as usize) else {
                return Ok(curr);
            };
            let neigh = neigh.clone();
            for n in neigh {
                let d = self.dist_to(q, n)?;
                if d < curr_dist {
                    curr_dist = d;
                    curr = n;
                    changed = true;
                }
            }
            if !changed {
                return Ok(curr);
            }
        }
    }

    fn search_layer(
        &self,
        q: &[f32],
        entry: u32,
        ef: usize,
        layer: u8,
    ) -> Result<Vec<(u32, f32)>, B::GetError<crate::schemas::EmbeddingError>> {
        use std::collections::BinaryHeap;
        let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();
        visited.insert(entry);
        let d0 = self.dist_to(q, entry)?;
        let mut candidates: BinaryHeap<MinDist> = BinaryHeap::new();
        candidates.push(MinDist {
            idx: entry,
            dist: d0,
        });
        let mut results: BinaryHeap<MaxDist> = BinaryHeap::new();
        results.push(MaxDist {
            idx: entry,
            dist: d0,
        });
        while let Some(c) = candidates.pop() {
            let farthest = results.peek().map(|r| r.dist).unwrap_or(f32::INFINITY);
            if c.dist > farthest && results.len() >= ef {
                break;
            }
            let neigh = {
                let node = &self.index.nodes[c.idx as usize];
                let Some(neigh) = node.neighbors.get(layer as usize) else {
                    continue;
                };
                neigh.clone()
            };
            for n in neigh {
                if !visited.insert(n) {
                    continue;
                }
                let d = self.dist_to(q, n)?;
                let farthest = results.peek().map(|r| r.dist).unwrap_or(f32::INFINITY);
                if d < farthest || results.len() < ef {
                    candidates.push(MinDist { idx: n, dist: d });
                    results.push(MaxDist { idx: n, dist: d });
                    if results.len() > ef {
                        results.pop();
                    }
                }
            }
        }
        Ok(results.into_iter().map(|m| (m.idx, m.dist)).collect())
    }
}

/// Cosine distance = 1 - dot(a, b) for pre-normalized vectors.
pub(crate) fn cosine_dist(a: &[f32], b: &[f32]) -> f32 {
    1.0 - dot(a, b)
}

/// True cosine similarity for arbitrary equal-length vectors.
///
/// Indexed embeddings follow the unit-vector convention, but the blob schema
/// cannot enforce it. Pairwise predicates therefore divide by both norms
/// instead of inheriting the ANN hot path's ingest-time assumption. A zero
/// vector has similarity zero, matching the crate's existing zero-vector
/// normalization convention.
pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (&a, &b) in a.iter().zip(b) {
        let a = f64::from(a);
        let b = f64::from(b);
        dot += a * b;
        norm_a += a * a;
        norm_b += b * b;
    }
    let norm_product = norm_a * norm_b;
    if norm_product == 0.0 {
        0.0
    } else {
        (dot / norm_product.sqrt()) as f32
    }
}

/// Min-heap wrapper: smaller distance = higher priority.
#[derive(Clone, Copy)]
struct MinDist {
    idx: u32,
    dist: f32,
}
impl PartialEq for MinDist {
    fn eq(&self, o: &Self) -> bool {
        self.dist == o.dist
    }
}
impl Eq for MinDist {}
impl PartialOrd for MinDist {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for MinDist {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // Invert so BinaryHeap (max-heap) behaves as min-heap
        // over distance.
        o.dist
            .partial_cmp(&self.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

/// Max-heap wrapper: larger distance = higher priority (for
/// evicting the farthest).
#[derive(Clone, Copy)]
struct MaxDist {
    idx: u32,
    dist: f32,
}
impl PartialEq for MaxDist {
    fn eq(&self, o: &Self) -> bool {
        self.dist == o.dist
    }
}
impl Eq for MaxDist {}
impl PartialOrd for MaxDist {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for MaxDist {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.dist
            .partial_cmp(&o.dist)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

/// Caller tried to insert a vector whose length disagrees with
/// the index's configured dimensionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DimMismatch {
    pub expected: usize,
    pub got: usize,
}

impl std::fmt::Display for DimMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "embedding dimensionality mismatch: expected {}, got {}",
            self.expected, self.got
        )
    }
}

impl std::error::Error for DimMismatch {}

/// L2-normalize `v` in place. Zero vectors are left untouched.
pub(crate) fn normalize(v: &mut [f32]) {
    let norm_sq: f32 = v.iter().map(|&x| x * x).sum();
    if norm_sq > 0.0 {
        let inv = 1.0 / norm_sq.sqrt();
        for x in v.iter_mut() {
            *x *= inv;
        }
    }
}

/// Dot product. Assumes both slices have equal length.
fn dot(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(&x, &y)| x * y).sum()
}

/// Builder for a flat (brute-force) k-NN index — reference /
/// oracle form. Canonical path: [`crate::testing::FlatBuilder`].
///
/// All vectors are L2-normalized at insert time so the distance
/// metric at query time is exact cosine similarity (`dot(q, v) =
/// cos(q, v)` for unit vectors). Pre-normalizing moves the
/// division into the build pass and keeps the query hot path a
/// single dot product per doc.
#[doc(hidden)]
pub struct FlatBuilder {
    dim: usize,
    handles: Vec<Inline<Handle<Embedding>>>,
}

impl FlatBuilder {
    /// Start a fresh builder. `dim` is the expected embedding
    /// length — stored in the index and checked against the
    /// query vector at query time.
    pub fn new(dim: usize) -> Self {
        assert!(dim > 0, "FlatBuilder: dim must be > 0");
        Self {
            dim,
            handles: Vec::new(),
        }
    }

    /// Insert an embedding by its `handle` — the handle points
    /// at an [`Embedding`] blob in the pile's blob store. The
    /// builder stores neither the raw vector nor any copy of
    /// it — the pile owns the embedding and content-addresses
    /// it, so two indexes that embed the same entity share
    /// storage.
    ///
    /// Use [`crate::schemas::put_embedding`] to put + normalize
    /// + get a handle in one step.
    pub fn insert(&mut self, handle: Inline<Handle<Embedding>>) {
        self.handles.push(handle);
    }

    /// Consume the builder and produce a flat index.
    pub fn build(self) -> FlatIndex {
        FlatIndex {
            dim: self.dim,
            handles: self.handles,
        }
    }

    /// Number of embeddings inserted so far.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// `true` if no embeddings have been inserted.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Configured embedding dimensionality.
    pub fn dim(&self) -> usize {
        self.dim
    }
}

/// Brute-force k-NN index.
///
/// Stores embedding handles — the blobs live in the pile's blob store,
/// content-addressed. Attached query operations resolve handles through a caller-supplied
/// [`BlobStoreGet`][g] at query time, so two indexes that
/// embed the same entity share storage.
///
/// ANN retrieval assumes stored embeddings are L2-normalized (the convention;
/// see [`Embedding`]'s docs). The exact pair predicate divides by both norms.
///
/// [g]: triblespace_core::repo::BlobStoreGet
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct FlatIndex {
    dim: usize,
    handles: Vec<Inline<Handle<Embedding>>>,
}

impl FlatIndex {
    /// Embedding dimensionality.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Number of indexed embeddings.
    pub fn doc_count(&self) -> usize {
        self.handles.len()
    }

    /// The stored embedding-handle table. `handles()[i]` is the
    /// content-addressed pointer to the embedding blob.
    pub fn handles(&self) -> &[Inline<Handle<Embedding>>] {
        &self.handles
    }

    /// Attach a blob store to this index, returning a queryable
    /// view.
    ///
    /// The view wraps `store` in an internal
    /// [`BlobCache`][c] keyed on `Handle<Embedding>`.
    /// `B: Clone` so the cache can own the store; typical
    /// readers are cheap-clone.
    ///
    /// [c]: triblespace_core::blob::BlobCache
    pub fn attach<'a, B>(&'a self, store: &B) -> AttachedFlatIndex<'a, B>
    where
        B: triblespace_core::repo::BlobStoreGet + Clone,
    {
        AttachedFlatIndex {
            index: self,
            cache: triblespace_core::blob::BlobCache::new(store.clone()),
        }
    }
}

/// A [`FlatIndex`] paired with the blob store its handles
/// resolve against — produced by [`FlatIndex::attach`].
///
/// Owns a [`BlobCache`][c] over the store, specialized to
/// `(Embedding, View<[f32]>)`. Dropping the view drops the
/// cache; the underlying store is unaffected.
///
/// [c]: triblespace_core::blob::BlobCache
#[doc(hidden)]
pub struct AttachedFlatIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    index: &'a FlatIndex,
    cache: triblespace_core::blob::BlobCache<B, Embedding, anybytes::View<[f32]>>,
}

impl<'a, B> AttachedFlatIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    /// The inner index.
    pub fn index(&self) -> &FlatIndex {
        self.index
    }

    /// Build an exact symmetric cosine predicate over two handle variables.
    /// This is filter-only; [`Self::similar_to`] owns brute-force retrieval.
    pub fn cosine_at_least(
        &self,
        a: Variable<EmbHandle>,
        b: Variable<EmbHandle>,
        score_floor: f32,
    ) -> crate::constraint::CosineAtLeast<'_, Self, Embedding> {
        crate::constraint::CosineAtLeast::new(self, a, b, score_floor)
    }

    /// Convenience wrapper for the common
    /// "search from a known handle" case. Mirrors
    /// [`AttachedHNSWIndex::similar_to`][a] for the brute-force
    /// index — walks all handles once at construction and stores the native
    /// result bag. See [`crate::constraint::SimilarTo`].
    ///
    /// [`Self::candidates_above`] can repeat a handle (see its docs), so
    /// the collapse inside
    /// [`SimilarTo::from_candidates`][crate::constraint::SimilarTo::from_candidates]
    /// is load-bearing on this path, not defensive.
    ///
    /// [a]: crate::hnsw::AttachedHNSWIndex::similar_to
    pub fn similar_to(
        &self,
        probe: Inline<EmbHandle>,
        var: Variable<EmbHandle>,
        score_floor: f32,
    ) -> crate::constraint::SimilarTo<EmbHandle> {
        let candidates = self
            .candidates_above(probe, score_floor)
            .map(|v| v.into_iter().map(|h| h.raw).collect())
            .unwrap_or_default();
        crate::constraint::SimilarTo::from_candidates(var, candidates)
    }

    /// Brute-force counterpart to
    /// [`AttachedHNSWIndex::candidates_above`][a] — `O(N)` over
    /// the corpus, returns every above-threshold handle (no
    /// approximation, no `ef_search` cap). Same expectation
    /// applies: production callers go through the engine via
    /// [`Self::similar_to`] inside a
    /// `find!`; this leaf is for tests and benchmarks.
    ///
    /// **Not distinct.** This walks [`FlatIndex::handles`] positionally,
    /// and [`FlatBuilder::insert`] pushes one entry per call with no
    /// collapse — so a handle inserted twice is returned twice. Content
    /// addressing makes that ordinary, not pathological: identical vectors
    /// are one handle.
    ///
    /// [a]: crate::hnsw::AttachedHNSWIndex::candidates_above
    #[doc(hidden)]
    pub fn candidates_above(
        &self,
        from_handle: Inline<EmbHandle>,
        score_floor: f32,
    ) -> Result<Vec<Inline<EmbHandle>>, B::GetError<crate::schemas::EmbeddingError>> {
        let from = self.cache.get(from_handle)?;
        let query = from.as_ref().as_ref();
        if query.len() != self.index.dim {
            return Ok(Vec::new());
        }
        // Already-normalised by put_embedding, so dot = cosine.
        let mut out = Vec::new();
        for &handle in self.index.handles.iter() {
            let view = self.cache.get(handle)?;
            let score = dot(query, view.as_ref().as_ref());
            if score >= score_floor {
                out.push(handle);
            }
        }
        Ok(out)
    }
}

impl FlatIndex {
    /// Theoretical size of the naive flat-array serialization in
    /// bytes — baseline for comparing against more compressed
    /// forms. `24` B header + 32 B per embedding handle;
    /// embeddings live in the pile's blob store and aren't
    /// counted here.
    pub fn byte_size(&self) -> usize {
        24 + self.handles.len() * 32
    }
}

impl<'a, B> crate::constraint::CosineSimilarity<Embedding> for AttachedHNSWIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    fn cosine_between(
        &self,
        a: Inline<Handle<Embedding>>,
        b: Inline<Handle<Embedding>>,
    ) -> Option<f32> {
        let va = self.cache.get(a).ok()?;
        let vb = self.cache.get(b).ok()?;
        let a_slice: &[f32] = va.as_ref().as_ref();
        let b_slice: &[f32] = vb.as_ref().as_ref();
        if a_slice.len() != b_slice.len() {
            return None;
        }
        Some(cosine_similarity(a_slice, b_slice))
    }
}

impl<'a, B> crate::constraint::CosineSimilarity<Embedding> for AttachedFlatIndex<'a, B>
where
    B: triblespace_core::repo::BlobStoreGet,
{
    fn cosine_between(
        &self,
        a: Inline<Handle<Embedding>>,
        b: Inline<Handle<Embedding>>,
    ) -> Option<f32> {
        let va = self.cache.get(a).ok()?;
        let vb = self.cache.get(b).ok()?;
        let a_slice: &[f32] = va.as_ref().as_ref();
        let b_slice: &[f32] = vb.as_ref().as_ref();
        if a_slice.len() != b_slice.len() {
            return None;
        }
        Some(cosine_similarity(a_slice, b_slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use triblespace_core::blob::MemoryBlobStore;
    use triblespace_core::repo::SnapshotSource;

    #[test]
    fn true_cosine_handles_extreme_f32_magnitudes() {
        assert_eq!(cosine_similarity(&[1.0e20], &[1.0e20]), 1.0);
        assert_eq!(cosine_similarity(&[1.0e-30], &[1.0e-30]), 1.0);
    }

    /// Put `vec` into `store` as a normalized [`Embedding`] blob
    /// and return the handle.
    fn put_emb(store: &mut MemoryBlobStore, vec: Vec<f32>) -> Inline<Handle<Embedding>> {
        crate::schemas::put_embedding::<_>(store, vec).unwrap()
    }

    /// Build a [`FlatIndex`] from raw vectors. Returns the index,
    /// the store, and the handle for each vector (parallel to
    /// `vecs`) — callers query with the handles they want.
    fn build_flat(
        dim: usize,
        vecs: &[Vec<f32>],
    ) -> (FlatIndex, MemoryBlobStore, Vec<Inline<Handle<Embedding>>>) {
        let mut store = MemoryBlobStore::new();
        let mut b = FlatBuilder::new(dim);
        let mut handles = Vec::with_capacity(vecs.len());
        for v in vecs {
            let h = put_emb(&mut store, v.clone());
            b.insert(h);
            handles.push(h);
        }
        (b.build(), store, handles)
    }

    /// Freeze one stable snapshot of an existing store.
    fn snapshot_of(store: &mut MemoryBlobStore) -> <MemoryBlobStore as SnapshotSource>::Snapshot {
        store.snapshot().unwrap()
    }

    #[test]
    fn flat_exact_match_includes_self_at_cos_one() {
        let (idx, mut store, handles) = build_flat(
            3,
            &[
                vec![1.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0],
                vec![0.0, 0.0, 1.0],
            ],
        );
        let hits = idx
            .attach(&snapshot_of(&mut store))
            .candidates_above(handles[0], 0.999)
            .unwrap();
        assert_eq!(hits, vec![handles[0]]);
    }

    #[test]
    fn flat_threshold_selects_near_matches() {
        let (idx, mut store, handles) =
            build_flat(2, &[vec![1.0, 0.0], vec![0.9, 0.1], vec![0.0, 1.0]]);
        let got: std::collections::HashSet<_> = idx
            .attach(&snapshot_of(&mut store))
            .candidates_above(handles[0], 0.8)
            .unwrap()
            .into_iter()
            .collect();
        assert!(got.contains(&handles[0]));
        assert!(got.contains(&handles[1]));
        assert!(!got.contains(&handles[2]));
    }

    #[test]
    fn flat_parallel_inputs_dedupe_at_put() {
        // Two parallel inputs normalise to the same unit vector —
        // `put_embedding` produces one handle for both.
        let (_idx, _store, handles) = build_flat(2, &[vec![3.0, 0.0], vec![100.0, 0.0]]);
        assert_eq!(handles[0], handles[1]);
    }

    #[test]
    fn flat_empty_index_has_no_candidates() {
        let mut store = MemoryBlobStore::new();
        let idx = FlatBuilder::new(4).build();
        let probe = put_emb(&mut store, vec![1.0, 0.0, 0.0, 0.0]);
        let snapshot = store.snapshot().unwrap();
        assert!(idx
            .attach(&snapshot)
            .candidates_above(probe, 0.0)
            .unwrap()
            .is_empty());
    }

    fn sample_flat() -> (FlatIndex, MemoryBlobStore, Vec<Inline<Handle<Embedding>>>) {
        build_flat(
            3,
            &[
                vec![1.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0],
                vec![0.5, 0.5, 0.0],
            ],
        )
    }

    #[test]
    fn flat_byte_size_matches_formula() {
        let (idx, _, _) = sample_flat();
        assert_eq!(idx.byte_size(), 24 + idx.doc_count() * 32);
    }

    // ── HNSW tests ────────────────────────────────────────────────

    /// Build an HNSW index, returning index + store + per-vector
    /// handles (parallel to `vecs`).
    fn build_hnsw(
        dim: usize,
        seed: u64,
        vecs: &[Vec<f32>],
    ) -> (
        crate::succinct::SuccinctHNSWIndex,
        MemoryBlobStore,
        Vec<Inline<Handle<Embedding>>>,
    ) {
        let mut store = MemoryBlobStore::new();
        let mut b = HNSWBuilder::new(dim).with_seed(seed);
        let mut handles = Vec::with_capacity(vecs.len());
        for v in vecs {
            let h = put_emb(&mut store, v.clone());
            b.insert(h, v.clone()).unwrap();
            handles.push(h);
        }
        (b.build(), store, handles)
    }

    #[test]
    fn hnsw_empty_index_has_no_candidates() {
        let mut store = MemoryBlobStore::new();
        let idx = HNSWBuilder::new(4).build();
        assert_eq!(idx.doc_count(), 0);
        let probe = put_emb(&mut store, vec![1.0, 0.0, 0.0, 0.0]);
        let snapshot = store.snapshot().unwrap();
        assert!(idx
            .attach(&snapshot)
            .candidates_above(probe, 0.0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn hnsw_single_doc_returns_itself() {
        let (idx, mut store, handles) = build_hnsw(3, 42, &[vec![1.0, 0.0, 0.0]]);
        let hits = idx
            .attach(&snapshot_of(&mut store))
            .candidates_above(handles[0], 0.999)
            .unwrap();
        assert_eq!(hits, vec![handles[0]]);
    }

    #[test]
    fn hnsw_threshold_excludes_orthogonal() {
        let (idx, mut store, handles) =
            build_hnsw(2, 42, &[vec![1.0, 0.0], vec![0.9, 0.1], vec![0.0, 1.0]]);
        let got: std::collections::HashSet<_> = idx
            .attach(&snapshot_of(&mut store))
            .candidates_above(handles[0], 0.8)
            .unwrap()
            .into_iter()
            .collect();
        assert!(got.contains(&handles[0]));
        assert!(got.contains(&handles[1]));
        assert!(!got.contains(&handles[2]));
    }

    #[test]
    fn hnsw_threshold_recall_matches_flat_on_small_corpus() {
        // Build both indexes over the same vectors, probe from the
        // same pre-computed handles, and confirm HNSW's
        // above-threshold set mostly matches the flat oracle's.
        // Strict recall is algorithm-dependent; we require most
        // expected matches to survive.
        let mut rng = 0xBABE_u64;
        let next = |r: &mut u64| {
            *r = r.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = *r;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        let dim = 16;
        let vecs: Vec<Vec<f32>> = (0..200)
            .map(|_| {
                (0..dim)
                    .map(|_| (next(&mut rng) as i32 as f32) / (i32::MAX as f32))
                    .collect()
            })
            .collect();

        let (flat, mut fstore, fhandles) = build_flat(dim, &vecs);
        let (hnsw, mut hstore, hhandles) = build_hnsw(dim, 42, &vecs);
        // Handles must agree (same content → same Blake3 hash).
        assert_eq!(fhandles, hhandles);
        let fsnapshot = fstore.snapshot().unwrap();
        let hsnapshot = hstore.snapshot().unwrap();
        let hnsw_view = hnsw.attach(&hsnapshot).with_ef_search(50);
        let flat_view = flat.attach(&fsnapshot);

        let floor = 0.6;
        let mut total_hits = 0usize;
        let mut total_overlap = 0usize;
        for probe in fhandles.iter().take(5) {
            let truth: std::collections::HashSet<_> = flat_view
                .candidates_above(*probe, floor)
                .unwrap()
                .into_iter()
                .collect();
            let got: std::collections::HashSet<_> = hnsw_view
                .candidates_above(*probe, floor)
                .unwrap()
                .into_iter()
                .collect();
            total_hits += truth.len();
            total_overlap += truth.intersection(&got).count();
        }
        assert!(total_hits > 0, "test fixture: floor excluded everything");
        let recall = total_overlap as f32 / total_hits as f32;
        assert!(recall >= 0.7, "HNSW recall {recall:.2} below 0.7 threshold");
    }

    #[test]
    fn hnsw_deterministic_seed_reproduces_structure() {
        let vecs: Vec<Vec<f32>> = (1u8..=20)
            .map(|i| {
                vec![
                    (i as f32) / 20.0,
                    ((i as f32) * 2.0) % 1.0,
                    ((i as f32) * 3.0) % 1.0,
                ]
            })
            .collect();
        let (a, mut a_store, a_handles) = build_hnsw(3, 123, &vecs);
        let (b, mut b_store, b_handles) = build_hnsw(3, 123, &vecs);
        assert_eq!(a.doc_count(), b.doc_count());
        assert_eq!(a.max_level(), b.max_level());
        assert_eq!(a_handles, b_handles);
        let ra = a
            .attach(&a_store.snapshot().unwrap())
            .candidates_above(a_handles[0], 0.5)
            .unwrap();
        let rb = b
            .attach(&b_store.snapshot().unwrap())
            .candidates_above(b_handles[0], 0.5)
            .unwrap();
        assert_eq!(ra, rb);
    }

    #[test]
    fn hnsw_dim_mismatch_rejected_at_insert() {
        let mut store = MemoryBlobStore::new();
        let mut b = HNSWBuilder::new(3);
        let h = put_emb(&mut store, vec![1.0, 0.0]);
        let err = b.insert(h, vec![1.0, 0.0]).unwrap_err();
        assert_eq!(err.expected, 3);
        assert_eq!(err.got, 2);
    }

    fn sample_hnsw() -> (HNSWIndex, MemoryBlobStore, Vec<Inline<Handle<Embedding>>>) {
        let mut store = MemoryBlobStore::new();
        let mut b = HNSWBuilder::new(3).with_seed(42);
        let vecs = [
            vec![1.0f32, 0.0, 0.0],
            vec![0.9, 0.1, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ];
        let mut handles = Vec::with_capacity(vecs.len());
        for v in &vecs {
            let h = put_emb(&mut store, v.clone());
            b.insert(h, v.clone()).unwrap();
            handles.push(h);
        }
        (b.build_naive(), store, handles)
    }

    #[test]
    fn hnsw_byte_size_positive_and_growing() {
        let (idx, _, _) = sample_hnsw();
        let small = idx.byte_size();
        assert!(small > 0);
        let vecs = [
            vec![1.0f32, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.5, 0.5, 0.0],
            vec![0.0, 0.0, 1.0],
            vec![0.2, 0.3, 0.5],
        ];
        let mut store = MemoryBlobStore::new();
        let mut b = HNSWBuilder::new(3).with_seed(19);
        for v in &vecs {
            let h = put_emb(&mut store, v.clone());
            b.insert(h, v.clone()).unwrap();
        }
        let larger = b.build_naive().byte_size();
        assert!(larger > small);
    }
}
