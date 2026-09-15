//! Triblespace query-engine integration.
//!
//! Three constraint shapes ship:
//!
//! * [`BM25Filter`] — multi-term BM25 constraint produced by
//!   [`BM25Index::matches`] / `SuccinctBM25Index::matches`.
//!   Binds a single `Variable<D>` (the doc) to documents whose
//!   summed BM25 score across the query terms is at least
//!   `score_floor`. Score is not a bound variable: it's a fixed
//!   parameter, set at construction time. Callers who need the
//!   exact score recompute it via the `score` inherent helper.
//! * [`CosineAtLeast`] — an exact, symmetric, filter-only predicate
//!   `cosine_at_least(a, b, score_floor)` over two
//!   same-encoding `Variable<Handle<E>>` values, produced by the
//!   `cosine_at_least()` method on
//!   [`crate::hnsw::AttachedHNSWIndex`] /
//!   [`crate::hnsw::AttachedFlatIndex`] /
//!   [`crate::succinct::AttachedSuccinctHNSWIndex`]. Other constraints
//!   source both handle domains; this constraint only confirms —
//!   like `InlineRange` in the core engine, it estimates
//!   `usize::MAX` and proposes nothing.
//! * [`SimilarTo`] — a unary set constraint over the result of one
//!   fixed-probe backend search. Flat and NVFP4 retrieval are complete;
//!   HNSW and succinct HNSW retrieval are approximate.
//!
//! All three speak the engine's cooperative protocol directly:
//! `estimate` guides join ordering, `propose` appends candidate values
//! into the shared [`ProposalBuffer`], `confirm` kills entries in a
//! [`Candidates`] region, and `satisfied` checks fully-bound rows.
//!
//! See `docs/QUERY_ENGINE_INTEGRATION.md` for the long-form
//! design.

use std::collections::HashSet;

use triblespace_core::blob::BlobEncoding;
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, RawInline};
use triblespace_core::query::{
    Binding, Candidates, Constraint, Frontier, ProposalBuffer, Variable, VariableId, VariableSet,
};

use crate::bm25::BM25Index;
#[cfg(test)]
use crate::schemas::Embedding;

/// Minimum surface a BM25 index must expose for the
/// [`BM25Filter`] constraint to work against it. Implemented
/// for both the naive [`crate::bm25::BM25Index`] and the
/// succinct [`crate::succinct::SuccinctBM25Index`], as well as the portable
/// exact-TF [`crate::portable_bm25::PortableBM25Query`], so each
/// can plug into `find!` / `pattern!` without changes at the
/// engine layer.
pub trait BM25Queryable {
    /// Iterate `(key, score)` for the posting list of `term`.
    /// Keys are 32-byte triblespace `RawInline`s — the caller's
    /// `Variable<S>` decodes them through whatever `InlineEncoding`
    /// is appropriate. Empty iterator if the term is absent.
    fn query_term_boxed<'a>(
        &'a self,
        term: &RawInline,
    ) -> Box<dyn Iterator<Item = (RawInline, f32)> + 'a>;
}

impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    BM25Queryable for BM25Index<D, T>
{
    fn query_term_boxed<'a>(
        &'a self,
        term: &RawInline,
    ) -> Box<dyn Iterator<Item = (RawInline, f32)> + 'a> {
        // Wrap the raw bytes in `Inline<T>` at the trait boundary
        // — the typed API inside the index expects `&Inline<T>`.
        let term_val = Inline::<T>::new(*term);
        Box::new(self.query_term(&term_val).map(|(v, s)| (v.raw, s)))
    }
}

impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    BM25Queryable for crate::portable_bm25::PortableBM25Query<'_, D, T>
{
    fn query_term_boxed<'a>(
        &'a self,
        term: &RawInline,
    ) -> Box<dyn Iterator<Item = (RawInline, f32)> + 'a> {
        let term_val = Inline::<T>::new(*term);
        Box::new(
            self.query_term(&term_val)
                .map(|(value, score)| (value.raw, score)),
        )
    }
}

#[cfg(feature = "succinct")]
impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    BM25Queryable for crate::succinct::SuccinctBM25Index<D, T>
{
    fn query_term_boxed<'a>(
        &'a self,
        term: &RawInline,
    ) -> Box<dyn Iterator<Item = (RawInline, f32)> + 'a> {
        let term_val = Inline::<T>::new(*term);
        Box::new(self.query_term(&term_val).map(|(v, s)| (v.raw, s)))
    }
}

// ── BM25 filter: multi-term bag-of-words → docs above floor ─────────

/// Multi-term BM25 constraint. Binds `doc` to documents whose
/// summed BM25 score across `terms` is at least `score_floor`.
///
/// Score is **not** a bound variable — it's a constraint
/// parameter set at construction time. This mirrors how
/// search filtering handles scores: filter on a fixed floor inside the
/// engine, recompute the precise score afterwards via the `score` inherent
/// helper if you need it for ranking. Two reasons:
///
/// - Exact frequencies and derived scores stay inside the index;
///   the engine sees docs only.
/// - One less variable per BM25 clause in the planner — joins
///   stay tight, and there's no Cartesian-blowup dedupe to do.
///
/// Pre-aggregated at construction: walk every term's posting
/// list once, sum scores into a `HashMap<doc, f32>`, drop
/// scores below `score_floor`, keep just the doc keys.
/// `score_floor = 0.0` is the natural "any matching doc" form
/// — BM25 scores are non-negative, so `>= 0.0` matches every
/// doc that appears in at least one posting list. Keying the sum
/// by doc is also what makes the doc list a *set*: see
/// `aggregate_above`.
///
/// Generic over any `I: BM25Queryable`, so it works against
/// [`BM25Index`] or [`crate::succinct::SuccinctBM25Index`]
/// without code duplication.
///
/// # Example
///
/// ```
/// use triblespace_core::find;
/// use triblespace_core::id::Id;
/// use triblespace_search::bm25::BM25Builder;
/// use triblespace_search::tokens::hash_tokens;
///
/// let mut b: BM25Builder = BM25Builder::new();
/// b.insert(&Id::new([1; 16]).unwrap(), hash_tokens("graph search algorithms"));
/// b.insert(&Id::new([2; 16]).unwrap(), hash_tokens("cooking for pangrams"));
/// b.insert(&Id::new([3; 16]).unwrap(), hash_tokens("graph search primer"));
/// let idx = b.build();
///
/// let terms = hash_tokens("graph search");
/// // Filter: docs that match at all (floor = 0.0).
/// let matched: Vec<Id> = find!(
///     (doc: Id),
///     idx.matches(doc, &terms, 0.0)
/// )
/// .map(|(d,)| d)
/// .collect();
/// // Rank: recompute precise scores afterwards.
/// let mut ranked: Vec<(Id, f32)> = matched
///     .into_iter()
///     .map(|id| {
///         use triblespace_core::inline::{IntoInline, InlineEncoding};
///         let v: triblespace_core::inline::Inline<
///             triblespace_core::inline::encodings::genid::GenId,
///         > = (&id).to_inline();
///         (id, idx.score(&v, &terms))
///     })
///     .collect();
/// ranked.sort_unstable_by(|left, right| {
///     right
///         .1
///         .total_cmp(&left.1)
///         .then_with(|| left.0.cmp(&right.0))
/// });
/// assert_eq!(ranked.len(), 2);
/// ```
pub struct BM25Filter<S = GenId>
where
    S: triblespace_core::inline::InlineEncoding,
{
    doc: Variable<S>,
    /// Pre-filtered doc keys whose summed score across the query
    /// terms is `>= score_floor`, deduplicated in first-occurrence
    /// order. Score is dropped after the filter — re-derived on
    /// demand.
    entries: Vec<RawInline>,
    /// Set-shaped companion to `entries` for pointwise confirmation.
    membership: HashSet<RawInline>,
}

impl<S> BM25Filter<S>
where
    S: triblespace_core::inline::InlineEncoding,
{
    /// Build a filter from a pre-computed doc list. Use the
    /// `matches` method on [`BM25Index`] or `SuccinctBM25Index`
    /// rather than constructing directly.
    ///
    /// Accepts any `IntoIterator<Item = RawInline>` so callers
    /// can pass a `Vec<RawInline>` or a streaming iterator
    /// without forcing a collect. Duplicate occurrences collapse
    /// at construction: the constraint's denotation is the raw
    /// value SET, and proposing a value twice would inflate the
    /// engine's bag multiplicity.
    ///
    /// The collapse is kept even though every in-crate producer
    /// ([`BM25Index::matches`] and friends) is already distinct by
    /// construction — see `aggregate_above` — for two reasons. It is a
    /// public constructor, so the input is whatever a caller hands it; and
    /// it is *free*: `confirm` / `satisfied` need a set-shaped
    /// `membership` anyway, and building it with `HashSet::insert` yields
    /// the distinct `entries` order as the same pass's byproduct. There is
    /// no separable "dedup pass" here to trade away — dropping the
    /// distinctness guarantee would not save a single hash.
    pub fn from_entries<I>(doc: Variable<S>, entries: I) -> Self
    where
        I: IntoIterator<Item = RawInline>,
    {
        let entries = entries.into_iter();
        let hint = entries.size_hint().0;
        let mut membership = HashSet::with_capacity(hint);
        let mut unique = Vec::with_capacity(hint);
        for entry in entries {
            if membership.insert(entry) {
                unique.push(entry);
            }
        }
        Self {
            doc,
            entries: unique,
            membership,
        }
    }

    fn contains_raw(&self, value: &RawInline) -> bool {
        self.membership.contains(value)
    }
}

/// Aggregate a bag-of-words query's posting lists into the
/// list of docs whose summed score clears `score_floor`.
/// Shared by `BM25Index::matches` and
/// `SuccinctBM25Index::matches` so the two backends produce
/// identical filtering behaviour.
///
/// **The output is distinct by construction**: every doc key is a
/// `HashMap` key here, so a doc that appears under several query terms — or is
/// repeated by another [`BM25Queryable`] implementation — is one entry with
/// the summed score. The in-crate builders already canonicalize repeated rows
/// by document key, but this boundary preserves set semantics for every
/// implementation of the shared trait.
fn aggregate_above<I: BM25Queryable + ?Sized>(
    index: &I,
    terms: &[RawInline],
    score_floor: f32,
) -> Vec<RawInline> {
    let mut acc: std::collections::HashMap<RawInline, f32> = std::collections::HashMap::new();
    for term in terms {
        for (doc, score) in index.query_term_boxed(term) {
            *acc.entry(doc).or_insert(0.0) += score;
        }
    }
    let out: Vec<RawInline> = acc
        .into_iter()
        .filter_map(|(doc, sum)| (sum >= score_floor).then_some(doc))
        .collect();
    // Locks the invariant the four `matches` / `matches_text` entry points
    // rely on, so a future streaming posting-list merge here can't quietly
    // start inflating public row multiplicity.
    debug_assert_eq!(
        out.iter().collect::<HashSet<_>>().len(),
        out.len(),
        "aggregate_above must key by doc, so its output is distinct"
    );
    out
}

impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    crate::portable_bm25::PortableBM25Query<'_, D, T>
{
    /// Build a query-engine filter from this portable exact-TF corpus.
    pub fn matches(
        &self,
        doc: Variable<D>,
        terms: &[Inline<T>],
        score_floor: f32,
    ) -> BM25Filter<D> {
        let raw_terms: Vec<RawInline> = terms.iter().map(|term| term.raw).collect();
        BM25Filter::from_entries(doc, aggregate_above(self, &raw_terms, score_floor))
    }

    /// Summed BM25 score for one document across the supplied typed terms.
    pub fn score(&self, doc: &Inline<D>, terms: &[Inline<T>]) -> f32 {
        let mut sum = 0.0;
        for term in terms {
            for (candidate, score) in self.query_term(term) {
                if candidate.raw == doc.raw {
                    sum += score;
                    break;
                }
            }
        }
        sum
    }
}

impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    BM25Index<D, T>
{
    /// Multi-term BM25 filter constraint. Binds `doc` to
    /// documents whose summed BM25 score across `terms` is
    /// `>= score_floor`. Pass `0.0` for "any doc that appears
    /// in at least one posting list" (BM25 scores are
    /// non-negative).
    ///
    /// Recompute precise per-result scores via [`Self::score`]
    /// when you need them for ranking — keeps score out of the
    /// engine's bound variables.
    pub fn matches(
        &self,
        doc: Variable<D>,
        terms: &[Inline<T>],
        score_floor: f32,
    ) -> BM25Filter<D> {
        let raw_terms: Vec<RawInline> = terms.iter().map(|t| t.raw).collect();
        BM25Filter::from_entries(doc, aggregate_above(self, &raw_terms, score_floor))
    }

    /// Summed BM25 score for `doc` across `terms`. Returns
    /// `0.0` for docs that don't appear in any posting list.
    /// Both backends evaluate the same formula from exact corpus
    /// statistics; the succinct index stores raw frequencies rather than
    /// quantized scores.
    pub fn score(&self, doc: &Inline<D>, terms: &[Inline<T>]) -> f32 {
        let mut sum = 0.0;
        for term in terms {
            for (d, s) in self.query_term(term) {
                if d.raw == doc.raw {
                    sum += s;
                    break;
                }
            }
        }
        sum
    }
}

/// Convenience methods for word-hash-keyed indexes — skip the
/// `&hash_tokens(text)` ceremony at every call site.
///
/// `matches_text` and `score_text` are sugar over [`Self::matches`]
/// and [`Self::score`]: tokenise the query string with
/// [`crate::tokens::hash_tokens`] (whitespace + lowercase + Blake3),
/// then delegate. Available only on indexes whose term schema is
/// [`crate::tokens::WordHash`] — pair them up with
/// `BM25Builder::<D, WordHash>::new()` builders.
impl<D: triblespace_core::inline::InlineEncoding> BM25Index<D, crate::tokens::WordHash> {
    /// Same as [`Self::matches`], but takes a query string and
    /// tokenises it with [`crate::tokens::hash_tokens`] internally.
    pub fn matches_text(&self, doc: Variable<D>, text: &str, score_floor: f32) -> BM25Filter<D> {
        self.matches(doc, &crate::tokens::hash_tokens(text), score_floor)
    }

    /// Same as [`Self::score`], but takes a query string and
    /// tokenises it with [`crate::tokens::hash_tokens`] internally.
    /// Use after `find!` collects to recompute precise per-result
    /// scores for ranking.
    pub fn score_text(&self, doc: &Inline<D>, text: &str) -> f32 {
        self.score(doc, &crate::tokens::hash_tokens(text))
    }
}

#[cfg(feature = "succinct")]
impl<D: triblespace_core::inline::InlineEncoding, T: triblespace_core::inline::InlineEncoding>
    crate::succinct::SuccinctBM25Index<D, T>
{
    /// Succinct-side sibling of [`BM25Index::matches`]. Same
    /// shape, same constraint type — picks up the succinct
    /// index's scoring transparently.
    pub fn matches(
        &self,
        doc: Variable<D>,
        terms: &[Inline<T>],
        score_floor: f32,
    ) -> BM25Filter<D> {
        let raw_terms: Vec<RawInline> = terms.iter().map(|t| t.raw).collect();
        BM25Filter::from_entries(doc, aggregate_above(self, &raw_terms, score_floor))
    }

    /// Succinct-side sibling of [`BM25Index::score`].
    pub fn score(&self, doc: &Inline<D>, terms: &[Inline<T>]) -> f32 {
        let mut sum = 0.0;
        for term in terms {
            for (d, s) in self.query_term(term) {
                if d.raw == doc.raw {
                    sum += s;
                    break;
                }
            }
        }
        sum
    }
}

/// Word-hash convenience for the succinct path — same shape as the
/// naive-index sugar, deriving exact scoring from succinct frequencies.
#[cfg(feature = "succinct")]
impl<D: triblespace_core::inline::InlineEncoding>
    crate::succinct::SuccinctBM25Index<D, crate::tokens::WordHash>
{
    /// Succinct-side sibling of [`BM25Index::matches_text`].
    pub fn matches_text(&self, doc: Variable<D>, text: &str, score_floor: f32) -> BM25Filter<D> {
        self.matches(doc, &crate::tokens::hash_tokens(text), score_floor)
    }

    /// Succinct-side sibling of [`BM25Index::score_text`].
    pub fn score_text(&self, doc: &Inline<D>, text: &str) -> f32 {
        self.score(doc, &crate::tokens::hash_tokens(text))
    }
}

impl<'a, S> Constraint<'a> for BM25Filter<S>
where
    S: triblespace_core::inline::InlineEncoding + 'a,
{
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.doc.index)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        if variable == self.doc.index {
            Some(self.entries.len())
        } else {
            None
        }
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        if variable != self.doc.index {
            return;
        }
        for row in 0..frontier.len() {
            proposals.open(row as u32);
            proposals.extend_from_slice(&self.entries);
        }
    }

    /// Membership in the posting set does not depend on the parent binding.
    fn confirm(&self, variable: VariableId, _frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable != self.doc.index {
            return;
        }
        cands.retain(|raw| self.contains_raw(raw));
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        match binding.get(self.doc.index) {
            Some(bound) => self.contains_raw(bound),
            None => true,
        }
    }
}

// ── Similarity constraint ───────────────────────────────────────────

/// Backing surface an attached embedding store must expose for the generic
/// [`CosineAtLeast`] exact binary predicate. Implemented for the three
/// `Embedding` attached views:
/// [`crate::hnsw::AttachedHNSWIndex`],
/// [`crate::hnsw::AttachedFlatIndex`], and
/// [`crate::succinct::AttachedSuccinctHNSWIndex`].
///
/// Fetch failures map to [`None`], which is exact "no match" behavior at the
/// query boundary because constraint hooks have no error channel.
pub trait CosineSimilarity<E: BlobEncoding> {
    /// Exact cosine similarity between the two handles, or
    /// [`None`] if either blob can't be fetched / parsed.
    fn cosine_between(&self, a: Inline<Handle<E>>, b: Inline<Handle<E>>) -> Option<f32>;
}

/// Exact binary cosine predicate:
/// `cosine_at_least(a, b, score_floor)` holds iff `a` and `b` are both
/// embedding handles with `cosine(*a, *b) ≥ score_floor`.
///
/// Semantics are symmetric and binding-history independent. This is a
/// filter-only predicate: other constraints must source both handle domains,
/// and this constraint checks candidate pairs pointwise. It follows the
/// same shape as the core engine's `InlineRange` — the estimate saturates
/// at `usize::MAX` so the intersection never picks it as the proposer,
/// `propose` is intentionally empty, and `confirm` kills candidates whose
/// pair is resolved and below the floor. Candidates whose peer variable is
/// still unbound are left alive — the predicate is unresolved until the
/// engine binds the other side. Approximate directional retrieval is
/// exposed separately by [`SimilarTo`].
///
/// `score_floor` is fixed at constraint-construction — it's a
/// query parameter, not a bound variable. Callers who need the
/// exact score can fetch both handles after the query and
/// compute it without the approximation / quantisation that a
/// score-variable would bring in.
///
/// Produced by the `cosine_at_least` method on an
/// [`crate::hnsw::AttachedHNSWIndex`] /
/// [`crate::hnsw::AttachedFlatIndex`] /
/// [`crate::succinct::AttachedSuccinctHNSWIndex`].
///
/// # Example
///
/// Pin the probe and provide a genuine candidate domain, then let the exact
/// predicate filter that domain:
///
/// ```
/// use std::collections::HashSet;
/// use triblespace_core::and;
/// use triblespace_core::blob::MemoryBlobStore;
/// use triblespace_core::find;
/// use triblespace_core::query::{temp, ContainsConstraint};
/// use triblespace_core::repo::SnapshotSource;
/// use triblespace_core::inline::Inline;
/// use triblespace_search::hnsw::HNSWBuilder;
/// use triblespace_search::schemas::{put_embedding, EmbHandle};
///
/// let mut store = MemoryBlobStore::new();
/// let mut b = HNSWBuilder::new(3).with_seed(42);
/// let mut handles = Vec::new();
/// for v in [
///     vec![1.0f32, 0.0, 0.0],
///     vec![0.9, 0.1, 0.0],
///     vec![0.0, 1.0, 0.0],
/// ] {
///     let h = put_embedding::<_>(&mut store, v.clone()).unwrap();
///     b.insert(h, v).unwrap();
///     handles.push(h);
/// }
/// let idx = b.build();
/// let snapshot = store.snapshot().unwrap();
/// let view = idx.attach(&snapshot);
///
/// let probe = handles[0];
/// let candidates: HashSet<_> = handles.iter().copied().collect();
/// let rows: Vec<(Inline<EmbHandle>,)> = find!(
///     (neighbour: Inline<EmbHandle>),
///     temp!(
///         (anchor),
///         and!(
///             anchor.is(probe),
///             (&candidates).has(neighbour),
///             view.cosine_at_least(anchor, neighbour, 0.8),
///         )
///     )
/// )
/// .collect();
///
/// let got: HashSet<_> = rows.into_iter().map(|(h,)| h).collect();
/// assert!(got.contains(&handles[0]));
/// assert!(got.contains(&handles[1]));
/// assert!(!got.contains(&handles[2])); // below floor
/// ```
///
/// For the common single-probe retrieval case use [`SimilarTo`], which owns
/// one already-materialized backend search result instead of pretending an
/// approximate graph walk is an exact binary relation.
pub struct CosineAtLeast<'a, I, E>
where
    I: CosineSimilarity<E> + ?Sized,
    E: BlobEncoding,
{
    index: &'a I,
    a: Variable<Handle<E>>,
    b: Variable<Handle<E>>,
    score_floor: f32,
}

impl<'a, I, E> CosineAtLeast<'a, I, E>
where
    I: CosineSimilarity<E> + ?Sized,
    E: BlobEncoding,
{
    /// Build a constraint. Usually invoked through the `cosine_at_least`
    /// method on an attached index rather than directly.
    pub fn new(
        index: &'a I,
        a: Variable<Handle<E>>,
        b: Variable<Handle<E>>,
        score_floor: f32,
    ) -> Self {
        Self {
            index,
            a,
            b,
            score_floor,
        }
    }

    fn pair_matches(&self, a: RawInline, b: RawInline) -> bool {
        self.index
            .cosine_between(Inline::new(a), Inline::new(b))
            .is_some_and(|score| score >= self.score_floor)
    }
}

impl<'a, I, E> Constraint<'a> for CosineAtLeast<'a, I, E>
where
    I: CosineSimilarity<E> + ?Sized + 'a,
    E: BlobEncoding,
{
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.a.index).union(VariableSet::new_singleton(self.b.index))
    }

    /// Saturates at `usize::MAX`: this predicate owns no domain, so the
    /// intersection must keep it behind every genuine source without
    /// falsely marking the variable unconstrained.
    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        if variable == self.a.index || variable == self.b.index {
            Some(usize::MAX)
        } else {
            None
        }
    }

    fn propose(
        &self,
        _variable: VariableId,
        _frontier: &Frontier<'_>,
        _proposals: &mut ProposalBuffer,
    ) {
        // Intentionally empty: exact pairwise cosine is a predicate, not an
        // ANN domain source. `SimilarTo` owns directional retrieval.
    }

    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable != self.a.index && variable != self.b.index {
            return;
        }
        if self.a.index == self.b.index {
            // Repeated variable: the candidate must clear the floor
            // against itself.
            cands.retain(|candidate| self.pair_matches(*candidate, *candidate));
            return;
        }
        let peer = if variable == self.a.index {
            self.b.index
        } else {
            self.a.index
        };
        // The peer's *value* varies row by row, so the pair test is per
        // parent run.
        cands.for_each_parent(|row, run| {
            let Some(&peer_value) = frontier.row(row as usize).get(peer) else {
                // Peer unbound: the pair is unresolved, keep every candidate
                // alive until the engine binds the other side.
                return;
            };
            if variable == self.a.index {
                run.retain(|candidate| self.pair_matches(*candidate, peer_value));
            } else {
                run.retain(|candidate| self.pair_matches(peer_value, *candidate));
            }
        });
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        match (binding.get(self.a.index), binding.get(self.b.index)) {
            (Some(&a), Some(&b)) => self.pair_matches(a, b),
            _ => true,
        }
    }
}

/// Unary similarity constraint: `similar_to(probe, var, score_floor)`
/// binds `var` to the candidate set returned by one backend search
/// from `probe` at `score_floor`.
///
/// The candidate set is pre-materialised at construction. Flat and NVFP4
/// search produce every indexed handle above the threshold. HNSW and
/// succinct HNSW are approximate and may omit qualifying handles. Once
/// constructed, query semantics are exact membership in this frozen
/// set; no engine action re-walks the index. Duplicate occurrences in
/// the backend's result list collapse at construction — the constraint
/// denotes the raw [`RawInline`] support set, exactly the rows a query
/// head can distinguish.
///
/// Produced by the `similar_to` method on an [`crate::nvfp4::NvFp4CosineIndex`]
/// or an
/// [`crate::hnsw::AttachedHNSWIndex`] /
/// [`crate::hnsw::AttachedFlatIndex`] /
/// [`crate::succinct::AttachedSuccinctHNSWIndex`].
///
/// # Example
///
/// ```
/// use std::collections::HashSet;
/// use triblespace_core::blob::MemoryBlobStore;
/// use triblespace_core::find;
/// use triblespace_core::repo::SnapshotSource;
/// use triblespace_core::inline::Inline;
/// use triblespace_search::hnsw::HNSWBuilder;
/// use triblespace_search::schemas::{put_embedding, EmbHandle};
///
/// let mut store = MemoryBlobStore::new();
/// let mut b = HNSWBuilder::new(3).with_seed(42);
/// let mut handles = Vec::new();
/// for v in [
///     vec![1.0f32, 0.0, 0.0],
///     vec![0.9, 0.1, 0.0],
///     vec![0.0, 1.0, 0.0],
/// ] {
///     let h = put_embedding::<_>(&mut store, v.clone()).unwrap();
///     b.insert(h, v).unwrap();
///     handles.push(h);
/// }
/// let idx = b.build();
/// let snapshot = store.snapshot().unwrap();
/// let view = idx.attach(&snapshot);
///
/// // No temp!, no `.is()` — the probe is pinned on the call.
/// let rows: Vec<(Inline<EmbHandle>,)> = find!(
///     (neighbour: Inline<EmbHandle>),
///     view.similar_to(handles[0], neighbour, 0.8)
/// )
/// .collect();
///
/// let got: HashSet<_> = rows.into_iter().map(|(h,)| h).collect();
/// assert!(got.contains(&handles[0]));
/// assert!(got.contains(&handles[1]));
/// assert!(!got.contains(&handles[2])); // below floor
/// ```
pub struct SimilarTo<E: BlobEncoding> {
    var: Variable<Handle<E>>,
    /// Backend result list from the one walk at construction,
    /// deduplicated in first-occurrence order.
    candidates: Vec<RawInline>,
    /// Set-shaped companion used by pointwise confirmation.
    membership: HashSet<RawInline>,
}

impl<E: BlobEncoding> SimilarTo<E> {
    /// Build from a pre-computed candidate list. Usually invoked
    /// through the `similar_to` method on an attached index
    /// rather than directly. Duplicate occurrences collapse at
    /// construction — the constraint denotes the raw value SET.
    ///
    /// Unlike [`BM25Filter::from_entries`], whose in-crate producers are
    /// all distinct by construction, this collapse is **load-bearing for
    /// the crate's own callers**. Embedding handles are content-addressed,
    /// so two entities that embed to the same vector share one handle, and
    /// neither `HNSWBuilder::insert` nor `FlatBuilder::insert` collapses a
    /// repeated handle — the index's handle table stores it once per
    /// insert. `candidates_above` then maps node → handle on all three
    /// backends and hands the repeat straight through. Nothing downstream
    /// would collapse it — the engine has no head-claiming layer, so a repeated
    /// proposal is a repeated row.
    pub fn from_candidates(var: Variable<Handle<E>>, candidates: Vec<RawInline>) -> Self {
        let mut membership = HashSet::with_capacity(candidates.len());
        let mut unique = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if membership.insert(candidate) {
                unique.push(candidate);
            }
        }
        Self {
            var,
            candidates: unique,
            membership,
        }
    }

    fn contains_raw(&self, value: &RawInline) -> bool {
        self.membership.contains(value)
    }
}

impl<'a, E: BlobEncoding> Constraint<'a> for SimilarTo<E> {
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.var.index)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        if variable == self.var.index {
            Some(self.candidates.len())
        } else {
            None
        }
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        if variable != self.var.index {
            return;
        }
        for row in 0..frontier.len() {
            proposals.open(row as u32);
            proposals.extend_from_slice(&self.candidates);
        }
    }

    /// Membership in the retrieved neighbourhood does not depend on the
    /// parent binding.
    fn confirm(&self, variable: VariableId, _frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable != self.var.index {
            return;
        }
        cands.retain(|raw| self.contains_raw(raw));
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        match binding.get(self.var.index) {
            Some(bound) => self.contains_raw(bound),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bm25::BM25Builder;
    use crate::tokens::hash_tokens;
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::blob::MemoryBlobStore;
    use triblespace_core::id::Id;
    use triblespace_core::inline::{InlineEncoding, IntoInline, TryFromInline};
    use triblespace_core::query::BindingStore;
    use triblespace_core::query::Query;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource};

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    /// `GenId`-schema RawInline → `Id` test helper.
    fn raw_value_to_id(raw: &RawInline) -> Option<Id> {
        Inline::<GenId>::new(*raw).try_from_inline::<Id>().ok()
    }

    /// `Id` → `GenId`-schema RawInline test helper.
    fn id_to_raw_value(id: Id) -> RawInline {
        GenId::inline_from(id).raw
    }

    fn project_first(binding: &Binding) -> Option<RawInline> {
        binding.get(0).copied()
    }

    fn project_pair(binding: &Binding) -> Option<(RawInline, RawInline)> {
        Some((*binding.get(0)?, *binding.get(1)?))
    }

    fn embedding_raw(byte: u8) -> RawInline {
        Inline::<Handle<Embedding>>::new([byte; 32]).raw
    }

    /// Live survivors of a confirm pass over the whole buffer.
    fn live(buffer: &ProposalBuffer) -> Vec<RawInline> {
        buffer.live_values(0).copied().collect()
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CollapsedEmbedding;

    impl TryFromInline<'_, Handle<Embedding>> for CollapsedEmbedding {
        type Error = std::convert::Infallible;

        fn try_from_inline(_: &Inline<Handle<Embedding>>) -> Result<Self, Self::Error> {
            Ok(Self)
        }
    }

    fn sample_index() -> BM25Index {
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("the quick brown fox"));
        b.insert(id(2), hash_tokens("the lazy brown dog"));
        b.insert(id(3), hash_tokens("quick silver fox jumps"));
        b.build_naive()
    }

    // ── BM25Filter (single doc variable, score-as-floor) ────

    #[test]
    fn matches_filter_variables_is_singleton_of_doc() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("fox");
        let c = idx.matches(doc, &terms, 0.0);

        let vars = c.variables();
        assert!(vars.is_set(doc.index));
        let mut found = 0;
        for i in 0..32 {
            if vars.is_set(i) {
                found += 1;
            }
        }
        assert_eq!(found, 1);
    }

    #[test]
    fn matches_filter_estimate_is_match_count() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("fox");
        let c = idx.matches(doc, &terms, 0.0);

        // "fox" appears in doc 1 and doc 3.
        assert_eq!(c.estimate(doc.index, &Binding::default()), Some(2));
        assert_eq!(c.estimate(255, &Binding::default()), None);
    }

    #[test]
    fn matches_filter_proposes_matching_docs() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("fox");
        let c = idx.matches(doc, &terms, 0.0);

        let mut props = ProposalBuffer::new();
        c.propose(doc.index, &Frontier::default(), &mut props);
        assert_eq!(props.len(), 2);

        let ids: HashSet<Id> = props
            .iter()
            .map(|r| raw_value_to_id(r).expect("valid GenId value"))
            .collect();
        assert!(ids.contains(&id(1)));
        assert!(ids.contains(&id(3)));
    }

    #[test]
    fn matches_filter_confirm_filters_non_matching_docs() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("fox");
        let c = idx.matches(doc, &terms, 0.0);

        let mut props = ProposalBuffer::new();
        props.push(id_to_raw_value(id(1)));
        props.push(id_to_raw_value(id(2)));
        props.push(id_to_raw_value(id(3)));
        c.confirm(doc.index, &Frontier::default(), &mut props.region(0));

        assert_eq!(props.count_live(0), 2);
        let ids: HashSet<Id> = live(&props)
            .iter()
            .map(|r| raw_value_to_id(r).unwrap())
            .collect();
        assert!(ids.contains(&id(1)));
        assert!(!ids.contains(&id(2)));
        assert!(ids.contains(&id(3)));
    }

    #[test]
    fn matches_filter_satisfied_checks_bound_doc() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("fox");
        let c = idx.matches(doc, &terms, 0.0);

        let empty = Binding::default();
        assert!(c.satisfied(&empty));

        let mut bound = BindingStore::new();
        bound.bind(doc.index, &id_to_raw_value(id(1)));
        assert!(c.satisfied(&bound.view()));

        let mut unmatching = BindingStore::new();
        unmatching.bind(doc.index, &id_to_raw_value(id(2)));
        assert!(!c.satisfied(&unmatching.view()));
    }

    #[test]
    fn matches_multi_term_aggregates_across_terms() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        // "quick fox" hits docs 1 and 3 (both contain "quick"
        // and "fox"); doc 2 contains neither.
        let terms = hash_tokens("quick fox");
        let c = idx.matches(doc, &terms, 0.0);

        let mut props = ProposalBuffer::new();
        c.propose(doc.index, &Frontier::default(), &mut props);
        let ids: HashSet<Id> = props
            .iter()
            .map(|r| raw_value_to_id(r).expect("genid"))
            .collect();
        assert!(ids.contains(&id(1)));
        assert!(ids.contains(&id(3)));
        assert!(!ids.contains(&id(2)));
    }

    /// `matches_text` produces the same proposed-doc set as
    /// `matches(&hash_tokens(text), ...)`, just without the explicit
    /// tokenisation at the call site.
    #[test]
    fn matches_text_matches_explicit_tokens() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc_a: Variable<GenId> = ctx.next_variable();
        let doc_b: Variable<GenId> = ctx.next_variable();

        let explicit = idx.matches(doc_a, &hash_tokens("quick fox"), 0.0);
        let sugar = idx.matches_text(doc_b, "quick fox", 0.0);

        let mut props_a = ProposalBuffer::new();
        let mut props_b = ProposalBuffer::new();
        explicit.propose(doc_a.index, &Frontier::default(), &mut props_a);
        sugar.propose(doc_b.index, &Frontier::default(), &mut props_b);

        let set_a: HashSet<Id> = props_a
            .iter()
            .map(|r| raw_value_to_id(r).expect("genid"))
            .collect();
        let set_b: HashSet<Id> = props_b
            .iter()
            .map(|r| raw_value_to_id(r).expect("genid"))
            .collect();
        assert_eq!(
            set_a, set_b,
            "matches_text yields the same doc set as matches(hash_tokens(...))",
        );
    }

    /// `score_text` agrees with `score(&hash_tokens(text))` to f32
    /// precision — the only difference is the call-site ergonomics.
    #[test]
    fn score_text_matches_explicit_tokens() {
        let idx = sample_index();
        let s_explicit = idx.score(&id(1).to_inline(), &hash_tokens("quick fox"));
        let s_sugar = idx.score_text(&id(1).to_inline(), "quick fox");
        assert_eq!(s_explicit, s_sugar);
    }

    #[test]
    fn matches_score_floor_drops_low_scoring_docs() {
        // Build a corpus where two docs match different numbers
        // of terms, so the summed scores diverge sharply.
        let mut b: BM25Builder = BM25Builder::new();
        b.insert(id(1), hash_tokens("fox quick brown jumps"));
        b.insert(id(2), hash_tokens("only fox here, nothing else"));
        b.insert(id(3), hash_tokens("unrelated"));
        let idx = b.build_naive();

        let terms = hash_tokens("fox quick brown jumps");
        // Compute per-doc summed scores so we can pick a floor
        // that excludes doc 2 but keeps doc 1.
        let s1 = idx.score(&id(1).to_inline(), &terms);
        let s2 = idx.score(&id(2).to_inline(), &terms);
        assert!(s1 > s2, "fixture: full-match should beat partial");

        // Floor below s2 → both. Floor between s2 and s1 → only doc 1.
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let c_low = idx.matches(doc, &terms, 0.0);
        let c_mid = idx.matches(doc, &terms, (s1 + s2) / 2.0);

        let mut low_props = ProposalBuffer::new();
        c_low.propose(doc.index, &Frontier::default(), &mut low_props);
        let low_ids: HashSet<Id> = low_props
            .iter()
            .map(|r| raw_value_to_id(r).unwrap())
            .collect();
        assert!(low_ids.contains(&id(1)));
        assert!(low_ids.contains(&id(2)));

        let mut mid_props = ProposalBuffer::new();
        c_mid.propose(doc.index, &Frontier::default(), &mut mid_props);
        let mid_ids: HashSet<Id> = mid_props
            .iter()
            .map(|r| raw_value_to_id(r).unwrap())
            .collect();
        assert!(mid_ids.contains(&id(1)));
        assert!(!mid_ids.contains(&id(2)));
    }

    #[test]
    fn score_helper_matches_aggregated_sum() {
        // `idx.score(doc, terms)` should equal the sum of per-
        // term posting-list scores for that doc.
        let idx = sample_index();
        let terms = hash_tokens("quick fox");

        for byte in [1u8, 3] {
            let doc_value: Inline<GenId> = id(byte).to_inline();
            let helper_score = idx.score(&doc_value, &terms);

            let target = GenId::inline_from(id(byte)).raw;
            let mut expected = 0.0_f32;
            for t in &terms {
                for (d, s) in idx.query_term(t) {
                    if d.raw == target {
                        expected += s;
                        break;
                    }
                }
            }

            assert!(
                (helper_score - expected).abs() < 1e-6,
                "score helper drifted from posting-list sum for doc {byte}"
            );
        }

        // Doc with no matching terms scores 0.0.
        let doc2_value: Inline<GenId> = id(2).to_inline();
        assert_eq!(idx.score(&doc2_value, &terms), 0.0);
    }

    #[test]
    fn matches_empty_query_yields_no_rows() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms: Vec<triblespace_core::inline::Inline<crate::tokens::WordHash>> = Vec::new();
        let c = idx.matches(doc, &terms, 0.0);

        assert_eq!(c.estimate(doc.index, &Binding::default()), Some(0));

        let mut props = ProposalBuffer::new();
        c.propose(doc.index, &Frontier::default(), &mut props);
        assert!(props.is_empty());
    }

    #[test]
    fn matches_no_matching_docs_yields_no_rows() {
        let idx = sample_index();
        let mut ctx = triblespace_core::query::VariableContext::new();
        let doc: Variable<GenId> = ctx.next_variable();
        let terms = hash_tokens("aardvark zeppelin");
        let c = idx.matches(doc, &terms, 0.0);

        assert_eq!(c.estimate(doc.index, &Binding::default()), Some(0));
        let mut props = ProposalBuffer::new();
        c.propose(doc.index, &Frontier::default(), &mut props);
        assert!(props.is_empty());
    }

    /// `from_entries` is public and may receive duplicate occurrences;
    /// the constraint denotes the raw SET, so duplicates collapse at
    /// construction — estimate, propose, and the public query heads all
    /// see each value once.
    #[test]
    fn from_entries_collapses_duplicate_occurrences() {
        let doc = Variable::<GenId>::new(0);
        let entries = [
            id_to_raw_value(id(3)),
            id_to_raw_value(id(1)),
            id_to_raw_value(id(1)),
            id_to_raw_value(id(2)),
        ];
        let constraint = BM25Filter::from_entries(doc, entries);

        assert_eq!(constraint.estimate(doc.index, &Binding::default()), Some(3));

        let mut props = ProposalBuffer::new();
        constraint.propose(doc.index, &Frontier::default(), &mut props);
        assert_eq!(
            &props[..],
            [entries[0], entries[1], entries[3]],
            "first-occurrence order, duplicates collapsed",
        );

        let mut rows: Vec<_> =
            Query::new(BM25Filter::from_entries(doc, entries), project_first).collect();
        rows.sort_unstable();
        let mut expected = vec![entries[0], entries[1], entries[3]];
        expected.sort_unstable();
        assert_eq!(rows, expected);
    }

    // ── Exact pairwise cosine + directional retrieval ─────────

    /// Build a 3-doc corpus where doc 1 = [1,0,0], doc 2 = [0,1,0],
    /// doc 3 ≈ doc 1. Returns (flat_index, hnsw_index, store,
    /// handles) — handles is parallel-indexed `[h1, h2, h3]`.
    fn sample_sim() -> (
        crate::hnsw::FlatIndex,
        crate::hnsw::HNSWIndex,
        MemoryBlobStore,
        [Inline<Handle<Embedding>>; 3],
    ) {
        use crate::hnsw::{FlatBuilder, HNSWBuilder};
        let mut store = MemoryBlobStore::new();
        let vecs = [
            vec![1.0f32, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.9, 0.1, 0.0],
        ];
        let mut handles: [Inline<Handle<Embedding>>; 3] = [Inline::new([0u8; 32]); 3];
        for (i, v) in vecs.iter().enumerate() {
            handles[i] = crate::schemas::put_embedding::<_>(&mut store, v.clone()).unwrap();
        }
        let mut flat = FlatBuilder::new(3);
        for h in handles.iter() {
            flat.insert(*h);
        }
        let mut hnsw = HNSWBuilder::new(3).with_seed(42);
        for (i, v) in vecs.iter().enumerate() {
            hnsw.insert(handles[i], v.clone()).unwrap();
        }
        (flat.build(), hnsw.build_naive(), store, handles)
    }

    #[test]
    fn flat_cosine_filters_candidates_exactly_in_both_binding_orders() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);

        let mut ctx = triblespace_core::query::VariableContext::new();
        let a: Variable<Handle<Embedding>> = ctx.next_variable();
        let b: Variable<Handle<Embedding>> = ctx.next_variable();
        let c = view.cosine_at_least(a, b, 0.8);

        let mut binding = BindingStore::new();
        binding.bind(a.index, &handles[0].raw);

        let mut no_domain = ProposalBuffer::new();
        c.propose(b.index, &binding.frontier(), &mut no_domain);
        assert!(
            no_domain.is_empty(),
            "exact cosine must never source an ANN domain"
        );

        let mut bind_b = ProposalBuffer::new();
        for handle in handles.iter() {
            bind_b.push(handle.raw);
        }
        c.confirm(b.index, &binding.frontier(), &mut bind_b.region(0));
        assert_eq!(live(&bind_b), [handles[0].raw, handles[2].raw]);

        let mut peer_binding = BindingStore::new();
        peer_binding.bind(b.index, &handles[2].raw);
        let mut bind_a = ProposalBuffer::new();
        for handle in handles.iter() {
            bind_a.push(handle.raw);
        }
        c.confirm(a.index, &peer_binding.frontier(), &mut bind_a.region(0));
        assert_eq!(live(&bind_a), [handles[0].raw, handles[2].raw]);
    }

    /// With the peer variable unbound the pair is unresolved and every
    /// candidate must stay alive — the engine confirms again once the
    /// peer binds.
    #[test]
    fn cosine_confirm_keeps_candidates_while_peer_is_unbound() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);

        let mut ctx = triblespace_core::query::VariableContext::new();
        let a: Variable<Handle<Embedding>> = ctx.next_variable();
        let b: Variable<Handle<Embedding>> = ctx.next_variable();
        let c = view.cosine_at_least(a, b, 0.8);

        let mut props = ProposalBuffer::new();
        for handle in handles.iter() {
            props.push(handle.raw);
        }
        c.confirm(b.index, &Frontier::default(), &mut props.region(0));
        assert_eq!(props.count_live(0), handles.len());
    }

    #[test]
    fn flat_cosine_satisfied_checks_the_same_exact_predicate() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);

        let mut ctx = triblespace_core::query::VariableContext::new();
        let a: Variable<Handle<Embedding>> = ctx.next_variable();
        let b: Variable<Handle<Embedding>> = ctx.next_variable();
        let c = view.cosine_at_least(a, b, 0.8);

        assert!(c.satisfied(&Binding::default()));

        let mut good = BindingStore::new();
        good.bind(a.index, &handles[0].raw);
        good.bind(b.index, &handles[2].raw);
        assert!(c.satisfied(&good.view()));

        let mut bad = BindingStore::new();
        bad.bind(a.index, &handles[0].raw);
        bad.bind(b.index, &handles[1].raw);
        assert!(!c.satisfied(&bad.view()));
    }

    #[test]
    fn hnsw_cosine_accepts_an_exact_match_outside_the_ann_index() {
        let (_flat, hnsw, mut store, handles) = sample_sim();
        let outside =
            crate::schemas::put_embedding::<_>(&mut store, vec![0.999, 0.001, 0.0]).unwrap();
        let snapshot = store.snapshot().unwrap();
        let view = hnsw.attach(&snapshot);

        let mut ctx = triblespace_core::query::VariableContext::new();
        let a: Variable<Handle<Embedding>> = ctx.next_variable();
        let b: Variable<Handle<Embedding>> = ctx.next_variable();
        let c = view.cosine_at_least(a, b, 0.99);

        let mut binding = BindingStore::new();
        binding.bind(a.index, &handles[0].raw);
        let mut candidates = ProposalBuffer::new();
        candidates.push(outside.raw);
        c.confirm(b.index, &binding.frontier(), &mut candidates.region(0));
        assert_eq!(live(&candidates), [outside.raw]);
    }

    #[test]
    fn pairwise_cosine_divides_by_norms_for_raw_embedding_blobs() {
        let (flat, _hnsw, mut store, _handles) = sample_sim();
        let a_handle = store.put::<Embedding, _>(vec![2.0f32, 0.0, 0.0]).unwrap();
        let b_handle = store.put::<Embedding, _>(vec![3.0f32, 0.0, 0.0]).unwrap();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);
        let a = Variable::<Handle<Embedding>>::new(0);
        let b = Variable::<Handle<Embedding>>::new(1);

        let mut binding = BindingStore::new();
        binding.bind(a.index, &a_handle.raw);
        let mut candidates = ProposalBuffer::new();
        candidates.push(b_handle.raw);
        view.cosine_at_least(a, b, 1.01).confirm(
            b.index,
            &binding.frontier(),
            &mut candidates.region(0),
        );
        assert_eq!(
            candidates.count_live(0),
            0,
            "parallel vectors have cosine one, not dot six"
        );
    }

    #[test]
    fn cosine_estimate_saturates_even_when_the_peer_is_bound() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);

        let mut ctx = triblespace_core::query::VariableContext::new();
        let a: Variable<Handle<Embedding>> = ctx.next_variable();
        let b: Variable<Handle<Embedding>> = ctx.next_variable();
        let unrelated: Variable<GenId> = ctx.next_variable();
        let c = view.cosine_at_least(a, b, 0.8);

        let empty = Binding::default();
        assert_eq!(c.estimate(a.index, &empty), Some(usize::MAX));
        assert_eq!(c.estimate(b.index, &empty), Some(usize::MAX));

        let mut bound = BindingStore::new();
        bound.bind(a.index, &handles[0].raw);
        assert_eq!(c.estimate(b.index, &bound.view()), Some(usize::MAX));
        assert_eq!(c.estimate(unrelated.index, &empty), None);
    }

    #[test]
    fn repeated_cosine_variable_is_checked_during_confirmation() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);
        let x = Variable::<Handle<Embedding>>::new(0);

        let mut accepted = ProposalBuffer::new();
        accepted.push(handles[0].raw);
        accepted.push(handles[1].raw);
        view.cosine_at_least(x, x, 0.99).confirm(
            x.index,
            &Frontier::default(),
            &mut accepted.region(0),
        );
        assert_eq!(accepted.count_live(0), 2);

        let mut rejected = ProposalBuffer::new();
        rejected.push(handles[0].raw);
        view.cosine_at_least(x, x, 1.01).confirm(
            x.index,
            &Frontier::default(),
            &mut rejected.region(0),
        );
        assert_eq!(rejected.count_live(0), 0);
    }

    /// End-to-end through the real engine: constant constraints source
    /// both domains, exact cosine filters the pair.
    #[test]
    fn exact_cosine_filters_in_production_queries() {
        let (flat, _hnsw, mut store, handles) = sample_sim();
        let snapshot = store.snapshot().unwrap();
        let view = flat.attach(&snapshot);
        let a = Variable::<Handle<Embedding>>::new(0);
        let b = Variable::<Handle<Embedding>>::new(1);

        let good = triblespace_core::and!(
            a.is(handles[0]),
            b.is(handles[2]),
            view.cosine_at_least(a, b, 0.8),
        );
        let rows: Vec<_> = Query::new(good, project_pair).collect();
        assert_eq!(rows, [(handles[0].raw, handles[2].raw)]);

        let bad = triblespace_core::and!(
            a.is(handles[0]),
            b.is(handles[1]),
            view.cosine_at_least(a, b, 0.8),
        );
        assert!(Query::new(bad, project_pair).next().is_none());

        let repeated = triblespace_core::and!(a.is(handles[0]), view.cosine_at_least(a, a, 1.01),);
        assert!(Query::new(repeated, project_first).next().is_none());
    }

    // ── SimilarTo (unary frozen retrieval set) ─────────────────

    #[test]
    fn similarity_constraints_are_generic_over_blob_encoding() {
        struct EqualityCosine;

        impl CosineSimilarity<SimpleArchive> for EqualityCosine {
            fn cosine_between(
                &self,
                a: Inline<Handle<SimpleArchive>>,
                b: Inline<Handle<SimpleArchive>>,
            ) -> Option<f32> {
                Some(if a == b { 1.0 } else { 0.0 })
            }
        }

        let value = Inline::<Handle<SimpleArchive>>::new([7; 32]);
        let other = Inline::<Handle<SimpleArchive>>::new([8; 32]);
        let a = Variable::<Handle<SimpleArchive>>::new(0);
        let b = Variable::<Handle<SimpleArchive>>::new(1);
        let cosine = EqualityCosine;
        let exact = triblespace_core::and!(
            a.is(value),
            b.is(value),
            CosineAtLeast::new(&cosine, a, b, 1.0),
        );
        assert_eq!(
            Query::new(exact, project_pair).collect::<Vec<_>>(),
            [(value.raw, value.raw)],
        );

        let similar = SimilarTo::from_candidates(a, vec![value.raw, other.raw]);
        let mut rows = Query::new(similar, project_first).collect::<Vec<_>>();
        rows.sort_unstable();
        assert_eq!(rows, [value.raw, other.raw]);
    }

    #[test]
    fn similar_to_collapses_duplicates_and_speaks_the_protocol() {
        let neighbour = Variable::<Handle<Embedding>>::new(0);
        let candidates = vec![
            embedding_raw(3),
            embedding_raw(1),
            embedding_raw(1),
            embedding_raw(2),
        ];
        let constraint = SimilarTo::from_candidates(neighbour, candidates.clone());

        assert_eq!(
            constraint.estimate(neighbour.index, &Binding::default()),
            Some(3)
        );

        let mut props = ProposalBuffer::new();
        constraint.propose(neighbour.index, &Frontier::default(), &mut props);
        assert_eq!(
            &props[..],
            [candidates[0], candidates[1], candidates[3]],
            "first-occurrence order, duplicates collapsed",
        );

        let mut mixed = ProposalBuffer::new();
        mixed.push(embedding_raw(1));
        mixed.push(embedding_raw(9));
        mixed.push(embedding_raw(2));
        constraint.confirm(neighbour.index, &Frontier::default(), &mut mixed.region(0));
        assert_eq!(live(&mixed), [embedding_raw(1), embedding_raw(2)]);

        let mut bound = BindingStore::new();
        bound.bind(neighbour.index, &embedding_raw(2));
        assert!(constraint.satisfied(&bound.view()));
        bound.bind(neighbour.index, &embedding_raw(9));
        assert!(!constraint.satisfied(&bound.view()));
        assert!(constraint.satisfied(&Binding::default()));
    }

    #[test]
    fn similar_to_set_identity_is_raw_support_before_rust_conversion() {
        let first = embedding_raw(1);
        let second = embedding_raw(2);
        let rows = triblespace_core::find!(
            neighbour: CollapsedEmbedding,
            SimilarTo::from_candidates(neighbour, vec![first, first, second])
        )
        .collect::<Vec<_>>();

        assert_eq!(rows, [CollapsedEmbedding, CollapsedEmbedding]);
    }

    #[test]
    fn similar_to_snapshot_outlives_attached_index_and_blob_snapshot() {
        let neighbour = Variable::<Handle<Embedding>>::new(0);
        let (constraint, mut expected) = {
            let (flat, _hnsw, mut store, handles) = sample_sim();
            let snapshot = store.snapshot().unwrap();
            let constraint = flat
                .attach(&snapshot)
                .similar_to(handles[0], neighbour, 0.8);
            (constraint, vec![handles[0].raw, handles[2].raw])
        };

        let mut rows: Vec<_> = Query::new(constraint, project_first).collect();
        rows.sort_unstable();
        expected.sort_unstable();
        assert_eq!(rows, expected);
    }

    /// A BM25 bag and a SimilarTo bag over the same variable compose
    /// through the engine's propose/confirm split in both estimate
    /// orders: the tighter side proposes, the other confirms.
    #[test]
    fn bm25_and_similar_to_intersect_in_both_orders() {
        let candidate = Variable::<Handle<Embedding>>::new(0);
        let source = vec![
            embedding_raw(3),
            embedding_raw(1),
            embedding_raw(1),
            embedding_raw(2),
        ];
        let allowed = vec![embedding_raw(1), embedding_raw(2)];
        let expected = vec![embedding_raw(1), embedding_raw(2)];

        // SimilarTo's two-value set is tighter, so it proposes and
        // BM25 confirms.
        let forward = triblespace_core::and!(
            BM25Filter::<Handle<Embedding>>::from_entries(candidate, source.clone()),
            SimilarTo::from_candidates(candidate, allowed.clone()),
        );
        let mut forward_rows: Vec<_> = Query::new(forward, project_first).collect();
        forward_rows.sort_unstable();
        assert_eq!(forward_rows, expected);

        // Reversing the child types makes BM25's shorter set own the
        // proposal while SimilarTo exercises pointwise confirmation.
        let reverse = triblespace_core::and!(
            SimilarTo::from_candidates(candidate, source),
            BM25Filter::<Handle<Embedding>>::from_entries(candidate, allowed),
        );
        let mut reverse_rows: Vec<_> = Query::new(reverse, project_first).collect();
        reverse_rows.sort_unstable();
        assert_eq!(reverse_rows, expected);
    }

    // ── Source distinctness: where the collapse is load-bearing ────
    //
    // The engine has no head-claiming layer, so a value proposed twice is a
    // row emitted twice: multiplicity may only come from joins, never from a
    // source repeating itself. These two tests pin down which producers can
    // repeat and prove the interface property holds either way.

    /// Repeated BM25 rows join canonically by document key before either index
    /// is built. `aggregate_above` then retains set-shaped output while it sums
    /// contributions from several query terms.
    #[test]
    fn bm25_duplicate_rows_are_canonical_before_aggregation() {
        fn corpus() -> BM25Builder {
            let mut b: BM25Builder = BM25Builder::new();
            b.insert(id(1), hash_tokens("the quick brown fox"));
            b.insert(id(1), hash_tokens("the quick brown fox again"));
            b.insert(id(2), hash_tokens("the lazy brown dog"));
            b
        }
        let fox = hash_tokens("fox");
        let naive = corpus().build_naive();

        // The raw posting-list walk is already distinct by document key.
        let postings: Vec<_> = naive.query_term(&fox[0]).collect();
        assert_eq!(postings.len(), 1);

        // The constraint denotes the set, so the query head sees one row.
        let rows: Vec<Id> = triblespace_core::find!(
            (doc: Id),
            naive.matches(doc, &fox, 0.0)
        )
        .map(|(d,)| d)
        .collect();
        assert_eq!(rows, [id(1)]);

        #[cfg(feature = "succinct")]
        {
            // The succinct backend implements the same `(Docs, F)` join.
            let succinct = corpus().build();
            assert_eq!(succinct.query_term(&fox[0]).count(), 1);
            let rows: Vec<Id> = triblespace_core::find!(
                (doc: Id),
                succinct.matches(doc, &fox, 0.0)
            )
            .map(|(d,)| d)
            .collect();
            assert_eq!(rows, [id(1)]);
        }
    }

    /// Embedding handles are content-addressed, so two entities that embed to
    /// the same vector share one handle — and neither `FlatBuilder::insert`
    /// nor `HNSWBuilder::insert` collapses a repeat, so the handle table holds
    /// it twice and `candidates_above` hands both copies through. Nothing
    /// downstream would collapse them, which makes the dedup inside
    /// `SimilarTo::from_candidates` load-bearing rather than defensive on all
    /// three retrieval backends.
    #[test]
    fn similar_to_collapses_a_handle_the_index_stores_twice() {
        use crate::hnsw::{FlatBuilder, HNSWBuilder};

        let mut store = MemoryBlobStore::new();
        let near = vec![1.0f32, 0.0, 0.0];
        let far = vec![0.0f32, 1.0, 0.0];
        let near_h = crate::schemas::put_embedding::<_>(&mut store, near.clone()).unwrap();
        let far_h = crate::schemas::put_embedding::<_>(&mut store, far.clone()).unwrap();

        let mut flat_b = FlatBuilder::new(3);
        flat_b.insert(near_h);
        flat_b.insert(near_h);
        flat_b.insert(far_h);
        let flat = flat_b.build();

        let mut hnsw_b = HNSWBuilder::new(3).with_seed(42);
        hnsw_b.insert(near_h, near.clone()).unwrap();
        hnsw_b.insert(near_h, near.clone()).unwrap();
        hnsw_b.insert(far_h, far).unwrap();
        let hnsw = hnsw_b.build_naive();

        let snapshot = store.snapshot().unwrap();
        let flat_view = flat.attach(&snapshot);
        let hnsw_view = hnsw.attach(&snapshot);

        // Both leaf walks repeat the shared handle.
        assert_eq!(flat_view.candidates_above(near_h, 0.8).unwrap().len(), 2);
        assert_eq!(hnsw_view.candidates_above(near_h, 0.8).unwrap().len(), 2);

        // One row per distinct handle through the engine, on every backend.
        let expected = [near_h.raw];
        let neighbour = Variable::<Handle<Embedding>>::new(0);
        assert_eq!(
            Query::new(flat_view.similar_to(near_h, neighbour, 0.8), project_first)
                .collect::<Vec<_>>(),
            expected
        );
        let rows: Vec<Inline<Handle<Embedding>>> = triblespace_core::find!(
            (n: Inline<Handle<Embedding>>),
            hnsw_view.similar_to(near_h, n, 0.8)
        )
        .map(|(h,)| h)
        .collect();
        assert_eq!(rows, [near_h]);

        #[cfg(feature = "succinct")]
        {
            // `from_naive` copies the handle table verbatim — no universe, no
            // sort, no dedup — so the succinct walk repeats it too.
            let succinct = crate::succinct::SuccinctHNSWIndex::from_naive(&hnsw).unwrap();
            let succinct_view = succinct.attach(&snapshot);
            assert_eq!(
                succinct_view.candidates_above(near_h, 0.8).unwrap().len(),
                2
            );
            let rows: Vec<Inline<Handle<Embedding>>> = triblespace_core::find!(
                (n: Inline<Handle<Embedding>>),
                succinct_view.similar_to(near_h, n, 0.8)
            )
            .map(|(h,)| h)
            .collect();
            assert_eq!(rows, [near_h]);
        }
    }
}
