use super::*;
use smallvec::SmallVec;

/// Debug check for the `estimate` relevance contract: whether a constraint
/// answers `Some` or `None` must depend only on *which* variables are bound,
/// never on their values. Composites read relevance off one row of the batch,
/// so a constraint that flips mid-frontier silently changes the bag — and in
/// either direction, which is why it is worth catching rather than
/// documenting alone.
///
/// Sampled rather than exhaustive: checking every row of a 16k frontier on
/// every confirm would make debug builds unusable. Rows are walked with a
/// stride so the sample spans the whole batch and always includes the last
/// row, and frontiers of `MAX_ROWS` or fewer are checked completely. A
/// violation that is uniform across the sampled rows but not the skipped ones
/// would slip through; a constraint whose relevance depends on values is
/// overwhelmingly unlikely to agree on a spread this wide by accident.
///
/// Not `#[cfg(debug_assertions)]`: `debug_assert!` still *compiles* its body
/// in release (it expands to `if cfg!(debug_assertions)`), so gating this
/// would break the release build. It is simply never called there.
fn frontier_relevance_is_uniform<'a, C: Constraint<'a>>(
    constraints: &[C],
    variable: VariableId,
    frontier: &Frontier<'_>,
) -> bool {
    const MAX_ROWS: usize = 64;
    let rows = frontier.len();
    if rows < 2 {
        return true;
    }
    let stride = rows.div_ceil(MAX_ROWS);
    constraints.iter().all(|c| {
        let expected = c.estimate(variable, &frontier.row(0)).is_some();
        (0..rows)
            .step_by(stride)
            .chain(std::iter::once(rows - 1))
            .all(|i| c.estimate(variable, &frontier.row(i)).is_some() == expected)
    })
}

/// Logical conjunction of constraints (AND).
///
/// All children must agree on every variable binding. Built by the
/// [`and!`](crate::and) macro or directly via [`new`](Self::new).
///
/// The intersection delegates to its children using cardinality-aware
/// ordering: the child with the lowest [`estimate`](Constraint::estimate)
/// proposes candidates, and the remaining children
/// [`confirm`](Constraint::confirm) them in order of increasing estimate.
/// This strategy keeps the candidate set small from the start and avoids
/// materialising cross products.
///
/// Variables from all children are exposed as a single union, so the
/// engine sees one flat set of variables regardless of how many
/// sub-constraints contribute.
pub struct IntersectionConstraint<C> {
    constraints: Vec<C>,
}

impl<'a, C> IntersectionConstraint<C>
where
    C: Constraint<'a> + 'a,
{
    /// Creates an intersection over the given constraints.
    pub fn new(constraints: Vec<C>) -> Self {
        IntersectionConstraint { constraints }
    }
}

impl<'a> IntersectionConstraint<Box<dyn Constraint<'a> + Send + Sync + 'a>> {
    /// What `pattern!` returns: the intersection of its clauses, or the one
    /// clause itself when there is only one. An intersection of one child
    /// would still estimate that child on every row to choose a proposer
    /// that cannot differ, so it is not built at all. The relevance check
    /// in `propose` stays wherever an intersection really chooses.
    pub fn arc_or_single(
        mut constraints: Vec<Box<dyn Constraint<'a> + Send + Sync + 'a>>,
    ) -> std::sync::Arc<dyn Constraint<'a> + Send + Sync + 'a> {
        if constraints.len() == 1 {
            std::sync::Arc::from(constraints.pop().expect("exactly one constraint"))
        } else {
            std::sync::Arc::new(IntersectionConstraint::new(constraints))
        }
    }
}

impl<'a, C> Constraint<'a> for IntersectionConstraint<C>
where
    C: Constraint<'a> + 'a,
{
    /// Returns the union of all children's variable sets.
    fn variables(&self) -> VariableSet {
        self.constraints
            .iter()
            .fold(VariableSet::new_empty(), |vs, c| vs.union(c.variables()))
    }

    /// Returns the **minimum** estimate across children that constrain
    /// `variable`. The tightest child bounds the search, reflecting the
    /// intersection semantics: every child must agree, so the smallest
    /// candidate set dominates.
    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.constraints
            .iter()
            .filter_map(|c| c.estimate(variable, binding))
            .min()
    }

    /// The componentwise minimum over the children that constrain
    /// `variable`: every value and every row the intersection reaches lies
    /// within each child's, so the smallest bounds them all.
    fn cardinality(&self, variable: VariableId, binding: &Binding) -> Option<Cardinality> {
        self.constraints
            .iter()
            .filter_map(|c| c.cardinality(variable, binding))
            .reduce(|acc, c| Cardinality {
                distinct: acc.distinct.min(c.distinct),
                rows: acc.rows.min(c.rows),
            })
    }

    /// Lets each row's tightest child propose, then confirms through the
    /// rest — kills land in the region's liveness words; nothing is
    /// compacted. Children that return `None` for this variable are
    /// skipped.
    ///
    /// The tightest child is a *per-row* decision, exactly as the variable
    /// choice is: an estimate is a function of the row's binding, and one
    /// row's binding can make the archive the selective source while
    /// another's makes a hash set selective. Rows that agree — the common
    /// case — travel as one batch with no row copied; genuine disagreement
    /// pays for one [`Frontier::with_select`] sub-batch per source, which
    /// is what keeps each `propose`/`confirm` pass homogeneous enough for a
    /// batched executor to dispatch it as a unit.
    ///
    /// Only the tail region this call appended (from the incoming buffer
    /// length onward) is confirmed, so proposals appended by sibling
    /// constraints in an enclosing composite are never filtered through
    /// this intersection's children.
    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        let rows = frontier.len();
        if rows == 0 {
            return;
        }

        // Per-row: the tightest child, and which children have an opinion
        // about `variable` at all.
        let mut choice: Vec<usize> = Vec::with_capacity(rows);
        // Rows on which each child claimed the variable. Only read by the
        // debug assertion below — this loop already visits every row, so the
        // contract check is exhaustive here rather than sampled.
        let mut relevant_rows: SmallVec<[usize; 8]> =
            SmallVec::from_elem(0, self.constraints.len());
        // Row 0 names every relevant child under the checked relevance
        // contract. Keep its estimate beside the child index: this is both
        // the relevance list and the confirmer order below, so wide
        // intersections need no second allocation merely to sort.
        let mut confirmers: SmallVec<[(usize, usize); 8]> = SmallVec::new();
        for row in 0..rows {
            let binding = frontier.row(row);
            let mut best = usize::MAX;
            let mut best_child = usize::MAX;
            for (i, c) in self.constraints.iter().enumerate() {
                if let Some(estimate) = c.estimate(variable, &binding) {
                    relevant_rows[i] += 1;
                    if row == 0 {
                        confirmers.push((estimate, i));
                    }
                    if best_child == usize::MAX || estimate < best {
                        best = estimate;
                        best_child = i;
                    }
                }
            }
            choice.push(best_child);
        }
        // NOT a `debug_assert!`. The per-row tally above runs in every build
        // — release included — so the only thing `debug_assert!` bought was
        // discarding the conclusion we had already paid for. And the failure
        // it guards is silent: a violating constraint does not crash, it
        // returns a DIFFERENT BAG. Measured on the contract fixture, 18 rows
        // at width 1 against 11 at width 4096, with nothing to indicate the
        // seven that vanished. A wrong answer nobody can see is worse than a
        // panic, so this one is paid for in release too. The `confirm`-side
        // twin stays debug-only: its uniformity scan is work done ONLY for
        // the check, which is a different trade.
        assert!(
            relevant_rows.iter().all(|&n| n == 0 || n == rows),
            "Constraint::estimate returned Some for some rows of a frontier \
             and None for others on variable {variable}. Whether the answer \
             is Some or None must depend only on which variables are bound, \
             not on their values (see Constraint::estimate). This propose \
             ORs relevance across the batch, so a child that claims the \
             variable on any row is then allowed to confirm every row."
        );

        // No child constrains this variable anywhere in the batch.
        if choice.iter().all(|&c| c == usize::MAX) {
            return;
        }

        // Cheapest child filters first, so later confirmers see fewer live
        // entries. Same rule `confirm` applies, for the same reason: kills
        // conjoin, so confirmer order is a pure cost heuristic and the
        // batch's first row can supply it for the whole pass. These two
        // paths previously disagreed — `confirm` sorted, this one ran in
        // declaration order — which was an undefended inconsistency rather
        // than a decision.
        let single = choice.iter().all(|&c| c == choice[0]);
        if single {
            let base = proposals.len();
            self.constraints[choice[0]].propose(variable, frontier, proposals);
            let mut region = proposals.region(base);
            if !confirmers.is_sorted_by_key(|&(estimate, _)| estimate) {
                confirmers.sort_unstable_by_key(|&(estimate, _)| estimate);
            }
            for &(_, i) in confirmers.iter().filter(|&&(_, i)| i != choice[0]) {
                self.constraints[i].confirm(variable, frontier, &mut region);
            }
            return;
        }

        let mut select: Vec<u32> = Vec::new();
        let mut positions: Vec<u32> = Vec::new();
        for proposer in 0..self.constraints.len() {
            positions.clear();
            positions.extend(
                choice
                    .iter()
                    .enumerate()
                    .filter(|(_, &c)| c == proposer)
                    .map(|(row, _)| row as u32),
            );
            if positions.is_empty() {
                continue;
            }
            select.clear();
            frontier.compose(positions.iter().copied(), &mut select);
            let sub = frontier.with_select(&select);

            let base = proposals.len();
            self.constraints[proposer].propose(variable, &sub, proposals);
            let mut region = proposals.region(base);
            if !confirmers.is_sorted_by_key(|&(estimate, _)| estimate) {
                confirmers.sort_unstable_by_key(|&(estimate, _)| estimate);
            }
            for &(_, i) in confirmers.iter().filter(|&&(_, i)| i != proposer) {
                self.constraints[i].confirm(variable, &sub, &mut region);
            }
            // The child tagged its candidates with sub-batch row numbers;
            // lift them back into this frontier's coordinates before the
            // region reaches our caller.
            proposals.remap_region(base, &positions);
        }
    }

    /// Confirms proposals through all children that constrain `variable`,
    /// all killing into the shared mask.
    ///
    /// Ordering the children by estimate is a pure cost heuristic — kills
    /// conjoin regardless — so the batch's first row supplies the ordering
    /// for the whole pass rather than each row re-deciding it.
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if frontier.is_empty() {
            return;
        }
        let binding = frontier.row(0);
        debug_assert!(
            frontier_relevance_is_uniform(&self.constraints, variable, frontier),
            "Constraint::estimate returned Some for some rows of a frontier \
             and None for others on variable {variable}. Whether the answer \
             is Some or None must depend only on which variables are bound, \
             not on their values (see Constraint::estimate). Reading \
             relevance off row 0 — as this does — otherwise changes the bag."
        );
        let mut relevant_constraints: SmallVec<[(usize, &C); 8]> = self
            .constraints
            .iter()
            .filter_map(|c| Some((c.estimate(variable, &binding)?, c)))
            .collect();
        if !relevant_constraints.is_sorted_by_key(|(estimate, _)| *estimate) {
            relevant_constraints.sort_unstable_by_key(|(estimate, _)| *estimate);
        }

        for (_, c) in relevant_constraints.iter() {
            c.confirm(variable, frontier, cands);
        }
    }

    /// Returns `true` only when **every** child is satisfied.
    fn satisfied(&self, binding: &Binding) -> bool {
        self.constraints.iter().all(|c| c.satisfied(binding))
    }

    /// Returns the union of all children's influence sets for `variable`.
    fn influence(&self, variable: VariableId) -> VariableSet {
        self.constraints
            .iter()
            .fold(VariableSet::new_empty(), |acc, c| {
                acc.union(c.influence(variable))
            })
    }
}

/// Combines constraints into an [`IntersectionConstraint`] (logical AND).
///
/// All constraints must agree on every variable binding for a result to
/// be produced. Accepts one or more constraint expressions.
///
/// ```rust,ignore
/// and!(set.pattern(e, a, v), allowed.has(v))
/// ```
#[macro_export]
macro_rules! and {
    // Emits `Arc<IntersectionConstraint<Box<dyn Constraint + Send + Sync>>>`.
    // The outer `Arc` makes the whole tree cheap to `Clone` (single
    // refcount bump) — required by the `parallel` feature's `Query::clone`
    // during rayon split. `Send + Sync` on the trait object lets the tree
    // cross rayon thread boundaries. Every in-tree constraint built via
    // this macro already satisfies Send + Sync; non-thread-safe constraint
    // types (e.g. `Rc`-backed ContainsConstraint variants) can still be
    // used via direct `IntersectionConstraint::new` construction.
    // A single constraint needs no intersection: wrapping it would only
    // re-estimate it on every row to pick the proposer it already is.
    ($c:expr $(,)?) => (::std::sync::Arc::new($c));
    ($($c:expr),+ $(,)?) => (
        ::std::sync::Arc::new(
            $crate::query::intersectionconstraint::IntersectionConstraint::new(vec![
                $(Box::new($c)
                    as Box<dyn $crate::query::Constraint + Send + Sync>),+
            ])
        )
    )
}

/// Re-export of the [`and!`] macro.
pub use and;
