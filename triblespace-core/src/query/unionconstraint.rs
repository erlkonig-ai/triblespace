use super::*;
use itertools::Itertools;

/// Logical disjunction of constraints (OR).
///
/// A value is accepted if *any* variant accepts it. Built by the
/// [`or!`](crate::or) macro, by [`pattern_changes!`](crate::macros::pattern_changes),
/// or directly via [`new`](Self::new).
///
/// All variants must declare the same [`VariableSet`]; this is asserted at
/// construction time. Branch-local variables are unsupported because the
/// engine's result schema is flat — every row binds the same variable set
/// exactly once, so a variable that exists only in some alternatives has
/// no representation. (This is a result-model restriction, not a semantic
/// one: the union itself is monotonic.) Since `pattern!` folds attribute
/// constants and literal values into constant [`Term`](crate::query::Term)s
/// (they never become variables), the requirement is about the *query
/// variables the caller wrote*: every arm must mention the same ones.
/// Estimates are summed across variants, proposals are merged and
/// deduplicated, and confirmations are ORed per candidate region.
///
/// Before proposing or confirming, the union checks each variant's
/// [`satisfied`](Constraint::satisfied) status for the row and skips
/// variants that are provably dead. This is not a leftover of the old
/// hidden-variable desugar — folding literals into constant `Term`s did
/// not retire it, because deadness does not come from the constants. It
/// comes from a variant being a *conjunction*: `pattern!` lowers to an
/// [`IntersectionConstraint`](crate::query::intersectionconstraint::IntersectionConstraint) with
/// one clause per triple, and a propose/confirm pass consults only the
/// clauses that return `Some` from `estimate` for the variable at hand.
/// So in an arm like `{ ?p @ nickname: "Ali", city: ?out }` the `nickname`
/// clause takes no part in the `?out` pass at all. Once `?p` is bound to
/// an entity whose nickname is not `"Ali"` that arm is logically dead, yet
/// its `city` clause would still propose the entity's city — and since the
/// union ORs the per-variant survivors, the arm then confirms its own
/// proposal and the row escapes. The liveness gate is what notices: the
/// pinned clause's own `satisfied` is `false`, the intersection conjoins
/// that to kill the arm, and the union drops the arm's contribution for
/// that row. Both call sites are independently load-bearing; the
/// `union_dead_variant_leak` integration test pins one leak per site.
pub struct UnionConstraint<C> {
    constraints: Vec<C>,
}

impl<'a, C> UnionConstraint<C>
where
    C: Constraint<'a> + 'a,
{
    /// Creates a union over the given constraints.
    ///
    /// # Panics
    ///
    /// Panics if `constraints` is empty (a zero-arm union has no
    /// well-defined variable set), or if the variants do not all
    /// declare the same variable set.
    pub fn new(constraints: Vec<C>) -> Self {
        assert!(
            !constraints.is_empty(),
            "UnionConstraint requires at least one variant; \
             use a different constraint type for the empty case"
        );
        if let Some((i, (a, b))) = constraints
            .iter()
            .map(|c| c.variables())
            .tuple_windows()
            .enumerate()
            .find(|(_, (a, b))| a != b)
        {
            panic!(
                "all union (or!) variants must mention the same query \
                 variables: variant {} declares {:?} but variant {} \
                 declares {:?}",
                i,
                a,
                i + 1,
                b
            );
        }
        UnionConstraint { constraints }
    }
}

impl<'a, C> Constraint<'a> for UnionConstraint<C>
where
    C: Constraint<'a> + 'a,
{
    /// Returns the variable set of the first variant (all variants share
    /// the same set, enforced at construction).
    fn variables(&self) -> VariableSet {
        self.constraints[0].variables()
    }

    /// Returns the **sum** of estimates across all variants. A union can
    /// produce candidates from any branch, so the cardinalities add.
    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.constraints
            .iter()
            .filter_map(|c| c.estimate(variable, binding))
            .reduce(|acc, e| acc + e)
    }

    /// Returns the **sum** of volumes across all variants, as for
    /// [`estimate`](Self::estimate).
    fn estimate_volume(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.constraints
            .iter()
            .filter_map(|c| c.estimate_volume(variable, binding))
            .reduce(|acc, e| acc + e)
    }

    /// Collects proposals from every variant that is satisfied *for a
    /// given row*, then sorts and deduplicates per row. Dead variants
    /// (where [`satisfied`](Constraint::satisfied) returns `false`) are
    /// skipped so their stale bindings cannot inject values that no live
    /// variant would produce.
    ///
    /// With a batch, "dead" is per row: a variant alive nowhere is skipped
    /// entirely (the single-binding behaviour), a variant alive everywhere
    /// proposes untouched, and a variant alive for only some rows has the
    /// rest of its contribution dropped again before the sort.
    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        let rows = frontier.len();
        let base = proposals.len();
        let mut satisfied = vec![false; rows];
        for c in self.constraints.iter() {
            let mut any = false;
            let mut all = true;
            for (row, slot) in satisfied.iter_mut().enumerate() {
                *slot = c.satisfied(&frontier.row(row));
                any |= *slot;
                all &= *slot;
            }
            if !any {
                continue;
            }
            let variant_base = proposals.len();
            c.propose(variable, frontier, proposals);
            if !all {
                proposals.retain_region(variant_base, |row, _| satisfied[row as usize]);
            }
        }
        // Freshness rule: a proposer may rewrite its own freshly-appended
        // region before returning — indices freeze once the caller can see
        // them. The union's set semantics need the sort-dedup, and the key
        // is `(row, value)`: the set is per parent binding, not across the
        // batch. Sorting by that key also restores contiguous segments.
        // `tagged` yields only live entries, which matters here: a variant
        // may kill inside its own propose (an `and!` arm whose narrow side
        // confirms as it goes), and `rewrite_region` republishes everything
        // it is handed as live, so reading the dead back would resurrect
        // them.
        let mut fresh: Vec<(u32, RawInline)> = proposals.tagged(base).collect();
        fresh.sort_unstable();
        fresh.dedup();
        proposals.rewrite_region(base, fresh);
    }

    /// Confirms proposals against every variant that is satisfied for the
    /// candidate's own row (each on a scratch copy of the region's
    /// liveness) and ors the per-variant survivors together. A value passes
    /// if *any* live variant confirms it.
    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        let rows = frontier.len();
        // `any_live` accumulates, per candidate, whether *some* live variant
        // kept it. It is sized in liveness **words**, not candidates: one
        // word carries several candidates and a region that starts mid-word
        // needs one word more than a candidate count implies.
        // `live_word_len` is the only thing that knows.
        let mut any_live = vec![0u32; cands.live_word_len()];
        let mut satisfied = vec![false; rows];
        for c in self.constraints.iter() {
            let mut any = false;
            let mut all = true;
            for (row, slot) in satisfied.iter_mut().enumerate() {
                *slot = c.satisfied(&frontier.row(row));
                any |= *slot;
                all &= *slot;
            }
            if !any {
                continue;
            }
            // Each variant votes on its own copy of the region's liveness, so
            // one variant's kills cannot hide a candidate from the next. The
            // scratch keeps the region's bit alignment, which is what lets
            // the votes be merged word-wise.
            let mut scratch = cands.live_words();
            if !all {
                // A variant that is dead for a row must not vote for that
                // row's candidates. Kill by *index* through a scratch region
                // rather than zeroing words directly: a word is shared by
                // several candidates, which need not share a parent.
                let mut votes = cands.scratch(&mut scratch);
                for i in 0..votes.len() {
                    if !satisfied[votes.parent(i) as usize] {
                        votes.kill(i);
                    }
                }
            }
            c.confirm(variable, frontier, &mut cands.scratch(&mut scratch));
            or_words(&mut any_live, &scratch);
        }
        // Kill-only by construction: every `scratch` started as a copy of the
        // liveness on entry and confirmers may only clear, so `any_live` is a
        // subset of what was already live — writing it back kills exactly the
        // candidates no variant confirmed and revives nothing.
        //
        // Write through `set_live_words` rather than a kill loop because that
        // is the one path that knows about region boundaries: bit-packed, the
        // first and last words of a region carry bits owned by *neighbouring*
        // regions of the same buffer, and it masks them out. Do not
        // "simplify" this into a direct word copy.
        cands.set_live_words(&any_live);
    }

    /// Returns `true` when **at least one** variant is satisfied.
    fn satisfied(&self, binding: &Binding) -> bool {
        self.constraints.iter().any(|c| c.satisfied(binding))
    }

    /// Returns the union of all variants' influence sets for `variable`.
    fn influence(&self, variable: VariableId) -> VariableSet {
        self.constraints
            .iter()
            .fold(VariableSet::new_empty(), |acc, c| {
                acc.union(c.influence(variable))
            })
    }
}

/// Combines constraints into a [`UnionConstraint`] (logical OR).
///
/// A result is produced when *any* of the given constraints is satisfied.
/// All constraints must declare the same variable set.
///
/// ```rust,ignore
/// or!(pattern!(&set_a, [...]), pattern!(&set_b, [...]))
/// ```
#[macro_export]
macro_rules! or {
    ($($c:expr),+ $(,)?) => (
        ::std::sync::Arc::new(
            $crate::query::unionconstraint::UnionConstraint::new(vec![
                $(Box::new($c)
                    as Box<dyn $crate::query::Constraint + Send + Sync>),+
            ])
        )
    )
}

/// Re-export of the [`or!`] macro.
pub use or;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::constantconstraint::ConstantConstraint;

    #[derive(Clone, Copy)]
    struct RepeatedValueSource {
        value: RawInline,
    }

    impl<'a> Constraint<'a> for RepeatedValueSource {
        fn variables(&self) -> VariableSet {
            VariableSet::new_singleton(0)
        }

        fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
            (variable == 0).then_some(2)
        }

        fn propose(
            &self,
            variable: VariableId,
            frontier: &Frontier<'_>,
            proposals: &mut ProposalBuffer,
        ) {
            assert_eq!(variable, 0);
            for parent in 0..frontier.len() {
                proposals.open(parent as u32);
                proposals.extend([self.value, self.value]);
            }
        }

        fn confirm(
            &self,
            _variable: VariableId,
            _frontier: &Frontier<'_>,
            _candidates: &mut Candidates<'_>,
        ) {
        }
    }

    #[test]
    #[should_panic(expected = "UnionConstraint requires at least one variant")]
    fn empty_union_panics_at_construction() {
        // Without this assert, `variables()` would later panic on
        // `self.constraints[0]` with an unhelpful index-out-of-bounds.
        let _: UnionConstraint<ConstantConstraint> = UnionConstraint::new(vec![]);
    }

    #[test]
    fn union_deduplicates_on_parent_and_value() {
        let mut value = [0; 32];
        value[31] = 7;
        let source = RepeatedValueSource { value };
        let union = UnionConstraint::new(vec![source, source]);

        let root = Frontier::default();
        let selected = [0, 0];
        let frontier = root.with_select(&selected);
        let mut proposals = ProposalBuffer::new();
        union.propose(0, &frontier, &mut proposals);

        assert_eq!(
            proposals.tagged(0).collect::<Vec<_>>(),
            vec![(0, value), (1, value)],
            "equal values collapse within a parent but remain distinct across parents",
        );
    }
}
