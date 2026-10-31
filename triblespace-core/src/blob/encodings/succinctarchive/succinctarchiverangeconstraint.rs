use super::*;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;
use crate::query::Binding;
use crate::query::Candidates;
use crate::query::Constraint;
use crate::query::Frontier;
use crate::query::ProposalBuffer;
use crate::query::Variable;
use crate::query::VariableId;
use crate::query::VariableSet;

/// Inline-range constraint for [`SuccinctArchive`].
///
/// Mirrors [`TribleSet::value_in_range`](crate::trible::TribleSet::value_in_range).
/// The implementation leans on two archive primitives:
///
/// - [`Universe::search_range`] turns the inclusive value range
///   `[min, max]` into a half-open code range `[lo, hi)` in O(log n).
///   This works because [`Universe`] guarantees value-ordered codes.
/// - [`SuccinctArchive::enumerate_domain_in_range`] walks only the codes
///   that actually appear on the indexed axis (here: V) within `[lo, hi)`,
///   skipping empty groups via the same `select1` stride that powers the
///   unbounded [`enumerate_domain`].
///
/// Total propose cost is O(log n + K) where K is the count of distinct
/// V-position codes whose values fall in the range. The `cached_estimate`
/// is the upper bound `hi - lo` (codes in range, before V-presence
/// filtering) — computed once at construction in O(log n) and returned
/// in O(1) at planning time.
///
/// # Example
///
/// ```rust,ignore
/// find!(ts: Inline<NsTAIInterval>,
///     and!(
///         pattern!(&archive, [{ ?id @ attr: ?ts }]),
///         archive.value_in_range(ts, min_ts, max_ts),
///     )
/// )
/// ```
pub struct SuccinctArchiveRangeConstraint<'a, U>
where
    U: Universe,
{
    variable_v: VariableId,
    min: RawInline,
    max: RawInline,
    archive: &'a SuccinctArchive<U>,
    /// Cached upper-bound estimate: width of the universe code range
    /// covering `[min, max]`. Computed once at construction so
    /// `estimate` is O(1) at planning time.
    cached_estimate: usize,
}

impl<'a, U> SuccinctArchiveRangeConstraint<'a, U>
where
    U: Universe,
{
    pub fn new<V: InlineEncoding>(
        variable_v: Variable<V>,
        min: Inline<V>,
        max: Inline<V>,
        archive: &'a SuccinctArchive<U>,
    ) -> Self {
        // O(log n) range lookup once at construction; query-time estimate
        // is just the cached width.
        let code_range = archive.domain.search_range(&min.raw, &max.raw);
        let cached_estimate = code_range.end.saturating_sub(code_range.start);
        SuccinctArchiveRangeConstraint {
            variable_v: variable_v.index,
            min: min.raw,
            max: max.raw,
            archive,
            cached_estimate,
        }
    }
}

impl<'a, U> Constraint<'a> for SuccinctArchiveRangeConstraint<'a, U>
where
    U: Universe,
{
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.variable_v)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        if variable != self.variable_v {
            return None;
        }
        Some(self.cached_estimate)
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        if variable != self.variable_v {
            return;
        }
        let code_range = self.archive.domain.search_range(&self.min, &self.max);
        for row in 0..frontier.len() {
            proposals.open(row as u32);
            proposals.extend(
                self.archive
                    .enumerate_domain_in_range(&self.archive.v_a, code_range.clone()),
            );
        }
    }

    /// The range test does not depend on the parent binding.
    fn confirm(&self, variable: VariableId, _frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable == self.variable_v {
            cands.retain(|v| *v >= self.min && *v <= self.max);
        }
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        match binding.get(self.variable_v) {
            Some(v) => *v >= self.min && *v <= self.max,
            None => true,
        }
    }
}

/// Domain-range constraint for [`SuccinctArchive`], on no particular axis.
///
/// Created by [`SuccinctArchive::domain_in_range`]. The archive's domain is
/// the sorted set of every raw value occurring in E, A or V position, so
/// the values in `[min, max]` are one contiguous code range
/// ([`Universe::search_range`]), and proposing them is one domain access
/// per code. Which position a value occupies is left to the patterns the
/// constraint is joined with. The estimate is the exact proposal count,
/// computed once at construction.
pub struct SuccinctArchiveDomainRangeConstraint<'a, U>
where
    U: Universe,
{
    variable: VariableId,
    min: RawInline,
    max: RawInline,
    codes: std::ops::Range<usize>,
    archive: &'a SuccinctArchive<U>,
}

impl<'a, U> SuccinctArchiveDomainRangeConstraint<'a, U>
where
    U: Universe,
{
    pub fn new<V: InlineEncoding>(
        variable: Variable<V>,
        min: Inline<V>,
        max: Inline<V>,
        archive: &'a SuccinctArchive<U>,
    ) -> Self {
        SuccinctArchiveDomainRangeConstraint {
            variable: variable.index,
            min: min.raw,
            max: max.raw,
            codes: archive.domain.search_range(&min.raw, &max.raw),
            archive,
        }
    }

    fn contains(&self, value: &RawInline) -> bool {
        *value >= self.min && *value <= self.max
    }
}

impl<'a, U> Constraint<'a> for SuccinctArchiveDomainRangeConstraint<'a, U>
where
    U: Universe,
{
    fn variables(&self) -> VariableSet {
        VariableSet::new_singleton(self.variable)
    }

    fn estimate(&self, variable: VariableId, _binding: &Binding) -> Option<usize> {
        (variable == self.variable).then_some(self.codes.len())
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        if variable != self.variable {
            return;
        }
        for row in 0..frontier.len() {
            proposals.open(row as u32);
            proposals.extend(
                self.codes
                    .clone()
                    .map(|code| self.archive.domain.access(code)),
            );
        }
    }

    /// The range test does not depend on the parent binding.
    fn confirm(&self, variable: VariableId, _frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable == self.variable {
            cands.retain(|value| self.contains(value));
        }
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        binding
            .get(self.variable)
            .is_none_or(|value| self.contains(value))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::id::RawId;
    use crate::inline::encodings::genid::GenId;
    use crate::inline::encodings::UnknownInline;
    use crate::inline::Encodes;
    use crate::prelude::*;
    use crate::query::VariableContext;
    use crate::trible::Trible;

    use super::super::{OrderedUniverse, SuccinctArchive, UnionArchive};
    use super::*;

    attributes! {
        "DD00000000000000DD00000000000001" unsafe as range_link: GenId;
        "DD00000000000000DD00000000000002" unsafe as range_raw: UnknownInline;
    }

    fn id(bytes: RawId) -> Id {
        Id::new(bytes).unwrap()
    }

    fn bound(raw: RawId) -> Inline<GenId> {
        GenId::encode(raw)
    }

    /// The id-shaped part of the domain, as a range.
    fn every_id() -> (Inline<GenId>, Inline<GenId>) {
        (bound([0; 16]), bound([0xff; 16]))
    }

    /// Three entities 10.., 20.., 30..: e1 links to e2, e3 links to e1,
    /// e2 holds a raw value. So e2 occurs only as a value, and every id in
    /// the domain is one of the entities or the two attributes.
    fn fixture() -> (TribleSet, [Id; 3]) {
        let [e1, e2, e3] = [0x10, 0x20, 0x30].map(|first| {
            let mut raw = [0x11; 16];
            raw[0] = first;
            id(raw)
        });
        let mut set = TribleSet::new();
        set.insert(&Trible::force(&e1, &range_link.id(), &GenId::encode(e2)));
        set.insert(&Trible::force(
            &e2,
            &range_raw.id(),
            &Inline::<UnknownInline>::new([0x7f; 32]),
        ));
        set.insert(&Trible::force(&e3, &range_link.id(), &GenId::encode(e1)));
        (set, [e1, e2, e3])
    }

    fn encoded(ids: impl IntoIterator<Item = Id>) -> BTreeSet<RawInline> {
        ids.into_iter().map(|id| GenId::encode(id).raw).collect()
    }

    fn proposed<'a>(constraint: &impl Constraint<'a>, variable: VariableId) -> BTreeSet<RawInline> {
        let mut proposals = ProposalBuffer::new();
        constraint.propose(variable, &Frontier::default(), &mut proposals);
        let values: Vec<RawInline> = proposals.live_values(0).copied().collect();
        let distinct: BTreeSet<_> = values.iter().copied().collect();
        assert_eq!(values.len(), distinct.len(), "a value proposed twice");
        distinct
    }

    #[test]
    fn domain_in_range_proposes_every_domain_value_in_range_and_nothing_else() {
        let (set, [e1, e2, e3]) = fixture();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let mut ctx = VariableContext::new();
        let v = ctx.next_variable::<GenId>();
        let estimate = |constraint: &SuccinctArchiveDomainRangeConstraint<'_, _>| {
            constraint.estimate(v.index, &Default::default())
        };

        // Every id-shaped value, whatever its axis: entities, attributes,
        // and e2, which occurs only as a value. The raw value is not one.
        let (min, max) = every_id();
        let everything = archive.domain_in_range(v, min, max);
        let ids = encoded([e1, e2, e3, range_link.id(), range_raw.id()]);
        assert_eq!(proposed(&everything, v.index), ids);
        assert_eq!(estimate(&everything), Some(5));

        // A prefix range: 2x... holds only e2.
        let (mut low, mut high) = ([0; 16], [0xff; 16]);
        low[0] = 0x20;
        high[0] = 0x2f;
        let prefix = archive.domain_in_range(v, bound(low), bound(high));
        assert_eq!(proposed(&prefix, v.index), encoded([e2]));
        assert_eq!(estimate(&prefix), Some(1));

        // Both ends are inclusive.
        let exact = archive.domain_in_range(v, GenId::encode(e1), GenId::encode(e3));
        assert_eq!(proposed(&exact, v.index), encoded([e1, e2, e3]));
        let single = archive.domain_in_range(v, GenId::encode(e2), GenId::encode(e2));
        assert_eq!(proposed(&single, v.index), encoded([e2]));

        // A range between domain values, and an inverted one, propose
        // nothing.
        let (mut gap_low, mut gap_high) = ([0; 16], [0xff; 16]);
        gap_low[0] = 0x21;
        gap_high[0] = 0x2f;
        for (min, max) in [(gap_low, gap_high), ([0xff; 16], [0; 16])] {
            let empty = archive.domain_in_range(v, bound(min), bound(max));
            assert!(proposed(&empty, v.index).is_empty());
            assert_eq!(estimate(&empty), Some(0));
        }
    }

    #[test]
    fn the_pattern_decides_the_position_of_a_domain_range() {
        let (set, [e1, e2, e3]) = fixture();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let (min, max) = every_id();
        // The range proposes the attributes and e2 as well; entity position
        // keeps exactly the linking entities.
        let entities: BTreeSet<Id> = find!(
            e: Id,
            and!(
                pattern!(&archive, [{ ?e @ range_link: _?v }]),
                archive.domain_in_range(e, min, max),
            )
        )
        .collect();
        assert_eq!(entities, BTreeSet::from([e1, e3]));
        // Value position keeps the linked ones.
        let values: BTreeSet<Id> = find!(
            v: Id,
            and!(
                pattern!(&archive, [{ _?e @ range_link: ?v }]),
                archive.domain_in_range(v, min, max),
            )
        )
        .collect();
        assert_eq!(values, BTreeSet::from([e1, e2]));
    }

    #[test]
    fn the_union_proposes_a_value_several_shards_hold_once() {
        let (set, [e1, e2, e3]) = fixture();
        // Every fact on the left, all but the first again on the right.
        let mut left = TribleSet::new();
        let mut right = TribleSet::new();
        for (index, trible) in set.iter().enumerate() {
            left.insert(trible);
            if index != 0 {
                right.insert(trible);
            }
        }
        let union = UnionArchive::new(
            [&left, &right]
                .into_iter()
                .map(SuccinctArchive::<OrderedUniverse>::from)
                .collect::<Vec<_>>(),
        );
        let mut ctx = VariableContext::new();
        let v = ctx.next_variable::<GenId>();
        let (min, max) = every_id();
        let all = union.domain_in_range(v, min, max);
        assert_eq!(
            proposed(&all, v.index),
            encoded([e1, e2, e3, range_link.id(), range_raw.id()])
        );
        let entities: BTreeSet<Id> = find!(
            e: Id,
            and!(
                pattern!(&union, [{ ?e @ range_link: _?v }]),
                union.domain_in_range(e, min, max),
            )
        )
        .collect();
        assert_eq!(entities, BTreeSet::from([e1, e3]));
    }

    #[cfg(feature = "proptest")]
    mod property_tests {
        use proptest::collection::vec;
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Joined with an entity-position pattern, a prefix-shaped
            /// domain range finds exactly what `TribleSet::entity_in_range`
            /// finds, over one archive and over the same facts split
            /// across two shards. Half the values are ids, so the range
            /// also meets ids in value position.
            #[test]
            fn domain_range_entities_agree_with_the_tribleset(
                facts in vec((1u8..=255, any::<u8>(), any::<bool>(), any::<bool>()), 1..48),
                low in any::<u8>(),
                high in any::<u8>(),
            ) {
                let mut set = TribleSet::new();
                let mut left = TribleSet::new();
                let mut right = TribleSet::new();
                for (entity, value, linked, side) in facts {
                    let mut raw = [entity; 16];
                    raw[1] = value;
                    let fact = if linked {
                        Trible::force(&id(raw), &range_link.id(), &GenId::encode(id([value | 1; 16])))
                    } else {
                        Trible::force(
                            &id(raw),
                            &range_raw.id(),
                            &Inline::<UnknownInline>::new([value; 32]),
                        )
                    };
                    set.insert(&fact);
                    if side {
                        left.insert(&fact);
                    } else {
                        right.insert(&fact);
                    }
                }
                let (mut min, mut max) = ([0u8; 16], [0xffu8; 16]);
                min[0] = low.min(high);
                max[0] = low.max(high);
                // The TribleSet takes ids; nil is not one, and no entity is nil.
                let mut lowest = min;
                lowest[15] = lowest[15].max(1);
                let (lo, hi) = (id(lowest), id(max));

                let expected: BTreeSet<Id> = find!(
                    e: Id,
                    and!(
                        pattern!(&set, [{ ?e @ range_link: _?v }]),
                        set.entity_in_range(e, lo, hi),
                    )
                )
                .collect();
                let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
                let single: BTreeSet<Id> = find!(
                    e: Id,
                    and!(
                        pattern!(&archive, [{ ?e @ range_link: _?v }]),
                        archive.domain_in_range(e, bound(min), bound(max)),
                    )
                )
                .collect();
                prop_assert_eq!(&single, &expected);

                if left.is_empty() || right.is_empty() {
                    return Ok(());
                }
                let shards: Vec<SuccinctArchive<OrderedUniverse>> =
                    [&left, &right].into_iter().map(Into::into).collect();
                let union = UnionArchive::new(shards);
                let split: BTreeSet<Id> = find!(
                    e: Id,
                    and!(
                        pattern!(&union, [{ ?e @ range_link: _?v }]),
                        union.domain_in_range(e, bound(min), bound(max)),
                    )
                )
                .collect();
                prop_assert_eq!(split, expected);
            }
        }
    }
}
