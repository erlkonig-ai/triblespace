use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::ops::Range;
use std::sync::Arc;

use crate::id::Id;
use crate::inline::encodings::genid::GenId;
use crate::inline::{InlineEncoding, RawInline};
use crate::query::unionconstraint::UnionConstraint;
use crate::query::{
    Binding, Candidates, Constraint, Frontier, ProposalBuffer, Term, TriblePattern, VariableId,
    VariableSet,
};
use crate::trible::Trible;

use super::{
    SuccinctArchive, SuccinctArchiveConstraint, SuccinctArchiveDomainRangeConstraint, Universe,
};

/// A [`TriblePattern`] view that unions several Succinct archive shards.
///
/// Owns its shard list (`Arc<[SuccinctArchive]>` — the archives underneath
/// are `Bytes`/`Arc`-backed views, so cloning shards in is a handful of
/// refcount bumps, never a data copy). Ownership makes the union `'static`
/// wherever its universe is, so it can flow into type-erased consumers
/// without borrowed-slice gymnastics.
#[derive(Clone)]
pub struct UnionArchive<U> {
    segments: Arc<[SuccinctArchive<U>]>,
}

impl<U> UnionArchive<U> {
    /// Wrap attached physical shards.
    ///
    /// # Panics
    ///
    /// Panics when `segments` is empty. A physical union requires at least
    /// one shard; use a different constraint to represent an empty relation.
    pub fn new(segments: impl Into<Arc<[SuccinctArchive<U>]>>) -> Self {
        let segments = segments.into();
        assert!(
            !segments.is_empty(),
            "UnionArchive requires at least one physical shard"
        );
        Self { segments }
    }

    /// Number of physical Succinct shards behind this logical union.
    ///
    /// This is storage provenance, not a logical cardinality: compaction may
    /// change it without changing the relation exposed by [`TriblePattern`].
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Return one logical cover containing this cover plus additional shards.
    ///
    /// Attached archives are cheap `Bytes`-backed clones. The original cover
    /// remains immutable, which makes this useful for validating a staged
    /// delta against one already-frozen snapshot.
    pub fn with_segments(&self, additional: impl IntoIterator<Item = SuccinctArchive<U>>) -> Self
    where
        SuccinctArchive<U>: Clone,
    {
        let mut segments = self.segments.to_vec();
        segments.extend(additional);
        Self::new(segments)
    }

    /// Return the logical union of two immutable physical covers.
    ///
    /// This is a shallow operation: archives retain their shared backing
    /// bytes and only the shard list is copied. Equal or overlapping shards
    /// need not be recognized here because every observation path applies set
    /// semantics across the resulting cover.
    pub fn union(&self, other: &Self) -> Self
    where
        SuccinctArchive<U>: Clone,
    {
        self.with_segments(other.segments.iter().cloned())
    }
}

impl<U> UnionArchive<U>
where
    U: Universe,
{
    /// [`SuccinctArchive::domain_in_range`] over every shard: the domain
    /// values in the inclusive range `[min, max]`, whichever positions they
    /// occur in. A value several shards hold is proposed once.
    pub fn domain_in_range<V: InlineEncoding>(
        &self,
        variable: crate::query::Variable<V>,
        min: crate::inline::Inline<V>,
        max: crate::inline::Inline<V>,
    ) -> UnionConstraint<SuccinctArchiveDomainRangeConstraint<'_, U>> {
        UnionConstraint::new(
            self.segments
                .iter()
                .map(|segment| segment.domain_in_range(variable, min, max))
                .collect(),
        )
    }

    /// Iterate the logical set union in canonical EAV order.
    ///
    /// The k-way merge retains one position per physical shard and removes
    /// facts repeated by overlapping shards. Physical compaction therefore
    /// cannot affect the observed sequence.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = Trible> + 'a {
        UnionArchiveTribles::new(&self.segments)
    }

    /// Iterate one fixed attribute in ascending decoded `(value, entity)`
    /// order across the logical set union.
    ///
    /// The k-way merge keeps one cursor per physical shard and removes facts
    /// repeated by overlapping shards. Local universe codes never cross the
    /// abstraction boundary.
    pub fn iter_attribute_value_entities<'a>(
        &'a self,
        attribute: &Id,
    ) -> impl Iterator<Item = (RawInline, Id)> + 'a {
        UnionArchiveAttributeValueEntities::new(&self.segments, attribute, false)
    }

    /// Iterate one fixed attribute in descending decoded `(value, entity)`
    /// order across the logical set union.
    pub fn iter_attribute_value_entities_rev<'a>(
        &'a self,
        attribute: &Id,
    ) -> impl Iterator<Item = (RawInline, Id)> + 'a {
        UnionArchiveAttributeValueEntities::new(&self.segments, attribute, true)
    }

    /// [`Self::iter_attribute_value_entities`], starting at the first fact
    /// whose raw value is at least `from`.
    ///
    /// Each shard seeks its own start in O(log n), so the facts below `from`
    /// are neither decoded nor merged.
    pub fn iter_attribute_value_entities_from<'a>(
        &'a self,
        attribute: &Id,
        from: &RawInline,
    ) -> impl Iterator<Item = (RawInline, Id)> + 'a {
        UnionArchiveAttributeValueEntities::with_ranges(
            &self.segments,
            self.segments
                .iter()
                .map(|segment| segment.attribute_value_range_from(attribute, from))
                .collect(),
            false,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TribleHeapItem {
    trible: Trible,
    segment: usize,
}

impl Ord for TribleHeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.trible
            .cmp(&other.trible)
            .then_with(|| self.segment.cmp(&other.segment))
            .reverse()
    }
}

impl PartialOrd for TribleHeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Ordered, deduplicating cursor over every fact in a physical cover.
struct UnionArchiveTribles<'a, U> {
    segments: &'a [SuccinctArchive<U>],
    positions: Vec<usize>,
    heap: BinaryHeap<TribleHeapItem>,
    last: Option<Trible>,
}

impl<'a, U> UnionArchiveTribles<'a, U>
where
    U: Universe,
{
    fn new(segments: &'a [SuccinctArchive<U>]) -> Self {
        let mut heap = BinaryHeap::new();
        let positions = vec![0; segments.len()];
        for (segment, archive) in segments.iter().enumerate() {
            if !archive.eav_c.is_empty() {
                heap.push(TribleHeapItem {
                    trible: archive.decode_eav_trible(0),
                    segment,
                });
            }
        }
        Self {
            segments,
            positions,
            heap,
            last: None,
        }
    }

    fn advance(&mut self, segment: usize) {
        self.positions[segment] += 1;
        let position = self.positions[segment];
        let archive = &self.segments[segment];
        if position < archive.eav_c.len() {
            self.heap.push(TribleHeapItem {
                trible: archive.decode_eav_trible(position),
                segment,
            });
        }
    }
}

impl<U> Iterator for UnionArchiveTribles<'_, U>
where
    U: Universe,
{
    type Item = Trible;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item) = self.heap.pop() {
            self.advance(item.segment);
            if self.last == Some(item.trible) {
                continue;
            }
            self.last = Some(item.trible);
            return Some(item.trible);
        }
        None
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HeapItem {
    pair: (RawInline, Id),
    segment: usize,
    descending: bool,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        debug_assert_eq!(self.descending, other.descending);
        let order = self
            .pair
            .cmp(&other.pair)
            .then_with(|| self.segment.cmp(&other.segment));
        if self.descending {
            order
        } else {
            order.reverse()
        }
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Ordered, deduplicating cursor over one fixed attribute in a physical
/// [`UnionArchive`] cover.
struct UnionArchiveAttributeValueEntities<'a, U> {
    segments: &'a [SuccinctArchive<U>],
    ranges: Vec<Range<usize>>,
    heap: BinaryHeap<HeapItem>,
    descending: bool,
    last: Option<(RawInline, Id)>,
}

impl<'a, U> UnionArchiveAttributeValueEntities<'a, U>
where
    U: Universe,
{
    fn new(segments: &'a [SuccinctArchive<U>], attribute: &Id, descending: bool) -> Self {
        let ranges = segments
            .iter()
            .map(|segment| {
                super::base_range(
                    &segment.domain,
                    &segment.a_a,
                    &super::id_into_value(attribute),
                )
            })
            .collect();
        Self::with_ranges(segments, ranges, descending)
    }

    /// One cursor per shard over its AVE positions in `ranges`.
    fn with_ranges(
        segments: &'a [SuccinctArchive<U>],
        mut ranges: Vec<Range<usize>>,
        descending: bool,
    ) -> Self {
        let mut heap = BinaryHeap::new();
        for (index, (segment, range)) in segments.iter().zip(&mut ranges).enumerate() {
            let position = if descending {
                if range.start == range.end {
                    continue;
                }
                range.end -= 1;
                range.end
            } else {
                let Some(position) = range.next() else {
                    continue;
                };
                position
            };
            heap.push(HeapItem {
                pair: segment.decode_ave_value_entity(position),
                segment: index,
                descending,
            });
        }
        Self {
            segments,
            ranges,
            heap,
            descending,
            last: None,
        }
    }

    fn advance(&mut self, segment: usize) {
        let range = &mut self.ranges[segment];
        let position = if self.descending {
            if range.start == range.end {
                return;
            }
            range.end -= 1;
            range.end
        } else {
            let Some(position) = range.next() else {
                return;
            };
            position
        };
        self.heap.push(HeapItem {
            pair: self.segments[segment].decode_ave_value_entity(position),
            segment,
            descending: self.descending,
        });
    }
}

impl<U> Iterator for UnionArchiveAttributeValueEntities<'_, U>
where
    U: Universe,
{
    type Item = (RawInline, Id);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(item) = self.heap.pop() {
            self.advance(item.segment);
            if self.last == Some(item.pair) {
                continue;
            }
            self.last = Some(item.pair);
            return Some(item.pair);
        }
        None
    }
}

/// Atomic normalized union over one finite set of Succinct archive shards.
///
/// A thin wrapper over [`UnionConstraint`]: every shard constraint carries
/// the pattern's [`Term`]s natively (constant positions included), so all
/// shards declare the same variable set by construction and the union's
/// equal-variable-set requirement holds trivially. The wrapper exists so
/// the shard union stays structurally opaque — one logical source, not a
/// user-visible `or!` that formula rewrites could split back into
/// independently materialized arms.
pub struct UnionArchiveConstraint<'a, U>
where
    U: Universe,
{
    union: UnionConstraint<SuccinctArchiveConstraint<'a, U>>,
}

impl<'a, U> UnionArchiveConstraint<'a, U>
where
    U: Universe,
{
    fn new(constraints: Vec<SuccinctArchiveConstraint<'a, U>>) -> Self {
        Self {
            union: UnionConstraint::new(constraints),
        }
    }
}

impl<'a, U> Constraint<'a> for UnionArchiveConstraint<'a, U>
where
    U: Universe,
{
    fn variables(&self) -> VariableSet {
        self.union.variables()
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.union.estimate(variable, binding)
    }

    fn propose(
        &self,
        variable: VariableId,
        frontier: &Frontier<'_>,
        proposals: &mut ProposalBuffer,
    ) {
        self.union.propose(variable, frontier, proposals)
    }

    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        self.union.confirm(variable, frontier, cands)
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        self.union.satisfied(binding)
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        self.union.influence(variable)
    }
}

impl<U> TriblePattern for UnionArchive<U>
where
    U: Universe + Send + Sync,
{
    type PatternConstraint<'p>
        = UnionArchiveConstraint<'p, U>
    where
        Self: 'p;

    fn pattern<'p, V: InlineEncoding>(
        &'p self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'p> {
        let e: Term<GenId> = e.into();
        let a: Term<GenId> = a.into();
        let v: Term<V> = v.into();
        UnionArchiveConstraint::new(
            self.segments
                .iter()
                .map(|segment| segment.pattern(e, a, v))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::examples::literature;
    use crate::inline::encodings::hash::Handle;
    use crate::prelude::*;

    use super::*;
    use crate::blob::encodings::succinctarchive::OrderedUniverse;

    #[test]
    fn query_union_deduplicates_overlap_across_shards() {
        let ada = ufoid();
        let grace = ufoid();

        let mut left = TribleSet::new();
        left += entity! { &ada @ literature::firstname: "Ada" };

        let mut right = TribleSet::new();
        right += entity! { &ada @ literature::firstname: "Ada" };
        right += entity! { &grace @ literature::firstname: "Grace" };

        let segments: Vec<SuccinctArchive<OrderedUniverse>> =
            [&left, &right].into_iter().map(Into::into).collect();
        let union = UnionArchive::new(segments);

        let mut names: Vec<[u8; 32]> = find!(
            name: Inline<_>,
            pattern!(&union, [{ _?person @ literature::firstname: ?name }])
        )
        .map(|name| name.raw)
        .collect();
        names.sort();
        let ada: Inline<Handle<UTF8String>> = "Ada".to_inline();
        let grace: Inline<Handle<UTF8String>> = "Grace".to_inline();
        let mut expected = [ada.raw, grace.raw];
        expected.sort();

        assert_eq!(union.segment_count(), 2);
        assert_eq!(names, expected);
    }

    #[test]
    fn ordered_attribute_iteration_merges_and_deduplicates_shards() {
        let attribute = ufoid();
        let other_attribute = ufoid();
        let e1 = ufoid();
        let e2 = ufoid();
        let e3 = ufoid();
        let low = Inline::<UnknownInline>::new([0x20; 32]);
        let high = Inline::<UnknownInline>::new([0x40; 32]);

        let mut left = TribleSet::new();
        left.insert(&Trible::force(&e2, &attribute, &low));
        left.insert(&Trible::force(&e3, &attribute, &high));

        let mut right = TribleSet::new();
        right.insert(&Trible::force(&e1, &attribute, &low));
        right.insert(&Trible::force(&e2, &attribute, &low));
        right.insert(&Trible::force(&e3, &other_attribute, &high));

        let union = UnionArchive::new(
            [&left, &right]
                .into_iter()
                .map(SuccinctArchive::<OrderedUniverse>::from)
                .collect::<Vec<_>>(),
        );
        let mut expected = vec![(low.raw, *e1), (low.raw, *e2), (high.raw, *e3)];
        expected.sort_unstable();

        assert_eq!(
            union
                .iter_attribute_value_entities(&attribute)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            union
                .iter_attribute_value_entities_rev(&attribute)
                .collect::<Vec<_>>(),
            expected.iter().copied().rev().collect::<Vec<_>>()
        );
    }

    #[test]
    fn seeked_attribute_iteration_agrees_with_the_filtered_unseeked_union() {
        let attribute = ufoid();
        let other_attribute = ufoid();
        let entities: Vec<_> = (0..12).map(|_| ufoid()).collect();
        let value = |first: u8| Inline::<UnknownInline>::new([first; 32]);

        // Three overlapping shards, each with its own local domain, and
        // another attribute's values interleaved with ours.
        let mut shards = vec![TribleSet::new(), TribleSet::new(), TribleSet::new()];
        for (index, entity) in entities.iter().enumerate() {
            let fact = Trible::force(entity, &attribute, &value(0x10 + 0x08 * (index as u8 % 7)));
            shards[index % 3].insert(&fact);
            if index % 4 == 0 {
                shards[(index + 1) % 3].insert(&fact);
            }
            shards[(index + 2) % 3].insert(&Trible::force(
                entity,
                &other_attribute,
                &value(0x14 + 0x08 * (index as u8 % 5)),
            ));
        }
        let union = UnionArchive::new(
            shards
                .iter()
                .map(SuccinctArchive::<OrderedUniverse>::from)
                .collect::<Vec<_>>(),
        );

        for bound in 0u8..=0x60 {
            let from = [bound; 32];
            let expected: Vec<_> = union
                .iter_attribute_value_entities(&attribute)
                .filter(|(value, _)| *value >= from)
                .collect();
            let seeked: Vec<_> = union
                .iter_attribute_value_entities_from(&attribute, &from)
                .collect();
            assert_eq!(seeked, expected, "bound {bound:#x}");
            if let Some(first) = seeked.first() {
                assert!(first.0 >= from);
                assert!(union
                    .iter_attribute_value_entities(&attribute)
                    .take_while(|pair| pair != first)
                    .all(|(value, _)| value < from));
            }
        }
    }

    #[test]
    fn ordered_iteration_is_cover_independent_and_deduplicates_overlap() {
        let ada = ufoid();
        let grace = ufoid();

        let mut left = TribleSet::new();
        left += entity! { &ada @ literature::firstname: "Ada" };

        let mut right = TribleSet::new();
        right += entity! { &ada @ literature::firstname: "Ada" };
        right += entity! { &grace @ literature::firstname: "Grace" };

        let mut logical = left.clone();
        logical += right.clone();
        let expected = logical.iter_ordered().copied().collect::<Vec<_>>();
        let union = UnionArchive::new(
            [&right, &left]
                .into_iter()
                .map(SuccinctArchive::<OrderedUniverse>::from)
                .collect::<Vec<_>>(),
        );

        assert_eq!(union.iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn immutable_cover_extension_keeps_the_original_snapshot() {
        let ada = ufoid();
        let grace = ufoid();
        let mut first = TribleSet::new();
        first += entity! { &ada @ literature::firstname: "Ada" };
        let mut second = TribleSet::new();
        second += entity! { &grace @ literature::firstname: "Grace" };

        let original = UnionArchive::new(vec![SuccinctArchive::<OrderedUniverse>::from(&first)]);
        let extended = original.with_segments([SuccinctArchive::from(&second)]);

        assert_eq!(original.segment_count(), 1);
        assert_eq!(extended.segment_count(), 2);
        assert_eq!(original.iter().count(), first.len());
        assert_eq!(extended.iter().count(), first.len() + second.len());
    }

    #[test]
    fn immutable_cover_union_is_logically_idempotent() {
        let ada = ufoid();
        let grace = ufoid();
        let mut first = TribleSet::new();
        first += entity! { &ada @ literature::firstname: "Ada" };
        let mut second = first.clone();
        second += entity! { &grace @ literature::firstname: "Grace" };

        let left = UnionArchive::new(vec![SuccinctArchive::<OrderedUniverse>::from(&first)]);
        let right = UnionArchive::new(vec![SuccinctArchive::<OrderedUniverse>::from(&second)]);
        let joined = left.union(&right);

        assert_eq!(left.segment_count(), 1);
        assert_eq!(right.segment_count(), 1);
        assert_eq!(joined.segment_count(), 2);
        assert_eq!(
            joined.iter().collect::<Vec<_>>(),
            second.iter_ordered().copied().collect::<Vec<_>>()
        );
    }

    #[test]
    #[should_panic(expected = "UnionArchive requires at least one physical shard")]
    fn rejects_empty_physical_union() {
        UnionArchive::<OrderedUniverse>::new(Vec::<SuccinctArchive<OrderedUniverse>>::new());
    }
}
