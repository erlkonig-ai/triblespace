//! Transparent unions of heterogeneous trible patterns.
//!
//! A [`TriblePattern`] answers one triple pattern from one fact source. Some
//! readers have two sources for the same facts: a resident derived index
//! (for example a Rank9-accelerated [`UnionArchive`](crate::blob::encodings::succinctarchive::UnionArchive))
//! that a maintenance worker carries on its own cadence, and the few raw
//! [`TribleSet`] payloads that landed since its last carry. The reader wants
//! one pattern over both, so every existing query helper written against a
//! single `impl TriblePattern` keeps working unchanged. [`PatternUnion`]
//! provides that: it lowers each triple pattern to the same-variable union of
//! its arms' constraints, exactly as the [`or!`](crate::or) macro would, but
//! packaged as one logical source so a caller never has to split its query.
//!
//! This is not a catalog and it materialises nothing: each arm is queried in
//! place, and the residual arm is whatever small set of payloads the caller
//! chose through the collection algebra.

use super::unionconstraint::UnionConstraint;
use super::{Constraint, Term, TriblePattern};
use crate::inline::encodings::genid::GenId;
use crate::inline::InlineEncoding;
use crate::trible::TribleSet;

/// One logical fact source made of two pattern arms, queried as a union.
///
/// Both arms lower every triple pattern with the same terms, so the union's
/// equal-variable-set requirement holds by construction.
pub struct PatternUnion<A, B> {
    /// Usually the resident derived index.
    pub left: A,
    /// Usually the residual raw payloads the index does not yet cover.
    pub right: B,
}

impl<A, B> PatternUnion<A, B> {
    /// Query `left` and `right` as one source.
    pub fn new(left: A, right: B) -> Self {
        Self { left, right }
    }
}

impl<A, B> TriblePattern for PatternUnion<A, B>
where
    A: TriblePattern + Send + Sync,
    B: TriblePattern + Send + Sync,
{
    type PatternConstraint<'a>
        = UnionConstraint<Box<dyn Constraint<'a> + Send + Sync + 'a>>
    where
        Self: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        let e: Term<GenId> = e.into();
        let a: Term<GenId> = a.into();
        let v: Term<V> = v.into();
        UnionConstraint::new(vec![
            Box::new(self.left.pattern(e, a, v)) as Box<dyn Constraint<'a> + Send + Sync + 'a>,
            Box::new(self.right.pattern(e, a, v)) as Box<dyn Constraint<'a> + Send + Sync + 'a>,
        ])
    }
}

/// A slice of trible sets is one source: the union of its members. An empty
/// slice is the empty source, lowered as one empty arm so the union stays
/// well formed.
impl TriblePattern for [TribleSet] {
    type PatternConstraint<'a>
        = UnionConstraint<<TribleSet as TriblePattern>::PatternConstraint<'a>>
    where
        Self: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        let e: Term<GenId> = e.into();
        let a: Term<GenId> = a.into();
        let v: Term<V> = v.into();
        let mut arms: Vec<<TribleSet as TriblePattern>::PatternConstraint<'a>> =
            self.iter().map(|set| set.pattern(e, a, v)).collect();
        if arms.is_empty() {
            arms.push(TribleSet::new().pattern(e, a, v));
        }
        UnionConstraint::new(arms)
    }
}

impl TriblePattern for Vec<TribleSet> {
    type PatternConstraint<'a>
        = UnionConstraint<<TribleSet as TriblePattern>::PatternConstraint<'a>>
    where
        Self: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        self.as_slice().pattern(e, a, v)
    }
}

/// An optional arm: `None` is the empty source, lowered as one empty
/// [`TribleSet`] arm so a union containing it stays well formed.
impl<P> TriblePattern for Option<P>
where
    P: TriblePattern + Send + Sync,
{
    type PatternConstraint<'a>
        = UnionConstraint<Box<dyn Constraint<'a> + Send + Sync + 'a>>
    where
        Self: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        let e: Term<GenId> = e.into();
        let a: Term<GenId> = a.into();
        let v: Term<V> = v.into();
        let arm: Box<dyn Constraint<'a> + Send + Sync + 'a> = match self {
            Some(pattern) => Box::new(pattern.pattern(e, a, v)),
            None => Box::new(TribleSet::new().pattern(e, a, v)),
        };
        UnionConstraint::new(vec![arm])
    }
}

/// A reference to a pattern is the pattern.
impl<'r, P> TriblePattern for &'r P
where
    P: TriblePattern + ?Sized,
{
    type PatternConstraint<'a>
        = P::PatternConstraint<'a>
    where
        Self: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<Term<GenId>>,
        a: impl Into<Term<GenId>>,
        v: impl Into<Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        (**self).pattern(e, a, v)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::inlineencodings::ShortString;
    use crate::prelude::*;

    attributes! {
        "9976023ABF9750B68336A123DDAA7787" as label: ShortString;
    }

    #[test]
    fn union_answers_from_either_arm_and_absent_arms_are_harmless() {
        let a = ufoid();
        let b = ufoid();
        let mut left = TribleSet::new();
        left += entity! { &a @ label: "left" };
        let mut right = TribleSet::new();
        right += entity! { &b @ label: "right" };

        let both = PatternUnion::new(&left, vec![right.clone()]);
        let mut labels: Vec<String> =
            find!(l: String, pattern!(&both, [{ label: ?l }])).collect();
        labels.sort();
        assert_eq!(labels, vec!["left".to_owned(), "right".to_owned()]);

        let only_left = PatternUnion::new(&left, Vec::<TribleSet>::new());
        let labels: Vec<String> =
            find!(l: String, pattern!(&only_left, [{ label: ?l }])).collect();
        assert_eq!(labels, vec!["left".to_owned()]);

        let absent: Option<TribleSet> = None;
        let with_absent = PatternUnion::new(&left, PatternUnion::new(absent, vec![right]));
        let mut labels: Vec<String> =
            find!(l: String, pattern!(&with_absent, [{ label: ?l }])).collect();
        labels.sort();
        assert_eq!(labels, vec!["left".to_owned(), "right".to_owned()]);
    }
}
