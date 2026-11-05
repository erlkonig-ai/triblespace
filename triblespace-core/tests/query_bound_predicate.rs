use std::cell::Cell;
use std::collections::HashSet;
use triblespace_core::prelude::*;
use triblespace_core::query::Query;

fn values() -> HashSet<Inline<UnknownInline>> {
    (0..40).map(|n| Inline::new([n; 32])).collect()
}

#[test]
fn failure_keeps_only_failed_row_after_false_and_unprojected_prefix() {
    for width in [1, 64, 4096] {
        let values = values();
        let x = Variable::<UnknownInline>::new(0);
        let projected = Cell::new(0);
        let mut query = Query::new(values.has(x), |binding| {
            projected.set(projected.get() + 1);
            // A conversion/projection can decline an accepted row.
            (projected.get() > 3).then(|| *x.extract(binding))
        })
        .with_frontier_width(width);
        let mut consumed = Vec::new();
        let mut failed = None;
        let result = query.try_next_where(|binding| {
            let raw = x.extract(binding).raw;
            if consumed.len() == 11 {
                failed = Some(raw);
                return Err("unavailable");
            }
            consumed.push(raw);
            Ok(consumed.len() <= 3)
        });
        assert_eq!(result, Err("unavailable"));
        assert_eq!(projected.get(), 3);
        assert_eq!(
            query.try_next_where(|_| Err::<bool, _>("still missing")),
            Err("still missing")
        );
        let resumed = query
            .try_next_where(|binding| {
                assert_eq!(Some(x.extract(binding).raw), failed);
                Ok::<_, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(Some(resumed.raw), failed);
        let tail: Vec<_> = query.collect();
        assert_eq!(tail.len(), 28);
        let all: HashSet<_> = consumed
            .into_iter()
            .chain([resumed.raw])
            .chain(tail.into_iter().map(|v| v.raw))
            .collect();
        assert_eq!(
            all.len(),
            40,
            "no rejected or unprojected prefix replay at width {width}"
        );
    }
}

#[test]
fn empty_binding_failure_is_retryable_and_then_exhausts() {
    let mut query = Query::new(
        IntersectionConstraint::<Box<dyn triblespace_core::query::Constraint>>::new(vec![]),
        |_| Some(()),
    );
    assert_eq!(query.try_next_where(|_| Err::<bool, _>(7)), Err(7));
    assert_eq!(query.try_next_where(|_| Ok::<_, ()>(true)), Ok(Some(())));
    assert_eq!(query.next(), None);
}

#[test]
fn ordinary_iteration_preserves_hidden_witness_bags_at_all_widths() {
    for width in [1, 64, 4096] {
        let values = values();
        let x = Variable::<UnknownInline>::new(0);
        let y = Variable::<UnknownInline>::new(1);
        let query = Query::new(and!(values.has(x), values.has(y)), |binding| {
            Some(*x.extract(binding))
        })
        .with_frontier_width(width);
        let rows: Vec<_> = query.collect();
        assert_eq!(rows.len(), 1600);
        for x in &values {
            assert_eq!(rows.iter().filter(|v| *v == x).count(), 40);
        }
    }
}

#[cfg(feature = "parallel")]
#[test]
fn parallel_iteration_preserves_the_ordinary_bag() {
    use rayon::prelude::*;
    let values = values();
    let x = Variable::<UnknownInline>::new(0);
    let y = Variable::<UnknownInline>::new(1);
    let query = Query::new(and!(values.has(x), values.has(y)), |binding| {
        Some(*x.extract(binding))
    });
    let mut sequential: Vec<_> = query.clone().collect();
    let mut parallel: Vec<_> = query.into_par_iter().collect();
    sequential.sort();
    parallel.sort();
    assert_eq!(parallel, sequential);
    assert_eq!(parallel.len(), 1600);
}
