use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;
use triblespace::core::metadata;
use triblespace::prelude::*;

// Fixed-size inline values, so the bench measures intrinsic-id construction
// rather than blob hashing.
mod bench_attr {
    use triblespace::prelude::inlineencodings::U256BE;
    use triblespace::prelude::*;

    attributes! {
        pub field_01: U256BE;
        pub field_02: U256BE;
        pub field_03: U256BE;
        pub field_04: U256BE;
        pub field_05: U256BE;
        pub field_06: U256BE;
        pub field_07: U256BE;
        pub field_08: U256BE;
        pub field_09: U256BE;
        pub field_10: U256BE;
        pub field_11: U256BE;
        pub field_12: U256BE;
        pub field_13: U256BE;
        pub field_14: U256BE;
        pub field_15: U256BE;
        pub field_16: U256BE;
        pub repeated: U256BE;
    }
}

fn required_entity(arity: usize) -> Fragment {
    match arity {
        1 => entity! { bench_attr::field_01: 1u64 },
        3 => entity! {
            bench_attr::field_01: 1u64,
            bench_attr::field_02: 2u64,
            bench_attr::field_03: 3u64,
        },
        5 => entity! {
            bench_attr::field_01: 1u64,
            bench_attr::field_02: 2u64,
            bench_attr::field_03: 3u64,
            bench_attr::field_04: 4u64,
            bench_attr::field_05: 5u64,
        },
        8 => entity! {
            bench_attr::field_01: 1u64,
            bench_attr::field_02: 2u64,
            bench_attr::field_03: 3u64,
            bench_attr::field_04: 4u64,
            bench_attr::field_05: 5u64,
            bench_attr::field_06: 6u64,
            bench_attr::field_07: 7u64,
            bench_attr::field_08: 8u64,
        },
        16 => entity! {
            bench_attr::field_01: 1u64,
            bench_attr::field_02: 2u64,
            bench_attr::field_03: 3u64,
            bench_attr::field_04: 4u64,
            bench_attr::field_05: 5u64,
            bench_attr::field_06: 6u64,
            bench_attr::field_07: 7u64,
            bench_attr::field_08: 8u64,
            bench_attr::field_09: 9u64,
            bench_attr::field_10: 10u64,
            bench_attr::field_11: 11u64,
            bench_attr::field_12: 12u64,
            bench_attr::field_13: 13u64,
            bench_attr::field_14: 14u64,
            bench_attr::field_15: 15u64,
            bench_attr::field_16: 16u64,
        },
        _ => unreachable!("unsupported required arity"),
    }
}

fn repeated_values(arity: usize, half_duplicates: bool) -> Vec<u64> {
    (0..arity)
        .map(|i| {
            let value = if half_duplicates { i / 2 } else { i };
            value as u64
        })
        .collect()
}

fn repeated_entity(values: &[u64]) -> Fragment {
    entity! {
        bench_attr::repeated*: values.iter().copied(),
    }
}

fn bench_construction(c: &mut Criterion) {
    let mut required = c.benchmark_group("entity_intrinsic/construct_required");
    for arity in [1usize, 3, 5, 8, 16] {
        required.bench_with_input(BenchmarkId::from_parameter(arity), &arity, |b, &arity| {
            b.iter(|| black_box(required_entity(arity)));
        });
    }
    required.finish();

    let mut repeated = c.benchmark_group("entity_intrinsic/construct_repeated");
    for arity in [1usize, 2, 3, 5, 8, 16, 32, 128] {
        for half_duplicates in [false, true] {
            let values = repeated_values(arity, half_duplicates);
            let case = if half_duplicates {
                "half_dup"
            } else {
                "unique"
            };
            repeated.bench_with_input(BenchmarkId::new(case, arity), &values, |b, values| {
                b.iter(|| black_box(repeated_entity(black_box(values))));
            });
        }
    }
    repeated.finish();
}

fn aggregate_inputs(entity_count: usize) -> Vec<[u64; 3]> {
    (0..entity_count as u64)
        .map(|i| [3 * i, 3 * i + 1, 3 * i + 2])
        .collect()
}

fn aggregate_fragment(inputs: &[[u64; 3]]) -> Fragment {
    let mut aggregate = Fragment::empty();
    for values in inputs {
        aggregate += entity! {
            bench_attr::field_01: values[0],
            bench_attr::field_02: values[1],
            bench_attr::field_03: values[2],
        };
    }
    aggregate
}

fn aggregate_set(inputs: &[[u64; 3]]) -> TribleSet {
    let mut aggregate = TribleSet::new();
    for values in inputs {
        aggregate += entity! {
            bench_attr::field_01: values[0],
            bench_attr::field_02: values[1],
            bench_attr::field_03: values[2],
        };
    }
    aggregate
}

fn bench_aggregation(c: &mut Criterion) {
    const ENTITY_COUNT: usize = 512;
    let inputs = aggregate_inputs(ENTITY_COUNT);
    let mut group = c.benchmark_group("entity_intrinsic/aggregate_512x3");
    group.sample_size(20);

    group.bench_function("fragment", |b| {
        b.iter_batched(
            || (),
            |_| black_box(aggregate_fragment(black_box(&inputs))),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("tribleset", |b| {
        b.iter_batched(
            || (),
            |_| black_box(aggregate_set(black_box(&inputs))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn derived_attribute_warmup() {
    let _ = bench_attr::field_01.id();
    let _ = bench_attr::field_02.id();
    let _ = bench_attr::field_03.id();
    let _ = bench_attr::field_04.id();
    let _ = bench_attr::field_05.id();
    let _ = bench_attr::field_06.id();
    let _ = bench_attr::field_07.id();
    let _ = bench_attr::field_08.id();
    let _ = bench_attr::field_09.id();
    let _ = bench_attr::field_10.id();
    let _ = bench_attr::field_11.id();
    let _ = bench_attr::field_12.id();
    let _ = bench_attr::field_13.id();
    let _ = bench_attr::field_14.id();
    let _ = bench_attr::field_15.id();
    let _ = bench_attr::field_16.id();
    let _ = bench_attr::repeated.id();
    let _ = metadata::tag.id();
}

fn benches(c: &mut Criterion) {
    derived_attribute_warmup();
    bench_construction(c);
    bench_aggregation(c);
}

criterion_group!(entity_benches, benches);
criterion_main!(entity_benches);
