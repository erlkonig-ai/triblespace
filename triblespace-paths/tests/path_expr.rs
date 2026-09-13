use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::id::{ExclusiveId, Id};
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::{Inline, RawInline};
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::query::{Binding, Query, Variable};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::Fragment;
use triblespace_core::trible::TribleSet;
use triblespace_paths::{
    automaton_fingerprint, GraphEdge, PathExpr, PathIndex, PathSummaryBlob, Step,
};

fn vertex(byte: u8) -> RawInline {
    [byte; 32]
}

fn attribute(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn edge(source: u8, label: u8, target: u8) -> GraphEdge {
    GraphEdge {
        source: vertex(source),
        attribute: attribute(label),
        target: vertex(target),
    }
}

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn tagged_edge(source: u8, target: u8) -> TribleSet {
    let source = id(source);
    let target = id(target);
    entity! { ExclusiveId::force_ref(&source) @ metadata::tag: target }.into_facts()
}

#[test]
fn public_expression_api_materializes_compound_paths() {
    let expression = PathExpr::from(Step::Forward(attribute(1)))
        .then(PathExpr::from(Step::Forward(attribute(2))).optional())
        .or(PathExpr::from(Step::Forward(attribute(3))).inverse().plus());
    let index = PathIndex::from_edges(
        expression.compile(),
        [edge(1, 1, 2), edge(2, 2, 3), edge(4, 3, 3), edge(5, 3, 4)],
    )
    .unwrap();

    assert_eq!(
        index.accepted_pairs().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (vertex(1), vertex(2)),
            (vertex(1), vertex(3)),
            (vertex(3), vertex(4)),
            (vertex(3), vertex(5)),
            (vertex(4), vertex(5)),
        ])
    );
}

#[test]
fn canonical_expression_construction_stabilizes_automaton_fingerprints() {
    let first: PathExpr = Step::Forward(attribute(1)).into();
    let second: PathExpr = Step::ForwardExcept(vec![attribute(3), attribute(2)]).into();
    let left = first.clone().or(second.clone()).or(first).compile();
    let right = PathExpr::from(Step::ForwardExcept(vec![
        attribute(2),
        attribute(3),
        attribute(2),
    ]))
    .or(PathExpr::from(Step::Forward(attribute(1))))
    .compile();

    assert_eq!(left, right);
    assert_eq!(automaton_fingerprint(&left), automaton_fingerprint(&right));
}

#[test]
fn compiled_expression_roundtrips_through_native_collection_and_query_constraint() {
    let expression = PathExpr::from(Step::Forward(metadata::tag.id().into())).plus();
    let signing_key = SigningKey::from_bytes(&[17; 32]);
    let authority = signing_key.verifying_key();
    let name = "graph";
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection(name, policy.clone()).unwrap();
    let target = store
        .derive::<PathSummaryBlob>(source, expression.compile(), policy)
        .unwrap();
    let mut graph = tagged_edge(1, 2);
    graph += tagged_edge(2, 3);
    store
        .commit(source, &signing_key, Fragment::from(graph))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let support = source.admitted(&snapshot).unwrap();
    let snapshot = block_on(store.maintain_exact(target, &signing_key, &support)).unwrap();
    let index: Arc<PathIndex> = snapshot
        .collection_exact(target, &support)
        .unwrap()
        .view()
        .unwrap();
    let end = Variable::<UnknownInline>::new(0);
    let start = Inline::<UnknownInline>::new(RawInline::from(id(1)));
    let reachable = Query::new(index.constraint(start, end), |binding: &Binding| {
        binding.get(end.index).copied()
    })
    .collect::<BTreeSet<_>>();

    assert_eq!(
        reachable,
        BTreeSet::from([RawInline::from(id(2)), RawInline::from(id(3))])
    );
}
