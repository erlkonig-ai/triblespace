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

/// The root commits a view stands for, following each root foundation up
/// the view's descriptor chain through the leaves of every hop. Lattice v2
/// supports are collection-local, so this is the only way a test can still
/// say "this view stands for these commits".
fn stood_for<R, E>(
    view: &triblespace_core::collection::CollectionSnapshot<R, E>,
) -> triblespace_core::collection::Support
where
    R: triblespace_core::repo::StoreRead,
    E: triblespace_core::collection::CollectionEncoding,
{
    use triblespace_core::collection::{descriptor, Collection, SourceLocator};
    use triblespace_core::inline::encodings::hash::Handle;
    let snapshot = view.snapshot();
    let mut chain = vec![view.cover().collection().handle()];
    loop {
        let facts: triblespace_core::trible::TribleSet =
            snapshot.get(*chain.last().unwrap()).unwrap();
        match descriptor::source(&facts).unwrap() {
            Some(source) => chain.push(source),
            None => break,
        }
    }
    let root: Collection<triblespace_core::blob::encodings::simplearchive::SimpleArchive> =
        Collection::open(snapshot, *chain.last().unwrap()).unwrap();
    let scope: std::collections::BTreeSet<_> = chain.iter().copied().collect();
    let coverage = snapshot.coverage(&scope).unwrap();
    let top: std::collections::BTreeSet<[u8; 32]> = view
        .support()
        .unwrap()
        .members()
        .map(|member| member.raw)
        .collect();
    let (foundations, _) = coverage.frontier_support(root.handle());
    root.cover(
        foundations
            .iter_ordered()
            .filter(|raw| {
                let mut images = std::collections::BTreeSet::from([**raw]);
                for hop in chain.iter().rev().skip(1) {
                    images = images
                        .iter()
                        .flat_map(|image| coverage.leaf_outputs(*hop, SourceLocator::of(*image)))
                        .map(|output| output.raw)
                        .collect();
                }
                images.iter().any(|image| top.contains(image))
            })
            .map(|raw| Handle::from_hash(triblespace_core::inline::Inline::new(*raw)))
            .collect::<Vec<_>>(),
    )
}

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
    let snapshot = block_on(store.maintain(target, &signing_key)).unwrap();
    let observed = snapshot.collection(target).unwrap();
    assert_eq!(stood_for(&observed), support);
    let index: Arc<PathIndex> = observed.view().unwrap();
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
