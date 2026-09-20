use std::collections::HashSet;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
#[cfg(feature = "nvfp4-cuda")]
use mary::nn::nvfp4_cosine::cuda::CudaUpperScanner;
use mary::nn::nvfp4_cosine::CpuF64UpperScanner;

use triblespace_core::and;
use triblespace_core::attribute::Attribute;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::query::ContainsConstraint;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::BlobStorePut;
use triblespace_core::trible::{Fragment, Trible, TribleSet};

use triblespace_search::nvfp4::{NvFp4CosineIndex, NvFp4CosineSet, NvFp4EmbeddingAttribute};
use triblespace_search::schemas::Embedding;

fn direct_policy(authority: &SigningKey) -> CollectionPolicy {
    let root = authority.verifying_key();
    CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root))
}

#[test]
fn simplearchive_mapping_lazy_view_and_exact_queries_compose() {
    let authority = SigningKey::from_bytes(&[91; 32]);
    let policy = direct_policy(&authority);
    let attribute = Attribute::<Handle<Embedding>>::named("nvfp4-test-embedding");
    let mut store = MemoryRepo::default();

    let positive = store.put::<Embedding, _>(vec![1.0f32, 0.0, 0.0]).unwrap();
    let diagonal = store.put::<Embedding, _>(vec![1.0f32, 1.0, 0.0]).unwrap();
    let negative = store.put::<Embedding, _>(vec![-1.0f32, 0.0, 0.0]).unwrap();

    let mut facts = TribleSet::new();
    for (entity, embedding) in [
        (1, positive),
        (2, diagonal),
        (3, negative),
        // Projection has set semantics by exact embedding handle.
        (4, positive),
    ] {
        let entity = Id::new([entity; 16]).unwrap();
        facts.insert(&Trible::force(&entity, &attribute.id(), &embedding));
    }

    let source = store.collection("nvfp4-source", policy.clone()).unwrap();
    let target = store
        .derive::<NvFp4CosineSet<Embedding>>(
            source,
            NvFp4EmbeddingAttribute::new(attribute.id(), 3).unwrap(),
            policy,
        )
        .unwrap();
    store
        .commit(source, &authority, Fragment::from(facts))
        .unwrap();

    let snapshot = block_on(store.maintain(target, &authority)).unwrap();
    let collection = snapshot.collection(target).unwrap();
    let index: NvFp4CosineIndex<Embedding> = collection.view().unwrap();
    let snapshot = collection.snapshot();

    assert_eq!(index.dimension(), 3);
    assert_eq!(index.segment_count(), 1);
    let scanner = CpuF64UpperScanner;
    let top = index
        .top_k(snapshot, &[1.0, 0.0, 0.0], 2, &scanner)
        .unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].embedding, positive);
    assert_eq!(top[0].score, 1.0);
    assert_eq!(top[1].embedding, diagonal);
    assert!(top[1].score > 0.7 && top[1].score < 0.71);

    #[cfg(feature = "nvfp4-cuda")]
    {
        let segments = index.scan_segments();
        let cuda = CudaUpperScanner::new(&segments).unwrap();
        let cuda_top = index.top_k(snapshot, &[1.0, 0.0, 0.0], 2, &cuda).unwrap();
        assert!(
            cuda_top == top,
            "CUDA and proof-oracle exact results differ"
        );
    }

    let above = index
        .above(snapshot, &[1.0, 0.0, 0.0], 0.7, &scanner)
        .unwrap();
    assert_eq!(
        above
            .iter()
            .map(|hit| hit.embedding)
            .collect::<Vec<Inline<Handle<Embedding>>>>(),
        vec![positive, diagonal],
    );

    let direct_support: HashSet<_> = above.iter().map(|hit| hit.embedding).collect();
    let engine_support: HashSet<_> = triblespace_core::find!(
        neighbour: Inline<Handle<Embedding>>,
        index
            .similar_to(snapshot, positive, neighbour, 0.7, &scanner)
            .unwrap()
    )
    .collect();
    assert_eq!(engine_support, direct_support);

    let allowed = HashSet::from([positive, negative]);
    let composed: HashSet<_> = triblespace_core::find!(
        neighbour: Inline<Handle<Embedding>>,
        and!(
            (&allowed).has(neighbour),
            index
                .similar_to(snapshot, positive, neighbour, 0.7, &scanner)
                .unwrap(),
        )
    )
    .collect();
    assert_eq!(composed, HashSet::from([positive]));

    let missing_probe = Inline::<Handle<Embedding>>::new([0xff; 32]);
    let mut variables = triblespace_core::query::VariableContext::new();
    let neighbour = variables.next_variable::<Handle<Embedding>>();
    assert!(index
        .similar_to(snapshot, missing_probe, neighbour, 0.7, &scanner)
        .is_err());
}
