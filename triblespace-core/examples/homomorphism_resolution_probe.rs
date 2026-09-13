use std::collections::BTreeSet;
use std::convert::Infallible;
use std::hint::black_box;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use triblespace_core::blob::Blob;
use triblespace_core::collection::{
    discover_collection_records, empty_metadata_handle, mapping_algorithm,
    resolve_collection_semantics, AdmissionPolicy, CollectionClaimValidation, CollectionCommit,
    CollectionData, CollectionDerive, CollectionHandle, CollectionMapping, CollectionMerge,
    CollectionOperationError, CollectionPolicy, CollectionRecord, CollectionStore,
    CollectionStoreExt, CollectionValidationRequest, KIND_COLLECTION_MAPPING,
};
use triblespace_core::id::Id;
use triblespace_core::inline::Inline;
use triblespace_core::prelude::blobencodings::SimpleArchive;
use triblespace_core::repo::{memoryrepo::MemoryRepo, BlobStoreGet, BlobStoreMeta, SnapshotSource};
use triblespace_core::trible::Fragment;

#[derive(Clone, Copy, Debug)]
enum Shape {
    Chain,
    Balanced,
}

#[derive(Clone, Copy, Debug)]
enum Mapping {
    None,
    Endpoints,
    Leaves,
    All,
}

#[derive(Clone, Copy)]
struct ProbeMapping;

impl CollectionMapping for ProbeMapping {
    type Source = SimpleArchive;
    type Target = SimpleArchive;

    fn fragment(&self) -> Fragment {
        triblespace_core::prelude::entity! {
            triblespace_core::metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm: id(6),
        }
    }

    fn bind(_source: &Fragment, _target: &Fragment) -> Result<Self, CollectionOperationError> {
        Ok(Self)
    }

    fn map<R>(
        &self,
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<SimpleArchive>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Ok(source.clone())
    }
}

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn data(domain: &[u8], index: u64, extra: &[u8]) -> CollectionData {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&index.to_le_bytes());
    hasher.update(extra);
    Inline::new(*hasher.finalize().as_bytes())
}

fn mapped(input: CollectionData) -> CollectionData {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mapped-target-v1");
    hasher.update(&input.raw);
    Inline::new(*hasher.finalize().as_bytes())
}

fn build(
    leaves: usize,
    shape: Shape,
    mapping: Mapping,
) -> (
    triblespace_core::collection::DiscoveredCollectionRecords,
    BTreeSet<CollectionCommit>,
    CollectionHandle,
    usize,
    usize,
) {
    assert!(leaves >= 2);
    if matches!(shape, Shape::Balanced) {
        assert!(leaves.is_power_of_two());
    }

    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let authority = signing_key.verifying_key();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("source", policy.clone()).unwrap();
    let target = store.derive_with(source, ProbeMapping, policy).unwrap();
    let source_collection = source.handle();
    let target_collection = target.handle();
    let leaf_data: Vec<_> = (0..leaves)
        .map(|i| data(b"source-leaf-v1", i as u64, &[]))
        .collect();
    let commits: Vec<_> = leaf_data
        .iter()
        .map(|element| {
            CollectionCommit::sign(
                &signing_key,
                source_collection,
                *element,
                empty_metadata_handle(),
            )
        })
        .collect();

    let mut all_elements = leaf_data.clone();
    let mut merges = Vec::with_capacity(leaves - 1);
    let root = match shape {
        Shape::Chain => {
            let mut current = leaf_data[0];
            for (step, next) in leaf_data.iter().copied().enumerate().skip(1) {
                let result = data(
                    b"source-chain-node-v1",
                    step as u64,
                    &[leaves.trailing_zeros() as u8],
                );
                merges.push(CollectionMerge::sign(
                    &signing_key,
                    source_collection,
                    current,
                    next,
                    result,
                ));
                all_elements.push(result);
                current = result;
            }
            current
        }
        Shape::Balanced => {
            let mut level = leaf_data.clone();
            let mut node = 0_u64;
            while level.len() > 1 {
                let mut next_level = Vec::with_capacity(level.len() / 2);
                for pair in level.chunks_exact(2) {
                    let result = data(
                        b"source-balanced-node-v1",
                        node,
                        &[leaves.trailing_zeros() as u8],
                    );
                    node += 1;
                    merges.push(CollectionMerge::sign(
                        &signing_key,
                        source_collection,
                        pair[0],
                        pair[1],
                        result,
                    ));
                    all_elements.push(result);
                    next_level.push(result);
                }
                level = next_level;
            }
            level[0]
        }
    };

    let mapped_inputs: Vec<_> = match mapping {
        Mapping::None => Vec::new(),
        Mapping::Endpoints => vec![leaf_data[0], root],
        Mapping::Leaves => leaf_data.clone(),
        Mapping::All => all_elements.clone(),
    };
    let derives: Vec<_> = mapped_inputs
        .iter()
        .map(|input| {
            CollectionDerive::sign(&signing_key, target_collection, *input, mapped(*input))
        })
        .collect();

    for record in &commits {
        CollectionStore::insert(&mut store, CollectionRecord::Commit(*record)).unwrap();
    }
    for record in &merges {
        CollectionStore::insert(&mut store, CollectionRecord::Merge(*record)).unwrap();
    }
    for record in &derives {
        CollectionStore::insert(&mut store, CollectionRecord::Derive(*record)).unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    let records = discover_collection_records(&snapshot).unwrap();
    let authorized = commits.iter().copied().collect();
    (
        records,
        authorized,
        target_collection,
        all_elements.len(),
        derives.len(),
    )
}

fn accepted(
    _: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<()>, Infallible> {
    Ok(CollectionClaimValidation::Accepted)
}

fn parse_shape(value: &str) -> Shape {
    match value {
        "chain" => Shape::Chain,
        "balanced" => Shape::Balanced,
        _ => panic!("shape must be chain or balanced"),
    }
}

fn parse_mapping(value: &str) -> Mapping {
    match value {
        "none" => Mapping::None,
        "endpoints" => Mapping::Endpoints,
        "leaves" => Mapping::Leaves,
        "all" => Mapping::All,
        _ => panic!("mapping must be none, endpoints, leaves, or all"),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let shape = parse_shape(args.get(1).map(String::as_str).unwrap_or("balanced"));
    let mapping = parse_mapping(args.get(2).map(String::as_str).unwrap_or("all"));
    let leaves: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(64);
    let min_millis: u64 = args.get(4).map(|s| s.parse().unwrap()).unwrap_or(500);
    let (records, authorized, target, members, maps) = build(leaves, shape, mapping);

    let warm = resolve_collection_semantics(
        &records,
        &std::collections::BTreeMap::new(),
        &authorized,
        accepted,
    )
    .unwrap();
    let target_frontier = warm.semantics().frontier(target).map_or(0, BTreeSet::len);
    black_box(warm);

    let deadline = Duration::from_millis(min_millis);
    let started = Instant::now();
    let mut iterations = 0_u64;
    while iterations == 0 || started.elapsed() < deadline {
        let result = resolve_collection_semantics(
            &records,
            &std::collections::BTreeMap::new(),
            &authorized,
            accepted,
        )
        .unwrap();
        black_box(result);
        iterations += 1;
    }
    let elapsed = started.elapsed();
    println!(
        "shape={shape:?},mapping={mapping:?},leaves={leaves},members={members},maps={maps},frontier={target_frontier},iterations={iterations},elapsed_ns={},ns_per={:.1}",
        elapsed.as_nanos(),
        elapsed.as_nanos() as f64 / iterations as f64,
    );
}
