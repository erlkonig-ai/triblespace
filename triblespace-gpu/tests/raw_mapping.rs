//! CPU-only execution plumbing plus an explicit, bounded CUDA parity gate.

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchiveBlob, SuccinctRotation, UnionArchive,
    WaveletMatrixFreezeBackend,
};
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionDerivation, CollectionMapping, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, SnapshotSource};
use triblespace_core::trible::{Fragment, Trible, TribleSet};
use triblespace_gpu::BackendSuccinctMapping;

fn facts(start: u32, count: u32) -> TribleSet {
    (start..start + count)
        .map(|ordinal| {
            let mut data = [0u8; 64];
            data[0] = 1;
            data[16] = 2;
            data[32] = 3;
            data[60..].copy_from_slice(&ordinal.to_be_bytes());
            Trible { data }
        })
        .collect()
}

fn singleton_domain_source() -> Blob<SimpleArchive> {
    let mut data = [0u8; 64];
    data[15] = 1;
    data[31] = 1;
    data[63] = 1;
    let facts: TribleSet = [Trible { data }].into_iter().collect();
    facts.to_blob()
}

fn varied_facts(start: u32, count: u32) -> TribleSet {
    (start..start + count)
        .map(|ordinal| {
            let mut data = [0u8; 64];
            data[0] = 1;
            data[12..16].copy_from_slice(&(ordinal % 8).to_be_bytes());
            data[16] = 2;
            data[28..32].copy_from_slice(&(ordinal % 5).to_be_bytes());
            data[32] = 3;
            data[60..].copy_from_slice(&ordinal.to_be_bytes());
            Trible { data }
        })
        .collect()
}

#[derive(Default)]
struct Reference;

impl WaveletMatrixFreezeBackend for Reference {
    type Error = Infallible;
    fn freeze_rotation(
        &self,
        _: SuccinctRotation,
        _: usize,
        sequence: &[u32],
        planes: &mut [&mut [u64]],
    ) -> Result<(), Self::Error> {
        let mut current = sequence.to_vec();
        let mut next = vec![0; sequence.len()];
        let width = planes.len();
        for (depth, plane) in planes.iter_mut().enumerate() {
            plane.fill(0);
            let shift = width - 1 - depth;
            let zeros = current
                .iter()
                .filter(|code| (*code >> shift) & 1 == 0)
                .count();
            let (mut zero, mut one) = (0, zeros);
            for (position, &code) in current.iter().enumerate() {
                if (code >> shift) & 1 == 0 {
                    next[zero] = code;
                    zero += 1;
                } else {
                    plane[position / 64] |= 1u64 << (position % 64);
                    next[one] = code;
                    one += 1;
                }
            }
            std::mem::swap(&mut current, &mut next);
        }
        Ok(())
    }
}

trait Counted: WaveletMatrixFreezeBackend + Default {
    fn counter() -> &'static AtomicUsize;
    fn constructions() -> &'static AtomicUsize;
}

struct CountedReference;
static CPU_CALLS: AtomicUsize = AtomicUsize::new(0);
static CPU_CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
impl Default for CountedReference {
    fn default() -> Self {
        CPU_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}
impl Counted for CountedReference {
    fn counter() -> &'static AtomicUsize {
        &CPU_CALLS
    }
    fn constructions() -> &'static AtomicUsize {
        &CPU_CONSTRUCTIONS
    }
}
impl WaveletMatrixFreezeBackend for CountedReference {
    type Error = Infallible;
    fn freeze_rotation(
        &self,
        rotation: SuccinctRotation,
        alphabet: usize,
        sequence: &[u32],
        planes: &mut [&mut [u64]],
    ) -> Result<(), Self::Error> {
        CPU_CALLS.fetch_add(1, Ordering::Relaxed);
        Reference.freeze_rotation(rotation, alphabet, sequence, planes)
    }
}

fn maintenance_uses_both_operations<B: Counted>()
where
    B::Error: std::fmt::Display,
{
    let signer = SigningKey::from_bytes(&[59; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(signer.verifying_key()),
        AdmissionPolicy::direct(signer.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("raw-backend", policy.clone()).unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), policy)
        .unwrap();
    let mut expected = TribleSet::new();
    for start in [0, 32, 64, 96] {
        let part = varied_facts(start, 64);
        expected += part.clone();
        store.commit(source, &signer, Fragment::from(part)).unwrap();
    }
    B::counter().store(0, Ordering::Relaxed);
    B::constructions().store(0, Ordering::Relaxed);
    let snapshot = store.snapshot().unwrap();
    let source_descriptor: TribleSet = snapshot.get(source.handle()).unwrap();
    let target_descriptor: TribleSet = snapshot.get(target.handle()).unwrap();
    for _ in 0..3 {
        let bound = BackendSuccinctMapping::<B>::bind(
            &Fragment::from(source_descriptor.clone()),
            &Fragment::from(target_descriptor.clone()),
        )
        .unwrap();
        assert_eq!(
            bound.fragment().facts(),
            <SuccinctArchiveBlob as CollectionDerivation>::fragment(&()).facts()
        );
    }
    assert_eq!(
        B::constructions().load(Ordering::Relaxed),
        0,
        "descriptor binding must not initialize a device"
    );
    let fine = block_on(store.ensure_with::<BackendSuccinctMapping<B>>(target, &signer)).unwrap();
    assert!(
        B::constructions().load(Ordering::Relaxed) > 0,
        "actual maps initialize the backend"
    );
    assert_eq!(
        B::counter().load(Ordering::Relaxed),
        4 * 6,
        "four raw derivations"
    );
    let fine_records = fine
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!fine_records
        .iter()
        .any(|record| matches!(record, CollectionRecord::Merge(_))));
    B::counter().store(0, Ordering::Relaxed);
    let compact =
        block_on(store.maintain_with::<BackendSuccinctMapping<B>>(target, &signer)).unwrap();
    let records = compact
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let merges = records
        .iter()
        .filter(|record| matches!(record, CollectionRecord::Merge(_)))
        .count();
    assert!(merges > 0, "must exercise target MERGE, not just map");
    assert_eq!(
        B::counter().load(Ordering::Relaxed),
        merges * 6,
        "every target carry uses the backend; no source merges exist"
    );
    for record in &records {
        record.verify_strict().unwrap();
        let (expected, output) = match record {
            CollectionRecord::Derive(record) => {
                let input: Blob<SimpleArchive> = compact
                    .get(Handle::<SimpleArchive>::from_hash(record.input()))
                    .unwrap();
                (
                    SuccinctArchiveBlob::build_from_simple_archive(&input).unwrap(),
                    record.output(),
                )
            }
            CollectionRecord::Merge(record) => {
                let (low, high) = record.inputs();
                let low: Blob<SuccinctArchiveBlob> = compact
                    .get(Handle::<SuccinctArchiveBlob>::from_hash(low))
                    .unwrap();
                let high: Blob<SuccinctArchiveBlob> = compact
                    .get(Handle::<SuccinctArchiveBlob>::from_hash(high))
                    .unwrap();
                (
                    SuccinctArchiveBlob::merge(&[low, high]).unwrap(),
                    record.result(),
                )
            }
            CollectionRecord::Commit(_) => continue,
        };
        let actual: Blob<SuccinctArchiveBlob> = compact
            .get(Handle::<SuccinctArchiveBlob>::from_hash(output))
            .unwrap();
        assert_eq!(actual.bytes.as_ref(), expected.bytes.as_ref());
        assert_eq!(actual.get_handle(), expected.get_handle());
    }
    let view = compact.collection(target).unwrap();
    assert_eq!(
        view.view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        expected
    );
    let calls = B::counter().load(Ordering::Relaxed);
    let constructions = B::constructions().load(Ordering::Relaxed);
    let again =
        block_on(store.maintain_with::<BackendSuccinctMapping<B>>(target, &signer)).unwrap();
    assert_eq!(
        B::counter().load(Ordering::Relaxed),
        calls,
        "fixed point performs no backend work"
    );
    assert_eq!(again.records().unwrap().count(), records.len());
    assert_eq!(
        B::constructions().load(Ordering::Relaxed),
        constructions,
        "no-op maintenance may bind descriptors but must not initialize a backend"
    );
}

#[test]
fn canonical_mapping_uses_backend_for_derives_and_target_merges() {
    let accelerated = BackendSuccinctMapping::new(Reference);
    assert_eq!(
        accelerated.fragment().facts(),
        <SuccinctArchiveBlob as CollectionDerivation>::fragment(&()).facts()
    );
    maintenance_uses_both_operations::<CountedReference>();
    let source = singleton_domain_source();
    assert_eq!(
        SuccinctArchiveBlob::build_from_simple_archive_with_backend(&source, &Reference)
            .unwrap()
            .get_handle(),
        SuccinctArchiveBlob::build_from_simple_archive(&source)
            .unwrap()
            .get_handle(),
        "an all-zero code sequence still has one zero plane"
    );
}

#[derive(Default)]
struct Fails;
impl WaveletMatrixFreezeBackend for Fails {
    type Error = &'static str;
    fn freeze_rotation(
        &self,
        _: SuccinctRotation,
        _: usize,
        _: &[u32],
        planes: &mut [&mut [u64]],
    ) -> Result<(), Self::Error> {
        for plane in planes {
            plane.fill(u64::MAX);
        }
        Err("device failure after partial output")
    }
}

#[test]
fn returned_backend_failures_use_canonical_cpu_without_partial_output() {
    let mapping = BackendSuccinctMapping::new(Fails);
    let mut store = MemoryRepo::default();
    let snapshot = store.snapshot().unwrap();
    let source: Blob<SimpleArchive> = facts(0, 65).to_blob();
    let cpu = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
    let output = mapping.map(&source, &snapshot).unwrap();
    assert_eq!(output.bytes.as_ref(), cpu.bytes.as_ref());
    assert_eq!(output.get_handle(), cpu.get_handle());
    let other = SuccinctArchiveBlob::build_from_simple_archive(&facts(32, 65).to_blob()).unwrap();
    let joined = mapping
        .join_images(&Fragment::empty(), &output, &other, &snapshot)
        .unwrap()
        .unwrap();
    let expected = SuccinctArchiveBlob::merge(&[cpu, other]).unwrap();
    assert_eq!(joined.bytes.as_ref(), expected.bytes.as_ref());
    assert_eq!(joined.get_handle(), expected.get_handle());
}

#[cfg(feature = "cuda")]
mod cuda {
    use super::*;
    use std::time::Instant;
    use triblespace_gpu::CudaWaveletFreeze;

    struct StrictCuda(CudaWaveletFreeze);
    static CUDA_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CUDA_CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
    impl Default for StrictCuda {
        fn default() -> Self {
            CUDA_CONSTRUCTIONS.fetch_add(1, Ordering::Relaxed);
            Self(CudaWaveletFreeze::default())
        }
    }
    impl Counted for StrictCuda {
        fn counter() -> &'static AtomicUsize {
            &CUDA_CALLS
        }
        fn constructions() -> &'static AtomicUsize {
            &CUDA_CONSTRUCTIONS
        }
    }
    impl WaveletMatrixFreezeBackend for StrictCuda {
        type Error = Infallible;
        fn freeze_rotation(
            &self,
            rotation: SuccinctRotation,
            alphabet: usize,
            sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            // A fallback must never turn hardware parity into a CPU-only pass.
            self.0
                .freeze_rotation(rotation, alphabet, sequence, planes)
                .expect("CUDA hardware gate may not fall back");
            CUDA_CALLS.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    #[ignore = "requires an exclusively reserved CUDA device/shared-memory budget"]
    fn cuda_collection_derives_and_target_merges_match_canonical_bytes() {
        maintenance_uses_both_operations::<StrictCuda>();
    }

    #[test]
    #[ignore = "requires an exclusively reserved CUDA device/shared-memory budget"]
    fn cuda_raw_byte_hash_and_union_parity() {
        let backend = CudaWaveletFreeze::default();
        let start = Instant::now();
        let singleton = singleton_domain_source();
        assert_eq!(
            SuccinctArchiveBlob::build_from_simple_archive_with_backend(&singleton, &backend)
                .unwrap()
                .get_handle(),
            SuccinctArchiveBlob::build_from_simple_archive(&singleton)
                .unwrap()
                .get_handle(),
            "singleton alphabet/all-zero wavelet"
        );
        for count in [
            0u32, 1, 2, 5, 6, 7, 14, 15, 16, 30, 31, 32, 33, 62, 63, 64, 65, 126, 127, 128, 129,
            254, 255, 256, 257, 4096,
        ] {
            for varied in [false, true] {
                let input = if varied {
                    varied_facts(0, count)
                } else {
                    facts(0, count)
                };
                let source: Blob<SimpleArchive> = (&input).to_blob();
                let cpu = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
                let gpu =
                    SuccinctArchiveBlob::build_from_simple_archive_with_backend(&source, &backend)
                        .unwrap();
                assert_eq!(
                    gpu.bytes.as_ref(),
                    cpu.bytes.as_ref(),
                    "N={count}, varied E/A={varied}"
                );
                assert_eq!(gpu.get_handle(), cpu.get_handle());
                let other_facts = if varied {
                    varied_facts(count / 2, count)
                } else {
                    facts(count / 2, count)
                };
                let other =
                    SuccinctArchiveBlob::build_from_simple_archive(&(&other_facts).to_blob())
                        .unwrap();
                let merged = SuccinctArchiveBlob::merge_with_backend(
                    &[gpu.clone(), other.clone(), gpu.clone()],
                    &backend,
                )
                .unwrap();
                let reverse =
                    SuccinctArchiveBlob::merge_with_backend(&[other, gpu], &backend).unwrap();
                let union: Blob<SimpleArchive> = (input + other_facts).to_blob();
                let expected = SuccinctArchiveBlob::build_from_simple_archive(&union).unwrap();
                assert_eq!(merged.bytes.as_ref(), expected.bytes.as_ref());
                assert_eq!(merged.get_handle(), expected.get_handle());
                assert_eq!(reverse.get_handle(), expected.get_handle());
            }
        }
        eprintln!(
            "CUDA raw byte/hash/union parity finished in {:.3}s",
            start.elapsed().as_secs_f64()
        );
    }
}
