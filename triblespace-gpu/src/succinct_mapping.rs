//! An execution choice for the existing canonical collection mapping.

use std::sync::OnceLock;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    SuccinctArchiveBlob, WaveletMatrixFreezeBackend,
};
use triblespace_core::blob::Blob;
use triblespace_core::collection::{
    CollectionDerivation, CollectionEncoding, CollectionMapping, CollectionOperationError,
};
use triblespace_core::repo::{BlobStoreGet, BlobStoreMeta, StoreRead};
use triblespace_core::trible::Fragment;

/// Raw Succinct derivation and target compaction using one wavelet backend.
///
/// The descriptor is exactly the canonical SimpleArchive-to-Succinct descriptor:
/// a device is an execution choice, never part of a collection's identity. Both
/// `map` and `join_images` use the raw writer, without a native query arena.
/// Returned construction/backend failures retry the canonical CPU operation;
/// allocation failure, runtime panic and OOM are not caught. Callers must
/// reserve a device and sufficient shared memory before selecting this mapping.
/// Binding is device-free. The first actual `map` or `join_images` operation
/// initializes the backend; later operations on that binding reuse it. CubeCL
/// retains its client/shader/allocator caches through its existing runtime.
pub struct BackendSuccinctMapping<B> {
    backend: OnceLock<B>,
}

impl<B> BackendSuccinctMapping<B> {
    /// Select an already initialized backend for direct mapping operations.
    pub fn new(backend: B) -> Self {
        Self {
            backend: OnceLock::from(backend),
        }
    }
}

impl<B> CollectionMapping for BackendSuccinctMapping<B>
where
    B: WaveletMatrixFreezeBackend + Default,
    B::Error: std::fmt::Display,
{
    type Source = SimpleArchive;
    type Target = SuccinctArchiveBlob;

    fn fragment(&self) -> Fragment {
        <SuccinctArchiveBlob as CollectionDerivation>::fragment(&())
    }

    fn bind(source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        <SuccinctArchiveBlob as CollectionDerivation>::bind(source, target)?;
        Ok(Self {
            backend: OnceLock::new(),
        })
    }

    fn map<R>(
        &self,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<SuccinctArchiveBlob>, CollectionOperationError>
    where
        R: StoreRead,
    {
        match SuccinctArchiveBlob::build_from_simple_archive_with_backend(
            source,
            self.backend.get_or_init(B::default),
        ) {
            Ok(output) => Ok(output),
            Err(error) => {
                tracing::warn!(%error, "Succinct backend build failed; retrying canonical CPU build");
                <SuccinctArchiveBlob as CollectionDerivation>::map(&(), source, reader)
            }
        }
    }

    fn join_images<R>(
        &self,
        target_descriptor: &Fragment,
        low: &Blob<SuccinctArchiveBlob>,
        high: &Blob<SuccinctArchiveBlob>,
        reader: &R,
    ) -> Result<Option<Blob<SuccinctArchiveBlob>>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        match SuccinctArchiveBlob::merge_with_backend(
            &[low.clone(), high.clone()],
            self.backend.get_or_init(B::default),
        ) {
            Ok(output) => Ok(Some(output)),
            Err(error) => {
                tracing::warn!(%error, "Succinct backend merge failed; retrying canonical CPU merge");
                <SuccinctArchiveBlob as CollectionEncoding>::join_members(
                    target_descriptor,
                    low,
                    high,
                    reader,
                )
                .map(Some)
            }
        }
    }
}

/// Canonical raw Succinct maintenance on the default CUDA device.
#[cfg(feature = "cuda")]
pub type CudaSuccinctMapping = BackendSuccinctMapping<crate::CudaWaveletFreeze>;
