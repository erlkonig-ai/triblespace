//! One native WeMM model for content-keyed text AND image NVFP4 rows.
//!
//! Descriptor binding and image joins need no GPU. Computation is explicit:
//! the caller first binds a genuine frozen model pile through Mary's unsafe
//! native loader, then lends the resulting OWNED runtime to this thread with
//! [`with_wemm_runtime`]. A generic `StoreRead` is never treated as CUDA alias
//! provenance. The collection argument is caller-established frozen-store
//! provenance; the native facade itself proves only its actual selected root,
//! validated assets and device. READ/WRITE admission remains the store's job.
//!
//! The fixed profile accepts UTF-8 text and complete PNG/JPEG images through
//! the SAME model. The native framing limit is 256 IDs, without truncation.
//! PDFs, unsupported formats and overlength inputs fail the entire image;
//! there is no successful partial leaf that would suppress a future retry.
//! Only an archive with no selected content values honestly maps to empty.
//! Embeddings, normalization, quantization and scoring stay on GPU. Only
//! canonical row bytes and final scores cross back to the host.

use std::{cell::RefCell, fmt, marker::PhantomData, rc::Rc};

use anybytes::{Bytes, View};
use triblespace_core::blob::encodings::{rawbytes::RawBytes, simplearchive::SimpleArchive};
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{CollectionHandle, CollectionOperationError, DeriveMapping};
use triblespace_core::id::{id_hex, ExclusiveId, Id};
use triblespace_core::inline::encodings::{genid::GenId, hash::Handle, shortstring::ShortString};
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::macros::{attributes, entity, find};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::patch::{Entry, IdentitySchema, PATCH};
use triblespace_core::query::TriblePattern;
use triblespace_core::repo::{is_missing_blob, BlobStoreGet, StoreRead};
use triblespace_core::temp;
use triblespace_core::trible::{Fragment, TribleSet};

use crate::nvfp4::{nvfp4_dimension, NvFp4CosineIndex, NvFp4CosineSet, ReconstructedCosines};
pub use crate::semantic_attributes::{semantic_compute, semantic_content_attribute};
pub use mary::format::attrs::{model_collection, model_root};

/// Minted by the release operator with `trible genid`, 2026-10-01.
/// New mapping, never a reinterpretation of a Nomic descriptor or row.
pub const WEMM_CONTENT_TO_NVFP4: Id = id_hex!("C2218047C697B76F657619C33B0B560D");
/// Minted with `trible genid`, 2026-10-01. Native BF16 GB10 kernels, pinned
/// assets/framing, B1 <=256 IDs and complete PNG/JPEG white-pad preparation.
/// A change to these semantics or canonical output bytes needs another profile.
pub const GB10_NATIVE_BF16_PROFILE: Id = id_hex!("56AA6AA44ECDFF68B91CA45E39BC9EB6");
pub const DIMENSION: usize = 4096;
pub const COMPUTE_CLASS: &str = "gb10";

attributes! {
    /// Configuration asset. Anchor minted by `trible genid`, 2026-10-01.
    "C1FEADBAD086C8A7EC00C1080D7E2F13" as pub wemm_config: Handle<RawBytes>;
    /// Exact tokenizer JSON. Anchor minted by `trible genid`, 2026-10-01.
    "438EE4FAA8F9465B38DD8CCAD595D3DE" as pub wemm_tokenizer_json: Handle<RawBytes>;
    /// Exact chat template. Anchor minted by `trible genid`, 2026-10-01.
    "6850FB2F899C4EA04257547C9C5D63BC" as pub wemm_chat_template: Handle<RawBytes>;
    /// Kernel AND input profile. Anchor minted by `trible genid`, 2026-10-01.
    "B3CC3C4ED14B1F099A3D47FCC876E51C" as pub wemm_kernel_profile: GenId;
}

/// Semantic inputs, not the physical archives carrying the selected model.
/// Unknown kernel profiles remain readable/carryable but cannot compute here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WemmIdentity {
    pub model_collection: CollectionHandle,
    pub model_root: Id,
    pub config: Inline<Handle<RawBytes>>,
    pub tokenizer_json: Inline<Handle<RawBytes>>,
    pub chat_template: Inline<Handle<RawBytes>>,
    pub kernel_profile: Id,
}

impl WemmIdentity {
    fn require_loaded_selection(
        &self,
        root: Id,
        config: Inline<Handle<RawBytes>>,
        tokenizer_json: Inline<Handle<RawBytes>>,
        chat_template: Inline<Handle<RawBytes>>,
    ) -> Result<(), CollectionOperationError> {
        if self.kernel_profile != GB10_NATIVE_BF16_PROFILE {
            return Err(fatal("unsupported WeMM kernel/input profile"));
        }
        if (
            self.model_root,
            self.config,
            self.tokenizer_json,
            self.chat_template,
        ) != (root, config, tokenizer_json, chat_template)
        {
            return Err(fatal(
                "WeMM runtime's actual root/assets do not match the descriptor",
            ));
        }
        Ok(())
    }
}

/// Retained descriptor selection is a PATCH set, with no cached source rows.
pub struct WemmIndex<E: BlobEncoding> {
    content_attributes: PATCH<16, IdentitySchema, ()>,
    identity: WemmIdentity,
    encoding: PhantomData<E>,
}

impl<E: BlobEncoding> Clone for WemmIndex<E> {
    fn clone(&self) -> Self {
        Self {
            content_attributes: self.content_attributes.clone(),
            identity: self.identity,
            encoding: PhantomData,
        }
    }
}
impl<E: BlobEncoding> PartialEq for WemmIndex<E> {
    fn eq(&self, other: &Self) -> bool {
        self.content_attributes == other.content_attributes && self.identity == other.identity
    }
}
impl<E: BlobEncoding> Eq for WemmIndex<E> {}
impl<E: BlobEncoding> fmt::Debug for WemmIndex<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WemmIndex")
            .field(
                "content_attributes",
                &self.content_attributes.iter().collect::<Vec<_>>(),
            )
            .field("identity", &self.identity)
            .finish()
    }
}

impl<E: BlobEncoding> WemmIndex<E> {
    pub fn new(
        content_attributes: impl IntoIterator<Item = Id>,
        identity: WemmIdentity,
    ) -> Result<Self, CollectionOperationError> {
        let mut selected = PATCH::default();
        for attribute in content_attributes {
            selected.insert(&Entry::new(attribute.as_ref()));
        }
        if selected.is_empty() {
            return Err(fatal("WeMM index selects no content attribute"));
        }
        Ok(Self {
            content_attributes: selected,
            identity,
            encoding: PhantomData,
        })
    }

    pub fn identity(&self) -> WemmIdentity {
        self.identity
    }

    pub fn content_attributes(&self) -> impl Iterator<Item = Id> + '_ {
        self.content_attributes
            .iter()
            .map(|raw| Id::new(*raw).expect("inserted valid attribute id"))
    }

    fn values(
        &self,
        source: &Blob<SimpleArchive>,
    ) -> Result<PATCH<32, IdentitySchema, ()>, CollectionOperationError> {
        // Only this operation's source member; not a retained model/catalogue.
        let facts = TribleSet::try_from_blob(source.clone()).map_err(|e| fatal(e.to_string()))?;
        let mut values = PATCH::default();
        for attribute in self.content_attributes() {
            for value in find!(value: Inline<Handle<RawBytes>>,
                temp!((subject), facts.pattern::<Handle<RawBytes>>(subject, attribute.to_inline(), value))
            ) {
                values.insert(&Entry::new(&value.raw));
            }
        }
        Ok(values)
    }

    /// Query the same model space as this mapping, with a fresh serial text
    /// forward. No model fallback, host vector, original-vector rerank or
    /// member reselection is hidden here. The view stays caller-selected.
    pub fn reconstructed_cosines(
        &self,
        index: &NvFp4CosineIndex<E>,
        text: &str,
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        with_matching_runtime(&self.identity, |runtime| runtime.score_text(index, text))
    }

    /// Whole PNG/JPEG query, with the same model and fixed preparation profile
    /// as content derivation. No inferred crop and no separate image embedder.
    pub fn reconstructed_cosines_image(
        &self,
        index: &NvFp4CosineIndex<E>,
        encoded: &[u8],
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        with_matching_runtime(&self.identity, |runtime| {
            runtime.score_image(index, encoded)
        })
    }

    /// File-query dispatch uses exactly the derivation content classifier, so
    /// UTF-8, PNG and JPEG share this descriptor's one model space. Unsupported
    /// binary/PDF input refuses rather than taking a broader query-only path.
    pub fn reconstructed_cosines_content(
        &self,
        index: &NvFp4CosineIndex<E>,
        encoded: &[u8],
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        match classify(encoded)? {
            Input::Text(text) => self.reconstructed_cosines(index, text),
            Input::Image(bytes) => self.reconstructed_cosines_image(index, bytes),
        }
    }
}

struct Recipe;
impl MetaDescribe for Recipe {
    fn describe() -> Fragment {
        entity! { ExclusiveId::force_ref(&WEMM_CONTENT_TO_NVFP4) @
            metadata::name: "wemm-content-to-nvfp4",
            metadata::description: "Content handles under selected attributes embedded by one pinned native WeMM model for UTF-8 text and complete PNG/JPEG images, B1 at most 256 framed IDs without truncation, as canonical 4096-dimensional two-stage NVFP4 set rows. Unsupported selected content fails the whole source image. Root and exact assets, GB10 compute and kernel/input profile are descriptor identity; physical model archives are not.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

impl<E> DeriveMapping for WemmIndex<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
{
    type Source = SimpleArchive;
    type Target = NvFp4CosineSet<E>;

    fn fragment(&self) -> Fragment {
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: Recipe::describe(),
            metadata::blob_encoding*: E::describe(),
            nvfp4_dimension: DIMENSION as u64,
            semantic_compute: COMPUTE_CLASS,
            semantic_content_attribute*: self.content_attributes(),
            model_collection: self.identity.model_collection,
            model_root: self.identity.model_root,
            wemm_config: self.identity.config,
            wemm_tokenizer_json: self.identity.tokenizer_json,
            wemm_chat_template: self.identity.chat_template,
            wemm_kernel_profile: self.identity.kernel_profile,
        }
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        use triblespace_core::collection::descriptor;
        let facts = target.facts();
        if descriptor::mapping_algorithm(facts).map_err(|e| fatal(e.to_string()))?
            != Some(WEMM_CONTENT_TO_NVFP4)
        {
            return Err(fatal("descriptor is not the native WeMM mapping"));
        }
        if crate::nvfp4::mapping_dimension(target)? != DIMENSION {
            return Err(fatal("native WeMM descriptor requires dimension 4096"));
        }
        let compute: String = Inline::<ShortString>::new(argument(facts, semantic_compute.id())?)
            .try_from_inline()
            .map_err(|e| fatal(format!("invalid compute class: {e:?}")))?;
        if compute != COMPUTE_CLASS {
            return Err(fatal("native WeMM descriptor requires compute class gb10"));
        }
        let mapping = descriptor::mapping(facts)
            .map_err(|e| fatal(e.to_string()))?
            .ok_or_else(|| fatal("descriptor names no mapping"))?;
        let subject: Inline<GenId> = mapping.to_inline();
        let attribute: Inline<GenId> = semantic_content_attribute.id().to_inline();
        let selected = find!(value: Id, facts.pattern::<GenId>(subject, attribute, value));
        Self::new(
            selected,
            WemmIdentity {
                model_collection: Inline::new(argument(facts, model_collection.id())?),
                model_root: id_argument(facts, model_root.id())?,
                config: Inline::new(argument(facts, wemm_config.id())?),
                tokenizer_json: Inline::new(argument(facts, wemm_tokenizer_json.id())?),
                chat_template: Inline::new(argument(facts, wemm_chat_template.id())?),
                kernel_profile: id_argument(facts, wemm_kernel_profile.id())?,
            },
        )
    }

    fn computable_here(&self) -> bool {
        RUNTIME.with(|slot| {
            let Some(runtime) = slot.current() else {
                return false;
            };
            runtime
                .try_borrow()
                .is_ok_and(|runtime| runtime.matches(&self.identity))
        })
    }

    fn map<R: StoreRead>(
        &self,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError> {
        triblespace_core::collection::simplearchive_union::validate_element(source)
            .map_err(|e| fatal(e.to_string()))?;
        let values = self.values(source)?;
        if values.is_empty() {
            return NvFp4CosineSet::from_quantized_rows_4096([]).map_err(|e| fatal(e.to_string()));
        }
        with_matching_runtime(&self.identity, |runtime| {
            // Exact-byte readiness against this same frozen reader before any
            // expensive forward. Do not use passive residency as a prohibition
            // on fetching; discard each borrowed body after checking it rather
            // than retaining a second content catalogue. A late missing body
            // therefore does not repeatedly recompute earlier embeddings.
            for raw in values.iter_ordered() {
                let bytes = content_bytes(reader, Inline::new(*raw))?;
                classify(bytes.as_ref())?;
            }
            // Per-call output only. Any failed selected value drops this vector;
            // no partial target blob is returned or published by the mapping.
            let mut rows = Vec::new();
            for raw in values.iter_ordered() {
                let handle = Inline::<Handle<RawBytes>>::new(*raw);
                let bytes = content_bytes(reader, handle)?;
                rows.push((*raw, runtime.encode_content(bytes.as_ref())?));
            }
            NvFp4CosineSet::from_quantized_rows_4096(rows).map_err(|e| fatal(e.to_string()))
        })
    }
}

fn argument(facts: &TribleSet, attribute: Id) -> Result<[u8; 32], CollectionOperationError> {
    triblespace_core::collection::descriptor::mapping_argument(facts, attribute)
        .map_err(|e| fatal(e.to_string()))?
        .ok_or_else(|| fatal(format!("WeMM descriptor lacks {attribute:X}")))
}
fn id_argument(facts: &TribleSet, attribute: Id) -> Result<Id, CollectionOperationError> {
    Inline::<GenId>::new(argument(facts, attribute)?)
        .try_from_inline()
        .map_err(|e| fatal(format!("WeMM descriptor has invalid id: {e:?}")))
}
fn fatal(message: impl Into<String>) -> CollectionOperationError {
    CollectionOperationError::Fatal(message.into())
}

fn content_bytes<R: BlobStoreGet>(
    reader: &R,
    handle: Inline<Handle<RawBytes>>,
) -> Result<Bytes, CollectionOperationError> {
    reader.get(handle).map_err(|error| {
        if is_missing_blob(&error) {
            CollectionOperationError::MissingDependency(Handle::<RawBytes>::to_hash(handle))
        } else {
            fatal(format!("WeMM content read: {error}"))
        }
    })
}

enum Input<'a> {
    Text(&'a str),
    Image(&'a [u8]),
}
fn classify(bytes: &[u8]) -> Result<Input<'_>, CollectionOperationError> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(b"\xff\xd8\xff") {
        return Ok(Input::Image(bytes));
    }
    if bytes.starts_with(b"%PDF") {
        return Err(fatal(
            "WeMM PDF input is not supported; no partial text extraction",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| fatal("WeMM supports UTF-8 text or PNG/JPEG content only"))?;
    // ASCII prefixes such as BM/RIFF/GIF are not evidence of a binary file:
    // ordinary notes (notably "BM25 ranks documents") must remain text.
    if text.trim().is_empty()
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(fatal(
            "WeMM selected content is empty or binary, not supported text",
        ));
    }
    Ok(Input::Text(text))
}

/// An owned selected native session, never an ambient model loader. Without
/// `semantic-wemm-cuda` this type has no public constructor; descriptors and
/// joins still work and nonempty compute explicitly reports unavailable.
pub struct WemmRuntime {
    identity: WemmIdentity,
    #[cfg(feature = "semantic-wemm-cuda")]
    native: mary::models::qwen3_5::native::NativeWemm,
    #[cfg(feature = "semantic-wemm-cuda")]
    encoder: mary::nn::nvfp4_cosine::cuda_encode::CudaRowEncoder4096,
    #[cfg(feature = "semantic-wemm-cuda")]
    scorer: mary::nn::nvfp4_cosine::cuda_score::CudaReconstructedScorer4096,
}

impl WemmRuntime {
    /// The caller establishes that `identity.model_collection` is the admitted
    /// collection whose FROZEN facts supplied the selected model. NativeWemm
    /// does not claim collection membership or grant authorization. Its loader's
    /// immutable backing/preceding-page lifetime premise remains in force until
    /// CUDA teardown, even after this runtime/lease is dropped.
    ///
    /// The actual native root, validated asset bytes and actual selected device
    /// are checked here; they cannot be relabelled by a separate device argument.
    #[cfg(feature = "semantic-wemm-cuda")]
    pub fn from_native(
        identity: WemmIdentity,
        native: mary::models::qwen3_5::native::NativeWemm,
    ) -> Result<Self, CollectionOperationError> {
        let assets = native.asset_handles();
        identity.require_loaded_selection(
            native.model_root(),
            assets.config,
            assets.tokenizer_json,
            assets.chat_template,
        )?;
        let (name, major, minor) = native.device_identity().map_err(fatal)?;
        require_gb10(&name, major, minor)?;
        let device = native.device().clone();
        let encoder = mary::nn::nvfp4_cosine::cuda_encode::CudaRowEncoder4096::new(device.clone())
            .map_err(|e| fatal(e.to_string()))?;
        let scorer = mary::nn::nvfp4_cosine::cuda_score::CudaReconstructedScorer4096::new(device)
            .map_err(|e| fatal(e.to_string()))?;
        Ok(Self {
            identity,
            native,
            encoder,
            scorer,
        })
    }

    pub fn identity(&self) -> WemmIdentity {
        self.identity
    }

    fn matches(&self, identity: &WemmIdentity) -> bool {
        cfg!(feature = "semantic-wemm-cuda")
            && self.identity == *identity
            && identity.kernel_profile == GB10_NATIVE_BF16_PROFILE
    }

    fn encode_content(
        &mut self,
        bytes: &[u8],
    ) -> Result<mary::nn::nvfp4_cosine::QuantizedRow, CollectionOperationError> {
        let input = classify(bytes)?;
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            let embedding = match input {
                Input::Text(text) => self.native.embed_text(text),
                Input::Image(bytes) => self.native.embed_image(bytes, None),
            }
            .map_err(fatal)?;
            return self
                .encoder
                .encode(&embedding)
                .map_err(|e| fatal(e.to_string()));
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = input;
            Err(fatal("native WeMM CUDA runtime is not compiled"))
        }
    }

    fn score_text<E>(
        &mut self,
        index: &NvFp4CosineIndex<E>,
        text: &str,
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        E: BlobEncoding,
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            let embedding = self.native.embed_text(text).map_err(fatal)?;
            let query = self
                .scorer
                .prepare(&embedding)
                .map_err(|e| fatal(e.to_string()))?;
            return index
                .reconstructed_cosines_cuda_4096(&self.scorer, &query)
                .map_err(|e| fatal(e.to_string()));
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = (index, text);
            Err(fatal("native WeMM CUDA runtime is not compiled"))
        }
    }

    fn score_image<E>(
        &mut self,
        index: &NvFp4CosineIndex<E>,
        encoded: &[u8],
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        E: BlobEncoding,
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            if !matches!(classify(encoded)?, Input::Image(_)) {
                return Err(fatal("image query is not PNG/JPEG"));
            }
            let embedding = self.native.embed_image(encoded, None).map_err(fatal)?;
            let query = self
                .scorer
                .prepare(&embedding)
                .map_err(|e| fatal(e.to_string()))?;
            return index
                .reconstructed_cosines_cuda_4096(&self.scorer, &query)
                .map_err(|e| fatal(e.to_string()));
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = (index, encoded);
            Err(fatal("native WeMM CUDA runtime is not compiled"))
        }
    }
}

fn require_gb10(name: &str, major: i32, minor: i32) -> Result<(), CollectionOperationError> {
    if name != "NVIDIA GB10" || (major, minor) != (12, 1) {
        return Err(fatal(format!(
            "WeMM profile requires actual NVIDIA GB10 CC12.1; found {name} CC{major}.{minor}"
        )));
    }
    Ok(())
}

// One owned lease, not a process-wide model cache. The generic shell permits
// panic/nesting tests without allocating a model or initializing a GPU.
struct ScopedSlot<T> {
    current: RefCell<Option<Rc<RefCell<T>>>>,
}
impl<T> ScopedSlot<T> {
    const fn new() -> Self {
        Self {
            current: RefCell::new(None),
        }
    }
    fn current(&self) -> Option<Rc<RefCell<T>>> {
        self.current.borrow().clone()
    }
    fn run<R>(
        &self,
        runtime: Rc<RefCell<T>>,
        body: impl FnOnce() -> R,
    ) -> Result<R, CollectionOperationError> {
        {
            let mut current = self
                .current
                .try_borrow_mut()
                .map_err(|_| fatal("WeMM scope is reentrant"))?;
            if current.is_some() {
                return Err(fatal("nested WeMM runtime scope is not allowed"));
            }
            if runtime.try_borrow_mut().is_err() {
                return Err(fatal("WeMM runtime is already borrowed"));
            }
            *current = Some(runtime);
        }
        struct Restore<'a, T>(&'a ScopedSlot<T>);
        impl<T> Drop for Restore<'_, T> {
            fn drop(&mut self) {
                *self.0.current.borrow_mut() = None;
            }
        }
        let restore = Restore(self);
        let result = body();
        drop(restore);
        Ok(result)
    }
}

thread_local! { static RUNTIME: ScopedSlot<WemmRuntime> = const { ScopedSlot::new() }; }

/// Install an owned lease only for this synchronous closure, including a
/// directly driven current-thread `block_on`. A spawned task/thread does not
/// inherit it; do not return a future and poll it after this scope ends.
/// Nested scopes refuse instead of silently overwriting. The slot is restored
/// on both error returns and unwinding; ownership survives only as long as the
/// caller's `Rc` or an active access does. Alias backing obligations outlive it.
pub fn with_wemm_runtime<R>(
    runtime: Rc<RefCell<WemmRuntime>>,
    body: impl FnOnce() -> R,
) -> Result<R, CollectionOperationError> {
    RUNTIME.with(|slot| slot.run(runtime, body))
}

fn with_matching_runtime<R>(
    identity: &WemmIdentity,
    body: impl FnOnce(&mut WemmRuntime) -> Result<R, CollectionOperationError>,
) -> Result<R, CollectionOperationError> {
    let runtime = RUNTIME
        .with(ScopedSlot::current)
        .ok_or_else(|| fatal("native WeMM computation requires an explicit scoped runtime"))?;
    let mut runtime = runtime
        .try_borrow_mut()
        .map_err(|_| fatal("native WeMM runtime is already in use"))?;
    if !runtime.matches(identity) {
        return Err(fatal(
            "scoped WeMM runtime identity/profile does not match this mapping",
        ));
    }
    body(&mut runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::Embedding;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::{
        AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
    };
    use triblespace_core::repo::{memoryrepo::MemoryRepo, SnapshotSource};
    use triblespace_core::trible::Trible;

    fn identity() -> WemmIdentity {
        WemmIdentity {
            model_collection: Inline::new([1; 32]),
            model_root: Id::new([2; 16]).unwrap(),
            config: Inline::new([3; 32]),
            tokenizer_json: Inline::new([4; 32]),
            chat_template: Inline::new([5; 32]),
            kernel_profile: GB10_NATIVE_BF16_PROFILE,
        }
    }
    fn mapping() -> WemmIndex<Embedding> {
        WemmIndex::new(
            [metadata::name.id(), metadata::description.id()],
            identity(),
        )
        .unwrap()
    }
    fn descriptor(mapping: &WemmIndex<Embedding>) -> (MemoryRepo, Fragment) {
        let mut store = MemoryRepo::default();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(key), AdmissionPolicy::direct(key));
        let source = store.collection("source", policy.clone()).unwrap();
        let target: Collection<NvFp4CosineSet<Embedding>> =
            store.derive_with(source, mapping.clone(), policy).unwrap();
        let blob: Blob<SimpleArchive> = store.snapshot().unwrap().get(target.handle()).unwrap();
        (
            store,
            Fragment::from(TribleSet::try_from_blob(blob).unwrap()),
        )
    }

    #[test]
    fn descriptor_roundtrip_annotations_and_unavailable_profile_need_no_device() {
        let index = mapping();
        let (_, mut descriptor) = descriptor(&index);
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &descriptor).unwrap(),
            index
        );
        descriptor += entity! { _ @ metadata::name: "unrecognised future annotation" };
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &descriptor).unwrap(),
            index
        );
        let reordered = WemmIndex::<Embedding>::new(
            [
                metadata::description.id(),
                metadata::name.id(),
                metadata::name.id(),
            ],
            identity(),
        )
        .unwrap();
        assert_eq!(index.fragment(), reordered.fragment());
        assert!(
            !index.computable_here(),
            "no ambient GPU/model lookup without a lease"
        );
        let mut unknown = identity();
        unknown.kernel_profile = Id::new([8; 16]).unwrap();
        let unknown = WemmIndex::<Embedding>::new(index.content_attributes(), unknown).unwrap();
        let (_, description) = self::descriptor(&unknown);
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &description).unwrap(),
            unknown
        );
        assert!(!unknown.computable_here());
    }

    #[test]
    fn each_semantic_pin_changes_identity_but_neither_packaging_nor_order_is_a_pin() {
        let index = mapping();
        let original = identity();
        let mut alternatives = [original; 6];
        alternatives[0].model_collection = Inline::new([7; 32]);
        alternatives[1].model_root = Id::new([7; 16]).unwrap();
        alternatives[2].config = Inline::new([7; 32]);
        alternatives[3].tokenizer_json = Inline::new([7; 32]);
        alternatives[4].chat_template = Inline::new([7; 32]);
        alternatives[5].kernel_profile = Id::new([7; 16]).unwrap();
        for identity in alternatives {
            assert_ne!(identity, original);
            assert_ne!(
                index.fragment(),
                WemmIndex::<Embedding>::new(index.content_attributes(), identity)
                    .unwrap()
                    .fragment()
            );
        }
        assert_eq!(model_root.id(), mary::format::attrs::model_root.id());
        assert_eq!(
            model_collection.id(),
            mary::format::attrs::model_collection.id()
        );
        assert_eq!(
            semantic_content_attribute.id(),
            crate::semantic_attributes::semantic_content_attribute.id()
        );
    }

    #[test]
    fn loaded_selection_cannot_be_relabelled_and_hardware_is_not_an_architecture_guess() {
        let id = identity();
        assert!(id
            .require_loaded_selection(
                id.model_root,
                id.config,
                id.tokenizer_json,
                id.chat_template
            )
            .is_ok());
        assert!(id
            .require_loaded_selection(
                Id::new([9; 16]).unwrap(),
                id.config,
                id.tokenizer_json,
                id.chat_template
            )
            .is_err());
        assert!(id
            .require_loaded_selection(
                id.model_root,
                Inline::new([9; 32]),
                id.tokenizer_json,
                id.chat_template
            )
            .is_err());
        assert!(id
            .require_loaded_selection(
                id.model_root,
                id.config,
                Inline::new([9; 32]),
                id.chat_template
            )
            .is_err());
        assert!(id
            .require_loaded_selection(
                id.model_root,
                id.config,
                id.tokenizer_json,
                Inline::new([9; 32])
            )
            .is_err());
        let mut other = id;
        other.kernel_profile = Id::new([9; 16]).unwrap();
        assert!(other
            .require_loaded_selection(
                id.model_root,
                id.config,
                id.tokenizer_json,
                id.chat_template
            )
            .is_err());
        assert!(require_gb10("NVIDIA GB10", 12, 1).is_ok());
        for (name, major, minor) in [
            ("NVIDIA GB10", 12, 0),
            ("another GPU", 12, 1),
            ("aarch64 Linux", 12, 1),
        ] {
            assert!(require_gb10(name, major, minor).is_err());
        }
    }

    #[test]
    fn content_selection_is_a_value_set_and_only_no_selection_maps_empty_without_runtime() {
        let index = mapping();
        let mut facts = TribleSet::new();
        for (entity, attribute, value) in [
            (1, metadata::name.id(), 3),
            (2, metadata::name.id(), 3),
            (1, metadata::description.id(), 4),
            (3, metadata::tag.id(), 5),
        ] {
            facts.insert(&Trible::force(
                &Id::new([entity; 16]).unwrap(),
                &attribute,
                &Inline::<Handle<RawBytes>>::new([value; 32]),
            ));
        }
        let source = facts.to_blob();
        let values = index.values(&source).unwrap();
        assert_eq!(
            values.iter_ordered().copied().collect::<Vec<_>>(),
            vec![[3; 32], [4; 32]]
        );
        let mut store = MemoryRepo::default();
        let reader = store.snapshot().unwrap();
        assert!(index
            .map(&source, &reader)
            .unwrap_err()
            .to_string()
            .contains("explicit scoped runtime"));
        let empty = index.map(&TribleSet::new().to_blob(), &reader).unwrap();
        assert_eq!(
            empty.bytes.as_ref(),
            NvFp4CosineSet::<Embedding>::from_quantized_rows_4096([])
                .unwrap()
                .bytes
                .as_ref()
        );
    }

    #[test]
    fn exact_body_read_distinguishes_named_absence_from_backend_fault() {
        struct Fault;
        impl BlobStoreGet for Fault {
            type GetError<E: std::error::Error + Send + Sync + 'static> = std::io::Error;
            fn get<T, S>(
                &self,
                _: Inline<Handle<S>>,
            ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
            where
                S: BlobEncoding + 'static,
                T: TryFromBlob<S>,
                Handle<S>: triblespace_core::inline::InlineEncoding,
            {
                Err(std::io::Error::other("deliberate disk fault"))
            }
        }
        let handle = Inline::<Handle<RawBytes>>::new([9; 32]);
        let mut store = MemoryRepo::default();
        assert_eq!(
            content_bytes(&store.snapshot().unwrap(), handle).unwrap_err(),
            CollectionOperationError::MissingDependency(Handle::<RawBytes>::to_hash(handle))
        );
        assert!(
            matches!(content_bytes(&Fault, handle), Err(CollectionOperationError::Fatal(message))
            if message.contains("deliberate disk fault"))
        );
    }

    #[test]
    fn image_carry_remains_available_without_a_model_or_gpu() {
        let mut id = identity();
        id.kernel_profile = Id::new([6; 16]).unwrap();
        let index = WemmIndex::<Embedding>::new([metadata::name.id()], id).unwrap();
        let (mut store, target) = descriptor(&index);
        // Existing CPU quantizer is only a fixture oracle, never runtime code.
        let row = mary::nn::nvfp4_cosine::QuantizedRow::quantize(&vec![1.0; DIMENSION], DIMENSION)
            .unwrap();
        let image =
            NvFp4CosineSet::<Embedding>::from_quantized_rows_4096([([1; 32], row)]).unwrap();
        let joined = index
            .join_images(
                &target,
                &[image.clone(), image.clone()],
                &store.snapshot().unwrap(),
            )
            .unwrap();
        assert_eq!(joined.bytes.as_ref(), image.bytes.as_ref());
        assert!(!index.computable_here());
    }

    #[test]
    fn unsupported_selected_bytes_error_without_truncation_or_pdf_extraction() {
        for input in [
            b"%PDF-1.7 plain text".as_slice(),
            b"GIF89a\x01\0\x01\0",
            b"BM\0",
            b"RIFF\x01\0",
            b"\0",
            b"",
            b"  ",
        ] {
            assert!(classify(input).is_err());
        }
        for note in [
            "BM25 ranks documents",
            "RIFF is an audio container",
            "GIF89a describes a format",
        ] {
            assert!(matches!(classify(note.as_bytes()), Ok(Input::Text(text)) if text == note));
        }
        assert!(matches!(
            classify(b"\x89PNG\r\n\x1a\n"),
            Ok(Input::Image(_))
        ));
        assert!(matches!(classify(b"\xff\xd8\xff"), Ok(Input::Image(_))));
        let long = "exact raw text ".repeat(10_000);
        let Input::Text(selected) = classify(long.as_bytes()).unwrap() else {
            panic!("not text")
        };
        assert_eq!(
            selected, long,
            "framing/token bounds belong to NativeWemm; never pre-truncate"
        );
    }

    #[test]
    fn owned_scope_refuses_nesting_and_clears_after_result_or_unwind() {
        let slot = ScopedSlot::new();
        let owned = Rc::new(RefCell::new(7));
        assert_eq!(Rc::strong_count(&owned), 1);
        let result: Result<Result<(), &str>, _> = slot.run(owned.clone(), || {
            assert!(Rc::ptr_eq(&slot.current().unwrap(), &owned));
            assert!(slot.run(Rc::new(RefCell::new(9)), || ()).is_err());
            assert!(Rc::ptr_eq(&slot.current().unwrap(), &owned));
            Err("ordinary error")
        });
        assert_eq!(result.unwrap(), Err("ordinary error"));
        assert!(slot.current().is_none());
        assert_eq!(Rc::strong_count(&owned), 1);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = slot.run(owned.clone(), || panic!("intentional unwind"));
        }));
        assert!(panic.is_err());
        assert!(slot.current().is_none());
        assert_eq!(Rc::strong_count(&owned), 1);
        let guard = owned.borrow_mut();
        assert!(slot.run(owned.clone(), || ()).is_err());
        drop(guard);
        assert_eq!(slot.run(owned, || 42).unwrap(), 42);
    }
}
