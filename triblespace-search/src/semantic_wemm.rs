//! One native WeMM model for content-keyed text AND image NVFP4 rows.
//!
//! Descriptor binding and image joins need no GPU. Computation is explicit:
//! the caller first binds a genuine frozen model pile through Mary's unsafe
//! native loader, then lends the resulting OWNED runtime to this thread with
//! [`with_wemm_runtime`]. A generic `StoreRead` is never treated as CUDA alias
//! provenance. The native facade proves its actual selected root, validated
//! assets and device; which collection carried the model is the store's
//! business and is not part of an index's identity. READ/WRITE admission
//! remains the store's job.
//!
//! The mapping is total on content bytes, through the SAME model for text
//! and images. A PNG/JPEG the fixed preparation decodes is one row. UTF-8
//! text (an HTML page reduced to its text) and a PDF's text layer are cut by
//! the pinned tokenizer into windows of at most [`WINDOW_IDS`] framed IDs:
//! greedily whole lines, a line that does not fit alone between words, a word
//! between characters. Each of the first `window_cap` windows is one row
//! under the same content handle, and the carrier scores a handle at the
//! maximum over its rows, so a query matching any window finds the content.
//! Everything else (binary, blank, a PDF without a text layer, an image the
//! preparation cannot decode) is zero rows: a value of the function, not a
//! refusal, so no foundation waits on content no machine can read.
//! Embeddings, normalization, quantization and scoring stay on GPU. Only
//! canonical row bytes and final scores cross back to the host.

use std::borrow::Cow;
use std::{cell::RefCell, fmt, marker::PhantomData, rc::Rc};

use anybytes::{Bytes, View};
use triblespace_core::blob::encodings::{rawbytes::RawBytes, simplearchive::SimpleArchive};
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{CollectionOperationError, DeriveMapping};
use triblespace_core::id::{id_hex, ExclusiveId, Id};
use triblespace_core::inline::encodings::{genid::GenId, hash::Handle, iu256::U256BE};
use triblespace_core::inline::{Inline, IntoInline, TryFromInline};
use triblespace_core::macros::{attributes, entity, find};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::patch::{Entry, IdentitySchema, PATCH};
use triblespace_core::query::TriblePattern;
use triblespace_core::repo::{is_missing_blob, BlobStoreGet, StoreRead};
use triblespace_core::temp;
use triblespace_core::trible::{Fragment, TribleSet};

use crate::content_text::{looks_like_html, pdf_text, strip_html};
use crate::nvfp4::{nvfp4_dimension, NvFp4CosineIndex, NvFp4CosineSet, ReconstructedCosines};
pub use crate::semantic_attributes::{semantic_compute, semantic_content_attribute};
pub use mary::format::attrs::model_root;

/// Minted with `trible genid`, 2026-10-06. It replaces
/// `C2218047C697B76F657619C33B0B560D` (2026-10-01), which read only what fits
/// one forward and refused the whole source image for anything else; it was
/// never maintained outside scratch piles, and nothing reads it.
pub const WEMM_CONTENT_WINDOWS_TO_NVFP4: Id = id_hex!("3D288D450426ABD3FFF0D2C05887C09D");
/// Minted with `trible genid`, 2026-10-01. Native BF16 GB10 kernels, pinned
/// assets/framing, windows of <=256 IDs and complete PNG/JPEG white-pad
/// preparation. Since 2026-11-08 windows run as right-padded batches of up
/// to [`WINDOW_BATCH`], each pooled at its own last token; every row is
/// bit-identical to its one-window forward (mary c2e280a), so the profile is
/// unchanged. A change to these semantics or canonical output bytes needs
/// another profile.
pub const GB10_NATIVE_BF16_PROFILE: Id = id_hex!("56AA6AA44ECDFF68B91CA45E39BC9EB6");
/// Most text windows in one forward. Chosen on a GB10 (2026-11-08): a
/// steady 248-ID scan (on a build with the DeltaNet unroll) gave per window
/// 155 ms at 1, 127 at 2, 125 at 4, 142 at 8, 248 at 16, and the CubeCL pool
/// held 639 MiB up to 4 and 2585 MiB from 8; without the unroll a 303-window
/// corpus took 173.5 ms per window at 1 and 153.2 at 4. Above 4 the K=12288
/// down projection slows per row. Each window's row is bit-identical at every
/// batch size.
pub const WINDOW_BATCH: usize = 4;
pub const DIMENSION: usize = 4096;
pub const COMPUTE_CLASS: &str = "gb10";
/// The most framed token IDs one text window takes: eight under the profile's
/// 256, and part of [`WEMM_CONTENT_WINDOWS_TO_NVFP4`].
pub const WINDOW_IDS: usize = 248;
/// The window cap to describe an index with unless there is a reason to read
/// further into long content. The cap is identity: another cap is another
/// descriptor.
pub const DEFAULT_WINDOW_CAP: u64 = 16;

// The asset attributes `wemm_config` (C1FEADBAD086C8A7EC00C1080D7E2F13),
// `wemm_tokenizer_json` (438EE4FAA8F9465B38DD8CCAD595D3DE) and
// `wemm_chat_template` (6850FB2F899C4EA04257547C9C5D63BC), minted 2026-10-01,
// named side-file blobs beside a member-only root. The complete model root
// covers all three since 2026-11-07, so descriptors no longer carry them; an
// older descriptor that does is still bound, and they are ignored.
attributes! {
    /// Kernel AND input profile. Anchor minted by `trible genid`, 2026-10-01.
    "B3CC3C4ED14B1F099A3D47FCC876E51C" as pub wemm_kernel_profile: GenId;
    /// The most windows, and so rows, one content value maps to. Anchor
    /// minted by `trible genid`, 2026-10-06.
    "B999AF3E65C457A9DFD54EBA05C211B7" as pub wemm_window_cap: U256BE;
}

/// What an embedding IS a function of, and nothing else: the model and the
/// way it is run. Content-only, so the same model gives the same index
/// identity on every machine and in every collection that carries it.
///
/// - `model_root` is the COMPLETE model root
///   (`mary::ingest::build_model_root_with`), whose content-derived id
///   covers the weights, the tokenizer, the configuration and the chat
///   template. A changed tokenizer or template changes the token ids a text
///   becomes, and so the vectors; that is why they are in the root and why
///   the root alone suffices here. Which collection, pile or archive carried
///   the model is provenance, not identity, and is not stated.
/// - `kernel_profile` stays. The profile names the native BF16 GB10 kernels
///   together with the input semantics (framing, at most 256 IDs per
///   window in right-padded batches, the 256-patch white-pad image
///   preparation). Every one of those
///   changes the vector for the same model and content: another kernel
///   accumulates the BF16 GEMMs in another order and lands on other bits,
///   which quantize to other NVFP4 rows, and another preparation feeds the
///   model other pixels. Rows from two profiles in one index would be scored
///   against each other as if they were comparable. So the profile is part
///   of what the embedding is, and an index under another profile is another
///   index ([`GB10_NATIVE_BF16_PROFILE`]).
///
/// Unknown kernel profiles remain readable/carryable but cannot compute here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WemmIdentity {
    pub model_root: Id,
    pub kernel_profile: Id,
}

impl WemmIdentity {
    fn require_loaded_selection(&self, root: Id) -> Result<(), CollectionOperationError> {
        if self.kernel_profile != GB10_NATIVE_BF16_PROFILE {
            return Err(fatal("unsupported WeMM kernel/input profile"));
        }
        if self.model_root != root {
            return Err(fatal(
                "WeMM runtime's actual root does not match the descriptor",
            ));
        }
        Ok(())
    }
}

/// Retained descriptor selection is a PATCH set, with no cached source rows.
pub struct WemmIndex<E: BlobEncoding> {
    content_attributes: PATCH<16, IdentitySchema, ()>,
    identity: WemmIdentity,
    window_cap: u64,
    encoding: PhantomData<E>,
}

impl<E: BlobEncoding> Clone for WemmIndex<E> {
    fn clone(&self) -> Self {
        Self {
            content_attributes: self.content_attributes.clone(),
            identity: self.identity,
            window_cap: self.window_cap,
            encoding: PhantomData,
        }
    }
}
impl<E: BlobEncoding> PartialEq for WemmIndex<E> {
    fn eq(&self, other: &Self) -> bool {
        self.content_attributes == other.content_attributes
            && self.identity == other.identity
            && self.window_cap == other.window_cap
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
            .field("window_cap", &self.window_cap)
            .finish()
    }
}

impl<E: BlobEncoding> WemmIndex<E> {
    /// `window_cap` is how many windows of one text become rows; see
    /// [`DEFAULT_WINDOW_CAP`].
    pub fn new(
        content_attributes: impl IntoIterator<Item = Id>,
        identity: WemmIdentity,
        window_cap: u64,
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
            window_cap,
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

    /// File-query dispatch reads content as derivation does: an image whole,
    /// text (an HTML page's text, a PDF's text layer) as one query, which must
    /// fit the profile's 256 framed IDs. Content the mapping reads nothing in
    /// refuses rather than taking a broader query-only path.
    pub fn reconstructed_cosines_content(
        &self,
        index: &NvFp4CosineIndex<E>,
        encoded: &[u8],
    ) -> Result<ReconstructedCosines, CollectionOperationError>
    where
        View<[f32]>: TryFromBlob<E>,
        <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
    {
        match classify(encoded) {
            Some(Input::Text(text)) => self.reconstructed_cosines(index, &text),
            Some(Input::Image(bytes)) => self.reconstructed_cosines_image(index, bytes),
            None => Err(fatal("WeMM reads no text or image in this content")),
        }
    }
}

struct Recipe;
impl MetaDescribe for Recipe {
    fn describe() -> Fragment {
        entity! { ExclusiveId::force_ref(&WEMM_CONTENT_WINDOWS_TO_NVFP4) @
            metadata::name: "wemm-content-windows-to-nvfp4",
            metadata::description: "Content handles under selected attributes embedded by one pinned native WeMM model as canonical 4096-dimensional two-stage NVFP4 set rows keyed by the content handle. A complete PNG/JPEG the fixed preparation decodes is one row. UTF-8 text, reduced to its text when it sniffs as HTML, and a PDF text layer are cut by the pinned tokenizer into windows of at most 248 framed IDs, greedily whole lines, a line too long alone between words, a word too long alone between characters; each of the first window-cap windows is one row. Any other content is no row. The complete model root (weights, tokenizer, configuration and chat template), GB10 compute, kernel/input profile and window cap are descriptor identity; the collection and physical archives carrying the model are not.",
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
            model_root: self.identity.model_root,
            wemm_kernel_profile: self.identity.kernel_profile,
            wemm_window_cap: self.window_cap,
        }
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        use triblespace_core::collection::descriptor;
        let facts = target.facts();
        if descriptor::mapping_algorithm(facts).map_err(|e| fatal(e.to_string()))?
            != Some(WEMM_CONTENT_WINDOWS_TO_NVFP4)
        {
            return Err(fatal("descriptor is not the native WeMM windows mapping"));
        }
        if crate::nvfp4::mapping_dimension(target)? != DIMENSION {
            return Err(fatal("native WeMM descriptor requires dimension 4096"));
        }
        let compute =
            crate::semantic_attributes::compute_class(argument(facts, semantic_compute.id())?);
        if compute != Some(COMPUTE_CLASS) {
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
                model_root: id_argument(facts, model_root.id())?,
                kernel_profile: id_argument(facts, wemm_kernel_profile.id())?,
            },
            u64::try_from_inline(&Inline::<U256BE>::new(argument(
                facts,
                wemm_window_cap.id(),
            )?))
            .map_err(|e| fatal(format!("invalid WeMM window cap: {e:?}")))?,
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
                content_bytes(reader, Inline::new(*raw))?;
            }
            // Per-call output only. A failed forward drops this vector; no
            // partial target blob is returned or published by the mapping.
            let mut rows = Vec::new();
            let mut texts = Vec::new();
            for raw in values.iter_ordered() {
                let bytes = content_bytes(reader, Inline::new(*raw))?;
                match classify(bytes.as_ref()) {
                    Some(Input::Text(text)) => texts.push((*raw, text.into_owned())),
                    Some(Input::Image(image)) => rows.extend(
                        runtime.encode_image(image)?.into_iter().map(|row| (*raw, row))),
                    None => {}
                }
            }
            // Every text window of this foundation, WINDOW_BATCH per forward.
            // The texts are cut in parallel, all before the first forward;
            // the windows and batches are the sequential ones, in order.
            let cuts = runtime.cut_all(&texts, self.window_cap);
            let windows: Vec<(&[u8; 32], &str)> = texts
                .iter()
                .zip(&cuts)
                .flat_map(|((raw, _), cut)| cut.iter().map(move |w| (raw, *w)))
                .collect();
            for chunk in windows.chunks(WINDOW_BATCH) {
                let embedded = runtime.encode_windows(&chunk.iter().map(|(_, w)| *w).collect::<Vec<_>>())?;
                rows.extend(chunk.iter().zip(embedded).map(|((raw, _), row)| (**raw, row)));
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
    Text(Cow<'a, str>),
    Image(&'a [u8]),
}
/// What this mapping reads in content bytes, decided by the bytes alone: a
/// PNG/JPEG whole, or the text of UTF-8 (an HTML page without its markup) or
/// of a PDF's text layer. `None` is everything else: binary, blank, a PDF
/// without a text layer.
fn classify(bytes: &[u8]) -> Option<Input<'_>> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(b"\xff\xd8\xff") {
        return Some(Input::Image(bytes));
    }
    let text = if bytes.starts_with(b"%PDF") {
        Cow::Owned(pdf_text(bytes))
    } else {
        let text = std::str::from_utf8(bytes).ok()?;
        // ASCII prefixes such as BM/RIFF/GIF are not evidence of a binary file:
        // ordinary notes (notably "BM25 ranks documents") must remain text.
        if text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return None;
        }
        if looks_like_html(text) {
            Cow::Owned(strip_html(text))
        } else {
            Cow::Borrowed(text)
        }
    };
    (!text.trim().is_empty()).then_some(Input::Text(text))
}

/// The first `cap` windows of `text`, in order. Each is the longest run of
/// whole lines that `fits`; a line that does not fit alone is cut between
/// words, and a word that does not fit alone between characters. Whitespace
/// between windows belongs to neither.
///
/// `same(shorter, longer)`, for `longer` starting with `shorter`, may be true
/// only where `fits(longer) == fits(shorter)` (for the real cut,
/// `InputCodec::same_text`). The cut then skips the probes it makes
/// redundant and is exactly the cut without it: a probe is skipped only
/// when it extends `rest[..end]`, which has already fit (`end` moves only on
/// a fit, and a later unit's pass starts at 0), so the skipped probe would
/// have said true too. That turns a run of blank lines, which the template
/// trims from the probe's end, from one full tokenization per line into
/// none.
#[cfg_attr(not(feature = "semantic-wemm-cuda"), allow(dead_code))]
fn windows<'t>(
    text: &'t str,
    cap: u64,
    mut fits: impl FnMut(&str) -> bool,
    same: impl Fn(&str, &str) -> bool,
) -> Vec<&'t str> {
    let units: [fn(&str) -> usize; 3] = [
        |s| s.find('\n').map_or(s.len(), |at| at + 1),
        |s| {
            let word = s.find(char::is_whitespace).unwrap_or(s.len());
            s.len() - s[word..].trim_start().len()
        },
        |s| s.chars().next().map_or(0, char::len_utf8),
    ];
    let mut windows = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() && (windows.len() as u64) < cap {
        let mut end = 0;
        for unit in units {
            while end < rest.len() {
                let next = end + unit(&rest[end..]);
                let known = end > 0 && same(&rest[..end], &rest[..next]);
                if !known && !fits(&rest[..next]) {
                    break;
                }
                end = next;
            }
            if end > 0 {
                break;
            }
        }
        // One character always fits the real framing; this keeps any `fits`
        // finite.
        let end = end.max(units[2](rest));
        windows.push(rest[..end].trim_end());
        rest = rest[end..].trim_start();
    }
    windows
}

/// Whether `window` frames to at most [`WINDOW_IDS`] IDs. A probe the codec
/// can prove too long without tokenizing (`surely_exceeds`) gets the same
/// false it would have computed: the greedy cut's first probe of a window is
/// the whole rest of a one-line text, up to 1 MiB, and that tokenization
/// was most of the cost of cutting HTML.
#[cfg(feature = "semantic-wemm-cuda")]
fn window_fits(codec: &mary::models::qwen3_5::input_codec::InputCodec, window: &str) -> bool {
    !codec.surely_exceeds(window, WINDOW_IDS)
        && codec
            .text(window)
            .is_ok_and(|ids| ids.as_slice().len() <= WINDOW_IDS)
}

/// The real cut: [`windows`] under [`window_fits`], skipping the probes
/// `InputCodec::same_text` answers, and how many probes it did run.
#[cfg(feature = "semantic-wemm-cuda")]
fn cut_windows<'t>(
    codec: &mary::models::qwen3_5::input_codec::InputCodec,
    text: &'t str,
    cap: u64,
) -> (Vec<&'t str>, usize) {
    use mary::models::qwen3_5::input_codec::InputCodec;
    let mut probes = 0;
    let fits = |window: &str| {
        probes += 1;
        window_fits(codec, window)
    };
    let cut = windows(text, cap, fits, InputCodec::same_text);
    (cut, probes)
}

/// The threads [`cut_all`] cuts on.
#[cfg(feature = "semantic-wemm-cuda")]
const CUT_THREADS: usize = 8;

/// A text whose cut takes longer is named on stderr when it finishes, so a
/// slow derivation says which content it spent the time on.
#[cfg(feature = "semantic-wemm-cuda")]
const SLOW_CUT: std::time::Duration = std::time::Duration::from_secs(10);

/// [`cut_windows`] of every text, in the texts' order, on up to
/// [`CUT_THREADS`] threads. Each text is cut whole on one thread by the same
/// pure function, and its windows land at its own index, so the result is
/// the sequential one; only the wall time changes. A cut slower than
/// [`SLOW_CUT`] is logged.
#[cfg(feature = "semantic-wemm-cuda")]
fn cut_all<'t>(
    codec: &mary::models::qwen3_5::input_codec::InputCodec,
    texts: &'t [([u8; 32], String)],
    cap: u64,
) -> Vec<Vec<&'t str>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let mut cuts = vec![Vec::new(); texts.len()];
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..CUT_THREADS.min(texts.len()))
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some((raw, text)) = texts.get(at) else {
                            break done;
                        };
                        let started = std::time::Instant::now();
                        let (cut, probes) = cut_windows(codec, text, cap);
                        let took = started.elapsed();
                        if took > SLOW_CUT {
                            eprintln!(
                                "wemm: slow cut of {}… ({} text bytes) in {:.1} s: {} windows, {probes} probes",
                                raw[..8].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                                text.len(),
                                took.as_secs_f64(),
                                cut.len()
                            );
                        }
                        done.push((at, cut));
                    }
                })
            })
            .collect();
        for worker in workers {
            let done = worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            for (at, cut) in done {
                cuts[at] = cut;
            }
        }
    });
    cuts
}

/// An owned selected native session, never an ambient model loader. Without
/// `semantic-wemm-cuda` this type has no public constructor; descriptors and
/// joins still work and nonempty compute explicitly reports unavailable.
pub struct WemmRuntime {
    identity: WemmIdentity,
    #[cfg(feature = "semantic-wemm-cuda")]
    native: mary::models::qwen3_5::native::NativeWemm,
    #[cfg(feature = "semantic-wemm-cuda")]
    codec: mary::models::qwen3_5::input_codec::InputCodec,
    #[cfg(feature = "semantic-wemm-cuda")]
    encoder: mary::nn::nvfp4_cosine::cuda_encode::CudaRowEncoder4096,
    #[cfg(feature = "semantic-wemm-cuda")]
    scorer: mary::nn::nvfp4_cosine::cuda_score::CudaReconstructedScorer4096,
}

impl WemmRuntime {
    /// The caller establishes that the admitted collection's FROZEN facts
    /// supplied the selected model. NativeWemm does not claim collection
    /// membership or grant authorization. Its loader's immutable
    /// backing/preceding-page lifetime premise remains in force until CUDA
    /// teardown, even after this runtime/lease is dropped.
    ///
    /// The actual native root and actual selected device are checked here;
    /// they cannot be relabelled by a separate device argument. The root
    /// carries its tokenizer, configuration and template in its identity.
    ///
    /// `codec` cuts text into windows. It must be the codec of the same
    /// assets `native` was bound with (`Assets::codec`).
    #[cfg(feature = "semantic-wemm-cuda")]
    pub fn from_native(
        identity: WemmIdentity,
        native: mary::models::qwen3_5::native::NativeWemm,
        codec: mary::models::qwen3_5::input_codec::InputCodec,
    ) -> Result<Self, CollectionOperationError> {
        identity.require_loaded_selection(native.model_root())?;
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
            codec,
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

    /// The first `cap` windows of each text, cut by the pinned tokenizer,
    /// in the texts' order ([`cut_all`]).
    fn cut_all<'t>(&self, texts: &'t [([u8; 32], String)], cap: u64) -> Vec<Vec<&'t str>> {
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            return cut_all(&self.codec, texts, cap);
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = cap;
            texts.iter().map(|_| Vec::new()).collect()
        }
    }

    /// One row per window, all of them through one batched forward.
    fn encode_windows(
        &mut self,
        windows: &[&str],
    ) -> Result<Vec<mary::nn::nvfp4_cosine::QuantizedRow>, CollectionOperationError> {
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            let embeddings = self.native.embed_texts(windows).map_err(fatal)?;
            return embeddings
                .iter()
                .map(|e| self.encoder.encode(e).map_err(|e| fatal(e.to_string())))
                .collect();
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = windows;
            Err(fatal("native WeMM CUDA runtime is not compiled"))
        }
    }

    /// One row for an image the fixed preparation decodes; an image it cannot
    /// decode (damaged, or wider or taller than 4096 pixels) is no row.
    fn encode_image(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<mary::nn::nvfp4_cosine::QuantizedRow>, CollectionOperationError> {
        #[cfg(feature = "semantic-wemm-cuda")]
        {
            use mary::models::qwen3_5::image_prepare::DecodedRgba;
            if DecodedRgba::decode(bytes).is_err() {
                return Ok(Vec::new());
            }
            let embedding = self.native.embed_image(bytes, None).map_err(fatal)?;
            return Ok(vec![self.encoder.encode(&embedding).map_err(|e| fatal(e.to_string()))?]);
        }
        #[cfg(not(feature = "semantic-wemm-cuda"))]
        {
            let _ = bytes;
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
            if !matches!(classify(encoded), Some(Input::Image(_))) {
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
        AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy, CollectionStoreExt,
    };
    use triblespace_core::repo::{memoryrepo::MemoryRepo, SnapshotSource};
    use triblespace_core::trible::Trible;

    fn identity() -> WemmIdentity {
        WemmIdentity {
            model_root: Id::new([2; 16]).unwrap(),
            kernel_profile: GB10_NATIVE_BF16_PROFILE,
        }
    }
    fn mapping() -> WemmIndex<Embedding> {
        WemmIndex::new(
            [metadata::name.id(), metadata::description.id()],
            identity(),
            DEFAULT_WINDOW_CAP,
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
            DEFAULT_WINDOW_CAP,
        )
        .unwrap();
        assert_eq!(index.fragment(), reordered.fragment());
        let capped =
            WemmIndex::<Embedding>::new(index.content_attributes(), identity(), 4).unwrap();
        let (_, description) = self::descriptor(&capped);
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &description).unwrap(),
            capped
        );
        assert!(
            !index.computable_here(),
            "no ambient GPU/model lookup without a lease"
        );
        let mut unknown = identity();
        unknown.kernel_profile = Id::new([8; 16]).unwrap();
        let unknown =
            WemmIndex::<Embedding>::new(index.content_attributes(), unknown, DEFAULT_WINDOW_CAP)
                .unwrap();
        let (_, description) = self::descriptor(&unknown);
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &description).unwrap(),
            unknown
        );
        assert!(!unknown.computable_here());
    }

    /// A stand-in complete model put into `repo` (the weights a named leaf,
    /// a tokenizer, a configuration and a template), built the way importers
    /// build roots.
    fn complete_root(
        repo: &mut MemoryRepo,
        weight: &str,
        vocab_b: &str,
        hidden: i64,
        template: &str,
    ) -> Fragment {
        use triblespace_core::blob::encodings::utf8string::UTF8String;
        use triblespace_core::repo::BlobStorePut;
        let tokenizer = format!(
            r###"{{"version": "1.0", "added_tokens": [], "normalizer": null,
            "pre_tokenizer": {{"type": "BertPreTokenizer"}}, "post_processor": null, "decoder": null,
            "model": {{"type": "WordPiece", "unk_token": "[UNK]", "continuing_subword_prefix": "##",
            "max_input_chars_per_word": 100, "vocab": {{"[UNK]": 0, "a": 1, "{vocab_b}": 2}}}}}}"###
        );
        let mut facts = TribleSet::new();
        let path = repo.put::<UTF8String, _>("w".to_owned()).unwrap();
        let kind = repo.put::<UTF8String, _>(weight.to_owned()).unwrap();
        let leaf = entity! { _ @ mary::format::attrs::kind: kind };
        let leaf_id = leaf.root().unwrap();
        facts += leaf.into_facts();
        let module = entity! { _ @
            mary::format::attrs::safetensor_path: path,
            mary::format::attrs::weight: leaf_id,
        };
        let members = vec![module.root().unwrap()];
        facts += module.into_facts();
        let tok = mary::tokenizer::save_tokenizer_json(tokenizer.as_bytes(), "t", repo).unwrap();
        let tokenizer = tok.root();
        facts += tok.into_facts();
        // A stand-in configuration node: the root's core links its id.
        let config = entity! { _ @ metadata::name: format!("hidden_size {hidden}") };
        let config_id = config.root().unwrap();
        facts += config.into_facts();
        let chat_template = repo.put::<UTF8String, _>(template.to_owned()).unwrap();
        mary::ingest::build_model_root_with(
            repo,
            "org/wemm",
            "native",
            members,
            facts,
            &[],
            mary::ingest::RootParts {
                tokenizer,
                config: Some(config_id),
                chat_template: Some(chat_template),
            },
        )
        .unwrap()
    }

    /// Publish `fragment` into a fresh `models` collection under its own
    /// signer, and select the model root back from that collection.
    fn published_root(
        seed: u8,
        build: impl FnOnce(&mut MemoryRepo) -> Fragment,
    ) -> (CollectionHandle, Id) {
        let mut repo = MemoryRepo::default();
        let fragment = build(&mut repo);
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let collection = repo.collection("models", policy).unwrap();
        repo.commit(collection, &key, fragment).unwrap();
        let store = repo.snapshot().unwrap();
        let model =
            mary::model_collection::snapshot_model_collection_for(&store, collection).unwrap();
        let root = mary::selection::select_model_root(
            model.facts(),
            &store,
            mary::selection::ModelSelector::Only,
        )
        .unwrap();
        (collection.handle(), root)
    }

    fn index_of(root: Id) -> Fragment {
        WemmIndex::<Embedding>::new(
            [metadata::name.id()],
            WemmIdentity {
                model_root: root,
                kernel_profile: GB10_NATIVE_BF16_PROFILE,
            },
            DEFAULT_WINDOW_CAP,
        )
        .unwrap()
        .fragment()
    }

    #[test]
    fn the_index_identity_is_the_model_content_not_the_collection_carrying_it() {
        let base = |repo: &mut MemoryRepo| complete_root(repo, "weights", "b", 8, "{{ m }}");
        let (first_collection, first) = published_root(0x31, base);
        let (second_collection, second) = published_root(0x32, base);
        assert_ne!(first_collection, second_collection, "two collections");
        assert_eq!(first, second, "one model");
        assert_eq!(index_of(first), index_of(second), "one index identity");
        for (what, build) in [
            (
                "weights",
                Box::new(|repo: &mut MemoryRepo| complete_root(repo, "other", "b", 8, "{{ m }}"))
                    as Box<dyn FnOnce(&mut MemoryRepo) -> Fragment>,
            ),
            (
                "tokenizer",
                Box::new(|repo: &mut MemoryRepo| complete_root(repo, "weights", "c", 8, "{{ m }}")),
            ),
            (
                "config",
                Box::new(|repo: &mut MemoryRepo| complete_root(repo, "weights", "b", 9, "{{ m }}")),
            ),
            (
                "template",
                Box::new(|repo: &mut MemoryRepo| {
                    complete_root(repo, "weights", "b", 8, "{{ m }} ")
                }),
            ),
        ] {
            let (_, changed) = published_root(0x31, build);
            assert_ne!(changed, first, "a changed {what} is another model");
            assert_ne!(
                index_of(changed),
                index_of(first),
                "a changed {what} is another index"
            );
        }
    }

    /// A descriptor written before the identity became content-only states
    /// the carrying collection and three asset handles. They are facts this
    /// mapping no longer models, so binding ignores them (open world).
    #[test]
    fn a_descriptor_with_retired_asset_arguments_still_binds() {
        let index = mapping();
        let (_, descriptor) = descriptor(&index);
        let mapping_id = triblespace_core::collection::descriptor::mapping(descriptor.facts())
            .unwrap()
            .unwrap();
        let mut older = descriptor.clone();
        for retired in [
            mary::format::attrs::model_collection.id(),
            id_hex!("C1FEADBAD086C8A7EC00C1080D7E2F13"),
            id_hex!("438EE4FAA8F9465B38DD8CCAD595D3DE"),
            id_hex!("6850FB2F899C4EA04257547C9C5D63BC"),
        ] {
            older.facts_mut().insert(&Trible::force(
                &mapping_id,
                &retired,
                &Inline::<Handle<RawBytes>>::new([7; 32]),
            ));
        }
        assert_eq!(
            WemmIndex::<Embedding>::bind(&Fragment::empty(), &older).unwrap(),
            index
        );
    }

    #[test]
    fn each_semantic_pin_changes_identity_but_neither_packaging_nor_order_is_a_pin() {
        let index = mapping();
        let original = identity();
        let mut alternatives = [original; 2];
        alternatives[0].model_root = Id::new([7; 16]).unwrap();
        alternatives[1].kernel_profile = Id::new([7; 16]).unwrap();
        for identity in alternatives {
            assert_ne!(identity, original);
            assert_ne!(
                index.fragment(),
                WemmIndex::<Embedding>::new(
                    index.content_attributes(),
                    identity,
                    DEFAULT_WINDOW_CAP
                )
                .unwrap()
                .fragment()
            );
        }
        assert_ne!(
            index.fragment(),
            WemmIndex::<Embedding>::new(index.content_attributes(), original, 4)
                .unwrap()
                .fragment(),
            "the window cap is part of the function"
        );
        assert_eq!(model_root.id(), mary::format::attrs::model_root.id());
        assert_eq!(
            semantic_content_attribute.id(),
            crate::semantic_attributes::semantic_content_attribute.id()
        );
    }

    #[test]
    fn loaded_selection_cannot_be_relabelled_and_hardware_is_not_an_architecture_guess() {
        let id = identity();
        assert!(id.require_loaded_selection(id.model_root).is_ok());
        assert!(id
            .require_loaded_selection(Id::new([9; 16]).unwrap())
            .is_err());
        let mut other = id;
        other.kernel_profile = Id::new([9; 16]).unwrap();
        assert!(other.require_loaded_selection(id.model_root).is_err());
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
        let index =
            WemmIndex::<Embedding>::new([metadata::name.id()], id, DEFAULT_WINDOW_CAP).unwrap();
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

    fn text(bytes: &[u8]) -> Option<String> {
        match classify(bytes)? {
            Input::Text(text) => Some(text.into_owned()),
            Input::Image(_) => None,
        }
    }

    /// A one-page PDF whose text layer is `lines`, one text line each.
    fn pdf(lines: &[&str]) -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};
        let mut document = Document::with_version("1.5");
        let pages = document.new_object_id();
        let font = document.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier",
        });
        let mut operations = vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("TL", vec![14.into()]),
            Operation::new("Td", vec![50.into(), 800.into()]),
        ];
        for line in lines {
            operations.push(Operation::new("'", vec![Object::string_literal(*line)]));
        }
        operations.push(Operation::new("ET", vec![]));
        let content = Content { operations }.encode().unwrap();
        let content = document.add_object(Stream::new(dictionary! {}, content));
        // On the page itself: lopdf 0.44 does not read fonts a page inherits.
        let page = document.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages, "Contents" => content,
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font } },
        });
        document.objects.insert(
            pages,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page.into()],
                "Count" => 1,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            }),
        );
        let catalog = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        document.trailer.set("Root", catalog);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn content_is_read_by_its_bytes_and_unreadable_bytes_are_nothing() {
        for input in [
            b"\0".as_slice(),
            b"\xff\xfe\x00\x01",
            b"GIF89a\x01\0\x01\0",
            b"BM\0",
            b"RIFF\x01\0",
            b"",
            b"  \n",
            b"%PDF-1.7 without a text layer",
        ] {
            assert!(classify(input).is_none(), "{input:?}");
        }
        for note in [
            "BM25 ranks documents",
            "RIFF is an audio container",
            "GIF89a describes a format",
        ] {
            assert_eq!(text(note.as_bytes()).as_deref(), Some(note));
        }
        assert!(matches!(
            classify(b"\x89PNG\r\n\x1a\n"),
            Some(Input::Image(_))
        ));
        assert!(matches!(classify(b"\xff\xd8\xff"), Some(Input::Image(_))));
        let long = "exact raw text ".repeat(10_000);
        assert_eq!(
            text(long.as_bytes()),
            Some(long),
            "windows cut text; classification never truncates"
        );
        let layer = text(&pdf(&[
            "The night train leaves at nine.",
            "Berths are narrow.",
        ]))
        .unwrap();
        assert!(
            layer.contains("The night train leaves at nine.")
                && layer.contains("Berths are narrow."),
            "{layer:?}"
        );
    }

    #[test]
    fn html_is_read_as_its_text() {
        let page = "<!DOCTYPE html><html><head><style>p{x:1}</style><script>var a=1;</script><title>Hydra</title></head><body><p>Two robot heads &amp; a desk.</p></body></html>";
        assert_eq!(
            text(page.as_bytes()).as_deref(),
            Some("Hydra Two robot heads & a desk.")
        );
        assert!(classify(b"<html><body><script>only();</script></body></html>").is_none());
        let markup = "<p>a paragraph that is not a whole page</p>";
        assert_eq!(text(markup.as_bytes()).as_deref(), Some(markup));
    }

    #[test]
    fn windows_pack_whole_lines_then_words_then_characters_up_to_the_cap() {
        let never = |_: &str, _: &str| false;
        let four_words = |window: &str| window.split_whitespace().count() <= 4;
        assert_eq!(
            windows(
                "one two\nthree four\nfive six seven\neight\n",
                16,
                four_words,
                never
            ),
            ["one two\nthree four", "five six seven\neight"]
        );
        let ten_bytes = |window: &str| window.trim().len() <= 10;
        let text = "  ab cd\nefghijkl mn opq\nrstuvwxyz\u{e4}BCDEFG\n";
        let all = ["ab cd", "efghijkl", "mn opq", "rstuvwxyz", "\u{e4}BCDEFG"];
        assert_eq!(windows(text, 16, ten_bytes, never), all);
        assert_eq!(windows(text, 2, ten_bytes, never), all[..2]);
        assert!(windows(text, 0, ten_bytes, never).is_empty());
        assert!(windows(" \n\t", 16, ten_bytes, never).is_empty());
        assert_eq!(windows("ab", 16, |_| false, never), ["a", "b"]);
        // A `same` that is true where `ten_bytes` must agree (only trimmed
        // whitespace added) cuts the same windows with fewer probes.
        let spaced = |a: &str, b: &str| b[a.len()..].chars().all(char::is_whitespace);
        let blank = format!("ab\n{}cd ef\n\n \ngh{}ij", "\n".repeat(50), " ".repeat(30));
        let counted = |skip: bool| {
            let mut probes = 0;
            let cut = windows(
                &blank,
                16,
                |w| {
                    probes += 1;
                    ten_bytes(w)
                },
                |a, b| skip && spaced(a, b),
            );
            (cut, probes)
        };
        let (plain, skip) = (counted(false), counted(true));
        assert_eq!(plain.0, ["ab", "cd ef", "gh", "ij"]);
        assert_eq!(plain.0, skip.0);
        assert!(skip.1 < plain.1, "{} < {}", skip.1, plain.1);
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

    /// The checkpoint codec of WEMM_CHECKPOINT_DIR (the pinned
    /// `tokenizer.json` and `chat_template.jinja`).
    #[cfg(feature = "semantic-wemm-cuda")]
    fn checkpoint_codec() -> mary::models::qwen3_5::input_codec::InputCodec {
        let dir = std::env::var("WEMM_CHECKPOINT_DIR").expect("set WEMM_CHECKPOINT_DIR");
        let assets = std::path::PathBuf::from(dir);
        mary::models::qwen3_5::input_codec::InputCodec::from_assets(
            &std::fs::read(assets.join("tokenizer.json")).unwrap(),
            &std::fs::read(assets.join("chat_template.jinja")).unwrap(),
        )
        .unwrap()
    }

    /// One cut of `text` timed (wall, this thread) with its probe count:
    /// `plain` probes the tokenizer only, `refusal` is [`window_fits`] with
    /// nothing skipped (the cut before `same_text`), `cut` is [`cut_windows`].
    #[cfg(feature = "semantic-wemm-cuda")]
    fn timed_cut<'t>(
        codec: &mary::models::qwen3_5::input_codec::InputCodec,
        variant: &str,
        text: &'t str,
    ) -> (Vec<&'t str>, usize, f64) {
        let started = std::time::Instant::now();
        let mut probes = 0;
        let (cut, probes) = match variant {
            "plain" => {
                let fits = |w: &str| {
                    probes += 1;
                    codec
                        .text(w)
                        .is_ok_and(|ids| ids.as_slice().len() <= WINDOW_IDS)
                };
                (
                    windows(text, DEFAULT_WINDOW_CAP, fits, |_, _| false),
                    probes,
                )
            }
            "refusal" => {
                let fits = |w: &str| {
                    probes += 1;
                    window_fits(codec, w)
                };
                (
                    windows(text, DEFAULT_WINDOW_CAP, fits, |_, _| false),
                    probes,
                )
            }
            "cut" => cut_windows(codec, text, DEFAULT_WINDOW_CAP),
            other => panic!("no cut {other}"),
        };
        (cut, probes, started.elapsed().as_secs_f64())
    }

    /// The cuts on real content, CPU only, byte for byte: every window of
    /// every sample under each variant of [`timed_cut`] that WEMM_CUTS names
    /// (default `plain,refusal,cut`), compared with the first. Prints per
    /// content the bytes, what it classified as, its windows, and each cut's
    /// probes and time (wall, one thread, release). WEMM_SAMPLE_DIR holds
    /// content files, read in name order.
    #[cfg(feature = "semantic-wemm-cuda")]
    #[test]
    #[ignore = "requires WEMM_CHECKPOINT_DIR and WEMM_SAMPLE_DIR; CPU only"]
    fn every_cut_gives_the_same_windows_on_real_content() {
        let codec = checkpoint_codec();
        let cuts = std::env::var("WEMM_CUTS").unwrap_or("plain,refusal,cut".into());
        let cuts: Vec<&str> = cuts.split(',').collect();
        let dir = std::env::var("WEMM_SAMPLE_DIR").expect("set WEMM_SAMPLE_DIR");
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        paths.sort();
        assert!(!paths.is_empty());
        let mut totals = vec![(0usize, 0.0f64); cuts.len()];
        let mut windows_total = 0;
        for path in &paths {
            let bytes = std::fs::read(path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy();
            let started = std::time::Instant::now();
            let input = classify(&bytes);
            let classify_s = started.elapsed().as_secs_f64();
            let (kind, text_len, report) = match &input {
                Some(Input::Text(text)) => {
                    let mut report = String::new();
                    let mut first: Option<Vec<&str>> = None;
                    for (variant, total) in cuts.iter().zip(&mut totals) {
                        let (cut, probes, seconds) = timed_cut(&codec, variant, text);
                        total.0 += probes;
                        total.1 += seconds;
                        report += &format!(" {variant}_probes={probes} {variant}_s={seconds:.3}");
                        match &first {
                            Some(first) => assert_eq!(first, &cut, "{name} {variant}"),
                            None => first = Some(cut),
                        }
                    }
                    let n = first.map_or(0, |cut| cut.len());
                    windows_total += n;
                    ("text", text.len(), format!(" windows={n}{report}"))
                }
                Some(Input::Image(_)) => ("image", 0, String::new()),
                None => ("none", 0, String::new()),
            };
            eprintln!(
                "content {name} bytes={} kind={kind} text_bytes={text_len} classify_s={classify_s:.3}{report}",
                bytes.len()
            );
        }
        let totals: Vec<String> = cuts
            .iter()
            .zip(&totals)
            .map(|(v, (probes, s))| format!("{v}_probes={probes} {v}_s={s:.3}"))
            .collect();
        eprintln!(
            "total contents={} windows={windows_total} {}",
            paths.len(),
            totals.join(" ")
        );
    }

    /// [`cut_all`] against [`cut_windows`] text by text on real content,
    /// CPU only: the same windows per text and so the same batches of
    /// [`WINDOW_BATCH`] windows, in the same order, for the forward. All
    /// sample texts form one foundation here. Prints both wall times.
    #[cfg(feature = "semantic-wemm-cuda")]
    #[test]
    #[ignore = "requires WEMM_CHECKPOINT_DIR and WEMM_SAMPLE_DIR; CPU only"]
    fn parallel_cut_hands_the_forward_the_sequential_batches() {
        let codec = checkpoint_codec();
        let dir = std::env::var("WEMM_SAMPLE_DIR").expect("set WEMM_SAMPLE_DIR");
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        paths.sort();
        let mut texts = Vec::new();
        for path in &paths {
            let bytes = std::fs::read(path).unwrap();
            if let Some(Input::Text(text)) = classify(&bytes) {
                let raw = *blake3::hash(&bytes).as_bytes();
                texts.push((raw, text.into_owned()));
            }
        }
        assert!(texts.len() > CUT_THREADS);
        let batches = |cuts: &[Vec<&str>]| -> Vec<Vec<([u8; 32], String)>> {
            let windows: Vec<(&[u8; 32], &str)> = texts
                .iter()
                .zip(cuts)
                .flat_map(|((raw, _), cut)| cut.iter().map(move |w| (raw, *w)))
                .collect();
            windows
                .chunks(WINDOW_BATCH)
                .map(|chunk| chunk.iter().map(|(r, w)| (**r, w.to_string())).collect())
                .collect()
        };
        let started = std::time::Instant::now();
        let sequential: Vec<Vec<&str>> = texts
            .iter()
            .map(|(_, text)| cut_windows(&codec, text, DEFAULT_WINDOW_CAP).0)
            .collect();
        let sequential_s = started.elapsed().as_secs_f64();
        let started = std::time::Instant::now();
        let parallel = cut_all(&codec, &texts, DEFAULT_WINDOW_CAP);
        let parallel_s = started.elapsed().as_secs_f64();
        assert_eq!(sequential, parallel);
        let (sequential, parallel) = (batches(&sequential), batches(&parallel));
        assert_eq!(sequential, parallel);
        eprintln!(
            "parallel texts={} batches={} windows={} threads={CUT_THREADS} sequential_s={sequential_s:.3} parallel_s={parallel_s:.3} identical=yes",
            texts.len(),
            parallel.len(),
            parallel.iter().map(Vec::len).sum::<usize>()
        );
    }

    /// Synthetic blank runs, the shape `same_text` exists for: the cut with
    /// nothing skipped against [`cut_windows`], byte for byte, each timed,
    /// and then all selected cases through [`cut_all`] (where a cut slower
    /// than [`SLOW_CUT`] logs its line). WEMM_BLANK_CASES picks cases by
    /// name (default all); WEMM_BLANK_OLD=0 times only the new cut.
    #[cfg(feature = "semantic-wemm-cuda")]
    #[test]
    #[ignore = "requires WEMM_CHECKPOINT_DIR; CPU only; the old cut is quadratic here"]
    fn blank_runs_cut_the_same_windows() {
        use mary::models::qwen3_5::input_codec::MAX_TEXT_BYTES;
        let codec = checkpoint_codec();
        let prose = |from: usize, n: usize| -> String {
            (from..from + n)
                .map(|i| format!("Entry {i}: the lighthouse keeper trimmed the lamp wick, wound the clockwork that turns the lens and logged each passing ship.\n"))
                .collect()
        };
        let words = |n: usize| -> String { (0..n).map(|i| format!("w{i}\n")).collect() };
        let blank = |n: usize| "\n".repeat(n);
        let cases: Vec<(&str, String)> = vec![
            ("lines-10k", prose(0, 2) + &blank(10_000) + &prose(2, 200)),
            ("lines-100k", prose(0, 2) + &blank(100_000) + &prose(2, 200)),
            ("lines-300k", prose(0, 2) + &blank(300_000) + &prose(2, 200)),
            ("lines-900k", prose(0, 2) + &blank(900_000) + &prose(2, 200)),
            ("words-900k", prose(0, 2) + &blank(900_000) + &words(2000)),
            (
                "spaces-900k",
                prose(0, 2) + &"   \n".repeat(225_000) + &prose(2, 200),
            ),
            (
                "cross-1m",
                "hello\n".to_string() + &blank(MAX_TEXT_BYTES) + &prose(0, 200),
            ),
        ];
        let pick = std::env::var("WEMM_BLANK_CASES").ok();
        let old = std::env::var("WEMM_BLANK_OLD").map_or(true, |v| v != "0");
        let mut ran = Vec::new();
        for (name, text) in &cases {
            if pick
                .as_ref()
                .is_some_and(|pick| !pick.split(',').any(|p| p == *name))
            {
                continue;
            }
            let (cut, probes, seconds) = timed_cut(&codec, "cut", text);
            let mut line = format!(
                "blank {name} bytes={} windows={} cut_probes={probes} cut_s={seconds:.3}",
                text.len(),
                cut.len()
            );
            if old {
                let (before, probes, seconds) = timed_cut(&codec, "refusal", text);
                assert_eq!(before, cut, "{name}");
                line += &format!(" refusal_probes={probes} refusal_s={seconds:.3} identical=yes");
            }
            eprintln!("{line}");
            ran.push((*blake3::hash(text.as_bytes()).as_bytes(), text.clone()));
        }
        assert!(!ran.is_empty(), "no case selected");
        let started = std::time::Instant::now();
        let parallel = cut_all(&codec, &ran, DEFAULT_WINDOW_CAP);
        for ((_, text), cut) in ran.iter().zip(&parallel) {
            assert_eq!(&cut_windows(&codec, text, DEFAULT_WINDOW_CAP).0, cut);
        }
        eprintln!(
            "blank cut_all cases={} parallel_s={:.3} identical=yes",
            ran.len(),
            started.elapsed().as_secs_f64()
        );
    }

    /// The real model on a scratch in-memory store: rows per content handle,
    /// and a query only the long text's later window matches scoring that
    /// handle highest. Prints bind, per-item and query latency. The runner
    /// sets WEMM_PILE (opened read-only and left unmodified until this process
    /// exits), WEMM_ASSETS, WEMM_ROOT, WEMM_GATE_PNG, and
    /// WEMM_GATE_OVERSIZE_PNG (an image wider than 4096 pixels).
    #[cfg(feature = "semantic-wemm-cuda")]
    #[test]
    #[ignore = "requires a reserved GB10 and a pile holding the complete WeMM root"]
    fn native_windows_rows_per_handle_and_maximum_scoring() {
        use mary::models::qwen3_5::input_codec::InputCodec;
        use mary::models::qwen3_5::native::{Assets, NativeWemm};
        use std::time::Instant;
        use triblespace_core::attribute::Attribute;
        use triblespace_core::collection::CollectionSnapshotExt;
        use triblespace_core::repo::BlobStorePut;

        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("set {name}"));
        // WEMM_PILE: a pile whose `models` collection (WEMM_MODELS, 64 hex
        // digits) holds the complete root WEMM_ROOT. Never written here.
        let path = std::path::PathBuf::from(var("WEMM_PILE"));
        let store = mary::persist::read_model_pile_snapshot_read_only(&path).unwrap();
        let handle = mary::model_collection::parse_collection_handle(&var("WEMM_MODELS")).unwrap();
        let collection = mary::model_collection::open_model_collection(&store, handle).unwrap();
        let model =
            mary::model_collection::snapshot_model_collection_for(&store, collection).unwrap();
        let root = Id::from_hex(&var("WEMM_ROOT")).unwrap();
        let assets = Assets::from_model_root(model.facts(), model.store(), root).unwrap();
        let codec: InputCodec = assets.codec().clone();
        let mut aliases =
            mary::nn::cuda_bf16_alias::CudaBf16Aliases::new(Default::default(), 759).unwrap();
        let started = Instant::now();
        // SAFETY: the runner keeps the model pile unmodified until this
        // process exits.
        let native = unsafe {
            NativeWemm::from_frozen(
                model.facts(),
                model.store(),
                root,
                assets,
                &mut aliases,
                |_, _, _, _| Ok(()),
            )
        }
        .unwrap();
        eprintln!("bind_ms={}", started.elapsed().as_millis());
        let identity = WemmIdentity {
            model_root: root,
            kernel_profile: GB10_NATIVE_BF16_PROFILE,
        };
        let runtime = Rc::new(RefCell::new(
            WemmRuntime::from_native(identity, native, codec.clone()).unwrap(),
        ));

        let filler: String = (0..40)
            .map(|i| format!("Entry {i}: the lighthouse keeper trimmed the lamp wick, wound the clockwork that turns the lens and logged each passing ship.\n"))
            .collect();
        let long = format!("{filler}Repotting an orchid: lift it from its old pot, cut away the rotten roots and set it in fresh coarse bark, never in garden soil.\nWater the orchid sparingly for a week afterwards and keep it out of direct sun while new roots grow.\n");
        let long_windows = cut_windows(&codec, &long, DEFAULT_WINDOW_CAP).0;
        assert!(long_windows.len() > 2);
        assert!(!long_windows[0].contains("orchid"));
        assert!(long_windows.last().unwrap().contains("orchid"));
        let pdf = pdf(&[
            "The night train to Vienna leaves Leiden at nine in the evening.",
            "Each sleeper cabin holds two berths and a small washbasin.",
        ]);
        let pdf_windows = cut_windows(&codec, &pdf_text(&pdf), DEFAULT_WINDOW_CAP)
            .0
            .len();
        let items: [(&str, Vec<u8>, usize); 6] = [
            (
                "short",
                b"A bowl of tomato soup with fresh basil and garlic bread.".to_vec(),
                1,
            ),
            ("long", long.clone().into_bytes(), long_windows.len()),
            ("pdf", pdf, pdf_windows),
            ("png", std::fs::read(var("WEMM_GATE_PNG")).unwrap(), 1),
            (
                "oversize-png",
                std::fs::read(var("WEMM_GATE_OVERSIZE_PNG")).unwrap(),
                0,
            ),
            ("binary", vec![0, 159, 146, 150, 255, 0, 1, 2], 0),
        ];

        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let content = Attribute::<Handle<RawBytes>>::named("wemm-gate-content");
        let mapping =
            WemmIndex::<Embedding>::new([content.id()], identity, DEFAULT_WINDOW_CAP).unwrap();
        let mut store = MemoryRepo::default();
        let source = store.collection("wemm-gate", policy.clone()).unwrap();
        let mut handles = Vec::new();
        for (entity, (_, bytes, _)) in items.iter().enumerate() {
            let handle = store
                .put::<RawBytes, _>(Blob::<RawBytes>::new(bytes.clone().into()))
                .unwrap();
            let mut facts = TribleSet::new();
            facts.insert(&Trible::force(
                &Id::new([entity as u8 + 1; 16]).unwrap(),
                &content.id(),
                &handle,
            ));
            store.commit(source, &key, Fragment::from(facts)).unwrap();
            handles.push(handle);
        }

        let reader = store.snapshot().unwrap();
        // The first pass also compiles the kernels; the second is warm.
        with_wemm_runtime(Rc::clone(&runtime), || {
            for pass in ["cold", "warm"] {
                for ((name, _, expected), handle) in items.iter().zip(&handles) {
                    let mut facts = TribleSet::new();
                    facts.insert(&Trible::force(
                        &Id::new([1; 16]).unwrap(),
                        &content.id(),
                        handle,
                    ));
                    let started = Instant::now();
                    let member = mapping.map(&facts.to_blob(), &reader).unwrap();
                    let bytes = member.bytes.as_ref();
                    // The carrier's footer: `N_u64 | D_u64`.
                    let rows =
                        u64::from_le_bytes(bytes[bytes.len() - 16..][..8].try_into().unwrap());
                    eprintln!(
                        "{pass} item={name} rows={rows} ms={}",
                        started.elapsed().as_millis()
                    );
                    assert_eq!(rows, *expected as u64, "{name}");
                }
            }
        })
        .unwrap();

        let target: Collection<NvFp4CosineSet<Embedding>> =
            store.derive_with(source, mapping.clone(), policy).unwrap();
        let index: NvFp4CosineIndex<Embedding> = with_wemm_runtime(Rc::clone(&runtime), || {
            let snapshot = futures::executor::block_on(
                store.maintain_with::<WemmIndex<Embedding>>(target, &key),
            )
            .unwrap();
            snapshot.collection(target).unwrap().view().unwrap()
        })
        .unwrap();
        assert_eq!(index.len(), items.iter().map(|item| item.2).sum::<usize>());
        let started = Instant::now();
        let cosines = with_wemm_runtime(runtime, || {
            mapping.reconstructed_cosines(
                &index,
                "How do I repot an orchid, and what should I plant it in?",
            )
        })
        .unwrap()
        .unwrap();
        eprintln!("query_ms={}", started.elapsed().as_millis());
        for ((name, ..), handle) in items.iter().zip(&handles) {
            eprintln!("cosine {name} {:?}", cosines.cosine(handle));
        }
        let long_score = cosines.cosine(&handles[1]).unwrap();
        for (at, handle) in handles.iter().enumerate() {
            if at != 1 {
                assert!(cosines
                    .cosine(handle)
                    .is_none_or(|score| score < long_score));
            }
        }
        assert!(cosines.cosine(&handles[4]).is_none() && cosines.cosine(&handles[5]).is_none());
    }
}
