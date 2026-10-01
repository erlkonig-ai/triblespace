//! The semantic index: an NVFP4 cosine set derived straight from source
//! facts through a nomic model that lives in the same pile.
//!
//! [`SemanticIndex`] is a [`DeriveMapping`] from one `SimpleArchive`
//! source (the Files collection, say) to [`NvFp4CosineSet`]. Its descriptor
//! names what to embed (any number of attributes whose values are handles to
//! content bytes), the one model that embeds them ([`SemanticModel`]: a
//! vision root, or a text root with its tokenizer root) in a named model
//! collection, the compute class the index is canonical on, and the row
//! dimension. The selected references are identity; unrelated observations
//! and the collection's physical member archives are not. A new selection is
//! a new descriptor and the old index stays readable.
//!
//! A row is keyed by the content handle it embeds: the 32-byte value `V` of
//! a selected `(entity, attribute, V)` fact. The index therefore asserts
//! nothing about how many values an entity has. A multi-valued attribute is
//! more values, and one blob held by several entities of one source member
//! is embedded once, as one row. The handles of the mapping of a union are
//! exactly the union of the mappings' handles. So are the rows when
//! embedding reproduces bit for bit, which makes the mapping a homomorphism
//! into the NVFP4 carrier's join; otherwise a blob that two members hold
//! carries one row per differing embedding (see below). A reader reaches
//! the entities through the source on the same value: the rows of an index
//! constrain `v`, and `pattern(e, a, v)` over the source (with `a` bound to
//! an attribute, or left free for "any attached content") names who holds
//! it. See [`crate::nvfp4::ReconstructedCosines`].
//!
//! One index is one model. Images go through nomic-embed-vision-v1.5 and
//! texts through the document side of nomic-embed-text-v1.5, the two halves
//! of one aligned space, so a text query finds an image by cosine alone. But
//! text-to-text cosines in this space sit near 0.7 and text-to-image near
//! 0.07, so the two kinds cannot share a floor or a ranking. The kind of a
//! row is the index it lives in: a vision index holds a row for every value
//! whose bytes the image decoder recognises, a text index for every value
//! whose bytes are a PDF with a text layer or UTF-8 text (HTML reduced to
//! its text). The two sets are disjoint by construction, because the bytes
//! alone decide ([`classify`]). A reader who wants both queries both, each
//! with its own floor, and unions them with `or!`.
//!
//! The text model reads the first 2,048 tokens of a document; chunk rows for
//! long documents are the follow-up. A scanned PDF has no text layer and
//! waits for an OCR model in the pile. Rows are the two-stage NVFP4 form
//! settled for the index side on 2026-09-11 (97.6 % recall\@10 against f32
//! on our own prose). No exact vector is stored per row, so this index is
//! read through its reconstructions
//! ([`crate::nvfp4::NvFp4CosineIndex::reconstructed_cosines`]); the exact
//! reranking reads of `top_k`, `above` and `similar_to` do not apply to it.
//!
//! The mapping is a function of the content bytes and the selected model
//! roots on the compute class it names. A GPU is not bit-deterministic across
//! hardware, so the descriptor carries the class it was computed on and the
//! mapping is pinned to it ([`DeriveMapping::computable_here`]): maintenance
//! on another class derives nothing, raises no error and still carries the
//! index, whose DERIVE results arrive by replication, and
//! [`SemanticIndex::map`] refuses to compute there. Any key the index
//! admits derives a file on the class, not only the file's writer, and a
//! content that already has a row whose bytes are here or can be fetched is
//! not embedded again. Within the class two embeddings of one
//! content need not agree bit for bit. A blob that two source members both
//! hold is embedded by both, and when the two rows differ the carrier keeps
//! both under the one content handle: its rows are a set, so the join stays
//! total. A reader binds each content handle once and scores it by the best
//! of its rows ([`crate::nvfp4::ReconstructedCosines`]). Bit-reproducible
//! embedding is therefore an optimisation (identical rows collapse into one),
//! not a condition of the join. A golden vector checked before publishing is
//! the follow-up that makes a driver update visible.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;

use anybytes::{Bytes, View};
use mary::embed::LocalEmbedder;
use mary::selection::{
    load_keymap_from_graph, load_tokenizer_from_graph, ModelSelector, TokenizerSelector,
};
use triblespace_core::blob::encodings::rawbytes::RawBytes;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{
    Collection, CollectionHandle, CollectionOperationError, CollectionSnapshotExt, Cover,
    DeriveMapping,
};
use triblespace_core::id::{id_hex, ExclusiveId, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::shortstring::ShortString;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::macros::{attributes, entity, find};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::query::TriblePattern;
use triblespace_core::repo::{BlobStoreGet, StoreRead};
use triblespace_core::trible::{Fragment, TribleSet, TRIBLE_LEN};

use crate::nvfp4::{encode_rows, nvfp4_dimension, NvFp4CosineSet, StoredRow, HANDLE_LEN};

/// The mapping algorithm: the values of the selected attributes of a
/// `SimpleArchive` source, each a handle to content bytes, embedded through
/// the one nomic v1.5 model the descriptor pins (vision for images, the text
/// model's document side for PDF text layers and UTF-8), to two-stage NVFP4
/// rows keyed by the content handle.
///
/// Minted with `trible genid` on 2026-09-27:
/// `523C31F03F049CA26A0E847CAAFC08F7`. It replaces
/// `2B69128192930EE0782CCA03B97677F5` of 2026-09-14, whose rows were keyed
/// `[model root | entity]` and `[attribute | entity]`: that key claimed one
/// value per entity, so a second value under one key could not join, and its
/// row named an entity rather than a value the source could be joined on. Its
/// descriptors and results are not rewritten or implicitly rebound. Earlier
/// ids: `021EE2F74220BDAE30CC35FB08FC9427` (archive-pinning),
/// `4704CB1C2A54CDBF96F54BFFC53A0733` and
/// `B94732E5DA22EFE9A4961BE906F5C500`. A mapping that computes something
/// else is a different function and gets a different id.
pub const NOMIC_ATTRIBUTES_TO_NVFP4: Id = id_hex!("523C31F03F049CA26A0E847CAAFC08F7");

attributes! {
    /// Historical archive-pinning argument, retained with its original id.
    /// A member archive of the pile's model collection carrying the roots
    /// named below and their tokenizer; repeatable. These pin the exact
    /// model bytes. Minted 2026-09-13.
    "FC76F2B04ACC2CE2F74BDC3CBEDBF37B" as pub semantic_model_archive: Handle<SimpleArchive>;
    /// The vision model root in the named collection, for a vision index.
    /// Minted 2026-09-13.
    "4ADAD28EE2152E087625A04BB7CA449B" as pub semantic_vision_root: GenId;
    /// The text model root in the named collection, for a text index.
    /// Minted 2026-09-13.
    "9273B441A9D0EEC0778A5B5488EB6851" as pub semantic_text_root: GenId;
    /// The text tokenizer root in the named collection. Minted with
    /// `trible genid` 2026-09-14: `E6A241C22B0457CD24AE65C1FC6AC177`.
    "E6A241C22B0457CD24AE65C1FC6AC177" as pub semantic_tokenizer_root: GenId;
}

pub use crate::semantic_attributes::{semantic_compute, semantic_content_attribute};

/// The containing model collection, shared with Mary's model references.
pub use mary::format::attrs::model_collection as semantic_model_collection;

/// The compute class of this process: the hardware the embeddings are
/// computed on. `gb10` is the two Sparks (aarch64 Linux); anything else is
/// named honestly and cannot maintain an index computed there.
///
/// JP, 2026-09-10: encode the hardware in the type and make the Sparks
/// canonical. A kernel identity inside the class is the follow-up.
pub fn local_compute() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "gb10"
    } else if cfg!(target_os = "macos") {
        "apple"
    } else {
        "other"
    }
}

struct NomicAttributesToNvFp4Recipe;

impl MetaDescribe for NomicAttributesToNvFp4Recipe {
    fn describe() -> Fragment {
        let id = NOMIC_ATTRIBUTES_TO_NVFP4;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "nomic-content-to-nvfp4",
            metadata::description: "The values of selected attributes of a SimpleArchive source, each a handle to content bytes, embedded through the one nomic-embed v1.5 model the descriptor pins (vision for images, the text model's document side for PDF text layers and UTF-8 text), as two-stage NVFP4 cosine rows keyed by the content handle. The bytes alone decide whether the model has anything to read in a value.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// The one model a semantic index embeds with, which is also the kind of
/// every row it holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticModel {
    /// Raster images through a vision model root.
    Vision {
        /// The vision model root in the named collection.
        root: Id,
    },
    /// PDF text layers and UTF-8 text through a text model root's document
    /// side.
    Text {
        /// The text model root in the named collection.
        root: Id,
        /// Its tokenizer root in the same collection.
        tokenizer: Id,
    },
}

/// One concrete semantic index: what to embed, with which model, on which
/// compute, into rows of which dimension.
pub struct SemanticIndex<E: BlobEncoding> {
    /// Attributes whose values are handles to content bytes.
    pub content_attributes: BTreeSet<Id>,
    /// The collection containing the selected model roots.
    /// Its physical support does not participate in this index's identity.
    pub model_collection: CollectionHandle,
    /// The model that embeds every row, and so the kind of every row.
    pub model: SemanticModel,
    /// The compute class the index is canonical on.
    pub compute: String,
    /// Row dimension (768 for the nomic v1.5 pair).
    pub dimension: usize,
    encoding: PhantomData<E>,
}

// The encoding parameter is a marker; the index's identity is its fields.
impl<E: BlobEncoding> Clone for SemanticIndex<E> {
    fn clone(&self) -> Self {
        Self {
            content_attributes: self.content_attributes.clone(),
            model_collection: self.model_collection,
            model: self.model,
            compute: self.compute.clone(),
            dimension: self.dimension,
            encoding: PhantomData,
        }
    }
}

impl<E: BlobEncoding> PartialEq for SemanticIndex<E> {
    fn eq(&self, other: &Self) -> bool {
        self.content_attributes == other.content_attributes
            && self.model_collection == other.model_collection
            && self.model == other.model
            && self.compute == other.compute
            && self.dimension == other.dimension
    }
}

impl<E: BlobEncoding> Eq for SemanticIndex<E> {}

impl<E: BlobEncoding> std::fmt::Debug for SemanticIndex<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticIndex")
            .field("content_attributes", &self.content_attributes)
            .field("model_collection", &self.model_collection)
            .field("model", &self.model)
            .field("compute", &self.compute)
            .field("dimension", &self.dimension)
            .finish()
    }
}

/// What an index's model reads from one content blob.
enum Input<'a> {
    /// Image bytes for the vision model.
    Image(&'a [u8]),
    /// A document's text for the text model's document side.
    Document(String),
}

impl<E: BlobEncoding> SemanticIndex<E> {
    /// A new index description. `dimension` must be positive and at least
    /// one content attribute must be selected.
    pub fn new(
        content_attributes: impl IntoIterator<Item = Id>,
        model_collection: CollectionHandle,
        model: SemanticModel,
        compute: impl Into<String>,
        dimension: usize,
    ) -> Result<Self, CollectionOperationError> {
        let index = Self {
            content_attributes: content_attributes.into_iter().collect(),
            model_collection,
            model,
            compute: compute.into(),
            dimension,
            encoding: PhantomData,
        };
        index.check()?;
        Ok(index)
    }

    fn check(&self) -> Result<(), CollectionOperationError> {
        if self.dimension == 0 {
            return Err(fatal("semantic index dimension must be positive"));
        }
        if self.content_attributes.is_empty() {
            return Err(fatal("semantic index embeds nothing: no content attribute"));
        }
        if self.compute.is_empty() {
            return Err(fatal("semantic index names no compute class"));
        }
        Ok(())
    }

    /// Every distinct value under a selected attribute in `source`: the
    /// candidate row keys. A set, because a repeated fact is one fact and a
    /// value held twice is one value.
    fn values(&self, source: &Blob<SimpleArchive>) -> BTreeSet<[u8; HANDLE_LEN]> {
        source
            .bytes
            .as_ref()
            .chunks_exact(TRIBLE_LEN)
            .filter(|raw| {
                self.content_attributes
                    .iter()
                    .any(|attribute| raw[16..32] == attribute[..])
            })
            .map(|raw| raw[32..].try_into().expect("32-byte trible value"))
            .collect()
    }

    /// What this index's model reads in `bytes`, decided by the bytes alone,
    /// or `None` when it has nothing to read there (the value then has no
    /// row, the same answer every time).
    fn model_input<'a>(&self, bytes: &'a [u8]) -> Option<Input<'a>> {
        match self.model {
            SemanticModel::Vision { .. } => image::guess_format(bytes)
                .is_ok()
                .then_some(Input::Image(bytes)),
            SemanticModel::Text { .. } => match classify(bytes) {
                Content::Pdf(text) | Content::Text(text) if !text.trim().is_empty() => {
                    Some(Input::Document(text))
                }
                _ => None,
            },
        }
    }

    /// The rows for `values`, each embedded by `embed` from what the model
    /// reads in its bytes and keyed by the value itself. `embed` answers
    /// `None` for input it cannot embed (an image the decoder rejects), which
    /// is a classification of the bytes and gets no row.
    fn embed_values<R, F>(
        &self,
        values: &BTreeSet<[u8; HANDLE_LEN]>,
        reader: &R,
        mut embed: F,
    ) -> Result<Blob<NvFp4CosineSet<E>>, CollectionOperationError>
    where
        R: BlobStoreGet,
        F: FnMut(Input<'_>) -> Result<Option<Vec<f32>>, CollectionOperationError>,
    {
        let mut rows = Vec::with_capacity(values.len());
        for raw in values {
            let bytes: Bytes = reader
                .get(Inline::<Handle<RawBytes>>::new(*raw))
                .map_err(|source| fatal(source.to_string()))?;
            let Some(input) = self.model_input(bytes.as_ref()) else {
                continue;
            };
            let Some(vector) = embed(input)? else {
                continue;
            };
            if vector.len() != self.dimension {
                return Err(fatal(format!(
                    "model produced {} dimensions, index has {}",
                    vector.len(),
                    self.dimension
                )));
            }
            rows.push(
                StoredRow::quantize(*raw, &vector, self.dimension)
                    .map_err(|source| fatal(source.to_string()))?,
            );
        }
        encode_rows::<E>(self.dimension, rows).map_err(|source| fatal(source.to_string()))
    }

    /// The embedder this index computes with, loaded from the explicitly
    /// named collection through `reader`, the same frozen records and
    /// authorization boundary the source came from.
    fn load_model<R>(&self, reader: &R) -> Result<Rc<Model>, CollectionOperationError>
    where
        R: StoreRead,
    {
        if reader
            .metadata(self.model_collection)
            .map_err(|source| fatal(source.to_string()))?
            .is_none()
        {
            let handle = Handle::<SimpleArchive>::to_hash(self.model_collection);
            return Err(CollectionOperationError::MissingDependency(handle));
        }
        let collection = Collection::<SimpleArchive>::open(reader, self.model_collection)
            .map_err(|source| fatal(format!("semantic index model collection: {source}")))?;
        let snapshot = reader
            .collection(collection)
            .map_err(|source| fatal(format!("semantic index model collection: {source:#}")))?;
        let references = (self.model_collection, self.model);
        // Operational reuse after admission, not model identity: the cheap
        // cover equality guards one thread's last inference observation before
        // materializing its graph. Changed packaging or annotations may reload
        // the runtime once, but cannot rekey the descriptor or derived rows.
        // No graph digest is minted and reuse never skips frozen admission.
        if let Some(model) = MODEL.with(|cache| {
            cache
                .borrow()
                .as_ref()
                .and_then(|(selected, observed, model)| {
                    (*selected == references && observed == snapshot.cover()).then(|| model.clone())
                })
        }) {
            return Ok(model);
        }
        let facts = snapshot
            .view::<TribleSet>()
            .map_err(|source| fatal(format!("semantic index model facts: {source:#}")))?;
        let device = mary::embed::default_device();
        let model = match self.model {
            SemanticModel::Vision { root } => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| {
                        fatal(format!("semantic index vision root {root:X}: {source:#}"))
                    })?;
                Model::Vision(
                    mary::embed::load_nomic_vision_from_keymap(keymap, device).map_err(
                        |source| fatal(format!("semantic index vision model: {source:#}")),
                    )?,
                )
            }
            SemanticModel::Text { root, tokenizer } => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| {
                        fatal(format!("semantic index text root {root:X}: {source:#}"))
                    })?;
                let tokenizer =
                    load_tokenizer_from_graph(&facts, reader, TokenizerSelector::Root(tokenizer))
                        .map_err(|source| {
                        fatal(format!("semantic index text tokenizer: {source:#}"))
                    })?;
                Model::Text(
                    mary::embed::nomic_text_from_parts(keymap, tokenizer, device).map_err(
                        |source| fatal(format!("semantic index text model: {source:#}")),
                    )?,
                )
            }
        };
        let model = Rc::new(model);
        MODEL.with(|cache| {
            *cache.borrow_mut() = Some((references, snapshot.cover().clone(), model.clone()));
        });
        Ok(model)
    }
}

type Backend = mary::nn::backend::B;

enum Model {
    Vision(mary::embed::NomicVisionEmbedder<Backend>),
    Text(mary::embed::NomicTextEmbedder<Backend>),
}

impl Model {
    /// Embed what the index's model reads. A rejected image is a
    /// classification of its bytes (no row); a text model failure is an error.
    fn embed(&self, input: Input<'_>) -> Result<Option<Vec<f32>>, CollectionOperationError> {
        match (self, input) {
            (Model::Vision(vision), Input::Image(bytes)) => Ok(vision.embed_image(bytes).ok()),
            (Model::Text(text), Input::Document(document)) => text
                .embed_document(&document)
                .map(Some)
                .map_err(|source| fatal(format!("text model: {source:#}"))),
            _ => Err(fatal("semantic index model does not read this input")),
        }
    }
}

type ModelReferences = (CollectionHandle, SemanticModel);

thread_local! {
    static MODEL: RefCell<Option<(ModelReferences, Cover<SimpleArchive>, Rc<Model>)>> = const { RefCell::new(None) };
}

fn fatal(message: impl Into<String>) -> CollectionOperationError {
    CollectionOperationError::Fatal(message.into())
}

fn mapping_entity(target: &Fragment) -> Result<Id, CollectionOperationError> {
    triblespace_core::collection::descriptor::mapping(target.facts())
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("semantic index descriptor carries no mapping"))
}

fn scalar_id(facts: &TribleSet, attribute: Id) -> Result<Option<Id>, CollectionOperationError> {
    let raw = triblespace_core::collection::descriptor::mapping_argument(facts, attribute)
        .map_err(|source| fatal(source.to_string()))?;
    raw.map(|raw| {
        Inline::<GenId>::new(raw)
            .try_from_inline::<Id>()
            .map_err(|source| fatal(format!("semantic index: invalid id argument: {source:?}")))
    })
    .transpose()
}

fn repeated_ids(facts: &TribleSet, mapping: Id, attribute: Id) -> BTreeSet<Id> {
    let subject: Inline<GenId> = mapping.to_inline();
    let attribute: Inline<GenId> = attribute.to_inline();
    find!(
        (v: Inline<GenId>),
        facts.pattern::<GenId>(subject, attribute, v)
    )
    .filter_map(|(v,)| v.try_from_inline::<Id>().ok())
    .collect()
}

/// What one content blob is, decided by its bytes alone, so the row a
/// mapping produces is a function of the bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Content {
    /// A raster the vision model can decode.
    Image,
    /// A PDF; its text layer, possibly empty (a scanned document).
    Pdf(String),
    /// Valid UTF-8 text.
    Text(String),
    /// Bytes this index has no model for.
    Other,
}

/// The most a PDF page's decompressed content may inflate to before it is
/// treated as hostile and skipped (lopdf's decompression-bomb guard).
const PDF_PAGE_CONTENT_LIMIT: usize = 64 * 1024 * 1024;

/// Classify content bytes: the image decoder decides first, then the PDF
/// magic, then UTF-8 validity. A file that decodes as an image is an image
/// even if it also happens to be valid UTF-8 (an SVG is text, and the image
/// decoder does not read SVG, so it lands on the text side, which is right).
pub fn classify(bytes: &[u8]) -> Content {
    if image::guess_format(bytes).is_ok() {
        return Content::Image;
    }
    if bytes.starts_with(b"%PDF") {
        return Content::Pdf(pdf_text(bytes));
    }
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.trim().is_empty() => {
            let text = if looks_like_html(text) {
                strip_html(text)
            } else {
                text.to_owned()
            };
            if text.trim().is_empty() {
                Content::Other
            } else {
                Content::Text(head(&text, TEXT_HEAD_BYTES))
            }
        }
        _ => Content::Other,
    }
}

/// The most of a document the text model is given. It reads 2,048 tokens,
/// about eight kilobytes of English; sixteen keeps every model-visible byte
/// and spares the tokenizer a megabyte of HTML it would only discard.
const TEXT_HEAD_BYTES: usize = 16 * 1024;

fn head(text: &str, bytes: usize) -> String {
    if text.len() <= bytes {
        return text.to_owned();
    }
    let mut end = bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn looks_like_html(text: &str) -> bool {
    let start = head(text, 512).to_ascii_lowercase();
    start.contains("<html") || start.contains("<!doctype html") || start.contains("<body")
}

/// The text of an HTML document: script and style blocks removed, tags
/// removed, the five common entities decoded, whitespace collapsed. A page
/// from the web archive is then what its reader saw, which is what a query
/// means by it.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while i < html.len() {
        if lower[i..].starts_with("<script") || lower[i..].starts_with("<style") {
            let close = if lower[i..].starts_with("<script") {
                "</script>"
            } else {
                "</style>"
            };
            match lower[i..].find(close) {
                Some(offset) => i += offset + close.len(),
                None => break,
            }
            out.push(' ');
            continue;
        }
        if html[i..].starts_with('<') {
            match html[i..].find('>') {
                Some(offset) => i += offset + 1,
                None => break,
            }
            out.push(' ');
            continue;
        }
        let next = html[i..].find('<').map(|o| i + o).unwrap_or(html.len());
        out.push_str(&html[i..next]);
        i = next;
    }
    let decoded = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The text layer of a PDF, every page in order; empty for a document that
/// has none, or that lopdf cannot read. A failure to read is the same answer
/// every time for the same bytes, so it is a classification, not an error.
fn pdf_text(bytes: &[u8]) -> String {
    let Ok(document) = lopdf::Document::load_mem(bytes) else {
        return String::new();
    };
    let pages: Vec<u32> = document.get_pages().keys().copied().collect();
    document
        .extract_text_with_limit(&pages, PDF_PAGE_CONTENT_LIMIT)
        .unwrap_or_default()
}

impl<E> DeriveMapping for SemanticIndex<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: std::fmt::Display + Send + Sync + 'static,
{
    type Source = SimpleArchive;
    type Target = NvFp4CosineSet<E>;

    fn fragment(&self) -> Fragment {
        let (vision, text, tokenizer): (
            Option<Inline<GenId>>,
            Option<Inline<GenId>>,
            Option<Inline<GenId>>,
        ) = match self.model {
            SemanticModel::Vision { root } => (Some(root.to_inline()), None, None),
            SemanticModel::Text { root, tokenizer } => {
                (None, Some(root.to_inline()), Some(tokenizer.to_inline()))
            }
        };
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <NomicAttributesToNvFp4Recipe as MetaDescribe>::describe(),
            metadata::blob_encoding*: E::describe(),
            nvfp4_dimension: self.dimension as u64,
            semantic_compute: self.compute.as_str(),
            semantic_content_attribute*: self.content_attributes.iter(),
            semantic_model_collection: self.model_collection,
            semantic_vision_root?: vision,
            semantic_text_root?: text,
            semantic_tokenizer_root?: tokenizer,
        }
    }

    /// The index is pinned to the compute class its descriptor names: on any
    /// other, maintenance derives nothing and still carries the index.
    fn computable_here(&self) -> bool {
        self.compute == local_compute()
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        let facts = target.facts();
        let algorithm = triblespace_core::collection::descriptor::mapping_algorithm(facts)
            .map_err(|source| fatal(source.to_string()))?;
        if algorithm != Some(NOMIC_ATTRIBUTES_TO_NVFP4) {
            return Err(fatal(format!(
                "semantic index mapping algorithm {:?} does not match {NOMIC_ATTRIBUTES_TO_NVFP4:X}",
                algorithm.map(|id| format!("{id:X}")),
            )));
        }
        let mapping = mapping_entity(target)?;
        let dimension = crate::nvfp4::mapping_dimension(target)?;
        let compute_raw = triblespace_core::collection::descriptor::mapping_argument(
            facts,
            semantic_compute.id(),
        )
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("semantic index names no compute class"))?;
        let compute_class: String = Inline::<ShortString>::new(compute_raw)
            .try_from_inline()
            .map_err(|source| {
                fatal(format!("semantic index: invalid compute class: {source:?}"))
            })?;
        let model_collection = triblespace_core::collection::descriptor::mapping_argument(
            facts,
            semantic_model_collection.id(),
        )
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("semantic index names no model collection"))?;
        let model = match (
            scalar_id(facts, semantic_vision_root.id())?,
            scalar_id(facts, semantic_text_root.id())?,
            scalar_id(facts, semantic_tokenizer_root.id())?,
        ) {
            (Some(root), None, None) => SemanticModel::Vision { root },
            (None, Some(root), Some(tokenizer)) => SemanticModel::Text { root, tokenizer },
            _ => {
                return Err(fatal(
                    "semantic index names neither one vision root nor one text root with its \
                     tokenizer root: one index is one model's rows",
                ))
            }
        };
        Self::new(
            repeated_ids(facts, mapping, semantic_content_attribute.id()),
            Inline::new(model_collection),
            model,
            compute_class,
            dimension,
        )
    }

    fn map<R>(
        &self,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError>
    where
        R: StoreRead,
    {
        triblespace_core::collection::simplearchive_union::validate_element(source)
            .map_err(|source| fatal(source.to_string()))?;

        let values = self.values(source);
        if values.is_empty() {
            return encode_rows::<E>(self.dimension, Vec::new())
                .map_err(|source| fatal(source.to_string()));
        }

        // Every dependency must be here before any model is loaded: a missing
        // blob is the one error the caller can act on (fetch it), so it must
        // not hide behind a model failure.
        for raw in &values {
            let handle = Inline::<Handle<RawBytes>>::new(*raw);
            if reader
                .metadata(handle)
                .map_err(|source| fatal(source.to_string()))?
                .is_none()
            {
                return Err(CollectionOperationError::MissingDependency(Handle::<
                    RawBytes,
                >::to_hash(
                    handle
                )));
            }
        }

        if self.compute != local_compute() {
            return Err(fatal(format!(
                "semantic index is computed on {} and this machine is {}; its DERIVE results arrive by replication",
                self.compute,
                local_compute()
            )));
        }
        let model = self.load_model(reader)?;
        // SEMANTIC_TRACE=1 prints one line per source member on stderr: what
        // it held and what it cost, the only progress an index build shows.
        let trace = std::env::var_os("SEMANTIC_TRACE").is_some();
        let started = std::time::Instant::now();
        let mut embedded = 0usize;
        let rows = self.embed_values(&values, reader, |input| {
            let vector = model.embed(input)?;
            embedded += usize::from(vector.is_some());
            Ok(vector)
        })?;
        if trace {
            eprintln!(
                "semantic index: member with {} content value(s): {embedded} row(s) in {:.1} s",
                values.len(),
                started.elapsed().as_secs_f64()
            );
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvfp4::NvFp4CosineIndex;
    use crate::schemas::Embedding;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::TryFromCover;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource};
    use triblespace_core::trible::Trible;

    const DIMENSION: usize = 8;

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    fn text_model() -> SemanticModel {
        SemanticModel::Text {
            root: Id::new([5; 16]).unwrap(),
            tokenizer: Id::new([6; 16]).unwrap(),
        }
    }

    fn vision_model() -> SemanticModel {
        SemanticModel::Vision {
            root: Id::new([4; 16]).unwrap(),
        }
    }

    /// A stand-in model: a function of what it reads, so the rows it makes
    /// are a function of the bytes, as the real model's are on one compute.
    fn fake_embed(input: Input<'_>) -> Result<Option<Vec<f32>>, CollectionOperationError> {
        let digest = match input {
            Input::Image(bytes) => blake3::hash(bytes),
            Input::Document(text) => blake3::hash(text.as_bytes()),
        };
        Ok(Some(
            digest.as_bytes()[..DIMENSION]
                .iter()
                .map(|byte| f32::from(*byte) - 127.5)
                .collect(),
        ))
    }

    fn map_with_fake<R: BlobStoreGet>(
        index: &SemanticIndex<Embedding>,
        facts: &TribleSet,
        reader: &R,
    ) -> Blob<NvFp4CosineSet<Embedding>> {
        let values = index.values(&facts.to_blob());
        index.embed_values(&values, reader, fake_embed).unwrap()
    }

    fn fact(entity: u8, attribute: Id, value: Inline<Handle<RawBytes>>) -> Trible {
        Trible::force(&Id::new([entity; 16]).unwrap(), &attribute, &value)
    }

    fn row_keys(member: &Blob<NvFp4CosineSet<Embedding>>) -> Vec<[u8; HANDLE_LEN]> {
        let rows = u64::from_le_bytes(
            member.bytes.as_ref()[member.bytes.len() - 16..][..8]
                .try_into()
                .unwrap(),
        ) as usize;
        member.bytes.as_ref()[..rows * HANDLE_LEN]
            .chunks_exact(HANDLE_LEN)
            .map(|key| key.try_into().unwrap())
            .collect()
    }

    /// A store holding `index` derived from an empty source: its target
    /// collection and the descriptor the store wrote for it.
    fn derived(
        index: &SemanticIndex<Embedding>,
    ) -> (
        (MemoryRepo, Collection<NvFp4CosineSet<Embedding>>),
        Fragment,
    ) {
        use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};

        let mut store = MemoryRepo::default();
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let source = store.collection("source", policy.clone()).unwrap();
        let target = store.derive_with(source, index.clone(), policy).unwrap();
        let snapshot = store.snapshot().unwrap();
        let descriptor: Blob<SimpleArchive> = snapshot.get(target.handle()).unwrap();
        let descriptor = Fragment::from(TribleSet::try_from_blob(descriptor).unwrap());
        ((store, target), descriptor)
    }

    #[test]
    fn descriptor_round_trips_every_argument() {
        let content = Id::new([1; 16]).unwrap();
        let body = Id::new([3; 16]).unwrap();
        for model in [text_model(), vision_model()] {
            let index =
                SemanticIndex::<Embedding>::new([content, body], collection(7), model, "gb10", 768)
                    .unwrap();

            // The descriptor a store writes is the one bind reads back.
            let (_, descriptor) = derived(&index);
            let bound = SemanticIndex::<Embedding>::bind(&Fragment::empty(), &descriptor).unwrap();
            assert_eq!(bound, index);
            assert!(!descriptor
                .facts()
                .iter()
                .any(|fact| fact.a() == &semantic_model_archive.id()));
            assert_eq!(
                semantic_model_collection.id(),
                mary::format::attrs::model_collection.id()
            );

            let mut changed = index.clone();
            changed.model_collection = collection(8);
            assert_ne!(changed.fragment(), index.fragment());
            changed = index.clone();
            changed.content_attributes.remove(&body);
            assert_ne!(changed.fragment(), index.fragment());
            changed = index.clone();
            changed.compute = "apple".to_owned();
            assert_ne!(changed.fragment(), index.fragment());
        }

        // The model is identity, and so is its kind.
        let text =
            SemanticIndex::<Embedding>::new([content], collection(7), text_model(), "gb10", 768)
                .unwrap();
        let vision =
            SemanticIndex::<Embedding>::new([content], collection(7), vision_model(), "gb10", 768)
                .unwrap();
        assert_ne!(text.fragment(), vision.fragment());
        let mut other_tokenizer = text.clone();
        other_tokenizer.model = SemanticModel::Text {
            root: Id::new([5; 16]).unwrap(),
            tokenizer: Id::new([9; 16]).unwrap(),
        };
        assert_ne!(other_tokenizer.fragment(), text.fragment());
    }

    #[test]
    fn a_descriptor_naming_two_models_is_refused() {
        let vision = SemanticIndex::<Embedding>::new(
            [Id::new([1; 16]).unwrap()],
            collection(7),
            vision_model(),
            "gb10",
            768,
        )
        .unwrap();
        let (_, descriptor) = derived(&vision);
        let mapping = triblespace_core::collection::descriptor::mapping(descriptor.facts())
            .unwrap()
            .unwrap();
        // Both roots on one mapping entity would be rows of two kinds in one
        // set, told apart by nothing.
        let text_root = Id::new([5; 16]).unwrap();
        let tokenizer_root = Id::new([6; 16]).unwrap();
        let mut both = descriptor.clone();
        both += entity! { ExclusiveId::force_ref(&mapping) @
            semantic_text_root: &text_root,
            semantic_tokenizer_root: &tokenizer_root,
        };
        let error = SemanticIndex::<Embedding>::bind(&Fragment::empty(), &both).unwrap_err();
        assert!(
            error.to_string().contains("one index is one model"),
            "{error}"
        );
    }

    #[test]
    fn a_named_model_collection_is_not_replaced_by_ambient_discovery() {
        use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};

        let mut store = MemoryRepo::default();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let root = key.verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let ambient = store
            .collection(mary::model_collection::mary_model_graph_name(), policy)
            .unwrap();
        store
            .commit(
                ambient,
                &key,
                entity! { metadata::name: "not the selected collection" },
            )
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let named = collection(11);
        let index = SemanticIndex::<Embedding>::new(
            [Id::new([1; 16]).unwrap()],
            named,
            vision_model(),
            local_compute(),
            768,
        )
        .unwrap();
        assert!(matches!(
            index.load_model(&snapshot),
            Err(CollectionOperationError::MissingDependency(handle)) if handle.raw == named.raw
        ));
    }

    /// Rows are keyed by the value: two values under one attribute of one
    /// entity are two rows, one value under two entities or two attributes is
    /// one row, and the key is the content handle itself.
    #[test]
    fn rows_are_keyed_by_content_handle() {
        let content = Id::new([1; 16]).unwrap();
        let attachment = Id::new([2; 16]).unwrap();
        let unselected = Id::new([3; 16]).unwrap();
        let mut store = MemoryRepo::default();
        let first = store
            .put::<RawBytes, _>(Bytes::from_source(b"the first document".to_vec()))
            .unwrap();
        let second = store
            .put::<RawBytes, _>(Bytes::from_source(b"the second document".to_vec()))
            .unwrap();
        let ignored = store
            .put::<RawBytes, _>(Bytes::from_source(b"an unselected attribute".to_vec()))
            .unwrap();
        let reader = store.snapshot().unwrap();

        let mut facts = TribleSet::new();
        // One entity, one attribute, two values.
        facts.insert(&fact(1, content, first));
        facts.insert(&fact(1, content, second));
        // The same value held by another entity, and under another
        // selected attribute.
        facts.insert(&fact(2, content, first));
        facts.insert(&fact(3, attachment, second));
        facts.insert(&fact(4, unselected, ignored));

        let index = SemanticIndex::<Embedding>::new(
            [content, attachment],
            collection(7),
            text_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        let member = map_with_fake(&index, &facts, &reader);
        let mut expected = vec![first.raw, second.raw];
        expected.sort_unstable();
        assert_eq!(row_keys(&member), expected);
    }

    /// The mapping of a union is the join of the mappings, byte for byte,
    /// including a value both sides hold and the empty member: the carrier's
    /// join is a plain union by content handle.
    #[test]
    fn mapping_is_a_join_homomorphism() {
        let content = Id::new([1; 16]).unwrap();
        let mut store = MemoryRepo::default();
        let mut blob = |bytes: &[u8]| {
            store
                .put::<RawBytes, _>(Bytes::from_source(bytes.to_vec()))
                .unwrap()
        };
        let shared = blob(b"a document both sides hold");
        let left_only = blob(b"only on the left");
        let right_only = blob(b"<html><body><p>only on the right</p></body></html>");
        let binary = blob(&[0xff, 0xfe, 0x00, 0x01]);
        let reader = store.snapshot().unwrap();

        let mut left = TribleSet::new();
        left.insert(&fact(1, content, shared));
        left.insert(&fact(2, content, left_only));
        left.insert(&fact(2, content, binary));
        let mut right = TribleSet::new();
        // The shared value under a different entity: one row, both sides.
        right.insert(&fact(3, content, shared));
        right.insert(&fact(3, content, right_only));
        let mut union = left.clone();
        union += right.clone();

        let index = SemanticIndex::<Embedding>::new(
            [content],
            collection(7),
            text_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        let mapped_left = map_with_fake(&index, &left, &reader);
        let mapped_right = map_with_fake(&index, &right, &reader);
        let mapped_union = map_with_fake(&index, &union, &reader);
        let joined = crate::nvfp4::join_members(&mapped_left, &mapped_right, DIMENSION).unwrap();
        assert_eq!(mapped_union.bytes.as_ref(), joined.bytes.as_ref());
        let reversed = crate::nvfp4::join_members(&mapped_right, &mapped_left, DIMENSION).unwrap();
        assert_eq!(reversed.bytes.as_ref(), joined.bytes.as_ref());
        // Bytes the text model cannot read get no row on either side.
        assert_eq!(row_keys(&mapped_union).len(), 3);

        let empty = map_with_fake(&index, &TribleSet::new(), &reader);
        let with_empty = crate::nvfp4::join_members(&mapped_left, &empty, DIMENSION).unwrap();
        assert_eq!(with_empty.bytes.as_ref(), mapped_left.bytes.as_ref());
    }

    /// An image and a text never share an index: the bytes decide which
    /// model reads them, so a vision index and a text index over the same
    /// source hold disjoint rows, and the kind of a row is its index.
    #[test]
    fn a_vision_and_a_text_index_split_the_values_by_their_bytes() {
        let content = Id::new([1; 16]).unwrap();
        let mut store = MemoryRepo::default();
        let png = store
            .put::<RawBytes, _>(Bytes::from_source(
                b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec(),
            ))
            .unwrap();
        let text = store
            .put::<RawBytes, _>(Bytes::from_source(b"a caption".to_vec()))
            .unwrap();
        let scanned = store
            .put::<RawBytes, _>(Bytes::from_source(b"%PDF-1.7 no text layer".to_vec()))
            .unwrap();
        let reader = store.snapshot().unwrap();
        let mut facts = TribleSet::new();
        facts.insert(&fact(1, content, png));
        facts.insert(&fact(1, content, text));
        facts.insert(&fact(2, content, scanned));

        let vision = SemanticIndex::<Embedding>::new(
            [content],
            collection(7),
            vision_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        let texts = SemanticIndex::<Embedding>::new(
            [content],
            collection(7),
            text_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        assert_eq!(
            row_keys(&map_with_fake(&vision, &facts, &reader)),
            vec![png.raw]
        );
        assert_eq!(
            row_keys(&map_with_fake(&texts, &facts, &reader)),
            vec![text.raw]
        );
    }

    /// The rows join the source on the content handle: a threshold over the
    /// reconstructions constrains `v`, and the source pattern with a free
    /// attribute names every entity holding a similar value.
    #[test]
    fn rows_join_the_source_on_the_content_handle() {
        let content = Id::new([1; 16]).unwrap();
        let mut store = MemoryRepo::default();
        let shared = store
            .put::<RawBytes, _>(Bytes::from_source(b"one attachment saved twice".to_vec()))
            .unwrap();
        let other = store
            .put::<RawBytes, _>(Bytes::from_source(b"something else".to_vec()))
            .unwrap();
        let mut facts = TribleSet::new();
        facts.insert(&fact(1, content, shared));
        facts.insert(&fact(2, content, shared));
        facts.insert(&fact(3, content, other));

        let index = SemanticIndex::<Embedding>::new(
            [content],
            collection(7),
            text_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        let reader = store.snapshot().unwrap();
        let member = map_with_fake(&index, &facts, &reader);
        let ((mut target_store, target), descriptor) = derived(&index);
        let member_handle = target_store
            .put::<NvFp4CosineSet<Embedding>, _>(member)
            .unwrap();
        let cover = target.cover([member_handle]);
        let view = NvFp4CosineIndex::<Embedding>::try_from_cover(
            &cover,
            &descriptor,
            &target_store.snapshot().unwrap(),
        )
        .unwrap();

        // The query is the shared document's own embedding.
        let query = fake_embed(Input::Document("one attachment saved twice".to_owned()))
            .unwrap()
            .unwrap();
        let cosines = view.reconstructed_cosines(&query).unwrap();
        let holders: BTreeSet<Id> = find!(
            holder: Id,
            triblespace_core::temp!(
                (attribute, value),
                triblespace_core::and!(
                    cosines.similar_to::<Handle<RawBytes>>(value, 0.99),
                    facts.pattern(holder, attribute, value),
                )
            )
        )
        .collect();
        assert_eq!(
            holders,
            BTreeSet::from([Id::new([1; 16]).unwrap(), Id::new([2; 16]).unwrap()])
        );
        assert!(cosines.cosine(&shared).unwrap() > 0.99);
        assert!(cosines.cosine(&other).unwrap() < 0.99);
    }

    /// Two embeddings of one content that disagree (another run, another
    /// kernel) are two rows under the one content handle. The leaves join,
    /// and a reader binds the handle once, scored by the better of its rows:
    /// each run's own query finds it, through the two-leaf cover and through
    /// the join alike, and each holder is named once.
    #[test]
    fn disagreeing_embeddings_of_one_content_join_and_read_once() {
        let content = Id::new([1; 16]).unwrap();
        let mut store = MemoryRepo::default();
        let shared = store
            .put::<RawBytes, _>(Bytes::from_source(b"one attachment saved twice".to_vec()))
            .unwrap();
        let other = store
            .put::<RawBytes, _>(Bytes::from_source(b"something else".to_vec()))
            .unwrap();
        let reader = store.snapshot().unwrap();
        let mut left = TribleSet::new();
        left.insert(&fact(1, content, shared));
        let mut right = TribleSet::new();
        right.insert(&fact(2, content, shared));
        right.insert(&fact(3, content, other));
        let mut facts = left.clone();
        facts += right.clone();

        let index = SemanticIndex::<Embedding>::new(
            [content],
            collection(7),
            text_model(),
            "gb10",
            DIMENSION,
        )
        .unwrap();
        // The second leaf's run disagrees with the first on every value.
        let drifted = |input: Input<'_>| {
            fake_embed(input).map(|vector| {
                vector.map(|mut vector| {
                    vector.reverse();
                    vector
                })
            })
        };
        let left_leaf = map_with_fake(&index, &left, &reader);
        let right_leaf = index
            .embed_values(&index.values(&right.to_blob()), &reader, drifted)
            .unwrap();
        let joined = crate::nvfp4::join_members(&left_leaf, &right_leaf, DIMENSION).unwrap();
        let keys = row_keys(&joined);
        assert_eq!(keys.len(), 3);
        assert_eq!(keys.iter().filter(|key| **key == shared.raw).count(), 2);

        let ((mut target_store, target), descriptor) = derived(&index);
        let [left_handle, right_handle, joined_handle] =
            [left_leaf, right_leaf, joined].map(|leaf| {
                target_store
                    .put::<NvFp4CosineSet<Embedding>, _>(leaf)
                    .unwrap()
            });
        let snapshot = target_store.snapshot().unwrap();
        let document = || Input::Document("one attachment saved twice".to_owned());
        let queries = [
            fake_embed(document()).unwrap().unwrap(),
            drifted(document()).unwrap().unwrap(),
        ];
        for cover in [
            target.cover([left_handle, right_handle]),
            target.cover([joined_handle]),
        ] {
            let view =
                NvFp4CosineIndex::<Embedding>::try_from_cover(&cover, &descriptor, &snapshot)
                    .unwrap();
            for query in &queries {
                let cosines = view.reconstructed_cosines(query).unwrap();
                assert_eq!(cosines.len(), 2, "one entry per content handle");
                assert!(cosines.cosine(&shared).unwrap() > 0.99);
                assert!(cosines.cosine(&other).unwrap() < 0.99);
                let mut holders: Vec<Id> = find!(
                    holder: Id,
                    triblespace_core::temp!(
                        (attribute, value),
                        triblespace_core::and!(
                            cosines.similar_to::<Handle<RawBytes>>(value, 0.99),
                            facts.pattern(holder, attribute, value),
                        )
                    )
                )
                .collect();
                holders.sort();
                assert_eq!(
                    holders,
                    vec![Id::new([1; 16]).unwrap(), Id::new([2; 16]).unwrap()]
                );
            }
        }
    }

    #[test]
    fn content_is_classified_by_its_bytes() {
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR";
        assert_eq!(classify(png), Content::Image);
        assert_eq!(
            classify(b"hello, world"),
            Content::Text("hello, world".to_owned())
        );
        assert_eq!(classify(b"   \n"), Content::Other);
        assert_eq!(classify(&[0xff, 0xfe, 0x00, 0x01]), Content::Other);
        // Not a real PDF: still a PDF by its magic, with no text layer.
        assert_eq!(classify(b"%PDF-1.7 garbage"), Content::Pdf(String::new()));
    }

    #[test]
    fn html_is_reduced_to_its_text() {
        let page = "<!DOCTYPE html><html><head><style>p{x:1}</style><script>var a=1;</script><title>Hydra</title></head><body><p>Two robot heads &amp; a desk.</p></body></html>";
        assert_eq!(
            classify(page.as_bytes()),
            Content::Text("Hydra Two robot heads & a desk.".to_owned())
        );
        let long = "x".repeat(TEXT_HEAD_BYTES + 100);
        match classify(long.as_bytes()) {
            Content::Text(text) => assert_eq!(text.len(), TEXT_HEAD_BYTES),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_index_that_embeds_nothing_is_refused() {
        let error = SemanticIndex::<Embedding>::new([], collection(1), vision_model(), "gb10", 768)
            .unwrap_err();
        assert!(error.to_string().contains("embeds nothing"), "{error}");
    }
}
