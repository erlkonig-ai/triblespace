//! The semantic index: an NVFP4 cosine set derived straight from source
//! facts through the nomic models that live in the same pile.
//!
//! [`SemanticIndex`] is a [`CollectionMapping`] from one `SimpleArchive`
//! source (the Files collection, say) to [`NvFp4CosineSet`]. Its descriptor
//! names what to embed (one content attribute whose values are handles to
//! raw bytes, classified by the bytes themselves: a raster image goes
//! through the vision model, a PDF's own text layer and any valid UTF-8 go
//! through the text model's document side; plus any number of attributes
//! whose values are handles to UTF-8 text), the model and tokenizer roots to
//! embed with and their containing collection handle, the compute class the
//! index is canonical on, and the row dimension. The selected references are
//! identity; unrelated observations and the collection's physical member
//! archives are not. A new selection is a new descriptor and the old index
//! stays readable.
//!
//! A row is keyed by what embedded it and the entity it belongs to, 32
//! bytes: a content row by the root of the model its bytes went through,
//! `[model root id | entity id]` (the vision root for an image, the text
//! root for a text or a PDF), a text-attribute row by its attribute,
//! `[attribute id | entity id]`. So a hit names the entity without any
//! stored per-entity vector (the vectors a writer may have stored under a
//! per-file attribute are not the index any more), and a reader tells an
//! image row from a text row by the key alone, which it must: text-to-text
//! cosines in this space sit near 0.7 and text-to-image near 0.07, so the
//! two kinds rank apart. JP, 2026-09-13, on this shape: "it's the right
//! shape let's build it".
//!
//! Images go through nomic-embed-vision-v1.5 and texts through the document
//! side of nomic-embed-text-v1.5, the two halves of one aligned space, so a
//! text query finds an image by cosine alone. JP, 2026-09-13, on the text
//! side: "just point to the file blob itself as a UTF8String if it is one";
//! a scanned PDF has no text layer and waits for an OCR model in the pile.
//! The text model reads the first 2,048 tokens of a document; chunk rows for
//! long documents are the follow-up. Rows are the two-stage NVFP4
//! form JP settled for the index side on 2026-09-11 (97.6 % recall\@10
//! against f32 on our own prose); [`NvFp4CosineIndex::reconstructed_top_k`]
//! answers a query from the rows alone.
//!
//! The mapping is a function of the source bytes and the selected model roots
//! on the compute class it names. A GPU is not bit-deterministic across
//! hardware, so the descriptor carries the class it was computed on and
//! [`SemanticIndex::map`] refuses to compute on another: there the DERIVE
//! results arrive by replication (JP, 2026-09-10: the Sparks are canonical,
//! customers buy appliances). A golden vector checked before publishing is
//! the follow-up that makes a driver update visible.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::rc::Rc;

use anybytes::{Bytes, View};
use mary::embed::LocalEmbedder;
use mary::selection::{
    load_keymap_from_graph, load_tokenizer_from_graph, ModelSelector, TokenizerSelector,
};
use triblespace_core::blob::encodings::rawbytes::RawBytes;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{
    Collection, CollectionHandle, CollectionMapping, CollectionOperationError,
    CollectionSnapshotExt, Cover,
};
use triblespace_core::id::{id_hex, ExclusiveId, Id, RawId};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::shortstring::ShortString;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::macros::{attributes, entity, find};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::query::TriblePattern;
use triblespace_core::repo::StoreRead;
use triblespace_core::trible::{Fragment, TribleSet, TRIBLE_LEN};

use crate::nvfp4::{encode_rows, nvfp4_dimension, NvFp4CosineSet, StoredRow, HANDLE_LEN};

/// The mapping algorithm: selected attributes of a `SimpleArchive` source,
/// embedded through the nomic v1.5 text and vision models pinned by the
/// descriptor, to two-stage NVFP4 rows keyed by model root (content rows)
/// or attribute (text-attribute rows) and entity. The content attribute's
/// bytes are classified (image, PDF text layer, UTF-8).
///
/// Minted with `trible genid` on 2026-09-14:
/// `2B69128192930EE0782CCA03B97677F5`. Models and the tokenizer are explicit
/// root references in one named collection, not member-archive handles. The
/// previous archive-pinning algorithm was `021EE2F74220BDAE30CC35FB08FC9427`;
/// its descriptors and results are not rewritten or implicitly rebound.
/// That algorithm replaced
/// `4704CB1C2A54CDBF96F54BFFC53A0733` of the same day, which keyed content
/// rows by the content attribute and so could not tell an image row from a
/// text row, and `B94732E5DA22EFE9A4961BE906F5C500`, the image-only mapping
/// of the night before; neither left sky. A mapping that computes something
/// else is a different function and gets a different id.
pub const NOMIC_ATTRIBUTES_TO_NVFP4: Id = id_hex!("2B69128192930EE0782CCA03B97677F5");

attributes! {
    /// The one attribute whose values are handles to raw content bytes; every
    /// entity carrying it gets a row when the bytes are an image, a PDF with
    /// a text layer, or UTF-8 text. Minted 2026-09-13.
    "13E4B93C65EA173282139D7DEBC1CC9B" as pub semantic_content_attribute: GenId;
    /// An attribute whose values are handles to UTF-8 text; repeatable, one
    /// text row per (attribute, entity). Minted 2026-09-13.
    "02C9C79EA911BE8AAF9070A83B26CD10" as pub semantic_text_attribute: GenId;
    /// Historical archive-pinning argument, retained with its original id.
    /// A member archive of the pile's model collection carrying the roots
    /// named below and their tokenizer; repeatable. These pin the exact
    /// model bytes. Minted 2026-09-13.
    "FC76F2B04ACC2CE2F74BDC3CBEDBF37B" as pub semantic_model_archive: Handle<SimpleArchive>;
    /// The vision model root in the named collection. Minted 2026-09-13.
    "4ADAD28EE2152E087625A04BB7CA449B" as pub semantic_vision_root: GenId;
    /// The text model root in the named collection. Minted 2026-09-13.
    "9273B441A9D0EEC0778A5B5488EB6851" as pub semantic_text_root: GenId;
    /// The text tokenizer root in the named collection. Minted with
    /// `trible genid` 2026-09-14: `E6A241C22B0457CD24AE65C1FC6AC177`.
    "E6A241C22B0457CD24AE65C1FC6AC177" as pub semantic_tokenizer_root: GenId;
    /// The compute class this index is canonical on; see [`local_compute`].
    /// Minted 2026-09-13.
    "1B1FFA9CC2BC1FCA50D2389F1B980BAC" as pub semantic_compute: ShortString;
}

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
            metadata::description: "Selected attributes of a SimpleArchive source embedded through the nomic-embed v1.5 vision and text models pinned by the descriptor, as two-stage NVFP4 cosine rows keyed by attribute and entity; the content attribute's bytes are classified as image, PDF text layer or UTF-8 text.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// One concrete semantic index: what to embed, with which model references,
/// on which compute, into rows of which dimension.
pub struct SemanticIndex<E: BlobEncoding> {
    /// Attribute whose values are handles to raw content bytes (image, PDF or
    /// UTF-8 text), if content is indexed.
    pub content_attribute: Option<Id>,
    /// Attributes whose values are handles to UTF-8 text.
    pub text_attributes: BTreeSet<Id>,
    /// The collection containing the selected roots and text tokenizer.
    /// Its physical support does not participate in this index's identity.
    pub model_collection: CollectionHandle,
    /// The vision root used for image content, when images are indexed.
    pub vision_root: Option<Id>,
    /// The text root; required when `text_attributes` is not empty.
    pub text_root: Option<Id>,
    /// The tokenizer root; required whenever a text root is named.
    pub tokenizer_root: Option<Id>,
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
            content_attribute: self.content_attribute,
            text_attributes: self.text_attributes.clone(),
            model_collection: self.model_collection,
            vision_root: self.vision_root,
            text_root: self.text_root,
            tokenizer_root: self.tokenizer_root,
            compute: self.compute.clone(),
            dimension: self.dimension,
            encoding: PhantomData,
        }
    }
}

impl<E: BlobEncoding> PartialEq for SemanticIndex<E> {
    fn eq(&self, other: &Self) -> bool {
        self.content_attribute == other.content_attribute
            && self.text_attributes == other.text_attributes
            && self.model_collection == other.model_collection
            && self.vision_root == other.vision_root
            && self.text_root == other.text_root
            && self.tokenizer_root == other.tokenizer_root
            && self.compute == other.compute
            && self.dimension == other.dimension
    }
}

impl<E: BlobEncoding> Eq for SemanticIndex<E> {}

impl<E: BlobEncoding> std::fmt::Debug for SemanticIndex<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticIndex")
            .field("content_attribute", &self.content_attribute)
            .field("text_attributes", &self.text_attributes)
            .field("model_collection", &self.model_collection)
            .field("vision_root", &self.vision_root)
            .field("text_root", &self.text_root)
            .field("tokenizer_root", &self.tokenizer_root)
            .field("compute", &self.compute)
            .field("dimension", &self.dimension)
            .finish()
    }
}

impl<E: BlobEncoding> SemanticIndex<E> {
    /// A new index description. `dimension` must be positive and at least
    /// one of the two model roots must be named with its attributes.
    pub fn new(
        content_attribute: Option<Id>,
        text_attributes: impl IntoIterator<Item = Id>,
        model_collection: CollectionHandle,
        vision_root: Option<Id>,
        text_root: Option<Id>,
        tokenizer_root: Option<Id>,
        compute: impl Into<String>,
        dimension: usize,
    ) -> Result<Self, CollectionOperationError> {
        let index = Self {
            content_attribute,
            text_attributes: text_attributes.into_iter().collect(),
            model_collection,
            vision_root,
            text_root,
            tokenizer_root,
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
        if self.content_attribute.is_some()
            && self.vision_root.is_none()
            && self.text_root.is_none()
        {
            return Err(fatal(
                "semantic index embeds content but names neither a vision nor a text root",
            ));
        }
        if !self.text_attributes.is_empty() && self.text_root.is_none() {
            return Err(fatal("semantic index embeds text but names no text root"));
        }
        if self.text_root.is_some() && self.tokenizer_root.is_none() {
            return Err(fatal(
                "semantic index names a text root but no tokenizer root",
            ));
        }
        if self.content_attribute.is_none() && self.text_attributes.is_empty() {
            return Err(fatal(
                "semantic index embeds nothing: no content or text attribute",
            ));
        }
        if self.compute.is_empty() {
            return Err(fatal("semantic index names no compute class"));
        }
        Ok(())
    }

    /// The row key of one (attribute, entity) pair: attribute id in the high
    /// sixteen bytes, entity id in the low sixteen. A content row's
    /// "attribute" is the root of the model that embedded it.
    pub fn row_key(attribute: Id, entity: RawId) -> [u8; HANDLE_LEN] {
        let mut key = [0u8; HANDLE_LEN];
        key[..16].copy_from_slice(&attribute[..]);
        key[16..].copy_from_slice(&entity);
        key
    }

    /// The (attribute, entity) pair a row key names, or `None` for a key
    /// that is not one of ours; for a content row the first id is the model
    /// root, the descriptor's `vision_root` or `text_root`.
    pub fn row_entity(key: &[u8; HANDLE_LEN]) -> Option<(Id, Id)> {
        let attribute = Id::new(key[..16].try_into().expect("16 bytes"))?;
        let entity = Id::new(key[16..].try_into().expect("16 bytes"))?;
        Some((attribute, entity))
    }

    /// The embedders this index computes with, loaded from
    /// the explicitly named collection through `reader`, the same frozen
    /// records and authorization boundary the source came from.
    fn models<R>(&self, reader: &R) -> Result<Rc<Models>, CollectionOperationError>
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
        let references = (
            self.model_collection,
            self.vision_root,
            self.text_root,
            self.tokenizer_root,
        );
        // Operational reuse after admission, not model identity: the cheap
        // cover equality guards one thread's last inference observation before
        // materializing its graph. Changed packaging or annotations may reload
        // the runtime once, but cannot rekey the descriptor or derived rows.
        // No graph digest is minted and reuse never skips frozen admission.
        if let Some(models) = MODELS.with(|cache| {
            cache
                .borrow()
                .as_ref()
                .and_then(|(selected, observed, models)| {
                    (*selected == references && observed == snapshot.cover())
                        .then(|| models.clone())
                })
        }) {
            return Ok(models);
        }
        let facts = snapshot
            .view::<TribleSet>()
            .map_err(|source| fatal(format!("semantic index model facts: {source:#}")))?;
        let device = mary::embed::default_device();
        let vision = match self.vision_root {
            Some(root) => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| {
                        fatal(format!("semantic index vision root {root:X}: {source:#}"))
                    })?;
                Some(
                    mary::embed::load_nomic_vision_from_keymap(keymap, device.clone()).map_err(
                        |source| fatal(format!("semantic index vision model: {source:#}")),
                    )?,
                )
            }
            None => None,
        };
        let text = match self.text_root {
            Some(root) => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| {
                        fatal(format!("semantic index text root {root:X}: {source:#}"))
                    })?;
                let tokenizer_root = self
                    .tokenizer_root
                    .ok_or_else(|| fatal("semantic index names no text tokenizer root"))?;
                let tokenizer = load_tokenizer_from_graph(
                    &facts,
                    reader,
                    TokenizerSelector::Root(tokenizer_root),
                )
                .map_err(|source| fatal(format!("semantic index text tokenizer: {source:#}")))?;
                Some(
                    mary::embed::nomic_text_from_parts(keymap, tokenizer, device).map_err(
                        |source| fatal(format!("semantic index text model: {source:#}")),
                    )?,
                )
            }
            None => None,
        };
        let models = Rc::new(Models { vision, text });
        MODELS.with(|cache| {
            *cache.borrow_mut() = Some((references, snapshot.cover().clone(), models.clone()));
        });
        Ok(models)
    }
}

type Backend = mary::nn::backend::B;

struct Models {
    vision: Option<mary::embed::NomicVisionEmbedder<Backend>>,
    text: Option<mary::embed::NomicTextEmbedder<Backend>>,
}

type ModelReferences = (CollectionHandle, Option<Id>, Option<Id>, Option<Id>);

thread_local! {
    static MODELS: RefCell<Option<(ModelReferences, Cover<SimpleArchive>, Rc<Models>)>> = const { RefCell::new(None) };
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

impl<E> CollectionMapping for SemanticIndex<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: std::fmt::Display + Send + Sync + 'static,
{
    type Source = SimpleArchive;
    type Target = NvFp4CosineSet<E>;

    fn fragment(&self) -> Fragment {
        let image: Option<Inline<GenId>> = self.content_attribute.map(|id| id.to_inline());
        let vision: Option<Inline<GenId>> = self.vision_root.map(|id| id.to_inline());
        let text: Option<Inline<GenId>> = self.text_root.map(|id| id.to_inline());
        let tokenizer: Option<Inline<GenId>> = self.tokenizer_root.map(|id| id.to_inline());
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <NomicAttributesToNvFp4Recipe as MetaDescribe>::describe(),
            metadata::blob_encoding*: E::describe(),
            nvfp4_dimension: self.dimension as u64,
            semantic_compute: self.compute.as_str(),
            semantic_content_attribute?: image,
            semantic_text_attribute*: self.text_attributes.iter(),
            semantic_model_collection: self.model_collection,
            semantic_vision_root?: vision,
            semantic_text_root?: text,
            semantic_tokenizer_root?: tokenizer,
        }
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
        Self::new(
            scalar_id(facts, semantic_content_attribute.id())?,
            repeated_ids(facts, mapping, semantic_text_attribute.id()),
            Inline::new(model_collection),
            scalar_id(facts, semantic_vision_root.id())?,
            scalar_id(facts, semantic_text_root.id())?,
            scalar_id(facts, semantic_tokenizer_root.id())?,
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

        // What this member asks to embed: per (attribute, entity), the set of
        // handles under it. A set, because a repeated fact is one fact; the
        // canonically lowest handle is the one embedded when there are
        // several, so the row is a function of the facts and never of their
        // order.
        let mut images: BTreeMap<RawId, BTreeSet<[u8; 32]>> = BTreeMap::new();
        let mut texts: BTreeMap<(Id, RawId), BTreeSet<[u8; 32]>> = BTreeMap::new();
        for raw in source.bytes.as_ref().chunks_exact(TRIBLE_LEN) {
            let entity: RawId = raw[..16].try_into().expect("16-byte entity");
            let value: [u8; 32] = raw[32..].try_into().expect("32-byte trible value");
            if self
                .content_attribute
                .is_some_and(|attribute| raw[16..32] == attribute[..])
            {
                images.entry(entity).or_default().insert(value);
                continue;
            }
            for attribute in &self.text_attributes {
                if raw[16..32] == attribute[..] {
                    texts.entry((*attribute, entity)).or_default().insert(value);
                }
            }
        }
        if images.is_empty() && texts.is_empty() {
            return encode_rows::<E>(self.dimension, Vec::new())
                .map_err(|source| fatal(source.to_string()));
        }

        // Every dependency must be here before any model is loaded: a missing
        // blob is the one error the caller can act on (fetch it), so it must
        // not hide behind a model failure.
        for handles in images.values() {
            let handle = Inline::<Handle<RawBytes>>::new(*handles.first().expect("non-empty set"));
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
        for handles in texts.values() {
            let handle =
                Inline::<Handle<UTF8String>>::new(*handles.first().expect("non-empty set"));
            if reader
                .metadata(handle)
                .map_err(|source| fatal(source.to_string()))?
                .is_none()
            {
                return Err(CollectionOperationError::MissingDependency(Handle::<
                    UTF8String,
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
        let models = self.models(reader)?;
        // SEMANTIC_TRACE=1 prints one line per source member on stderr: what
        // it held and what it cost, the only progress an index build shows.
        let trace = std::env::var_os("SEMANTIC_TRACE").is_some();
        let started = std::time::Instant::now();
        let (mut n_image, mut n_text, mut n_pdf, mut n_other) = (0usize, 0usize, 0usize, 0usize);

        let mut rows = Vec::with_capacity(images.len() + texts.len());
        if self.content_attribute.is_some() {
            for (entity, handles) in &images {
                let raw = *handles.first().expect("non-empty set");
                let bytes: Bytes = reader
                    .get(Inline::<Handle<RawBytes>>::new(raw))
                    .map_err(|source| fatal(source.to_string()))?;
                // The bytes say what they are; a kind this index has no
                // model for gets no row, the same answer every time.
                let kind = classify(bytes.as_ref());
                match &kind {
                    Content::Image => n_image += 1,
                    Content::Pdf(_) => n_pdf += 1,
                    Content::Text(_) => n_text += 1,
                    Content::Other => n_other += 1,
                }
                // The row is keyed by the root of the model it went through.
                let (vector, root) = match kind {
                    Content::Image => match (models.vision.as_ref(), self.vision_root) {
                        (Some(vision), Some(root)) => match vision.embed_image(bytes.as_ref()) {
                            Ok(vector) => (vector, root),
                            Err(_) => continue,
                        },
                        _ => continue,
                    },
                    Content::Pdf(text) | Content::Text(text) => {
                        if text.trim().is_empty() {
                            continue;
                        }
                        match (models.text.as_ref(), self.text_root) {
                            (Some(text_model), Some(root)) => (
                                text_model
                                    .embed_document(&text)
                                    .map_err(|source| fatal(format!("text model: {source:#}")))?,
                                root,
                            ),
                            _ => continue,
                        }
                    }
                    Content::Other => continue,
                };
                if vector.len() != self.dimension {
                    return Err(fatal(format!(
                        "model produced {} dimensions, index has {}",
                        vector.len(),
                        self.dimension
                    )));
                }
                rows.push(
                    StoredRow::quantize(Self::row_key(root, *entity), &vector, self.dimension)
                        .map_err(|source| fatal(source.to_string()))?,
                );
            }
        }
        if let Some(text_model) = models.text.as_ref() {
            for ((attribute, entity), handles) in &texts {
                let raw = *handles.first().expect("non-empty set");
                let text: View<str> = reader
                    .get(Inline::<Handle<UTF8String>>::new(raw))
                    .map_err(|source| fatal(source.to_string()))?;
                let vector = text_model
                    .embed_document(&text)
                    .map_err(|source| fatal(format!("text model: {source:#}")))?;
                if vector.len() != self.dimension {
                    return Err(fatal(format!(
                        "text model produced {} dimensions, index has {}",
                        vector.len(),
                        self.dimension
                    )));
                }
                rows.push(
                    StoredRow::quantize(
                        Self::row_key(*attribute, *entity),
                        &vector,
                        self.dimension,
                    )
                    .map_err(|source| fatal(source.to_string()))?,
                );
            }
        }
        if trace {
            eprintln!(
                "semantic index: member with {} content value(s) ({n_image} image, {n_text} text, {n_pdf} pdf, {n_other} other) and {} text fact(s): {} row(s) in {:.1} s",
                images.len(),
                texts.len(),
                rows.len(),
                started.elapsed().as_secs_f64()
            );
        }
        encode_rows::<E>(self.dimension, rows).map_err(|source| fatal(source.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::Embedding;

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    #[test]
    fn descriptor_round_trips_every_argument() {
        use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_core::repo::{BlobStoreGet, SnapshotSource};

        let image = Id::new([1; 16]).unwrap();
        let title = Id::new([2; 16]).unwrap();
        let body = Id::new([3; 16]).unwrap();
        let vision = Id::new([4; 16]).unwrap();
        let text = Id::new([5; 16]).unwrap();
        let tokenizer = Id::new([6; 16]).unwrap();
        let index = SemanticIndex::<Embedding>::new(
            Some(image),
            [title, body],
            collection(7),
            Some(vision),
            Some(text),
            Some(tokenizer),
            "gb10",
            768,
        )
        .unwrap();

        // The descriptor a store writes is the one bind reads back.
        let mut store = MemoryRepo::default();
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let source = store.collection("source", policy.clone()).unwrap();
        let target = store.derive_with(source, index.clone(), policy).unwrap();
        let snapshot = store.snapshot().unwrap();
        let descriptor: Blob<SimpleArchive> = snapshot.get(target.handle()).unwrap();
        let descriptor = Fragment::from(TribleSet::try_from_blob(descriptor).unwrap());
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
        changed.vision_root = Some(Id::new([9; 16]).unwrap());
        assert_ne!(changed.fragment(), index.fragment());
        changed = index.clone();
        changed.text_root = Some(Id::new([9; 16]).unwrap());
        assert_ne!(changed.fragment(), index.fragment());
        changed = index.clone();
        changed.tokenizer_root = Some(Id::new([9; 16]).unwrap());
        assert_ne!(changed.fragment(), index.fragment());
        changed = index.clone();
        changed.text_attributes.remove(&body);
        assert_ne!(changed.fragment(), index.fragment());
    }

    #[test]
    fn a_named_model_collection_is_not_replaced_by_ambient_discovery() {
        use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
        use triblespace_core::repo::{memoryrepo::MemoryRepo, SnapshotSource};

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
            Some(Id::new([1; 16]).unwrap()),
            [],
            named,
            Some(Id::new([2; 16]).unwrap()),
            None,
            None,
            local_compute(),
            768,
        )
        .unwrap();
        assert!(matches!(
            index.models(&snapshot),
            Err(CollectionOperationError::MissingDependency(handle)) if handle.raw == named.raw
        ));
    }

    #[test]
    fn a_text_model_requires_an_explicit_tokenizer_root() {
        let error = SemanticIndex::<Embedding>::new(
            Some(Id::new([1; 16]).unwrap()),
            [],
            collection(7),
            None,
            Some(Id::new([2; 16]).unwrap()),
            None,
            "gb10",
            768,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no tokenizer root"), "{error}");
    }

    #[test]
    fn row_key_names_attribute_and_entity() {
        let attribute = Id::new([0xAB; 16]).unwrap();
        let entity = [0xCD; 16];
        let key = SemanticIndex::<Embedding>::row_key(attribute, entity);
        assert_eq!(&key[..16], &attribute[..]);
        assert_eq!(&key[16..], &entity);
        let (a, e) = SemanticIndex::<Embedding>::row_entity(&key).unwrap();
        assert_eq!(a, attribute);
        assert_eq!(&e[..], &entity);
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
        let error =
            SemanticIndex::<Embedding>::new(None, [], collection(1), None, None, None, "gb10", 768)
                .unwrap_err();
        assert!(error.to_string().contains("embeds nothing"), "{error}");
    }
}
