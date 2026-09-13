//! The semantic index: an NVFP4 cosine set derived straight from source
//! facts through the nomic models that live in the same pile.
//!
//! [`SemanticIndex`] is a [`CollectionMapping`] from one `SimpleArchive`
//! source (the Files collection, say) to [`NvFp4CosineSet`]. Its descriptor
//! names what to embed (one attribute whose values are handles to image
//! bytes, and any number whose values are handles to UTF-8 text), the exact
//! model bytes to embed with (the archive handles of the roots inside the
//! pile's own `mary-model-graph` collection, so a new model is a new
//! descriptor and the old index stays readable), the compute class the index
//! is canonical on, and the row dimension.
//!
//! A row is keyed by the attribute it embeds and the entity it belongs to,
//! `[attribute id | entity id]` in 32 bytes, so a hit names the entity
//! without any stored per-entity vector: the vectors a writer may have
//! stored under a per-file attribute are not the index any more. JP,
//! 2026-09-13, on this shape: "it's the right shape let's build it".
//!
//! Images go through nomic-embed-vision-v1.5 and texts through the document
//! side of nomic-embed-text-v1.5, the two halves of one aligned space, so a
//! text query finds an image by cosine alone. Rows are the two-stage NVFP4
//! form JP settled for the index side on 2026-09-11 (97.6 % recall\@10
//! against f32 on our own prose); [`NvFp4CosineIndex::reconstructed_top_k`]
//! answers a query from the rows alone.
//!
//! The mapping is a function of the source bytes and the pinned model bytes
//! on the compute class it names. A GPU is not bit-deterministic across
//! hardware, so the descriptor carries the class it was computed on and
//! [`SemanticIndex::map`] refuses to compute on another: there the DERIVE
//! results arrive by replication (JP, 2026-09-10: the Sparks are canonical,
//! customers buy appliances). A golden vector checked before publishing is
//! the follow-up that makes a driver update visible.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use triblespace_core::query::TriblePattern;
use triblespace_core::collection::{CollectionMapping, CollectionOperationError};
use triblespace_core::id::{id_hex, ExclusiveId, Id, RawId};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::shortstring::ShortString;
use triblespace_core::inline::{Inline, IntoInline};
use triblespace_core::macros::{attributes, entity, find};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace_core::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

use crate::nvfp4::{encode_rows, nvfp4_dimension, NvFp4CosineSet, StoredRow, HANDLE_LEN};

/// The mapping algorithm: selected attributes of a `SimpleArchive` source,
/// embedded through the nomic v1.5 text and vision models pinned by the
/// descriptor, to two-stage NVFP4 rows keyed by attribute and entity.
///
/// Minted with `trible genid` on 2026-09-13.
pub const NOMIC_ATTRIBUTES_TO_NVFP4: Id = id_hex!("B94732E5DA22EFE9A4961BE906F5C500");

attributes! {
    /// The one attribute whose values are handles to image bytes; every
    /// entity carrying it gets a vision row. Minted 2026-09-13.
    "13E4B93C65EA173282139D7DEBC1CC9B" as pub semantic_image_attribute: GenId;
    /// An attribute whose values are handles to UTF-8 text; repeatable, one
    /// text row per (attribute, entity). Minted 2026-09-13.
    "02C9C79EA911BE8AAF9070A83B26CD10" as pub semantic_text_attribute: GenId;
    /// A member archive of the pile's model collection carrying the roots
    /// named below and their tokenizer; repeatable. These pin the exact
    /// model bytes. Minted 2026-09-13.
    "FC76F2B04ACC2CE2F74BDC3CBEDBF37B" as pub semantic_model_archive: Handle<SimpleArchive>;
    /// The vision model root inside those archives. Minted 2026-09-13.
    "4ADAD28EE2152E087625A04BB7CA449B" as pub semantic_vision_root: GenId;
    /// The text model root inside those archives. Minted 2026-09-13.
    "9273B441A9D0EEC0778A5B5488EB6851" as pub semantic_text_root: GenId;
    /// The compute class this index is canonical on; see [`local_compute`].
    /// Minted 2026-09-13.
    "1B1FFA9CC2BC1FCA50D2389F1B980BAC" as pub semantic_compute: ShortString;
}

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
            metadata::name: "nomic-attributes-to-nvfp4",
            metadata::description: "Selected image and text attributes of a SimpleArchive source, embedded through the nomic-embed v1.5 vision and text models pinned by the descriptor, as two-stage NVFP4 cosine rows keyed by attribute and entity.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// One concrete semantic index: what to embed, with which pinned model
/// bytes, on which compute, into rows of which dimension.
pub struct SemanticIndex<E: BlobEncoding> {
    /// Attribute whose values are handles to image bytes, if images are
    /// indexed.
    pub image_attribute: Option<Id>,
    /// Attributes whose values are handles to UTF-8 text.
    pub text_attributes: BTreeSet<Id>,
    /// Member archives of the model collection holding the roots and the
    /// text tokenizer.
    pub model_archives: BTreeSet<[u8; 32]>,
    /// The vision root; required when `image_attribute` is set.
    pub vision_root: Option<Id>,
    /// The text root; required when `text_attributes` is not empty.
    pub text_root: Option<Id>,
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
            image_attribute: self.image_attribute,
            text_attributes: self.text_attributes.clone(),
            model_archives: self.model_archives.clone(),
            vision_root: self.vision_root,
            text_root: self.text_root,
            compute: self.compute.clone(),
            dimension: self.dimension,
            encoding: PhantomData,
        }
    }
}

impl<E: BlobEncoding> PartialEq for SemanticIndex<E> {
    fn eq(&self, other: &Self) -> bool {
        self.image_attribute == other.image_attribute
            && self.text_attributes == other.text_attributes
            && self.model_archives == other.model_archives
            && self.vision_root == other.vision_root
            && self.text_root == other.text_root
            && self.compute == other.compute
            && self.dimension == other.dimension
    }
}

impl<E: BlobEncoding> Eq for SemanticIndex<E> {}

impl<E: BlobEncoding> std::fmt::Debug for SemanticIndex<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SemanticIndex")
            .field("image_attribute", &self.image_attribute)
            .field("text_attributes", &self.text_attributes)
            .field("model_archives", &self.model_archives.len())
            .field("vision_root", &self.vision_root)
            .field("text_root", &self.text_root)
            .field("compute", &self.compute)
            .field("dimension", &self.dimension)
            .finish()
    }
}

impl<E: BlobEncoding> SemanticIndex<E> {
    /// A new index description. `dimension` must be positive and at least
    /// one of the two model roots must be named with its attributes.
    pub fn new(
        image_attribute: Option<Id>,
        text_attributes: impl IntoIterator<Item = Id>,
        model_archives: impl IntoIterator<Item = [u8; 32]>,
        vision_root: Option<Id>,
        text_root: Option<Id>,
        compute: impl Into<String>,
        dimension: usize,
    ) -> Result<Self, CollectionOperationError> {
        let index = Self {
            image_attribute,
            text_attributes: text_attributes.into_iter().collect(),
            model_archives: model_archives.into_iter().collect(),
            vision_root,
            text_root,
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
        if self.model_archives.is_empty() {
            return Err(fatal("semantic index names no model archive"));
        }
        if self.image_attribute.is_some() && self.vision_root.is_none() {
            return Err(fatal("semantic index embeds images but names no vision root"));
        }
        if !self.text_attributes.is_empty() && self.text_root.is_none() {
            return Err(fatal("semantic index embeds text but names no text root"));
        }
        if self.image_attribute.is_none() && self.text_attributes.is_empty() {
            return Err(fatal("semantic index embeds nothing: no image or text attribute"));
        }
        if self.compute.is_empty() {
            return Err(fatal("semantic index names no compute class"));
        }
        Ok(())
    }

    /// The row key of one (attribute, entity) pair: attribute id in the high
    /// sixteen bytes, entity id in the low sixteen.
    pub fn row_key(attribute: Id, entity: RawId) -> [u8; HANDLE_LEN] {
        let mut key = [0u8; HANDLE_LEN];
        key[..16].copy_from_slice(&attribute[..]);
        key[16..].copy_from_slice(&entity);
        key
    }

    /// The (attribute, entity) pair a row key names, or `None` for a key
    /// that is not one of ours.
    pub fn row_entity(key: &[u8; HANDLE_LEN]) -> Option<(Id, Id)> {
        let attribute = Id::new(key[..16].try_into().expect("16 bytes"))?;
        let entity = Id::new(key[16..].try_into().expect("16 bytes"))?;
        Some((attribute, entity))
    }

    fn model_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(32 * (self.model_archives.len() + 2));
        for archive in &self.model_archives {
            key.extend_from_slice(archive);
        }
        for root in [self.vision_root, self.text_root] {
            match root {
                Some(id) => key.extend_from_slice(&id[..]),
                None => key.extend_from_slice(&[0u8; 16]),
            }
        }
        key
    }

    /// The embedders this index computes with, loaded once per thread from
    /// the pinned archives through `reader`, the same frozen boundary the
    /// source came from.
    fn models<R>(&self, reader: &R) -> Result<Rc<Models>, CollectionOperationError>
    where
        R: BlobStoreGet,
    {
        let key = self.model_key();
        if let Some(models) = MODELS.with(|cache| cache.borrow().get(&key).cloned()) {
            return Ok(models);
        }
        let mut facts = TribleSet::new();
        for raw in &self.model_archives {
            let handle = Inline::<Handle<SimpleArchive>>::new(*raw);
            let archive: TribleSet = reader.get(handle).map_err(|source| {
                fatal(format!(
                    "semantic index cannot read model archive {}: {source}",
                    hex(raw)
                ))
            })?;
            facts.union(archive);
        }
        let device = mary::embed::default_device();
        let vision = match self.vision_root {
            Some(root) => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| fatal(format!("semantic index vision root {root:X}: {source:#}")))?;
                Some(
                    mary::embed::load_nomic_vision_from_keymap(keymap, device.clone())
                        .map_err(|source| fatal(format!("semantic index vision model: {source:#}")))?,
                )
            }
            None => None,
        };
        let text = match self.text_root {
            Some(root) => {
                let keymap = load_keymap_from_graph(&facts, reader, ModelSelector::Root(root))
                    .map_err(|source| fatal(format!("semantic index text root {root:X}: {source:#}")))?;
                let tokenizer = load_tokenizer_from_graph(&facts, reader, TokenizerSelector::Only)
                    .map_err(|source| fatal(format!("semantic index text tokenizer: {source:#}")))?;
                Some(
                    mary::embed::nomic_text_from_parts(keymap, tokenizer, device)
                        .map_err(|source| fatal(format!("semantic index text model: {source:#}")))?,
                )
            }
            None => None,
        };
        let models = Rc::new(Models { vision, text });
        MODELS.with(|cache| {
            cache.borrow_mut().insert(key, models.clone());
        });
        Ok(models)
    }
}

type Backend = mary::nn::backend::B;

struct Models {
    vision: Option<mary::embed::NomicVisionEmbedder<Backend>>,
    text: Option<mary::embed::NomicTextEmbedder<Backend>>,
}

thread_local! {
    static MODELS: RefCell<HashMap<Vec<u8>, Rc<Models>>> = RefCell::new(HashMap::new());
}

fn fatal(message: impl Into<String>) -> CollectionOperationError {
    CollectionOperationError::Fatal(message.into())
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn mapping_entity(target: &Fragment) -> Result<Id, CollectionOperationError> {
    triblespace_core::collection::descriptor::mapping(target.facts())
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("semantic index descriptor carries no mapping"))
}

fn scalar_id(
    facts: &TribleSet,
    attribute: Id,
) -> Result<Option<Id>, CollectionOperationError> {
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

fn repeated_archives(facts: &TribleSet, mapping: Id, attribute: Id) -> BTreeSet<[u8; 32]> {
    let subject: Inline<GenId> = mapping.to_inline();
    let attribute: Inline<GenId> = attribute.to_inline();
    find!(
        (v: Inline<Handle<SimpleArchive>>),
        facts.pattern::<Handle<SimpleArchive>>(subject, attribute, v)
    )
    .map(|(v,)| v.raw)
    .collect()
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
        let image: Option<Inline<GenId>> = self.image_attribute.map(|id| id.to_inline());
        let vision: Option<Inline<GenId>> = self.vision_root.map(|id| id.to_inline());
        let text: Option<Inline<GenId>> = self.text_root.map(|id| id.to_inline());
        let mut fragment = entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <NomicAttributesToNvFp4Recipe as MetaDescribe>::describe(),
            metadata::blob_encoding*: E::describe(),
            nvfp4_dimension: self.dimension as u64,
            semantic_compute: self.compute.as_str(),
            semantic_image_attribute?: image,
            semantic_vision_root?: vision,
            semantic_text_root?: text,
        };
        let mapping = fragment.root().expect("mapping entity root");
        for attribute in &self.text_attributes {
            let value: Inline<GenId> = attribute.to_inline();
            fragment
                .facts_mut()
                .insert(&Trible::force(&mapping, &semantic_text_attribute.id(), &value));
        }
        for archive in &self.model_archives {
            let value = Inline::<Handle<SimpleArchive>>::new(*archive);
            fragment
                .facts_mut()
                .insert(&Trible::force(&mapping, &semantic_model_archive.id(), &value));
        }
        fragment
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        let facts = target.facts();
        let algorithm = triblespace_core::collection::descriptor::mapping_algorithm(facts).map_err(|source| fatal(source.to_string()))?;
        if algorithm != Some(NOMIC_ATTRIBUTES_TO_NVFP4) {
            return Err(fatal(format!(
                "semantic index mapping algorithm {:?} does not match {NOMIC_ATTRIBUTES_TO_NVFP4:X}",
                algorithm.map(|id| format!("{id:X}")),
            )));
        }
        let mapping = mapping_entity(target)?;
        let dimension = crate::nvfp4::mapping_dimension(target)?;
        let compute_raw =
            triblespace_core::collection::descriptor::mapping_argument(facts, semantic_compute.id())
                .map_err(|source| fatal(source.to_string()))?
                .ok_or_else(|| fatal("semantic index names no compute class"))?;
        let compute_class: String = Inline::<ShortString>::new(compute_raw)
            .try_from_inline()
            .map_err(|source| fatal(format!("semantic index: invalid compute class: {source:?}")))?;
        Self::new(
            scalar_id(facts, semantic_image_attribute.id())?,
            repeated_ids(facts, mapping, semantic_text_attribute.id()),
            repeated_archives(facts, mapping, semantic_model_archive.id()),
            scalar_id(facts, semantic_vision_root.id())?,
            scalar_id(facts, semantic_text_root.id())?,
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
        R: BlobStoreGet + BlobStoreMeta,
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
                .image_attribute
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
                return Err(CollectionOperationError::MissingDependency(
                    Handle::<RawBytes>::to_hash(handle),
                ));
            }
        }
        for handles in texts.values() {
            let handle = Inline::<Handle<UTF8String>>::new(*handles.first().expect("non-empty set"));
            if reader
                .metadata(handle)
                .map_err(|source| fatal(source.to_string()))?
                .is_none()
            {
                return Err(CollectionOperationError::MissingDependency(
                    Handle::<UTF8String>::to_hash(handle),
                ));
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

        let mut rows = Vec::with_capacity(images.len() + texts.len());
        if let (Some(attribute), Some(vision)) = (self.image_attribute, models.vision.as_ref()) {
            for (entity, handles) in &images {
                let raw = *handles.first().expect("non-empty set");
                let bytes: Bytes = reader
                    .get(Inline::<Handle<RawBytes>>::new(raw))
                    .map_err(|source| fatal(source.to_string()))?;
                // Not every value under the attribute is a raster image (a
                // PDF, an SVG); one that does not decode gets no row, which
                // is the same answer every time for the same bytes.
                let Ok(vector) = vision.embed_image(bytes.as_ref()) else {
                    continue;
                };
                if vector.len() != self.dimension {
                    return Err(fatal(format!(
                        "vision model produced {} dimensions, index has {}",
                        vector.len(),
                        self.dimension
                    )));
                }
                rows.push(
                    StoredRow::quantize(Self::row_key(attribute, *entity), &vector, self.dimension)
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
                    StoredRow::quantize(Self::row_key(*attribute, *entity), &vector, self.dimension)
                        .map_err(|source| fatal(source.to_string()))?,
                );
            }
        }
        encode_rows::<E>(self.dimension, rows).map_err(|source| fatal(source.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::Embedding;

    fn archive(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn descriptor_round_trips_every_argument() {
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionPolicy, CollectionStoreExt,
        };
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_core::repo::SnapshotSource;

        let image = Id::new([1; 16]).unwrap();
        let title = Id::new([2; 16]).unwrap();
        let body = Id::new([3; 16]).unwrap();
        let vision = Id::new([4; 16]).unwrap();
        let text = Id::new([5; 16]).unwrap();
        let index = SemanticIndex::<Embedding>::new(
            Some(image),
            [title, body],
            [archive(7), archive(8), archive(9)],
            Some(vision),
            Some(text),
            "gb10",
            768,
        )
        .unwrap();

        // The descriptor a store writes is the one bind reads back.
        let mut store = MemoryRepo::default();
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let policy = CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let source = store.collection("source", policy.clone()).unwrap();
        let target = store.derive_with(source, index.clone(), policy).unwrap();
        let snapshot = store.snapshot().unwrap();
        let descriptor: Blob<SimpleArchive> = snapshot.get(target.handle()).unwrap();
        let descriptor = Fragment::from(TribleSet::try_from_blob(descriptor).unwrap());
        let bound = SemanticIndex::<Embedding>::bind(&Fragment::empty(), &descriptor).unwrap();
        assert_eq!(bound, index);
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
    fn an_index_that_embeds_nothing_is_refused() {
        let error = SemanticIndex::<Embedding>::new(
            None,
            [],
            [archive(1)],
            None,
            None,
            "gb10",
            768,
        )
        .unwrap_err();
        assert!(error.to_string().contains("embeds nothing"), "{error}");
    }
}
