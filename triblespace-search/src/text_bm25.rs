//! BM25 as a derived collection: from one text attribute to the portable
//! carrier.
//!
//! [`PortableBM25Blob`] already joins by document union and pointwise-maximum
//! term frequency, so the LSM maintenance folds it exactly. What was missing
//! was a way to *get* one from facts: this module is the mapping. Its argument
//! is the attribute whose values are [`UTF8String`] handles and the tokenizer
//! to cut them with; both live in the derived descriptor, so `maintain` and
//! every reader act on the descriptor alone.
//!
//! The document key is the entity. An entity with several texts under the
//! attribute gets, per term, the largest frequency any one of its texts has:
//! not the sum, because the carrier joins by pointwise maximum, and only a
//! maximum over texts makes the map a homomorphism over source union,
//! `map(A ∪ B) = map(A) ⊔ map(B)`, when one entity's texts land in different
//! members. With one text per entity, which is the common case, the two agree.
//!
//! A text handle that is not resident is a missing dependency, never a
//! silently shorter document.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::{Blob, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{CollectionDerivation, CollectionOperationError};
use triblespace_core::id::{id_hex, ExclusiveId, Id, RawId};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::shortstring::ShortString;
use triblespace_core::inline::{Encodes, Inline, IntoInline, RawInline};
use triblespace_core::macros::{attributes, entity};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace_core::trible::{Fragment, TRIBLE_LEN};

use crate::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use crate::tokens::{bigram_tokens, code_tokens, hash_tokens, BigramHash, WordHash};

/// Stable identity of the text-attribute-to-BM25 mapping. Minted with
/// `trible genid` on 2026-09-10. The selected attribute and the tokenizer are
/// mapping-instance parameters.
pub const TEXT_ATTRIBUTE_TO_BM25: Id = id_hex!("221CC84DDF0A61477A26BCE6ABD879D1");

attributes! {
    /// Which tokenizer one concrete BM25 mapping cuts its texts with, by name:
    /// `word`, `bigram` or `code`. Part of the mapping instance, so two
    /// tokenizers over one attribute are two collections.
    ///
    /// Anchor minted with `trible genid` on 2026-09-10.
    "CAD86B2DE38743BB054167A35A8E95FF" as bm25_tokenizer: ShortString;
}

/// How a text is cut into terms. Each variant names one function of
/// [`crate::tokens`] and the term hash space it produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bm25Tokenizer {
    /// Unicode words, lowercased and hashed: [`hash_tokens`].
    Word,
    /// Adjacent word pairs: [`bigram_tokens`].
    Bigram,
    /// Identifiers split on case and punctuation, for source code: [`code_tokens`].
    Code,
}

impl Bm25Tokenizer {
    pub fn name(self) -> &'static str {
        match self {
            Self::Word => "word",
            Self::Bigram => "bigram",
            Self::Code => "code",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "word" => Some(Self::Word),
            "bigram" => Some(Self::Bigram),
            "code" => Some(Self::Code),
            _ => None,
        }
    }

    /// The raw 32-byte terms of `text` under this tokenizer.
    fn terms(self, text: &str) -> Vec<RawInline> {
        match self {
            Self::Word => hash_tokens(text).into_iter().map(|t| t.raw).collect(),
            Self::Bigram => bigram_tokens(text).into_iter().map(|t| t.raw).collect(),
            Self::Code => code_tokens(text).into_iter().map(|t| t.raw).collect(),
        }
    }
}

/// The argument of one BM25 derivation: which attribute holds the texts, and
/// how to cut them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextAttributeToBm25 {
    pub attribute: Id,
    pub tokenizer: Bm25Tokenizer,
}

struct TextAttributeToBm25Recipe;

impl MetaDescribe for TextAttributeToBm25Recipe {
    fn describe() -> Fragment {
        let id = TEXT_ATTRIBUTE_TO_BM25;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "text-attribute-to-bm25",
            metadata::description: "Canonical join-preserving projection from one selected Handle<UTF8String>-valued SimpleArchive attribute to a portable BM25 carrier: the entity is the document, its texts are cut by the named tokenizer, and term frequencies are exact counts. Joins by document union and pointwise-maximum frequency.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

fn mapping_fragment(argument: &TextAttributeToBm25) -> Fragment {
    let attribute: Inline<GenId> = argument.attribute.to_inline();
    entity! { _ @
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <TextAttributeToBm25Recipe as MetaDescribe>::describe(),
        metadata::attribute: attribute,
        bm25_tokenizer: argument.tokenizer.name(),
    }
}

fn fatal(message: impl Into<String>) -> CollectionOperationError {
    CollectionOperationError::Fatal(message.into())
}

impl CollectionDerivation for PortableBM25Blob {
    type Source = SimpleArchive;
    type Argument = TextAttributeToBm25;

    fn fragment(argument: &Self::Argument) -> Fragment {
        mapping_fragment(argument)
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        let descriptor =
            triblespace_core::collection::descriptor::mapping_algorithm(target.facts())
                .map_err(|source| fatal(source.to_string()))?;
        if descriptor != Some(TEXT_ATTRIBUTE_TO_BM25) {
            return Err(fatal(format!(
                "BM25 mapping algorithm {:?} does not match {TEXT_ATTRIBUTE_TO_BM25:X}",
                descriptor.map(|id| format!("{id:X}")),
            )));
        }
        let attribute = triblespace_core::collection::descriptor::mapping_argument(
            target.facts(),
            metadata::attribute.id(),
        )
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("BM25 mapping is missing its text attribute"))?;
        let attribute = Inline::<GenId>::new(attribute)
            .try_from_inline::<Id>()
            .map_err(|source| fatal(format!("invalid BM25 text attribute: {source:?}")))?;
        let tokenizer = triblespace_core::collection::descriptor::mapping_argument(
            target.facts(),
            bm25_tokenizer.id(),
        )
        .map_err(|source| fatal(source.to_string()))?
        .ok_or_else(|| fatal("BM25 mapping is missing its tokenizer"))?;
        let tokenizer: String = Inline::<ShortString>::new(tokenizer)
            .try_from_inline()
            .map_err(|source| fatal(format!("invalid BM25 tokenizer name: {source:?}")))?;
        let tokenizer = Bm25Tokenizer::from_name(&tokenizer)
            .ok_or_else(|| fatal(format!("unknown BM25 tokenizer {tokenizer:?}")))?;
        Ok(TextAttributeToBm25 {
            attribute,
            tokenizer,
        })
    }

    fn map<R>(
        argument: &Self::Argument,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        triblespace_core::collection::simplearchive_union::validate_element(source)
            .map_err(|source| fatal(source.to_string()))?;

        // Every text handle under the attribute, per entity. A set, because a
        // repeated fact is one fact and must count its terms once.
        let mut texts: BTreeMap<RawId, BTreeSet<RawInline>> = BTreeMap::new();
        for raw in source.bytes.as_ref().chunks_exact(TRIBLE_LEN) {
            if raw[16..32] == argument.attribute[..] {
                let entity: RawId = raw[..16].try_into().expect("16-byte entity");
                let value: RawInline = raw[32..].try_into().expect("32-byte trible value");
                texts.entry(entity).or_default().insert(value);
            }
        }

        let mut documents: Vec<Inline<GenId>> = Vec::with_capacity(texts.len());
        let mut counts: Vec<(Inline<GenId>, RawInline, u32)> = Vec::new();
        for (entity, handles) in texts {
            let document: Inline<GenId> = GenId::encode(entity);
            // Per term, the maximum over this entity's texts: see the module
            // doc for why not the sum.
            let mut frequencies: BTreeMap<RawInline, u32> = BTreeMap::new();
            for raw in handles {
                let handle = Inline::<Handle<UTF8String>>::new(raw);
                let resident = reader
                    .metadata(handle)
                    .map_err(|source| fatal(source.to_string()))?;
                if resident.is_none() {
                    return Err(CollectionOperationError::MissingDependency(Handle::<
                        UTF8String,
                    >::to_hash(
                        handle
                    )));
                }
                let blob: Blob<UTF8String> = reader
                    .get(handle)
                    .map_err(|source| fatal(source.to_string()))?;
                let text: View<str> = View::try_from_blob(blob).map_err(|source| {
                    fatal(format!(
                        "text {} is not UTF-8: {source:?}",
                        raw.iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<String>()
                    ))
                })?;
                let mut in_this_text: BTreeMap<RawInline, u32> = BTreeMap::new();
                for term in argument.tokenizer.terms(&text) {
                    *in_this_text.entry(term).or_insert(0) += 1;
                }
                for (term, frequency) in in_this_text {
                    frequencies
                        .entry(term)
                        .and_modify(|best| *best = (*best).max(frequency))
                        .or_insert(frequency);
                }
            }
            documents.push(document);
            counts.extend(
                frequencies
                    .into_iter()
                    .map(|(term, frequency)| (document, term, frequency)),
            );
        }

        let index = match argument.tokenizer {
            Bm25Tokenizer::Bigram => PortableBM25Index::<GenId, BigramHash>::from_exact_counts(
                documents,
                counts.into_iter().map(|(document, term, frequency)| {
                    (document, Inline::<BigramHash>::new(term), frequency)
                }),
            )
            .map_err(|source| fatal(source.to_string()))?
            .bytes()
            .clone(),
            Bm25Tokenizer::Word | Bm25Tokenizer::Code => {
                PortableBM25Index::<GenId, WordHash>::from_exact_counts(
                    documents,
                    counts.into_iter().map(|(document, term, frequency)| {
                        (document, Inline::<WordHash>::new(term), frequency)
                    }),
                )
                .map_err(|source| fatal(source.to_string()))?
                .bytes()
                .clone()
            }
        };
        Ok(Blob::new(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace_core::attribute::Attribute;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::CollectionEncoding;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource};
    use triblespace_core::trible::{Trible, TribleSet};

    fn text_facts(
        attribute: Id,
        rows: impl IntoIterator<Item = (u8, Inline<Handle<UTF8String>>)>,
    ) -> TribleSet {
        let mut facts = TribleSet::new();
        for (entity, text) in rows {
            let entity = Id::new([entity; 16]).unwrap();
            facts.insert(&Trible::force(&entity, &attribute, &text));
        }
        facts
    }

    #[test]
    fn derived_through_a_store_the_descriptor_binds_and_maintains() {
        use ed25519_dalek::SigningKey;
        use futures::executor::block_on;
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
        };
        use triblespace_core::repo::BlobStoreGet;

        let authority = SigningKey::from_bytes(&[41; 32]);
        let root = authority.verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let attribute = Attribute::<Handle<UTF8String>>::named("bm25-derived");
        let argument = TextAttributeToBm25 {
            attribute: attribute.id(),
            tokenizer: Bm25Tokenizer::Bigram,
        };
        let mut store = MemoryRepo::default();
        let text = store
            .put::<UTF8String, _>(String::from("the quick brown fox"))
            .unwrap();
        let source = store.collection("bm25-texts", policy.clone()).unwrap();
        let target = store
            .derive::<PortableBM25Blob>(source, argument, policy)
            .unwrap();
        store
            .commit(
                source,
                &authority,
                Fragment::from(text_facts(attribute.id(), [(1, text)])),
            )
            .unwrap();

        // The descriptor alone carries the argument back.
        let snapshot = store.snapshot().unwrap();
        let descriptor: Blob<SimpleArchive> = snapshot.get(target.handle()).unwrap();
        let descriptor = Fragment::from(TribleSet::try_from_blob(descriptor).unwrap());
        assert_eq!(
            PortableBM25Blob::bind(&Fragment::empty(), &descriptor).unwrap(),
            argument
        );
        drop(snapshot);

        // Maintenance realises one member holding the one document.
        let snapshot = block_on(store.maintain(target, &authority)).unwrap();
        let collection = snapshot.collection(target).unwrap();
        let members: Vec<_> = collection.cover().members().collect();
        assert_eq!(members.len(), 1);
        let member: Blob<PortableBM25Blob> = snapshot.get(members[0]).unwrap();
        let index =
            PortableBM25Index::<GenId, BigramHash>::from_bytes(member.bytes.clone()).unwrap();
        assert_eq!(index.doc_count(), 1);
        assert_eq!(index.term_count(), 3);
    }

    #[test]
    fn mapping_is_a_join_homomorphism_over_source_union() {
        let attribute = Attribute::<Handle<UTF8String>>::named("bm25-homomorphism");
        let argument = TextAttributeToBm25 {
            attribute: attribute.id(),
            tokenizer: Bm25Tokenizer::Word,
        };
        let mut store = MemoryRepo::default();
        let apples = store
            .put::<UTF8String, _>(String::from("apples and pears, apples"))
            .unwrap();
        let pears = store
            .put::<UTF8String, _>(String::from("pears only"))
            .unwrap();
        let empty = store.put::<UTF8String, _>(String::from("")).unwrap();
        let snapshot = store.snapshot().unwrap();

        let left = text_facts(attribute.id(), [(1, apples), (2, pears)]);
        let right = text_facts(attribute.id(), [(2, apples), (3, empty)]);
        let mut union = left.clone();
        union += right.clone();

        let mapped_left = PortableBM25Blob::map(&argument, &left.to_blob(), &snapshot).unwrap();
        let mapped_right = PortableBM25Blob::map(&argument, &right.to_blob(), &snapshot).unwrap();
        let mapped_union = PortableBM25Blob::map(&argument, &union.to_blob(), &snapshot).unwrap();
        let descriptor = PortableBM25Blob::fragment(&argument);
        let joined =
            PortableBM25Blob::join_members(&descriptor, &mapped_left, &mapped_right, &snapshot)
                .unwrap();
        assert_eq!(mapped_union.bytes.as_ref(), joined.bytes.as_ref());

        let index =
            PortableBM25Index::<GenId, WordHash>::from_bytes(mapped_union.bytes.clone()).unwrap();
        assert_eq!(index.doc_count(), 3);
        let two: Inline<GenId> = GenId::encode([2u8; 16]);
        let apple_terms = hash_tokens("apples");
        assert_eq!(index.term_frequency(&two, &apple_terms[0]).unwrap(), 2);
        // "pears" occurs once in each of entity 2's texts: the maximum, not the sum.
        let pear_terms = hash_tokens("pears");
        assert_eq!(index.term_frequency(&two, &pear_terms[0]).unwrap(), 1);
    }

    #[test]
    fn a_missing_text_is_a_missing_dependency() {
        let attribute = Attribute::<Handle<UTF8String>>::named("bm25-missing");
        let argument = TextAttributeToBm25 {
            attribute: attribute.id(),
            tokenizer: Bm25Tokenizer::Word,
        };
        let mut store = MemoryRepo::default();
        let snapshot = store.snapshot().unwrap();
        let absent: Inline<Handle<UTF8String>> = Inline::new([7u8; 32]);
        let facts = text_facts(attribute.id(), [(1, absent)]);
        assert!(matches!(
            PortableBM25Blob::map(&argument, &facts.to_blob(), &snapshot),
            Err(CollectionOperationError::MissingDependency(_))
        ));
    }
}
