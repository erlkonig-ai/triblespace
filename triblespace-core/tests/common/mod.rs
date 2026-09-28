//! A derived encoding for integration tests of the derived machinery.
//!
//! Every index the crate defines is attached, not derived, so these tests
//! derive through [`Image`] (a `SimpleArchive`'s bytes followed by `0xC1`,
//! joined by union) and [`ImageTwo`] (an image's bytes followed by `0xC2`).
//! The ids are the crate's own test-image ids, minted with `trible genid` on
//! 2026-09-28.

#![allow(dead_code)]

use std::convert::Infallible;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::simplearchive_union;
use triblespace_core::collection::{
    mapping_algorithm, CollectionDerivation, CollectionEncoding, CollectionOperationError, Cover,
    TryFromCover, TryFromCoverError, KIND_COLLECTION_MAPPING,
};
use triblespace_core::id::{id_hex, ExclusiveId, Id};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::prelude::entity;
use triblespace_core::repo::{BlobStoreGet, BlobStoreMeta, StoreRead};
use triblespace_core::trible::{Fragment, TribleSet};

const IMAGE: Id = id_hex!("AFEDC28B3883A4AEB3BADA9E6E1CDE47");
/// The mapping algorithm of [`Image`].
pub const IMAGE_MAPPING: Id = id_hex!("CB417A44A612FE2D2A77A56206126CA6");
const IMAGE_TWO: Id = id_hex!("03C9E070964C0B824D73A98FF4DB0615");
const IMAGE_TWO_MAPPING: Id = id_hex!("C516B3F35FF46179BA21FC010F7ED769");

pub struct Image;
pub struct ImageTwo;
struct ImageMapping;
struct ImageTwoMapping;

impl BlobEncoding for Image {}
impl BlobEncoding for ImageTwo {}

fn described(id: Id, name: &str, tag: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&id) @
        metadata::name: name.to_owned(),
        metadata::tag: tag,
    }
}

impl MetaDescribe for Image {
    fn describe() -> Fragment {
        described(IMAGE, "derived-test-image", metadata::KIND_BLOB_ENCODING)
    }
}

impl MetaDescribe for ImageTwo {
    fn describe() -> Fragment {
        described(
            IMAGE_TWO,
            "derived-test-image-two",
            metadata::KIND_BLOB_ENCODING,
        )
    }
}

impl MetaDescribe for ImageMapping {
    fn describe() -> Fragment {
        described(
            IMAGE_MAPPING,
            "derived-test-image-mapping",
            metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        )
    }
}

impl MetaDescribe for ImageTwoMapping {
    fn describe() -> Fragment {
        described(
            IMAGE_TWO_MAPPING,
            "derived-test-image-two-mapping",
            metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        )
    }
}

fn fatal(reason: impl ToString) -> CollectionOperationError {
    CollectionOperationError::Fatal(reason.to_string())
}

fn suffixed<E: BlobEncoding>(bytes: &[u8], suffix: &[u8]) -> Blob<E> {
    let mut out = bytes.to_vec();
    out.extend_from_slice(suffix);
    Blob::new(out.into())
}

impl Image {
    pub fn image(source: &Blob<SimpleArchive>) -> Blob<Image> {
        suffixed(source.bytes.as_ref(), &[0xC1])
    }

    pub fn archive(image: &Blob<Image>) -> Result<Blob<SimpleArchive>, CollectionOperationError> {
        let bytes = image
            .bytes
            .as_ref()
            .strip_suffix(&[0xC1])
            .ok_or_else(|| fatal("a test image lacks its suffix"))?;
        let archive = Blob::new(bytes.to_vec().into());
        simplearchive_union::validate_element(&archive).map_err(fatal)?;
        Ok(archive)
    }

    /// The join of several images.
    pub fn join(images: &[Blob<Image>]) -> Blob<Image> {
        let mut joined = Blob::<SimpleArchive>::new(Vec::<u8>::new().into());
        for image in images {
            joined = simplearchive_union::join(&joined, &Self::archive(image).unwrap()).unwrap();
        }
        Self::image(&joined)
    }
}

impl ImageTwo {
    pub fn image(source: &Blob<Image>) -> Blob<ImageTwo> {
        suffixed(source.bytes.as_ref(), &[0xC2])
    }

    pub fn first(image: &Blob<ImageTwo>) -> Result<Blob<Image>, CollectionOperationError> {
        let bytes = image
            .bytes
            .as_ref()
            .strip_suffix(&[0xC2])
            .ok_or_else(|| fatal("a second test image lacks its suffix"))?;
        let first = Blob::new(bytes.to_vec().into());
        Image::archive(&first)?;
        Ok(first)
    }
}

impl CollectionEncoding for Image {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Self::archive(member).map(drop)
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let joined = simplearchive_union::join(&Self::archive(low)?, &Self::archive(high)?)
            .map_err(fatal)?;
        Ok(Self::image(&joined))
    }
}

impl CollectionEncoding for ImageTwo {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Self::first(member).map(drop)
    }

    fn join_members<R>(
        descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let joined =
            Image::join_members(descriptor, &Self::first(low)?, &Self::first(high)?, reader)?;
        Ok(Self::image(&joined))
    }
}

fn mapping_fragment<M: MetaDescribe>() -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <M as MetaDescribe>::describe(),
    }
}

fn require(target: &Fragment, expected: Id) -> Result<(), CollectionOperationError> {
    let actual = triblespace_core::collection::descriptor::mapping_algorithm(target.facts())
        .map_err(fatal)?;
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(fatal("the descriptor names another test mapping"))
    }
}

impl CollectionDerivation for Image {
    type Source = SimpleArchive;
    type Argument = ();

    fn fragment(_argument: &()) -> Fragment {
        mapping_fragment::<ImageMapping>()
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<(), CollectionOperationError> {
        require(target, IMAGE_MAPPING)
    }

    fn map<R: StoreRead>(
        _argument: &(),
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError> {
        Ok(Self::image(source))
    }
}

impl CollectionDerivation for ImageTwo {
    type Source = Image;
    type Argument = ();

    fn fragment(_argument: &()) -> Fragment {
        mapping_fragment::<ImageTwoMapping>()
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<(), CollectionOperationError> {
        require(target, IMAGE_TWO_MAPPING)
    }

    fn map<R: StoreRead>(
        _argument: &(),
        source: &Blob<Image>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError> {
        Ok(Self::image(source))
    }
}

fn facts_of<E>(
    archive: Blob<SimpleArchive>,
) -> Result<TribleSet, TryFromCoverError<E, CollectionOperationError>> {
    TribleSet::try_from_blob(archive)
        .map_err(|error| TryFromCoverError::View(fatal(format!("{error:?}"))))
}

/// The facts a cover of images holds.
pub struct ImageFacts(pub TribleSet);

impl TryFromCover<Image> for ImageFacts {
    type Error = CollectionOperationError;

    fn try_from_cover<R>(
        cover: &Cover<Image>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut facts = TribleSet::new();
        for member in cover.members() {
            let blob: Blob<Image> =
                snapshot
                    .get(member)
                    .map_err(|source| TryFromCoverError::MemberGet {
                        member: Handle::to_hash(member),
                        source,
                    })?;
            let archive = Image::archive(&blob).map_err(TryFromCoverError::View)?;
            facts += facts_of(archive)?;
        }
        Ok(Self(facts))
    }
}

impl TryFromCover<ImageTwo> for ImageFacts {
    type Error = CollectionOperationError;

    fn try_from_cover<R>(
        cover: &Cover<ImageTwo>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut facts = TribleSet::new();
        for member in cover.members() {
            let blob: Blob<ImageTwo> =
                snapshot
                    .get(member)
                    .map_err(|source| TryFromCoverError::MemberGet {
                        member: Handle::to_hash(member),
                        source,
                    })?;
            let first = ImageTwo::first(&blob).map_err(TryFromCoverError::View)?;
            let archive = Image::archive(&first).map_err(TryFromCoverError::View)?;
            facts += facts_of(archive)?;
        }
        Ok(Self(facts))
    }
}
