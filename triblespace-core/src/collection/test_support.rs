//! Test-only oracles over the lattice-v2 model.
//!
//! A collection's support is a cover of its OWN foundations, and production
//! code never compares two collections' supports. Tests written against the
//! earlier model asserted that a view "stands for" a set of root commits;
//! [`stood_for`] answers that question the only way the model allows, by
//! following each root foundation up the view's descriptor chain through the
//! leaves (`DERIVE` records) of every hop, by locator.

use std::collections::BTreeSet;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::inline::Inline;
use crate::repo::StoreRead;
use crate::trible::TribleSet;

use super::{
    descriptor, Collection, CollectionEncoding, CollectionSnapshot, SourceLocator, Support,
};

/// The root commits `view` stands for: every admitted foundation `F` of the
/// root beneath it that reaches one of `view`'s own support members through a
/// chain of leaves, one per hop.
pub(crate) fn stood_for<R, E>(view: &CollectionSnapshot<R, E>) -> Support<SimpleArchive>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let snapshot = view.snapshot();
    let mut chain = vec![view.cover().collection().handle()];
    loop {
        let last = *chain.last().expect("the chain starts at the view");
        let facts: TribleSet = snapshot.get(last).expect("a descriptor in the chain");
        match descriptor::source(&facts).expect("a decodable source") {
            Some(source) => chain.push(source),
            None => break,
        }
    }
    let root = *chain.last().expect("the chain ends at a root");
    let scope: BTreeSet<_> = chain.iter().copied().collect();
    let coverage = snapshot.coverage(&scope).expect("coverage of the chain");
    let top: BTreeSet<[u8; 32]> = view
        .support()
        .expect("view support")
        .data_members()
        .map(|member| member.raw)
        .collect();
    let (foundations, _) = coverage.frontier_support(root);
    let mut stood = Vec::new();
    for raw in foundations.iter_ordered() {
        let mut images = BTreeSet::from([*raw]);
        for hop in chain.iter().rev().skip(1) {
            images = images
                .iter()
                .flat_map(|image| coverage.leaf_outputs(*hop, SourceLocator::of(*image)))
                .map(|output| output.raw)
                .collect();
        }
        if images.iter().any(|image| top.contains(image)) {
            stood.push(Inline::new(*raw));
        }
    }
    Support::from_data(Collection::from_handle(root), stood)
}

/// A test-only derived encoding: a `SimpleArchive`'s bytes followed by
/// `0xC1`, with union as its join.
///
/// Every index this crate defines is attached, not derived, so tests of the
/// derived machinery -- leaves, admission, the derived carry, observation --
/// use this instead. Its encoding id was minted with `trible genid` on
/// 2026-09-28.
pub(crate) struct TestImage;

const TEST_IMAGE: crate::id::Id = crate::id_hex!("AFEDC28B3883A4AEB3BADA9E6E1CDE47");
/// Minted with `trible genid` on 2026-09-28.
const TEST_IMAGE_MAPPING: crate::id::Id = crate::id_hex!("CB417A44A612FE2D2A77A56206126CA6");
/// A second hop over [`TestImage`]: its bytes followed by `0xC2`. Minted with
/// `trible genid` on 2026-09-28.
pub(crate) struct TestImageTwo;

const TEST_IMAGE_TWO: crate::id::Id = crate::id_hex!("03C9E070964C0B824D73A98FF4DB0615");
/// Minted with `trible genid` on 2026-09-28.
const TEST_IMAGE_TWO_MAPPING: crate::id::Id = crate::id_hex!("C516B3F35FF46179BA21FC010F7ED769");

struct TestImageMapping;
struct TestImageTwoMapping;

mod test_images {
    use std::convert::Infallible;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::{Blob, BlobEncoding};
    use crate::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
    use crate::collection::{
        CollectionDerivation, CollectionEncoding, CollectionOperationError, Cover, TryFromCover,
        TryFromCoverError,
    };
    use crate::id::ExclusiveId;
    use crate::macros::entity;
    use crate::metadata::{self, MetaDescribe};
    use crate::repo::{BlobStoreGet, BlobStoreMeta, StoreRead};
    use crate::trible::{Fragment, TribleSet};

    use super::{
        TestImage, TestImageMapping, TestImageTwo, TestImageTwoMapping, TEST_IMAGE,
        TEST_IMAGE_MAPPING, TEST_IMAGE_TWO, TEST_IMAGE_TWO_MAPPING,
    };

    impl BlobEncoding for TestImage {}
    impl BlobEncoding for TestImageTwo {}

    fn described(id: crate::id::Id, name: &str, tag: crate::id::Id) -> Fragment {
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: name.to_owned(),
            metadata::tag: tag,
        }
    }

    impl MetaDescribe for TestImage {
        fn describe() -> Fragment {
            described(
                TEST_IMAGE,
                "derived-test-image",
                metadata::KIND_BLOB_ENCODING,
            )
        }
    }

    impl MetaDescribe for TestImageTwo {
        fn describe() -> Fragment {
            described(
                TEST_IMAGE_TWO,
                "derived-test-image-two",
                metadata::KIND_BLOB_ENCODING,
            )
        }
    }

    impl MetaDescribe for TestImageMapping {
        fn describe() -> Fragment {
            described(
                TEST_IMAGE_MAPPING,
                "derived-test-image-mapping",
                metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
            )
        }
    }

    impl MetaDescribe for TestImageTwoMapping {
        fn describe() -> Fragment {
            described(
                TEST_IMAGE_TWO_MAPPING,
                "derived-test-image-two-mapping",
                metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
            )
        }
    }

    fn fatal(reason: impl ToString) -> CollectionOperationError {
        CollectionOperationError::Fatal(reason.to_string())
    }

    fn suffixed<E>(bytes: &[u8], suffix: &[u8]) -> Blob<E>
    where
        E: BlobEncoding,
    {
        let mut out = bytes.to_vec();
        out.extend_from_slice(suffix);
        Blob::new(out.into())
    }

    impl TestImage {
        /// The image of one archive.
        pub(crate) fn image(source: &Blob<SimpleArchive>) -> Blob<TestImage> {
            suffixed(source.bytes.as_ref(), &[0xC1])
        }

        /// The archive one image holds.
        pub(crate) fn archive(
            image: &Blob<TestImage>,
        ) -> Result<Blob<SimpleArchive>, CollectionOperationError> {
            let bytes = image
                .bytes
                .as_ref()
                .strip_suffix(&[0xC1])
                .ok_or_else(|| fatal("a test image lacks its suffix"))?;
            let archive = Blob::new(bytes.to_vec().into());
            crate::collection::simplearchive_union::validate_element(&archive).map_err(fatal)?;
            Ok(archive)
        }
    }

    impl TestImageTwo {
        /// The second-hop image of one first-hop image.
        pub(crate) fn image(source: &Blob<TestImage>) -> Blob<TestImageTwo> {
            suffixed(source.bytes.as_ref(), &[0xC2])
        }

        fn first(image: &Blob<TestImageTwo>) -> Result<Blob<TestImage>, CollectionOperationError> {
            let bytes = image
                .bytes
                .as_ref()
                .strip_suffix(&[0xC2])
                .ok_or_else(|| fatal("a second test image lacks its suffix"))?;
            let first = Blob::new(bytes.to_vec().into());
            TestImage::archive(&first)?;
            Ok(first)
        }
    }

    impl CollectionEncoding for TestImage {
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
            let joined = crate::collection::simplearchive_union::join(
                &Self::archive(low)?,
                &Self::archive(high)?,
            )
            .map_err(fatal)?;
            Ok(Self::image(&joined))
        }
    }

    impl CollectionEncoding for TestImageTwo {
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
            let joined = TestImage::join_members(
                descriptor,
                &Self::first(low)?,
                &Self::first(high)?,
                reader,
            )?;
            Ok(Self::image(&joined))
        }
    }

    fn mapping_fragment<M: MetaDescribe>() -> Fragment {
        entity! {
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <M as MetaDescribe>::describe(),
        }
    }

    fn require(target: &Fragment, expected: crate::id::Id) -> Result<(), CollectionOperationError> {
        let actual =
            crate::collection::descriptor::mapping_algorithm(target.facts()).map_err(fatal)?;
        if actual == Some(expected) {
            Ok(())
        } else {
            Err(fatal("the descriptor names another test mapping"))
        }
    }

    impl CollectionDerivation for TestImage {
        type Source = SimpleArchive;
        type Argument = ();

        fn fragment(_argument: &()) -> Fragment {
            mapping_fragment::<TestImageMapping>()
        }

        fn bind(_source: &Fragment, target: &Fragment) -> Result<(), CollectionOperationError> {
            require(target, TEST_IMAGE_MAPPING)
        }

        fn map<R>(
            _argument: &(),
            source: &Blob<SimpleArchive>,
            _reader: &R,
        ) -> Result<Blob<Self>, CollectionOperationError>
        where
            R: StoreRead,
        {
            Ok(Self::image(source))
        }
    }

    impl CollectionDerivation for TestImageTwo {
        type Source = TestImage;
        type Argument = ();

        fn fragment(_argument: &()) -> Fragment {
            mapping_fragment::<TestImageTwoMapping>()
        }

        fn bind(_source: &Fragment, target: &Fragment) -> Result<(), CollectionOperationError> {
            require(target, TEST_IMAGE_TWO_MAPPING)
        }

        fn map<R>(
            _argument: &(),
            source: &Blob<TestImage>,
            _reader: &R,
        ) -> Result<Blob<Self>, CollectionOperationError>
        where
            R: StoreRead,
        {
            Ok(Self::image(source))
        }
    }

    fn facts_of<R: BlobStoreGet>(
        archive: Blob<SimpleArchive>,
    ) -> Result<TribleSet, TryFromCoverError<R::GetError<Infallible>, CollectionOperationError>>
    {
        <TribleSet as crate::blob::TryFromBlob<SimpleArchive>>::try_from_blob(archive)
            .map_err(|error| TryFromCoverError::View(fatal(format!("{error:?}"))))
    }

    impl TryFromCover<TestImage> for TribleSet {
        type Error = CollectionOperationError;

        fn try_from_cover<R>(
            cover: &Cover<TestImage>,
            _descriptor: &Fragment,
            snapshot: &R,
        ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
        where
            R: BlobStoreGet,
        {
            let mut facts = TribleSet::new();
            for member in cover.members() {
                let blob: Blob<TestImage> =
                    snapshot
                        .get(member)
                        .map_err(|source| TryFromCoverError::MemberGet {
                            member: crate::inline::encodings::hash::Handle::to_hash(member),
                            source,
                        })?;
                let archive = TestImage::archive(&blob).map_err(TryFromCoverError::View)?;
                facts += facts_of::<R>(archive)?;
            }
            Ok(facts)
        }
    }

    impl TryFromCover<TestImageTwo> for TribleSet {
        type Error = CollectionOperationError;

        fn try_from_cover<R>(
            cover: &Cover<TestImageTwo>,
            _descriptor: &Fragment,
            snapshot: &R,
        ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
        where
            R: BlobStoreGet,
        {
            let mut facts = TribleSet::new();
            for member in cover.members() {
                let blob: Blob<TestImageTwo> =
                    snapshot
                        .get(member)
                        .map_err(|source| TryFromCoverError::MemberGet {
                            member: crate::inline::encodings::hash::Handle::to_hash(member),
                            source,
                        })?;
                let first = TestImageTwo::first(&blob).map_err(TryFromCoverError::View)?;
                let archive = TestImage::archive(&first).map_err(TryFromCoverError::View)?;
                facts += facts_of::<R>(archive)?;
            }
            Ok(facts)
        }
    }
}
