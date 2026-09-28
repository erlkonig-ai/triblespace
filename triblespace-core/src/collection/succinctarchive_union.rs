//! Canonical raw SuccinctArchive set union, and the Succinct and Rank9
//! indexes attached to a [`SimpleArchive`](crate::blob::encodings::simplearchive::SimpleArchive)
//! root.
//!
//! SimpleArchive and raw SuccinctArchive each own canonical set union for
//! their bytes, and the canonical conversion preserves it:
//!
//! ```text
//! succinct(a ∪ b) = succinct(a) ∪ succinct(b)
//! ```
//!
//! Both indexes are attached collections: a Succinct archive of a node is
//! mapped from the node's own bytes, a merged node's from the merged
//! `SimpleArchive`, and a Rank9 accelerator from the same node's Succinct
//! attachment, which its attached descriptor names. Neither has merges of
//! its own, and a host believes only the MAPs it signed.

use super::descriptor as descriptor_facts;
use super::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use crate::id::ExclusiveId;
use crate::metadata;
use crate::prelude::entity;
use crate::trible::Fragment;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    merge_ordered_archives, OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive,
    SuccinctArchiveBlob, SuccinctArchiveRawBuildError, SuccinctArchiveRawMergeError,
};
use crate::blob::Blob;
use crate::id::Id;
use crate::id_hex;
use crate::inline::encodings::hash::Handle;
use crate::metadata::MetaDescribe;
use crate::repo::{BlobStoreGet, BlobStoreMeta};

use super::records::mapping_reads_attached;
use super::{
    Collection, CollectionAttachment, CollectionData, CollectionEncoding, CollectionHandle,
    CollectionOperationError,
};

mod collection;
pub use collection::*;

fn resident_raw<R>(
    source: crate::inline::Inline<Handle<SuccinctArchiveBlob>>,
    reader: &R,
) -> Result<Blob<SuccinctArchiveBlob>, CollectionOperationError>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    let resident = reader
        .metadata(source)
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
        .is_some();
    if !resident {
        return Err(CollectionOperationError::MissingDependency(Handle::<
            SuccinctArchiveBlob,
        >::to_hash(
            source
        )));
    }
    reader
        .get::<Blob<SuccinctArchiveBlob>, SuccinctArchiveBlob>(source)
        .map_err(|error| {
            CollectionOperationError::Fatal(format!(
                "resident raw SuccinctArchive {} could not be read: {error}",
                hex::encode_upper(source.raw),
            ))
        })
}

fn attach_rank9<R>(
    root: &Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    reader: &R,
) -> Result<(Blob<SuccinctArchiveBlob>, SuccinctArchive<OrderedUniverse>), CollectionOperationError>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    let source = Rank9AcceleratedSuccinctArchiveBlob::source_handle(root)
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    let raw = resident_raw(source, reader)?;
    let attached = SuccinctArchive::from_accelerated_parts(raw.clone(), root.clone())
        .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
    Ok((raw, attached))
}

impl CollectionEncoding for SuccinctArchiveBlob {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        SuccinctArchiveBlob::validate(member)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        join(low, high).map_err(|source| match source {
            SuccinctArchiveRawMergeError::DomainTooWide
            | SuccinctArchiveRawMergeError::TooManyRows => {
                CollectionOperationError::Capacity(source.to_string())
            }
            SuccinctArchiveRawMergeError::InvalidInput { .. }
            | SuccinctArchiveRawMergeError::Construction(_) => {
                CollectionOperationError::Fatal(source.to_string())
            }
        })
    }
}

impl CollectionEncoding for Rank9AcceleratedSuccinctArchiveBlob {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let source = Self::source_handle(member)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        let raw = resident_raw(source, reader)?;
        SuccinctArchive::<OrderedUniverse>::validate_accelerated_parts(&raw, member)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }

    fn missing_representation_dependencies<R>(
        member: CollectionData,
        reader: &R,
    ) -> Result<Vec<CollectionData>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let root = reader
            .get::<Blob<Self>, Self>(Handle::<Self>::from_hash(member))
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let source = Self::source_handle(&root)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let resident = reader
            .metadata(source)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .is_some();
        Ok(if resident {
            Vec::new()
        } else {
            vec![Handle::<SuccinctArchiveBlob>::to_hash(source)]
        })
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let (low_raw, low) = attach_rank9(low, reader)?;
        let (high_raw, high) = attach_rank9(high, reader)?;

        // The raw source lattice currently has a u32 in-memory construction
        // boundary. Usually the sum of the child geometries proves that their
        // union also fits, and the accelerated join can proceed directly. At
        // the astronomical boundary where that upper bound is inconclusive,
        // ask the raw lattice for the exact answer first. This keeps source and
        // target capacity behavior aligned without charging ordinary Rank9
        // joins for a redundant raw merge.
        let may_cross_raw_capacity = low
            .eav_c
            .len()
            .checked_add(high.eav_c.len())
            .map_or(true, |rows| rows > u32::MAX as usize)
            || low
                .domain
                .len()
                .checked_add(high.domain.len())
                .map_or(true, |values| values > u32::MAX as usize);
        if may_cross_raw_capacity {
            let raw =
                SuccinctArchiveBlob::merge(&[low_raw, high_raw]).map_err(
                    |source| match source {
                        SuccinctArchiveRawMergeError::DomainTooWide
                        | SuccinctArchiveRawMergeError::TooManyRows => {
                            CollectionOperationError::Capacity(source.to_string())
                        }
                        SuccinctArchiveRawMergeError::InvalidInput { .. }
                        | SuccinctArchiveRawMergeError::Construction(_) => {
                            CollectionOperationError::Fatal(source.to_string())
                        }
                    },
                )?;
            let raw_handle = raw.get_handle();
            let resident = reader
                .metadata(raw_handle)
                .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
                .is_some();
            if !resident {
                return Err(CollectionOperationError::MissingDependency(Handle::<
                    SuccinctArchiveBlob,
                >::to_hash(
                    raw_handle
                )));
            }
            return SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw)
                .map_err(|source| CollectionOperationError::Fatal(source.to_string()));
        }

        let merged = merge_ordered_archives(&[low, high]);
        let (raw, accelerated) = merged.to_accelerated_parts();
        let raw_handle = raw.get_handle();
        let resident = reader
            .metadata(raw_handle)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .is_some();
        if !resident {
            return Err(CollectionOperationError::MissingDependency(Handle::<
                SuccinctArchiveBlob,
            >::to_hash(
                raw_handle
            )));
        }
        Ok(accelerated)
    }
}

/// Mapping algorithm for canonical SimpleArchive-to-SuccinctArchive conversion.
///
/// Minted with `trible genid` on 2026-08-29.
pub const SIMPLE_TO_SUCCINCT_MAPPING_V1: Id = id_hex!("9C8CFEB097B0A336E09D506E8DD361C2");

/// Self-description of the parameter-free canonical conversion.
pub struct SimpleToSuccinctMappingV1;

impl MetaDescribe for SimpleToSuccinctMappingV1 {
    fn describe() -> Fragment {
        let id = SIMPLE_TO_SUCCINCT_MAPPING_V1;
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "simple-to-succinct-v1",
                metadata::description: "Canonical conversion from a SimpleArchive trible set to its raw SuccinctArchive encoding. The mapping preserves set union and has no parameters.",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

fn mapping_fragment() -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <SimpleToSuccinctMappingV1 as MetaDescribe>::describe(),
    }
}

impl CollectionAttachment for SuccinctArchiveBlob {
    type Argument = ();

    fn fragment(_argument: &Self::Argument) -> Fragment {
        mapping_fragment()
    }

    fn bind(
        _parent: &Fragment,
        attached: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        let actual = descriptor_facts::mapping_algorithm(attached.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let expected = Some(SIMPLE_TO_SUCCINCT_MAPPING_V1);
        if actual != expected {
            return Err(CollectionOperationError::Fatal(format!(
                "succinct collection mapping algorithm {:?} does not match simple-to-succinct algorithm {}",
                actual.map(|id| format!("{id:X}")),
                format!("{:X}", expected.expect("mapping algorithm")),
            )));
        }
        Ok(())
    }

    /// A node's Succinct archive, from the node's own bytes: a merged node's
    /// from the merged `SimpleArchive`, never from its children's archives.
    fn map<R>(
        _argument: &Self::Argument,
        node: &Blob<SimpleArchive>,
        _siblings: &[CollectionData],
        _reader: &R,
    ) -> Result<Blob<SuccinctArchiveBlob>, CollectionOperationError>
    where
        R: crate::repo::StoreRead,
    {
        derive_element(node).map_err(|source| match source {
            SuccinctArchiveRawBuildError::TooManyRows(_)
            | SuccinctArchiveRawBuildError::DomainTooWide(_) => {
                CollectionOperationError::Capacity(source.to_string())
            }
            SuccinctArchiveRawBuildError::Source(_)
            | SuccinctArchiveRawBuildError::Construction(_) => {
                CollectionOperationError::Fatal(source.to_string())
            }
        })
    }
}

/// Raw-to-accelerated mapping algorithm for 32-bit little-endian targets.
///
/// Minted with `trible genid` on 2026-08-29. The identity pins the portable
/// source schema, accelerated-root format, canonical Rank9 builder, Jerky
/// serialization epoch, pointer width, and byte order. A change that can alter
/// canonical root bytes requires a new mapping identity.
pub const RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE: Id =
    id_hex!("57756614C20DA2C9B1D33679136176A7");

/// Raw-to-accelerated mapping algorithm for 32-bit big-endian targets.
pub const RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE: Id =
    id_hex!("D225E3B88CAE65ECAA2DADA8E861D4B5");

/// Raw-to-accelerated mapping algorithm for 64-bit little-endian targets.
pub const RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE: Id =
    id_hex!("30B1F8ABE7BA8348551D8A94209A841C");

/// Raw-to-accelerated mapping algorithm for 64-bit big-endian targets.
pub const RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE: Id =
    id_hex!("7B628024E742E031F4E58789D2847D70");

/// ABI-qualified raw-to-accelerated mapping description.
pub struct RawToRank9AcceleratedMappingV1;

impl MetaDescribe for RawToRank9AcceleratedMappingV1 {
    fn describe() -> Fragment {
        let id = current_rank9_accelerated_mapping_algorithm();
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "raw-to-rank9-accelerated-succinctarchive-v1",
                metadata::description: "Canonical mapping from one portable SuccinctArchive to its ABI-qualified Rank9-accelerated encoding, whose header names that archive. Attached to a SimpleArchive root, it maps each node's attachment in the Succinct attached collection its mapping names; the accelerator is usable only where that archive is resident.",
                metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

#[cfg(all(target_pointer_width = "32", target_endian = "little"))]
const CURRENT_RANK9_ACCELERATED_MAPPING: Id = RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_LE;
#[cfg(all(target_pointer_width = "32", target_endian = "big"))]
const CURRENT_RANK9_ACCELERATED_MAPPING: Id = RAW_TO_RANK9_ACCELERATED_MAPPING_V1_32_BE;
#[cfg(all(target_pointer_width = "64", target_endian = "little"))]
const CURRENT_RANK9_ACCELERATED_MAPPING: Id = RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_LE;
#[cfg(all(target_pointer_width = "64", target_endian = "big"))]
const CURRENT_RANK9_ACCELERATED_MAPPING: Id = RAW_TO_RANK9_ACCELERATED_MAPPING_V1_64_BE;

/// Mapping algorithm id for the exact accelerated ABI supported by this build.
pub const fn current_rank9_accelerated_mapping_algorithm() -> Id {
    CURRENT_RANK9_ACCELERATED_MAPPING
}

fn rank9_accelerated_mapping_fragment(succinct: Collection<SuccinctArchiveBlob>) -> Fragment {
    entity! {
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <RawToRank9AcceleratedMappingV1 as MetaDescribe>::describe(),
        mapping_reads_attached: succinct.handle(),
    }
}

/// A node's Rank9 accelerator, built from the same node's attachment in the
/// Succinct attached collection its descriptor names. The accelerator's
/// header names that raw archive, so it is usable only where the archive is
/// resident too.
impl CollectionAttachment for Rank9AcceleratedSuccinctArchiveBlob {
    /// The Succinct attached collection of the same parent this reads.
    type Argument = Collection<SuccinctArchiveBlob>;

    fn fragment(succinct: &Self::Argument) -> Fragment {
        rank9_accelerated_mapping_fragment(*succinct)
    }

    fn bind(
        _parent: &Fragment,
        attached: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        let actual = descriptor_facts::mapping_algorithm(attached.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        let expected = Some(current_rank9_accelerated_mapping_algorithm());
        if actual != expected {
            return Err(CollectionOperationError::Fatal(format!(
                "accelerated SuccinctArchive mapping algorithm {:?} does not match {}",
                actual.map(|id| format!("{id:X}")),
                format!("{:X}", expected.expect("mapping algorithm")),
            )));
        }
        match descriptor_facts::reads_attached(attached.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .as_slice()
        {
            [succinct] => Ok(Collection::from_handle(*succinct)),
            siblings => Err(CollectionOperationError::Fatal(format!(
                "a Rank9 attachment reads exactly one Succinct attached collection; its mapping names {}",
                siblings.len(),
            ))),
        }
    }

    fn siblings(succinct: &Self::Argument) -> Vec<CollectionHandle> {
        vec![succinct.handle()]
    }

    fn map<R>(
        _argument: &Self::Argument,
        _node: &Blob<SimpleArchive>,
        siblings: &[CollectionData],
        reader: &R,
    ) -> Result<Blob<Rank9AcceleratedSuccinctArchiveBlob>, CollectionOperationError>
    where
        R: crate::repo::StoreRead,
    {
        let [raw] = siblings else {
            return Err(CollectionOperationError::Fatal(
                "a Rank9 attachment needs the node's Succinct attachment".to_owned(),
            ));
        };
        let raw = resident_raw(Handle::<SuccinctArchiveBlob>::from_hash(*raw), reader)?;
        SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

/// Return the canonical empty raw SuccinctArchive artifact.
pub fn empty() -> Blob<SuccinctArchiveBlob> {
    SuccinctArchiveBlob::merge(&[])
        .expect("the fixed empty raw SuccinctArchive construction cannot fail")
}

/// Canonically derive one raw SuccinctArchive element from a SimpleArchive.
pub fn derive_element(
    source: &Blob<SimpleArchive>,
) -> Result<Blob<SuccinctArchiveBlob>, SuccinctArchiveRawBuildError> {
    SuccinctArchiveBlob::build_from_simple_archive(source)
}

/// Compute the canonical union of two raw SuccinctArchive elements.
pub fn join(
    left: &Blob<SuccinctArchiveBlob>,
    right: &Blob<SuccinctArchiveBlob>,
) -> Result<Blob<SuccinctArchiveBlob>, SuccinctArchiveRawMergeError> {
    SuccinctArchiveBlob::merge(&[left.clone(), right.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::blob::IntoBlob;
    use crate::collection::descriptor::identity_for_tests;
    use crate::collection::simplearchive_union;
    use crate::collection::{CanonicalAttachment, CollectionPolicy};
    use crate::trible::{Trible, TribleSet, TRIBLE_LEN};

    fn direct_policy() -> CollectionPolicy {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        CollectionPolicy::new(
            crate::collection::AdmissionPolicy::direct(authority),
            crate::collection::AdmissionPolicy::direct(authority),
        )
    }

    /// The named `SimpleArchive` root these tests attach to.
    fn raw_root(name: &str) -> Fragment {
        simplearchive_union::descriptor(name, direct_policy())
    }

    fn attached(parent: &Fragment) -> Fragment {
        descriptor_facts::attaching_with(
            identity_for_tests(parent),
            &CanonicalAttachment::<SuccinctArchiveBlob>::new(()),
        )
    }

    fn row(entity: u8, attribute: u8, value: u8) -> [u8; TRIBLE_LEN] {
        let mut row = [value; TRIBLE_LEN];
        row[..16].fill(entity);
        row[16..32].fill(attribute);
        row
    }

    fn archive(rows: impl IntoIterator<Item = [u8; TRIBLE_LEN]>) -> Blob<SimpleArchive> {
        let mut facts = TribleSet::new();
        for row in rows {
            facts.insert(&Trible::force_raw(row).unwrap());
        }
        facts.to_blob()
    }

    /// The index is attached to its parent through one explicit mapping: it
    /// names the parent, not a source, and carries no policy and no name.
    #[test]
    fn the_index_attaches_to_its_parent_through_its_mapping() {
        let parent = raw_root("first");
        let index = attached(&parent);
        assert_eq!(
            descriptor_facts::parent(index.facts()),
            Ok(Some(identity_for_tests(&parent)))
        );
        assert_eq!(descriptor_facts::source(index.facts()), Ok(None));
        assert_eq!(descriptor_facts::name(index.facts()), Ok(None));
        assert_eq!(
            descriptor_facts::capability_policies(index.facts(), None).count(),
            0,
            "an attached collection has no policy of its own"
        );
        // The same mapping over another parent is another collection.
        assert_ne!(
            identity_for_tests(&index),
            identity_for_tests(&attached(&raw_root("second")))
        );
        assert_eq!(
            descriptor_facts::mapping_algorithm(index.facts()),
            Ok(Some(SIMPLE_TO_SUCCINCT_MAPPING_V1))
        );
        assert_eq!(
            descriptor_facts::representation(index.facts()).unwrap(),
            <SuccinctArchiveBlob as MetaDescribe>::id()
        );
        assert!(<SuccinctArchiveBlob as CollectionAttachment>::bind(&parent, &index).is_ok());

        // A Rank9 index names the Succinct attached collection it reads.
        let succinct = Collection::<SuccinctArchiveBlob>::from_handle(identity_for_tests(&index));
        let rank9 = descriptor_facts::attaching_with(
            identity_for_tests(&parent),
            &CanonicalAttachment::<Rank9AcceleratedSuccinctArchiveBlob>::new(succinct),
        );
        assert_eq!(
            descriptor_facts::reads_attached(rank9.facts()),
            Ok(vec![succinct.handle()])
        );
        assert_eq!(
            <Rank9AcceleratedSuccinctArchiveBlob as CollectionAttachment>::bind(&parent, &rank9),
            Ok(succinct)
        );
    }

    #[test]
    fn canonical_empty_is_the_bottom_and_the_join_identity() {
        let source_empty: Blob<SimpleArchive> = TribleSet::new().to_blob();
        let derived_empty = derive_element(&source_empty).unwrap();
        let canonical_empty = empty();
        assert_eq!(derived_empty.bytes, canonical_empty.bytes);

        let element = derive_element(&archive([row(1, 9, 3)])).unwrap();
        let joined = join(&canonical_empty, &element).unwrap();
        assert_eq!(joined.bytes, element.bytes);
        assert_eq!(joined.get_handle(), element.get_handle());
    }

    /// A merged node's Succinct attachment is mapped from the merged
    /// `SimpleArchive`, and that is byte for byte the structural join of its
    /// children's attachments: the join shortcut is never needed for
    /// correctness.
    #[test]
    fn a_merged_nodes_attachment_from_its_bytes_is_the_structural_join_of_its_childrens() {
        let shared = row(3, 10, 40);
        let children = [
            archive([row(2, 10, 60), shared]),
            archive([row(1, 10, 20), shared]),
            archive([row(4, 11, 20), row(4, 12, 21)]),
        ];
        let merged = children
            .iter()
            .skip(1)
            .fold(children[0].clone(), |merged, child| {
                simplearchive_union::join(&merged, child).unwrap()
            });
        let from_bytes = derive_element(&merged).unwrap();
        let structural = SuccinctArchiveBlob::merge(
            &children
                .iter()
                .map(|child| derive_element(child).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(from_bytes.bytes, structural.bytes);
        assert_eq!(from_bytes.get_handle(), structural.get_handle());
    }
}
