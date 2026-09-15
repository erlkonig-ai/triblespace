//! A grow-only set of opaque entity IDs.
//!
//! Canonical bytes are a strictly increasing sequence of nonnil 16-byte IDs;
//! there is no header, padding, native-endian integer, or referenced payload.
//! Empty is zero bytes. [`encode`] canonicalizes authored IDs, and [`join`]
//! computes set union. [`derive_element`] projects the typed `GenId` values of
//! one configured `SimpleArchive` attribute, not the subjects asserting them.
//! Receipt facts remain ordinary source COMMITs; the set is their maintained
//! projection, with no interpretation of the entities its values name.
//!
//! Ordinary attachment checks only fixed-width framing and shares the original
//! bytes through [`View`]. It does not revalidate ordering, reconstruct a
//! canonical set, or hash content. Membership and ordered iteration rely on
//! the encoding's canonical-order contract; use [`validate_element`] at an
//! explicit audit boundary. Nil rows cannot become invalid Rust `Id` values:
//! typed iteration skips them, while the canonical audit rejects them.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use anybytes::{Bytes, View};
use itertools::{Either, Itertools};

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::{Blob, BlobEncoding, TryFromBlob};
use crate::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use crate::collection::{
    descriptor, CollectionData, CollectionDerivation, CollectionEncoding, CollectionOperationError,
    Cover, TryFromCover, TryFromCoverError,
};
use crate::id::{ExclusiveId, Id, RawId, ID_LEN};
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::{Encodes, Inline};
use crate::macros::entity;
use crate::metadata::{self, MetaDescribe};
use crate::repo::{BlobStoreGet, BlobStoreMeta, StoreRead};
use crate::trible::{Fragment, RawTrible, Trible};

/// Canonical flat entity-ID set; its collection join is ordinary set union.
pub struct EntityIdSetBlob;

impl BlobEncoding for EntityIdSetBlob {}

impl MetaDescribe for EntityIdSetBlob {
    fn describe() -> Fragment {
        // Minted by /Users/jp/.local/bin/trible genid on 2026-09-15.
        let id = crate::id_hex!("0BF639287590CFC9CE0E2B83D9FBC1E3");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "entity-id-set-v1",
            metadata::description: "Grow-only entity-ID set. Canonical bytes are strictly sorted, duplicate-free, nonnil 16-byte entity IDs in lexicographic byte order, without a header or padding. Empty is zero bytes. Join is set union; IDs remain opaque and name no blob dependencies.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Invalid fixed-width framing or noncanonical set contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntityIdSetError {
    /// A source archive has malformed framing or an invalid trible layout.
    InvalidSource(UnarchiveError),
    /// A flat payload must contain complete 16-byte rows.
    BadLength(usize),
    /// Canonical sets contain no nil entity ID.
    NilId(usize),
    /// The row at this index is no greater than its predecessor.
    NotStrictlyIncreasing(usize),
}

impl fmt::Display for EntityIdSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(source) => write!(formatter, "invalid source archive: {source}"),
            Self::BadLength(length) => {
                write!(
                    formatter,
                    "entity-ID set has {length} bytes, not complete {ID_LEN}-byte rows"
                )
            }
            Self::NilId(index) => write!(formatter, "entity-ID set row {index} is nil"),
            Self::NotStrictlyIncreasing(index) => {
                write!(
                    formatter,
                    "entity-ID set row {index} is not strictly increasing"
                )
            }
        }
    }
}

impl Error for EntityIdSetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSource(source) => Some(source),
            _ => None,
        }
    }
}

impl TryFromBlob<EntityIdSetBlob> for View<[RawId]> {
    type Error = EntityIdSetError;

    fn try_from_blob(blob: Blob<EntityIdSetBlob>) -> Result<Self, Self::Error> {
        let length = blob.bytes.len();
        // RawId is a byte-aligned [u8; 16] with no invalid bit patterns, so
        // fixed-width length is the only fallible structural requirement.
        blob.bytes
            .view()
            .map_err(|_| EntityIdSetError::BadLength(length))
    }
}

/// Encode authored IDs canonically, independent of input order or duplicates.
pub fn encode(ids: impl IntoIterator<Item = Id>) -> Blob<EntityIdSetBlob> {
    encode_rows(ids.into_iter().map(Id::raw).collect())
}

fn encode_rows(mut rows: Vec<RawId>) -> Blob<EntityIdSetBlob> {
    rows.sort_unstable();
    rows.dedup();
    Blob::new(Bytes::from_source(rows))
}

impl Encodes<Vec<Id>> for EntityIdSetBlob {
    type Output = Blob<Self>;

    fn encode(source: Vec<Id>) -> Self::Output {
        encode(source)
    }
}

impl Encodes<&[Id]> for EntityIdSetBlob {
    type Output = Blob<Self>;

    fn encode(source: &[Id]) -> Self::Output {
        encode(source.iter().copied())
    }
}

fn validate_rows(rows: &[RawId]) -> Result<(), EntityIdSetError> {
    for (index, id) in rows.iter().enumerate() {
        if *id == [0; ID_LEN] {
            return Err(EntityIdSetError::NilId(index));
        }
        if index != 0 && rows[index - 1] >= *id {
            return Err(EntityIdSetError::NotStrictlyIncreasing(index));
        }
    }
    Ok(())
}

/// Explicit linear audit of framing, nonnil IDs, ordering, and uniqueness.
pub fn validate_element(blob: &Blob<EntityIdSetBlob>) -> Result<(), EntityIdSetError> {
    validate_rows(&View::<[RawId]>::try_from_blob(blob.clone())?)
}

/// Construct the canonical union of two canonically ordered elements.
///
/// Only fixed-width framing is checked here: sorted merge relies on the
/// encoding contract rather than auditing earlier producers again. Use
/// [`validate_element`] for an explicit audit. This is new producer work, not
/// a step in attaching or querying a cover.
pub fn join(
    low: &Blob<EntityIdSetBlob>,
    high: &Blob<EntityIdSetBlob>,
) -> Result<Blob<EntityIdSetBlob>, EntityIdSetError> {
    let low = View::<[RawId]>::try_from_blob(low.clone())?;
    let high = View::<[RawId]>::try_from_blob(high.clone())?;
    let rows: Vec<RawId> = low
        .iter()
        .copied()
        .merge(high.iter().copied())
        .dedup()
        .collect();
    Ok(Blob::new(Bytes::from_source(rows)))
}

impl CollectionEncoding for EntityIdSetBlob {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        validate_element(member).map_err(|error| CollectionOperationError::Fatal(error.to_string()))
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
        join(low, high).map_err(|error| CollectionOperationError::Fatal(error.to_string()))
    }
}

/// Canonical projection of one attribute's individually typed `GenId` values.
///
/// Minted with installed `trible genid` on 2026-09-15.
pub const GENID_ATTRIBUTE_VALUES_MAPPING_V1: Id =
    crate::id_hex!("7E4257A14880E8B4855B6282B337B4B5");

/// Self-description of the canonical attribute-value projection algorithm.
pub struct GenIdAttributeValuesMappingV1;

impl MetaDescribe for GenIdAttributeValuesMappingV1 {
    fn describe() -> Fragment {
        let id = GENID_ATTRIBUTE_VALUES_MAPPING_V1;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "genid-attribute-values-mapping-v1",
            metadata::description: "Project the individually well-formed nonnil GenId values under the SimpleArchive attribute named by metadata::attribute into EntityIdSetBlob. Subjects and other facts are not set members or qualifiers. Projection commutes with union even when assertion fields are split across source members, and repeated values collapse regardless of assertion identity.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// Project the values of one configured attribute, independently per fact.
///
/// Subjects, timestamps, tags, and other attributes neither qualify nor become
/// members of the set. A nil or malformed `GenId` value is not a typed match.
/// The source is checked for safe row framing/layout, not canonical ordering;
/// output sorting and deduplication are the new projection's own work.
pub fn derive_element(
    source: &Blob<SimpleArchive>,
    attribute: Id,
) -> Result<Blob<EntityIdSetBlob>, EntityIdSetError> {
    let rows: View<[RawTrible]> = source
        .bytes
        .clone()
        .view()
        .map_err(|_| EntityIdSetError::InvalidSource(UnarchiveError::BadArchive))?;
    let mut values = Vec::new();
    for row in rows.iter() {
        let trible = Trible::as_transmute_force_raw(row)
            .ok_or(EntityIdSetError::InvalidSource(UnarchiveError::BadTrible))?;
        if *trible.a() == attribute {
            if let Ok(id) = trible.v::<GenId>().try_from_inline::<Id>() {
                values.push(id.raw());
            }
        }
    }
    Ok(encode_rows(values))
}

impl CollectionDerivation for EntityIdSetBlob {
    type Source = SimpleArchive;
    type Argument = Id;

    fn fragment(attribute: &Id) -> Fragment {
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: <GenIdAttributeValuesMappingV1 as MetaDescribe>::describe(),
            metadata::attribute: attribute,
        }
    }

    fn bind(_source: &Fragment, target: &Fragment) -> Result<Id, CollectionOperationError> {
        let algorithm = descriptor::mapping_algorithm(target.facts())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        if algorithm != Some(GENID_ATTRIBUTE_VALUES_MAPPING_V1) {
            return Err(CollectionOperationError::Fatal(format!(
                "entity-ID value mapping algorithm does not match {GENID_ATTRIBUTE_VALUES_MAPPING_V1:X}"
            )));
        }
        let raw = descriptor::mapping_argument(target.facts(), metadata::attribute.id())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal(
                    "entity-ID value mapping is missing metadata::attribute".to_owned(),
                )
            })?;
        Inline::<GenId>::new(raw)
            .try_from_inline::<Id>()
            .map_err(|error| {
                CollectionOperationError::Fatal(format!(
                    "invalid entity-ID value mapping attribute: {error:?}"
                ))
            })
    }

    fn map<R>(
        attribute: &Id,
        source: &Blob<SimpleArchive>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: StoreRead,
    {
        derive_element(source, *attribute)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))
    }
}

/// A logical set over a frozen cover's shared, fixed-width member views.
///
/// Attachment costs O(number of members), without enumerating IDs. Membership
/// binary-searches each member. Iteration merges and deduplicates their sorted
/// streams on demand; it never creates a physical union blob.
#[derive(Clone, Debug, Default)]
pub struct EntityIdSet {
    members: Vec<View<[RawId]>>,
}

impl TryFromBlob<EntityIdSetBlob> for EntityIdSet {
    type Error = EntityIdSetError;

    fn try_from_blob(blob: Blob<EntityIdSetBlob>) -> Result<Self, Self::Error> {
        Ok(Self {
            members: vec![View::<[RawId]>::try_from_blob(blob)?],
        })
    }
}

impl EntityIdSet {
    /// Positive membership in any resident member of this frozen cover.
    pub fn contains(&self, id: Id) -> bool {
        let raw = id.raw();
        self.members
            .iter()
            .any(|member| member.binary_search(&raw).is_ok())
    }

    /// Iterate distinct IDs in byte order, merging the cover only on demand.
    pub fn iter(&self) -> impl Iterator<Item = Id> + '_ {
        let rows = match self.members.as_slice() {
            [member] => Either::Left(member.iter().copied()),
            _ => Either::Right(
                self.members
                    .iter()
                    .map(|member| member.iter().copied())
                    .kmerge()
                    .dedup(),
            ),
        };
        rows.filter_map(Id::new)
    }

    /// Exact cardinality of canonical input; overlapping covers need a merge.
    ///
    /// Unlike attachment, requesting this count can enumerate the cover.
    pub fn len(&self) -> usize {
        match self.members.as_slice() {
            [] => 0,
            [member] => member.len(),
            _ => self.iter().count(),
        }
    }

    /// Whether the logical union is empty.
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

/// Exact member attribution for a cover's structural decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityIdSetViewError {
    /// The member whose resident bytes could not be attached.
    pub member: CollectionData,
    /// Its structural error; ordinary reads do not run the canonical audit.
    pub source: EntityIdSetError,
}

impl fmt::Display for EntityIdSetViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "entity-ID set member {} cannot be attached: {}",
            hex::encode_upper(self.member.raw),
            self.source,
        )
    }
}

impl Error for EntityIdSetViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl TryFromCover<EntityIdSetBlob> for EntityIdSet {
    type Error = EntityIdSetViewError;

    fn try_from_cover<R>(
        cover: &Cover<EntityIdSetBlob>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut members = Vec::new();
        for handle in cover.members() {
            let member = Handle::<EntityIdSetBlob>::to_hash(handle);
            let blob = snapshot
                .get::<Blob<EntityIdSetBlob>, EntityIdSetBlob>(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let rows = View::<[RawId]>::try_from_blob(blob).map_err(|source| {
                TryFromCoverError::View(EntityIdSetViewError { member, source })
            })?;
            members.push(rows);
        }
        Ok(Self { members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use futures::executor::block_on;

    use crate::blob::MemoryBlobStore;
    use crate::collection::{
        AdmissionPolicy, CanonicalDerivation, Collection, CollectionHandle, CollectionPolicy,
        CollectionRead, CollectionSnapshotExt, CollectionStoreExt,
    };
    use crate::inline::encodings::time::NsTAIInterval;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{SnapshotSource, WantRead};
    use crate::trible::TribleSet;

    fn id(byte: u8) -> Id {
        Id::new([byte; ID_LEN]).unwrap()
    }

    fn collection() -> Collection<EntityIdSetBlob> {
        // These encoding-view fixtures need no descriptor or publication.
        Collection::from_handle(CollectionHandle::new([17; 32]))
    }

    #[test]
    fn attribute_projection_keeps_values_across_split_facts_and_duplicate_assertions() {
        let attribute = metadata::supersedes.id();
        let rows = [
            Trible::force(&id(31), &attribute, &GenId::encode(id(1))),
            Trible::force(
                &id(31),
                &metadata::created_at.id(),
                &Inline::<NsTAIInterval>::new([0; 32]),
            ),
            Trible::force(
                &id(31),
                &metadata::tag.id(),
                &GenId::encode(metadata::KIND_MULTI),
            ),
            Trible::force(&id(32), &attribute, &GenId::encode(id(1))),
            Trible::force(&id(32), &attribute, &GenId::encode(id(2))),
            Trible::force(&id(40), &metadata::tag.id(), &GenId::encode(id(3))),
        ];
        let facts: TribleSet = rows.iter().copied().collect();
        let all = derive_element(&SimpleArchive::encode(&facts), attribute).unwrap();
        assert_eq!(all, encode([id(1), id(2)]));
        let set = EntityIdSet::try_from_blob(all.clone()).unwrap();
        for subject in [id(31), id(32), id(40)] {
            assert!(!set.contains(subject), "assertion IDs are not projected");
        }
        assert!(!set.contains(id(3)), "another attribute is not projected");

        // Every partition includes cases where the event edge is separated
        // from its type/timestamp and duplicate assertions are in other members.
        for mask in 0..(1_usize << rows.len()) {
            let left: TribleSet = rows
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1_usize << *index) != 0)
                .map(|(_, row)| *row)
                .collect();
            let right: TribleSet = rows
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1_usize << *index) == 0)
                .map(|(_, row)| *row)
                .collect();
            let left = derive_element(&SimpleArchive::encode(left), attribute).unwrap();
            let right = derive_element(&SimpleArchive::encode(right), attribute).unwrap();
            assert_eq!(join(&left, &right).unwrap(), all, "partition {mask}");
        }

        let receipt = id(31);
        let annotation_only = entity! { ExclusiveId::force_ref(&receipt) @
            metadata::created_at: Inline::<NsTAIInterval>::new([1; 32]),
        };
        assert_eq!(
            derive_element(&SimpleArchive::encode(annotation_only), attribute).unwrap(),
            encode([]),
        );
    }

    #[test]
    fn attribute_projection_skips_untyped_values_but_rejects_bad_row_framing() {
        let attribute = metadata::supersedes.id();
        let rows = [
            Trible::force(&id(31), &attribute, &GenId::encode(id(1))),
            Trible::force(&id(31), &attribute, &Inline::<GenId>::new([0; 32])),
            Trible::force(&id(32), &attribute, &Inline::<GenId>::new([1; 32])),
        ];
        let facts: TribleSet = rows.iter().copied().collect();
        assert_eq!(
            derive_element(&SimpleArchive::encode(facts), attribute).unwrap(),
            encode([id(1)]),
        );

        let malformed = Blob::new(Bytes::from_source(vec![0_u8; 63]));
        assert_eq!(
            derive_element(&malformed, attribute).unwrap_err(),
            EntityIdSetError::InvalidSource(UnarchiveError::BadArchive),
        );
        let nil_subject = Blob::new(Bytes::from_source(vec![[0_u8; 64]]));
        assert_eq!(
            derive_element(&nil_subject, attribute).unwrap_err(),
            EntityIdSetError::InvalidSource(UnarchiveError::BadTrible),
        );

        // Projection does not audit earlier producers' canonical ordering.
        let reordered = Blob::new(Bytes::from_source(
            rows.iter().rev().map(|row| row.data).collect::<Vec<_>>(),
        ));
        assert_eq!(
            derive_element(&reordered, attribute).unwrap(),
            encode([id(1)]),
        );
    }

    #[test]
    fn mapping_descriptor_pins_the_attribute_and_rejects_another_algorithm() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let mut store = MemoryRepo::default();
        let source = store
            .collection("id-value-projection", policy.clone())
            .unwrap();
        let argument = metadata::supersedes.id();
        let target = descriptor::deriving_with(
            source.handle(),
            &CanonicalDerivation::<EntityIdSetBlob>::new(argument),
            policy.clone(),
        );
        let other_attribute = descriptor::deriving_with(
            source.handle(),
            &CanonicalDerivation::<EntityIdSetBlob>::new(metadata::tag.id()),
            policy.clone(),
        );
        assert_ne!(target, other_attribute);
        assert_eq!(
            descriptor::mapping_algorithm(target.facts()).unwrap(),
            Some(GENID_ATTRIBUTE_VALUES_MAPPING_V1),
        );
        assert_eq!(
            descriptor::mapping_argument(target.facts(), metadata::attribute.id()).unwrap(),
            Some(GenId::encode(argument).raw),
        );
        assert_eq!(
            EntityIdSetBlob::bind(&Fragment::empty(), &target).unwrap(),
            argument,
        );
        let another_algorithm = descriptor::deriving_with(
            source.handle(),
            &CanonicalDerivation::<crate::collection::latest::LatestBlob>::new(argument),
            policy,
        );
        assert!(EntityIdSetBlob::bind(&Fragment::empty(), &another_algorithm).is_err());

        let without_attribute = Fragment::from(
            target
                .facts()
                .iter()
                .filter(|row| *row.a() != metadata::attribute.id())
                .copied()
                .collect::<TribleSet>(),
        );
        assert!(EntityIdSetBlob::bind(&Fragment::empty(), &without_attribute).is_err());
    }

    #[test]
    fn ordinary_maintenance_derives_receipt_values_without_changing_source_commits() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let mut store = MemoryRepo::default();
        let source = store.collection("receipt-facts", policy.clone()).unwrap();
        let target = store
            .derive::<EntityIdSetBlob>(source, metadata::supersedes.id(), policy)
            .unwrap();
        let first_receipt = id(31);
        let second_receipt = id(32);
        let first = entity! { ExclusiveId::force_ref(&first_receipt) @
            metadata::supersedes: id(1),
        };
        store.commit(source, &key, first).unwrap();
        let early = block_on(store.maintain(target, &key))
            .unwrap()
            .collection(target)
            .unwrap();
        assert_eq!(
            early
                .view::<EntityIdSet>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [id(1)],
        );
        store
            .commit(
                source,
                &key,
                entity! { ExclusiveId::force_ref(&first_receipt) @
                    metadata::created_at: Inline::<NsTAIInterval>::new([1; 32]),
                },
            )
            .unwrap();
        store
            .commit(
                source,
                &key,
                entity! { ExclusiveId::force_ref(&second_receipt) @
                    metadata::supersedes*: [id(1), id(2)],
                },
            )
            .unwrap();
        let completed = block_on(store.maintain(target, &key)).unwrap();
        assert_eq!(
            completed
                .collection(target)
                .unwrap()
                .view::<EntityIdSet>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [id(1), id(2)],
        );
        assert_eq!(
            early
                .view::<EntityIdSet>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            [id(1)],
            "the original observation remains frozen",
        );
        let source_facts = completed
            .collection(source)
            .unwrap()
            .view::<TribleSet>()
            .unwrap();
        assert_eq!(
            source_facts.len(),
            4,
            "ordinary receipt facts remain intact"
        );
        let records = completed.records().unwrap().count();
        let repeated = block_on(store.maintain(target, &key)).unwrap();
        assert_eq!(repeated.records().unwrap().count(), records);
        assert_eq!(repeated.wants().unwrap().count(), 0);
    }

    #[test]
    fn canonical_writer_sorts_deduplicates_and_uses_exactly_sixteen_bytes_per_id() {
        let blob = encode([id(3), id(1), id(2), id(1)]);
        assert_eq!(
            EntityIdSetBlob::id(),
            crate::id_hex!("0BF639287590CFC9CE0E2B83D9FBC1E3")
        );
        assert_eq!(blob.bytes.len(), 3 * ID_LEN);
        assert_eq!(
            blob.bytes.as_ref(),
            [id(1).raw(), id(2).raw(), id(3).raw()].concat()
        );
        validate_element(&blob).unwrap();
        let set = EntityIdSet::try_from_blob(blob).unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), [id(1), id(2), id(3)]);
        assert_eq!(set.len(), 3);
        assert!(set.contains(id(2)));
        assert!(!set.contains(id(4)));

        let empty = encode([]);
        assert!(empty.bytes.is_empty());
        let empty = EntityIdSet::try_from_blob(empty).unwrap();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert!(!empty.contains(id(1)));
    }

    #[test]
    fn typed_attachment_retains_backing_and_does_not_audit_canonical_rows() {
        let rows = vec![id(3).raw(), id(1).raw(), id(1).raw()];
        let blob = Blob::new(Bytes::from_source(rows.clone()));
        let pointer = blob.bytes.as_ptr();
        let raw = View::<[RawId]>::try_from_blob(blob.clone()).unwrap();
        let set = EntityIdSet::try_from_blob(blob.clone()).unwrap();
        assert_eq!(raw.as_ptr().cast::<u8>(), pointer);
        assert_eq!(set.members[0].as_ptr().cast::<u8>(), pointer);
        assert_eq!(raw.as_ref(), rows.as_slice());
        assert_eq!(
            validate_element(&blob),
            Err(EntityIdSetError::NotStrictlyIncreasing(1))
        );
        drop(blob);
        assert_eq!(raw.as_ref(), rows.as_slice());

        let nil = Blob::new(Bytes::from_source(vec![[0_u8; ID_LEN]]));
        assert!(EntityIdSet::try_from_blob(nil.clone())
            .unwrap()
            .iter()
            .next()
            .is_none());
        assert_eq!(validate_element(&nil), Err(EntityIdSetError::NilId(0)));
    }

    #[test]
    fn typed_rows_need_only_byte_alignment_and_keep_the_sliced_backing() {
        let backing = Bytes::from_source([vec![0_u8], id(7).raw().to_vec()].concat());
        let payload = backing.slice(1..);
        let pointer = payload.as_ptr();
        let set = EntityIdSet::try_from_blob(Blob::new(payload)).unwrap();
        drop(backing);
        assert_eq!(set.members[0].as_ptr().cast::<u8>(), pointer);
        assert_eq!(set.iter().collect::<Vec<_>>(), [id(7)]);
        assert!(set.contains(id(7)));
    }

    #[test]
    fn framing_and_explicit_audit_errors_stay_distinct() {
        for tail in 1..ID_LEN {
            let blob = Blob::new(Bytes::from_source(vec![1_u8; ID_LEN + tail]));
            assert!(matches!(
                EntityIdSet::try_from_blob(blob.clone()),
                Err(EntityIdSetError::BadLength(length)) if length == ID_LEN + tail
            ));
            assert_eq!(
                validate_element(&blob),
                Err(EntityIdSetError::BadLength(ID_LEN + tail))
            );
            assert_eq!(
                join(&blob, &encode([])).unwrap_err(),
                EntityIdSetError::BadLength(ID_LEN + tail)
            );
        }
        let duplicate = Blob::new(Bytes::from_source(vec![id(1).raw(); 2]));
        assert_eq!(
            validate_element(&duplicate),
            Err(EntityIdSetError::NotStrictlyIncreasing(1))
        );
        // Sorted union naturally deduplicates; it does not invoke the audit.
        assert_eq!(
            join(&duplicate, &encode([])).unwrap().bytes,
            encode([id(1)]).bytes
        );
    }

    #[test]
    fn canonical_union_obeys_the_set_laws() {
        let sets: Vec<_> = (0_u8..8)
            .map(|mask| {
                encode(
                    (1_u8..=3)
                        .filter(|bit| mask & (1_u8 << (*bit - 1)) != 0)
                        .map(id),
                )
            })
            .collect();
        for a in &sets {
            assert_eq!(join(a, a).unwrap().bytes, a.bytes);
            assert_eq!(join(a, &sets[0]).unwrap().bytes, a.bytes);
            for b in &sets {
                let ab = join(a, b).unwrap();
                assert_eq!(ab.bytes, join(b, a).unwrap().bytes);
                validate_element(&ab).unwrap();
                for c in &sets {
                    assert_eq!(
                        join(&ab, c).unwrap().bytes,
                        join(a, &join(b, c).unwrap()).unwrap().bytes,
                    );
                }
            }
        }
    }

    #[test]
    fn cover_read_retains_shards_and_unions_overlaps_on_demand() {
        let mut store = MemoryBlobStore::new();
        let a = encode([id(1), id(3)]);
        let b = encode([id(2), id(3)]);
        let a_ptr = a.bytes.as_ptr();
        let b_ptr = b.bytes.as_ptr();
        let a = store.insert(a);
        let b = store.insert(b);
        let empty = store.insert(encode([]));
        let snapshot = store.snapshot().unwrap();
        let cover = collection().cover([a, b, a, empty]);
        let set = EntityIdSet::try_from_cover(&cover, &Fragment::empty(), &snapshot).unwrap();
        assert_eq!(set.members.len(), 3);
        assert!(set
            .members
            .iter()
            .any(|member| member.as_ptr().cast::<u8>() == a_ptr));
        assert!(set
            .members
            .iter()
            .any(|member| member.as_ptr().cast::<u8>() == b_ptr));
        assert_eq!(set.iter().collect::<Vec<_>>(), [id(1), id(2), id(3)]);
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
        for byte in 1..=4 {
            assert_eq!(set.contains(id(byte)), byte <= 3);
        }
        let no_members = collection().cover([]);
        let empty =
            EntityIdSet::try_from_cover(&no_members, &Fragment::empty(), &snapshot).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn cover_errors_keep_the_exact_missing_or_malformed_member() {
        let mut store = MemoryBlobStore::new();
        let absent = encode([id(1)]).get_handle();
        let malformed = store.insert(Blob::<EntityIdSetBlob>::new(Bytes::from_source(vec![1_u8])));
        let snapshot = store.snapshot().unwrap();
        for handle in [absent, malformed] {
            let cover = collection().cover([handle]);
            let error =
                EntityIdSet::try_from_cover(&cover, &Fragment::empty(), &snapshot).unwrap_err();
            match error {
                TryFromCoverError::MemberGet { member, .. } => assert_eq!(member.raw, absent.raw),
                TryFromCoverError::View(error) => {
                    assert_eq!(error.member.raw, malformed.raw);
                    assert_eq!(error.source, EntityIdSetError::BadLength(1));
                }
                error => panic!("unexpected cover error: {error}"),
            }
        }
    }
}
