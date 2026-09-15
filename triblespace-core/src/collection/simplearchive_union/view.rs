//! Logical fact views over typed `SimpleArchive` covers.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::{Blob, TryFromBlob};
use crate::collection::{CollectionData, Cover, TryFromCover, TryFromCoverError};
use crate::inline::encodings::hash::Handle;
use crate::repo::BlobStoreGet;
use crate::trible::{Fragment, TribleSet};

/// Failure to form a logical fact union from an already validated exact cover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactViewError {
    /// Member whose canonical bytes failed to decode.
    pub member: CollectionData,
    /// Exact SimpleArchive decoding failure.
    pub source: UnarchiveError,
}

impl fmt::Display for FactViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "collection member {} could not form the fact view: {}",
            hex::encode_upper(self.member.raw),
            self.source,
        )
    }
}

impl Error for FactViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl TryFromCover<SimpleArchive> for TribleSet {
    type Error = FactViewError;

    fn try_from_cover<R>(
        cover: &Cover<SimpleArchive>,
        _descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let mut facts = TribleSet::new();
        for handle in cover.members() {
            let member = Handle::<SimpleArchive>::to_hash(handle);
            let blob = snapshot
                .get::<Blob<SimpleArchive>, SimpleArchive>(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let member_facts = TribleSet::try_from_blob(blob)
                .map_err(|source| TryFromCoverError::View(FactViewError { member, source }))?;
            // PATCH union retains the member-backed leaves. There is no
            // temporary archive to serialize, validate again, hash or copy.
            facts += member_facts;
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use anybytes::Bytes;

    use crate::blob::MemoryBlobStore;
    use crate::collection::{Collection, CollectionHandle};
    use crate::repo::SnapshotSource;
    use crate::trible::TRIBLE_LEN;

    fn row(byte: u8) -> [u8; TRIBLE_LEN] {
        [byte; TRIBLE_LEN]
    }

    fn archive(rows: impl IntoIterator<Item = [u8; TRIBLE_LEN]>) -> Blob<SimpleArchive> {
        // The u128 backing guarantees 16-byte alignment without depending on
        // the allocator's treatment of byte-aligned Vec<[u8; 64]> buffers.
        let aligned: Vec<[u128; 4]> = rows
            .into_iter()
            .map(|row| {
                std::array::from_fn(|word| {
                    u128::from_ne_bytes(row[word * 16..][..16].try_into().unwrap())
                })
            })
            .collect();
        Blob::new(Bytes::from(aligned))
    }

    #[test]
    fn cover_view_unions_overlaps_duplicates_and_empty_members() {
        let mut store = MemoryBlobStore::default();
        let empty = store.insert(archive([]));
        let a = store.insert(archive([row(1), row(3)]));
        let b = store.insert(archive([row(2), row(3)]));
        let c = store.insert(archive([row(4)]));
        let reader = store.snapshot().unwrap();
        let collection = Collection::<SimpleArchive>::from_handle(CollectionHandle::new([1; 32]));

        for (handles, expected) in [
            (vec![], vec![]),
            (vec![empty], vec![]),
            (vec![a], vec![row(1), row(3)]),
            (
                vec![c, empty, a, b, a],
                vec![row(1), row(2), row(3), row(4)],
            ),
            (vec![b, a, c], vec![row(1), row(2), row(3), row(4)]),
        ] {
            let facts =
                TribleSet::try_from_cover(&collection.cover(handles), &Fragment::empty(), &reader)
                    .unwrap();
            assert_eq!(
                facts
                    .iter_ordered()
                    .map(|trible| trible.data)
                    .collect::<Vec<_>>(),
                expected,
            );
        }
    }

    #[test]
    fn cover_view_attributes_decode_errors_to_the_exact_member() {
        let collection = Collection::<SimpleArchive>::from_handle(CollectionHandle::new([1; 32]));
        for (invalid, expected) in [
            (
                Blob::new(Bytes::from(vec![1_u8; 63])),
                UnarchiveError::BadArchive,
            ),
            (
                archive([row(3), row(2)]),
                UnarchiveError::BadCanonicalizationOrdering,
            ),
        ] {
            let mut store = MemoryBlobStore::default();
            let valid = store.insert(archive([row(1)]));
            let invalid = store.insert(invalid);
            let reader = store.snapshot().unwrap();
            let error = TribleSet::try_from_cover(
                &collection.cover([valid, invalid]),
                &Fragment::empty(),
                &reader,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                TryFromCoverError::View(FactViewError { member, source })
                    if member == Handle::<SimpleArchive>::to_hash(invalid) && source == expected
            ));
        }
    }

    #[test]
    fn cover_view_attributes_missing_bytes_to_the_exact_member() {
        let mut store = MemoryBlobStore::default();
        let valid = store.insert(archive([row(1)]));
        let missing = archive([row(2)]).get_handle();
        let reader = store.snapshot().unwrap();
        let collection = Collection::<SimpleArchive>::from_handle(CollectionHandle::new([1; 32]));
        let error = TribleSet::try_from_cover(
            &collection.cover([valid, missing]),
            &Fragment::empty(),
            &reader,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TryFromCoverError::MemberGet { member, .. }
                if member == Handle::<SimpleArchive>::to_hash(missing)
        ));
    }

    #[test]
    fn cover_view_retains_original_archive_leaves_after_the_reader_is_dropped() {
        let (facts, input_addresses) = {
            let a = archive([row(1), row(3)]);
            let b = archive([row(2), row(3)]);
            let input_addresses: BTreeSet<usize> = a
                .bytes
                .chunks_exact(TRIBLE_LEN)
                .chain(b.bytes.chunks_exact(TRIBLE_LEN))
                .map(|row| row.as_ptr() as usize)
                .collect();
            let mut store = MemoryBlobStore::default();
            let a = store.insert(a);
            let b = store.insert(b);
            let reader = store.snapshot().unwrap();
            let collection =
                Collection::<SimpleArchive>::from_handle(CollectionHandle::new([1; 32]));
            let facts =
                TribleSet::try_from_cover(&collection.cover([a, b]), &Fragment::empty(), &reader)
                    .unwrap();
            (facts, input_addresses)
        };

        assert_eq!(
            facts
                .iter_ordered()
                .map(|trible| trible.data)
                .collect::<Vec<_>>(),
            [row(1), row(2), row(3)],
        );
        assert!(facts
            .eav
            .iter()
            .all(|row| input_addresses.contains(&(row.as_ptr() as usize))));
        assert_eq!(
            [
                facts.eav.archive_owner_guard_stats(),
                facts.eva.archive_owner_guard_stats(),
                facts.aev.archive_owner_guard_stats(),
                facts.ave.archive_owner_guard_stats(),
                facts.vea.archive_owner_guard_stats(),
                facts.vae.archive_owner_guard_stats(),
            ],
            [(true, 3); 6],
        );
    }
}
