//! Exact bearer-handle discovery and key confirmation.
//!
//! A blob handle `H` is both the content address and the read capability for
//! those exact immutable bytes. The raw handle never crosses the provider
//! directory or the exact-GET stream:
//!
//! - `L = blob_locator(H)` is the opaque locator sent to a candidate;
//! - the candidate proves knowledge of `H` first with
//!   `keyed(provider; H || requester)`; and
//! - only then does the requester prove knowledge of `H` with
//!   `keyed(requester; provider || H)`.
//!
//! Each proof is keyed by one TLS-authenticated endpoint identity and names
//! the other, so it binds both and is exactly one 64-byte BLAKE3 block. `H`
//! sits on opposite sides of the two messages, so the two roles never produce
//! the same value: not on one connection, where equality would let a requester
//! that knows only `L` echo the provider's proof back, and not across a
//! swapped pair of roles. They are deterministic because replay by the same
//! requester to the same provider merely repeats an authorized read of
//! immutable content; replay under any other endpoint identity fails.

use anyhow::Result;
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::BlobStoreList;

use crate::protocol::RawHash;
use crate::transport::PeerId;

/// Snapshot-coherent reverse index from opaque locator to resident handle.
///
/// The locator is a cryptographic image of the handle. Its collision model is
/// the same 256-bit content-address assumption used by the blob namespace.
pub(crate) type BearerLocatorIndex = PATCH<32, IdentitySchema, RawHash>;

pub use triblespace_core::blob::locator::blob_locator;

/// Provider-first proof of knowledge: `keyed(provider; H || requester)`.
pub(crate) fn provider_proof(handle: RawHash, requester: PeerId, provider: PeerId) -> RawHash {
    keyed_block(&provider, &handle, &requester)
}

/// Requester-second proof of knowledge: `keyed(requester; provider || H)`.
pub(crate) fn requester_proof(handle: RawHash, requester: PeerId, provider: PeerId) -> RawHash {
    keyed_block(&requester, &provider, &handle)
}

fn keyed_block(key: &[u8; 32], first: &[u8; 32], second: &[u8; 32]) -> RawHash {
    let mut block = [0; 64];
    block[..32].copy_from_slice(first);
    block[32..].copy_from_slice(second);
    *blake3::keyed_hash(key, &block).as_bytes()
}

/// Compare fixed-width key-confirmation values without an early mismatch exit.
pub(crate) fn proof_matches(actual: &RawHash, expected: &RawHash) -> bool {
    actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Build the exact locator index for one immutable blob-store observation.
pub(crate) fn locator_index<R>(snapshot: &R) -> Result<BearerLocatorIndex>
where
    R: BlobStoreList,
{
    let mut index = BearerLocatorIndex::new();
    for info in snapshot.blobs() {
        let handle = info
            .map_err(|error| anyhow::anyhow!("cannot enumerate bearer blobs: {error:?}"))?
            .handle
            .raw;
        let locator = blob_locator(handle);
        index.insert(&PatchEntry::with_value(&locator, handle));
    }
    Ok(index)
}

/// Apply one store-snapshot delta to a structurally shared locator index.
///
/// Native Pile/Yard snapshots answer both differences from PATCH indexes. A
/// list-only backend may conservatively enumerate old and new in full; remove
/// then add remains correct.
pub(crate) fn update_locator_index<R>(
    snapshot: &R,
    previous: &R,
    previous_index: &BearerLocatorIndex,
) -> Result<BearerLocatorIndex>
where
    R: BlobStoreList,
{
    let mut index = previous_index.clone();
    for info in previous.blobs_diff(snapshot) {
        let handle = info
            .map_err(|error| anyhow::anyhow!("cannot enumerate removed bearer blobs: {error:?}"))?
            .handle
            .raw;
        index.remove(&blob_locator(handle));
    }
    for info in snapshot.blobs_diff(previous) {
        let handle = info
            .map_err(|error| anyhow::anyhow!("cannot enumerate added bearer blobs: {error:?}"))?
            .handle
            .raw;
        index.replace(&PatchEntry::with_value(&blob_locator(handle), handle));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use anybytes::Bytes;
    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::inline::Inline;
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobInfo, BlobStorePut, SnapshotSource};

    use super::*;

    #[test]
    fn proofs_match_their_known_answers() {
        // Computed independently with the reference blake3 crate. These bytes
        // are wire format: a provider and a requester must agree on them.
        let (handle, requester, provider) = ([1; 32], [2; 32], [3; 32]);
        assert_eq!(
            provider_proof(handle, requester, provider),
            hex_literal::hex!("0319B3498D8C22E3F8E2BB46556AE3ED205335DA0C5D6A6CF3C3DC42740CBA28")
        );
        assert_eq!(
            requester_proof(handle, requester, provider),
            hex_literal::hex!("8D30D403E89833D30A2ADD3EC09038019C4F59B3DFA2DADE2B3315989575A9F8")
        );
    }

    #[test]
    fn a_provider_proof_never_serves_as_a_requester_proof() {
        let (handle, requester, provider) = ([21; 32], [22; 32], [23; 32]);
        // Echo: a requester that knows only the locator receives the
        // provider's proof and returns it on the same connection.
        assert_ne!(
            provider_proof(handle, requester, provider),
            requester_proof(handle, requester, provider)
        );
        // Swap: the proof a provider hands out must not be the requester
        // proof of the connection with the roles reversed.
        assert_ne!(
            provider_proof(handle, requester, provider),
            requester_proof(handle, provider, requester)
        );
        assert_ne!(
            requester_proof(handle, requester, provider),
            provider_proof(handle, provider, requester)
        );
    }

    #[derive(Clone)]
    struct ListSnapshot(Vec<BlobInfo>);

    impl BlobStoreList for ListSnapshot {
        type Iter<'a> = std::vec::IntoIter<Result<BlobInfo, Infallible>>;
        type Err = Infallible;

        fn blobs<'a>(&'a self) -> Self::Iter<'a> {
            self.0
                .iter()
                .copied()
                .map(Ok)
                .collect::<Vec<_>>()
                .into_iter()
        }
    }

    fn info(raw: RawHash) -> BlobInfo {
        BlobInfo {
            handle: Inline::<Handle<UnknownBlob>>::new(raw),
            length: 1,
        }
    }

    #[test]
    fn proofs_are_role_and_endpoint_bound() {
        let handle = [7; 32];
        let requester = [8; 32];
        let provider = [9; 32];
        let provider_value = provider_proof(handle, requester, provider);
        let requester_value = requester_proof(handle, requester, provider);

        assert_ne!(blob_locator(handle), handle);
        assert_ne!(provider_value, requester_value);
        assert_ne!(provider_value, provider_proof(handle, [10; 32], provider));
        assert_ne!(provider_value, provider_proof(handle, requester, [10; 32]));
        assert!(!proof_matches(&provider_value, &requester_value));
        assert!(proof_matches(&provider_value, &provider_value));
    }

    #[test]
    fn locator_index_tracks_patch_backed_snapshot_additions() {
        let mut store = MemoryRepo::default();
        let before = store.snapshot().unwrap();
        let before_index = locator_index(&before).unwrap();
        let added = store
            .put::<UnknownBlob, _>(Bytes::from_source(vec![17; 257]))
            .unwrap();
        let after = store.snapshot().unwrap();
        let after_index = update_locator_index(&after, &before, &before_index).unwrap();

        assert!(before_index.get(&blob_locator(added.raw)).is_none());
        assert_eq!(after_index.get(&blob_locator(added.raw)), Some(&added.raw));
    }

    #[test]
    fn locator_index_fallback_remove_then_add_is_exact() {
        let removed = [21; 32];
        let retained = [22; 32];
        let added = [23; 32];
        let before = ListSnapshot(vec![info(removed), info(retained)]);
        let after = ListSnapshot(vec![info(retained), info(added)]);
        let before_index = locator_index(&before).unwrap();
        let after_index = update_locator_index(&after, &before, &before_index).unwrap();

        assert!(after_index.get(&blob_locator(removed)).is_none());
        assert_eq!(after_index.get(&blob_locator(retained)), Some(&retained));
        assert_eq!(after_index.get(&blob_locator(added)), Some(&added));
    }
}
