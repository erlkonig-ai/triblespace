//! Messages crossing the synchronous store / asynchronous host boundary.
//!
//! Collection repair admission is monotone. The host streams authenticated leaves to
//! the store side in bounded batches, where one refresh drain inserts all
//! available batches and crosses a single durability barrier.

use crate::provider::ProviderObservation;
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::{
    COLLECTION_COMMIT_BYTES_LEN, COLLECTION_DERIVE_BYTES_LEN, COLLECTION_MERGE_BYTES_LEN,
    CollectionRecord,
};

/// A changed immutable local serving observation.
///
/// The snapshot slot is replaced before this command is sent. The host uses
/// notices update exact-handle wake subscriptions and periodic repair roots.
pub(crate) struct SnapshotNotice {
    /// Exact active collection handles and their opaque semantic repair roots.
    pub(crate) collections: Vec<(triblespace_core::collection::CollectionHandle, [u8; 32])>,
    /// Whether an immutable serving snapshot is now installed.
    pub(crate) installed: bool,
}

/// Commands sent from [`crate::peer::Peer`] to the host runtime.
pub(crate) enum NetCommand {
    SnapshotChanged(SnapshotNotice),
    /// Replace the exact opaque provider keys selected by the current admitted
    /// artifact observation. Raw handles never cross this boundary.
    ProvidersUpdated(ProviderObservation),
}

/// Authenticated, structurally canonical collection items returned by repair.
///
/// These values remain inert evidence until ordinary local derivation admits
/// them for an exact collection action.
pub(crate) enum NetEvent {
    /// One payload verified on the wire against the handle it was fetched by.
    Blob(Blob<UnknownBlob>),
    CollectionRecord(CollectionRecord),
    /// One native authorization proof. Named claims remain ordinary immutable
    /// dependencies and are fetched only when a consumer follows them.
    CapabilityProof(CapabilityProof),
}

impl NetEvent {
    fn admission_bytes(&self) -> usize {
        match self {
            Self::Blob(blob) => blob.bytes.len(),
            Self::CollectionRecord(CollectionRecord::Commit(_)) => 1 + COLLECTION_COMMIT_BYTES_LEN,
            Self::CollectionRecord(CollectionRecord::Merge(_)) => 1 + COLLECTION_MERGE_BYTES_LEN,
            Self::CollectionRecord(CollectionRecord::Derive(_)) => 1 + COLLECTION_DERIVE_BYTES_LEN,
            Self::CapabilityProof(proof) => proof.as_bytes().len(),
        }
    }
}

impl std::fmt::Debug for NetEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blob(blob) => formatter
                .debug_struct("Blob")
                .field("hash", &blob.get_handle().raw)
                .field("len", &blob.bytes.len())
                .finish(),
            Self::CollectionRecord(record) => formatter
                .debug_tuple("CollectionRecord")
                .field(record)
                .finish(),
            Self::CapabilityProof(proof) => formatter
                .debug_tuple("CapabilityProof")
                .field(proof)
                .finish(),
        }
    }
}

/// Maximum number of independently authenticated items carried by one
/// host-to-store message.
pub(crate) const MAX_ADMISSION_BATCH_ITEMS: usize = 4_096;
/// Soft byte ceiling for one host-to-store message.
///
/// Blob values are indivisible at this boundary. One blob larger than this
/// ceiling is therefore carried alone; `Bytes` keeps the file-backed receive
/// mapping shared instead of copying it into the channel.
pub(crate) const MAX_ADMISSION_BATCH_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of batches buffered across the async/synchronous bridge and
/// consumed by one refresh drain.
pub(crate) const MAX_ADMISSION_BRIDGE_BATCHES: usize = 16;

/// One bounded unit of monotone store admission.
#[derive(Debug, Default)]
pub(crate) struct NetEventBatch {
    events: Vec<NetEvent>,
    bytes: usize,
}

impl NetEventBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn into_events(self) -> impl Iterator<Item = NetEvent> {
        self.events.into_iter()
    }

    /// Append `event`, or return it unchanged when the nonempty batch has
    /// reached either bound. An indivisible oversized event is accepted only
    /// into an empty batch and immediately makes it ready to send.
    pub(crate) fn try_push(&mut self, event: NetEvent) -> Result<(), NetEvent> {
        let event_bytes = event.admission_bytes();
        let exceeds_count = self.events.len() >= MAX_ADMISSION_BATCH_ITEMS;
        let exceeds_bytes = self
            .bytes
            .checked_add(event_bytes)
            .is_none_or(|bytes| bytes > MAX_ADMISSION_BATCH_BYTES);
        if !self.events.is_empty() && (exceeds_count || exceeds_bytes) {
            return Err(event);
        }
        self.bytes = self.bytes.saturating_add(event_bytes);
        self.events.push(event);
        Ok(())
    }

    pub(crate) fn is_full(&self) -> bool {
        self.events.len() >= MAX_ADMISSION_BATCH_ITEMS || self.bytes >= MAX_ADMISSION_BATCH_BYTES
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use triblespace_core::collection::{
        CollectionCommit, CollectionData, CollectionRecord, empty_metadata_handle,
    };

    use super::*;

    fn record(byte: u8) -> NetEvent {
        NetEvent::CollectionRecord(CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[byte; 32]),
            triblespace_core::collection::CollectionHandle::new([0xA5; 32]),
            CollectionData::new([byte; 32]),
            empty_metadata_handle(),
        )))
    }

    #[test]
    fn admission_batches_enforce_count_and_byte_bounds() {
        let mut count_bounded = NetEventBatch::default();
        for byte in 0..MAX_ADMISSION_BATCH_ITEMS {
            count_bounded.try_push(record(byte as u8)).unwrap();
        }
        assert!(count_bounded.is_full());
        assert!(count_bounded.try_push(record(0xFF)).is_err());
    }

    #[test]
    fn record_batching_keeps_items_bounded() {
        let mut batch = NetEventBatch::default();
        batch.try_push(record(0x33)).unwrap();
        assert_eq!(batch.len(), 1);
    }
}
