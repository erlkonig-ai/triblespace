//! Exact acquisition and local storage, without serving the local inventory.

use super::*;

/// A locally writable store with lazy exact-blob acquisition and no pile serving.
///
/// A leech uses the same store traits and [`PeerSnapshot`] as [`Peer`], but never
/// builds a serving inventory, advertises resident handles, or activates
/// collection repair. Local reads and writes do not start its host. The first
/// missing exact-handle acquisition starts the shared endpoint; this can still
/// participate in discovery and DHT routing, so "not serving the pile" does not
/// mean an outbound-only network endpoint.
///
/// H remains a read capability. Exact acquisition reuses the provider-first,
/// endpoint-bound bearer exchange and requested-handle verification. Neither H
/// nor a local L-to-H mapping is exposed as a public inventory.
///
/// Construction is deliberately dormant, with no conversion from an arbitrary
/// running peer and no mutable access to its serving controls. A zero publication
/// budget or [`ReconcileDirection::ReadOnly`] on an ordinary peer is not this
/// boundary: those peers still serve their resident inventory.
pub struct Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    // This field is visible only inside the parent peer module. Production
    // construction below always starts dormant, and no Leech method installs a
    // serving snapshot, activates a collection, or publishes provider state.
    pub(super) peer: Peer<S>,
}

impl<S> Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    /// Attach lazy exact acquisition without starting a host or serving the pile.
    pub fn lazy(store: S, key: SigningKey, config: PeerConfig) -> Self {
        Self {
            peer: Peer::lazy(store, key, config),
        }
    }

    pub fn id(&self) -> EndpointId {
        self.peer.id()
    }

    /// Inspect runtime evidence without starting the host or refreshing storage.
    pub fn health(&self) -> Arc<crate::health::HealthSnapshot> {
        self.peer.health()
    }

    /// Borrow the local backend. Drop the guard before another operation or I/O.
    pub fn store(&self) -> impl DerefMut<Target = S> + '_ {
        self.peer.store()
    }

    /// Close live acquisition ownership and return the backend without flushing it.
    pub fn into_store(self) -> S {
        self.peer.into_store()
    }

    pub fn try_local(&mut self, hash: RawHash) -> Option<Bytes> {
        BlobStoreGet::get::<Bytes, UnknownBlob>(&self.snapshot().ok()?, Inline::new(hash)).ok()
    }

    /// Read or acquire an exact blob without publishing WANT or serving state.
    ///
    /// The existing wire verifier binds the returned blob to the requested H;
    /// the verified blob is cached locally and read through a fresh backend
    /// observation. Captured semantic snapshots are not advanced by acquisition.
    pub async fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> Result<Option<Bytes>, PeerAcquireError> {
        let snapshot = self
            .snapshot()
            .map_err(|error| PeerAcquireError(format!("cannot observe resident blob: {error}")))?;
        let Some(reader) = snapshot.acquire_reader(handle).await? else {
            return Ok(None);
        };
        reader
            .get(handle)
            .map(Some)
            .map_err(|error| PeerAcquireError(format!("cannot read acquired blob: {error}")))
    }
}

impl<S> SnapshotSource for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type Snapshot = PeerSnapshot<S>;
    type SnapshotError = PeerSnapshotError<S::SnapshotError>;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.peer.snapshot_from_store()
    }
}

impl<S> AsyncBlobStoreAcquire for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type AcquireError = PeerAcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        Leech::acquire(self, handle)
    }
}

impl<S> BlobStorePut for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.peer.put(item)
    }
}

impl<S> CollectionStore for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type InsertError = <S as CollectionStore>::InsertError;

    fn insert(
        &mut self,
        record: triblespace_core::collection::CollectionRecord,
    ) -> Result<(), Self::InsertError> {
        self.peer.insert(record)
    }
}

impl<S> CapabilityProofStore for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type InsertError = <S as CapabilityProofStore>::InsertError;

    fn insert_proof(
        &mut self,
        proof: triblespace_core::capability::CapabilityProof,
    ) -> Result<(), Self::InsertError> {
        self.peer.insert_proof(proof)
    }
}

impl<S> StorageFlush for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type Error = <S as StorageFlush>::Error;

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.peer.flush()
    }
}

impl<S> StorageClose for Leech<S>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + StorageClose
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    type Error = <S as StorageClose>::Error;

    fn close(self) -> Result<(), Self::Error> {
        self.peer.close()
    }
}
