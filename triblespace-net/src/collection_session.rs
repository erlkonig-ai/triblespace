//! READ-authorized, stream-pinned repair of one collection overlay.

use std::sync::Arc;

use anyhow::{Result, bail};
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::{CollectionHandle, CollectionRecord};
use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH};

use crate::collection_activation::{CollectionAuthorizationEvidenceError, CollectionRepairOverlay};
use crate::collection_delta::{decode_record, encode_record};
use crate::collection_wire::{
    CollectionRepairAdmission, CollectionRepairCommand, CollectionRepairComponent,
    CollectionRepairManifest, recv_repair_admission, recv_repair_collection, recv_repair_command,
    recv_repair_hello, recv_repair_node_response, send_repair_admission, send_repair_bootstrap,
    send_repair_done, send_repair_node_request, send_repair_node_response,
};
use crate::patch_repair::{
    PatchNode, PatchNodeResponse, PatchRepairRequest, PatchRepairWalker, PatchSummary,
    patch_node_response, validate_patch_node,
};
use crate::protocol::RawHash;
use crate::transport::Conn;

/// A valid, collection-scoped reply, not a broken shared transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionRepairRefusal {
    Rejected,
    Unavailable,
}

impl std::fmt::Display for CollectionRepairRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "remote rejected READ(C) evidence",
            Self::Unavailable => "remote does not retain the requested collection",
        })
    }
}

impl std::error::Error for CollectionRepairRefusal {}

/// Evidence missing from the caller's immutable local observation.
#[derive(Clone, Debug)]
pub(crate) struct CollectionRepairDelta {
    pub(crate) compared_at: crate::clock::Mono,
    pub(crate) local: CollectionRepairManifest,
    pub(crate) remote: CollectionRepairManifest,
    pub(crate) records: Vec<CollectionRecord>,
    pub(crate) authorization_evidence: Vec<CapabilityProof>,
    /// Positive hints from the peer's pinned resident inventory, never payloads.
    pub(crate) blob_handles: Vec<RawHash>,
    pub(crate) inventory_cursor: Option<InventoryRepairCursor>,
    /// Semantic evidence remains incomplete, independently of inventory hints.
    pub(crate) more: bool,
}

/// Bounded DFS frontier for one remote inventory, reusable across admitted streams.
/// The host owns its per-target retention bound. A changed summary starts a
/// freshly authenticated walk above the last visited key, then wraps to low
/// keys after that suffix completes. Local comparisons stay on the original PATCH.
/// A 32-byte key bounds DFS pending siblings to at most 32 * 255 nodes.
#[derive(Clone, Debug)]
pub(crate) struct InventoryRepairCursor {
    collection: CollectionHandle,
    remote: PatchSummary,
    local: PATCH<32, IdentitySchema, (), Blake3Merkle>,
    walker: PatchRepairWalker<CollectionRepairComponent>,
    visited: Option<RawHash>,
    /// Lower bound only for a freshly pinned walk; never an old Merkle proof.
    resume_after: Option<RawHash>,
    wrap: bool,
}

impl CollectionRepairDelta {
    /// Incompleteness alone is not progress: absent resource descriptors can
    /// leave AUTH deferred indefinitely. Retry those on the ordinary cadence,
    /// while immediately continuing a bounded pass that actually added data.
    /// Inventory hints alone do not prove that any body was acquired.
    pub(crate) fn retry_immediately(&self) -> bool {
        self.more && (!self.records.is_empty() || !self.authorization_evidence.is_empty())
    }
}

const MAX_REPAIR_RECORD_ITEMS: usize = 4_096;
const MAX_REPAIR_AUTHORIZATION_EVIDENCE_ITEMS: usize = 16;
const MAX_REPAIR_NODE_REQUESTS: usize = 16_384;
const MAX_SEMANTIC_REPAIR_NODE_REQUESTS: usize = 511;
const MAX_BLOB_INVENTORY_NODE_REQUESTS: usize = 128;
const MAX_SERVER_REPAIR_COMMANDS: usize =
    MAX_SEMANTIC_REPAIR_NODE_REQUESTS + MAX_BLOB_INVENTORY_NODE_REQUESTS + 1;
const MAX_SEMANTIC_NODE_RESPONSE_BYTES: usize = 64 << 20;
const MAX_BLOB_INVENTORY_RESPONSE_BYTES: usize = 2 << 20;
const MAX_SERVER_NODE_RESPONSE_BYTES: usize =
    MAX_SEMANTIC_NODE_RESPONSE_BYTES + MAX_BLOB_INVENTORY_RESPONSE_BYTES;
// AUTH runs first, but deferred leaves must not consume the entire stream and
// prevent independent collection records from making progress.
const MAX_AUTHORIZATION_REPAIR_NODE_REQUESTS: usize = MAX_SEMANTIC_REPAIR_NODE_REQUESTS / 2;

/// Serve the body of one collection-repair operation after its operation byte
/// has already been consumed.
///
/// `lookup` must return an immutable overlay. Its lifetime is the stream's
/// snapshot lease: every manifest and node response comes from the exact same
/// semantic and inventory PATCH roots, so no historical-root cache is needed. Returned
/// bootstrap proofs are inert inputs for a later coherent authorization
/// observation; they never authorize this pinned session.
pub(crate) async fn serve_collection_repair<R, W>(
    recv: &mut R,
    send: &mut W,
    remote: VerifyingKey,
    lookup: impl FnOnce(CollectionHandle) -> Option<Arc<CollectionRepairOverlay>>,
) -> Result<Vec<CapabilityProof>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let collection = recv_repair_collection(recv).await?;
    let Some(overlay) = lookup(collection) else {
        send_repair_admission(send, CollectionRepairAdmission::Unavailable).await?;
        send.shutdown().await?;
        return Ok(Vec::new());
    };
    let hello = recv_repair_hello(recv).await?;
    let evidence = overlay.authorization_evidence();
    let bootstrap = hello
        .bootstrap_proofs
        .into_iter()
        .filter(|proof| {
            evidence.get(proof.id()).is_none()
                && proof.resource().into_bytes() == collection.raw
                && proof.prefixes().any(|prefix| prefix.subject() == remote)
                && evidence.validate_proof(proof).is_ok()
        })
        .collect::<Vec<_>>();
    let read_evidence = overlay
        .authorization_evidence()
        .proofs()
        .cloned()
        .collect::<Vec<_>>();
    let admitted = evidence.reader_is_admitted_by(remote, &read_evidence);
    if !admitted {
        send_repair_admission(send, CollectionRepairAdmission::Rejected).await?;
        send.shutdown().await?;
        return Ok(bootstrap);
    }

    let manifest = manifest(&overlay);
    send_repair_admission(send, CollectionRepairAdmission::Admitted(manifest)).await?;
    let mut commands = 0_usize;
    let mut response_bytes = 0_usize;
    loop {
        if commands == MAX_SERVER_REPAIR_COMMANDS {
            bail!("collection repair command budget exhausted");
        }
        commands += 1;
        match recv_repair_command(recv).await? {
            CollectionRepairCommand::Done => {
                require_eof(recv).await?;
                send.shutdown().await?;
                return Ok(bootstrap);
            }
            CollectionRepairCommand::Node {
                component,
                prefix,
                expected_digest,
            } => {
                let summary = manifest.component(component);
                let Some(root) = summary.root() else {
                    bail!("client requested a node from an empty collection PATCH");
                };
                let request = PatchRepairRequest::new(
                    component,
                    summary,
                    component.key_len(),
                    prefix,
                    expected_digest,
                )?;
                if request.prefix().is_empty() && request.expected_digest() != root {
                    bail!("collection repair request does not pin the manifest root");
                }
                let response = node_response(&overlay, component, request.prefix())?;
                if response_bytes >= MAX_SERVER_NODE_RESPONSE_BYTES {
                    bail!("collection repair response budget exhausted");
                }
                response_bytes = response_bytes.saturating_add(node_response_wire_len(&response));
                send_repair_node_response(send, &response, component).await?;
            }
        }
    }
}

fn node_response_wire_len(response: &PatchNodeResponse<Vec<u8>>) -> usize {
    match response {
        PatchNodeResponse::SnapshotUnavailable | PatchNodeResponse::PrefixAbsent => 1,
        PatchNodeResponse::Found(crate::patch_repair::PatchNode::Leaf { leaf, .. }) => {
            1 + 1 + 32 + leaf.key.len() + 4 + leaf.value.len()
        }
        PatchNodeResponse::Found(crate::patch_repair::PatchNode::Branch { branch, .. }) => {
            1 + 1 + 32 + 8 + branch.representative.len() + 1 + 4 + branch.children.len() * 41
        }
    }
}

pub(crate) fn manifest(overlay: &CollectionRepairOverlay) -> CollectionRepairManifest {
    CollectionRepairManifest {
        wake_root: overlay.wake_root(),
        records: overlay.records().summary(),
        authorization_evidence: overlay.authorization_evidence().summary(),
        resident_blobs: PatchSummary::from_patch(overlay.blob_inventory()),
    }
}

fn node_response(
    overlay: &CollectionRepairOverlay,
    component: CollectionRepairComponent,
    prefix: &[u8],
) -> Result<PatchNodeResponse<Vec<u8>>> {
    match component {
        CollectionRepairComponent::Record => {
            patch_node_response(overlay.records().patch(), &[], prefix, |key, record| {
                if record.fingerprint().raw() != key {
                    bail!("collection record fingerprint does not match its PATCH leaf key");
                }
                encode_record(overlay.collection(), *record).map_err(anyhow::Error::new)
            })
        }
        CollectionRepairComponent::AuthorizationEvidence => patch_node_response(
            overlay.authorization_evidence().patch(),
            &overlay.collection().raw,
            prefix,
            |key, proof| {
                if proof.id().raw != key[32..] {
                    bail!("authorization proof id does not match its PATCH leaf key");
                }
                Ok(proof.as_bytes().to_vec())
            },
        ),
        CollectionRepairComponent::ResidentBlob => patch_node_response(
            overlay.blob_inventory(),
            &[],
            prefix,
            |_, ()| Ok(Vec::new()),
        ),
    }
}

/// Pull one exact collection overlay over an already authenticated iroh
/// connection. TLS binds `conn.remote_id()`; the supplied native proof forest
/// can bootstrap a cold server, while same-session READ(C) comes only from its
/// already pinned local evidence.
/// An inventory cursor resumes the same summary's authenticated DFS, or starts
/// a fresh root-validated suffix after a summary change. The caller retains its
/// last successful cursor across failed exchanges; no progress from a failed
/// exchange is committed. Bounded passes progress without any payload landing.
pub(crate) async fn pull_collection<C: Conn>(
    conn: &C,
    local: &CollectionRepairOverlay,
    read_bootstrap: Vec<CapabilityProof>,
    inventory_cursor: Option<InventoryRepairCursor>,
) -> Result<CollectionRepairDelta> {
    let (mut send, mut recv) = conn.open_bi().await?;
    pull_collection_stream(
        &mut send,
        &mut recv,
        local,
        read_bootstrap,
        inventory_cursor,
    )
    .await
}

async fn pull_collection_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    local: &CollectionRepairOverlay,
    read_bootstrap: Vec<CapabilityProof>,
    inventory_cursor: Option<InventoryRepairCursor>,
) -> Result<CollectionRepairDelta>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    crate::protocol::send_u8(send, crate::collection_wire::OP_COLLECTION_REPAIR).await?;
    crate::protocol::send_hash(send, &local.collection().raw).await?;
    send_repair_bootstrap(send, &read_bootstrap).await?;
    let remote = match recv_repair_admission(recv).await? {
        CollectionRepairAdmission::Admitted(manifest) => manifest,
        CollectionRepairAdmission::Rejected => return Err(CollectionRepairRefusal::Rejected.into()),
        CollectionRepairAdmission::Unavailable => {
            return Err(CollectionRepairRefusal::Unavailable.into());
        }
    };
    // A long repair must not make its older pinned manifest appear fresh at
    // completion. This is the observation instant, not the completion instant.
    let compared_at = crate::clock::mono_now();

    let mut remaining_requests = MAX_SEMANTIC_REPAIR_NODE_REQUESTS;
    let mut response_bytes = 0_usize;
    let (authorization_evidence, authorization_more) = pull_authorization_evidence_patch(
        send,
        recv,
        local,
        remote.authorization_evidence,
        &mut remaining_requests,
        &mut response_bytes,
    )
    .await?;
    let (records, record_more) = pull_record_patch(
        send,
        recv,
        local,
        remote.records,
        &mut remaining_requests,
        &mut response_bytes,
    )
    .await?;
    // Inventory cannot consume the semantic repair reservation. It has its own
    // bounded allowance and never performs a body fetch or WRITE admission.
    let (blob_handles, inventory_cursor) = pull_blob_inventory_patch(
        send,
        recv,
        local,
        remote.resident_blobs,
        inventory_cursor,
        &mut response_bytes,
    )
    .await?;
    send_repair_done(send).await?;
    send.shutdown().await?;
    require_eof(recv).await?;
    Ok(CollectionRepairDelta {
        compared_at,
        local: manifest(local),
        remote,
        records,
        authorization_evidence,
        blob_handles,
        inventory_cursor,
        more: authorization_more || record_more,
    })
}

async fn pull_record_patch<W, R>(
    send: &mut W,
    recv: &mut R,
    local: &CollectionRepairOverlay,
    remote: PatchSummary,
    remaining_requests: &mut usize,
    response_bytes: &mut usize,
) -> Result<(Vec<CollectionRecord>, bool)>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let component = CollectionRepairComponent::Record;
    let mut walker = PatchRepairWalker::new(component, remote, component.key_len())?;
    let mut missing = Vec::new();
    let mut requests = 0;
    let mut complete = false;
    loop {
        if requests >= MAX_REPAIR_NODE_REQUESTS
            || *remaining_requests == 0
            || *response_bytes >= MAX_SEMANTIC_NODE_RESPONSE_BYTES
            || missing.len() >= MAX_REPAIR_RECORD_ITEMS
        {
            break;
        }
        let request = walker.next_request(|_, prefix| {
            local.records().patch().merkle_node(prefix).map(|node| {
                PatchSummary::new(Some(node.digest()), node.leaf_count())
                    .expect("a PATCH node is nonempty")
            })
        })?;
        let Some(request) = request else {
            complete = true;
            break;
        };
        requests += 1;
        *remaining_requests -= 1;
        send_repair_node_request(send, &request, component).await?;
        let response = recv_repair_node_response(recv, component).await?;
        *response_bytes = response_bytes.saturating_add(node_response_wire_len(&response));
        let mut verified_leaf = None;
        validate_response(
            &request,
            component,
            local.collection(),
            &response,
            |key, bytes| {
                let record = decode_record(local.collection(), bytes)?;
                if record.fingerprint().raw().as_slice() != key {
                    bail!("collection record body does not match its PATCH leaf key");
                }
                verified_leaf = Some(record);
                Ok(())
            },
        )?;
        if walker
            .accept(&request, response, |_, key| {
                let Ok(key) = <[u8; 32]>::try_from(key) else {
                    return false;
                };
                local
                    .records()
                    .get(triblespace_core::collection::CollectionRecordFingerprint::from_raw(key))
                    .is_some()
            })?
            .is_some()
        {
            missing.push(
                verified_leaf
                    .ok_or_else(|| anyhow::anyhow!("accepted collection leaf was not verified"))?,
            );
        }
    }
    if complete {
        walker.finish()?;
    }
    Ok((missing, !complete))
}

async fn pull_authorization_evidence_patch<W, R>(
    send: &mut W,
    recv: &mut R,
    local: &CollectionRepairOverlay,
    remote: PatchSummary,
    remaining_requests: &mut usize,
    response_bytes: &mut usize,
) -> Result<(Vec<CapabilityProof>, bool)>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let component = CollectionRepairComponent::AuthorizationEvidence;
    let mut walker = PatchRepairWalker::new(component, remote, component.key_len())?;
    let mut missing = Vec::new();
    let mut requests = 0;
    let mut complete = false;
    let mut deferred = false;
    loop {
        if requests >= MAX_AUTHORIZATION_REPAIR_NODE_REQUESTS
            || *remaining_requests == 0
            || *response_bytes >= MAX_SEMANTIC_NODE_RESPONSE_BYTES / 2
            || missing.len() >= MAX_REPAIR_AUTHORIZATION_EVIDENCE_ITEMS
        {
            break;
        }
        let request = walker
            .next_request(|_, prefix| local.authorization_evidence().prefix_summary(prefix))?;
        let Some(request) = request else {
            complete = true;
            break;
        };
        requests += 1;
        *remaining_requests -= 1;
        send_repair_node_request(send, &request, component).await?;
        let response = recv_repair_node_response(recv, component).await?;
        *response_bytes = response_bytes.saturating_add(node_response_wire_len(&response));
        validate_response(
            &request,
            component,
            local.collection(),
            &response,
            |key, bytes| validate_authorization_leaf_bytes(local.collection(), key, bytes),
        )?;
        if let Some(leaf) = walker.accept(&request, response, |_, key| {
            let Ok(key) = <[u8; 32]>::try_from(key) else {
                return false;
            };
            local
                .authorization_evidence()
                .get(CapabilityProofId::new(key))
                .is_some()
        })? {
            let proof = CapabilityProof::from_bytes(&leaf.value)?;
            match local.authorization_evidence().validate_proof(&proof) {
                Ok(()) => missing.push(proof),
                Err(
                    CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(_)
                    | CollectionAuthorizationEvidenceError::WrongRoot,
                ) if proof.resource().into_bytes() != local.collection().raw => {
                    // R may arrive through ordinary blob acquisition after
                    // this pinned observation. Do not ingest unrouted proofs,
                    // block independent C records, or claim AUTH convergence.
                    deferred = true;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    if complete {
        walker.finish()?;
    }
    Ok((missing, !complete || deferred))
}

async fn pull_blob_inventory_patch<W, R>(
    send: &mut W,
    recv: &mut R,
    local: &CollectionRepairOverlay,
    remote: PatchSummary,
    cursor: Option<InventoryRepairCursor>,
    response_bytes: &mut usize,
) -> Result<(Vec<RawHash>, Option<InventoryRepairCursor>)>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let component = CollectionRepairComponent::ResidentBlob;
    let mut cursor = match cursor {
        Some(mut cursor) if cursor.collection == local.collection() => {
            if cursor.remote != remote {
                cursor.remote = remote;
                cursor.walker = PatchRepairWalker::new(component, remote, component.key_len())?;
                cursor.resume_after = cursor.visited;
                cursor.wrap |= cursor.resume_after.is_some();
            }
            cursor
        }
        _ => InventoryRepairCursor {
            collection: local.collection(),
            remote,
            local: local.blob_inventory().clone(),
            walker: PatchRepairWalker::new(component, remote, component.key_len())?,
            visited: None,
            resume_after: None,
            wrap: false,
        },
    };
    let mut missing = Vec::new();
    let started_bytes = *response_bytes;
    for _ in 0..MAX_BLOB_INVENTORY_NODE_REQUESTS {
        if response_bytes.saturating_sub(started_bytes) >= MAX_BLOB_INVENTORY_RESPONSE_BYTES
            || *response_bytes >= MAX_SERVER_NODE_RESPONSE_BYTES
        {
            break;
        }
        let request = cursor.walker.next_request_after(
            |_, prefix| {
                cursor.local.merkle_node(prefix).map(|node| {
                    PatchSummary::new(Some(node.digest()), node.leaf_count())
                        .expect("a PATCH node is nonempty")
                })
            },
            cursor.resume_after.as_ref().map(|key| key.as_slice()),
        )?;
        let Some(request) = request else {
            cursor.walker.finish()?;
            if cursor.wrap {
                // Earlier additions were deliberately outside the suffix.
                // Revisit them on a subsequent bounded session, not recursively
                // in this one. This says nothing about absence in either range.
                cursor.walker = PatchRepairWalker::new(component, remote, component.key_len())?;
                cursor.visited = None;
                cursor.resume_after = None;
                cursor.wrap = false;
                return Ok((missing, Some(cursor)));
            }
            return Ok((missing, None));
        };
        send_repair_node_request(send, &request, component).await?;
        let response = recv_repair_node_response(recv, component).await?;
        *response_bytes = response_bytes.saturating_add(node_response_wire_len(&response));
        validate_response(
            &request,
            component,
            local.collection(),
            &response,
            validate_inventory_leaf_bytes,
        )?;
        let visited = match &response {
            PatchNodeResponse::Found(PatchNode::Leaf { leaf, .. }) => {
                Some(<RawHash>::try_from(leaf.key.as_slice()).map_err(|_| {
                    anyhow::anyhow!("resident blob inventory leaf has an invalid handle length")
                })?)
            }
            _ => None,
        };
        let leaf = cursor.walker.accept(&request, response, |_, key| {
            let Ok(key) = <RawHash>::try_from(key) else {
                return false;
            };
            cursor.resume_after.is_some_and(|bound| key <= bound)
                || cursor.local.get(&key).is_some()
        })?;
        if let Some(visited) = visited {
            cursor.visited = Some(cursor.visited.map_or(visited, |prior| prior.max(visited)));
        }
        if let Some(leaf) = leaf {
            missing.push(<RawHash>::try_from(leaf.key.as_slice()).map_err(|_| {
                anyhow::anyhow!("resident blob inventory leaf has an invalid handle length")
            })?);
        }
    }
    // Preserve the authenticated frontier instead of revisiting the same early
    // missing leaves on every bounded session. No payload must land for this
    // traversal to progress, and no negative residency claim is inferred.
    Ok((missing, Some(cursor)))
}

fn validate_inventory_leaf_bytes(key: &[u8], bytes: &[u8]) -> Result<()> {
    if key.len() != 32 || !bytes.is_empty() {
        bail!("resident blob inventory leaf must be an exact handle with an empty value");
    }
    Ok(())
}

fn validate_authorization_leaf_bytes(
    audience: CollectionHandle,
    key: &[u8],
    bytes: &[u8],
) -> Result<()> {
    let proof = CapabilityProof::from_bytes(bytes)?;
    if key.len() != 64 || key[..32] != audience.raw || proof.id().raw != key[32..] {
        bail!("authorization proof body does not match its scoped PATCH leaf key");
    }
    proof.verify_signatures()?;
    Ok(())
}

fn validate_response<S>(
    request: &PatchRepairRequest<S>,
    component: CollectionRepairComponent,
    collection: CollectionHandle,
    response: &PatchNodeResponse<Vec<u8>>,
    validate_leaf: impl FnOnce(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    match response {
        PatchNodeResponse::Found(node) => {
            let base: &[u8] = match component {
                CollectionRepairComponent::Record | CollectionRepairComponent::ResidentBlob => &[],
                CollectionRepairComponent::AuthorizationEvidence => &collection.raw,
            };
            validate_patch_node(
                request,
                base.len() + component.key_len(),
                base,
                node,
                |key, bytes| validate_leaf(key, bytes),
            )
        }
        PatchNodeResponse::PrefixAbsent => {
            bail!("remote omitted an authenticated collection PATCH prefix")
        }
        PatchNodeResponse::SnapshotUnavailable => {
            bail!("remote lost a stream-pinned collection PATCH")
        }
    }
}

async fn require_eof<R: AsyncRead + Unpin>(recv: &mut R) -> Result<()> {
    let mut trailing = [0u8; 1];
    if recv.read(&mut trailing).await? != 0 {
        bail!("collection repair stream contains trailing bytes");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::capability::{CapabilityResource, capability_action};
    use triblespace_core::collection::{
        ACTION_READ, ACTION_WRITE, AdmissionPolicy, CollectionCommit, CollectionData,
        CollectionPolicy, CollectionRecord, CollectionStore, CollectionStoreExt,
        KIND_COLLECTION_DESCRIPTOR, empty_metadata_handle, read_capability, write_capability,
    };
    use triblespace_core::metadata;
    use triblespace_core::prelude::entity;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{
        BlobStoreList, BlobStorePut, CapabilityProofStore, SnapshotSource, WantRead,
    };

    use crate::collection_activation::collection_repair_overlay;
    use crate::protocol::recv_u8;

    use super::*;

    pub(crate) fn inventory(
        handles: impl IntoIterator<Item = RawHash>,
    ) -> Arc<PATCH<32, IdentitySchema, (), Blake3Merkle>> {
        let mut patch = PATCH::new();
        for handle in handles {
            patch.insert(&triblespace_core::patch::Entry::with_value(&handle, ()));
        }
        Arc::new(patch)
    }

    async fn pull(
        local: &CollectionRepairOverlay,
        remote: Arc<CollectionRepairOverlay>,
        reader: VerifyingKey,
    ) -> Result<CollectionRepairDelta> {
        pull_with_cursor(local, remote, reader, None).await
    }

    pub(crate) async fn pull_with_cursor(
        local: &CollectionRepairOverlay,
        remote: Arc<CollectionRepairOverlay>,
        reader: VerifyingKey,
        cursor: Option<InventoryRepairCursor>,
    ) -> Result<CollectionRepairDelta> {
        pull_with_cursor_ending(local, remote, reader, cursor, TestEnding::Complete).await
    }

    #[derive(Clone, Copy)]
    pub(crate) enum TestEnding {
        Complete,
        ReadError,
        Timeout,
    }

    struct TestReader<R> {
        inner: R,
        ending: TestEnding,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for TestReader<R> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buffer.filled().len();
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, buffer) {
                std::task::Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                    match this.ending {
                        TestEnding::Complete => std::task::Poll::Ready(Ok(())),
                        TestEnding::ReadError => std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "injected failure after the authenticated inventory page",
                        ))),
                        TestEnding::Timeout => std::task::Poll::Pending,
                    }
                }
                result => result,
            }
        }
    }

    pub(crate) async fn pull_with_cursor_ending(
        local: &CollectionRepairOverlay,
        remote: Arc<CollectionRepairOverlay>,
        reader: VerifyingKey,
        cursor: Option<InventoryRepairCursor>,
        ending: TestEnding,
    ) -> Result<CollectionRepairDelta> {
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let (mut server_recv, mut server_send) = tokio::io::split(server_io);
        let (client_recv, mut client_send) = tokio::io::split(client_io);
        let mut client_recv = TestReader {
            inner: client_recv,
            ending,
        };
        let server = tokio::spawn(async move {
            assert_eq!(
                recv_u8(&mut server_recv).await.unwrap(),
                crate::collection_wire::OP_COLLECTION_REPAIR
            );
            let retained =
                serve_collection_repair(&mut server_recv, &mut server_send, reader, |collection| {
                    (collection == remote.collection()).then_some(remote)
                })
                .await
                .unwrap();
            assert!(retained.is_empty());
        });
        let pull =
            pull_collection_stream(&mut client_send, &mut client_recv, local, vec![], cursor);
        let result = match ending {
            TestEnding::Timeout => tokio::time::timeout(std::time::Duration::from_secs(1), pull)
                .await
                .unwrap_or_else(|error| Err(anyhow::Error::new(error))),
            _ => pull.await,
        };
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn resident_inventory_returns_positive_hints_without_payloads_or_writes() {
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "resident-inventory",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap()
            .handle();
        let snapshot = store.snapshot().unwrap();
        let local = collection_repair_overlay(&snapshot, collection)
            .unwrap()
            .with_blob_inventory(inventory([[2; 32], [4; 32]]));
        let mut remote_inventory = inventory([[1; 32], [2; 32], [3; 32]]);
        let remote = Arc::new(
            collection_repair_overlay(&snapshot, collection)
                .unwrap()
                .with_blob_inventory(remote_inventory.clone()),
        );
        let pinned_root = remote.wake_root();
        Arc::make_mut(&mut remote_inventory)
            .insert(&triblespace_core::patch::Entry::with_value(&[5; 32], ()));
        assert_eq!(remote.wake_root(), pinned_root);
        assert_ne!(local.wake_root(), pinned_root);
        let refreshed = remote
            .as_ref()
            .clone()
            .with_blob_inventory(remote_inventory);
        assert_ne!(refreshed.wake_root(), pinned_root);
        let delta = pull(
            &local,
            remote,
            SigningKey::from_bytes(&[90; 32]).verifying_key(),
        )
        .await
        .unwrap();
        assert_eq!(delta.blob_handles, [[1; 32], [3; 32]]);
        assert!(delta.records.is_empty());
        assert!(delta.authorization_evidence.is_empty());
        assert!(!delta.more);
        assert!(delta.inventory_cursor.is_none());
        assert!(delta.inventory_cursor.is_none());
        assert!(!delta.retry_immediately());
        assert_eq!(delta.remote.resident_blobs.leaf_count(), 3);
        assert_eq!(delta.local.records, delta.remote.records);
        assert_eq!(
            delta.local.authorization_evidence,
            delta.remote.authorization_evidence
        );
        assert_eq!(
            snapshot.blobs().count(),
            store.snapshot().unwrap().blobs().count()
        );
        assert!(snapshot.wants().unwrap().next().is_none());
    }

    #[tokio::test]
    async fn inventory_cursor_enumerates_large_patch_without_local_residency_progress() {
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "large-resident-inventory",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap()
            .handle();
        let snapshot = store.snapshot().unwrap();
        let local = collection_repair_overlay(&snapshot, collection).unwrap();
        let handles = (0_u32..2048)
            .map(|index| *blake3::hash(&index.to_be_bytes()).as_bytes())
            .collect::<std::collections::BTreeSet<_>>();
        let remote = Arc::new(
            local
                .clone()
                .with_blob_inventory(inventory(handles.iter().copied())),
        );
        let reader = SigningKey::from_bytes(&[91; 32]).verifying_key();
        let mut cursor = None;
        let mut received = std::collections::BTreeSet::new();
        let mut sessions = 0;
        loop {
            let delta = pull_with_cursor(&local, remote.clone(), reader, cursor)
                .await
                .unwrap();
            sessions += 1;
            assert!(sessions < 64, "retained DFS frontier must reach every leaf");
            assert!(!delta.more);
            assert!(
                !delta.retry_immediately(),
                "hints alone must not create a hot loop"
            );
            assert!(delta.blob_handles.len() <= MAX_BLOB_INVENTORY_NODE_REQUESTS);
            for handle in delta.blob_handles {
                assert!(
                    received.insert(handle),
                    "a continued walk must not repeat hints"
                );
            }
            cursor = delta.inventory_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(sessions > 1);
        assert_eq!(received, handles);
        assert!(local.blob_inventory().is_empty());
        assert!(snapshot.wants().unwrap().next().is_none());
    }

    #[tokio::test]
    async fn changed_inventory_summary_reauthenticates_then_wraps_to_earlier_keys() {
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "changed-resident-inventory",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap()
            .handle();
        let local = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        let remote = Arc::new(local.clone().with_blob_inventory(inventory(
            (0_u32..512).map(|index| *blake3::hash(&index.to_be_bytes()).as_bytes()),
        )));
        let reader = SigningKey::from_bytes(&[92; 32]).verifying_key();
        let first = pull(&local, remote, reader).await.unwrap();
        assert!(first.inventory_cursor.is_some());
        let changed = Arc::new(local.clone().with_blob_inventory(inventory([[0; 32]])));
        let suffix = pull_with_cursor(&local, changed.clone(), reader, first.inventory_cursor)
            .await
            .unwrap();
        assert!(suffix.blob_handles.is_empty());
        assert!(
            suffix.inventory_cursor.is_some(),
            "a changed-root suffix must wrap"
        );
        let delta = pull_with_cursor(&local, changed, reader, suffix.inventory_cursor)
            .await
            .unwrap();
        assert_eq!(delta.blob_handles, [[0; 32]]);
        assert!(delta.inventory_cursor.is_none());
    }

    #[tokio::test]
    async fn inventory_cursor_reaches_late_original_handles_while_every_session_appends() {
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "growing-resident-inventory",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap()
            .handle();
        let local = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        let originals = (0_u32..2048)
            .map(|index| {
                let mut hash = *blake3::hash(&index.to_be_bytes()).as_bytes();
                hash[0] |= 128;
                hash
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut handles = originals.clone();
        let reader = SigningKey::from_bytes(&[96; 32]).verifying_key();
        let mut cursor = None;
        let mut received = std::collections::BTreeSet::new();
        let mut wrapped = false;
        for session in 0_u32..64 {
            // Every root differs. These new low keys must not send traversal
            // back to its beginning before it reaches old high handles.
            let mut added = [0; 32];
            added[28..].copy_from_slice(&session.to_be_bytes());
            assert!(handles.insert(added));
            let remote = Arc::new(
                local
                    .clone()
                    .with_blob_inventory(inventory(handles.iter().copied())),
            );
            let delta = pull_with_cursor(&local, remote, reader, cursor)
                .await
                .unwrap();
            assert!(!delta.more);
            assert!(!delta.retry_immediately());
            assert!(delta.blob_handles.len() <= MAX_BLOB_INVENTORY_NODE_REQUESTS);
            received.extend(delta.blob_handles);
            cursor = delta.inventory_cursor;
            if originals.is_subset(&received) {
                assert!(session > 0);
                wrapped = true;
                break;
            }
            assert!(cursor.is_some());
        }
        assert!(
            wrapped,
            "root churn must not starve the original late prefixes"
        );
        assert!(
            local.blob_inventory().is_empty(),
            "no hinted payload landed"
        );

        // Once the suffix ends, the continuation wraps and exposes additions
        // that were behind the watermark. No old proof is reused after a root change.
        let remote = Arc::new(
            local
                .clone()
                .with_blob_inventory(inventory(handles.iter().copied())),
        );
        for _ in 0..64 {
            let delta = pull_with_cursor(&local, remote.clone(), reader, cursor)
                .await
                .unwrap();
            received.extend(delta.blob_handles);
            cursor = delta.inventory_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(received, handles);
    }

    #[test]
    fn inventory_leaf_binds_exact_handle_and_requires_empty_value() {
        let patch = inventory([[94; 32]]);
        let component = CollectionRepairComponent::ResidentBlob;
        let summary = PatchSummary::from_patch(&patch);
        let request =
            PatchRepairRequest::new(component, summary, 32, vec![], summary.root().unwrap())
                .unwrap();
        let valid = patch_node_response(&patch, &[], &[], |_, ()| Ok(Vec::new())).unwrap();
        let collection = CollectionHandle::new([95; 32]);
        validate_response(
            &request,
            component,
            collection,
            &valid,
            validate_inventory_leaf_bytes,
        )
        .unwrap();
        for changed_key in [false, true] {
            let mut invalid = valid.clone();
            let PatchNodeResponse::Found(crate::patch_repair::PatchNode::Leaf { leaf, .. }) =
                &mut invalid
            else {
                panic!("one inventory entry is a leaf");
            };
            if changed_key {
                leaf.key[0] ^= 1;
            } else {
                leaf.value.push(1);
            }
            assert!(
                validate_response(
                    &request,
                    component,
                    collection,
                    &invalid,
                    validate_inventory_leaf_bytes
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn custom_capability_repairs_without_definition_blobs_but_never_admits_read() {
        for open_read in [false, true] {
            let root = SigningKey::from_bytes(&[80; 32]);
            let reader = SigningKey::from_bytes(&[81; 32]);
            let custom = triblespace_core::inline::Inline::new([82; 32]);
            let mut bindings = AdmissionPolicy::direct(root.verifying_key()).binding(custom);
            if open_read {
                bindings += AdmissionPolicy::Open.binding(read_capability());
            }
            let descriptor = entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                resource_policy*: bindings,
            };
            let mut store = MemoryRepo::default();
            store
                .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
                .unwrap();
            store
                .put::<SimpleArchive, _>(
                    entity! { capability_action: ACTION_WRITE }.facts().clone(),
                )
                .unwrap();
            let collection = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .unwrap();
            let before = store.snapshot().unwrap();
            let client = collection_repair_overlay(&before, collection).unwrap();
            let proof = CapabilityProof::new(
                CapabilityResource::from(collection),
                &root,
                custom,
                reader.verifying_key(),
            );
            store.insert_proof(proof.clone()).unwrap();
            let after = store.snapshot().unwrap();
            assert!(
                !after.contains_blob(custom).unwrap(),
                "AUTH must not need the capability definition blob"
            );
            let server = Arc::new(
                collection_repair_overlay(&after, collection)
                    .unwrap()
                    .with_blob_inventory(inventory([[87; 32], [88; 32]])),
            );
            assert_eq!(server.authorization_evidence().len(), 1);
            let (server_io, client_io) = tokio::io::duplex(1 << 20);
            let (mut server_recv, mut server_send) = tokio::io::split(server_io);
            let (mut client_recv, mut client_send) = tokio::io::split(client_io);
            let server_task = tokio::spawn(async move {
                assert_eq!(
                    recv_u8(&mut server_recv).await.unwrap(),
                    crate::collection_wire::OP_COLLECTION_REPAIR
                );
                let retained = serve_collection_repair(
                    &mut server_recv,
                    &mut server_send,
                    reader.verifying_key(),
                    |requested| (requested == collection).then_some(server),
                )
                .await
                .unwrap();
                assert!(retained.is_empty(), "custom evidence is not READ bootstrap");
            });
            let result = pull_collection_stream(
                &mut client_send,
                &mut client_recv,
                &client,
                vec![proof.clone()],
                None,
            )
            .await;
            if open_read {
                let delta = result.unwrap();
                assert_eq!(delta.authorization_evidence, [proof]);
                assert!(delta.records.is_empty());
                assert_eq!(delta.blob_handles, [[87; 32], [88; 32]]);
            } else {
                assert!(result.unwrap_err().to_string().contains("rejected READ(C)"));
                let mut remainder = Vec::new();
                client_recv.read_to_end(&mut remainder).await.unwrap();
                assert!(
                    remainder.is_empty(),
                    "no manifest, AUTH or blob inventory before READ admission"
                );
            }
            server_task.await.unwrap();
            assert_eq!(before.blobs().count(), after.blobs().count());
            assert!(after.wants().unwrap().next().is_none());
        }
    }

    #[tokio::test]
    async fn subordinate_proof_defers_until_its_resource_arrives_without_blocking_records() {
        use triblespace_core::capability::policy::resource_collection;

        let resource_root = SigningKey::from_bytes(&[97; 32]);
        let reader = SigningKey::from_bytes(&[98; 32]).verifying_key();
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let collection = server_store
            .collection("subordinate-repair", policy.clone())
            .unwrap();
        let mut client_store = MemoryRepo::default();
        let client_collection = client_store
            .collection("subordinate-repair", policy)
            .unwrap();
        assert_eq!(collection.handle(), client_collection.handle());
        let capability = triblespace_core::inline::Inline::new([99; 32]);
        let resource_facts = entity! {
            resource_collection: collection.handle(),
            resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key()).binding(capability),
        };
        let resource = server_store
            .put::<SimpleArchive, _>(resource_facts.facts().clone())
            .unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::from(resource),
            &resource_root,
            capability,
            reader,
        );
        server_store.insert_proof(proof.clone()).unwrap();
        server_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &resource_root,
                collection.handle(),
                CollectionData::new(resource.raw),
                empty_metadata_handle(),
            )))
            .unwrap();
        let remote = Arc::new(
            collection_repair_overlay(&server_store.snapshot().unwrap(), collection.handle())
                .unwrap(),
        );
        assert_eq!(remote.authorization_evidence().len(), 1);

        let before = client_store.snapshot().unwrap();
        let local = collection_repair_overlay(&before, collection.handle()).unwrap();
        let first = pull(&local, remote.clone(), reader).await.unwrap();
        assert!(first.authorization_evidence.is_empty());
        assert_eq!(
            first.records.len(),
            1,
            "missing R must not suppress independent C records"
        );
        assert!(first.more, "skipped AUTH is not a reconciled remote root");
        assert!(
            first.retry_immediately(),
            "new C records are useful progress"
        );
        let after_wire = client_store.snapshot().unwrap();
        assert_eq!(before.blobs().count(), after_wire.blobs().count());
        assert!(!after_wire.contains_blob(resource).unwrap());
        assert!(after_wire.wants().unwrap().next().is_none());
        for record in first.records {
            client_store.insert(record).unwrap();
        }

        let still_cold = client_store.snapshot().unwrap();
        let local = collection_repair_overlay(&still_cold, collection.handle()).unwrap();
        for _ in 0..3 {
            let deferred = pull(&local, remote.clone(), reader).await.unwrap();
            assert!(deferred.more, "AUTH remains explicitly incomplete");
            assert!(deferred.authorization_evidence.is_empty());
            assert!(deferred.records.is_empty());
            assert!(
                !deferred.retry_immediately(),
                "unchanged deferred evidence waits for periodic repair"
            );
        }
        assert_eq!(before.blobs().count(), still_cold.blobs().count());
        assert!(!still_cold.contains_blob(resource).unwrap());
        assert!(still_cold.wants().unwrap().next().is_none());

        // Stand in for the ordinary blob acquisition path, outside repair.
        assert_eq!(
            client_store
                .put::<SimpleArchive, _>(resource_facts.facts().clone())
                .unwrap(),
            resource
        );
        let resident = client_store.snapshot().unwrap();
        let local = collection_repair_overlay(&resident, collection.handle()).unwrap();
        assert!(
            local.authorization_evidence().is_empty(),
            "first incoming R proof is not cached locally"
        );
        let second = pull(&local, remote.clone(), reader).await.unwrap();
        assert_eq!(second.authorization_evidence, [proof.clone()]);
        assert!(second.records.is_empty());
        assert!(!second.more);
        client_store.insert_proof(proof.clone()).unwrap();

        let final_snapshot = client_store.snapshot().unwrap();
        assert!(
            !final_snapshot.contains_blob(capability).unwrap(),
            "repair does not acquire capability definitions"
        );
        assert!(final_snapshot.wants().unwrap().next().is_none());
        let local = collection_repair_overlay(&final_snapshot, collection.handle()).unwrap();
        assert_eq!(local.authorization_evidence().get(proof.id()), Some(&proof));
        assert_eq!(local.wake_root(), remote.wake_root());
        let final_delta = pull(&local, remote, reader).await.unwrap();
        assert!(final_delta.authorization_evidence.is_empty());
        assert!(final_delta.records.is_empty());
        assert!(!final_delta.more);
    }

    #[tokio::test]
    async fn many_absent_resource_descriptors_cannot_starve_collection_records() {
        use triblespace_core::capability::policy::resource_collection;
        use triblespace_core::id::Id;

        let root = SigningKey::from_bytes(&[100; 32]);
        let reader = SigningKey::from_bytes(&[101; 32]).verifying_key();
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let collection = server_store
            .collection("deferred-auth-budget", policy.clone())
            .unwrap();
        let mut client_store = MemoryRepo::default();
        assert_eq!(
            client_store
                .collection("deferred-auth-budget", policy)
                .unwrap()
                .handle(),
            collection.handle()
        );
        let capability = triblespace_core::inline::Inline::new([102; 32]);
        let mut resources = Vec::new();
        // Even the leaves alone exceed the complete stream's request budget.
        // None can be ingested until its immutable routing descriptor arrives.
        for index in 0..MAX_SERVER_REPAIR_COMMANDS {
            let tag = Id::new((index as u128 + 1).to_le_bytes()).unwrap();
            let facts = entity! {
                metadata::tag: tag,
                resource_collection: collection.handle(),
                resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(capability),
            };
            let resource = server_store
                .put::<SimpleArchive, _>(facts.facts().clone())
                .unwrap();
            server_store
                .insert_proof(CapabilityProof::new(
                    CapabilityResource::from(resource),
                    &root,
                    capability,
                    reader,
                ))
                .unwrap();
            resources.push(resource);
        }
        let commit = CollectionRecord::Commit(CollectionCommit::sign(
            &root,
            collection.handle(),
            CollectionData::new([103; 32]),
            empty_metadata_handle(),
        ));
        server_store.insert(commit).unwrap();
        let remote = Arc::new(
            collection_repair_overlay(&server_store.snapshot().unwrap(), collection.handle())
                .unwrap()
                .with_blob_inventory(inventory(
                    (0_u32..2048).map(|index| *blake3::hash(&index.to_be_bytes()).as_bytes()),
                )),
        );
        assert_eq!(
            remote.authorization_evidence().len(),
            MAX_SERVER_REPAIR_COMMANDS as u64
        );
        let before = client_store.snapshot().unwrap();
        let local = collection_repair_overlay(&before, collection.handle()).unwrap();
        let first = pull(&local, remote.clone(), reader).await.unwrap();
        assert_eq!(first.records, [commit], "AUTH reserves a C-record budget");
        assert!(first.authorization_evidence.is_empty());
        assert!(
            !first.blob_handles.is_empty(),
            "inventory has a separate reservation"
        );
        assert!(first.inventory_cursor.is_some());
        assert!(first.more);
        assert!(first.retry_immediately());
        client_store.insert(commit).unwrap();

        let after = client_store.snapshot().unwrap();
        let local = collection_repair_overlay(&after, collection.handle()).unwrap();
        for _ in 0..2 {
            let deferred = pull(&local, remote.clone(), reader).await.unwrap();
            assert!(deferred.more);
            assert!(deferred.records.is_empty());
            assert!(deferred.authorization_evidence.is_empty());
            assert!(!deferred.retry_immediately());
        }
        assert_eq!(before.blobs().count(), after.blobs().count());
        assert!(
            resources
                .into_iter()
                .all(|resource| !after.contains_blob(resource).unwrap())
        );
        assert!(after.wants().unwrap().next().is_none());
    }

    #[test]
    fn received_auth_leaf_rejects_wrong_resource_root_or_signature_even_with_valid_hash() {
        use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
        let root = SigningKey::from_bytes(&[83; 32]);
        let stranger = SigningKey::from_bytes(&[84; 32]);
        let reader = SigningKey::from_bytes(&[85; 32]);
        let custom = triblespace_core::inline::Inline::new([86; 32]);
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::Open.binding(read_capability())
                + AdmissionPolicy::direct(root.verifying_key()).binding(custom),
        };
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let local = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        let proof_for = |issuer: &SigningKey, capability, resource| {
            CapabilityProof::new(
                CapabilityResource::from(resource),
                issuer,
                capability,
                reader.verifying_key(),
            )
        };
        let mut bad_bytes = proof_for(&root, custom, collection).as_bytes().to_vec();
        *bad_bytes.last_mut().unwrap() ^= 1;
        let bad_signature = CapabilityProof::from_bytes(&bad_bytes).unwrap();
        let cases = [
            (true, proof_for(&root, custom, collection)),
            (true, proof_for(&root, write_capability(), collection)),
            (
                false,
                proof_for(&root, custom, CollectionHandle::new([87; 32])),
            ),
            (false, proof_for(&stranger, custom, collection)),
            (false, bad_signature),
        ];
        for (valid, proof) in cases {
            let mut patch = PATCH::<64, IdentitySchema, CapabilityProof, Blake3Merkle>::new();
            let mut key = [0; 64];
            key[..32].copy_from_slice(&collection.raw);
            key[32..].copy_from_slice(&proof.id().raw);
            patch.insert(&Entry::with_value(&key, proof));
            let node = patch.merkle_node(&collection.raw).unwrap();
            let summary = PatchSummary::new(Some(node.digest()), 1).unwrap();
            let request = PatchRepairRequest::new(
                CollectionRepairComponent::AuthorizationEvidence,
                summary,
                32,
                vec![],
                node.digest(),
            )
            .unwrap();
            let response = patch_node_response(&patch, &collection.raw, &[], |_, proof| {
                Ok(proof.as_bytes().to_vec())
            })
            .unwrap();
            let accepted = validate_response(
                &request,
                CollectionRepairComponent::AuthorizationEvidence,
                collection,
                &response,
                |key, bytes| {
                    validate_authorization_leaf_bytes(local.collection(), key, bytes)?;
                    local
                        .authorization_evidence()
                        .validate_proof(&CapabilityProof::from_bytes(bytes)?)?;
                    Ok(())
                },
            );
            assert_eq!(accepted.is_ok(), valid);
        }
    }

    #[tokio::test]
    async fn repair_disclosure_uses_read_alternatives_and_never_open_write() {
        for allowed in [false, true] {
            let root_a = SigningKey::from_bytes(&[20; 32]);
            let root_b = SigningKey::from_bytes(&[21; 32]);
            let reader = SigningKey::from_bytes(&[22; 32]);
            let alternatives = if allowed {
                AdmissionPolicy::direct(root_a.verifying_key()).binding(read_capability())
                    + AdmissionPolicy::direct(root_b.verifying_key()).binding(read_capability())
            } else {
                triblespace_core::trible::Fragment::empty()
            };
            let descriptor = entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                resource_policy*: alternatives + AdmissionPolicy::Open.binding(write_capability()),
            };
            let mut store = MemoryRepo::default();
            store
                .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
                .unwrap();
            store
                .put::<SimpleArchive, _>(
                    entity! { capability_action: ACTION_WRITE }.facts().clone(),
                )
                .unwrap();
            let collection = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .unwrap();
            let proof = CapabilityProof::new(
                CapabilityResource::from(collection),
                &root_b,
                triblespace_core::collection::read_capability(),
                reader.verifying_key(),
            );
            store.insert_proof(proof).unwrap();
            let client = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
            store
                .insert(CollectionRecord::Commit(CollectionCommit::sign(
                    &root_a,
                    collection,
                    CollectionData::new([23; 32]),
                    empty_metadata_handle(),
                )))
                .unwrap();
            let server = Arc::new(
                collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap(),
            );
            let (server_io, client_io) = tokio::io::duplex(1 << 20);
            let (mut server_recv, mut server_send) = tokio::io::split(server_io);
            let (mut client_recv, mut client_send) = tokio::io::split(client_io);
            let server_task = tokio::spawn(async move {
                assert_eq!(
                    recv_u8(&mut server_recv).await.unwrap(),
                    crate::collection_wire::OP_COLLECTION_REPAIR
                );
                let bootstrap = serve_collection_repair(
                    &mut server_recv,
                    &mut server_send,
                    reader.verifying_key(),
                    |collection| (collection == server.collection()).then_some(server),
                )
                .await
                .unwrap();
                assert!(bootstrap.is_empty());
            });
            let result =
                pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![], None)
                    .await;
            if allowed {
                assert_eq!(result.unwrap().records.len(), 1);
            } else {
                assert!(result.unwrap_err().to_string().contains("rejected READ(C)"));
                let mut remaining = Vec::new();
                client_recv.read_to_end(&mut remaining).await.unwrap();
                assert!(
                    remaining.is_empty(),
                    "denial must not disclose a manifest or records"
                );
            }
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn one_stream_repairs_records_without_global_inventory() {
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let server_collection = server_store.collection("shared", policy.clone()).unwrap();
        server_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &SigningKey::from_bytes(&[7; 32]),
                server_collection.handle(),
                CollectionData::new([9; 32]),
                empty_metadata_handle(),
            )))
            .unwrap();
        let server_snapshot = server_store.snapshot().unwrap();
        let server = Arc::new(
            collection_repair_overlay(&server_snapshot, server_collection.handle()).unwrap(),
        );
        let mut client_store = MemoryRepo::default();
        let client_collection = client_store.collection("shared", policy).unwrap();
        assert_eq!(client_collection.handle(), server_collection.handle());
        let client_snapshot = client_store.snapshot().unwrap();
        let client =
            collection_repair_overlay(&client_snapshot, client_collection.handle()).unwrap();
        let expected_remote = manifest(&server);
        let expected_local = manifest(&client);
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let (mut server_recv, mut server_send) = tokio::io::split(server_io);
        let (mut client_recv, mut client_send) = tokio::io::split(client_io);
        let server_task = tokio::spawn(async move {
            assert_eq!(
                recv_u8(&mut server_recv).await.unwrap(),
                crate::collection_wire::OP_COLLECTION_REPAIR
            );
            let bootstrap = serve_collection_repair(
                &mut server_recv,
                &mut server_send,
                SigningKey::from_bytes(&[8; 32]).verifying_key(),
                |collection| (collection == server.collection()).then_some(server),
            )
            .await
            .unwrap();
            assert!(bootstrap.is_empty());
        });

        let delta =
            pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![], None)
                .await
                .unwrap();
        assert_eq!(delta.records.len(), 1);
        assert!(delta.authorization_evidence.is_empty());
        assert_eq!(delta.local, expected_local);
        assert_eq!(delta.remote, expected_remote);
        assert_ne!(delta.local, delta.remote);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_local_read_evidence_admits_and_repairs_only_native_proof_bytes() {
        let root = SigningKey::from_bytes(&[10; 32]);
        let reader = SigningKey::from_bytes(&[11; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::Open,
        );
        let mut server_store = MemoryRepo::default();
        let server_collection = server_store.collection("private", policy.clone()).unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::from(server_collection.handle()),
            &root,
            triblespace_core::collection::read_capability(),
            reader.verifying_key(),
        );
        server_store.insert_proof(proof.clone()).unwrap();
        let server_snapshot = server_store.snapshot().unwrap();
        let server = Arc::new(
            collection_repair_overlay(&server_snapshot, server_collection.handle()).unwrap(),
        );

        let mut client_store = MemoryRepo::default();
        let client_collection = client_store.collection("private", policy).unwrap();
        let client_snapshot = client_store.snapshot().unwrap();
        let client =
            collection_repair_overlay(&client_snapshot, client_collection.handle()).unwrap();
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let (mut server_recv, mut server_send) = tokio::io::split(server_io);
        let (mut client_recv, mut client_send) = tokio::io::split(client_io);
        let server_task = tokio::spawn(async move {
            assert_eq!(
                recv_u8(&mut server_recv).await.unwrap(),
                crate::collection_wire::OP_COLLECTION_REPAIR
            );
            let bootstrap = serve_collection_repair(
                &mut server_recv,
                &mut server_send,
                reader.verifying_key(),
                |collection| (collection == server.collection()).then_some(server),
            )
            .await
            .unwrap();
            assert!(bootstrap.is_empty());
        });

        let delta =
            pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![], None)
                .await
                .unwrap();
        assert_eq!(delta.authorization_evidence, [proof]);
        assert!(delta.records.is_empty());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn cold_native_read_proof_is_returned_for_ingest_and_current_session_is_rejected() {
        let root = SigningKey::from_bytes(&[12; 32]);
        let reader = SigningKey::from_bytes(&[13; 32]);
        let other_reader = SigningKey::from_bytes(&[14; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::Open,
        );
        let mut server_store = MemoryRepo::default();
        let server_collection = server_store.collection("cold", policy.clone()).unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::from(server_collection.handle()),
            &root,
            triblespace_core::collection::read_capability(),
            reader.verifying_key(),
        );
        let other_proof = CapabilityProof::new(
            CapabilityResource::from(server_collection.handle()),
            &root,
            triblespace_core::collection::read_capability(),
            other_reader.verifying_key(),
        );
        let server_snapshot = server_store.snapshot().unwrap();
        let server = Arc::new(
            collection_repair_overlay(&server_snapshot, server_collection.handle()).unwrap(),
        );
        let mut client_store = MemoryRepo::default();
        let client_collection = client_store.collection("cold", policy).unwrap();
        let client_snapshot = client_store.snapshot().unwrap();
        let client =
            collection_repair_overlay(&client_snapshot, client_collection.handle()).unwrap();
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let (mut server_recv, mut server_send) = tokio::io::split(server_io);
        let (mut client_recv, mut client_send) = tokio::io::split(client_io);
        let server_task = tokio::spawn(async move {
            assert_eq!(
                recv_u8(&mut server_recv).await.unwrap(),
                crate::collection_wire::OP_COLLECTION_REPAIR
            );
            serve_collection_repair(
                &mut server_recv,
                &mut server_send,
                reader.verifying_key(),
                |collection| (collection == server.collection()).then_some(server),
            )
            .await
            .unwrap()
        });

        let error = pull_collection_stream(
            &mut client_send,
            &mut client_recv,
            &client,
            vec![proof.clone(), other_proof],
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("rejected READ(C)"));
        assert_eq!(server_task.await.unwrap(), [proof]);
    }
}
