//! READ-authorized, stream-pinned repair of one collection overlay.

use std::sync::Arc;

use anyhow::{Result, bail};
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::{CollectionHandle, CollectionRecord};

use crate::collection_activation::CollectionRepairOverlay;
use crate::collection_delta::{decode_record, encode_record};
use crate::collection_wire::{
    CollectionRepairAdmission, CollectionRepairCommand, CollectionRepairComponent,
    CollectionRepairManifest, recv_repair_admission, recv_repair_collection, recv_repair_command,
    recv_repair_hello, recv_repair_node_response, send_repair_admission, send_repair_bootstrap,
    send_repair_done, send_repair_node_request, send_repair_node_response,
};
use crate::patch_repair::{
    PatchNodeResponse, PatchRepairRequest, PatchRepairWalker, PatchSummary, patch_node_response,
    validate_patch_node,
};
use crate::transport::Conn;

/// Evidence missing from the caller's immutable local observation.
#[derive(Clone, Debug)]
pub(crate) struct CollectionRepairDelta {
    pub(crate) compared_at: crate::clock::Mono,
    pub(crate) local: CollectionRepairManifest,
    pub(crate) remote: CollectionRepairManifest,
    pub(crate) records: Vec<CollectionRecord>,
    pub(crate) authorization_evidence: Vec<CapabilityProof>,
    pub(crate) more: bool,
}

const MAX_REPAIR_RECORD_ITEMS: usize = 4_096;
const MAX_REPAIR_AUTHORIZATION_EVIDENCE_ITEMS: usize = 16;
const MAX_REPAIR_NODE_REQUESTS: usize = 16_384;
const MAX_SERVER_REPAIR_COMMANDS: usize = 512;
const MAX_SERVER_NODE_RESPONSE_BYTES: usize = 64 << 20;

/// Serve the body of one collection-repair operation after its operation byte
/// has already been consumed.
///
/// `lookup` must return an immutable overlay. Its lifetime is the stream's
/// snapshot lease: every manifest and node response comes from the exact same
/// semantic PATCH roots, so no historical-root cache is needed. Returned
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
        .filter(|proof| proof.leaf_key() == remote && evidence.validate_read_proof(proof).is_ok())
        .collect::<Vec<_>>();
    let read_evidence = overlay
        .authorization_evidence()
        .proofs()
        .cloned()
        .collect::<Vec<_>>();
    let admitted =
        evidence.reader_is_admitted_by_at(remote, &read_evidence, crate::clock::epoch_now());
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
    }
}

/// Pull one exact collection overlay over an already authenticated iroh
/// connection. TLS binds `conn.remote_id()`; the supplied native proof forest
/// can bootstrap a cold server, while same-session READ(C) comes only from its
/// already pinned local evidence.
pub(crate) async fn pull_collection<C: Conn>(
    conn: &C,
    local: &CollectionRepairOverlay,
    read_bootstrap: Vec<CapabilityProof>,
) -> Result<CollectionRepairDelta> {
    let (mut send, mut recv) = conn.open_bi().await?;
    pull_collection_stream(&mut send, &mut recv, local, read_bootstrap).await
}

async fn pull_collection_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    local: &CollectionRepairOverlay,
    read_bootstrap: Vec<CapabilityProof>,
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
        CollectionRepairAdmission::Rejected => bail!("remote rejected READ(C) evidence"),
        CollectionRepairAdmission::Unavailable => {
            bail!("remote does not retain the requested collection")
        }
    };
    // A long repair must not make its older pinned manifest appear fresh at
    // completion. This is the observation instant, not the completion instant.
    let compared_at = crate::clock::mono_now();

    let mut remaining_requests = MAX_SERVER_REPAIR_COMMANDS - 1;
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
    send_repair_done(send).await?;
    send.shutdown().await?;
    require_eof(recv).await?;
    Ok(CollectionRepairDelta {
        compared_at,
        local: manifest(local),
        remote,
        records,
        authorization_evidence,
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
            || *response_bytes >= MAX_SERVER_NODE_RESPONSE_BYTES
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
    loop {
        if requests >= MAX_REPAIR_NODE_REQUESTS
            || *remaining_requests == 0
            || *response_bytes >= MAX_SERVER_NODE_RESPONSE_BYTES
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
            |key, bytes| validate_authorization_leaf(local, key, bytes),
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
            missing.push(CapabilityProof::from_bytes(&leaf.value)?);
        }
    }
    if complete {
        walker.finish()?;
    }
    Ok((missing, !complete))
}

fn validate_authorization_leaf(
    local: &CollectionRepairOverlay,
    key: &[u8],
    bytes: &[u8],
) -> Result<()> {
    let proof = CapabilityProof::from_bytes(bytes)?;
    if key.len() != 64 || key[..32] != local.collection().raw || proof.id().raw != key[32..] {
        bail!("authorization proof body does not match its scoped PATCH leaf key");
    }
    local.authorization_evidence().validate_proof(&proof)?;
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
                CollectionRepairComponent::Record => &[],
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
mod tests {
    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::capability::{Capability, CapabilityMode, CapabilityResource};
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy, CollectionRecord,
        CollectionStore, CollectionStoreExt, KIND_COLLECTION_DESCRIPTOR, empty_metadata_handle,
        read_capability, write_capability,
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
            let collection = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .unwrap();
            let before = store.snapshot().unwrap();
            let client = collection_repair_overlay(&before, collection).unwrap();
            let proof = CapabilityProof::issue_root(
                &root,
                CapabilityResource::from(collection),
                Capability::new(custom, CapabilityMode::Invoke),
                None,
                reader.verifying_key(),
            );
            store.insert_proof(proof.clone()).unwrap();
            let after = store.snapshot().unwrap();
            assert!(
                !after.contains_blob(custom).unwrap(),
                "AUTH must not need the capability definition blob"
            );
            let server = Arc::new(collection_repair_overlay(&after, collection).unwrap());
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
            )
            .await;
            if open_read {
                let delta = result.unwrap();
                assert_eq!(delta.authorization_evidence, [proof]);
                assert!(delta.records.is_empty());
            } else {
                assert!(result.unwrap_err().to_string().contains("rejected READ(C)"));
                let mut remainder = Vec::new();
                client_recv.read_to_end(&mut remainder).await.unwrap();
                assert!(
                    remainder.is_empty(),
                    "no generic AUTH inventory before READ admission"
                );
            }
            server_task.await.unwrap();
            assert_eq!(before.blobs().count(), after.blobs().count());
            assert!(after.wants().unwrap().next().is_none());
        }
    }

    #[test]
    fn received_auth_leaf_rejects_wrong_resource_capability_or_root_even_with_valid_hash() {
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
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let local = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        let proof_for = |issuer: &SigningKey, capability, resource| {
            CapabilityProof::issue_root(
                issuer,
                CapabilityResource::from(resource),
                Capability::new(capability, CapabilityMode::Invoke),
                None,
                reader.verifying_key(),
            )
        };
        let cases = [
            (true, proof_for(&root, custom, collection)),
            (false, proof_for(&root, write_capability(), collection)),
            (
                false,
                proof_for(&root, custom, CollectionHandle::new([87; 32])),
            ),
            (false, proof_for(&stranger, custom, collection)),
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
                |key, bytes| validate_authorization_leaf(&local, key, bytes),
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
            let collection = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .unwrap();
            let proof = CapabilityProof::issue_root(
                &root_b,
                CapabilityResource::from(collection),
                Capability::new(
                    triblespace_core::collection::read_capability(),
                    CapabilityMode::Invoke,
                ),
                None,
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
                pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![]).await;
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

        let delta = pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![])
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
        let proof = CapabilityProof::issue_root(
            &root,
            CapabilityResource::from(server_collection.handle()),
            Capability::new(
                triblespace_core::collection::read_capability(),
                CapabilityMode::Invoke,
            ),
            None,
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

        let delta = pull_collection_stream(&mut client_send, &mut client_recv, &client, vec![])
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
        let proof = CapabilityProof::issue_root(
            &root,
            CapabilityResource::from(server_collection.handle()),
            Capability::new(
                triblespace_core::collection::read_capability(),
                CapabilityMode::Invoke,
            ),
            None,
            reader.verifying_key(),
        );
        let other_proof = CapabilityProof::issue_root(
            &root,
            CapabilityResource::from(server_collection.handle()),
            Capability::new(
                triblespace_core::collection::read_capability(),
                CapabilityMode::Invoke,
            ),
            None,
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
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("rejected READ(C)"));
        assert_eq!(server_task.await.unwrap(), [proof]);
    }
}
