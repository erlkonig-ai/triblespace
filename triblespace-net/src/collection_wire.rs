//! Dense wire frames for one READ-authorized collection repair session.
//!
//! One bidirectional stream pins one [`CollectionRepairManifest`]. The client
//! may send bounded native READ(C) bootstrap proofs before admission, then an
//! admitted client walks the record and authorization-evidence PATCHes
//! interactively beneath those exact roots. Blob acquisition is a separate
//! bearer-addressed protocol and never participates in collection repair.

use anyhow::{Result, anyhow, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use triblespace_core::capability::{CapabilityProof, MAX_CAPABILITY_PROOF_BYTES};
use triblespace_core::collection::CollectionHandle;

use crate::patch_repair::{
    PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchNodeResponse, PatchRepairRequest,
    PatchSummary,
};
use crate::protocol::{
    recv_hash, recv_u8, recv_u32_be, recv_u64_be, send_hash, send_u8, send_u32_be, send_u64_be,
};

/// Direct-RPC operation which opens one collection repair session.
///
/// `0x0D` was a pre-v17 provider-cover operation. The ALPN generation change
/// deliberately frees the byte for this clean-slate meaning.
pub(crate) const OP_COLLECTION_REPAIR: u8 = 0x0D;

/// Maximum native READ proof branches accepted at one session boundary.
pub(crate) const MAX_COLLECTION_READ_BOOTSTRAP_PROOFS: usize = 16;
/// Aggregate bound across the length-prefixed READ proof frames.
pub(crate) const MAX_COLLECTION_READ_BOOTSTRAP_BYTES: usize =
    MAX_COLLECTION_READ_BOOTSTRAP_PROOFS * MAX_CAPABILITY_PROOF_BYTES;
/// Largest value transported by one authenticated PATCH leaf.
pub(crate) const MAX_COLLECTION_LEAF_BYTES: usize = MAX_CAPABILITY_PROOF_BYTES;

const REPAIR_ADMITTED: u8 = 0x00;
const REPAIR_REJECTED: u8 = 0x01;
const REPAIR_UNAVAILABLE: u8 = 0x02;

const REQUEST_NODE: u8 = 0x01;
const REQUEST_DONE: u8 = 0xFF;

const NODE_FOUND: u8 = 0x00;
const NODE_PREFIX_ABSENT: u8 = 0x01;
const NODE_LEAF: u8 = 0x00;
const NODE_BRANCH: u8 = 0x01;

/// One of the two grow-only PATCHes in collection repair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CollectionRepairComponent {
    Record,
    AuthorizationEvidence,
}

impl CollectionRepairComponent {
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Record => 32,
            Self::AuthorizationEvidence => 32,
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Record => 0,
            Self::AuthorizationEvidence => 1,
        }
    }

    fn from_wire(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(Self::Record),
            1 => Ok(Self::AuthorizationEvidence),
            other => bail!("unknown collection repair component {other:#x}"),
        }
    }
}

/// Client bootstrap material sent before the server decides READ(C).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectionRepairHello {
    pub(crate) bootstrap_proofs: Vec<CapabilityProof>,
}

/// Exact repair state pinned for one accepted stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CollectionRepairManifest {
    pub(crate) wake_root: [u8; 32],
    pub(crate) records: PatchSummary,
    pub(crate) authorization_evidence: PatchSummary,
}

impl CollectionRepairManifest {
    pub(crate) const fn component(self, component: CollectionRepairComponent) -> PatchSummary {
        match component {
            CollectionRepairComponent::Record => self.records,
            CollectionRepairComponent::AuthorizationEvidence => self.authorization_evidence,
        }
    }
}

/// Server decision at the READ(C) boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionRepairAdmission {
    Admitted(CollectionRepairManifest),
    Rejected,
    Unavailable,
}

/// One client command after admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CollectionRepairCommand {
    Node {
        component: CollectionRepairComponent,
        prefix: Vec<u8>,
        expected_digest: [u8; 32],
    },
    Done,
}

pub(crate) async fn send_repair_bootstrap<W: AsyncWrite + Unpin>(
    send: &mut W,
    bootstrap_proofs: &[CapabilityProof],
) -> Result<()> {
    if bootstrap_proofs.len() > MAX_COLLECTION_READ_BOOTSTRAP_PROOFS {
        bail!(
            "collection READ proof forest has {} proofs; limit is {}",
            bootstrap_proofs.len(),
            MAX_COLLECTION_READ_BOOTSTRAP_PROOFS
        );
    }
    send_u32_be(
        send,
        u32::try_from(bootstrap_proofs.len()).expect("proof count bound fits u32"),
    )
    .await?;
    let mut aggregate = 0usize;
    for proof in bootstrap_proofs {
        let length = proof.as_bytes().len();
        aggregate = aggregate
            .checked_add(length)
            .ok_or_else(|| anyhow!("collection READ bootstrap length overflow"))?;
        if aggregate > MAX_COLLECTION_READ_BOOTSTRAP_BYTES {
            bail!(
                "collection READ bootstrap is {aggregate} bytes; limit is {MAX_COLLECTION_READ_BOOTSTRAP_BYTES}"
            );
        }
        send_u32_be(
            send,
            u32::try_from(length).expect("native proof bound fits u32"),
        )
        .await?;
        send.write_all(proof.as_bytes())
            .await
            .map_err(|error| anyhow!("send collection READ proof: {error}"))?;
    }
    Ok(())
}

/// Decode the body after the caller has already consumed
/// [`OP_COLLECTION_REPAIR`].
pub(crate) async fn recv_repair_hello<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<CollectionRepairHello> {
    Ok(CollectionRepairHello {
        bootstrap_proofs: recv_repair_bootstrap(recv).await?,
    })
}

pub(crate) async fn recv_repair_collection<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<CollectionHandle> {
    Ok(CollectionHandle::new(recv_hash(recv).await?))
}

pub(crate) async fn recv_repair_bootstrap<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Vec<CapabilityProof>> {
    let count = recv_u32_be(recv).await? as usize;
    if count > MAX_COLLECTION_READ_BOOTSTRAP_PROOFS {
        bail!(
            "collection READ bootstrap has {count} proofs; limit is {MAX_COLLECTION_READ_BOOTSTRAP_PROOFS}"
        );
    }
    let mut bootstrap_proofs = Vec::new();
    bootstrap_proofs
        .try_reserve_exact(count)
        .map_err(|error| anyhow!("cannot allocate collection READ proof forest: {error}"))?;
    let mut aggregate = 0usize;
    for _ in 0..count {
        let length = recv_u32_be(recv).await? as usize;
        if length > MAX_CAPABILITY_PROOF_BYTES {
            bail!("collection READ proof is {length} bytes; limit is {MAX_CAPABILITY_PROOF_BYTES}");
        }
        aggregate = aggregate
            .checked_add(length)
            .ok_or_else(|| anyhow!("collection READ bootstrap length overflow"))?;
        if aggregate > MAX_COLLECTION_READ_BOOTSTRAP_BYTES {
            bail!(
                "collection READ bootstrap is {aggregate} bytes; limit is {MAX_COLLECTION_READ_BOOTSTRAP_BYTES}"
            );
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|error| anyhow!("cannot allocate collection READ proof: {error}"))?;
        bytes.resize(length, 0);
        recv.read_exact(&mut bytes)
            .await
            .map_err(|error| anyhow!("receive collection READ proof: {error}"))?;
        bootstrap_proofs.push(CapabilityProof::from_bytes(&bytes)?);
    }
    Ok(bootstrap_proofs)
}

pub(crate) async fn send_repair_admission<W: AsyncWrite + Unpin>(
    send: &mut W,
    admission: CollectionRepairAdmission,
) -> Result<()> {
    match admission {
        CollectionRepairAdmission::Admitted(manifest) => {
            send_u8(send, REPAIR_ADMITTED).await?;
            send_hash(send, &manifest.wake_root).await?;
            send_summary(send, manifest.records).await?;
            send_summary(send, manifest.authorization_evidence).await?;
        }
        CollectionRepairAdmission::Rejected => send_u8(send, REPAIR_REJECTED).await?,
        CollectionRepairAdmission::Unavailable => send_u8(send, REPAIR_UNAVAILABLE).await?,
    }
    Ok(())
}

pub(crate) async fn recv_repair_admission<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<CollectionRepairAdmission> {
    Ok(match recv_u8(recv).await? {
        REPAIR_ADMITTED => CollectionRepairAdmission::Admitted(CollectionRepairManifest {
            wake_root: recv_hash(recv).await?,
            records: recv_summary(recv).await?,
            authorization_evidence: recv_summary(recv).await?,
        }),
        REPAIR_REJECTED => CollectionRepairAdmission::Rejected,
        REPAIR_UNAVAILABLE => CollectionRepairAdmission::Unavailable,
        other => bail!("unknown collection repair admission {other:#x}"),
    })
}

async fn send_summary<W: AsyncWrite + Unpin>(send: &mut W, summary: PatchSummary) -> Result<()> {
    match summary.root() {
        Some(root) => {
            send_u8(send, 1).await?;
            send_hash(send, &root).await?;
        }
        None => {
            send_u8(send, 0).await?;
            send_hash(send, &[0; 32]).await?;
        }
    }
    send_u64_be(send, summary.leaf_count()).await
}

async fn recv_summary<R: AsyncRead + Unpin>(recv: &mut R) -> Result<PatchSummary> {
    let present = recv_u8(recv).await?;
    let raw = recv_hash(recv).await?;
    let count = recv_u64_be(recv).await?;
    let root = match present {
        0 => {
            if raw != [0; 32] {
                bail!("empty PATCH summary carries a nonzero root field");
            }
            None
        }
        1 => Some(raw),
        other => bail!("invalid PATCH summary root tag {other:#x}"),
    };
    PatchSummary::new(root, count)
}

pub(crate) async fn send_repair_node_request<W: AsyncWrite + Unpin, S>(
    send: &mut W,
    request: &PatchRepairRequest<S>,
    component: CollectionRepairComponent,
) -> Result<()> {
    if request.prefix().len() > component.key_len() {
        bail!("collection PATCH request prefix exceeds component key length");
    }
    send_u8(send, REQUEST_NODE).await?;
    send_u8(send, component.wire()).await?;
    send_u8(
        send,
        u8::try_from(request.prefix().len()).expect("collection PATCH keys fit u8"),
    )
    .await?;
    send.write_all(request.prefix())
        .await
        .map_err(|error| anyhow!("send collection PATCH prefix: {error}"))?;
    send_hash(send, &request.expected_digest()).await
}

pub(crate) async fn send_repair_done<W: AsyncWrite + Unpin>(send: &mut W) -> Result<()> {
    send_u8(send, REQUEST_DONE).await
}

pub(crate) async fn recv_repair_command<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<CollectionRepairCommand> {
    match recv_u8(recv).await? {
        REQUEST_DONE => Ok(CollectionRepairCommand::Done),
        REQUEST_NODE => {
            let component = CollectionRepairComponent::from_wire(recv_u8(recv).await?)?;
            let prefix_len = recv_u8(recv).await? as usize;
            if prefix_len > component.key_len() {
                bail!("collection PATCH request prefix exceeds component key length");
            }
            let mut prefix = vec![0; prefix_len];
            recv.read_exact(&mut prefix)
                .await
                .map_err(|error| anyhow!("receive collection PATCH prefix: {error}"))?;
            let expected_digest = recv_hash(recv).await?;
            Ok(CollectionRepairCommand::Node {
                component,
                prefix,
                expected_digest,
            })
        }
        other => bail!("unknown collection repair command {other:#x}"),
    }
}

pub(crate) async fn send_repair_node_response<W: AsyncWrite + Unpin>(
    send: &mut W,
    response: &PatchNodeResponse<Vec<u8>>,
    component: CollectionRepairComponent,
) -> Result<()> {
    match response {
        PatchNodeResponse::SnapshotUnavailable => {
            bail!("a stream-pinned collection snapshot became unavailable")
        }
        PatchNodeResponse::PrefixAbsent => send_u8(send, NODE_PREFIX_ABSENT).await?,
        PatchNodeResponse::Found(node) => {
            send_u8(send, NODE_FOUND).await?;
            match node {
                PatchNode::Leaf { digest, leaf } => {
                    if leaf.key.len() != component.key_len() {
                        bail!("collection PATCH leaf key has the wrong length");
                    }
                    if leaf.value.len() > MAX_COLLECTION_LEAF_BYTES {
                        bail!(
                            "collection PATCH leaf is {} bytes; limit is {MAX_COLLECTION_LEAF_BYTES}",
                            leaf.value.len()
                        );
                    }
                    send_u8(send, NODE_LEAF).await?;
                    send_hash(send, digest).await?;
                    send.write_all(&leaf.key)
                        .await
                        .map_err(|error| anyhow!("send collection PATCH leaf key: {error}"))?;
                    send_u32_be(
                        send,
                        u32::try_from(leaf.value.len())
                            .expect("collection leaf byte bound fits u32"),
                    )
                    .await?;
                    send.write_all(&leaf.value)
                        .await
                        .map_err(|error| anyhow!("send collection PATCH leaf value: {error}"))?;
                }
                PatchNode::Branch {
                    digest,
                    leaf_count,
                    branch,
                } => {
                    if branch.representative.len() != component.key_len() {
                        bail!("collection PATCH branch representative has the wrong length");
                    }
                    if !(2..=256).contains(&branch.children.len()) {
                        bail!("collection PATCH branch fanout is not canonical");
                    }
                    send_u8(send, NODE_BRANCH).await?;
                    send_hash(send, digest).await?;
                    send_u64_be(send, *leaf_count).await?;
                    send.write_all(&branch.representative)
                        .await
                        .map_err(|error| {
                            anyhow!("send collection PATCH branch representative: {error}")
                        })?;
                    send_u8(send, branch.end_depth).await?;
                    send_u32_be(
                        send,
                        u32::try_from(branch.children.len())
                            .expect("canonical PATCH fanout fits u32"),
                    )
                    .await?;
                    for child in &branch.children {
                        send_u8(send, child.edge).await?;
                        send_hash(send, &child.digest).await?;
                        send_u64_be(send, child.leaf_count).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn recv_repair_node_response<R: AsyncRead + Unpin>(
    recv: &mut R,
    component: CollectionRepairComponent,
) -> Result<PatchNodeResponse<Vec<u8>>> {
    match recv_u8(recv).await? {
        NODE_PREFIX_ABSENT => Ok(PatchNodeResponse::PrefixAbsent),
        NODE_FOUND => {
            let kind = recv_u8(recv).await?;
            let digest = recv_hash(recv).await?;
            match kind {
                NODE_LEAF => {
                    let mut key = vec![0; component.key_len()];
                    recv.read_exact(&mut key)
                        .await
                        .map_err(|error| anyhow!("receive collection PATCH leaf key: {error}"))?;
                    let length = recv_u32_be(recv).await? as usize;
                    if length > MAX_COLLECTION_LEAF_BYTES {
                        bail!(
                            "collection PATCH leaf is {length} bytes; limit is {MAX_COLLECTION_LEAF_BYTES}"
                        );
                    }
                    let mut value = Vec::new();
                    value.try_reserve_exact(length).map_err(|error| {
                        anyhow!("cannot allocate collection PATCH leaf: {error}")
                    })?;
                    value.resize(length, 0);
                    recv.read_exact(&mut value)
                        .await
                        .map_err(|error| anyhow!("receive collection PATCH leaf value: {error}"))?;
                    Ok(PatchNodeResponse::Found(PatchNode::Leaf {
                        digest,
                        leaf: PatchLeaf { key, value },
                    }))
                }
                NODE_BRANCH => {
                    let leaf_count = recv_u64_be(recv).await?;
                    let mut representative = vec![0; component.key_len()];
                    recv.read_exact(&mut representative)
                        .await
                        .map_err(|error| {
                            anyhow!("receive collection PATCH branch representative: {error}")
                        })?;
                    let end_depth = recv_u8(recv).await?;
                    let child_count = recv_u32_be(recv).await? as usize;
                    if !(2..=256).contains(&child_count) {
                        bail!("collection PATCH branch fanout is {child_count}");
                    }
                    let mut children = Vec::with_capacity(child_count);
                    for _ in 0..child_count {
                        children.push(PatchChild {
                            edge: recv_u8(recv).await?,
                            digest: recv_hash(recv).await?,
                            leaf_count: recv_u64_be(recv).await?,
                        });
                    }
                    Ok(PatchNodeResponse::Found(PatchNode::Branch {
                        digest,
                        leaf_count,
                        branch: PatchBranch {
                            representative,
                            end_depth,
                            children,
                        },
                    }))
                }
                other => bail!("unknown collection PATCH node kind {other:#x}"),
            }
        }
        other => bail!("unknown collection PATCH response {other:#x}"),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use triblespace_core::capability::CapabilityResource;

    use super::*;

    fn proof() -> CapabilityProof {
        CapabilityProof::new(
            CapabilityResource::new([2; 32]),
            &SigningKey::from_bytes(&[1; 32]),
            triblespace_core::collection::read_capability(),
            SigningKey::from_bytes(&[3; 32]).verifying_key(),
        )
    }

    #[tokio::test]
    async fn hello_and_manifest_roundtrip_without_ending_the_stream() {
        let (mut left, mut right) = tokio::io::duplex(1 << 20);
        let hello = CollectionRepairHello {
            bootstrap_proofs: vec![proof()],
        };
        let collection = CollectionHandle::new([2; 32]);
        let manifest = CollectionRepairManifest {
            wake_root: [4; 32],
            records: PatchSummary::new(Some([5; 32]), 7).unwrap(),
            authorization_evidence: PatchSummary::new(None, 0).unwrap(),
        };
        let sent_hello = hello.clone();
        let writer = tokio::spawn(async move {
            send_u8(&mut left, OP_COLLECTION_REPAIR).await.unwrap();
            send_hash(&mut left, &collection.raw).await.unwrap();
            send_repair_bootstrap(&mut left, &sent_hello.bootstrap_proofs)
                .await
                .unwrap();
            assert_eq!(recv_u8(&mut left).await.unwrap(), 0xA5);
            send_repair_admission(&mut left, CollectionRepairAdmission::Admitted(manifest))
                .await
                .unwrap();
        });

        assert_eq!(recv_u8(&mut right).await.unwrap(), OP_COLLECTION_REPAIR);
        assert_eq!(
            recv_repair_collection(&mut right).await.unwrap(),
            collection
        );
        assert_eq!(recv_repair_hello(&mut right).await.unwrap(), hello);
        send_u8(&mut right, 0xA5).await.unwrap();
        assert_eq!(
            recv_repair_admission(&mut right).await.unwrap(),
            CollectionRepairAdmission::Admitted(manifest)
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_native_bootstrap_proof_is_rejected_before_body_read() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&1_u32.to_be_bytes());
        frame.extend_from_slice(
            &u32::try_from(MAX_CAPABILITY_PROOF_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        let mut input = frame.as_slice();
        let error = recv_repair_bootstrap(&mut input).await.unwrap_err();
        assert!(
            error.to_string().contains("collection READ proof is"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn node_commands_and_leaf_values_roundtrip() {
        let component = CollectionRepairComponent::Record;
        let summary = PatchSummary::new(Some([7; 32]), 1).unwrap();
        let request =
            PatchRepairRequest::new(component, summary, component.key_len(), vec![], [7; 32])
                .unwrap();
        let response = PatchNodeResponse::Found(PatchNode::Leaf {
            digest: [7; 32],
            leaf: PatchLeaf {
                key: vec![8; 32],
                value: vec![9; 192],
            },
        });
        let expected_response = response.clone();
        let (mut left, mut right) = tokio::io::duplex(1 << 20);
        let writer = tokio::spawn(async move {
            send_repair_node_request(&mut left, &request, component)
                .await
                .unwrap();
            send_repair_done(&mut left).await.unwrap();
            send_repair_node_response(&mut left, &response, component)
                .await
                .unwrap();
        });

        assert!(matches!(
            recv_repair_command(&mut right).await.unwrap(),
            CollectionRepairCommand::Node {
                component: CollectionRepairComponent::Record,
                ref prefix,
                expected_digest,
            } if prefix.is_empty() && expected_digest == [7; 32]
        ));
        assert_eq!(
            recv_repair_command(&mut right).await.unwrap(),
            CollectionRepairCommand::Done
        );
        assert_eq!(
            recv_repair_node_response(&mut right, component)
                .await
                .unwrap(),
            expected_response
        );
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn collection_repair_rejects_the_retired_inline_blob_command() {
        let mut retired_blob_command = [0x02].as_slice();
        let error = recv_repair_command(&mut retired_blob_command)
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "unknown collection repair command 0x2");
    }
}
