//! Pull walks on `recon/1` (design 2.4, 2.5, D8).
//!
//! A walk frame names its collection, its kind and its number. The kind is
//! the PATCH walked: records, authorization evidence or held blob references.
//! The number is the puller's, counted per peer, collection and kind, so a
//! frame of an ended walk is told apart from its successor's. The frame kind
//! is the role: a request comes from the puller, a response from the
//! responder, and an end from either side, which a side byte says.
//!
//! | frame         | payload after collection, kind (u8), number (u16)                |
//! |---------------|------------------------------------------------------------------|
//! | WALK_REQUEST  | 0 open; 1 node: prefix; 2 value: key                              |
//! | WALK_RESPONSE | 0 summary: root, count; 1 branch; 2 leaf; 3 value: key, bytes    |
//! | WALK_END      | side (0 puller, 1 responder), reason (0 done, 1 refused, 2 failed)|
//!
//! A branch is its prefix (a length byte and the bytes), digest, leaf count
//! (u64), representative, end depth (u8) and children, each an edge byte, a
//! digest and a leaf count. A leaf is its prefix, digest and key: a value
//! travels only when the puller asks for it. Every key is 32 bytes relative
//! to its kind's base, and integers are big-endian. A kind or operation this
//! reader does not know skips the frame; a known one that does not parse is
//! malformed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;
use tracing::debug;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, MemoryBlobStore};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId, QuorumOutcome};
use triblespace_core::collection::{CollectionHandle, CollectionRecordFingerprint, descriptor};
use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH};
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::TribleSet;

use crate::channel::{NetEvent, NetEventBatch};
use crate::clock::Mono;
use crate::collection_activation::{
    CollectionAuthorizationEvidenceError, CollectionRepairOverlay, record_root,
};
use crate::collection_delta::{decode_record, encode_record};
use crate::collection_wire::MAX_COLLECTION_LEAF_BYTES;
use crate::connection::{ConnectionTable, Link, ReconEvent, Service};
use crate::health::{Health, RepairComparison, RepairFailure, RepairFrontier};
use crate::host::{CollectionSnapshot, METADATA_BLOB_BYTES, StoreSnapshot};
use crate::landing::{LandSlot, Landed};
use crate::patch_repair::{
    PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchNodeResponse, PatchRepairRequest,
    PatchRepairWalker, PatchSummary, patch_node_response, validate_patch_node,
};
use crate::protocol::{RawHash, op_get_blob_with_limit};
use crate::recon::{FRAME_WALK_END, FRAME_WALK_REQUEST, FRAME_WALK_RESPONSE, Frame, Malformed};
use crate::transport::{PeerId, Transport};

/// Bytes of every key a walk enumerates, relative to its kind's base.
const KEY_BYTES: usize = 32;
/// Collection handle, kind, number and operation.
const HEADER_BYTES: usize = 32 + 1 + 2 + 1;
/// One child of a branch: edge, digest and leaf count.
const CHILD_BYTES: usize = 1 + 32 + 8;

const OPEN: u8 = 0;
const NODE: u8 = 1;
const VALUE: u8 = 2;

const SUMMARY: u8 = 0;
const BRANCH: u8 = 1;
const LEAF: u8 = 2;
const VALUED: u8 = 3;

/// What a walk enumerates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum WalkKind {
    /// The collection's records: its COMMITs and DERIVEs.
    Records,
    /// Its authorization evidence, keyed by proof id under the collection.
    Authorization,
    /// The blobs it holds, as handles without values.
    References,
}

impl WalkKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Records => 0,
            Self::Authorization => 1,
            Self::References => 2,
        }
    }

    const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Records),
            1 => Some(Self::Authorization),
            2 => Some(Self::References),
            _ => None,
        }
    }
}

/// One walk, as both of its sides name it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WalkId {
    pub(crate) collection: CollectionHandle,
    pub(crate) kind: WalkKind,
    pub(crate) number: u16,
}

/// Why a walk ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndReason {
    /// The puller has what it walked for.
    Done,
    /// The responder does not send this collection to the puller.
    Refused,
    /// A side could not go on: an absent prefix or value, a failed check, or
    /// a deadline.
    Failed,
}

/// A puller's request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    /// Pin a snapshot and answer with its summary.
    Open,
    /// The node at this prefix of the pinned snapshot.
    Node(Vec<u8>),
    /// The value under this key.
    Value([u8; KEY_BYTES]),
}

/// A responder's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Response {
    Summary(PatchSummary),
    /// The node at a requested prefix. A leaf carries its key, not its value.
    Node {
        prefix: Vec<u8>,
        node: PatchNode<()>,
    },
    Value {
        key: [u8; KEY_BYTES],
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WalkBody {
    Request(Request),
    Response(Response),
    /// The walk ended at the side that sent this, the puller's or the
    /// responder's; its number retires.
    End {
        by_puller: bool,
        reason: EndReason,
    },
}

/// One frame of a pull walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalkFrame {
    pub(crate) walk: WalkId,
    pub(crate) body: WalkBody,
}

impl WalkFrame {
    pub(crate) fn collection(&self) -> CollectionHandle {
        self.walk.collection
    }

    /// Append the payload after its collection; returns the frame kind.
    pub(crate) fn encode(&self, payload: &mut Vec<u8>) -> u8 {
        payload.push(self.walk.kind.wire());
        payload.extend_from_slice(&self.walk.number.to_be_bytes());
        match &self.body {
            WalkBody::Request(request) => {
                match request {
                    Request::Open => payload.push(OPEN),
                    Request::Node(prefix) => {
                        payload.push(NODE);
                        payload.extend_from_slice(prefix);
                    }
                    Request::Value(key) => {
                        payload.push(VALUE);
                        payload.extend_from_slice(key);
                    }
                }
                FRAME_WALK_REQUEST
            }
            WalkBody::Response(response) => {
                match response {
                    Response::Summary(summary) => {
                        payload.push(SUMMARY);
                        payload.extend_from_slice(&summary.root().unwrap_or_default());
                        payload.extend_from_slice(&summary.leaf_count().to_be_bytes());
                    }
                    Response::Node { prefix, node } => {
                        payload.push(match node {
                            PatchNode::Branch { .. } => BRANCH,
                            PatchNode::Leaf { .. } => LEAF,
                        });
                        let length = u8::try_from(prefix.len()).expect("a prefix fits its key");
                        payload.push(length);
                        payload.extend_from_slice(prefix);
                        payload.extend_from_slice(&node.digest());
                        match node {
                            PatchNode::Branch {
                                leaf_count, branch, ..
                            } => {
                                payload.extend_from_slice(&leaf_count.to_be_bytes());
                                payload.extend_from_slice(&branch.representative);
                                payload.push(branch.end_depth);
                                for child in &branch.children {
                                    payload.push(child.edge);
                                    payload.extend_from_slice(&child.digest);
                                    payload.extend_from_slice(&child.leaf_count.to_be_bytes());
                                }
                            }
                            PatchNode::Leaf { leaf, .. } => payload.extend_from_slice(&leaf.key),
                        }
                    }
                    Response::Value { key, bytes } => {
                        payload.push(VALUED);
                        payload.extend_from_slice(key);
                        payload.extend_from_slice(bytes);
                    }
                }
                FRAME_WALK_RESPONSE
            }
            WalkBody::End { by_puller, reason } => {
                payload.push(if *by_puller { 0 } else { 1 });
                payload.push(match reason {
                    EndReason::Done => 0,
                    EndReason::Refused => 1,
                    EndReason::Failed => 2,
                });
                FRAME_WALK_END
            }
        }
    }

    /// Decode a walk frame's whole payload, collection first. `None` is a
    /// walk kind or operation this reader does not know.
    pub(crate) fn decode(kind: u8, payload: &[u8]) -> Result<Option<Self>, Malformed> {
        if payload.len() < HEADER_BYTES {
            return Err(Malformed("walk frame shorter than its header"));
        }
        let collection = CollectionHandle::new(payload[..32].try_into().unwrap());
        let Some(walk_kind) = WalkKind::from_wire(payload[32]) else {
            return Ok(None);
        };
        let walk = WalkId {
            collection,
            kind: walk_kind,
            number: u16::from_be_bytes([payload[33], payload[34]]),
        };
        let operation = payload[35];
        let mut rest = Reader(&payload[HEADER_BYTES..]);
        let body = match (kind, operation) {
            (FRAME_WALK_REQUEST, OPEN) => WalkBody::Request(Request::Open),
            (FRAME_WALK_REQUEST, NODE) => {
                if rest.0.len() > KEY_BYTES {
                    return Err(Malformed("walk node prefix longer than its key"));
                }
                WalkBody::Request(Request::Node(rest.take(rest.0.len())?))
            }
            (FRAME_WALK_REQUEST, VALUE) => WalkBody::Request(Request::Value(rest.hash()?)),
            (FRAME_WALK_RESPONSE, SUMMARY) => {
                let root = rest.hash()?;
                let count = rest.u64()?;
                // A real root is a digest; all zeros stands for the empty set.
                let root = (root != [0; 32]).then_some(root);
                let summary = PatchSummary::new(root, count)
                    .map_err(|_| Malformed("walk summary root and count disagree"))?;
                WalkBody::Response(Response::Summary(summary))
            }
            (FRAME_WALK_RESPONSE, BRANCH | LEAF) => {
                let length = usize::from(rest.byte()?);
                if length > KEY_BYTES {
                    return Err(Malformed("walk node prefix longer than its key"));
                }
                let prefix = rest.take(length)?;
                let digest = rest.hash()?;
                let node = if operation == LEAF {
                    PatchNode::Leaf {
                        digest,
                        leaf: PatchLeaf {
                            key: rest.take(KEY_BYTES)?,
                            value: (),
                        },
                    }
                } else {
                    let leaf_count = rest.u64()?;
                    let representative = rest.take(KEY_BYTES)?;
                    let end_depth = rest.byte()?;
                    if rest.0.len() % CHILD_BYTES != 0 {
                        return Err(Malformed("walk branch children overrun their frame"));
                    }
                    let mut children = Vec::with_capacity(rest.0.len() / CHILD_BYTES);
                    while !rest.0.is_empty() {
                        children.push(PatchChild {
                            edge: rest.byte()?,
                            digest: rest.hash()?,
                            leaf_count: rest.u64()?,
                        });
                    }
                    PatchNode::Branch {
                        digest,
                        leaf_count,
                        branch: PatchBranch {
                            representative,
                            end_depth,
                            children,
                        },
                    }
                };
                WalkBody::Response(Response::Node { prefix, node })
            }
            (FRAME_WALK_RESPONSE, VALUED) => {
                let key = rest.hash()?;
                if rest.0.len() > MAX_COLLECTION_LEAF_BYTES {
                    return Err(Malformed("walk value larger than a leaf"));
                }
                WalkBody::Response(Response::Value {
                    key,
                    bytes: rest.take(rest.0.len())?,
                })
            }
            (FRAME_WALK_END, side) => {
                if side > 1 {
                    return Err(Malformed("walk end from neither side"));
                }
                let reason = match rest.byte()? {
                    0 => EndReason::Done,
                    1 => EndReason::Refused,
                    // A reason this reader does not know still ends the walk.
                    _ => EndReason::Failed,
                };
                WalkBody::End {
                    by_puller: side == 0,
                    reason,
                }
            }
            _ => return Ok(None),
        };
        if !rest.0.is_empty() {
            return Err(Malformed("trailing bytes after a walk frame"));
        }
        Ok(Some(Self { walk, body }))
    }
}

/// The unread rest of a walk frame.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<Vec<u8>, Malformed> {
        if self.0.len() < length {
            return Err(Malformed("walk frame shorter than its fields"));
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken.to_vec())
    }

    fn byte(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn hash(&mut self) -> Result<[u8; 32], Malformed> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
}

/// A walk ends after this long without progress: every walk that has not
/// ended waits for something owed, a response, a landing acknowledgement or
/// a descriptor.
pub(crate) const WALK_DEADLINE: Duration = Duration::from_secs(60);
/// Node and value requests one walk keeps in flight.
const MAX_WALK_REQUESTS: usize = 64;
/// Values one walk hands to landing before they are acknowledged. A walk
/// whose landing queue is full requests no further nodes.
const MAX_WALK_UNLANDED: usize = 1024;
/// How often walk deadlines are checked.
const WALK_TICK: Duration = Duration::from_secs(1);
/// Frame events waiting for the walk task.
pub(crate) const WALK_EVENTS: usize = 256;

/// One walk of this side's, as landing and descriptor fetches name it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct WalkRef {
    pub(crate) peer: PeerId,
    pub(crate) walk: WalkId,
}

/// A record pull ended: its records walk and its authorization walk both
/// did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecordPullDone {
    pub(crate) peer: PeerId,
    pub(crate) collection: CollectionHandle,
    /// The [`record_root`] of the summaries the walks pinned at the peer; a
    /// walk that ended before its summary counts as empty.
    pub(crate) root: [u8; 32],
    /// Both walks completed: their count proofs closed, every value they
    /// requested landed without a failed insert, and no proof stayed
    /// deferred.
    pub(crate) completed: bool,
}

/// What the walks ask of the rest of the host.
pub(crate) enum Output {
    /// Values for the landing task, acknowledged under their walk.
    Land(WalkRef, Vec<NetEvent>),
    /// A held-blob hint for the store side, which nothing acknowledges.
    Hint(NetEvent),
    /// Fetch the routing descriptor a deferred proof names, from the peer.
    Fetch {
        walk: WalkRef,
        proof: CapabilityProof,
        descriptor: RawHash,
    },
    Done(RecordPullDone),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ending {
    Completed,
    /// The count proof closed, but a value failed to land or a proof stayed
    /// deferred.
    Incomplete,
    Failed,
    TimedOut,
}

type PullKey = (PeerId, RawHash, WalkKind);

/// A walk this side pulls from one peer.
struct Pull {
    link: Link,
    walk: WalkId,
    /// The local observation subtrees are compared with, fixed at the start.
    local: Arc<CollectionSnapshot>,
    /// Present from the summary until the walk ends.
    walker: Option<PatchRepairWalker<()>>,
    summary: Option<PatchSummary>,
    summarised_at: Option<Mono>,
    /// Node requests in flight, by prefix.
    nodes: HashMap<Vec<u8>, PatchRepairRequest<()>>,
    /// Value requests in flight.
    values: HashSet<[u8; KEY_BYTES]>,
    /// Values handed to landing and not acknowledged yet.
    unlanded: usize,
    /// Descriptor fetches in flight for deferred proofs.
    fetching: usize,
    landed: u64,
    failed: u64,
    deferred: bool,
    /// The start or the last response, acknowledgement or fetch.
    progress: Mono,
}

impl Pull {
    /// Take one response. A missing leaf becomes a value request, or a hint
    /// for a held reference; an arriving value goes to landing.
    fn accept(
        &mut self,
        response: Response,
        live: Option<&CollectionSnapshot>,
        peer: PeerId,
        now: Mono,
        outputs: &mut Vec<Output>,
    ) -> anyhow::Result<()> {
        self.progress = now;
        let WalkId {
            collection, kind, ..
        } = self.walk;
        match response {
            Response::Summary(summary) => {
                if self.summary.is_some() {
                    bail!("a second walk summary");
                }
                self.walker = Some(PatchRepairWalker::new((), summary, KEY_BYTES)?);
                self.summary = Some(summary);
                self.summarised_at = Some(now);
            }
            Response::Node { prefix, node } => {
                let request = self
                    .nodes
                    .remove(&prefix)
                    .ok_or_else(|| anyhow!("a walk node nobody requested"))?;
                let base = base(kind, collection);
                validate_patch_node(&request, base.len() + KEY_BYTES, &base, &node, |_, ()| {
                    Ok(())
                })?;
                let walker = self.walker.as_mut().expect("nodes follow the summary");
                let missing =
                    walker.accept(&request, PatchNodeResponse::Found(node), |_, key| {
                        live.is_some_and(|live| contains(kind, live.repair(), key))
                    })?;
                if let Some(leaf) = missing {
                    let key = <[u8; KEY_BYTES]>::try_from(leaf.key)
                        .map_err(|_| anyhow!("a walk leaf key of the wrong length"))?;
                    if kind == WalkKind::References {
                        outputs.push(Output::Hint(NetEvent::BlobHint {
                            collection,
                            source: peer,
                            handle: key,
                        }));
                    } else {
                        self.link
                            .send(frame(self.walk, WalkBody::Request(Request::Value(key))));
                        self.values.insert(key);
                    }
                }
            }
            Response::Value { key, bytes } => {
                if !self.values.remove(&key) {
                    bail!("a walk value nobody requested");
                }
                match kind {
                    WalkKind::Records => {
                        let record = decode_record(collection, &bytes)?;
                        if record.fingerprint().raw() != key {
                            bail!("a record under another record's key");
                        }
                        self.land(peer, vec![NetEvent::CollectionRecord(record)], outputs);
                    }
                    WalkKind::Authorization => {
                        let proof = CapabilityProof::from_bytes(&bytes)?;
                        if proof.id().raw != key {
                            bail!("a proof under another proof's key");
                        }
                        proof.verify_signatures()?;
                        let routed = proof.resource().into_bytes() != collection.raw;
                        let evidence = live
                            .unwrap_or(&self.local)
                            .repair()
                            .authorization_evidence();
                        match evidence.validate_proof(&proof) {
                            Ok(()) => {
                                self.land(peer, vec![NetEvent::CapabilityProof(proof)], outputs)
                            }
                            // A proof over a resource routed to C needs that
                            // resource's descriptor, which the peer holds.
                            Err(
                                CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(
                                    descriptor,
                                ),
                            ) if routed => {
                                self.fetching += 1;
                                outputs.push(Output::Fetch {
                                    walk: WalkRef {
                                        peer,
                                        walk: self.walk,
                                    },
                                    proof,
                                    descriptor: descriptor.raw,
                                });
                            }
                            Err(CollectionAuthorizationEvidenceError::WrongRoot) if routed => {
                                self.deferred = true;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    WalkKind::References => bail!("held references carry no values"),
                }
            }
        }
        Ok(())
    }

    fn land(&mut self, peer: PeerId, events: Vec<NetEvent>, outputs: &mut Vec<Output>) {
        self.unlanded += events.len();
        outputs.push(Output::Land(
            WalkRef {
                peer,
                walk: self.walk,
            },
            events,
        ));
    }

    /// Request nodes while both windows have room.
    fn pump(&mut self) -> anyhow::Result<()> {
        let Some(walker) = self.walker.as_mut() else {
            return Ok(());
        };
        let (kind, local) = (self.walk.kind, self.local.repair());
        while self.nodes.len() + self.values.len() < MAX_WALK_REQUESTS
            && self.unlanded < MAX_WALK_UNLANDED
        {
            let Some(request) =
                walker.next_request(|_, prefix| local_summary(kind, local, prefix))?
            else {
                break;
            };
            let prefix = request.prefix().to_vec();
            self.link.send(frame(
                self.walk,
                WalkBody::Request(Request::Node(prefix.clone())),
            ));
            self.nodes.insert(prefix, request);
        }
        Ok(())
    }

    /// Whether the walk ended, and whether it completed. It ends when nothing
    /// is owed any more and a pump with free windows found the frontier
    /// empty.
    fn finished(&mut self) -> anyhow::Result<Option<bool>> {
        if self.summary.is_none()
            || !self.nodes.is_empty()
            || !self.values.is_empty()
            || self.unlanded > 0
            || self.fetching > 0
        {
            return Ok(None);
        }
        self.walker
            .take()
            .expect("a walk keeps its walker until it ends")
            .finish()?;
        Ok(Some(self.failed == 0 && !self.deferred))
    }
}

/// A record pull: one walk over C's records and one over its authorization
/// evidence, from one peer.
struct RecordPull {
    /// Walks still running.
    running: usize,
    completed: bool,
    failure: Option<RepairFailure>,
    /// The local frontier at the start.
    local: Option<RepairFrontier>,
    compared_at: Option<Mono>,
    records: Option<PatchSummary>,
    authorization: Option<PatchSummary>,
    records_received: u64,
    proofs_received: u64,
}

/// A walk this side serves: the puller's number, and the snapshot pinned at
/// its first request.
struct Served {
    number: u16,
    pinned: Arc<CollectionSnapshot>,
}

/// Every walk of one node, those it pulls and those it serves.
///
/// A walk is named by peer, collection, kind and number, and at most one per
/// peer, collection and kind runs on a side. A frame, an acknowledgement or a
/// fetch for a number that is not the running one is dropped: its walk
/// ended, and its number retired with it.
pub(crate) struct Walks {
    /// Whether this node serves collections at all.
    serves: bool,
    health: Health,
    snapshot: Option<Arc<StoreSnapshot>>,
    pulls: HashMap<PullKey, Pull>,
    /// The next number per peer, collection and kind.
    numbers: HashMap<PullKey, u16>,
    record_pulls: HashMap<(PeerId, RawHash), RecordPull>,
    /// By connection id, collection and kind.
    served: HashMap<(u64, RawHash, WalkKind), Served>,
    outputs: Vec<Output>,
}

impl Walks {
    pub(crate) fn new(serves: bool, health: Health) -> Self {
        Self {
            serves,
            health,
            snapshot: None,
            pulls: HashMap::new(),
            numbers: HashMap::new(),
            record_pulls: HashMap::new(),
            served: HashMap::new(),
            outputs: Vec::new(),
        }
    }

    /// Take the latest serving snapshot: what new walks pin and what a
    /// missing leaf is checked against.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) {
        self.snapshot = Some(snapshot);
    }

    pub(crate) fn take(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.outputs)
    }

    /// Start a record pull of C from the peer on `link`, unless one runs.
    pub(crate) fn start_record_pull(
        &mut self,
        link: &Link,
        collection: CollectionHandle,
        now: Mono,
    ) {
        let peer = link.peer();
        if self.record_pulls.contains_key(&(peer, collection.raw)) {
            return;
        }
        let local = self.local(collection);
        self.health
            .with_peer(collection, peer, |health| health.started(now));
        let mut record_pull = RecordPull {
            running: 0,
            completed: local.is_some(),
            failure: local.is_none().then_some(RepairFailure::Failed),
            local: local.as_ref().map(|local| frontier(local.repair())),
            compared_at: None,
            records: None,
            authorization: None,
            records_received: 0,
            proofs_received: 0,
        };
        let Some(local) = local else {
            return self.finish(peer, collection, record_pull, now);
        };
        record_pull.running = 2;
        self.record_pulls
            .insert((peer, collection.raw), record_pull);
        for kind in [WalkKind::Records, WalkKind::Authorization] {
            self.open(link, collection, kind, local.clone(), now);
        }
    }

    /// Start a walk of C's held references from the peer on `link`, unless
    /// one runs. Missing references become hints for the store side.
    pub(crate) fn start_reference_pull(
        &mut self,
        link: &Link,
        collection: CollectionHandle,
        now: Mono,
    ) {
        let key = (link.peer(), collection.raw, WalkKind::References);
        if self.pulls.contains_key(&key) {
            return;
        }
        if let Some(local) = self.local(collection) {
            self.open(link, collection, WalkKind::References, local, now);
        }
    }

    /// A record pull of C from `peer` could not start: no connection.
    pub(crate) fn unreachable(&mut self, peer: PeerId, collection: CollectionHandle, now: Mono) {
        if self.record_pulls.contains_key(&(peer, collection.raw)) {
            return;
        }
        self.health
            .with_peer(collection, peer, |health| health.started(now));
        let record_pull = RecordPull {
            running: 0,
            completed: false,
            failure: Some(RepairFailure::Failed),
            local: None,
            compared_at: None,
            records: None,
            authorization: None,
            records_received: 0,
            proofs_received: 0,
        };
        self.finish(peer, collection, record_pull, now);
    }

    fn local(&self, collection: CollectionHandle) -> Option<Arc<CollectionSnapshot>> {
        self.snapshot.as_ref()?.collection(collection)
    }

    fn open(
        &mut self,
        link: &Link,
        collection: CollectionHandle,
        kind: WalkKind,
        local: Arc<CollectionSnapshot>,
        now: Mono,
    ) {
        let key = (link.peer(), collection.raw, kind);
        let next = self.numbers.entry(key).or_default();
        let walk = WalkId {
            collection,
            kind,
            number: *next,
        };
        *next = next.wrapping_add(1);
        link.send(frame(walk, WalkBody::Request(Request::Open)));
        self.pulls.insert(
            key,
            Pull {
                link: link.clone(),
                walk,
                local,
                walker: None,
                summary: None,
                summarised_at: None,
                nodes: HashMap::new(),
                values: HashSet::new(),
                unlanded: 0,
                fetching: 0,
                landed: 0,
                failed: 0,
                deferred: false,
                progress: now,
            },
        );
    }

    /// Take one walk frame from the peer on `link`.
    pub(crate) fn frame(&mut self, link: &Link, frame: WalkFrame, now: Mono) {
        let WalkFrame { walk, body } = frame;
        match body {
            WalkBody::Request(request) => self.serve(link, walk, request),
            WalkBody::End {
                by_puller: true, ..
            } => {
                let key = (link.id(), walk.collection.raw, walk.kind);
                if self
                    .served
                    .get(&key)
                    .is_some_and(|served| served.number == walk.number)
                {
                    self.served.remove(&key);
                }
            }
            WalkBody::Response(response) => self.pulled(link, walk, Some(response), now),
            WalkBody::End {
                by_puller: false, ..
            } => self.pulled(link, walk, None, now),
        }
    }

    /// One frame of a walk this side pulls; `None` is the responder ending
    /// it.
    fn pulled(&mut self, link: &Link, walk: WalkId, response: Option<Response>, now: Mono) {
        let key = (link.peer(), walk.collection.raw, walk.kind);
        let Some(pull) = self
            .pulls
            .get_mut(&key)
            .filter(|pull| pull.walk == walk && pull.link.id() == link.id())
        else {
            return;
        };
        let Some(response) = response else {
            return self.end(key, Ending::Failed, false, now);
        };
        let live = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(walk.collection));
        let accepted = pull.accept(
            response,
            live.as_deref(),
            link.peer(),
            now,
            &mut self.outputs,
        );
        self.advance(key, accepted, now);
    }

    /// Pump a walk after `result` and end it if it finished or failed.
    fn advance(&mut self, key: PullKey, result: anyhow::Result<()>, now: Mono) {
        let pull = self.pulls.get_mut(&key).expect("an advancing walk runs");
        match result
            .and_then(|()| pull.pump())
            .and_then(|()| pull.finished())
        {
            Ok(None) => {}
            Ok(Some(true)) => self.end(key, Ending::Completed, true, now),
            Ok(Some(false)) => self.end(key, Ending::Incomplete, true, now),
            Err(error) => {
                debug!(%error, "walk failed");
                self.end(key, Ending::Failed, true, now);
            }
        }
    }

    /// End a walk this side pulls, telling the responder if `tell`.
    fn end(&mut self, key: PullKey, ending: Ending, tell: bool, now: Mono) {
        let Some(pull) = self.pulls.remove(&key) else {
            return;
        };
        let (peer, _, kind) = key;
        let collection = pull.walk.collection;
        if tell {
            let reason = match ending {
                Ending::Completed | Ending::Incomplete => EndReason::Done,
                Ending::Failed | Ending::TimedOut => EndReason::Failed,
            };
            pull.link.send(frame(
                pull.walk,
                WalkBody::End {
                    by_puller: true,
                    reason,
                },
            ));
        }
        if kind == WalkKind::References {
            if ending == Ending::Completed {
                self.outputs
                    .push(Output::Hint(NetEvent::BlobInventoryPassCompleted {
                        collection,
                        source: peer,
                    }));
            }
            return;
        }
        let Some(record_pull) = self.record_pulls.get_mut(&(peer, collection.raw)) else {
            return;
        };
        record_pull.running -= 1;
        record_pull.completed &= ending == Ending::Completed;
        record_pull.failure = match ending {
            Ending::Failed => Some(RepairFailure::Failed),
            Ending::TimedOut => Some(RepairFailure::Deadline),
            Ending::Completed | Ending::Incomplete => record_pull.failure,
        };
        record_pull.compared_at = match (record_pull.compared_at, pull.summarised_at) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (first, second) => first.or(second),
        };
        if kind == WalkKind::Records {
            record_pull.records = pull.summary;
            record_pull.records_received = pull.landed;
        } else {
            record_pull.authorization = pull.summary;
            record_pull.proofs_received = pull.landed;
        }
        if record_pull.running == 0 {
            let record_pull = self.record_pulls.remove(&(peer, collection.raw)).unwrap();
            self.finish(peer, collection, record_pull, now);
        }
    }

    /// Report an ended record pull.
    fn finish(&mut self, peer: PeerId, collection: CollectionHandle, pull: RecordPull, now: Mono) {
        let empty = PatchSummary::new(None, 0).expect("the empty summary");
        let records = pull.records.unwrap_or(empty);
        let authorization = pull.authorization.unwrap_or(empty);
        let root = record_root(collection, records, authorization);
        self.health.with_peer(collection, peer, |health| {
            health.in_flight = false;
            health.last_completed_at = Some(now);
            if let Some(failure) = pull.failure {
                health.last_failure_at = Some(now);
                health.last_failure = Some(failure);
            }
            if let (Some(local), Some(observed_at), Some(_), Some(_)) = (
                pull.local,
                pull.compared_at,
                pull.records,
                pull.authorization,
            ) {
                health.compared(
                    RepairComparison {
                        observed_at,
                        local,
                        remote: RepairFrontier {
                            wake_root: root,
                            records,
                            authorization_evidence: authorization,
                        },
                        records_received: pull.records_received,
                        proofs_received: pull.proofs_received,
                        more: !pull.completed,
                    },
                    now,
                );
            }
        });
        self.outputs.push(Output::Done(RecordPullDone {
            peer,
            collection,
            root,
            completed: pull.completed,
        }));
    }

    /// Answer one request of a walk the peer on `link` pulls from this side.
    fn serve(&mut self, link: &Link, walk: WalkId, request: Request) {
        let key = (link.id(), walk.collection.raw, walk.kind);
        let reply = |body| link.send(frame(walk, body));
        let ended = |reason| WalkBody::End {
            by_puller: false,
            reason,
        };
        if request == Request::Open {
            // A new walk replaces the peer's previous one of this kind.
            self.served.remove(&key);
            let pinned = self
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.collection(walk.collection))
                .filter(|pinned| self.serves && self.sends(link.peer(), pinned));
            let Some(pinned) = pinned else {
                return reply(ended(EndReason::Refused));
            };
            reply(WalkBody::Response(Response::Summary(summary(
                walk.kind,
                pinned.repair(),
            ))));
            self.served.insert(
                key,
                Served {
                    number: walk.number,
                    pinned,
                },
            );
            return;
        }
        let current = self
            .served
            .get(&key)
            .filter(|served| served.number == walk.number);
        match current.and_then(|served| answer(walk.kind, served.pinned.repair(), request)) {
            Some(response) => reply(WalkBody::Response(response)),
            None => {
                // An absent prefix or value ends the walk; so does a request
                // of a walk not served here.
                if current.is_some() {
                    self.served.remove(&key);
                }
                reply(ended(EndReason::Failed));
            }
        }
    }

    /// Whether this side sends C to `peer`: its peering for C sends to the
    /// peer, or the peer passes READ under the pinned evidence.
    fn sends(&self, peer: PeerId, pinned: &CollectionSnapshot) -> bool {
        let collection = pinned.repair().collection();
        let mut flagged = false;
        self.health.update(|health| {
            flagged = health.peerings.iter().any(|peering| {
                peering.collection == collection
                    && peering.peer == peer
                    && peering.peered
                    && peering.sends
            });
        });
        flagged
            || VerifyingKey::from_bytes(&peer).is_ok_and(|peer| {
                let evidence = pinned.repair().authorization_evidence();
                let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
                matches!(
                    evidence.reader_is_admitted_by(peer, &proofs),
                    QuorumOutcome::Met
                )
            })
    }

    /// The landing task acknowledged values of `walk`.
    pub(crate) fn landed(&mut self, walk: WalkRef, landed: u64, failed: u64, now: Mono) {
        let key = (walk.peer, walk.walk.collection.raw, walk.walk.kind);
        let Some(pull) = self
            .pulls
            .get_mut(&key)
            .filter(|pull| pull.walk == walk.walk)
        else {
            return;
        };
        pull.unlanded = pull
            .unlanded
            .saturating_sub(usize::try_from(landed + failed).unwrap_or(usize::MAX));
        pull.landed += landed;
        pull.failed += failed;
        pull.progress = now;
        self.advance(key, Ok(()), now);
    }

    /// A deferred proof's descriptor fetch ended. A descriptor that routes
    /// the proof to C lands with it; otherwise the proof stays deferred.
    pub(crate) fn fetched(
        &mut self,
        walk: WalkRef,
        proof: CapabilityProof,
        descriptor: Option<Blob<UnknownBlob>>,
        now: Mono,
    ) {
        let key = (walk.peer, walk.walk.collection.raw, walk.walk.kind);
        let Some(pull) = self
            .pulls
            .get_mut(&key)
            .filter(|pull| pull.walk == walk.walk)
        else {
            return;
        };
        pull.fetching -= 1;
        pull.progress = now;
        match descriptor.filter(|descriptor| routes(walk.walk.collection, &proof, descriptor)) {
            Some(descriptor) => pull.land(
                walk.peer,
                vec![NetEvent::Blob(descriptor), NetEvent::CapabilityProof(proof)],
                &mut self.outputs,
            ),
            None => pull.deferred = true,
        }
        self.advance(key, Ok(()), now);
    }

    /// The `recon/1` stream or the connection of `link` ended, and every walk
    /// on it with it, in both roles.
    pub(crate) fn ended(&mut self, link: &Link, now: Mono) {
        self.served.retain(|(id, _, _), _| *id != link.id());
        let keys = self
            .pulls
            .iter()
            .filter(|(_, pull)| pull.link.id() == link.id())
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in keys {
            self.end(key, Ending::Failed, false, now);
        }
    }

    /// End the walks that made no progress for [`WALK_DEADLINE`].
    pub(crate) fn expire(&mut self, now: Mono) {
        let keys = self
            .pulls
            .iter()
            .filter(|(_, pull)| now >= pull.progress + WALK_DEADLINE)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in keys {
            self.end(key, Ending::TimedOut, true, now);
        }
    }
}

fn frame(walk: WalkId, body: WalkBody) -> Frame {
    Frame::Walk(WalkFrame { walk, body })
}

/// The fixed key prefix each kind's PATCH puts before the walked key.
fn base(kind: WalkKind, collection: CollectionHandle) -> Vec<u8> {
    match kind {
        WalkKind::Authorization => collection.raw.to_vec(),
        WalkKind::Records | WalkKind::References => Vec::new(),
    }
}

fn summary(kind: WalkKind, overlay: &CollectionRepairOverlay) -> PatchSummary {
    match kind {
        WalkKind::Records => overlay.records().summary(),
        WalkKind::Authorization => overlay.authorization_evidence().summary(),
        WalkKind::References => PatchSummary::from_patch(overlay.blob_inventory()),
    }
}

fn local_summary(
    kind: WalkKind,
    overlay: &CollectionRepairOverlay,
    prefix: &[u8],
) -> Option<PatchSummary> {
    match kind {
        WalkKind::Records => node_summary(overlay.records().patch(), prefix),
        WalkKind::Authorization => overlay.authorization_evidence().prefix_summary(prefix),
        WalkKind::References => node_summary(overlay.blob_inventory(), prefix),
    }
}

fn node_summary<V>(
    patch: &PATCH<KEY_BYTES, IdentitySchema, V, Blake3Merkle>,
    prefix: &[u8],
) -> Option<PatchSummary> {
    patch.merkle_node(prefix).map(|node| {
        PatchSummary::new(Some(node.digest()), node.leaf_count()).expect("a PATCH node is nonempty")
    })
}

fn contains(kind: WalkKind, overlay: &CollectionRepairOverlay, key: &[u8]) -> bool {
    let Ok(key) = <[u8; KEY_BYTES]>::try_from(key) else {
        return false;
    };
    match kind {
        WalkKind::Records => overlay
            .records()
            .get(CollectionRecordFingerprint::from_raw(key))
            .is_some(),
        WalkKind::Authorization => overlay
            .authorization_evidence()
            .get(CapabilityProofId::new(key))
            .is_some(),
        WalkKind::References => overlay.blob_inventory().get(&key).is_some(),
    }
}

/// The node or value a request asks of a pinned snapshot, if present.
fn answer(kind: WalkKind, overlay: &CollectionRepairOverlay, request: Request) -> Option<Response> {
    match request {
        Request::Open => None,
        Request::Node(prefix) => {
            let found = match kind {
                WalkKind::Records => {
                    patch_node_response(overlay.records().patch(), &[], &prefix, |_, _| Ok(()))
                }
                WalkKind::Authorization => patch_node_response(
                    overlay.authorization_evidence().patch(),
                    &overlay.collection().raw,
                    &prefix,
                    |_, _| Ok(()),
                ),
                WalkKind::References => {
                    patch_node_response(overlay.blob_inventory(), &[], &prefix, |_, _| Ok(()))
                }
            };
            match found {
                Ok(PatchNodeResponse::Found(node)) => Some(Response::Node { prefix, node }),
                _ => None,
            }
        }
        Request::Value(key) => {
            let bytes = match kind {
                WalkKind::Records => overlay
                    .records()
                    .get(CollectionRecordFingerprint::from_raw(key))
                    .and_then(|record| encode_record(overlay.collection(), record).ok()),
                WalkKind::Authorization => overlay
                    .authorization_evidence()
                    .get(CapabilityProofId::new(key))
                    .map(|proof| proof.as_bytes().to_vec()),
                WalkKind::References => None,
            }?;
            Some(Response::Value { key, bytes })
        }
    }
}

fn frontier(overlay: &CollectionRepairOverlay) -> RepairFrontier {
    RepairFrontier {
        wake_root: overlay.wake_root(),
        records: overlay.records().summary(),
        authorization_evidence: overlay.authorization_evidence().summary(),
    }
}

/// Whether `proof` is evidence for C through the resource `descriptor`
/// describes.
fn routes(
    collection: CollectionHandle,
    proof: &CapabilityProof,
    descriptor: &Blob<UnknownBlob>,
) -> bool {
    let mut blobs = MemoryBlobStore::new();
    blobs.insert(descriptor.clone());
    let Ok(reader) = blobs.snapshot();
    // C's own descriptor is read only for a proof over C itself.
    descriptor::validate_proof_evidence(&reader, collection, &TribleSet::new(), proof).is_ok()
}

/// Starts pulls through the walk task.
#[derive(Clone)]
pub(crate) struct Pulls(mpsc::UnboundedSender<Command>);

impl Pulls {
    /// Pull C's records and authorization evidence from `peer`, dialling it
    /// if need be. A [`RecordPullDone`] reports the end; while a record pull
    /// from the peer runs, it stands for this one.
    pub(crate) fn start_record_pull(&self, peer: PeerId, collection: CollectionHandle) {
        let _ = self.0.send(Command::Start {
            peer,
            collection,
            records: true,
        });
    }

    /// Pull the blobs C holds at `peer`, as hints for the store side.
    pub(crate) fn start_reference_pull(&self, peer: PeerId, collection: CollectionHandle) {
        let _ = self.0.send(Command::Start {
            peer,
            collection,
            records: false,
        });
    }
}

enum Command {
    /// Start a record pull, or with `records` unset a reference pull.
    Start {
        peer: PeerId,
        collection: CollectionHandle,
        records: bool,
    },
    /// A dial for a start ended.
    Connected {
        peer: PeerId,
        collection: CollectionHandle,
        records: bool,
        link: Option<Link>,
    },
    Fetched {
        walk: WalkRef,
        proof: CapabilityProof,
        descriptor: Option<Blob<UnknownBlob>>,
    },
}

/// Run one node's walks: its landing task, and a task that hears `events`
/// from its connections, follows `snapshots` and passes held-blob hints to
/// `store`. Returns what starts pulls and where record pulls report their
/// ends.
pub(crate) fn spawn<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    snapshots: tokio::sync::watch::Receiver<Option<Arc<StoreSnapshot>>>,
    walks: Walks,
    events: mpsc::Receiver<ReconEvent>,
    lander: LandSlot,
    store: mpsc::Sender<NetEventBatch>,
) -> (Pulls, mpsc::UnboundedReceiver<RecordPullDone>) {
    let (commands, commanded) = mpsc::unbounded_channel();
    let (landing, items) = mpsc::unbounded_channel();
    let (acks, landed) = mpsc::unbounded_channel();
    let (hints, hinted) = mpsc::unbounded_channel();
    let (done, reports) = mpsc::unbounded_channel();
    tokio::spawn(crate::landing::run(lander, items, acks));
    tokio::spawn(forward(hinted, store));
    let task = Task {
        connections,
        walks,
        commands: Pulls(commands.clone()),
        landing,
        hints,
        done,
    };
    tokio::spawn(task.run(snapshots, events, commanded, landed));
    (Pulls(commands), reports)
}

struct Task<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    walks: Walks,
    /// Where dials and fetches report back.
    commands: Pulls,
    landing: mpsc::UnboundedSender<(WalkRef, Vec<NetEvent>)>,
    hints: mpsc::UnboundedSender<NetEvent>,
    done: mpsc::UnboundedSender<RecordPullDone>,
}

impl<T: Transport, S: Service> Task<T, S> {
    async fn run(
        mut self,
        mut snapshots: tokio::sync::watch::Receiver<Option<Arc<StoreSnapshot>>>,
        mut events: mpsc::Receiver<ReconEvent>,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut landed: mpsc::UnboundedReceiver<Landed<WalkRef>>,
    ) {
        let mut tick = tokio::time::interval(WALK_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        if let Some(snapshot) = snapshots.borrow_and_update().clone() {
            self.walks.observe(snapshot);
        }
        loop {
            tokio::select! {
                changed = snapshots.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if let Some(snapshot) = snapshots.borrow_and_update().clone() {
                        self.walks.observe(snapshot);
                    }
                }
                Some(event) = events.recv() => match event {
                    ReconEvent::Frame(link, Frame::Walk(frame)) => {
                        self.walks.frame(&link, frame, crate::clock::mono_now());
                    }
                    ReconEvent::Ended(link) | ReconEvent::Closed(link) => {
                        self.walks.ended(&link, crate::clock::mono_now());
                    }
                    _ => {}
                },
                Some(command) = commands.recv() => self.command(command),
                Some(ack) = landed.recv() => {
                    self.walks.landed(ack.key, ack.landed, ack.failed, crate::clock::mono_now());
                }
                _ = tick.tick() => self.walks.expire(crate::clock::mono_now()),
            }
            for output in self.walks.take() {
                self.output(output);
            }
        }
    }

    fn command(&mut self, command: Command) {
        let now = crate::clock::mono_now();
        match command {
            Command::Start {
                peer,
                collection,
                records,
            } => match self.connections.current(peer) {
                Some(connection) => self.start(&connection.link(), collection, records, now),
                None => {
                    let connections = self.connections.clone();
                    let commands = self.commands.0.clone();
                    tokio::spawn(async move {
                        let connected = connections.connect(peer).await;
                        let _ = commands.send(Command::Connected {
                            peer,
                            collection,
                            records,
                            link: connected.ok().map(|connection| connection.link()),
                        });
                    });
                }
            },
            Command::Connected {
                peer,
                collection,
                records,
                link,
            } => match link {
                Some(link) => self.start(&link, collection, records, now),
                None if records => self.walks.unreachable(peer, collection, now),
                None => {}
            },
            Command::Fetched {
                walk,
                proof,
                descriptor,
            } => self.walks.fetched(walk, proof, descriptor, now),
        }
    }

    fn start(&mut self, link: &Link, collection: CollectionHandle, records: bool, now: Mono) {
        if records {
            self.walks.start_record_pull(link, collection, now);
        } else {
            self.walks.start_reference_pull(link, collection, now);
        }
    }

    fn output(&self, output: Output) {
        match output {
            Output::Land(walk, events) => {
                let _ = self.landing.send((walk, events));
            }
            Output::Hint(event) => {
                let _ = self.hints.send(event);
            }
            Output::Done(done) => {
                let _ = self.done.send(done);
            }
            Output::Fetch {
                walk,
                proof,
                descriptor,
            } => {
                let connections = self.connections.clone();
                let commands = self.commands.0.clone();
                tokio::spawn(async move {
                    let fetch = async {
                        let connection = connections.current(walk.peer)?;
                        let local = connections.transport().local_id();
                        op_get_blob_with_limit(&connection, local, &descriptor, METADATA_BLOB_BYTES)
                            .await
                            .ok()
                            .flatten()
                    };
                    let descriptor = tokio::time::timeout(WALK_DEADLINE, fetch)
                        .await
                        .ok()
                        .flatten();
                    let _ = commands.send(Command::Fetched {
                        walk,
                        proof,
                        descriptor,
                    });
                });
            }
        }
    }
}

/// Pass held-blob hints to the store side in batches, waiting there for room
/// so that the walks never do.
async fn forward(mut hints: mpsc::UnboundedReceiver<NetEvent>, store: mpsc::Sender<NetEventBatch>) {
    while let Some(first) = hints.recv().await {
        let mut batch = NetEventBatch::default();
        let mut next = Some(first);
        while let Some(event) = next.take() {
            if let Err(event) = batch.try_push(event) {
                if store.send(std::mem::take(&mut batch)).await.is_err() {
                    return;
                }
                next = Some(event);
                continue;
            }
            next = hints.try_recv().ok();
        }
        if store.send(batch).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recon::Frame;

    fn walk(kind: WalkKind, number: u16) -> WalkId {
        WalkId {
            collection: CollectionHandle::new([7; 32]),
            kind,
            number,
        }
    }

    fn roundtrip(walk: WalkId, body: WalkBody) {
        let frame = Frame::Walk(WalkFrame { walk, body });
        let (kind, payload) = frame.encode();
        assert!(payload.len() <= crate::recon::MAX_RECON_FRAME_BYTES as usize);
        assert_eq!(Frame::decode(kind, &payload), Ok(Some(frame)));
    }

    #[test]
    fn every_walk_frame_round_trips() {
        let records = walk(WalkKind::Records, 0);
        roundtrip(records, WalkBody::Request(Request::Open));
        roundtrip(records, WalkBody::Request(Request::Node(Vec::new())));
        roundtrip(
            walk(WalkKind::Authorization, 9),
            WalkBody::Request(Request::Node(vec![1, 2, 3])),
        );
        roundtrip(records, WalkBody::Request(Request::Value([4; 32])));
        for summary in [
            PatchSummary::new(None, 0).unwrap(),
            PatchSummary::new(Some([5; 32]), 600).unwrap(),
        ] {
            roundtrip(records, WalkBody::Response(Response::Summary(summary)));
        }
        let children = (0..=255)
            .map(|edge| PatchChild {
                edge,
                digest: [edge; 32],
                leaf_count: u64::from(edge) + 1,
            })
            .collect();
        roundtrip(
            walk(WalkKind::References, u16::MAX),
            WalkBody::Response(Response::Node {
                prefix: vec![6; 32],
                node: PatchNode::Branch {
                    digest: [1; 32],
                    leaf_count: 1 << 40,
                    branch: PatchBranch {
                        representative: vec![2; 32],
                        end_depth: 31,
                        children,
                    },
                },
            }),
        );
        roundtrip(
            records,
            WalkBody::Response(Response::Node {
                prefix: Vec::new(),
                node: PatchNode::Leaf {
                    digest: [3; 32],
                    leaf: PatchLeaf {
                        key: vec![4; 32],
                        value: (),
                    },
                },
            }),
        );
        roundtrip(
            records,
            WalkBody::Response(Response::Value {
                key: [8; 32],
                bytes: vec![9; MAX_COLLECTION_LEAF_BYTES],
            }),
        );
        for (by_puller, reason) in [
            (true, EndReason::Done),
            (false, EndReason::Refused),
            (true, EndReason::Failed),
        ] {
            roundtrip(records, WalkBody::End { by_puller, reason });
        }
    }

    #[test]
    fn malformed_walk_frames_are_violations_and_unknown_ones_are_skipped() {
        let encode = |body| {
            Frame::Walk(WalkFrame {
                walk: walk(WalkKind::Records, 1),
                body,
            })
            .encode()
        };
        let (_, node) = encode(WalkBody::Request(Request::Node(vec![1; 32])));
        let (_, summary) = encode(WalkBody::Response(Response::Summary(
            PatchSummary::new(Some([5; 32]), 2).unwrap(),
        )));
        let (_, end) = encode(WalkBody::End {
            by_puller: true,
            reason: EndReason::Done,
        });
        let mut empty_root_with_leaves = summary.clone();
        empty_root_with_leaves[36..68].fill(0);
        let mut nonzero_root_without_leaves = summary.clone();
        nonzero_root_without_leaves[68..].fill(0);
        let mut third_side = end.clone();
        third_side[35] = 2;
        for (kind, payload) in [
            (FRAME_WALK_REQUEST, &node[..35]),
            (FRAME_WALK_REQUEST, &[&node[..], &[1]].concat()[..]),
            (FRAME_WALK_RESPONSE, &summary[..summary.len() - 1]),
            (FRAME_WALK_RESPONSE, &empty_root_with_leaves[..]),
            (FRAME_WALK_RESPONSE, &nonzero_root_without_leaves[..]),
            (FRAME_WALK_END, &end[..end.len() - 1]),
            (FRAME_WALK_END, &third_side[..]),
        ] {
            assert!(
                Frame::decode(kind, payload).is_err(),
                "{kind:#x} {}",
                payload.len()
            );
        }
        let mut unknown_kind = node.clone();
        unknown_kind[32] = 3;
        assert_eq!(Frame::decode(FRAME_WALK_REQUEST, &unknown_kind), Ok(None));
        let mut unknown_operation = node;
        unknown_operation[35] = 9;
        assert_eq!(
            Frame::decode(FRAME_WALK_REQUEST, &unknown_operation),
            Ok(None)
        );
    }

    /// Walks driven by hand: two nodes' [`Walks`] over a fake connection
    /// whose frames the test carries, landing into each node's store.
    mod walking {
        use super::*;

        use std::collections::BTreeSet;

        use ed25519_dalek::SigningKey;
        use iroh_base::EndpointId;
        use tokio::sync::mpsc::UnboundedReceiver;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::CapabilityResource;
        use triblespace_core::capability::policy::{resource_collection, resource_policy};
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionCommit, CollectionData, CollectionMerge, CollectionPolicy,
            CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt,
            empty_metadata_handle,
        };
        use triblespace_core::macros::entity;
        use triblespace_core::patch::Entry as PatchEntry;
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_core::repo::{
            BlobStoreGet, BlobStorePut, CapabilityProofStore, StoreChanges,
        };

        use crate::health::PeeringHealth;
        use crate::host::ActiveCollections;

        fn key(byte: u8) -> SigningKey {
            SigningKey::from_bytes(&[byte; 32])
        }

        fn open() -> CollectionPolicy {
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open)
        }

        /// One node: its store, its active collections and its walks.
        struct Node {
            key: SigningKey,
            store: MemoryRepo,
            active: ActiveCollections,
            walks: Walks,
            health: Health,
            /// Record pulls that ended here.
            done: Vec<RecordPullDone>,
            /// Hints for the store side.
            hints: Vec<NetEvent>,
            /// Landings not yet carried out, when the test holds them back.
            held: Vec<(WalkRef, Vec<NetEvent>)>,
            hold: bool,
            /// Descriptor fetches the test answers.
            fetches: Vec<(WalkRef, CapabilityProof, RawHash)>,
        }

        impl Node {
            fn new(byte: u8) -> Self {
                let key = key(byte);
                let health =
                    Health::new(EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap());
                Self {
                    walks: Walks::new(true, health.clone()),
                    health,
                    key,
                    store: MemoryRepo::default(),
                    active: ActiveCollections::new(),
                    done: Vec::new(),
                    hints: Vec::new(),
                    held: Vec::new(),
                    hold: false,
                    fetches: Vec::new(),
                }
            }

            fn id(&self) -> PeerId {
                self.key.verifying_key().to_bytes()
            }

            fn hold(&mut self, name: &str, policy: CollectionPolicy) -> CollectionHandle {
                let collection = self.store.collection(name, policy).unwrap().handle();
                self.active.insert(&PatchEntry::new(&collection.raw));
                self.observe();
                collection
            }

            fn commit(&mut self, collection: CollectionHandle, data: u64) -> CollectionRecord {
                let record = CollectionRecord::Commit(CollectionCommit::sign(
                    &self.key,
                    collection,
                    CollectionData::new(*blake3::hash(&data.to_be_bytes()).as_bytes()),
                    empty_metadata_handle(),
                ));
                self.store.insert(record).unwrap();
                record
            }

            fn observe(&mut self) {
                let snapshot = StoreSnapshot::from_store_changes(
                    self.store.snapshot().unwrap(),
                    &self.active,
                    self.key.verifying_key(),
                    None,
                    None,
                    StoreChanges::ALL,
                )
                .unwrap();
                self.walks.observe(Arc::new(snapshot));
            }

            fn records(&mut self, collection: CollectionHandle) -> BTreeSet<CollectionRecord> {
                self.store
                    .snapshot()
                    .unwrap()
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .filter(|record| record.collection() == collection)
                    .collect()
            }

            /// Carry out the walks' outputs: land (unless held back), and
            /// keep the rest for the test.
            fn outputs(&mut self, now: Mono) {
                loop {
                    let outputs = self.walks.take();
                    if outputs.is_empty() {
                        return;
                    }
                    let mut lands = Vec::new();
                    for output in outputs {
                        match output {
                            Output::Land(walk, events) if self.hold => {
                                self.held.push((walk, events))
                            }
                            Output::Land(walk, events) => lands.push((walk, events)),
                            Output::Hint(hint) => self.hints.push(hint),
                            Output::Fetch {
                                walk,
                                proof,
                                descriptor,
                            } => self.fetches.push((walk, proof, descriptor)),
                            Output::Done(done) => self.done.push(done),
                        }
                    }
                    self.land(lands, now);
                }
            }

            /// Insert, publish once and acknowledge each walk, as the
            /// landing task does.
            fn land(&mut self, lands: Vec<(WalkRef, Vec<NetEvent>)>, now: Mono) {
                let mut acks = Vec::new();
                for (walk, events) in lands {
                    let (mut landed, mut failed) = (0, 0);
                    for event in events {
                        let ok = match event {
                            NetEvent::CollectionRecord(record) => self.store.insert(record).is_ok(),
                            NetEvent::CapabilityProof(proof) => {
                                self.store.insert_proof(proof).is_ok()
                            }
                            NetEvent::Blob(blob) => self.store.put::<UnknownBlob, _>(blob).is_ok(),
                            _ => false,
                        };
                        if ok {
                            landed += 1;
                        } else {
                            failed += 1;
                        }
                    }
                    acks.push((walk, landed, failed));
                }
                if acks.is_empty() {
                    return;
                }
                self.observe();
                for (walk, landed, failed) in acks {
                    self.walks.landed(walk, landed, failed, now);
                }
            }

            /// Land what was held back, in order.
            fn release(&mut self, now: Mono) {
                self.hold = false;
                let held = std::mem::take(&mut self.held);
                self.land(held, now);
                self.outputs(now);
            }
        }

        /// A connection between two nodes: each side's link and the frames
        /// queued on it.
        struct Wire {
            to_right: Link,
            from_left: UnboundedReceiver<Frame>,
            to_left: Link,
            from_right: UnboundedReceiver<Frame>,
        }

        fn connect(left: &Node, right: &Node, id: u64) -> Wire {
            let (to_right, from_left) = Link::detached(id, right.id());
            let (to_left, from_right) = Link::detached(id, left.id());
            Wire {
                to_right,
                from_left,
                to_left,
                from_right,
            }
        }

        fn walk_frame(frame: Frame) -> WalkFrame {
            match frame {
                Frame::Walk(frame) => frame,
                other => panic!("not a walk frame: {other:?}"),
            }
        }

        /// Carry frames both ways until neither side sends, dropping those
        /// `keep` refuses; returns how many crossed.
        fn carry_while(
            left: &mut Node,
            right: &mut Node,
            wire: &mut Wire,
            now: Mono,
            mut keep: impl FnMut(&WalkFrame) -> bool,
        ) -> usize {
            let mut carried = 0;
            loop {
                left.outputs(now);
                right.outputs(now);
                if let Ok(frame) = wire.from_left.try_recv() {
                    let frame = walk_frame(frame);
                    if keep(&frame) {
                        carried += 1;
                        right.walks.frame(&wire.to_left, frame, now);
                    }
                } else if let Ok(frame) = wire.from_right.try_recv() {
                    let frame = walk_frame(frame);
                    if keep(&frame) {
                        carried += 1;
                        left.walks.frame(&wire.to_right, frame, now);
                    }
                } else {
                    return carried;
                }
            }
        }

        /// Carry one frame, the left side's first; whether there was one.
        fn step(left: &mut Node, right: &mut Node, wire: &mut Wire, now: Mono) -> bool {
            left.outputs(now);
            right.outputs(now);
            if let Ok(frame) = wire.from_left.try_recv() {
                right.walks.frame(&wire.to_left, walk_frame(frame), now);
            } else if let Ok(frame) = wire.from_right.try_recv() {
                left.walks.frame(&wire.to_right, walk_frame(frame), now);
            } else {
                return false;
            }
            true
        }

        fn carry(left: &mut Node, right: &mut Node, wire: &mut Wire, now: Mono) -> usize {
            carry_while(left, right, wire, now, |_| true)
        }

        fn root(node: &Node, collection: CollectionHandle) -> [u8; 32] {
            let snapshot = node.walks.snapshot.as_ref().unwrap();
            let overlay = snapshot.collection(collection).unwrap();
            record_root(
                collection,
                overlay.repair().records().summary(),
                overlay.repair().authorization_evidence().summary(),
            )
        }

        /// A record pull each way leaves both sides with the union, beyond
        /// the 511 node requests a repair pass used to be capped at.
        #[test]
        fn a_pull_and_its_reverse_leave_both_sides_with_the_union() {
            let now = crate::clock::mono_now();
            let mut left = Node::new(1);
            let mut right = Node::new(2);
            let collection = left.hold("union", open());
            assert_eq!(right.hold("union", open()), collection);
            let shared = (0..700)
                .map(|data| left.commit(collection, data))
                .collect::<Vec<_>>();
            for record in &shared[600..] {
                right.store.insert(*record).unwrap();
            }
            for data in 700..1300 {
                right.commit(collection, data);
            }
            left.observe();
            right.observe();
            let (left_root, right_root) = (root(&left, collection), root(&right, collection));
            let mut wire = connect(&left, &right, 1);
            left.walks
                .start_record_pull(&wire.to_right, collection, now);
            right
                .walks
                .start_record_pull(&wire.to_left, collection, now);
            assert!(carry(&mut left, &mut right, &mut wire, now) > 2 * 511);

            assert_eq!(left.records(collection).len(), 1300);
            assert_eq!(left.records(collection), right.records(collection));
            for (node, walked) in [(&left, right_root), (&right, left_root)] {
                let peer = if node.id() == left.id() {
                    right.id()
                } else {
                    left.id()
                };
                assert_eq!(
                    node.done,
                    [RecordPullDone {
                        peer,
                        collection,
                        root: walked,
                        completed: true,
                    }]
                );
            }
            assert!(left.walks.pulls.is_empty() && left.walks.served.is_empty());
            assert!(right.walks.pulls.is_empty() && right.walks.served.is_empty());
        }

        /// A responder sends C only to a peer it sends C to: one that passes
        /// READ under its evidence, or one whose peering it flagged.
        #[test]
        fn data_flows_only_in_send_flagged_directions() {
            let now = crate::clock::mono_now();
            let mut owner = Node::new(3);
            let mut stranger = Node::new(4);
            let policy = CollectionPolicy::new(
                AdmissionPolicy::direct(owner.key.verifying_key()),
                AdmissionPolicy::direct(owner.key.verifying_key()),
            );
            let collection = owner.hold("flagged", policy.clone());
            stranger.hold("flagged", policy);
            let owned = owner.commit(collection, 1);
            let foreign = stranger.commit(collection, 2);
            owner.observe();
            stranger.observe();
            let mut wire = connect(&stranger, &owner, 1);

            // The owner refuses the stranger, which lacks READ.
            stranger
                .walks
                .start_record_pull(&wire.to_right, collection, now);
            carry(&mut stranger, &mut owner, &mut wire, now);
            assert!(!stranger.done[0].completed);
            assert_eq!(stranger.records(collection), BTreeSet::from([foreign]));

            // The stranger sends to the owner, which passes READ.
            owner
                .walks
                .start_record_pull(&wire.to_left, collection, now);
            carry(&mut stranger, &mut owner, &mut wire, now);
            assert!(owner.done[0].completed);
            assert_eq!(owner.records(collection), BTreeSet::from([owned, foreign]));

            // A peering whose send flag the owner set (on credentials its
            // store does not hold) admits the stranger's walk.
            let stranger_id = stranger.id();
            owner.health.update(|health| {
                health.peerings.push(PeeringHealth {
                    collection,
                    peer: stranger_id,
                    asked: false,
                    peered: true,
                    sends: true,
                    receives: true,
                    refused_by_me: false,
                    refused_by_them: false,
                })
            });
            stranger
                .walks
                .start_record_pull(&wire.to_right, collection, now);
            carry(&mut stranger, &mut owner, &mut wire, now);
            assert!(stranger.done[1].completed);
            assert_eq!(
                stranger.records(collection),
                BTreeSet::from([owned, foreign])
            );
        }

        /// A walk that ends early keeps what landed, and the next walk
        /// fetches what is still missing; values fetched twice land twice
        /// harmlessly.
        #[test]
        fn a_dropped_walk_keeps_what_landed_and_duplicates_are_harmless() {
            let now = crate::clock::mono_now();
            let mut puller = Node::new(5);
            let mut responder = Node::new(6);
            let collection = puller.hold("dropped", open());
            responder.hold("dropped", open());
            let records = (0..200)
                .map(|data| responder.commit(collection, data))
                .collect::<BTreeSet<_>>();
            responder.observe();
            let mut wire = connect(&puller, &responder, 1);
            puller
                .walks
                .start_record_pull(&wire.to_right, collection, now);
            // Some values land, then the connection's recon/1 ends with the
            // rest in flight.
            let mut values = 0;
            carry_while(&mut puller, &mut responder, &mut wire, now, |frame| {
                if let WalkBody::Response(Response::Value { .. }) = frame.body {
                    values += 1;
                }
                values <= 50
            });
            puller.walks.ended(&wire.to_right, now);
            puller.outputs(now);
            let landed = puller.records(collection);
            assert!(!landed.is_empty() && landed.len() < 200, "{}", landed.len());
            assert!(!puller.done[0].completed);

            // The next walk's values are held back while the earlier ones
            // land again under it.
            let mut wire = connect(&puller, &responder, 2);
            puller
                .walks
                .start_record_pull(&wire.to_right, collection, now);
            puller.hold = true;
            carry(&mut puller, &mut responder, &mut wire, now);
            let duplicates = landed
                .iter()
                .map(|record| NetEvent::CollectionRecord(*record));
            let walk = puller.held[0].0;
            puller.held.push((walk, duplicates.collect()));
            puller.release(now);
            carry(&mut puller, &mut responder, &mut wire, now);
            assert_eq!(puller.records(collection), records);
            assert!(puller.done[1].completed, "{:?}", puller.done);
        }

        /// A proof over another resource routed to C waits for that
        /// resource's descriptor. A walk whose fetch of it failed lands the
        /// records but does not complete; the next pull lands the proof.
        #[test]
        fn a_deferred_proof_prevents_completion_until_its_descriptor_arrives() {
            let now = crate::clock::mono_now();
            let mut puller = Node::new(7);
            let mut responder = Node::new(8);
            let collection = puller.hold("deferred", open());
            responder.hold("deferred", open());
            let resource_root = key(9);
            let capability = triblespace_core::inline::Inline::new([10; 32]);
            let resource = responder
                .store
                .put::<SimpleArchive, _>(
                    entity! {
                        resource_collection: collection,
                        resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key())
                            .binding(capability),
                    }
                    .facts()
                    .clone(),
                )
                .unwrap();
            let proof = CapabilityProof::new(
                CapabilityResource::from(resource),
                &resource_root,
                capability,
                puller.key.verifying_key(),
            );
            responder.store.insert_proof(proof.clone()).unwrap();
            let record = responder.commit(collection, 11);
            responder.observe();
            let evidence = |node: &Node| {
                let snapshot = node.walks.snapshot.as_ref().unwrap();
                snapshot
                    .collection(collection)
                    .unwrap()
                    .repair()
                    .authorization_evidence()
                    .get(proof.id())
                    .cloned()
            };
            assert_eq!(evidence(&responder), Some(proof.clone()));

            let mut wire = connect(&puller, &responder, 1);
            for attempt in 0..2 {
                puller
                    .walks
                    .start_record_pull(&wire.to_right, collection, now);
                carry(&mut puller, &mut responder, &mut wire, now);
                let (walk, fetched, descriptor) = puller.fetches.pop().unwrap();
                assert_eq!((fetched, descriptor), (proof.clone(), resource.raw));
                // The first fetch fails; the second gets the descriptor.
                let blob = (attempt == 1).then(|| {
                    BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(
                        &responder.store.snapshot().unwrap(),
                        triblespace_core::inline::Inline::new(resource.raw),
                    )
                    .unwrap()
                });
                puller.walks.fetched(walk, proof.clone(), blob, now);
                carry(&mut puller, &mut responder, &mut wire, now);
                assert_eq!(puller.records(collection), BTreeSet::from([record]));
                assert_eq!(puller.done[attempt].completed, attempt == 1);
                assert_eq!(evidence(&puller).is_some(), attempt == 1);
            }
        }

        /// A walk that waits past its deadline ends, and the walks beside it
        /// on the same connection go on.
        #[test]
        fn a_stalled_walk_ends_while_others_continue() {
            let start = crate::clock::mono_now();
            let mut puller = Node::new(12);
            let mut responder = Node::new(13);
            let stalled = puller.hold("stalled", open());
            let flowing = puller.hold("flowing", open());
            responder.hold("stalled", open());
            responder.hold("flowing", open());
            for data in 0..100 {
                responder.commit(stalled, data);
                responder.commit(flowing, data);
            }
            responder.observe();
            let mut wire = connect(&puller, &responder, 1);
            puller
                .walks
                .start_record_pull(&wire.to_right, stalled, start);
            puller
                .walks
                .start_record_pull(&wire.to_right, flowing, start);
            // The responder never answers the stalled collection's walks.
            let answered = |frame: &WalkFrame| frame.walk.collection == flowing;
            let later = start + (WALK_DEADLINE - Duration::from_secs(1));
            let mut steps = 0;
            while carry_while(&mut puller, &mut responder, &mut wire, later, answered) > 0
                && steps < 4
            {
                steps += 1;
            }
            puller.walks.expire(start + WALK_DEADLINE);
            puller.outputs(start + WALK_DEADLINE);
            assert_eq!(puller.done.len(), 2);
            let ended = |collection| {
                puller
                    .done
                    .iter()
                    .find(|done| done.collection == collection)
                    .unwrap()
                    .completed
            };
            assert!(!ended(stalled));
            assert!(ended(flowing));
            assert_eq!(puller.records(flowing).len(), 100);
            assert!(puller.records(stalled).is_empty());
            assert!(puller.walks.pulls.is_empty());
        }

        /// Astra's regression: a walk that timed out has a response and a
        /// landing acknowledgement still on their way when its successor
        /// starts. Neither advances nor aborts the successor.
        #[test]
        fn late_frames_and_acknowledgements_of_a_retired_walk_touch_no_successor() {
            let start = crate::clock::mono_now();
            let mut puller = Node::new(14);
            let mut responder = Node::new(15);
            let collection = puller.hold("retired", open());
            responder.hold("retired", open());
            let records = (0..80)
                .map(|data| responder.commit(collection, data))
                .collect::<BTreeSet<_>>();
            responder.observe();
            let mut wire = connect(&puller, &responder, 1);
            puller
                .walks
                .start_record_pull(&wire.to_right, collection, start);
            // Landing stalls, and one value response is held back.
            puller.hold = true;
            let mut late = None;
            carry_while(&mut puller, &mut responder, &mut wire, start, |frame| {
                if late.is_none()
                    && matches!(frame.body, WalkBody::Response(Response::Value { .. }))
                {
                    late = Some(frame.clone());
                    return false;
                }
                true
            });
            let late = late.expect("a value was in flight");
            assert!(!puller.held.is_empty());
            let expired = start + WALK_DEADLINE;
            puller.walks.expire(expired);
            puller.outputs(expired);
            assert!(!puller.done[0].completed);
            // The responder hears the ends and lets the pins go.
            carry(&mut puller, &mut responder, &mut wire, expired);
            assert!(responder.walks.served.is_empty());

            // The successor opens; its summaries arrive.
            puller
                .walks
                .start_record_pull(&wire.to_right, collection, expired);
            let successor =
                puller.walks.pulls[&(responder.id(), collection.raw, WalkKind::Records)].walk;
            assert_ne!(successor.number, late.walk.number);
            // Both opens cross, then both summaries.
            for _ in 0..4 {
                assert!(step(&mut puller, &mut responder, &mut wire, expired));
            }
            puller.outputs(expired);
            let sent_before = wire.from_left.len();
            let pull = &puller.walks.pulls[&(responder.id(), collection.raw, WalkKind::Records)];
            let (nodes_before, unlanded_before) = (pull.nodes.len(), pull.unlanded);

            // The late response and the late acknowledgements arrive.
            puller.walks.frame(&wire.to_right, late, expired);
            let held = std::mem::take(&mut puller.held);
            assert!(held.iter().all(|(walk, _)| walk.walk != successor));
            puller.hold = false;
            puller.land(held, expired);
            puller.outputs(expired);
            assert_eq!(wire.from_left.len(), sent_before, "no request followed");
            let pull = &puller.walks.pulls[&(responder.id(), collection.raw, WalkKind::Records)];
            assert_eq!(pull.walk, successor);
            assert_eq!(
                (pull.nodes.len(), pull.unlanded),
                (nodes_before, unlanded_before)
            );
            assert_eq!(
                puller.done.len(),
                1,
                "the successor neither completed nor failed"
            );

            carry(&mut puller, &mut responder, &mut wire, expired);
            assert_eq!(puller.records(collection), records);
            assert!(puller.done[1].completed, "{:?}", puller.done);
        }

        /// A record value that is not a foundation ends the walk: a MERGE
        /// never replicates.
        #[test]
        fn a_merge_value_fails_the_walk() {
            let now = crate::clock::mono_now();
            let mut puller = Node::new(16);
            let mut responder = Node::new(17);
            let collection = puller.hold("merge", open());
            responder.hold("merge", open());
            responder.commit(collection, 1);
            responder.observe();
            let mut wire = connect(&puller, &responder, 1);
            puller
                .walks
                .start_record_pull(&wire.to_right, collection, now);
            let merge = CollectionRecord::Merge(
                CollectionMerge::sign(
                    &responder.key,
                    collection,
                    [CollectionData::new([2; 32]), CollectionData::new([3; 32])],
                    CollectionData::new([4; 32]),
                )
                .unwrap(),
            );
            carry_while(&mut puller, &mut responder, &mut wire, now, |frame| {
                !matches!(frame.body, WalkBody::Response(Response::Value { .. }))
            });
            let requested = *puller.walks.pulls
                [&(responder.id(), collection.raw, WalkKind::Records)]
                .values
                .iter()
                .next()
                .unwrap();
            let walk =
                puller.walks.pulls[&(responder.id(), collection.raw, WalkKind::Records)].walk;
            puller.walks.frame(
                &wire.to_right,
                WalkFrame {
                    walk,
                    body: WalkBody::Response(Response::Value {
                        key: requested,
                        bytes: merge.to_bytes(),
                    }),
                },
                now,
            );
            carry(&mut puller, &mut responder, &mut wire, now);
            assert!(!puller.done[0].completed);
            assert!(puller.records(collection).is_empty());
        }
    }
}
