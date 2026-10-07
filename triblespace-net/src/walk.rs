//! Walk streams: each side pushes its collection trees to its neighbours
//! (design: walk streams).
//!
//! A push carries one tree of one collection, pinned when the push starts,
//! to one neighbour on a `walk/1` stream the sender opens
//! ([`crate::walk_stream`]). The sender ([`crate::push`]) sends the tree's
//! root and walks the part of it the neighbour has not confirmed; the
//! receiver ([`crate::receive`]) prunes with HELD bitmaps, asks for the
//! values it lacks and lands them through the landing task
//! ([`crate::landing`]); its LANDED confirms the push, and the pushed root
//! becomes the confirmed root for that peer, collection and tree, which an
//! unchanged tree is pushed as alone next time; the receiver remembers the
//! roots that landed from each peer the same way, so a root it landed is
//! held whole however its own tree grew since. A push that ends any other
//! way leaves the confirmed root as it was, and what landed stays.
//!
//! The kinds of tree are the collection's records, its authorization
//! evidence (keyed by proof id under the collection) and the blobs it holds,
//! as handles without values: a held reference the receiver lacks is noted
//! held when the blob is resident, and fetched by hash from the sender
//! first otherwise. A record lands as it is; a proof lands once its evidence
//! validates, fetches the descriptor of a resource it is routed through, or
//! stays deferred, which fails the push.
//!
//! The walks task runs one node's pushes and receives. A push runs only on
//! the current connection to its neighbour, and the task never dials; at
//! most one push per peer, collection and kind runs at a time. A push or a
//! receive ends after [`WALK_DEADLINE`] without a frame from the other side.
//! A second push of the same tree from a peer replaces the first, which is
//! reset. Walk streams count as in use on their connection, so a draining
//! connection waits for them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::debug;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, MemoryBlobStore};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId, QuorumOutcome};
use triblespace_core::collection::{CollectionHandle, CollectionRecordFingerprint, descriptor};
use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH};
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::TribleSet;

use crate::channel::NetEvent;
use crate::clock::Mono;
use crate::collection_activation::{
    CollectionAuthorizationEvidenceError, CollectionAuthorizationEvidencePatch,
    CollectionRepairOverlay,
};
use crate::collection_delta::{decode_record, encode_record};
use crate::connection::{
    Connection, ConnectionTable, RESET_WALK_FAILED, RESET_WALK_REFUSED, Service, open_walk,
    read_frame, write_frame,
};
use crate::health::Health;
use crate::host::{CollectionSnapshot, METADATA_BLOB_BYTES, StoreSnapshot};
use crate::landing::{LandSlot, Landed};
use crate::patch_repair::{
    PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchNodeResponse, PatchSummary,
    patch_node_response,
};
use crate::protocol::{MAX_EXACT_BLOB_BYTES, RawHash, op_get_blob_with_limit};
use crate::push::{ConfirmedRoots, Push, PushKey};
use crate::receive::{Out, Receive};
use crate::recon::Malformed;
use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport};
use crate::walk_stream::Frame;
use crate::{push, receive};

/// Bytes of every key a walk enumerates, relative to its kind's base.
pub(crate) const KEY_BYTES: usize = 32;
/// One child of a branch: edge, digest and leaf count.
const CHILD_BYTES: usize = 1 + 32 + 8;

const BRANCH: u8 = 1;
const LEAF: u8 = 2;

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
    pub(crate) const fn wire(self) -> u8 {
        match self {
            Self::Records => 0,
            Self::Authorization => 1,
            Self::References => 2,
        }
    }

    pub(crate) const fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Records),
            1 => Some(Self::Authorization),
            2 => Some(Self::References),
            _ => None,
        }
    }
}

/// Append a summary: its root, all zeros for the empty set, and its leaf
/// count.
pub(crate) fn push_summary(payload: &mut Vec<u8>, summary: PatchSummary) {
    payload.extend_from_slice(&summary.root().unwrap_or_default());
    payload.extend_from_slice(&summary.leaf_count().to_be_bytes());
}

/// Append a prefix: a length byte and the bytes.
pub(crate) fn push_prefix(payload: &mut Vec<u8>, prefix: &[u8]) {
    let length = u8::try_from(prefix.len()).expect("a prefix fits its key");
    payload.push(length);
    payload.extend_from_slice(prefix);
}

/// The tag [`Reader::node`] reads a node back under: whether it is a branch
/// or a leaf.
pub(crate) fn node_tag(node: &PatchNode<()>) -> u8 {
    match node {
        PatchNode::Branch { .. } => BRANCH,
        PatchNode::Leaf { .. } => LEAF,
    }
}

/// Append a node after its tag: its prefix, its digest, and a branch's leaf
/// count, representative, end depth and children, or a leaf's key. The
/// children run to the end of the frame, so a node is the last thing in it.
pub(crate) fn push_node(payload: &mut Vec<u8>, prefix: &[u8], node: &PatchNode<()>) {
    push_prefix(payload, prefix);
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

/// The unread rest of a walk frame.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl Reader<'_> {
    pub(crate) fn take(&mut self, length: usize) -> Result<Vec<u8>, Malformed> {
        if self.0.len() < length {
            return Err(Malformed("walk frame shorter than its fields"));
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken.to_vec())
    }

    pub(crate) fn byte(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn hash(&mut self) -> Result<[u8; 32], Malformed> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// A prefix as [`push_prefix`] writes it, at most a key long.
    pub(crate) fn prefix(&mut self) -> Result<Vec<u8>, Malformed> {
        let length = usize::from(self.byte()?);
        if length > KEY_BYTES {
            return Err(Malformed("walk node prefix longer than its key"));
        }
        self.take(length)
    }

    /// A summary as [`push_summary`] writes it.
    pub(crate) fn summary(&mut self) -> Result<PatchSummary, Malformed> {
        let root = self.hash()?;
        let count = self.u64()?;
        // A real root is a digest; all zeros stands for the empty set.
        let root = (root != [0; 32]).then_some(root);
        PatchSummary::new(root, count)
            .map_err(|_| Malformed("walk summary root and count disagree"))
    }

    /// A node as [`push_node`] writes it after `tag`, its prefix first. It
    /// takes the rest of the frame.
    pub(crate) fn node(&mut self, tag: u8) -> Result<(Vec<u8>, PatchNode<()>), Malformed> {
        let leaf = match tag {
            LEAF => true,
            BRANCH => false,
            _ => return Err(Malformed("walk node neither branch nor leaf")),
        };
        let prefix = self.prefix()?;
        let digest = self.hash()?;
        let node = if leaf {
            PatchNode::Leaf {
                digest,
                leaf: PatchLeaf {
                    key: self.take(KEY_BYTES)?,
                    value: (),
                },
            }
        } else {
            let leaf_count = self.u64()?;
            let representative = self.take(KEY_BYTES)?;
            let end_depth = self.byte()?;
            if self.0.len() % CHILD_BYTES != 0 {
                return Err(Malformed("walk branch children overrun their frame"));
            }
            let mut children = Vec::with_capacity(self.0.len() / CHILD_BYTES);
            while !self.0.is_empty() {
                children.push(PatchChild {
                    edge: self.byte()?,
                    digest: self.hash()?,
                    leaf_count: self.u64()?,
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
        Ok((prefix, node))
    }
}

/// A push or a receive ends after this long without a frame from the other
/// side, and a blob fetch of a receive after this long without its blob.
pub(crate) const WALK_DEADLINE: Duration = Duration::from_secs(60);
/// Value requests and blob fetches one receive keeps in flight.
pub(crate) const MAX_WALK_REQUESTS: usize = 64;
/// Values one receive hands to landing before they are acknowledged. A
/// receive whose landing queue is full reads no further.
pub(crate) const MAX_WALK_UNLANDED: usize = 1024;

/// What the walks tell the scheduler: a push of a tree from a neighbour is
/// being received here, or ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Receiving {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    Received {
        collection: CollectionHandle,
        kind: WalkKind,
        /// Everything pushed landed, and the sender's root is confirmed.
        landed: bool,
    },
}

/// One node's pushes: which run, the roots its neighbours confirmed, and
/// the roots that landed here from each of them.
pub(crate) struct Walks {
    health: Health,
    snapshot: Option<Arc<StoreSnapshot>>,
    /// Pushes running, by peer, collection and kind.
    pushes: HashSet<PushKey>,
    confirmed: ConfirmedRoots,
    /// The root of the last push from each peer of each tree that landed
    /// here: the receiver's side of the confirmed root.
    landed: HashMap<PushKey, PatchSummary>,
}

impl Walks {
    pub(crate) fn new(health: Health) -> Self {
        Self {
            health,
            snapshot: None,
            pushes: HashSet::new(),
            confirmed: ConfirmedRoots::default(),
            landed: HashMap::new(),
        }
    }

    /// Start a push of C's `kind` tree to `peer` on a `walk/1` stream of the
    /// caller's: the push and its first frames, if this side sends C to the
    /// peer and no push of this kind to it runs. [`Walks::pushed`] ends it.
    pub(crate) fn push(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
    ) -> Option<(Push, Vec<Frame>)> {
        let key = (peer, collection.raw, kind);
        if self.pushes.contains(&key) {
            return None;
        }
        let pinned = self
            .local(collection)
            .filter(|pinned| self.sends(peer, pinned))?;
        self.pushes.insert(key);
        Some(Push::start(kind, pinned, self.confirmed.root(key)))
    }

    /// The push of C's `kind` tree to `peer` ended, confirmed or not. Returns
    /// whether the tree here differs from the one pushed: the caller then
    /// pushes again at once.
    pub(crate) fn pushed(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        outcome: push::Outcome,
        now: Mono,
    ) -> bool {
        let key = (peer, collection.raw, kind);
        self.pushes.remove(&key);
        let root = outcome.root;
        self.health.with_peer(collection, peer, |health| {
            health.pushed(now, kind, root, outcome.confirmed)
        });
        let changed = self
            .local(collection)
            .is_some_and(|current| summary(kind, current.repair()) != root);
        self.confirmed.settle(key, outcome);
        changed
    }

    /// Admit a push of C's `kind` tree from `peer`, if this side receives
    /// C from it: the receive, told the root that last landed from the
    /// peer.
    fn receive(
        &self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
    ) -> Option<Receive> {
        let admitted = self
            .local(collection)
            .is_some_and(|live| self.receives(peer, &live));
        let landed = self.landed.get(&(peer, collection.raw, kind)).copied();
        Receive::on_open(peer, collection, kind, admitted, landed)
    }

    /// A push of C's `kind` tree from `peer` ended here: everything landed,
    /// or not. `root` is the tree's root, if the push got that far.
    pub(crate) fn received(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        root: Option<PatchSummary>,
        landed: bool,
        now: Mono,
    ) {
        if let Some(root) = root.filter(|_| landed) {
            self.landed.insert((peer, collection.raw, kind), root);
        }
        self.health.with_peer(collection, peer, |health| {
            health.received(now, kind, root, landed)
        });
    }

    /// Take the latest serving snapshot: what new pushes pin, and what an
    /// incoming push is admitted against.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) {
        self.snapshot = Some(snapshot);
    }

    fn local(&self, collection: CollectionHandle) -> Option<Arc<CollectionSnapshot>> {
        self.snapshot.as_ref()?.collection(collection)
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

    /// Whether this side receives C from `peer`, the mirror of
    /// [`Self::sends`]: its peering for C receives from the peer, or the
    /// peer passes WRITE under the live evidence.
    fn receives(&self, peer: PeerId, live: &CollectionSnapshot) -> bool {
        let collection = live.repair().collection();
        let mut flagged = false;
        self.health.update(|health| {
            flagged = health.peerings.iter().any(|peering| {
                peering.collection == collection
                    && peering.peer == peer
                    && peering.peered
                    && peering.receives
            });
        });
        flagged
            || VerifyingKey::from_bytes(&peer).is_ok_and(|peer| {
                let evidence = live.repair().authorization_evidence();
                let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
                matches!(
                    evidence.writer_is_admitted_by(peer, &proofs),
                    QuorumOutcome::Met
                )
            })
    }
}

/// What a receive does with a value, a missing leaf or a fetched blob once
/// it is checked.
pub(crate) enum Admit {
    /// Events for the landing task.
    Land(Vec<NetEvent>),
    /// Fetch a blob by hash from the peer: a held reference, or the routing
    /// descriptor a deferred `proof` names.
    Fetch {
        handle: RawHash,
        proof: Option<CapabilityProof>,
    },
    /// A proof over a resource routed to C that the evidence here cannot
    /// place yet stays deferred: the push does not land.
    Defer,
    /// A held reference that could not be fetched: the push does not land,
    /// and the blob stays in the next difference.
    Fail,
}

/// Check the value under `key` of a `kind` push of C against `evidence`
/// (design 2.5). A record lands; a proof lands once its evidence validates,
/// fetches the descriptor of the resource it is routed through, or stays
/// deferred. Held references carry no values.
pub(crate) fn admit_value(
    kind: WalkKind,
    collection: CollectionHandle,
    key: [u8; KEY_BYTES],
    bytes: &[u8],
    evidence: &CollectionAuthorizationEvidencePatch,
) -> anyhow::Result<Admit> {
    match kind {
        WalkKind::Records => {
            let record = decode_record(collection, bytes)?;
            if record.fingerprint().raw() != key {
                bail!("a record under another record's key");
            }
            Ok(Admit::Land(vec![NetEvent::CollectionRecord(record)]))
        }
        WalkKind::Authorization => {
            let proof = CapabilityProof::from_bytes(bytes)?;
            if proof.id().raw != key {
                bail!("a proof under another proof's key");
            }
            proof.verify_signatures()?;
            let routed = proof.resource().into_bytes() != collection.raw;
            match evidence.validate_proof(&proof) {
                Ok(()) => Ok(Admit::Land(vec![NetEvent::CapabilityProof(proof)])),
                // A proof over a resource routed to C needs that resource's
                // descriptor, which the peer holds.
                Err(CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(
                    descriptor,
                )) if routed => Ok(Admit::Fetch {
                    handle: descriptor.raw,
                    proof: Some(proof),
                }),
                Err(CollectionAuthorizationEvidenceError::WrongRoot) if routed => Ok(Admit::Defer),
                Err(error) => Err(error.into()),
            }
        }
        WalkKind::References => bail!("held references carry no values"),
    }
}

/// What a leaf of a `kind` push of C that the local store lacks needs. A
/// held reference joins the held set as it is when the blob is resident, and
/// is fetched by hash otherwise; `None` is a value to request from the peer.
pub(crate) fn admit_missing(
    kind: WalkKind,
    collection: CollectionHandle,
    key: [u8; KEY_BYTES],
    snapshot: Option<&StoreSnapshot>,
) -> Option<Admit> {
    if kind != WalkKind::References {
        return None;
    }
    let held = NetEvent::Held {
        collection,
        handle: key,
    };
    Some(
        if snapshot.is_some_and(|snapshot| snapshot.get_blob(&key).is_some()) {
            Admit::Land(vec![held])
        } else {
            Admit::Fetch {
                handle: key,
                proof: None,
            }
        },
    )
}

/// What a blob fetch of a push of C brought back. A fetched held reference
/// lands, noted held in C; one that could not be fetched fails. A deferred
/// `proof`'s descriptor that routes it to C lands with it; otherwise the
/// proof stays deferred.
pub(crate) fn admit_fetched(
    collection: CollectionHandle,
    handle: RawHash,
    proof: Option<CapabilityProof>,
    blob: Option<Blob<UnknownBlob>>,
) -> Admit {
    match (proof, blob) {
        (None, Some(blob)) => Admit::Land(vec![
            NetEvent::Blob(blob),
            NetEvent::Held { collection, handle },
        ]),
        (None, None) => Admit::Fail,
        (Some(proof), descriptor) => {
            match descriptor.filter(|descriptor| routes(collection, &proof, descriptor)) {
                Some(descriptor) => Admit::Land(vec![
                    NetEvent::Blob(descriptor),
                    NetEvent::CapabilityProof(proof),
                ]),
                None => Admit::Defer,
            }
        }
    }
}

/// The fixed key prefix each kind's PATCH puts before the walked key.
pub(crate) fn base(kind: WalkKind, collection: CollectionHandle) -> Vec<u8> {
    match kind {
        WalkKind::Authorization => collection.raw.to_vec(),
        WalkKind::Records | WalkKind::References => Vec::new(),
    }
}

pub(crate) fn summary(kind: WalkKind, overlay: &CollectionRepairOverlay) -> PatchSummary {
    match kind {
        WalkKind::Records => overlay.records().summary(),
        WalkKind::Authorization => overlay.authorization_evidence().summary(),
        WalkKind::References => PatchSummary::from_patch(overlay.blob_inventory()),
    }
}

/// The summary of the subtree at `prefix` of a kind's PATCH, relative to its
/// base, if present: what a subtree held here is compared with.
pub(crate) fn local_summary(
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

pub(crate) fn contains(kind: WalkKind, overlay: &CollectionRepairOverlay, key: &[u8]) -> bool {
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

/// The node at `prefix` of a kind's PATCH, relative to its base, if present.
pub(crate) fn node(
    kind: WalkKind,
    overlay: &CollectionRepairOverlay,
    prefix: &[u8],
) -> Option<PatchNode<()>> {
    let found = match kind {
        WalkKind::Records => {
            patch_node_response(overlay.records().patch(), &[], prefix, |_, _| Ok(()))
        }
        WalkKind::Authorization => patch_node_response(
            overlay.authorization_evidence().patch(),
            &overlay.collection().raw,
            prefix,
            |_, _| Ok(()),
        ),
        WalkKind::References => {
            patch_node_response(overlay.blob_inventory(), &[], prefix, |_, _| Ok(()))
        }
    };
    match found {
        Ok(PatchNodeResponse::Found(node)) => Some(node),
        _ => None,
    }
}

/// The value under `key` of a kind's PATCH, as it travels, if present. Held
/// references carry none.
pub(crate) fn value(
    kind: WalkKind,
    overlay: &CollectionRepairOverlay,
    key: [u8; KEY_BYTES],
) -> Option<Vec<u8>> {
    match kind {
        WalkKind::Records => overlay
            .records()
            .get(CollectionRecordFingerprint::from_raw(key))
            .and_then(|record| encode_record(overlay.collection(), record).ok()),
        WalkKind::Authorization => overlay
            .authorization_evidence()
            .get(CapabilityProofId::new(key))
            .map(|proof| proof.as_bytes().to_vec()),
        WalkKind::References => None,
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

/// Starts pushes through the walks task, and hands it the `walk/1` streams
/// peers open.
#[derive(Clone)]
pub(crate) struct WalksHandle(pub(crate) mpsc::UnboundedSender<Command>);

impl WalksHandle {
    /// Push C's `kind` tree to `peer`, on the current connection to it: a
    /// peer with none, a collection this side does not send the peer, and a
    /// push of this kind to it already running each start nothing.
    pub(crate) fn push(&self, peer: PeerId, collection: CollectionHandle, kind: WalkKind) {
        let _ = self.0.send(Command::Push {
            peer,
            collection,
            kind,
        });
    }

    /// A `walk/1` stream `peer` opened for C's `kind` tree, after its tag
    /// and Open frame were read. The stream is refused unless this side
    /// receives C from the peer, and reset when the walks task is gone.
    pub(crate) fn incoming(
        &self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        send: Box<dyn SendStream>,
        recv: Box<dyn RecvStream>,
    ) {
        let incoming = Command::Incoming {
            peer,
            collection,
            kind,
            send,
            recv,
        };
        if let Err(mpsc::error::SendError(Command::Incoming {
            mut send, mut recv, ..
        })) = self.0.send(incoming)
        {
            send.reset(RESET_WALK_FAILED);
            recv.stop(RESET_WALK_FAILED);
        }
    }
}

pub(crate) enum Command {
    Push {
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
    },
    /// A push's stream ended.
    Pushed {
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        outcome: push::Outcome,
    },
    /// A `walk/1` stream `peer` opened on its connection, after its tag and
    /// Open frame: a push of C's tree of `kind`, read from `recv` and
    /// answered on `send`.
    Incoming {
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        send: Box<dyn SendStream>,
        recv: Box<dyn RecvStream>,
    },
    /// An incoming walk stream ended.
    Received {
        id: u64,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        root: Option<PatchSummary>,
        landed: bool,
    },
}

/// Run one node's walks: its landing task, and a task that starts pushes,
/// receives the pushes of its peers and follows `snapshots`. Returns what
/// starts pushes, and where receives are reported for the scheduler.
pub(crate) fn spawn<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
    walks: Walks,
    lander: LandSlot,
) -> (WalksHandle, mpsc::UnboundedReceiver<Event>) {
    let (commands, commanded) = mpsc::unbounded_channel();
    let (landing, items) = mpsc::unbounded_channel();
    let (acks, landed) = mpsc::unbounded_channel();
    let (events, heard) = mpsc::unbounded_channel();
    tokio::spawn(crate::landing::run(lander, items, acks));
    // The connections hand the walk/1 streams peers open to this task.
    connections.walks(WalksHandle(commands.clone()));
    let task = Task {
        connections,
        snapshots: snapshots.clone(),
        walks,
        commands: WalksHandle(commands.clone()),
        landing,
        events,
        incoming: HashMap::new(),
        next_stream: 0,
    };
    tokio::spawn(task.run(snapshots, commanded, landed));
    (WalksHandle(commands), heard)
}

struct Task<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
    walks: Walks,
    /// Where pushes and incoming streams report back.
    commands: WalksHandle,
    /// Values for the landing task, by incoming stream.
    landing: mpsc::UnboundedSender<(u64, Vec<NetEvent>)>,
    events: mpsc::UnboundedSender<Event>,
    /// Incoming walk streams being received, by peer, collection and kind.
    incoming: HashMap<PushKey, Receiving>,
    next_stream: u64,
}

/// An incoming walk stream's driver, as the task reaches it.
struct Receiving {
    id: u64,
    /// Its landing acknowledgements.
    acks: mpsc::UnboundedSender<(u64, u64)>,
    /// Dropped to replace it: the driver resets the stream.
    _replace: oneshot::Sender<()>,
}

impl<T: Transport, S: Service> Task<T, S> {
    async fn run(
        mut self,
        mut snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut landed: mpsc::UnboundedReceiver<Landed<u64>>,
    ) {
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
                Some(command) = commands.recv() => self.command(command),
                Some(ack) = landed.recv() => {
                    if let Some(receiving) = self.incoming.values().find(|receiving| receiving.id == ack.key) {
                        let _ = receiving.acks.send((ack.landed, ack.failed));
                    }
                }
                else => return,
            }
        }
    }

    fn command(&mut self, command: Command) {
        let now = crate::clock::mono_now();
        match command {
            Command::Push {
                peer,
                collection,
                kind,
            } => self.push(peer, collection, kind),
            Command::Pushed {
                peer,
                collection,
                kind,
                outcome,
            } => {
                // The tree changed while the push ran: the next push goes
                // out at once, from the root just confirmed.
                if self.walks.pushed(peer, collection, kind, outcome, now) {
                    self.push(peer, collection, kind);
                }
            }
            Command::Incoming {
                peer,
                collection,
                kind,
                mut send,
                mut recv,
            } => {
                let Some(receive) = self.walks.receive(peer, collection, kind) else {
                    send.reset(RESET_WALK_REFUSED);
                    recv.stop(RESET_WALK_REFUSED);
                    return;
                };
                let id = self.next_stream;
                self.next_stream += 1;
                let (acks, acked) = mpsc::unbounded_channel();
                let (replace, replaced) = oneshot::channel();
                // A second push of the same tree from the peer replaces the
                // first, whose driver resets it.
                self.incoming.insert(
                    (peer, collection.raw, kind),
                    Receiving {
                        id,
                        acks,
                        _replace: replace,
                    },
                );
                let _ = self.events.send(Event::Receiving { collection, kind });
                let driver = Driver {
                    connections: self.connections.clone(),
                    snapshots: self.snapshots.clone(),
                    landing: self.landing.clone(),
                    commands: self.commands.0.clone(),
                    id,
                    peer,
                    collection,
                    kind,
                };
                tokio::spawn(receive_stream(driver, receive, send, recv, acked, replaced));
            }
            Command::Received {
                id,
                peer,
                collection,
                kind,
                root,
                landed,
            } => {
                self.incoming.retain(|_, receiving| receiving.id != id);
                self.walks
                    .received(peer, collection, kind, root, landed, now);
                let _ = self.events.send(Event::Received {
                    collection,
                    kind,
                    landed,
                });
            }
        }
    }

    /// Push C's `kind` tree to `peer` on the current connection to it, if
    /// there is one and the walks start the push.
    fn push(&mut self, peer: PeerId, collection: CollectionHandle, kind: WalkKind) {
        let Some(connection) = self.connections.current(peer) else {
            return;
        };
        let Some((push, frames)) = self.walks.push(peer, collection, kind) else {
            return;
        };
        let commands = self.commands.0.clone();
        tokio::spawn(async move {
            let outcome = push_stream(&connection, collection, kind, push, frames).await;
            let _ = commands.send(Command::Pushed {
                peer,
                collection,
                kind,
                outcome,
            });
        });
    }
}

/// Fetch `handle` from `peer` within [`WALK_DEADLINE`]: a `descriptor` is
/// metadata, a held reference may be any blob.
async fn fetch_blob<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    peer: PeerId,
    handle: RawHash,
    descriptor: bool,
) -> Option<Blob<UnknownBlob>> {
    let limit = if descriptor {
        METADATA_BLOB_BYTES
    } else {
        MAX_EXACT_BLOB_BYTES
    };
    let fetch = async {
        let connection = connections.current(peer)?;
        let local = connections.transport().local_id();
        op_get_blob_with_limit(&connection, local, &handle, limit)
            .await
            .ok()
            .flatten()
    };
    tokio::time::timeout(WALK_DEADLINE, fetch)
        .await
        .ok()
        .flatten()
}

async fn write<W: AsyncWrite + Unpin>(send: &mut W, frame: &Frame) -> anyhow::Result<()> {
    let (kind, payload) = frame.encode();
    write_frame(send, kind, &payload).await
}

/// Drive one push on a `walk/1` stream opened on `connection`: the tag and
/// Open, the push's first frames, then each of the receiver's frames through
/// the push and its answers back, until Landed, which finishes the stream
/// and confirms the push, or a failure, a reset, the end of the stream or
/// [`WALK_DEADLINE`] without a frame, which reset it and leave the push
/// unconfirmed.
async fn push_stream<C: Conn>(
    connection: &Connection<C>,
    collection: CollectionHandle,
    kind: WalkKind,
    mut push: Push,
    frames: Vec<Frame>,
) -> push::Outcome {
    let Ok((mut send, recv)) = open_walk(connection, collection, kind).await else {
        return push.outcome();
    };
    let (framed, mut heard) = mpsc::channel(1);
    let reader = tokio::spawn(read_stream(Box::new(recv), framed));
    let failed = 'drive: {
        for frame in &frames {
            if write(&mut send, frame).await.is_err() {
                break 'drive true;
            }
        }
        loop {
            let Some(Some(frame)) = heard.recv().await else {
                break 'drive true;
            };
            let landed = frame == Frame::Landed;
            let answers = match push.on_frame(frame) {
                Ok(answers) => answers,
                Err(push::Failed(violation)) => {
                    debug!(violation, "walk/1 push failed");
                    break 'drive true;
                }
            };
            for answer in &answers {
                if write(&mut send, answer).await.is_err() {
                    break 'drive true;
                }
            }
            if landed {
                break 'drive false;
            }
        }
    };
    reader.abort();
    if failed {
        send.reset(RESET_WALK_FAILED);
    } else {
        let _ = send.shutdown().await;
    }
    push.outcome()
}

/// What one incoming walk stream's driver holds of the task.
struct Driver<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
    landing: mpsc::UnboundedSender<(u64, Vec<NetEvent>)>,
    commands: mpsc::UnboundedSender<Command>,
    id: u64,
    peer: PeerId,
    collection: CollectionHandle,
    kind: WalkKind,
}

/// A blob fetch's result, as a driver hears it.
type Fetched = (RawHash, Option<CapabilityProof>, Option<Blob<UnknownBlob>>);

/// Drive one incoming walk stream: feed its frames, while the receive wants
/// them, and what landing and blob fetches report to the [`Receive`], write
/// what it sends, and end the stream as the push did: finished after
/// `Landed`, reset otherwise. A stream whose push makes no progress for
/// [`WALK_DEADLINE`] is reset too.
async fn receive_stream<T: Transport, S: Service>(
    driver: Driver<T, S>,
    mut receive: Receive,
    mut send: Box<dyn SendStream>,
    recv: Box<dyn RecvStream>,
    mut acked: mpsc::UnboundedReceiver<(u64, u64)>,
    mut replaced: oneshot::Receiver<()>,
) {
    let (frames, mut framed) = mpsc::channel(1);
    let reader = tokio::spawn(read_stream(recv, frames));
    let (fetches, mut fetched) = mpsc::unbounded_channel::<Fetched>();
    let outcome = 'drive: loop {
        if let Some(outcome) = receive.outcome() {
            break Some(outcome);
        }
        let outs = tokio::select! {
            frame = framed.recv(), if receive.want_read() => match frame {
                Some(Some(frame)) => receive.on_frame(frame, driver.snapshots.borrow().clone()),
                Some(None) | None => break None,
            },
            Some((landed, failed)) = acked.recv() => receive.on_landed_ack(landed, failed),
            Some((handle, proof, blob)) = fetched.recv() => receive.on_fetched(handle, proof, blob),
            _ = &mut replaced => break None,
            else => break None,
        };
        for out in outs {
            match out {
                Out::Send(frame) => {
                    if write(&mut send, &frame).await.is_err() {
                        break 'drive None;
                    }
                }
                Out::Land(events) => {
                    let _ = driver.landing.send((driver.id, events));
                }
                Out::Fetch { handle, proof } => {
                    let connections = driver.connections.clone();
                    let fetches = fetches.clone();
                    let peer = driver.peer;
                    tokio::spawn(async move {
                        let blob = fetch_blob(connections, peer, handle, proof.is_some()).await;
                        let _ = fetches.send((handle, proof, blob));
                    });
                }
            }
        }
    };
    reader.abort();
    match outcome {
        Some(receive::Outcome::Landed) => {
            let _ = send.shutdown().await;
        }
        Some(receive::Outcome::Failed(failure)) => {
            debug!(?failure, "walk/1 push failed");
            send.reset(RESET_WALK_FAILED);
        }
        None => send.reset(RESET_WALK_FAILED),
    }
    let _ = driver.commands.send(Command::Received {
        id: driver.id,
        peer: driver.peer,
        collection: driver.collection,
        kind: driver.kind,
        root: receive.root(),
        landed: outcome == Some(receive::Outcome::Landed),
    });
}

/// Read a walk stream's frames to `frames`, one ahead of the driver, so no
/// frame is left half read when the driver turns to something else;
/// `None` ends it: the stream ended, failed, carried a malformed frame, or
/// went [`WALK_DEADLINE`] without one.
async fn read_stream(mut recv: Box<dyn RecvStream>, frames: mpsc::Sender<Option<Frame>>) {
    loop {
        let frame = match tokio::time::timeout(WALK_DEADLINE, read_frame(&mut recv)).await {
            Ok(Ok(Some((kind, payload)))) => match Frame::decode(kind, &payload) {
                Ok(Some(frame)) => Some(frame),
                Ok(None) => continue,
                Err(Malformed(violation)) => {
                    debug!(violation, "malformed walk/1 frame");
                    None
                }
            },
            Ok(Ok(None)) => None,
            Ok(Err(error)) => {
                debug!(?error, "walk/1 stream failed");
                None
            }
            Err(_) => {
                debug!("walk/1 stream deadline exceeded");
                None
            }
        };
        let ended = frame.is_none();
        if frames.send(frame).await.is_err() || ended {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One node's store, serving snapshot and walks, for the push and
    /// receive tests.
    pub(crate) mod walking {
        use super::*;

        use std::collections::BTreeSet;

        use ed25519_dalek::SigningKey;
        use iroh_base::EndpointId;
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy, CollectionRead,
            CollectionRecord, CollectionStore, CollectionStoreExt, HeldStore,
            empty_metadata_handle,
        };
        use triblespace_core::patch::Entry as PatchEntry;
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_core::repo::{BlobStorePut, CapabilityProofStore, StoreChanges};

        use crate::health::CollectionHealth;
        use crate::host::ActiveCollections;

        pub(crate) fn key(byte: u8) -> SigningKey {
            SigningKey::from_bytes(&[byte; 32])
        }

        pub(crate) fn open() -> CollectionPolicy {
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open)
        }

        /// One node: its store, its active collections and its walks.
        pub(crate) struct Node {
            pub(crate) key: SigningKey,
            pub(crate) store: MemoryRepo,
            pub(crate) active: ActiveCollections,
            pub(crate) walks: Walks,
            pub(crate) health: Health,
        }

        impl Node {
            pub(crate) fn new(byte: u8) -> Self {
                let key = key(byte);
                let health =
                    Health::new(EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap());
                Self {
                    walks: Walks::new(health.clone()),
                    health,
                    key,
                    store: MemoryRepo::default(),
                    active: ActiveCollections::new(),
                }
            }

            pub(crate) fn id(&self) -> PeerId {
                self.key.verifying_key().to_bytes()
            }

            /// Hold the collection `name` names: active here, and observed
            /// by health.
            pub(crate) fn hold(
                &mut self,
                name: &str,
                policy: CollectionPolicy,
            ) -> CollectionHandle {
                let collection = self.store.collection(name, policy).unwrap().handle();
                self.active.insert(&PatchEntry::new(&collection.raw));
                self.health.update(|health| {
                    health.collections.push(CollectionHealth {
                        collection,
                        local_frontier: None,
                        last_local_change_at: None,
                        peers: Vec::new(),
                    })
                });
                self.observe();
                collection
            }

            pub(crate) fn commit(
                &mut self,
                collection: CollectionHandle,
                data: u64,
            ) -> CollectionRecord {
                let record = CollectionRecord::Commit(CollectionCommit::sign(
                    &self.key,
                    collection,
                    CollectionData::new(*blake3::hash(&data.to_be_bytes()).as_bytes()),
                    empty_metadata_handle(),
                ));
                self.store.insert(record).unwrap();
                record
            }

            pub(crate) fn observe(&mut self) {
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

            /// The serving snapshot the walks last observed.
            pub(crate) fn serving(&self) -> &StoreSnapshot {
                self.walks.snapshot.as_deref().unwrap()
            }

            pub(crate) fn snapshot(&self) -> Arc<StoreSnapshot> {
                self.walks.snapshot.clone().unwrap()
            }

            pub(crate) fn records(
                &mut self,
                collection: CollectionHandle,
            ) -> BTreeSet<CollectionRecord> {
                self.store
                    .snapshot()
                    .unwrap()
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .filter(|record| record.collection() == collection)
                    .collect()
            }

            /// Insert each event; how many landed and how many failed.
            pub(crate) fn insert(&mut self, events: Vec<NetEvent>) -> (u64, u64) {
                let (mut landed, mut failed) = (0, 0);
                for event in events {
                    let ok = match event {
                        NetEvent::CollectionRecord(record) => self.store.insert(record).is_ok(),
                        NetEvent::CapabilityProof(proof) => self.store.insert_proof(proof).is_ok(),
                        NetEvent::Blob(blob) => self.store.put::<UnknownBlob, _>(blob).is_ok(),
                        NetEvent::Held { collection, handle } => {
                            self.store.note_held(
                                collection,
                                triblespace_core::inline::Inline::new(handle),
                            );
                            true
                        }
                    };
                    if ok {
                        landed += 1;
                    } else {
                        failed += 1;
                    }
                }
                (landed, failed)
            }
        }
    }

    /// Walk streams driven through the walks task over the simulated
    /// transport: a scripted sender pushes over a duplex pipe, and the task
    /// admits, receives, lands through the landing task and ends the
    /// stream; and the task's own push driver, over a connection into
    /// another task.
    #[cfg(feature = "sim")]
    mod receiving {
        use super::walking::{Node, open};
        use super::*;

        use std::collections::BTreeSet;
        use std::future::Future;
        use std::io;
        use std::pin::Pin;
        use std::sync::Mutex;
        use std::task::{Context, Poll};

        use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionPolicy, CollectionRecord, CollectionStore,
        };

        use crate::health::PeerHealth;
        use crate::landing::Land;
        use crate::protocol::TAG_WALK;
        use crate::transport::sim::{Crossed, SimConfig, SimNet, Tapped, Taps};
        use crate::walk_stream::{
            FRAME_DONE, FRAME_LANDED, FRAME_LEAF, FRAME_OPEN, FRAME_ROOT, FRAME_VALUE_REQUEST, held,
        };

        #[derive(Clone)]
        struct NoRequests;

        impl Service for NoRequests {
            async fn serve<W, R>(
                &self,
                _peer: PeerId,
                _tag: u8,
                _send: &mut W,
                _recv: &mut R,
            ) -> anyhow::Result<()>
            where
                W: SendStream,
                R: RecvStream,
            {
                anyhow::bail!("no request streams here")
            }
        }

        /// The halves of a duplex pipe as stream halves; a reset or stop is
        /// noted, not carried.
        struct Tx(WriteHalf<DuplexStream>, Arc<Mutex<Option<u32>>>);
        struct Rx(ReadHalf<DuplexStream>, Arc<Mutex<Option<u32>>>);

        impl AsyncWrite for Tx {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }

        impl SendStream for Tx {
            fn reset(&mut self, code: u32) {
                *self.1.lock().unwrap() = Some(code);
            }
        }

        impl AsyncRead for Rx {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, buf)
            }
        }

        impl RecvStream for Rx {
            fn stop(&mut self, code: u32) {
                *self.1.lock().unwrap() = Some(code);
            }
        }

        /// The node as the landing task's store side: inserts, then
        /// publishes the next serving snapshot.
        struct Lander {
            node: Mutex<Node>,
            snapshots: watch::Sender<Option<Arc<StoreSnapshot>>>,
        }

        impl Land for Lander {
            fn land(&self, events: Vec<NetEvent>) -> Vec<bool> {
                let mut node = self.node.lock().unwrap();
                let landed = events
                    .into_iter()
                    .map(|event| node.insert(vec![event]) == (1, 0))
                    .collect();
                node.observe();
                self.snapshots.send_replace(Some(node.snapshot()));
                landed
            }

            fn reobserve(&self) {}
        }

        /// A node on `net` behind a running walks task, through a tap: its
        /// table dials and accepts, the walk streams peers open reach the
        /// task, and the task's pushes go out on its connections.
        struct Hosted {
            peer: PeerId,
            lander: Arc<Lander>,
            walks: WalksHandle,
            table: ConnectionTable<Tapped, NoRequests>,
            taps: Taps,
            events: mpsc::UnboundedReceiver<Event>,
            server: tokio::task::JoinHandle<()>,
        }

        impl Hosted {
            fn new(node: Node, net: &SimNet) -> Self {
                let (mut harness, taps) = net.tap(&node.key);
                let peer = harness.transport.local_id();
                let table = ConnectionTable::new(harness.transport, NoRequests);
                let accepting = table.clone();
                let server = tokio::spawn(async move {
                    while let Some(incoming) = harness.incoming.recv().await {
                        accepting.accept(incoming.conn);
                    }
                });
                let (snapshots, snapshot) = watch::channel(Some(node.snapshot()));
                let walks = Walks::new(node.health.clone());
                let lander = Arc::new(Lander {
                    node: Mutex::new(node),
                    snapshots,
                });
                let (slot, lands) = watch::channel(Some(lander.clone() as Arc<dyn Land>));
                std::mem::forget(slot);
                let (walks, events) = spawn(table.clone(), snapshot, walks, lands);
                Self {
                    peer,
                    lander,
                    walks,
                    table,
                    taps,
                    events,
                    server,
                }
            }

            /// Open a scripted stream for C's records from `peer`; the
            /// opener's halves, and where the receiver's reset of it is
            /// noted.
            fn open(
                &self,
                peer: PeerId,
                collection: CollectionHandle,
            ) -> (
                WriteHalf<DuplexStream>,
                ReadHalf<DuplexStream>,
                Arc<Mutex<Option<u32>>>,
            ) {
                let (opener, acceptor) = tokio::io::duplex(1 << 20);
                let (recv, send) = tokio::io::split(acceptor);
                let reset = Arc::new(Mutex::new(None));
                self.walks.incoming(
                    peer,
                    collection,
                    WalkKind::Records,
                    Box::new(Tx(send, reset.clone())),
                    Box::new(Rx(recv, reset.clone())),
                );
                let (from, to) = tokio::io::split(opener);
                (to, from, reset)
            }

            fn records(&self, collection: CollectionHandle) -> BTreeSet<CollectionRecord> {
                self.lander.node.lock().unwrap().records(collection)
            }

            /// What health recorded of the pair with `peer` for C.
            fn health(&self, collection: CollectionHandle, peer: PeerId) -> Option<PeerHealth> {
                let node = self.lander.node.lock().unwrap();
                let health = node.health.snapshot();
                health
                    .collections
                    .iter()
                    .find(|entry| entry.collection == collection)?
                    .peers
                    .iter()
                    .find(|entry| entry.peer == peer)
                    .cloned()
            }

            /// Push C's `kind` tree to `peer` through the walks task and
            /// wait for the push to end; what health recorded of the pair.
            async fn push(
                &self,
                peer: PeerId,
                collection: CollectionHandle,
                kind: WalkKind,
            ) -> PeerHealth {
                let ended = |health: &PeerHealth| health.pushes.ok + health.pushes.failed;
                let before = self.health(collection, peer).as_ref().map_or(0, ended);
                self.walks.push(peer, collection, kind);
                for _ in 0..1_000 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    if let Some(health) = self.health(collection, peer)
                        && ended(&health) > before
                    {
                        return health;
                    }
                }
                panic!("the push never ended");
            }
        }

        impl Drop for Hosted {
            fn drop(&mut self) {
                self.server.abort();
            }
        }

        async fn write<W: AsyncWrite + Unpin>(send: &mut W, frame: Frame) {
            let (kind, payload) = frame.encode();
            write_frame(send, kind, &payload).await.unwrap();
        }

        async fn read<R: AsyncRead + Unpin>(recv: &mut R) -> Option<Frame> {
            let (kind, payload) = read_frame(recv).await.ok()??;
            Frame::decode(kind, &payload).unwrap()
        }

        /// Wait for the receiver to reset or stop the stream.
        async fn reset(reset: &Mutex<Option<u32>>) -> Option<u32> {
            for _ in 0..500 {
                if let Some(code) = *reset.lock().unwrap() {
                    return Some(code);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            None
        }

        /// Push `sender`'s records of C over the stream as a sender does,
        /// skipping what each reply says is held and answering value
        /// requests, until the receiver says everything landed or ends the
        /// stream, or `cut` values were answered. Returns whether it landed.
        async fn push(
            sender: &Node,
            collection: CollectionHandle,
            send: &mut WriteHalf<DuplexStream>,
            recv: &mut ReadHalf<DuplexStream>,
            cut: usize,
        ) -> bool {
            let kind = WalkKind::Records;
            let overlay = sender.serving().collection(collection).unwrap();
            let overlay = overlay.repair();
            let mut answered = 0;
            let value = |key| Frame::Value {
                key,
                bytes: value(kind, overlay, key).unwrap(),
            };
            write(
                send,
                Frame::Root {
                    summary: summary(kind, overlay),
                },
            )
            .await;
            let mut stack = vec![Vec::new()];
            while let Some(prefix) = stack.pop() {
                match node(kind, overlay, &prefix).unwrap() {
                    PatchNode::Leaf { leaf, .. } => {
                        let key = <[u8; 32]>::try_from(leaf.key).unwrap();
                        write(send, Frame::Leaf { key }).await;
                    }
                    pushed @ PatchNode::Branch { .. } => {
                        let PatchNode::Branch { branch, .. } = pushed.clone() else {
                            unreachable!()
                        };
                        write(
                            send,
                            Frame::Node {
                                prefix: prefix.clone(),
                                node: pushed,
                            },
                        )
                        .await;
                        let children = loop {
                            match read(recv).await {
                                Some(Frame::Held {
                                    prefix: p,
                                    children,
                                }) if p == prefix => {
                                    break children;
                                }
                                Some(Frame::ValueRequest { key }) => {
                                    if answered == cut {
                                        return false;
                                    }
                                    answered += 1;
                                    write(send, value(key)).await;
                                }
                                other => panic!("waiting for a reply: {other:?}"),
                            }
                        };
                        let end = usize::from(branch.end_depth);
                        for child in branch.children.iter().rev() {
                            if !held(&children, child.edge) {
                                let mut locator = branch.representative[..end].to_vec();
                                locator.push(child.edge);
                                stack.push(locator);
                            }
                        }
                    }
                }
            }
            write(send, Frame::Done).await;
            loop {
                match read(recv).await {
                    Some(Frame::Landed) => return true,
                    Some(Frame::ValueRequest { key }) => {
                        if answered == cut {
                            return false;
                        }
                        answered += 1;
                        write(send, value(key)).await;
                    }
                    Some(Frame::Held { .. }) => {}
                    Some(other) => panic!("waiting for Landed: {other:?}"),
                    None => return false,
                }
            }
        }

        /// A push from an admitted peer lands through the landing task and
        /// ends with Landed and a finished stream; one from a peer the
        /// receiver does not receive from is refused.
        #[tokio::test]
        async fn an_incoming_stream_lands_through_the_task_or_is_refused() {
            let mut sender = Node::new(50);
            let mut receiver = Node::new(51);
            let collection = sender.hold("stream", open());
            receiver.hold("stream", open());
            let owner = Node::new(52);
            let private = CollectionPolicy::new(
                AdmissionPolicy::direct(owner.key.verifying_key()),
                AdmissionPolicy::direct(owner.key.verifying_key()),
            );
            let refused = sender.hold("refused", private.clone());
            receiver.hold("refused", private);
            let records = (0..200)
                .map(|data| sender.commit(collection, data))
                .collect::<BTreeSet<_>>();
            for record in records.iter().take(50) {
                receiver.store.insert(*record).unwrap();
            }
            sender.observe();
            receiver.observe();
            let mut receiving = Hosted::new(receiver, &SimNet::new(1, SimConfig::default()));

            let (mut send, mut recv, landed) = receiving.open(sender.id(), collection);
            assert!(push(&sender, collection, &mut send, &mut recv, usize::MAX).await);
            assert!(read(&mut recv).await.is_none(), "the stream finished");
            assert_eq!(*landed.lock().unwrap(), None);
            assert_eq!(receiving.records(collection), records);
            let health = receiving.health(collection, sender.id()).unwrap();
            assert!(health.receives.last_ok && health.receives.ok == 1);
            assert_eq!(
                health.received.records,
                Some(summary(
                    WalkKind::Records,
                    sender.serving().collection(collection).unwrap().repair()
                ))
            );
            assert_eq!(
                receiving.events.try_recv(),
                Ok(Event::Receiving {
                    collection,
                    kind: WalkKind::Records
                })
            );
            assert_eq!(
                receiving.events.try_recv(),
                Ok(Event::Received {
                    collection,
                    kind: WalkKind::Records,
                    landed: true
                })
            );

            // A second push of the same tree is held whole at its first
            // node.
            let (mut send, mut recv, _) = receiving.open(sender.id(), collection);
            assert!(push(&sender, collection, &mut send, &mut recv, usize::MAX).await);

            let (_send, _recv, refusal) = receiving.open(sender.id(), refused);
            assert_eq!(reset(&refusal).await, Some(RESET_WALK_REFUSED));
            assert!(receiving.health(refused, sender.id()).is_none());
        }

        /// A second stream from the peer for the same tree replaces the
        /// first, which is reset; a push that omits a leaf is reset too.
        #[tokio::test]
        async fn a_replaced_or_failed_stream_is_reset() {
            let mut sender = Node::new(53);
            let mut receiver = Node::new(54);
            let collection = sender.hold("replaced", open());
            receiver.hold("replaced", open());
            let records = (0..20)
                .map(|data| sender.commit(collection, data))
                .collect::<Vec<_>>();
            sender.observe();
            receiver.observe();
            let receiving = Hosted::new(receiver, &SimNet::new(2, SimConfig::default()));
            let overlay = sender.serving().collection(collection).unwrap();
            let root = summary(WalkKind::Records, overlay.repair());

            let (mut first, _first_recv, first_reset) = receiving.open(sender.id(), collection);
            write(&mut first, Frame::Root { summary: root }).await;
            let (mut second, mut second_recv, second_reset) =
                receiving.open(sender.id(), collection);
            assert_eq!(reset(&first_reset).await, Some(RESET_WALK_FAILED));

            // The second pushes every leaf but one.
            write(&mut second, Frame::Root { summary: root }).await;
            for record in &records[1..] {
                write(
                    &mut second,
                    Frame::Leaf {
                        key: record.fingerprint().raw(),
                    },
                )
                .await;
            }
            write(&mut second, Frame::Done).await;
            assert_eq!(reset(&second_reset).await, Some(RESET_WALK_FAILED));
            // Its value requests went out before the end failed it.
            let mut requested = 0;
            while let Some(Frame::ValueRequest { .. }) = read(&mut second_recv).await {
                requested += 1;
            }
            assert_eq!(requested, 19);
            let health = receiving.health(collection, sender.id()).unwrap();
            assert_eq!((health.receives.ok, health.receives.failed), (0, 2));
            assert!(!health.receives.last_ok);
        }

        /// The frame kinds that crossed `taps` since `from` on walk streams
        /// to `peer`, those this side sent and those it heard.
        fn crossed(taps: &Taps, from: usize, peer: PeerId) -> (Vec<u8>, Vec<u8>) {
            let crossed = taps.since(from, peer, TAG_WALK);
            let kinds = |sent: bool| {
                crossed
                    .iter()
                    .filter(|crossed: &&Crossed| crossed.sent == sent)
                    .map(|crossed| crossed.kind)
                    .collect::<Vec<_>>()
            };
            (kinds(true), kinds(false))
        }

        fn count(kinds: &[u8], kind: u8) -> usize {
            kinds.iter().filter(|crossed| **crossed == kind).count()
        }

        /// The walks task's push driver over a simulated connection into
        /// another task's receiver. (a) Fifty records to an empty receiver:
        /// all land, Landed comes back, and the push is confirmed. (b) The
        /// confirmed tree again: Root then Done, answered with Landed alone.
        /// (c) A receiver holding forty of the fifty from elsewhere: its
        /// HELD prunes, so fewer than fifty leaves and exactly the ten
        /// missing values cross, and the ten land.
        #[tokio::test(start_paused = true)]
        async fn a_push_over_a_connection_lands_confirms_and_prunes() {
            let net = SimNet::new(
                0x3A1E,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let kind = WalkKind::Records;
            let mut sender = Node::new(55);
            let collection = sender.hold("pushed", open());
            let records = (0..50)
                .map(|data| sender.commit(collection, data))
                .collect::<Vec<_>>();
            sender.observe();
            let root = summary(
                kind,
                sender.serving().collection(collection).unwrap().repair(),
            );
            let all = records.iter().copied().collect::<BTreeSet<_>>();
            let sender = Hosted::new(sender, &net);
            let mut empty = Node::new(56);
            empty.hold("pushed", open());
            empty.observe();
            let mut empty = Hosted::new(empty, &net);
            let _connection = sender.table.connect(empty.peer).await.unwrap();

            // (a) Everything lands, and the push is confirmed.
            let from = sender.taps.len();
            let health = sender.push(empty.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
            assert_eq!(health.confirmed.records, Some(root));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(heard.last(), Some(&FRAME_LANDED));
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 50);
            assert_eq!(count(&sent, FRAME_LEAF), 50);
            assert_eq!(empty.records(collection), all);
            assert_eq!(
                empty.events.try_recv(),
                Ok(Event::Receiving { collection, kind })
            );
            assert_eq!(
                empty.events.try_recv(),
                Ok(Event::Received {
                    collection,
                    kind,
                    landed: true
                })
            );

            // (b) The confirmed tree is Root then Done, answered with
            // Landed alone.
            let from = sender.taps.len();
            let health = sender.push(empty.peer, collection, kind).await;
            assert_eq!((health.pushes.ok, health.pushes.failed), (2, 0));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(sent, [FRAME_OPEN, FRAME_ROOT, FRAME_DONE]);
            assert_eq!(heard, [FRAME_LANDED]);

            // The receiver commits a record of its own, so its tree is a
            // superset of the sender's: the unchanged push still lands on
            // the root it landed before.
            {
                let mut node = empty.lander.node.lock().unwrap();
                node.commit(collection, 1_000);
                node.observe();
                let snapshot = node.snapshot();
                empty.lander.snapshots.send_replace(Some(snapshot));
            }
            let from = sender.taps.len();
            let health = sender.push(empty.peer, collection, kind).await;
            assert_eq!((health.pushes.ok, health.pushes.failed), (3, 0));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(sent, [FRAME_OPEN, FRAME_ROOT, FRAME_DONE]);
            assert_eq!(heard, [FRAME_LANDED]);
            assert_eq!(empty.records(collection).len(), 51);

            // (c) A receiver that holds forty of the fifty prunes.
            let mut partial = Node::new(57);
            partial.hold("pushed", open());
            for record in &records[..40] {
                partial.store.insert(*record).unwrap();
            }
            partial.observe();
            let partial = Hosted::new(partial, &net);
            let _connection = sender.table.connect(partial.peer).await.unwrap();
            let from = sender.taps.len();
            let health = sender.push(partial.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            let (sent, heard) = crossed(&sender.taps, from, partial.peer);
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 10);
            let leaves = count(&sent, FRAME_LEAF);
            assert!(leaves < 50, "{leaves} leaves crossed: nothing was pruned");
            assert!(leaves >= 10);
            assert_eq!(partial.records(collection), all);

            // A peer with no current connection gets no push at all.
            let stranger = Node::new(58).id();
            sender.walks.push(stranger, collection, kind);
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(sender.health(collection, stranger).is_none());
        }

        /// A push cut after some values landed leaves them, fails the receive
        /// and leaves the sender's confirmed root as it was. The next push,
        /// driven by the walks task over a connection, is pruned by what
        /// landed: exactly the rest is asked for, and it lands.
        #[tokio::test(start_paused = true)]
        async fn a_push_cut_mid_way_leaves_what_landed_and_the_next_push_asks_for_the_rest() {
            let net = SimNet::new(
                0x3A1F,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let kind = WalkKind::Records;
            let mut sender = Node::new(59);
            let collection = sender.hold("cut", open());
            let records = (0..300)
                .map(|data| sender.commit(collection, data))
                .collect::<BTreeSet<_>>();
            sender.observe();
            let root = summary(
                kind,
                sender.serving().collection(collection).unwrap().repair(),
            );
            let mut receiver = Node::new(60);
            receiver.hold("cut", open());
            receiver.observe();
            let receiver = Hosted::new(receiver, &net);

            // The first push, scripted, answers fifty values and drops the
            // stream.
            let (send, recv, reset) = receiving_cut(&receiver, &sender, collection).await;
            drop((send, recv));
            assert_eq!(reset.await, Some(RESET_WALK_FAILED));
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if receiver
                    .health(collection, sender.id())
                    .is_some_and(|health| health.receives.failed == 1)
                {
                    break;
                }
            }
            let landed = receiver.records(collection).len();
            assert!(landed > 0 && landed < 300, "{landed} landed");
            let health = receiver.health(collection, sender.id()).unwrap();
            assert!(!health.receives.last_ok && health.received.records.is_none());

            // The sender never confirmed anything, and its next push asks
            // only for the rest.
            let sender = Hosted::new(sender, &net);
            assert!(sender.health(collection, receiver.peer).is_none());
            let _connection = sender.table.connect(receiver.peer).await.unwrap();
            let from = sender.taps.len();
            let health = sender.push(receiver.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!(health.confirmed.records, Some(root));
            let (sent, heard) = crossed(&sender.taps, from, receiver.peer);
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 300 - landed);
            assert!(count(&sent, FRAME_LEAF) < 300);
            assert_eq!(receiver.records(collection), records);
        }

        /// Open a scripted stream from `sender` to `receiver` and push until
        /// fifty values were answered: the halves, still open, and the
        /// receiver's reset of the stream once they drop.
        async fn receiving_cut(
            receiver: &Hosted,
            sender: &Node,
            collection: CollectionHandle,
        ) -> (
            WriteHalf<DuplexStream>,
            ReadHalf<DuplexStream>,
            impl Future<Output = Option<u32>>,
        ) {
            let (mut send, mut recv, reset_code) = receiver.open(sender.id(), collection);
            assert!(!push(sender, collection, &mut send, &mut recv, 50).await);
            (send, recv, async move { reset(&reset_code).await })
        }
    }
}
