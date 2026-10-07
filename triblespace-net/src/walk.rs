//! Walk streams: each side exchanges its collection trees with its
//! neighbours (design: walk streams).
//!
//! An exchange carries one tree of one collection both ways on one `walk/1`
//! stream ([`crate::walk_stream`]): each side sends its delta against the
//! tree the two agreed on last time, breadth first and without waiting, and
//! lands the other's ([`crate::exchange`]). Both LANDEDs crossing confirms
//! it, and the agreed tree for that peer, collection and kind becomes the
//! union of the two pinned trees, which both hold; an exchange that ends any
//! other way forgets it, and what landed stays. Agreed trees are forgotten
//! for a peer when a connection to it closes, and for a collection when it
//! is deselected; none is persisted.
//!
//! The kinds of tree are the collection's records, its authorization
//! evidence (keyed by proof id under the collection) and the blobs it holds,
//! as handles without values: a held reference a side lacks is noted held
//! when the blob is resident, and fetched by hash from the peer first
//! otherwise. A record lands as it is; a proof lands once its evidence
//! validates, fetches the descriptor of a resource it is routed through, or
//! stays deferred, which fails the exchange.
//!
//! The walks task runs one node's exchanges. Either side opens the stream
//! when its timer fires ([`crate::schedule`]), on the current connection to
//! the neighbour, and the task never dials; the other side joins it. One
//! exchange per peer, collection and kind runs at a time: when both open
//! one within a round trip, the stream the smaller peer id opened survives
//! and the larger id's own is reset [`RESET_WALK_DUPLICATE`], which neither
//! counts nor forgets anything; a later stream from the peer for a running
//! incoming exchange replaces it. An exchange ends after [`WALK_DEADLINE`]
//! without a frame from the peer while one is owed: before its DONE, and
//! after it for the values asked for; the peer's LANDED is waited for as
//! long as the connection lives, since landings take what time they take,
//! and a blob fetch ends after [`WALK_DEADLINE`] without progress, never for
//! its size. Walk streams count as in use on their connection, so a
//! draining connection waits for them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::bail;
use ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::debug;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, MemoryBlobStore};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId, QuorumOutcome};
use triblespace_core::collection::{
    CollectionHandle, CollectionRecord, CollectionRecordFingerprint, descriptor,
};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
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
    ConnectionTable, FrameError, RESET_WALK_DUPLICATE, RESET_WALK_FAILED, RESET_WALK_REFUSED,
    Service, open_walk, read_frame, write_frame,
};
use crate::exchange::{Ended, Exchange, Out, Outcome, Tree};
use crate::health::Health;
use crate::host::{CollectionSnapshot, METADATA_BLOB_BYTES, StoreSnapshot};
use crate::landing::{LandSlot, Landed};
use crate::patch_repair::{
    PatchBranch, PatchChild, PatchLeaf, PatchNode, PatchNodeResponse, PatchSummary,
    patch_node_response,
};
use crate::protocol::{
    MAX_EXACT_BLOB_BYTES, RawHash, TAG_BLOB, fetch_get_blob_stream_with_limit, send_u8,
};
use crate::recon::Malformed;
use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport, reset_code};
use crate::walk_stream::Frame;

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

/// One exchange, as the walks task and the agreed trees name it: its peer,
/// collection and kind.
pub(crate) type Key = (PeerId, RawHash, WalkKind);

fn agreed_key(peer: PeerId, collection: RawHash, kind: WalkKind) -> [u8; 65] {
    let mut key = [0; 65];
    key[..32].copy_from_slice(&peer);
    key[32..64].copy_from_slice(&collection);
    key[64] = kind.wire();
    key
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

/// An exchange ends after this long without a frame from the peer while one
/// is owed, and a blob fetch after this long without progress.
pub(crate) const WALK_DEADLINE: Duration = Duration::from_secs(60);
/// Value requests and blob fetches one exchange keeps in flight.
pub(crate) const MAX_WALK_REQUESTS: usize = 64;
/// Values one exchange hands to landing before they are acknowledged. An
/// exchange whose landing queue is full reads no further.
pub(crate) const MAX_WALK_UNLANDED: usize = 1024;

/// What the walks tell the scheduler: a peer's delta of a tree is being
/// received here, or its exchange ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    Receiving {
        collection: CollectionHandle,
        kind: WalkKind,
    },
    Received {
        collection: CollectionHandle,
        kind: WalkKind,
        /// Everything the peer sent landed, and LANDED went back.
        landed: bool,
    },
}

/// One node's exchanges: what each neighbour and this side agreed on, per
/// collection and kind, and whether each neighbour is sent or received
/// from.
pub(crate) struct Walks {
    health: Health,
    snapshot: Option<Arc<StoreSnapshot>>,
    /// The collections the last snapshot selected: one that leaves the
    /// selection is forgotten.
    selected: PATCH<32, IdentitySchema, ()>,
    /// The agreed tree of each peer, collection and kind: the union of the
    /// two trees pinned for the last confirmed exchange, which both hold.
    agreed: PATCH<65, IdentitySchema, Arc<Tree>>,
}

impl Walks {
    pub(crate) fn new(health: Health) -> Self {
        Self {
            health,
            snapshot: None,
            selected: PATCH::new(),
            agreed: PATCH::new(),
        }
    }

    /// Start an exchange of C's `kind` tree with `peer`, against what they
    /// agreed on: none when C is not selected and active here, or this side neither
    /// sends C to the peer nor receives C from it. [`Walks::ended`] ends it.
    pub(crate) fn start(
        &self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
    ) -> Option<Exchange> {
        self.selected.get(&collection.raw)?;
        let pinned = self.local(collection)?;
        let sends = self.sends(peer, &pinned);
        let receives = self.receives(peer, &pinned);
        if !sends && !receives {
            return None;
        }
        let agreed = self
            .agreed
            .get(&agreed_key(peer, collection.raw, kind))
            .cloned();
        Some(Exchange::start(
            collection, kind, pinned, agreed, sends, receives,
        ))
    }

    /// The exchange of C's `kind` tree with `peer` ended: health sees a push
    /// where this side sent, confirmed if the peer's LANDED arrived, and a
    /// receive where it received, landed if LANDED went back; the agreed
    /// tree is set when the exchange confirmed and forgotten otherwise.
    /// Returns whether to exchange again at once: a confirmed exchange of a
    /// tree that moved from the agreed one since. A failed exchange is left
    /// to C's timer however the tree moved: repeating it at once would retry
    /// a neighbour that cannot land it as fast as the attempts fail.
    pub(crate) fn ended(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        ended: Ended,
        now: Mono,
    ) -> bool {
        let key = agreed_key(peer, collection.raw, kind);
        let confirmed = ended
            .agreed
            .as_ref()
            .map_or(ended.root, |agreed| agreed.summary());
        self.health.with_peer(collection, peer, |health| {
            if ended.sends {
                health.pushed(now, kind, confirmed, ended.confirmed)
            }
            if ended.receives {
                health.received(now, kind, ended.peer_root, ended.landed)
            }
            // Directional end counters are LANDED receipts. This diagnostic
            // root, unlike those counters, exists only with shared agreement.
            let agreed_root = ended.agreed.as_ref().map(|tree| tree.summary());
            match kind {
                WalkKind::Records => health.confirmed.records = agreed_root,
                WalkKind::Authorization => health.confirmed.authorization_evidence = agreed_root,
                WalkKind::References => {}
            }
        });
        let Some(agreed) = ended.agreed else {
            self.agreed.remove(&key);
            return false;
        };
        let moved = ended.sends
            && self
                .local(collection)
                .is_some_and(|current| agreed.has_new_keys(&Tree::pinned(kind, current.repair())));
        // The key stays constant across exchanges; replace must publish the
        // new attached tree even though PATCH set equality observes keys only.
        self.agreed.replace(&Entry::with_value(&key, agreed));
        moved
    }

    /// A connection to `peer` closed: what they agreed on is forgotten. A
    /// peer that restarted holds no agreed trees, and an exchange against
    /// one it lacks fails the count proof until both forget it; forgetting
    /// costs the next exchange the delta against nothing, which the peer's
    /// announcements prune.
    pub(crate) fn closed(&mut self, peer: PeerId) {
        let dropped = self
            .agreed
            .iter()
            .filter(|key| key[..32] == peer)
            .copied()
            .collect::<Vec<_>>();
        for key in dropped {
            self.agreed.remove(&key);
        }
    }

    /// Take the latest serving snapshot: what new exchanges pin and are
    /// admitted against. A collection it no longer selects is forgotten for
    /// every peer.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) {
        let mut selected = PATCH::new();
        for collection in snapshot
            .active()
            .filter(|collection| snapshot.selected(*collection).is_some())
        {
            selected.insert(&Entry::new(&collection.raw));
        }
        let dropped = self
            .selected
            .iter()
            .filter(|key| selected.get(key).is_none())
            .copied()
            .collect::<HashSet<_>>(); // Ephemeral scratch for this observation only.
        if !dropped.is_empty() {
            let forgotten = self
                .agreed
                .iter()
                .filter(|key| dropped.contains(&key[32..64]))
                .copied()
                .collect::<Vec<_>>();
            for key in forgotten {
                self.agreed.remove(&key);
            }
        }
        self.selected = selected;
        self.snapshot = Some(snapshot);
    }

    fn local(&self, collection: CollectionHandle) -> Option<Arc<CollectionSnapshot>> {
        self.snapshot.as_ref()?.collection(collection)
    }

    /// Whether this side sends C to `peer`: an active peering's directional
    /// flag, otherwise READ admission under the pinned evidence.
    fn sends(&self, peer: PeerId, pinned: &CollectionSnapshot) -> bool {
        let collection = pinned.repair().collection();
        let mut flagged = None;
        self.health.update(|health| {
            flagged = health
                .peerings
                .iter()
                .find(|peering| {
                    peering.collection == collection && peering.peer == peer && peering.peered
                })
                .map(|peering| peering.sends);
        });
        flagged.unwrap_or_else(|| {
            VerifyingKey::from_bytes(&peer).is_ok_and(|peer| {
                let evidence = pinned.repair().authorization_evidence();
                let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
                matches!(
                    evidence.reader_is_admitted_by(peer, &proofs),
                    QuorumOutcome::Met
                )
            })
        })
    }

    /// Whether this side receives C from `peer`, the mirror of
    /// [`Self::sends`]: an active peering's receive flag, otherwise WRITE
    /// admission under the pinned evidence.
    fn receives(&self, peer: PeerId, pinned: &CollectionSnapshot) -> bool {
        let collection = pinned.repair().collection();
        let mut flagged = None;
        self.health.update(|health| {
            flagged = health
                .peerings
                .iter()
                .find(|peering| {
                    peering.collection == collection && peering.peer == peer && peering.peered
                })
                .map(|peering| peering.receives);
        });
        flagged.unwrap_or_else(|| {
            VerifyingKey::from_bytes(&peer).is_ok_and(|peer| {
                let evidence = pinned.repair().authorization_evidence();
                let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
                matches!(
                    evidence.writer_is_admitted_by(peer, &proofs),
                    QuorumOutcome::Met
                )
            })
        })
    }
}

/// What an exchange does with a value, a missing leaf or a fetched blob
/// once it is checked.
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
    /// place yet stays deferred: the exchange does not confirm.
    Defer,
    /// A held reference that could not be fetched: the exchange does not
    /// confirm, and the blob stays in the next delta.
    Fail,
}

/// The value under a key of one kind's tree.
#[derive(Clone)]
pub(crate) enum Value {
    Record(CollectionRecord),
    Proof(CapabilityProof),
    /// A held reference carries no value.
    Handle,
}

impl Value {
    /// The value as it travels in a VALUE frame; a held reference does not.
    pub(crate) fn bytes(&self, collection: CollectionHandle) -> Option<Vec<u8>> {
        match self {
            Self::Record(record) => encode_record(collection, *record).ok(),
            Self::Proof(proof) => Some(proof.as_bytes().to_vec()),
            Self::Handle => None,
        }
    }
}

/// Check the value under `key` of a `kind` exchange of C against `evidence`
/// (design 2.5): the value, and what to do with it. A record lands; a proof
/// lands once its evidence validates, fetches the descriptor of the
/// resource it is routed through, or stays deferred. Held references carry
/// no values.
pub(crate) fn admit_value(
    kind: WalkKind,
    collection: CollectionHandle,
    key: [u8; KEY_BYTES],
    bytes: &[u8],
    evidence: &CollectionAuthorizationEvidencePatch,
) -> anyhow::Result<(Value, Admit)> {
    match kind {
        WalkKind::Records => {
            let record = decode_record(collection, bytes)?;
            if record.fingerprint().raw() != key {
                bail!("a record under another record's key");
            }
            Ok((
                Value::Record(record),
                Admit::Land(vec![NetEvent::CollectionRecord(record)]),
            ))
        }
        WalkKind::Authorization => {
            let proof = CapabilityProof::from_bytes(bytes)?;
            if proof.id().raw != key {
                bail!("a proof under another proof's key");
            }
            proof.verify_signatures()?;
            let routed = proof.resource().into_bytes() != collection.raw;
            let admit = match evidence.validate_proof(&proof) {
                Ok(()) => Admit::Land(vec![NetEvent::CapabilityProof(proof.clone())]),
                // A proof over a resource routed to C needs that resource's
                // descriptor, which the peer holds.
                Err(CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(
                    descriptor,
                )) if routed => Admit::Fetch {
                    handle: descriptor.raw,
                    proof: Some(proof.clone()),
                },
                Err(CollectionAuthorizationEvidenceError::WrongRoot) if routed => Admit::Defer,
                Err(error) => return Err(error.into()),
            };
            Ok((Value::Proof(proof), admit))
        }
        WalkKind::References => bail!("held references carry no values"),
    }
}

/// What a leaf of a `kind` exchange of C that the local store lacks needs. A
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

/// What a blob fetch of an exchange of C brought back. A fetched held
/// reference lands, noted held in C; one that could not be fetched fails. A
/// deferred `proof`'s descriptor that routes it to C lands with it;
/// otherwise the proof stays deferred.
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

/// The summary of the node at `prefix` of a canonical PATCH, if present.
pub(crate) fn node_summary<const KEY_LEN: usize, V>(
    patch: &PATCH<KEY_LEN, IdentitySchema, V, Blake3Merkle>,
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

/// The value under `key` of a kind's PATCH, if present.
pub(crate) fn value(
    kind: WalkKind,
    overlay: &CollectionRepairOverlay,
    key: [u8; KEY_BYTES],
) -> Option<Value> {
    match kind {
        WalkKind::Records => overlay
            .records()
            .get(CollectionRecordFingerprint::from_raw(key))
            .map(Value::Record),
        WalkKind::Authorization => overlay
            .authorization_evidence()
            .get(CapabilityProofId::new(key))
            .cloned()
            .map(Value::Proof),
        WalkKind::References => overlay
            .blob_inventory()
            .get(&key)
            .is_some()
            .then_some(Value::Handle),
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

/// Starts exchanges through the walks task, and hands it the `walk/1`
/// streams peers open.
#[derive(Clone)]
pub(crate) struct WalksHandle(pub(crate) mpsc::UnboundedSender<Command>);

impl WalksHandle {
    /// Open an exchange of C's `kind` tree with `peer`, on the current
    /// connection to it: a peer with none, a collection this side neither
    /// sends the peer nor receives from it, and an exchange of this kind
    /// with it already running each start nothing.
    pub(crate) fn open(&self, peer: PeerId, collection: CollectionHandle, kind: WalkKind) {
        let _ = self.0.send(Command::Open {
            peer,
            collection,
            kind,
        });
    }

    /// A connection to `peer` closed: what the peer and this side agreed on
    /// is forgotten.
    pub(crate) fn closed(&self, peer: PeerId) {
        let _ = self.0.send(Command::Closed { peer });
    }

    /// A `walk/1` stream `peer` opened for C's `kind` tree, after its tag
    /// and Open frame were read. The stream is refused unless this side
    /// sends C to the peer or receives C from it, and reset when the walks
    /// task is gone.
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
    Open {
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
    },
    /// A connection to the peer closed.
    Closed { peer: PeerId },
    /// A `walk/1` stream `peer` opened on its connection, after its tag and
    /// Open frame: an exchange of C's tree of `kind`, read from `recv` and
    /// written on `send`.
    Incoming {
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        send: Box<dyn SendStream>,
        recv: Box<dyn RecvStream>,
    },
    /// An exchange's stream ended. `duplicate` says the peer reset it for
    /// the stream it opened at the same time, which neither side counts.
    Ended {
        id: u64,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        ended: Ended,
        duplicate: bool,
    },
}

/// Run one node's walks: its landing task, and a task that opens exchanges,
/// joins the exchanges its peers open and follows `snapshots`. Returns what
/// opens exchanges, and where receives are reported for the scheduler.
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
        running: HashMap::new(),
        next_id: 0,
    };
    tokio::spawn(task.run(snapshots, commanded, landed));
    (WalksHandle(commands), heard)
}

struct Task<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
    walks: Walks,
    /// Where exchanges report back.
    commands: WalksHandle,
    /// Values for the landing task, by exchange.
    landing: mpsc::UnboundedSender<(u64, Vec<NetEvent>)>,
    events: mpsc::UnboundedSender<Event>,
    /// Exchanges running, by peer, collection and kind.
    running: HashMap<Key, Running>,
    next_id: u64,
}

/// A running exchange's driver, as the task reaches it.
struct Running {
    id: u64,
    /// This side opened its stream.
    opened: bool,
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
            self.observe(snapshot);
        }
        loop {
            tokio::select! {
                changed = snapshots.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if let Some(snapshot) = snapshots.borrow_and_update().clone() {
                        self.observe(snapshot);
                    }
                }
                Some(command) = commands.recv() => {
                    // A command may win select while a newer publication
                    // is pending. Pin the latest observed store for Open /
                    // Incoming and use it when deciding whether to repush.
                    if snapshots.has_changed().unwrap_or(false)
                        && let Some(snapshot) = snapshots.borrow_and_update().clone()
                    {
                        self.observe(snapshot);
                    }
                    self.command(command);
                },
                Some(ack) = landed.recv() => {
                    if let Some(running) = self.running.values().find(|running| running.id == ack.key) {
                        let _ = running.acks.send((ack.landed, ack.failed));
                    }
                }
                else => return,
            }
        }
    }

    fn observe(&mut self, snapshot: Arc<StoreSnapshot>) {
        self.walks.observe(snapshot);
        // Dropping the replacement sender retires drivers admitted under
        // a selection that no longer exists. Their queued ends are stale.
        self.running
            .retain(|(_, collection, _), _| self.walks.selected.get(collection).is_some());
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Open {
                peer,
                collection,
                kind,
            } => self.open(peer, collection, kind),
            Command::Closed { peer } => {
                self.running.retain(|(other, _, _), _| *other != peer);
                self.walks.closed(peer);
            }
            Command::Incoming {
                peer,
                collection,
                kind,
                send,
                recv,
            } => self.incoming(peer, collection, kind, send, recv),
            Command::Ended {
                id,
                peer,
                collection,
                kind,
                ended,
                duplicate,
            } => {
                let key = (peer, collection.raw, kind);
                let current = self
                    .running
                    .get(&key)
                    .is_some_and(|running| running.id == id);
                if current {
                    self.running.remove(&key);
                }
                if ended.receives {
                    let _ = self.events.send(Event::Received {
                        collection,
                        kind,
                        landed: current && !duplicate && ended.landed,
                    });
                }
                // A replaced exchange, or one the peer reset for the stream
                // it opened at the same time, settles nothing.
                if !current || duplicate {
                    return;
                }
                // A confirmed exchange of a tree that moved meanwhile is
                // followed at once; a failed one waits for the timer.
                let now = crate::clock::mono_now();
                if self.walks.ended(peer, collection, kind, ended, now) {
                    self.open(peer, collection, kind);
                }
            }
        }
    }

    /// Open an exchange of C's `kind` tree with `peer` on the current
    /// connection to it, if there is one, the walks start the exchange and
    /// none runs.
    fn open(&mut self, peer: PeerId, collection: CollectionHandle, kind: WalkKind) {
        let key = (peer, collection.raw, kind);
        if self.running.contains_key(&key) {
            return;
        }
        let Some(connection) = self.connections.current(peer) else {
            return;
        };
        let Some(exchange) = self.walks.start(peer, collection, kind) else {
            return;
        };
        let (driver, acked, replaced) = self.register(key, true, &exchange);
        tokio::spawn(async move {
            let (ended, duplicate) = match open_walk(&connection, collection, kind).await {
                Ok((send, recv)) => {
                    drive(
                        &driver,
                        exchange,
                        Box::new(send),
                        Box::new(recv),
                        acked,
                        replaced,
                    )
                    .await
                }
                Err(_) => (exchange.end(), false),
            };
            driver.ended(ended, duplicate);
        });
    }

    /// Join the exchange `peer` opened for C's `kind` tree: refused unless
    /// this side sends C to the peer or receives C from it. It replaces the
    /// exchange running for the same key, if any: an earlier stream of the
    /// peer's, or this side's own, which the peer, holding the smaller id,
    /// resets; when this side holds the smaller id its own stream survives
    /// and the peer's is reset instead.
    fn incoming(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        mut send: Box<dyn SendStream>,
        mut recv: Box<dyn RecvStream>,
    ) {
        let key = (peer, collection.raw, kind);
        if self.running.get(&key).is_some_and(|running| running.opened)
            && self.connections.transport().local_id() < peer
        {
            send.reset(RESET_WALK_DUPLICATE);
            recv.stop(RESET_WALK_DUPLICATE);
            return;
        }
        let Some(exchange) = self.walks.start(peer, collection, kind) else {
            send.reset(RESET_WALK_REFUSED);
            recv.stop(RESET_WALK_REFUSED);
            return;
        };
        let (driver, acked, replaced) = self.register(key, false, &exchange);
        tokio::spawn(async move {
            let (ended, duplicate) = drive(&driver, exchange, send, recv, acked, replaced).await;
            driver.ended(ended, duplicate);
        });
    }

    /// Register an exchange under `key`, replacing one running there, and
    /// tell the scheduler when it receives: its driver, its landing
    /// acknowledgements and what replaces it.
    fn register(
        &mut self,
        key: Key,
        opened: bool,
        exchange: &Exchange,
    ) -> (
        Driver<T, S>,
        mpsc::UnboundedReceiver<(u64, u64)>,
        oneshot::Receiver<()>,
    ) {
        let id = self.next_id;
        self.next_id += 1;
        let (acks, acked) = mpsc::unbounded_channel();
        let (replace, replaced) = oneshot::channel();
        self.running.insert(
            key,
            Running {
                id,
                opened,
                acks,
                _replace: replace,
            },
        );
        let (peer, collection, kind) = (key.0, CollectionHandle::new(key.1), key.2);
        if exchange.receives() {
            let _ = self.events.send(Event::Receiving { collection, kind });
        }
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
        (driver, acked, replaced)
    }
}

/// Fetch `handle` from `peer`: a `descriptor` is metadata, a held reference
/// may be any blob. The fetch ends after [`WALK_DEADLINE`] without
/// progress, between any two chunks, never for its size, so a blob of any
/// size lands at a steady rate; the wait for an opener permit before it is
/// not timed.
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
    let connection = connections.current(peer)?;
    let local = connections.transport().local_id();
    let provider = connection.remote_id();
    let (mut send, recv) = connection.open_bi().await.ok()?;
    send_u8(&mut send, TAG_BLOB).await.ok()?;
    let mut recv = Progress::new(recv, WALK_DEADLINE);
    fetch_get_blob_stream_with_limit(&mut send, &mut recv, local, provider, &handle, limit)
        .await
        .ok()
        .flatten()
}

/// Stream IO under a deadline on byte progress: a read or write that moves
/// no byte for `idle` fails, and every byte moved starts the wait again.
struct Progress<R> {
    inner: R,
    idle: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<R> Progress<R> {
    fn new(inner: R, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Progress<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() != before => {
                let next = tokio::time::Instant::now() + this.idle;
                this.deadline.as_mut().reset(next);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(ready) => Poll::Ready(ready),
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no progress within the walk deadline",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Progress<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(n)) if n > 0 => {
                this.deadline
                    .as_mut()
                    .reset(tokio::time::Instant::now() + this.idle);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no write progress within the walk deadline",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What one exchange's driver holds of the task.
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

impl<T: Transport, S> Driver<T, S> {
    fn ended(&self, ended: Ended, duplicate: bool) {
        let _ = self.commands.send(Command::Ended {
            id: self.id,
            peer: self.peer,
            collection: self.collection,
            kind: self.kind,
            ended,
            duplicate,
        });
    }
}

/// A blob fetch's result, as a driver hears it.
type Fetched = (RawHash, Option<CapabilityProof>, Option<Blob<UnknownBlob>>);

/// Drive one exchange on its stream, after the tag and Open: write the
/// frames of this side's delta as the stream takes them, interleaved with
/// its answers, feed the peer's frames while the exchange wants them and
/// what landing and blob fetches report, and end the stream as the exchange
/// did: finished once confirmed, reset otherwise. A stream whose peer owes a
/// frame and sends none for [`WALK_DEADLINE`] is reset too. Returns the
/// exchange as it ended, and whether the peer reset the stream for the one
/// it opened at the same time.
async fn drive<T: Transport, S: Service>(
    driver: &Driver<T, S>,
    mut exchange: Exchange,
    send: Box<dyn SendStream>,
    recv: Box<dyn RecvStream>,
    mut acked: mpsc::UnboundedReceiver<(u64, u64)>,
    mut replaced: oneshot::Receiver<()>,
) -> (Ended, bool) {
    let (frames, mut framed) = mpsc::channel(1);
    let reader = tokio::spawn(read_stream(recv, frames));
    let (outgoing, written) = mpsc::channel(1);
    let (reset, resetting) = oneshot::channel();
    let (write_failed, mut writer_failed) = oneshot::channel();
    let mut writer = tokio::spawn(write_stream(send, written, resetting, write_failed));
    let (fetches, mut fetched) = mpsc::unbounded_channel::<Fetched>();
    let mut outbox = VecDeque::new();
    // ROOT first, whatever arrives meanwhile.
    let mut pending = exchange.next_delta();
    let mut heard_at = tokio::time::Instant::now();
    let mut duplicate = false;
    let failed = 'drive: loop {
        match exchange.outcome() {
            Some(Outcome::Confirmed) => break false,
            Some(Outcome::Failed(failure)) => {
                debug!(?failure, "walk/1 exchange failed");
                break true;
            }
            None => {}
        }
        // Answers first, then the delta, one frame ahead of the writer: the
        // stream's credit is the delta's only pace.
        if pending.is_none() {
            pending = outbox.pop_front().or_else(|| exchange.next_delta());
        }
        if exchange.outcome().is_some() {
            continue;
        }
        let deadline = exchange.awaits().then(|| heard_at + WALK_DEADLINE);
        let outs = tokio::select! {
            permit = outgoing.reserve(), if pending.is_some() => match permit {
                Ok(permit) => {
                    permit.send(pending.take().expect("a frame is pending"));
                    Vec::new()
                }
                Err(_) => break 'drive true,
            },
            frame = next_frame(&mut framed, deadline), if exchange.want_read() => match frame {
                Some(Ok(frame)) => {
                    heard_at = tokio::time::Instant::now();
                    exchange.on_frame(frame, driver.snapshots.borrow().clone())
                }
                Some(Err(code)) => {
                    duplicate = code == Some(RESET_WALK_DUPLICATE);
                    break 'drive true;
                }
                None => break 'drive true,
            },
            Some((landed, failed)) = acked.recv() => exchange.on_landed_ack(landed, failed),
            Some((handle, proof, blob)) = fetched.recv() => exchange.on_fetched(handle, proof, blob),
            _ = &mut writer_failed => break 'drive true,
            _ = &mut replaced => break 'drive true,
        };
        for out in outs {
            match out {
                Out::Send(frame) => outbox.push_back(frame),
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
    let mut reset = Some(reset);
    let mut failed = failed;
    if !failed {
        // The LANDED that confirmed the exchange may still be waiting for
        // the writer.
        let drain = async {
            for frame in pending.into_iter().chain(outbox) {
                outgoing.send(frame).await.map_err(|_| ())?;
            }
            Ok::<(), ()>(())
        };
        failed = tokio::select! {
            result = drain => result.is_err(),
            _ = &mut replaced => true,
            _ = &mut writer_failed => true,
        };
    }
    if failed {
        let _ = reset.take().unwrap().send(RESET_WALK_FAILED);
    }
    drop(outgoing);
    let (landed_written, finished) = if failed {
        writer.await.unwrap_or((false, false))
    } else {
        tokio::select! {
            result = &mut writer => result.unwrap_or((false, false)),
            _ = &mut replaced => {
                failed = true;
                let _ = reset.take().unwrap().send(RESET_WALK_FAILED);
                writer.await.unwrap_or((false, false))
            }
        }
    };
    let mut ended = exchange.end();
    ended.landed = landed_written;
    if failed || !finished || !landed_written {
        // A queued LANDED is not a write receipt. The peer's independent
        // receipt can still count our push, but no shared agreement survives.
        ended.agreed = None;
    }
    (ended, duplicate)
}

/// The next frame the reader forwarded, within `deadline` when the driver
/// is owed one: past it, as for a stream that ended.
async fn next_frame(
    frames: &mut mpsc::Receiver<Result<Frame, Option<u32>>>,
    deadline: Option<tokio::time::Instant>,
) -> Option<Result<Frame, Option<u32>>> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, frames.recv())
            .await
            .unwrap_or_else(|_| {
                debug!("walk/1 exchange deadline exceeded");
                Some(Err(None))
            }),
        None => frames.recv().await,
    }
}

/// Read a walk stream's frames to `frames`, one ahead of the driver, so no
/// frame is left half read when the driver turns to something else. An
/// `Err` ends it: the stream ended, failed (with the code the peer reset it
/// with, if it did) or carried a malformed frame. The driver times its
/// waits, when a frame is owed.
async fn read_stream(
    mut recv: Box<dyn RecvStream>,
    frames: mpsc::Sender<Result<Frame, Option<u32>>>,
) {
    loop {
        let frame = match read_frame(&mut recv).await {
            Ok(Some((kind, payload))) => match Frame::decode(kind, &payload) {
                Ok(Some(frame)) => Ok(frame),
                Ok(None) => continue,
                Err(Malformed(violation)) => {
                    debug!(violation, "malformed walk/1 frame");
                    Err(None)
                }
            },
            Ok(None) => Err(None),
            Err(error) => {
                debug!(?error, "walk/1 stream failed");
                Err(match error {
                    FrameError::Transport(error) => reset_code(&error),
                    FrameError::Violation(_) | FrameError::Stalled => None,
                })
            }
        };
        let ended = frame.is_err();
        if frames.send(frame).await.is_err() || ended {
            return;
        }
    }
}

/// Write `frames` to the stream in order and finish it once they end, or
/// reset it with the code `reset` brings, even in the middle of a frame the
/// peer is not reading. A stream that fails under a write is still reset or
/// finished as the driver says, once it says so. A failed write also wakes
/// the driver immediately. Writes have a byte-progress deadline, and final
/// shutdown is bounded and cancellable. Returns actual LANDED write and
/// successful stream-finish receipts separately.
async fn write_stream(
    mut send: Box<dyn SendStream>,
    mut frames: mpsc::Receiver<Frame>,
    reset: oneshot::Receiver<u32>,
    write_failed: oneshot::Sender<()>,
) -> (bool, bool) {
    let mut reset = std::pin::pin!(futures::FutureExt::fuse(reset));
    let mut broken = false;
    let mut write_failed = Some(write_failed);
    let mut landed_written = false;
    loop {
        tokio::select! {
            biased;
            Ok(code) = &mut reset => {
                send.reset(code);
                return (landed_written, false);
            }
            next = frames.recv() => {
                let Some(frame) = next else {
                    if !broken {
                        let finished = tokio::select! {
                            biased;
                            Ok(code) = &mut reset => {
                                send.reset(code);
                                false
                            }
                            result = tokio::time::timeout(WALK_DEADLINE, send.shutdown()) => {
                                matches!(result, Ok(Ok(())))
                            }
                        };
                        if !finished {
                            send.reset(RESET_WALK_FAILED);
                        }
                        return (landed_written, finished);
                    } else {
                        send.reset(RESET_WALK_FAILED);
                    }
                    return (landed_written, false);
                };
                if broken {
                    continue;
                }
                let (kind, payload) = frame.encode();
                tokio::select! {
                    biased;
                    Ok(code) = &mut reset => {
                        send.reset(code);
                        return (landed_written, false);
                    }
                    written = async {
                        write_frame(&mut Progress::new(&mut send, WALK_DEADLINE), kind, &payload).await
                    } => {
                        broken = written.is_err();
                        if broken {
                            if let Some(failed) = write_failed.take() {
                                let _ = failed.send(());
                            }
                        } else if matches!(frame, Frame::Landed) {
                            landed_written = true;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One node's store, serving snapshot and walks, for the exchange
    /// tests.
    pub(crate) mod walking {
        use super::*;

        use std::collections::BTreeSet;

        use ed25519_dalek::SigningKey;
        use iroh_base::EndpointId;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::collection::selection::{
            CONFIG_COLLECTION_NAME, write_sync_selection,
        };
        use triblespace_core::collection::{
            AdmissionPolicy, Collection, CollectionCommit, CollectionData, CollectionPolicy,
            CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, HeldStore,
            empty_metadata_handle, private_policy,
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

        /// One node: its store, its configuration, its active collections
        /// and its walks.
        pub(crate) struct Node {
            pub(crate) key: SigningKey,
            pub(crate) store: MemoryRepo,
            /// The pile's configuration collection, where selections live.
            config: Collection<SimpleArchive>,
            pub(crate) active: ActiveCollections,
            pub(crate) walks: Walks,
            pub(crate) health: Health,
        }

        impl Node {
            pub(crate) fn new(byte: u8) -> Self {
                let key = key(byte);
                let health =
                    Health::new(EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap());
                let mut store = MemoryRepo::default();
                let config = store
                    .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
                    .unwrap();
                Self {
                    walks: Walks::new(health.clone()),
                    health,
                    key,
                    store,
                    config,
                    active: ActiveCollections::new(),
                }
            }

            pub(crate) fn id(&self) -> PeerId {
                self.key.verifying_key().to_bytes()
            }

            /// Hold the collection `name` names: active here, selected for
            /// sync, and observed by health.
            pub(crate) fn hold(
                &mut self,
                name: &str,
                policy: CollectionPolicy,
            ) -> CollectionHandle {
                let collection = self.store.collection(name, policy).unwrap().handle();
                self.active.insert(&PatchEntry::new(&collection.raw));
                self.select(collection, true);
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

            /// Select or unselect the collection for sync in the pile's
            /// configuration; the next observation sees it.
            pub(crate) fn select(&mut self, collection: CollectionHandle, selected: bool) {
                write_sync_selection(
                    &mut self.store,
                    self.config,
                    &self.key,
                    collection,
                    selected,
                )
                .unwrap();
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

            /// The serving snapshot of C.
            pub(crate) fn pinned(&self, collection: CollectionHandle) -> Arc<CollectionSnapshot> {
                self.serving().collection(collection).unwrap()
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

    use walking::{Node, open};

    /// Every branch locator of a records tree, by the PATCH's own view.
    pub(crate) fn branches(
        patch: &PATCH<32, IdentitySchema, CollectionRecord, Blake3Merkle>,
        prefix: Vec<u8>,
        out: &mut Vec<Vec<u8>>,
    ) {
        let node = patch.merkle_node(&prefix).unwrap();
        if node.is_leaf() {
            return;
        }
        let base = node.representative()[..node.end_depth()].to_vec();
        out.push(prefix);
        for (edge, _) in node.children() {
            let mut child = base.clone();
            child.push(edge);
            branches(patch, child, out);
        }
    }

    /// The branch locators of a records tree on the paths to `keys`.
    pub(crate) fn paths(
        patch: &PATCH<32, IdentitySchema, CollectionRecord, Blake3Merkle>,
        keys: &[[u8; 32]],
    ) -> std::collections::BTreeSet<Vec<u8>> {
        let mut all = Vec::new();
        branches(patch, Vec::new(), &mut all);
        all.into_iter()
            .filter(|locator| keys.iter().any(|key| key.starts_with(locator)))
            .collect()
    }

    /// What a peer and this side agreed on is forgotten when a connection to
    /// it closes, so a peer that restarted is not held to a tree it lost;
    /// and a collection's agreed trees, for every peer, when the collection
    /// is deselected.
    #[test]
    fn agreed_trees_are_forgotten_when_a_peering_ends_or_a_collection_is_dropped() {
        let mut node = Node::new(63);
        let kept = node.hold("kept", open());
        let dropped = node.hold("dropped", open());
        node.commit(kept, 1);
        node.commit(dropped, 1);
        node.observe();
        let (a, b) = (Node::new(64).id(), Node::new(65).id());
        let kind = WalkKind::Records;
        let now = crate::clock::mono_now();
        let pairs = [(a, kept), (a, dropped), (b, kept), (b, dropped)];
        let remember = |node: &mut Node| {
            for (peer, collection) in pairs {
                let pinned = node.pinned(collection);
                let ended = Ended {
                    sends: true,
                    receives: true,
                    confirmed: true,
                    landed: true,
                    root: summary(kind, pinned.repair()),
                    peer_root: Some(summary(kind, pinned.repair())),
                    agreed: Some(Arc::new(Tree::pinned(kind, pinned.repair()))),
                };
                assert!(!node.walks.ended(peer, collection, kind, ended, now));
            }
        };
        let remembered = |node: &Node, peer: PeerId, collection: CollectionHandle| {
            node.walks
                .agreed
                .get(&agreed_key(peer, collection.raw, kind))
                .is_some()
        };
        remember(&mut node);
        for (peer, collection) in pairs {
            assert!(remembered(&node, peer, collection));
        }

        // A connection to A closes: A's trees go, B's stay.
        node.walks.closed(a);
        assert!(!remembered(&node, a, kept));
        assert!(!remembered(&node, a, dropped));
        assert!(remembered(&node, b, kept));
        assert!(remembered(&node, b, dropped));

        // One collection is deselected: its trees go for every peer, and
        // the other's stay, over this observation and the next.
        remember(&mut node);
        node.select(dropped, false);
        node.observe();
        node.observe();
        assert!(!remembered(&node, a, dropped));
        assert!(!remembered(&node, b, dropped));
        assert!(remembered(&node, a, kept));
        assert!(remembered(&node, b, kept));

        // Health saw every end: eight confirmed pushes and landed receives
        // for A, and the agreed root is each collection's own.
        let health = node.health.snapshot();
        let kept_health = health
            .collections
            .iter()
            .find(|entry| entry.collection == kept)
            .unwrap();
        let pair = kept_health
            .peers
            .iter()
            .find(|pair| pair.peer == a)
            .unwrap();
        assert_eq!((pair.pushes.ok, pair.pushes.failed), (2, 0));
        assert_eq!((pair.receives.ok, pair.receives.failed), (2, 0));
        assert_eq!(
            pair.confirmed.records,
            Some(summary(kind, node.pinned(kept).repair()))
        );
    }

    #[test]
    fn active_peering_directions_override_credential_admission() {
        let mut node = Node::new(109);
        let collection = node.hold("explicit directions", open());
        let peer = Node::new(110).id();
        let pinned = node.pinned(collection);
        assert!(node.walks.sends(peer, &pinned) && node.walks.receives(peer, &pinned));
        node.health.update(|health| {
            health.peerings.push(crate::health::PeeringHealth {
                collection,
                peer,
                asked: false,
                peered: true,
                sends: false,
                receives: true,
                refused_by_me: false,
                refused_by_them: false,
            })
        });
        assert!(!node.walks.sends(peer, &pinned));
        assert!(node.walks.receives(peer, &pinned));
        node.health.update(|health| {
            health.peerings[0].sends = true;
            health.peerings[0].receives = false;
        });
        assert!(node.walks.sends(peer, &pinned));
        assert!(!node.walks.receives(peer, &pinned));
    }

    #[test]
    fn a_failed_exchange_forgets_an_already_agreed_tree() {
        let mut node = Node::new(98);
        let collection = node.hold("forget after failure", open());
        node.commit(collection, 1);
        node.observe();
        let peer = Node::new(99).id();
        let kind = WalkKind::Records;
        let pinned = node.pinned(collection);
        let root = summary(kind, pinned.repair());
        node.walks.ended(
            peer,
            collection,
            kind,
            Ended {
                sends: true,
                receives: true,
                confirmed: true,
                landed: true,
                root,
                peer_root: Some(root),
                agreed: Some(Arc::new(Tree::pinned(kind, pinned.repair()))),
            },
            crate::clock::mono_now(),
        );
        let mut exchange = node.walks.start(peer, collection, kind).unwrap();
        assert!(
            node.walks
                .agreed
                .get(&agreed_key(peer, collection.raw, kind))
                .is_some()
        );
        // Connection interrupted before either LANDED, after a previously
        // confirmed exchange. The end is not a confirmation of old memory.
        assert!(matches!(exchange.next_delta(), Some(Frame::Root { .. })));
        let ended = exchange.end();
        assert!(!ended.confirmed && ended.agreed.is_none());
        node.walks
            .ended(peer, collection, kind, ended, crate::clock::mono_now());
        assert!(
            node.walks
                .agreed
                .get(&agreed_key(peer, collection.raw, kind))
                .is_none()
        );
        let health = node.health.snapshot();
        let pair = health
            .collections
            .iter()
            .find(|entry| entry.collection == collection)
            .unwrap()
            .peers
            .iter()
            .find(|pair| pair.peer == peer)
            .unwrap();
        assert!(pair.confirmed.records.is_none());
        let mut retry = node.walks.start(peer, collection, kind).unwrap();
        assert!(matches!(retry.next_delta(), Some(Frame::Root { .. })));
        assert!(matches!(retry.next_delta(), Some(Frame::Leaf { .. })));
    }

    /// Walk streams driven through the walks task over the simulated
    /// transport: a scripted peer over a duplex pipe, and the task's own
    /// driver over a connection into another task, both ways.
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

        use anybytes::Bytes;
        use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionPolicy, CollectionRecord, CollectionStore, HeldStore,
        };

        use crate::health::PeerHealth;
        use crate::landing::Land;
        use crate::protocol::{TAG_BLOB, TAG_WALK, serve_get_blob};
        use crate::transport::sim::{Crossed, SimConfig, SimNet, Tapped, Taps};
        use crate::walk_stream::{
            FRAME_DONE, FRAME_LANDED, FRAME_LEAF, FRAME_NODE, FRAME_OPEN, FRAME_ROOT,
            FRAME_VALUE_REQUEST,
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

        struct FailLanded(Tx, Arc<Mutex<bool>>);

        impl AsyncWrite for FailLanded {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if buf == [crate::walk_stream::FRAME_LANDED, 0, 0, 0, 0] {
                    *self.1.lock().unwrap() = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "scripted LANDED write failure",
                    )));
                }
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

        impl SendStream for FailLanded {
            fn reset(&mut self, code: u32) {
                self.0.reset(code);
            }
        }

        struct BlockLanded(Tx, Arc<Mutex<bool>>);

        impl AsyncWrite for BlockLanded {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if bytes == [crate::walk_stream::FRAME_LANDED, 0, 0, 0, 0] {
                    *self.1.lock().unwrap() = true;
                    return Poll::Pending;
                }
                Pin::new(&mut self.0).poll_write(cx, bytes)
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

        impl SendStream for BlockLanded {
            fn reset(&mut self, code: u32) {
                self.0.reset(code);
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
        /// task, and the task's exchanges go out on its connections. Its
        /// request streams are served by `S`.
        struct Hosted<S: Service = NoRequests> {
            peer: PeerId,
            lander: Arc<Lander>,
            walks: WalksHandle,
            table: ConnectionTable<Tapped, S>,
            taps: Taps,
            events: mpsc::UnboundedReceiver<Event>,
            server: tokio::task::JoinHandle<()>,
        }

        impl Hosted {
            fn new(node: Node, net: &SimNet) -> Self {
                Self::serving(node, net, |_, _| NoRequests)
            }
        }

        impl<S: Service> Hosted<S> {
            /// Host `node` with the request service `service` builds from
            /// the node's id and its serving snapshots.
            fn serving(
                node: Node,
                net: &SimNet,
                service: impl FnOnce(PeerId, watch::Receiver<Option<Arc<StoreSnapshot>>>) -> S,
            ) -> Self {
                let (mut harness, taps) = net.tap(&node.key);
                let peer = harness.transport.local_id();
                let (snapshots, snapshot) = watch::channel(Some(node.snapshot()));
                let table =
                    ConnectionTable::new(harness.transport, service(peer, snapshot.clone()));
                let accepting = table.clone();
                let server = tokio::spawn(async move {
                    while let Some(incoming) = harness.incoming.recv().await {
                        accepting.accept(incoming.conn);
                    }
                });
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
            /// opener's halves, and where the task's reset of it is noted.
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

            /// Commit a record and publish the serving snapshot.
            fn commit(&self, collection: CollectionHandle, data: u64) -> [u8; 32] {
                let mut node = self.lander.node.lock().unwrap();
                let key = node.commit(collection, data).fingerprint().raw();
                node.observe();
                let snapshot = node.snapshot();
                self.lander.snapshots.send_replace(Some(snapshot));
                key
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

            /// Wait for an exchange with `peer` for C to end: what health
            /// recorded of the pair.
            async fn ended(
                &self,
                peer: PeerId,
                collection: CollectionHandle,
                before: Option<PeerHealth>,
            ) -> PeerHealth {
                let ends = |health: &PeerHealth| {
                    health.pushes.ok
                        + health.pushes.failed
                        + health.receives.ok
                        + health.receives.failed
                };
                let before = before.as_ref().map_or(0, ends);
                for _ in 0..60_000 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    if let Some(health) = self.health(collection, peer)
                        && ends(&health) > before
                    {
                        return health;
                    }
                }
                panic!("the exchange never ended");
            }

            /// Open an exchange of C's `kind` tree with `peer` through the
            /// walks task and wait for it to end; what health recorded of
            /// the pair.
            async fn exchange(
                &self,
                peer: PeerId,
                collection: CollectionHandle,
                kind: WalkKind,
            ) -> PeerHealth {
                let before = self.health(collection, peer);
                self.walks.open(peer, collection, kind);
                self.ended(peer, collection, before).await
            }
        }

        impl<S: Service> Drop for Hosted<S> {
            fn drop(&mut self) {
                self.server.abort();
            }
        }

        /// A writer that writes at most `piece` bytes at a time, each after
        /// a `pause` from the write before: a transfer at a steady, slow
        /// rate.
        struct Paced<'a, W> {
            inner: &'a mut W,
            pause: Duration,
            piece: usize,
            sleep: Option<Pin<Box<tokio::time::Sleep>>>,
        }

        impl<W: AsyncWrite + Unpin> AsyncWrite for Paced<'_, W> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let this = &mut *self;
                if let Some(sleep) = &mut this.sleep {
                    std::task::ready!(sleep.as_mut().poll(cx));
                    this.sleep = None;
                }
                let piece = buf.len().min(this.piece);
                let written =
                    std::task::ready!(Pin::new(&mut *this.inner).poll_write(cx, &buf[..piece]))?;
                this.sleep = Some(Box::pin(tokio::time::sleep(this.pause)));
                Poll::Ready(Ok(written))
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut *self.inner).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut *self.inner).poll_shutdown(cx)
            }
        }

        /// Serves `blob/1` from the node's serving snapshot, one request at
        /// a time, writing each piece of a response after a pause: a
        /// transfer that makes steady progress for longer than the walk
        /// deadline.
        #[derive(Clone)]
        struct PacedBlobs {
            local: PeerId,
            snapshots: watch::Receiver<Option<Arc<StoreSnapshot>>>,
            pause: Duration,
            piece: usize,
            one_at_a_time: Arc<tokio::sync::Mutex<()>>,
        }

        impl Service for PacedBlobs {
            async fn serve<W, R>(
                &self,
                peer: PeerId,
                tag: u8,
                send: &mut W,
                recv: &mut R,
            ) -> anyhow::Result<()>
            where
                W: SendStream,
                R: RecvStream,
            {
                anyhow::ensure!(tag == TAG_BLOB, "only blob/1 is served here: {tag:#x}");
                let _one = self.one_at_a_time.lock().await;
                let snapshot = self.snapshots.borrow().clone();
                let (resolving, getting) = (snapshot.clone(), snapshot);
                let mut paced = Paced {
                    inner: send,
                    pause: self.pause,
                    piece: self.piece,
                    sleep: None,
                };
                serve_get_blob(
                    recv,
                    &mut paced,
                    peer,
                    self.local,
                    |locator| {
                        resolving
                            .as_ref()
                            .and_then(|snapshot| snapshot.bearer_locators().get(&locator).copied())
                    },
                    |handle| {
                        getting
                            .as_ref()
                            .and_then(|snapshot| snapshot.get_blob(&handle))
                    },
                )
                .await
            }
        }

        /// A sender holding `blobs` in C, served `pause` apart in `piece`s,
        /// and an empty receiver, connected: the sender, its references
        /// root and the handles held.
        fn holding(
            net: &SimNet,
            bytes: (u8, u8),
            blobs: &[u8],
            pause: Duration,
            piece: usize,
        ) -> (
            Hosted<PacedBlobs>,
            CollectionHandle,
            PatchSummary,
            Vec<RawHash>,
            Node,
        ) {
            let mut sender = Node::new(bytes.0);
            let collection = sender.hold("held", open());
            sender.store.track_held([collection]);
            let handles = blobs
                .iter()
                .map(|fill| {
                    let blob = Blob::<UnknownBlob>::new(Bytes::from_source(vec![*fill; 1 << 20]));
                    let handle = blob.get_handle().raw;
                    sender.insert(vec![
                        NetEvent::Blob(blob),
                        NetEvent::Held { collection, handle },
                    ]);
                    handle
                })
                .collect::<Vec<_>>();
            sender.observe();
            let root = summary(
                WalkKind::References,
                sender.serving().collection(collection).unwrap().repair(),
            );
            // A tracked held set is a closure: the collection's seeds are
            // held too, and the receiver holds the same ones.
            assert!(root.leaf_count() >= blobs.len() as u64);
            let sender = Hosted::serving(sender, net, |local, snapshots| PacedBlobs {
                local,
                snapshots,
                pause,
                piece,
                one_at_a_time: Arc::default(),
            });
            let mut receiver = Node::new(bytes.1);
            receiver.hold("held", open());
            receiver.store.track_held([collection]);
            receiver.observe();
            (sender, collection, root, handles, receiver)
        }

        /// Whether `node` holds every blob in `handles`, resident and in
        /// its held set of C with the references root `root`.
        fn holds(
            node: &Node,
            collection: CollectionHandle,
            root: PatchSummary,
            handles: &[RawHash],
        ) -> bool {
            handles
                .iter()
                .all(|handle| node.serving().get_blob(handle).is_some())
                && summary(
                    WalkKind::References,
                    node.serving().collection(collection).unwrap().repair(),
                ) == root
        }

        async fn write<W: AsyncWrite + Unpin>(send: &mut W, frame: Frame) {
            assert!(try_write(send, frame).await, "the stream is open");
        }

        /// Write a frame; whether the stream took it.
        async fn try_write<W: AsyncWrite + Unpin>(send: &mut W, frame: Frame) -> bool {
            let (kind, payload) = frame.encode();
            write_frame(send, kind, &payload).await.is_ok()
        }

        async fn read<R: AsyncRead + Unpin>(recv: &mut R) -> Option<Frame> {
            let (kind, payload) = read_frame(recv).await.ok()??;
            Frame::decode(kind, &payload).unwrap()
        }

        /// Wait for the task to reset or stop the stream.
        async fn reset(reset: &Mutex<Option<u32>>) -> Option<u32> {
            for _ in 0..500 {
                if let Some(code) = *reset.lock().unwrap() {
                    return Some(code);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            None
        }

        /// A scripted peer: stream `sender`'s whole records tree of C over
        /// the stream, breadth first and heeding no announcement, leaving
        /// out the leaf `omit` names; then answer value requests until the
        /// task says everything landed or ends the stream, or `cut` values
        /// were answered, sending LANDED for the task's own delta once its
        /// DONE is in. Returns whether the task's LANDED came, and how many
        /// value requests were heard.
        async fn stream(
            sender: &Node,
            collection: CollectionHandle,
            send: &mut WriteHalf<DuplexStream>,
            recv: &mut ReadHalf<DuplexStream>,
            cut: usize,
            omit: Option<[u8; 32]>,
        ) -> (bool, usize) {
            let kind = WalkKind::Records;
            let overlay = sender.serving().collection(collection).unwrap();
            let overlay = overlay.repair();
            let mut answered = 0;
            let mut heard = 0;
            let value = |key| Frame::Value {
                key,
                bytes: value(kind, overlay, key)
                    .unwrap()
                    .bytes(collection)
                    .unwrap(),
            };
            write(
                send,
                Frame::Root {
                    summary: summary(kind, overlay),
                },
            )
            .await;
            let mut queue = VecDeque::from([Vec::new()]);
            while let Some(prefix) = queue.pop_front() {
                match node(kind, overlay, &prefix).unwrap() {
                    PatchNode::Leaf { leaf, .. } => {
                        let key = <[u8; 32]>::try_from(leaf.key).unwrap();
                        if omit != Some(key) {
                            write(send, Frame::Leaf { key }).await;
                        }
                    }
                    sent @ PatchNode::Branch { .. } => {
                        let PatchNode::Branch { branch, .. } = sent.clone() else {
                            unreachable!()
                        };
                        let end = usize::from(branch.end_depth);
                        for child in &branch.children {
                            let mut locator = branch.representative[..end].to_vec();
                            locator.push(child.edge);
                            queue.push_back(locator);
                        }
                        write(send, Frame::Node { prefix, node: sent }).await;
                    }
                }
            }
            write(send, Frame::Done).await;
            loop {
                match read(recv).await {
                    Some(Frame::Landed) => return (true, heard),
                    Some(Frame::ValueRequest { key }) => {
                        heard += 1;
                        if answered == cut {
                            return (false, heard);
                        }
                        answered += 1;
                        // A request read after the task ended the exchange
                        // can no longer be answered.
                        if !try_write(send, value(key)).await {
                            return (false, heard);
                        }
                    }
                    Some(Frame::Done) => {
                        if !try_write(send, Frame::Landed).await {
                            return (false, heard);
                        }
                    }
                    Some(Frame::Root { .. } | Frame::Node { .. } | Frame::Leaf { .. }) => {}
                    Some(other) => panic!("waiting for Landed: {other:?}"),
                    None => return (false, heard),
                }
            }
        }

        /// A stream from an admitted peer lands through the landing task and
        /// ends with both LANDEDs and a finished stream; one from a peer the
        /// task neither sends to nor receives from is refused.
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
            let (confirmed, heard) =
                stream(&sender, collection, &mut send, &mut recv, usize::MAX, None).await;
            assert!(confirmed);
            assert_eq!(heard, 150, "the fifty held are not asked for");
            assert!(read(&mut recv).await.is_none(), "the stream finished");
            assert_eq!(*landed.lock().unwrap(), None);
            assert_eq!(receiving.records(collection), records);
            let health = receiving.health(collection, sender.id()).unwrap();
            assert!(health.receives.last_ok && health.receives.ok == 1);
            assert!(health.pushes.last_ok && health.pushes.ok == 1);
            let root = summary(
                WalkKind::Records,
                sender.serving().collection(collection).unwrap().repair(),
            );
            assert_eq!(health.received.records, Some(root));
            // The agreed tree is the union, which is the sender's tree.
            assert_eq!(health.confirmed.records, Some(root));
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

            // The same tree again: the root is held whole, and every node
            // the scripted peer still streams is in flight waste.
            let (mut send, mut recv, _) = receiving.open(sender.id(), collection);
            let (confirmed, heard) =
                stream(&sender, collection, &mut send, &mut recv, usize::MAX, None).await;
            assert!(confirmed);
            assert_eq!(heard, 0);

            let (_send, _recv, refusal) = receiving.open(sender.id(), refused);
            assert_eq!(reset(&refusal).await, Some(RESET_WALK_REFUSED));
            assert!(receiving.health(refused, sender.id()).is_none());
        }

        /// A second stream from the peer for the same tree replaces the
        /// first, which is reset and counted nowhere; a delta that omits a
        /// leaf is reset too, and counts as a failed receive and push.
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

            // The second streams every leaf but one.
            let omitted = records[0].fingerprint().raw();
            let (confirmed, heard) = stream(
                &sender,
                collection,
                &mut second,
                &mut second_recv,
                usize::MAX,
                Some(omitted),
            )
            .await;
            assert!(!confirmed);
            assert_eq!(reset(&second_reset).await, Some(RESET_WALK_FAILED));
            // Its value requests went out before the end failed it.
            let mut requested = heard;
            while let Some(frame) = read(&mut second_recv).await {
                if matches!(frame, Frame::ValueRequest { .. }) {
                    requested += 1;
                }
            }
            assert_eq!(requested, 19);
            for _ in 0..500 {
                if receiving
                    .health(collection, sender.id())
                    .is_some_and(|health| health.receives.failed == 1)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(receiving.records(collection).len() < 20);
            let health = receiving.health(collection, sender.id()).unwrap();
            assert_eq!((health.receives.ok, health.receives.failed), (0, 1));
            assert_eq!((health.pushes.ok, health.pushes.failed), (0, 1));
            assert!(!health.receives.last_ok);
        }

        /// The frames that crossed `taps` since `from` on walk streams to
        /// `peer`, in order, with whether this side sent each.
        fn walked(taps: &Taps, from: usize, peer: PeerId) -> Vec<Crossed> {
            taps.since(from, peer, TAG_WALK)
        }

        /// The frame kinds among `crossed` that this side sent, and those it
        /// heard.
        fn split(crossed: &[Crossed]) -> (Vec<u8>, Vec<u8>) {
            let kinds = |sent: bool| {
                crossed
                    .iter()
                    .filter(|crossed| crossed.sent == sent)
                    .map(|crossed| crossed.kind)
                    .collect::<Vec<_>>()
            };
            (kinds(true), kinds(false))
        }

        fn crossed(taps: &Taps, from: usize, peer: PeerId) -> (Vec<u8>, Vec<u8>) {
            split(&walked(taps, from, peer))
        }

        fn count(kinds: &[u8], kind: u8) -> usize {
            kinds.iter().filter(|crossed| **crossed == kind).count()
        }

        /// Two hosted nodes on a net with a fixed latency: `full` holds
        /// `records` of C, `empty` none.
        fn pair(
            seed: u64,
            bytes: (u8, u8),
            records: u64,
        ) -> (
            SimNet,
            Hosted,
            Hosted,
            CollectionHandle,
            Vec<CollectionRecord>,
        ) {
            let net = SimNet::new(
                seed,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let mut full = Node::new(bytes.0);
            let collection = full.hold("pair", open());
            let records = (0..records)
                .map(|data| full.commit(collection, data))
                .collect::<Vec<_>>();
            full.observe();
            let full = Hosted::new(full, &net);
            let mut empty = Node::new(bytes.1);
            empty.hold("pair", open());
            empty.observe();
            let empty = Hosted::new(empty, &net);
            (net, full, empty, collection, records)
        }

        /// A first sync to an empty peer: the full side streams its whole
        /// tree without waiting for anything, the empty side sends only its
        /// ROOT, its DONE, a request per value and LANDED, and the full
        /// side had written its last NODE before the first frame after the
        /// empty side's ROOT arrived.
        #[tokio::test(start_paused = true)]
        async fn first_sync_to_an_empty_peer_streams_without_waiting() {
            let (_net, full, empty, collection, records) = pair(0x3A1E, (55, 56), 300);
            let kind = WalkKind::Records;
            let _connection = full.table.connect(empty.peer).await.unwrap();
            let health = full.exchange(empty.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
            assert_eq!(empty.records(collection).len(), 300);

            let crossed = walked(&full.taps, 0, empty.peer);
            let (sent, heard) = split(&crossed);
            assert_eq!(count(&heard, FRAME_ROOT), 1);
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 300);
            assert_eq!(count(&heard, FRAME_DONE), 1);
            assert_eq!(count(&heard, FRAME_LANDED), 1);
            assert_eq!(heard.len(), 303, "{heard:?}");
            assert_eq!(count(&heard, FRAME_NODE) + count(&heard, FRAME_LEAF), 0);
            let mut expected = Vec::new();
            let pinned = full.lander.node.lock().unwrap().pinned(collection);
            branches(pinned.repair().records().patch(), Vec::new(), &mut expected);
            assert!(expected.len() > 1);
            assert_eq!(count(&sent, FRAME_NODE), expected.len());
            assert_eq!(count(&sent, FRAME_LEAF), records.len());

            // Zero waits. Stream data crosses the simulated transport
            // without latency, so the tap's order is the two tasks'
            // interleaving; the witness is a scripted empty peer that
            // sends its ROOT and DONE and then reads nothing until the full
            // side's DONE is in: the whole delta arrives before the peer
            // sends anything else, which a side that waited for a reply
            // could never finish.
            let stranger = Node::new(57).id();
            let before = full.health(collection, stranger);
            let (mut send, mut recv, _) = full.open(stranger, collection);
            write(
                &mut send,
                Frame::Root {
                    summary: PatchSummary::new(None, 0).unwrap(),
                },
            )
            .await;
            write(&mut send, Frame::Done).await;
            let mut delta = Vec::new();
            loop {
                let frame = read(&mut recv).await.expect("the delta");
                let done = frame == Frame::Done;
                delta.push(frame);
                if done {
                    break;
                }
            }
            assert!(matches!(delta[0], Frame::Root { .. }));
            let nodes = delta
                .iter()
                .filter(|frame| matches!(frame, Frame::Node { .. }))
                .count();
            let leaves = delta
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Leaf { key } => Some(*key),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(nodes, expected.len());
            assert_eq!(leaves.len(), records.len());
            assert!(
                delta.iter().all(|frame| !matches!(
                    frame,
                    Frame::Value { .. } | Frame::ValueRequest { .. }
                ))
            );
            // Now the values, and both LANDEDs.
            for key in &leaves {
                write(&mut send, Frame::ValueRequest { key: *key }).await;
            }
            let mut values = 0;
            let mut landed = delta.contains(&Frame::Landed);
            while values < leaves.len() || !landed {
                match read(&mut recv).await.expect("the values") {
                    Frame::Value { .. } => values += 1,
                    Frame::Landed => landed = true,
                    other => panic!("waiting for values: {other:?}"),
                }
            }
            write(&mut send, Frame::Landed).await;
            assert!(read(&mut recv).await.is_none(), "the stream finished");
            let health = full.ended(stranger, collection, before).await;
            assert!(health.pushes.last_ok, "{health:?}");
            eprintln!(
                "W8_EMPTY leaves={} nodes={} peer_frames={} delta_reply_waits=0 witness=scripted_peer_withholds_value_requests_until_DONE",
                leaves.len(),
                nodes,
                heard.len()
            );
        }

        async fn stale_completion_is_ignored(deselect: bool) {
            let net = SimNet::new(0x3A29, SimConfig::default());
            let mut node = Node::new(105);
            let collection = node.hold("retired completion", open());
            node.commit(collection, 1);
            node.observe();
            let snapshot = node.snapshot();
            let pinned = node.pinned(collection);
            let hosted = Hosted::new(node, &net);
            let (landing, _landings) = mpsc::unbounded_channel();
            let (events, _events) = mpsc::unbounded_channel();
            let mut task = Task {
                connections: hosted.table.clone(),
                snapshots: hosted.lander.snapshots.subscribe(),
                walks: Walks::new(hosted.lander.node.lock().unwrap().health.clone()),
                commands: hosted.walks.clone(),
                landing,
                events,
                running: HashMap::new(),
                next_id: 0,
            };
            task.observe(snapshot);
            let peer = Node::new(106).id();
            let kind = WalkKind::Records;
            let exchange = task.walks.start(peer, collection, kind).unwrap();
            let (driver, _acks, mut replaced) =
                task.register((peer, collection.raw, kind), false, &exchange);
            if deselect {
                let snapshot = {
                    let mut node = hosted.lander.node.lock().unwrap();
                    node.select(collection, false);
                    node.observe();
                    node.snapshot()
                };
                task.observe(snapshot);
            } else {
                task.command(Command::Closed { peer });
            }
            assert!(task.running.is_empty());
            assert_eq!(
                replaced.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            );
            task.command(Command::Ended {
                id: driver.id,
                peer,
                collection,
                kind,
                duplicate: false,
                ended: Ended {
                    sends: true,
                    receives: true,
                    confirmed: true,
                    landed: true,
                    root: summary(kind, pinned.repair()),
                    peer_root: Some(summary(kind, pinned.repair())),
                    agreed: Some(Arc::new(Tree::pinned(kind, pinned.repair()))),
                },
            });
            assert!(
                task.walks
                    .agreed
                    .get(&agreed_key(peer, collection.raw, kind))
                    .is_none()
            );
            assert_eq!(
                hosted.records(collection).len(),
                1,
                "retirement keeps landed values"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_closed_connection_cannot_restore_agreement_from_an_old_end() {
            stale_completion_is_ignored(false).await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_deselected_collection_cannot_restore_agreement_from_an_old_end() {
            stale_completion_is_ignored(true).await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_deselected_but_active_collection_refuses_new_open_and_incoming() {
            let net = SimNet::new(0x3A2B, SimConfig::default());
            let mut node = Node::new(114);
            let collection = node.hold("active but deselected", open());
            node.select(collection, false);
            node.observe();
            let snapshot = node.snapshot();
            assert!(snapshot.collection(collection).is_some(), "still active");
            assert!(snapshot.selected(collection).is_none());
            let hosted = Hosted::new(node, &net);
            let mut other = Node::new(115);
            other.hold("active but deselected", open());
            let other = Hosted::new(other, &net);
            let _connection = hosted.table.connect(other.peer).await.unwrap();
            assert!(
                hosted.table.current(other.peer).is_some(),
                "Open has a current connection"
            );
            let (landing, _landings) = mpsc::unbounded_channel();
            let (events, mut received) = mpsc::unbounded_channel();
            let mut task = Task {
                connections: hosted.table.clone(),
                snapshots: hosted.lander.snapshots.subscribe(),
                walks: Walks::new(hosted.lander.node.lock().unwrap().health.clone()),
                commands: hosted.walks.clone(),
                landing,
                events,
                running: HashMap::new(),
                next_id: 0,
            };
            task.observe(snapshot);
            let kind = WalkKind::Records;
            assert!(task.walks.start(other.peer, collection, kind).is_none());
            task.command(Command::Open {
                peer: other.peer,
                collection,
                kind,
            });
            assert!(task.running.is_empty());
            assert_eq!(task.next_id, 0);
            let (_script, driven) = tokio::io::duplex(1024);
            let (recv, send) = tokio::io::split(driven);
            let reset = Arc::new(Mutex::new(None));
            task.command(Command::Incoming {
                peer: other.peer,
                collection,
                kind,
                send: Box::new(Tx(send, reset.clone())),
                recv: Box::new(Rx(recv, reset.clone())),
            });
            assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_REFUSED));
            assert!(task.running.is_empty());
            assert_eq!(task.next_id, 0);
            assert!(received.try_recv().is_err(), "no admitted exchange events");
        }

        async fn blocked_final_write_finishes(retire: bool) {
            let net = SimNet::new(0x3A2A, SimConfig::default());
            let mut node = Node::new(107);
            let collection = node.hold("blocked final LANDED", open());
            let kind = WalkKind::Records;
            let exchange =
                Exchange::start(collection, kind, node.pinned(collection), None, true, true);
            let hosted = Hosted::new(node, &net);
            let (landing, _landings) = mpsc::unbounded_channel();
            let (commands, _commands) = mpsc::unbounded_channel();
            let driver = Driver {
                connections: hosted.table.clone(),
                snapshots: hosted.lander.snapshots.subscribe(),
                landing,
                commands,
                id: 1,
                peer: Node::new(108).id(),
                collection,
                kind,
            };
            let (script, driven) = tokio::io::duplex(1 << 20);
            let (mut recv, mut send) = tokio::io::split(script);
            let (driven_recv, driven_send) = tokio::io::split(driven);
            let reset = Arc::new(Mutex::new(None));
            let attempted = Arc::new(Mutex::new(false));
            let (_acks, acked) = mpsc::unbounded_channel();
            let (replace, replaced) = oneshot::channel();
            let task_attempted = attempted.clone();
            let task_reset = reset.clone();
            let task = tokio::spawn(async move {
                drive(
                    &driver,
                    exchange,
                    Box::new(BlockLanded(
                        Tx(driven_send, task_reset.clone()),
                        task_attempted,
                    )),
                    Box::new(Rx(driven_recv, task_reset)),
                    acked,
                    replaced,
                )
                .await
            });
            write(
                &mut send,
                Frame::Root {
                    summary: PatchSummary::new(None, 0).unwrap(),
                },
            )
            .await;
            loop {
                if read(&mut recv).await == Some(Frame::Done) {
                    break;
                }
            }
            write(&mut send, Frame::Landed).await;
            write(&mut send, Frame::Done).await;
            for _ in 0..100 {
                if *attempted.lock().unwrap() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                *attempted.lock().unwrap(),
                "LANDED blocks after logical confirmation"
            );
            if retire {
                drop(replace);
            } else {
                tokio::time::advance(WALK_DEADLINE + Duration::from_secs(1)).await;
            }
            let (ended, duplicate) = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("blocked final writer retires or times out")
                .unwrap();
            assert!(!duplicate);
            assert!(ended.confirmed);
            assert!(!ended.landed);
            assert!(ended.agreed.is_none());
            assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_FAILED));
        }

        #[tokio::test(start_paused = true)]
        async fn a_retired_driver_cancels_its_blocked_final_landed_write() {
            blocked_final_write_finishes(true).await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_blocked_final_landed_write_has_a_progress_deadline() {
            blocked_final_write_finishes(false).await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_failed_landed_write_cannot_leave_a_shared_agreement() {
            let net = SimNet::new(0x3A28, SimConfig::default());
            let mut node = Node::new(103);
            let collection = node.hold("LANDED write failure", open());
            node.commit(collection, 1);
            node.observe();
            let kind = WalkKind::Records;
            let exchange =
                Exchange::start(collection, kind, node.pinned(collection), None, true, true);
            let hosted = Hosted::new(node, &net);
            let (landing, _landings) = mpsc::unbounded_channel();
            let (commands, _commands) = mpsc::unbounded_channel();
            let driver = Driver {
                connections: hosted.table.clone(),
                snapshots: hosted.lander.snapshots.subscribe(),
                landing,
                commands,
                id: 1,
                peer: Node::new(104).id(),
                collection,
                kind,
            };
            let (script, driven) = tokio::io::duplex(1 << 20);
            let (mut recv, mut send) = tokio::io::split(script);
            let (driven_recv, driven_send) = tokio::io::split(driven);
            let reset = Arc::new(Mutex::new(None));
            let attempted = Arc::new(Mutex::new(false));
            let (_acks, acked) = mpsc::unbounded_channel();
            let (_replace, replaced) = oneshot::channel();
            let task_attempted = attempted.clone();
            let task_reset = reset.clone();
            let task = tokio::spawn(async move {
                drive(
                    &driver,
                    exchange,
                    Box::new(FailLanded(
                        Tx(driven_send, task_reset.clone()),
                        task_attempted,
                    )),
                    Box::new(Rx(driven_recv, task_reset)),
                    acked,
                    replaced,
                )
                .await
            });
            write(
                &mut send,
                Frame::Root {
                    summary: PatchSummary::new(None, 0).unwrap(),
                },
            )
            .await;
            let mut keys = Vec::new();
            loop {
                match read(&mut recv).await {
                    Some(Frame::Leaf { key }) => keys.push(key),
                    Some(Frame::Done) => break,
                    Some(Frame::Root { .. } | Frame::Node { .. }) => {}
                    other => panic!("our delta: {other:?}"),
                }
            }
            for key in keys {
                write(&mut send, Frame::ValueRequest { key }).await;
                let Some(Frame::Value { key: served, bytes }) = read(&mut recv).await else {
                    panic!("requested value");
                };
                assert_eq!(served, key);
                assert_eq!(
                    decode_record(collection, &bytes)
                        .unwrap()
                        .fingerprint()
                        .raw(),
                    key
                );
            }
            // The peer acknowledges our delta before ending its empty one.
            write(&mut send, Frame::Landed).await;
            write(&mut send, Frame::Done).await;
            let (ended, duplicate) = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("failed write wakes/finishes the driver")
                .unwrap();
            assert!(
                *attempted.lock().unwrap(),
                "a real LANDED write was attempted"
            );
            assert!(!duplicate);
            assert!(ended.confirmed, "the peer's directional receipt arrived");
            assert!(!ended.landed, "our failed write is not a receipt");
            assert!(ended.agreed.is_none());
            assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_FAILED));
        }

        /// The task's driver over a simulated connection into another
        /// task's, both ways. (a) Fifty records to an empty peer: all land,
        /// both LANDEDs cross, and both sides confirm the same agreed root.
        /// (b) The agreed tree again: ROOT then DONE each way, answered with
        /// LANDED alone. (c) A peer holding forty of the fifty from
        /// elsewhere asks for exactly the ten missing values. (d) A peer
        /// with no current connection gets no exchange at all.
        #[tokio::test(start_paused = true)]
        async fn an_exchange_over_a_connection_lands_confirms_and_prunes() {
            let (net, sender, mut empty, collection, records) = pair(0x3A1F, (57, 58), 50);
            let kind = WalkKind::Records;
            let root = summary(
                kind,
                sender
                    .lander
                    .node
                    .lock()
                    .unwrap()
                    .pinned(collection)
                    .repair(),
            );
            let all = records.iter().copied().collect::<BTreeSet<_>>();
            let _connection = sender.table.connect(empty.peer).await.unwrap();

            // (a) Everything lands, and both sides confirm the union.
            let from = sender.taps.len();
            let health = sender.exchange(empty.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
            assert_eq!(health.confirmed.records, Some(root));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(heard.last(), Some(&FRAME_LANDED));
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 50);
            assert_eq!(count(&sent, FRAME_LEAF), 50);
            assert_eq!(empty.records(collection), all);
            let other = empty.health(collection, sender.peer).unwrap();
            assert!(other.receives.last_ok && other.pushes.last_ok, "{other:?}");
            assert_eq!(other.confirmed.records, Some(root));
            assert_eq!(other.received.records, Some(root));
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

            // (b) The agreed tree is ROOT then DONE each way, answered with
            // LANDED alone.
            let from = sender.taps.len();
            let health = sender.exchange(empty.peer, collection, kind).await;
            assert_eq!((health.pushes.ok, health.pushes.failed), (2, 0));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(sent, [FRAME_OPEN, FRAME_ROOT, FRAME_DONE, FRAME_LANDED]);
            assert_eq!(heard, [FRAME_ROOT, FRAME_DONE, FRAME_LANDED]);

            // The peer commits a record of its own: its delta is that
            // record's path, which lands here, and the sender's is nothing.
            let own = empty.commit(collection, 1_000);
            let from = sender.taps.len();
            let health = sender.exchange(empty.peer, collection, kind).await;
            assert_eq!((health.pushes.ok, health.pushes.failed), (3, 0));
            let (sent, heard) = crossed(&sender.taps, from, empty.peer);
            assert_eq!(count(&sent, FRAME_NODE), 0);
            assert_eq!(count(&sent, FRAME_VALUE_REQUEST), 1);
            assert_eq!(count(&heard, FRAME_LEAF), 1);
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 0);
            assert!(
                sender
                    .records(collection)
                    .iter()
                    .any(|record| record.fingerprint().raw() == own)
            );
            assert_eq!(sender.records(collection).len(), 51);

            // (c) A peer that holds forty of the fifty asks for ten.
            let mut partial = Node::new(59);
            partial.hold("pair", open());
            for record in &records[..40] {
                partial.store.insert(*record).unwrap();
            }
            partial.observe();
            let partial = Hosted::new(partial, &net);
            let _connection = sender.table.connect(partial.peer).await.unwrap();
            let from = sender.taps.len();
            let health = sender.exchange(partial.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            let (sent, heard) = crossed(&sender.taps, from, partial.peer);
            // The ten of the fifty, and the peer's own record landed above.
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 11);
            assert_eq!(count(&sent, FRAME_VALUE_REQUEST), 0);
            assert!(count(&sent, FRAME_LEAF) >= 11);
            assert_eq!(partial.records(collection).len(), 51);
            assert!(partial.records(collection).is_superset(&all));

            // (d) A peer with no current connection gets no exchange.
            let stranger = Node::new(61).id();
            sender.walks.open(stranger, collection, kind);
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert!(sender.health(collection, stranger).is_none());
        }

        /// Two peers holding the same 300 records agree on them in one
        /// exchange; then each commits ten of its own and A opens one
        /// bidirectional stream. On it each side's delta is the
        /// root NODE, which announces the shared subtrees, plus the nodes on
        /// the paths to its own ten; exactly ten values are asked for each
        /// way, and both sides agree on the union.
        #[tokio::test(start_paused = true)]
        async fn a_shared_subtree_costs_one_frame_per_direction() {
            let (_net, a, b, collection, records) = pair(0x3A22, (62, 63), 300);
            let kind = WalkKind::Records;
            {
                let mut node = b.lander.node.lock().unwrap();
                for record in &records {
                    node.store.insert(*record).unwrap();
                }
                node.observe();
                let snapshot = node.snapshot();
                b.lander.snapshots.send_replace(Some(snapshot));
            }
            let _connection = a.table.connect(b.peer).await.unwrap();
            let health = a.exchange(b.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            let shared = summary(
                kind,
                a.lander.node.lock().unwrap().pinned(collection).repair(),
            );
            assert_eq!(health.confirmed.records, Some(shared));
            assert_eq!(
                b.health(collection, a.peer).unwrap().confirmed.records,
                Some(shared)
            );

            let own_a = (0..10)
                .map(|data| a.commit(collection, 1_000 + data))
                .collect::<Vec<_>>();
            let own_b = (0..10)
                .map(|data| b.commit(collection, 2_000 + data))
                .collect::<Vec<_>>();
            let from = [a.taps.len(), b.taps.len()];
            let before = [a.health(collection, b.peer), b.health(collection, a.peer)];
            a.walks.open(b.peer, collection, kind);
            let health_a = a.ended(b.peer, collection, before[0].clone()).await;
            let health_b = b.ended(a.peer, collection, before[1].clone()).await;
            assert!(
                health_a.pushes.last_ok && health_a.receives.last_ok,
                "{health_a:?}"
            );
            assert!(
                health_b.pushes.last_ok && health_b.receives.last_ok,
                "{health_b:?}"
            );
            assert_eq!((health_a.pushes.ok, health_a.pushes.failed), (2, 0));
            assert_eq!((health_b.pushes.ok, health_b.pushes.failed), (2, 0));
            assert_eq!(health_a.confirmed.records, health_b.confirmed.records);
            assert_eq!(a.records(collection).len(), 320);
            assert_eq!(b.records(collection), a.records(collection));

            for (side, from, own, other) in
                [(&a, from[0], &own_a, b.peer), (&b, from[1], &own_b, a.peer)]
            {
                let (sent, heard) = crossed(&side.taps, from, other);
                assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 10);
                assert_eq!(count(&sent, FRAME_VALUE_REQUEST), 10);
                let pinned = side.lander.node.lock().unwrap().pinned(collection);
                let expected = paths(pinned.repair().records().patch(), own);
                assert!(expected.contains(&Vec::new()));
                assert_eq!(count(&sent, FRAME_NODE), expected.len(), "{sent:?}");
                assert_eq!(count(&sent, FRAME_LEAF), 10);
                eprintln!(
                    "W8_AGREED_SHARED peer={other:?} nodes={} leaves=10 value_requests_sent=10 value_requests_received=10 fixture=prior_agreement_plus_10_unique_each scheduler=sim_zero_stream_latency",
                    expected.len()
                );
            }
        }

        /// After one exchange, seven records appended on one side and three
        /// on the other go out as the nodes on their paths alone: seven and
        /// three values are asked for, and both sides agree on the same
        /// root before and after.
        #[tokio::test(start_paused = true)]
        async fn an_incremental_exchange_skips_what_was_agreed_and_lands_only_the_new() {
            let (_net, a, b, collection, _) = pair(0x3A23, (64, 65), 300);
            let kind = WalkKind::Records;
            let _connection = a.table.connect(b.peer).await.unwrap();
            let health = a.exchange(b.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            let agreed = health.confirmed.records;
            assert_eq!(
                b.health(collection, a.peer).unwrap().confirmed.records,
                agreed
            );
            assert_eq!(b.records(collection).len(), 300);

            let seven = (0..7)
                .map(|data| a.commit(collection, 1_000 + data))
                .collect::<Vec<_>>();
            let three = (0..3)
                .map(|data| b.commit(collection, 2_000 + data))
                .collect::<Vec<_>>();
            let from = [a.taps.len(), b.taps.len()];
            let health = a.exchange(b.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            let health_b = b.health(collection, a.peer).unwrap();
            assert!(
                health_b.pushes.last_ok && health_b.receives.last_ok,
                "{health_b:?}"
            );
            assert_eq!(health.confirmed.records, health_b.confirmed.records);
            assert_ne!(health.confirmed.records, agreed);
            assert_eq!(a.records(collection).len(), 310);
            assert_eq!(b.records(collection), a.records(collection));
            for (side, from, own, other, asked) in [
                (&a, from[0], &seven, b.peer, 3),
                (&b, from[1], &three, a.peer, 7),
            ] {
                let (sent, heard) = crossed(&side.taps, from, other);
                assert_eq!(count(&heard, FRAME_VALUE_REQUEST), own.len());
                assert_eq!(count(&sent, FRAME_VALUE_REQUEST), asked);
                let pinned = side.lander.node.lock().unwrap().pinned(collection);
                let expected = paths(pinned.repair().records().patch(), own);
                assert_eq!(count(&sent, FRAME_NODE), expected.len(), "{sent:?}");
                assert_eq!(count(&sent, FRAME_LEAF), own.len());
                eprintln!(
                    "W8_INCREMENTAL peer={other:?} nodes={} leaves={} value_requests_sent={asked} value_requests_received={} scheduler=sim_zero_stream_latency",
                    expected.len(),
                    own.len(),
                    own.len()
                );
            }
        }

        /// Both sides open an exchange of the same tree within one round
        /// trip: the stream the smaller peer id opened survives and lands,
        /// the other is reset at both ends and counted nowhere.
        #[tokio::test(start_paused = true)]
        async fn simultaneous_opens_keep_the_smaller_peer_s_stream() {
            let (_net, a, b, collection, _) = pair(0x3A24, (66, 67), 100);
            let kind = WalkKind::Records;
            let _connection = a.table.connect(b.peer).await.unwrap();
            // The accepted connection is current at B once its opening
            // frame is read.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (smaller, larger) = if a.peer < b.peer { (&a, &b) } else { (&b, &a) };
            a.walks.open(b.peer, collection, kind);
            b.walks.open(a.peer, collection, kind);
            let health_a = a.ended(b.peer, collection, None).await;
            let health_b = b.ended(a.peer, collection, None).await;
            for health in [&health_a, &health_b] {
                assert!(
                    health.pushes.last_ok && health.receives.last_ok,
                    "{health:?}"
                );
                assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
                assert_eq!((health.receives.ok, health.receives.failed), (1, 0));
            }
            assert_eq!(health_a.confirmed.records, health_b.confirmed.records);
            assert_eq!(b.records(collection).len(), 100);

            // Each side opened one stream and heard the other's Open.
            for (side, other) in [(&a, b.peer), (&b, a.peer)] {
                let (sent, heard) = crossed(&side.taps, 0, other);
                assert_eq!(count(&sent, FRAME_OPEN), 1);
                assert_eq!(count(&heard, FRAME_OPEN), 1);
            }
            // On the smaller side, the stream that carried LANDED both ways
            // is the one it opened; on the larger side, the one it accepted.
            for (side, other, opened) in
                [(smaller, larger.peer, true), (larger, smaller.peer, false)]
            {
                let crossed = walked(&side.taps, 0, other);
                let streams = crossed
                    .iter()
                    .map(|crossed| crossed.stream)
                    .collect::<BTreeSet<_>>();
                assert_eq!(streams.len(), 2);
                let landed = |stream, sent| {
                    crossed.iter().any(|crossed| {
                        crossed.stream == stream
                            && crossed.sent == sent
                            && crossed.kind == FRAME_LANDED
                    })
                };
                let survivor = streams
                    .iter()
                    .copied()
                    .find(|stream| landed(*stream, true) && landed(*stream, false))
                    .expect("one stream carried LANDED both ways");
                let open = crossed
                    .iter()
                    .find(|crossed| crossed.stream == survivor && crossed.kind == FRAME_OPEN)
                    .unwrap();
                assert_eq!(open.sent, opened);
                let loser = streams
                    .iter()
                    .copied()
                    .find(|stream| *stream != survivor)
                    .unwrap();
                assert!(!landed(loser, true) && !landed(loser, false));
                assert!(
                    !crossed
                        .iter()
                        .any(|crossed| crossed.stream == loser && crossed.kind == FRAME_DONE)
                );
            }
        }

        /// An exchange cut after some values landed leaves them, fails both
        /// ways and forgets the agreed tree. The next exchange, driven by
        /// the walks task over a connection, asks for exactly the rest, and
        /// it lands.
        #[tokio::test(start_paused = true)]
        async fn an_exchange_cut_mid_way_leaves_what_landed_and_the_next_asks_for_the_rest() {
            let net = SimNet::new(
                0x3A25,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let kind = WalkKind::Records;
            let mut sender = Node::new(68);
            let collection = sender.hold("cut", open());
            let records = (0..300)
                .map(|data| sender.commit(collection, data))
                .collect::<BTreeSet<_>>();
            sender.observe();
            let root = summary(kind, sender.pinned(collection).repair());
            let mut receiver = Node::new(69);
            receiver.hold("cut", open());
            receiver.observe();
            let receiver = Hosted::new(receiver, &net);

            // The first, scripted, answers fifty values and drops the
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
            // The scripted peer LANDED our empty delta before cutting its
            // own. That directional push succeeded, but no union was agreed.
            assert!(health.pushes.last_ok && health.confirmed.records.is_none());

            // The sender agreed on nothing, and the next exchange asks only
            // for the rest.
            let sender = Hosted::new(sender, &net);
            assert!(sender.health(collection, receiver.peer).is_none());
            let _connection = sender.table.connect(receiver.peer).await.unwrap();
            let from = sender.taps.len();
            let health = sender.exchange(receiver.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!(health.confirmed.records, Some(root));
            let (sent, heard) = crossed(&sender.taps, from, receiver.peer);
            assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 300 - landed);
            assert!((300 - landed..=300).contains(&count(&sent, FRAME_LEAF)));
            assert_eq!(receiver.records(collection), records);
        }

        /// Open a scripted stream from `sender` to `receiver` and stream
        /// until fifty values were answered: the halves, still open, and the
        /// task's reset of the stream once they drop.
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
            assert!(
                !stream(sender, collection, &mut send, &mut recv, 50, None)
                    .await
                    .0
            );
            (send, recv, async move { reset(&reset_code).await })
        }

        /// A references exchange whose one held blob takes longer than the
        /// walk deadline to transfer still lands: the fetch is held to
        /// progress between chunks, not to a deadline for the whole blob,
        /// and after DONE each side waits for the other's LANDED as long as
        /// the connection lives.
        #[tokio::test(start_paused = true)]
        async fn a_references_exchange_lands_while_one_held_blob_outlasts_the_walk_deadline() {
            let net = SimNet::new(
                0x3A26,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let kind = WalkKind::References;
            // Six writes twenty seconds apart: two minutes for one blob.
            let (sender, collection, root, handles, receiver) =
                holding(&net, (70, 71), &[7], Duration::from_secs(20), 1 << 18);
            let mut receiver = Hosted::new(receiver, &net);
            let _connection = sender.table.connect(receiver.peer).await.unwrap();
            let from = sender.taps.len();
            let started = tokio::time::Instant::now();
            let health = sender.exchange(receiver.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
            let took = started.elapsed();
            assert!(took > WALK_DEADLINE, "{took:?}");
            let (sent, heard) = crossed(&sender.taps, from, receiver.peer);
            assert_eq!(heard.last(), Some(&FRAME_LANDED));
            assert!(count(&sent, FRAME_LEAF) >= 1);
            assert!(holds(
                &receiver.lander.node.lock().unwrap(),
                collection,
                root,
                &handles
            ));
            assert_eq!(
                receiver.events.try_recv(),
                Ok(Event::Receiving { collection, kind })
            );
            assert_eq!(
                receiver.events.try_recv(),
                Ok(Event::Received {
                    collection,
                    kind,
                    landed: true
                })
            );
        }

        /// A fetch phase longer than the walk deadline, two held blobs the
        /// sender serves one at a time, resets neither end: after DONE the
        /// receiver reads nothing it is owed and times nothing while it
        /// fetches, and the sender waits for LANDED as long as the
        /// connection lives.
        #[tokio::test(start_paused = true)]
        async fn a_references_fetch_phase_longer_than_the_walk_deadline_resets_neither_end() {
            let net = SimNet::new(
                0x3A27,
                SimConfig {
                    latency: Duration::from_millis(10)..Duration::from_millis(10),
                },
            );
            let kind = WalkKind::References;
            // Four writes fifteen seconds apart per blob, one blob at a
            // time: each fetch within the deadline, the two together past it.
            let (sender, collection, root, handles, receiver) =
                holding(&net, (72, 73), &[8, 9], Duration::from_secs(15), 1 << 20);
            let receiver = Hosted::new(receiver, &net);
            let _connection = sender.table.connect(receiver.peer).await.unwrap();
            let from = sender.taps.len();
            let started = tokio::time::Instant::now();
            let health = sender.exchange(receiver.peer, collection, kind).await;
            assert!(health.pushes.last_ok, "{health:?}");
            assert_eq!((health.pushes.ok, health.pushes.failed), (1, 0));
            let took = started.elapsed();
            assert!(took > WALK_DEADLINE, "{took:?}");
            let (_, heard) = crossed(&sender.taps, from, receiver.peer);
            assert_eq!(heard.last(), Some(&FRAME_LANDED));
            let received = receiver.health(collection, sender.peer).unwrap();
            assert!(received.receives.last_ok, "{received:?}");
            assert_eq!((received.receives.ok, received.receives.failed), (1, 0));
            assert!(holds(
                &receiver.lander.node.lock().unwrap(),
                collection,
                root,
                &handles
            ));
        }
    }
}
