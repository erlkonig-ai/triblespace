//! One exchange of one collection tree with one neighbour: both sides'
//! deltas on one `walk/1` stream (design: walk streams).
//!
//! Two neighbours that sync a collection keep, per tree, the AGREED tree:
//! the union of the two trees they pinned for their last confirmed
//! exchange, which both hold since. An exchange sends each side's delta
//! against it, breadth first and without waiting for the other side. A side
//! pins its snapshot and sends ROOT; then, from a queue of locators that
//! starts at the root if its root differs from the agreed root, it sends
//! every branch it reaches as a NODE and every leaf as a LEAF, and queues the
//! children of each branch that differ from the agreed tree's node at their
//! locator: a child equal to it is skipped, because the peer holds the
//! agreed tree. A NODE's child list announces the digest of every child, and
//! ROOT the root's. A side that hears an announcement of a locator whose
//! digest its own tree has there drops that locator and everything queued
//! under it, since the peer holds the subtree: "I have this" and "stop
//! sending me this" are one message, and with the delta going breadth first
//! announcements can prune work still queued. How much has already crossed
//! depends on scheduling and network delay, not on FIFO alone. DONE ends a
//! side's delta. The queue is always FIFO; exceeding [`FLOOD_LOCATORS`] fails
//! the bounded exchange rather than silently changing traversal order.
//!
//! The side that receives C from the peer lands the peer's delta as it
//! arrives. It keeps the locators the peer owes it, each with the digest and
//! leaf count declared for it: the root's, by ROOT, then every accepted
//! NODE's children, except those it already holds at that locator in its
//! pinned tree or in the agreed tree, which are accounted; so the children
//! the peer skips as equal to the agreed tree and those it skips because
//! this side announced them are accounted without a frame. A NODE is
//! accepted only at a locator owed, checked against the digest declared
//! there; a LEAF only under the owed locator on its key's path, with one
//! leaf and the digest its key binds. A NODE or LEAF at a locator this side
//! holds, sent before this side's announcement reached the peer, is checked
//! against what this side holds and owes nothing. The values of leaves the
//! live store lacks are asked for with VALUE_REQUEST, [`MAX_WALK_REQUESTS`]
//! at a time, and land through the landing task; a held reference is noted
//! held when its blob is resident and fetched by hash otherwise. A side
//! sends LANDED once the peer's DONE is in, nothing is owed, the leaves
//! pushed plus those accounted are the root's count, and every value asked
//! for landed without a failed insert, fetch or deferred proof; a side that
//! receives nothing lands nothing and sends LANDED right after the peer's
//! DONE. A side that has sent and received LANDED has confirmed the
//! exchange: the agreed tree preserves prior agreement and includes its
//! pinned tree plus every leaf the peer sent, which the peer computes alike.
//! An exchange that ends any other
//! way forgets the agreed tree; what landed stays.
//!
//! A side that sends C to the peer streams its delta; one that does not
//! sends an empty ROOT then DONE, without revealing its private tree's
//! digest/count, and the agreed tree it keeps is the one it held
//! plus what the peer sent, which is the peer's pinned tree while that tree
//! only grows. Values are served only by a side that sends.
//!
//! Separate bounds keep what an exchange costs. More than [`FLOOD_LOCATORS`]
//! queued/owed locators or equal announcements, or [`FLOOD_WANTED`] leaves
//! waiting for values, fails the exchange. Honest sufficiently wide trees
//! can exceed the explicit locator budget too; this is not unbounded sync.
//! Allocation grows with observed work, not eagerly to either ceiling.
//! And while [`MAX_WALK_UNLANDED`]
//! values are with the landing task the stream is not read
//! ([`Exchange::want_read`]), so the transport's flow control holds the
//! peer. The driver times its wait for a frame only while one is owed
//! ([`Exchange::awaits`]): before the peer's DONE, and for the values asked
//! for; after DONE the peer's LANDED takes what time its landings take.
//!
//! [`Exchange`] is that machine without its stream: [`crate::walk`] drives
//! it, feeding it the peer's frames ([`Exchange::on_frame`]) and what
//! landing and blob fetches report, and pulling the frames of its delta
//! ([`Exchange::next_delta`]) as the stream takes them, so the stream's flow
//! control is the only backpressure on the delta.

use std::collections::VecDeque;
use std::sync::Arc;

use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::{CollectionHandle, CollectionRecord};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH, PatchHash};

use crate::channel::NetEvent;
use crate::collection_activation::CollectionRepairOverlay;
use crate::host::{CollectionSnapshot, StoreSnapshot};
use crate::patch_repair::{
    PatchBranch, PatchChild, PatchNode, PatchRepairRequest, PatchSummary, validate_patch_node,
};
use crate::protocol::RawHash;
use crate::walk::{
    Admit, KEY_BYTES, MAX_WALK_REQUESTS, MAX_WALK_UNLANDED, Value, WalkKind, admit_fetched,
    admit_missing, admit_value, contains, local_summary, node, node_summary, summary, value,
};
use crate::walk_stream::Frame;

/// Missing leaves waiting for values beyond which an exchange fails. This
/// smaller bound is independent of the breadth-first locator frontier.
pub(crate) const FLOOD_WANTED: usize = 32 * 1024;
/// Grow-on-demand FIFO/owed/announcement budget. Unlike a withheld-value
/// flood, an honest wide frontier may exceed 32k before any leaf is sent.
const FLOOD_LOCATORS: usize = 1024 * 1024;

/// A relative locator's length followed by its zero-padded bytes. The length
/// distinguishes compressed prefixes from keys ending in zero bytes.
fn locator_key(locator: &[u8]) -> [u8; KEY_BYTES + 1] {
    let mut key = [0; KEY_BYTES + 1];
    key[0] = u8::try_from(locator.len()).expect("a checked locator fits its key");
    key[1..1 + locator.len()].copy_from_slice(locator);
    key
}

/// One kind's tree as both sides agreed on it: a persistent PATCH, the
/// union of the two trees pinned for the last confirmed exchange, kept per
/// peer, collection and kind ([`crate::walk::Walks`]).
#[derive(Clone)]
pub(crate) enum Tree {
    Records(PATCH<KEY_BYTES, IdentitySchema, CollectionRecord, Blake3Merkle>),
    /// Keyed by the collection, then the proof id.
    Authorization(
        CollectionHandle,
        PATCH<64, IdentitySchema, CapabilityProof, Blake3Merkle>,
    ),
    References(PATCH<KEY_BYTES, IdentitySchema, (), Blake3Merkle>),
}

impl Tree {
    /// The `kind` tree of `overlay`, shared with it.
    pub(crate) fn pinned(kind: WalkKind, overlay: &CollectionRepairOverlay) -> Self {
        match kind {
            WalkKind::Records => Self::Records(overlay.records().patch().clone()),
            WalkKind::Authorization => Self::Authorization(
                overlay.collection(),
                overlay.authorization_evidence().patch().clone(),
            ),
            WalkKind::References => Self::References(overlay.blob_inventory().clone()),
        }
    }

    fn empty(kind: WalkKind, collection: CollectionHandle) -> Self {
        match kind {
            WalkKind::Records => Self::Records(PATCH::new()),
            WalkKind::Authorization => Self::Authorization(collection, PATCH::new()),
            WalkKind::References => Self::References(PATCH::new()),
        }
    }

    pub(crate) fn summary(&self) -> PatchSummary {
        self.at(&[]).unwrap_or_else(empty)
    }

    /// A newer serving observation needs another exchange only for keys
    /// outside the agreed union. Publication may still lag landings; a
    /// strict subset is not new work and must not trigger an empty repush.
    pub(crate) fn has_new_keys(&self, current: &Self) -> bool {
        match (self, current) {
            (Self::Records(agreed), Self::Records(current)) => {
                !current.difference(agreed).is_empty()
            }
            (Self::Authorization(_, agreed), Self::Authorization(_, current)) => {
                !current.difference(agreed).is_empty()
            }
            (Self::References(agreed), Self::References(current)) => {
                !current.difference(agreed).is_empty()
            }
            _ => unreachable!("one agreement contains one kind"),
        }
    }

    fn union(&mut self, other: Self) {
        match (self, other) {
            (Self::Records(target), Self::Records(other)) => target.union(other),
            (
                Self::Authorization(collection, target),
                Self::Authorization(other_collection, other),
            ) => {
                assert_eq!(*collection, other_collection);
                target.union(other);
            }
            (Self::References(target), Self::References(other)) => target.union(other),
            _ => unreachable!("one agreement contains one kind"),
        }
    }

    /// The summary of the subtree at `locator`, relative to the kind's base,
    /// if present.
    pub(crate) fn at(&self, locator: &[u8]) -> Option<PatchSummary> {
        match self {
            Self::Records(patch) => node_summary(patch, locator),
            Self::Authorization(collection, patch) => {
                node_summary(patch, &[&collection.raw[..], locator].concat())
            }
            Self::References(patch) => node_summary(patch, locator),
        }
    }

    fn insert(&mut self, key: [u8; KEY_BYTES], value: Value) {
        match (self, value) {
            (Self::Records(patch), Value::Record(record)) => {
                patch.insert(&Entry::with_value(&key, record));
            }
            (Self::Authorization(collection, patch), Value::Proof(proof)) => {
                let mut absolute = [0; 64];
                absolute[..KEY_BYTES].copy_from_slice(&collection.raw);
                absolute[KEY_BYTES..].copy_from_slice(&key);
                patch.insert(&Entry::with_value(&absolute, proof));
            }
            (Self::References(patch), Value::Handle) => patch.insert(&Entry::new(&key)),
            _ => unreachable!("a value of another kind"),
        }
    }

    /// Include a subtree accounted from our own pinned tree. A receive-only
    /// side starts with no advertised keys, so already-held peer subtrees
    /// still have to enter its next agreement. Traverse only that subtree,
    /// not a shadow inventory of the live store.
    fn include_at(&mut self, source: &Self, locator: &[u8]) {
        match (self, source) {
            (Self::Records(target), Self::Records(source)) => {
                if let Some(node) = source.merkle_node(locator) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::with_value(&key, *source.get(&key).unwrap()));
                    }
                }
            }
            (Self::Authorization(collection, target), Self::Authorization(_, source)) => {
                let absolute = [&collection.raw[..], locator].concat();
                if let Some(node) = source.merkle_node(&absolute) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::with_value(&key, source.get(&key).unwrap().clone()));
                    }
                }
            }
            (Self::References(target), Self::References(source)) => {
                if let Some(node) = source.merkle_node(locator) {
                    for key in node.items_after(None, usize::MAX) {
                        target.insert(&Entry::new(&key));
                    }
                }
            }
            _ => unreachable!("one agreement contains one kind"),
        }
    }
}

fn empty() -> PatchSummary {
    PatchSummary::new(None, 0).expect("the empty summary is canonical")
}

/// What an exchange asks of its driver.
#[derive(Debug)]
pub(crate) enum Out {
    Send(Frame),
    /// Values for the landing task, acknowledged with
    /// [`Exchange::on_landed_ack`].
    Land(Vec<NetEvent>),
    /// Fetch a blob by hash from the peer, answered with
    /// [`Exchange::on_fetched`]: a held reference, or the routing descriptor
    /// a deferred `proof` names.
    Fetch {
        handle: RawHash,
        proof: Option<CapabilityProof>,
    },
}

/// How an exchange ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Both sides sent LANDED: the agreed tree is the union.
    Confirmed,
    Failed(Failure),
}

/// Why an exchange failed. What landed stays, and the agreed tree is
/// forgotten.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    /// The collection is not active here.
    Unavailable,
    /// A frame out of its place: a node, leaf or end before the root, a
    /// second root, a node or leaf at a locator the peer does not owe and
    /// this side does not hold, a value nobody asked for, a value request
    /// for a key the pinned tree lacks or from a peer this side does not
    /// send to, a LANDED before this side's DONE or a second one, an OPEN, or
    /// more queued/owed locators, waiting leaves or announcements than the
    /// explicit resource budgets permit, including honest wider trees.
    Protocol,
    /// A node is not canonical, or is not the node its parent (or the root)
    /// declared at its locator.
    BadNode,
    /// A value that does not decode, is not under its key, or is not
    /// evidence for the collection.
    BadValue,
    /// The leaves pushed and accounted do not add up to the root's count, or
    /// a locator owed was never pushed.
    CountMismatch,
    /// A value failed to land, or a held reference could not be fetched.
    InsertFailed,
    /// A proof waits for a descriptor that did not arrive.
    DeferredProof,
}

/// An exchange as it ended, for the walks task to settle.
pub(crate) struct Ended {
    pub(crate) sends: bool,
    pub(crate) receives: bool,
    /// The peer's LANDED arrived: this side's delta is confirmed.
    pub(crate) confirmed: bool,
    /// This side sent LANDED: the peer's delta landed whole.
    pub(crate) landed: bool,
    /// This side's pinned root.
    pub(crate) root: PatchSummary,
    /// The peer's root, if its ROOT arrived.
    pub(crate) peer_root: Option<PatchSummary>,
    /// The agreed tree, when both LANDEDs crossed.
    pub(crate) agreed: Option<Arc<Tree>>,
}

/// One exchange of one tree with one peer.
pub(crate) struct Exchange {
    collection: CollectionHandle,
    kind: WalkKind,
    pinned: Arc<CollectionSnapshot>,
    /// This side sends C to the peer: it streams its delta and serves
    /// values.
    sends: bool,
    /// This side receives C from the peer: it lands the peer's delta.
    receives: bool,
    agreed: Option<Arc<Tree>>,
    /// The agreed tree this exchange ends with if it is confirmed: this
    /// prior agreed union plus this side's pinned tree when it sends, and
    /// every authenticated peer leaf or already-held subtree accounted.
    next: Tree,
    /// The store as of the last frame: what missing leaves are checked
    /// against.
    snapshot: Option<Arc<StoreSnapshot>>,
    root_sent: bool,
    /// Locators of this side's delta still to send.
    queue: VecDeque<Vec<u8>>,
    /// Locators the peer announced with the digest this side's tree has
    /// there, not reached by the delta yet. Never more than
    /// [`FLOOD_LOCATORS`].
    announced: PATCH<33, IdentitySchema, ()>,
    done_sent: bool,
    peer_root: Option<PatchSummary>,
    /// The nodes the peer owes, by locator: the digest and leaf count
    /// declared for each by its parent, or by ROOT for the root. Consumed
    /// by the node or leaf pushed at each; DONE needs every one consumed.
    /// Never more than [`FLOOD_LOCATORS`].
    owed: PATCH<33, IdentitySchema, ([u8; 32], u64)>,
    /// Leaves pushed, and the leaves of the subtrees accounted as held.
    accounted: u64,
    /// Missing leaves not yet asked for, in the order pushed. Never more
    /// than [`FLOOD_WANTED`].
    wanted: VecDeque<[u8; KEY_BYTES]>,
    /// Value requests in flight.
    requests: PATCH<KEY_BYTES, IdentitySchema, ()>,
    /// Blob fetches in flight.
    fetching: usize,
    /// Values with the landing task.
    unlanded: usize,
    failed: u64,
    deferred: bool,
    peer_done: bool,
    landed_sent: bool,
    landed_received: bool,
    outcome: Option<Outcome>,
}

impl Exchange {
    /// Start an exchange of C's `kind` tree against `agreed`, pinning
    /// `pinned`. `sends` is whether this side sends C to the peer, `receives`
    /// whether it receives C from it; the caller starts none when neither
    /// holds.
    pub(crate) fn start(
        collection: CollectionHandle,
        kind: WalkKind,
        pinned: Arc<CollectionSnapshot>,
        agreed: Option<Arc<Tree>>,
        sends: bool,
        receives: bool,
    ) -> Self {
        let mine = summary(kind, pinned.repair());
        let next = if sends {
            let pinned_tree = Tree::pinned(kind, pinned.repair());
            if let Some(agreed) = &agreed {
                // Within a connection the held trees grow. A published
                // observation may lag already-acknowledged landings, but
                // must never shrink our logically held agreed union.
                let mut next = agreed.as_ref().clone();
                next.union(pinned_tree);
                next
            } else {
                pinned_tree
            }
        } else {
            agreed
                .as_deref()
                .cloned()
                .unwrap_or_else(|| Tree::empty(kind, collection))
        };
        let mut queue = VecDeque::new();
        if sends
            && mine.root().is_some()
            && agreed.as_ref().map(|agreed| agreed.summary()) != Some(mine)
        {
            queue.push_back(Vec::new());
        }
        Self {
            collection,
            kind,
            pinned,
            sends,
            receives,
            agreed,
            next,
            snapshot: None,
            root_sent: false,
            queue,
            announced: PATCH::new(),
            done_sent: false,
            peer_root: None,
            owed: PATCH::new(),
            accounted: 0,
            wanted: VecDeque::new(),
            requests: PATCH::new(),
            fetching: 0,
            unlanded: 0,
            failed: 0,
            deferred: false,
            peer_done: false,
            landed_sent: false,
            landed_received: false,
            outcome: None,
        }
    }

    pub(crate) fn receives(&self) -> bool {
        self.receives
    }

    /// This side's advertised root: empty when it sends no tree.
    pub(crate) fn root(&self) -> PatchSummary {
        if self.sends {
            summary(self.kind, self.pinned.repair())
        } else {
            empty()
        }
    }

    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// The next frame of this side's delta, when the stream can take one:
    /// ROOT first, then each node or leaf, then DONE, then nothing.
    pub(crate) fn next_delta(&mut self) -> Option<Frame> {
        if self.outcome.is_some() {
            return None;
        }
        if !self.root_sent {
            self.root_sent = true;
            return Some(Frame::Root {
                summary: self.root(),
            });
        }
        if self.done_sent {
            return None;
        }
        let Some(locator) = self.queue.pop_front() else {
            self.done_sent = true;
            return Some(Frame::Done);
        };
        let visited = node(self.kind, self.pinned.repair(), &locator)
            .expect("a pinned tree holds the nodes its own branches name");
        let PatchNode::Branch { ref branch, .. } = visited else {
            let PatchNode::Leaf { leaf, .. } = visited else {
                unreachable!()
            };
            let key = leaf.key.try_into().expect("a walked key is 32 bytes");
            return Some(Frame::Leaf { key });
        };
        for child in &branch.children {
            let locator = child_locator(branch, child);
            let announced = locator_key(&locator);
            if self.announced.get(&announced).is_some() {
                self.announced.remove(&announced);
                continue;
            }
            let declared = declared(child).expect("a pinned branch's child is nonempty");
            if self.agreed.as_ref().and_then(|agreed| agreed.at(&locator)) == Some(declared) {
                continue;
            }
            self.queue.push_back(locator);
            if self.queue.len() > FLOOD_LOCATORS {
                self.fail(Failure::Protocol);
                return None;
            }
        }
        debug_assert!(self.queue.len() <= FLOOD_LOCATORS);
        Some(Frame::Node {
            prefix: locator,
            node: visited,
        })
    }

    /// Take one frame from the peer, seeing the live store as `snapshot`.
    pub(crate) fn on_frame(
        &mut self,
        frame: Frame,
        snapshot: Option<Arc<StoreSnapshot>>,
    ) -> Vec<Out> {
        let mut outs = Vec::new();
        if self.outcome.is_some() {
            return outs;
        }
        self.snapshot = snapshot;
        if let Err(failure) = self.frame(frame, &mut outs) {
            self.fail(failure);
        }
        self.settle(&mut outs);
        outs
    }

    /// The landing task acknowledged values.
    pub(crate) fn on_landed_ack(&mut self, landed: u64, failed: u64) -> Vec<Out> {
        let mut outs = Vec::new();
        self.unlanded = self
            .unlanded
            .saturating_sub(usize::try_from(landed + failed).unwrap_or(usize::MAX));
        self.failed += failed;
        self.settle(&mut outs);
        outs
    }

    /// A blob fetch ended.
    pub(crate) fn on_fetched(
        &mut self,
        handle: RawHash,
        proof: Option<CapabilityProof>,
        blob: Option<Blob<UnknownBlob>>,
    ) -> Vec<Out> {
        let mut outs = Vec::new();
        self.fetching = self.fetching.saturating_sub(1);
        let admit = admit_fetched(self.collection, handle, proof, blob);
        self.admit(admit, &mut outs);
        self.settle(&mut outs);
        outs
    }

    /// Whether the driver should read the next frame: not once the exchange
    /// ended, and not while [`MAX_WALK_UNLANDED`] values are with the
    /// landing task.
    pub(crate) fn want_read(&self) -> bool {
        self.outcome.is_none() && self.unlanded < MAX_WALK_UNLANDED
    }

    /// Whether the peer owes this side a frame, so the driver times its
    /// wait for one: before the peer's DONE, and after it the values asked
    /// for. The peer's LANDED takes what time its landings take.
    pub(crate) fn awaits(&self) -> bool {
        !self.peer_done || !self.requests.is_empty()
    }

    /// The exchange as it ended, however it ended.
    pub(crate) fn end(self) -> Ended {
        let confirmed = self.outcome == Some(Outcome::Confirmed);
        Ended {
            sends: self.sends,
            receives: self.receives,
            confirmed: self.landed_received,
            landed: self.landed_sent,
            root: summary(self.kind, self.pinned.repair()),
            peer_root: self.peer_root,
            agreed: confirmed.then(|| Arc::new(self.next)),
        }
    }

    fn frame(&mut self, frame: Frame, outs: &mut Vec<Out>) -> Result<(), Failure> {
        match frame {
            Frame::Open { .. } => Err(Failure::Protocol),
            Frame::Root { summary } => {
                if self.peer_root.is_some() {
                    return Err(Failure::Protocol);
                }
                self.peer_root = Some(summary);
                if summary == crate::walk::summary(self.kind, self.pinned.repair()) {
                    // The peer's tree is this side's: nothing below the
                    // root is owed either way.
                    self.queue.clear();
                    if !self.sends {
                        self.next
                            .union(Tree::pinned(self.kind, self.pinned.repair()));
                    }
                }
                if self.receives
                    && let Some(digest) = summary.root()
                {
                    self.owe([(Vec::new(), digest, summary.leaf_count())])?;
                }
                Ok(())
            }
            Frame::Node { prefix, node } => {
                let root = self.arriving()?;
                let declared = PatchSummary::new(Some(node.digest()), node.leaf_count())
                    .map_err(|_| Failure::BadNode)?;
                let base = crate::walk::base(self.kind, self.collection);
                let canonical =
                    PatchRepairRequest::new(root, KEY_BYTES, prefix.clone(), node.digest())
                        .map_err(|_| Failure::BadNode)?;
                // Even an already-held or send-only announcement must bind
                // its children/count to its digest before it can prune work.
                validate_patch_node(&canonical, base.len() + KEY_BYTES, &base, &node, |_, ()| {
                    Ok(())
                })
                .map_err(|_| Failure::BadNode)?;
                let mine = local_summary(self.kind, self.pinned.repair(), &prefix);
                // The children announce what the peer holds. They matter
                // only where this side's delta may still reach: under a node
                // this side holds, differently from the peer and from the
                // agreed tree.
                if self.sends
                    && mine.is_some()
                    && mine != Some(declared)
                    && mine != self.agreed.as_ref().and_then(|agreed| agreed.at(&prefix))
                    && let PatchNode::Branch { branch, .. } = &node
                {
                    self.announce(branch)?;
                }
                if !self.receives {
                    return Ok(());
                }
                if prefix.len() > KEY_BYTES {
                    return Err(Failure::BadNode);
                }
                let owed_key = locator_key(&prefix);
                let Some((digest, leaf_count)) = self.owed.get(&owed_key).copied() else {
                    // In flight before this side's announcement reached the
                    // peer: it is what this side holds, or a violation.
                    if !self.holds(&prefix, declared) {
                        return Err(Failure::Protocol);
                    }
                    if let PatchNode::Leaf { leaf, .. } = node
                        && let Ok(key) = <[u8; KEY_BYTES]>::try_from(leaf.key)
                    {
                        self.remember(key)?;
                    }
                    return Ok(());
                };
                self.owed.remove(&owed_key);
                if node.leaf_count() != leaf_count {
                    return Err(Failure::BadNode);
                }
                let base = crate::walk::base(self.kind, self.collection);
                let request = PatchRepairRequest::new(root, KEY_BYTES, prefix.clone(), digest)
                    .map_err(|_| Failure::BadNode)?;
                validate_patch_node(&request, base.len() + KEY_BYTES, &base, &node, |_, ()| {
                    Ok(())
                })
                .map_err(|_| Failure::BadNode)?;
                match node {
                    PatchNode::Leaf { leaf, .. } => {
                        let key =
                            <[u8; KEY_BYTES]>::try_from(leaf.key).map_err(|_| Failure::BadNode)?;
                        self.leaf(key)
                    }
                    PatchNode::Branch { branch, .. } => self.owe(
                        branch
                            .children
                            .iter()
                            .map(|child| {
                                (
                                    child_locator(&branch, child),
                                    child.digest,
                                    child.leaf_count,
                                )
                            })
                            .collect::<Vec<_>>(),
                    ),
                }
            }
            Frame::Leaf { key } => {
                self.arriving()?;
                if !self.receives {
                    return Ok(());
                }
                // The leaf owed at the longest locator on its key's path,
                // once, with the digest its key binds.
                let owed = (0..=KEY_BYTES)
                    .rev()
                    .find(|len| self.owed.get(&locator_key(&key[..*len])).is_some());
                let Some(len) = owed else {
                    // In flight before this side's announcement reached the
                    // peer: a leaf this side holds, or a violation.
                    let held = contains(self.kind, self.pinned.repair(), &key)
                        || self
                            .agreed
                            .as_ref()
                            .is_some_and(|agreed| agreed.at(&key).is_some());
                    if !held {
                        return Err(Failure::Protocol);
                    }
                    return self.remember(key).map(|_| ());
                };
                let owed_key = locator_key(&key[..len]);
                let (digest, leaf_count) = *self
                    .owed
                    .get(&owed_key)
                    .expect("the locator was just found");
                self.owed.remove(&owed_key);
                let base = crate::walk::base(self.kind, self.collection);
                let absolute = [&base[..], &key[..]].concat();
                if leaf_count != 1 || digest != <Blake3Merkle as PatchHash>::leaf(&absolute) {
                    return Err(Failure::BadNode);
                }
                self.leaf(key)
            }
            Frame::Value { key, bytes } => {
                if self.requests.get(&key).is_none() {
                    return Err(Failure::Protocol);
                }
                self.requests.remove(&key);
                let live = self.live()?;
                let evidence = live.repair().authorization_evidence();
                let (value, admit) = admit_value(self.kind, self.collection, key, &bytes, evidence)
                    .map_err(|_| Failure::BadValue)?;
                self.next.insert(key, value);
                self.admit(admit, outs);
                Ok(())
            }
            Frame::ValueRequest { key } => {
                if !self.sends {
                    return Err(Failure::Protocol);
                }
                let bytes = value(self.kind, self.pinned.repair(), key)
                    .and_then(|value| value.bytes(self.collection))
                    .ok_or(Failure::Protocol)?;
                outs.push(Out::Send(Frame::Value { key, bytes }));
                Ok(())
            }
            Frame::Done => {
                let root = self.arriving()?;
                self.peer_done = true;
                if self.receives && (!self.owed.is_empty() || self.accounted != root.leaf_count()) {
                    return Err(Failure::CountMismatch);
                }
                Ok(())
            }
            Frame::Landed => {
                if !self.done_sent || self.landed_received {
                    return Err(Failure::Protocol);
                }
                self.landed_received = true;
                Ok(())
            }
        }
    }

    /// The peer's root, while its delta arrives: after its ROOT and before
    /// its DONE.
    fn arriving(&self) -> Result<PatchSummary, Failure> {
        match self.peer_root {
            Some(root) if !self.peer_done => Ok(root),
            _ => Err(Failure::Protocol),
        }
    }

    /// The live snapshot of C.
    fn live(&self) -> Result<Arc<CollectionSnapshot>, Failure> {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(self.collection))
            .ok_or(Failure::Unavailable)
    }

    /// Whether this side holds the subtree `declared` at `locator`: in its
    /// pinned tree, or in the agreed tree, which it holds too.
    fn holds(&self, locator: &[u8], declared: PatchSummary) -> bool {
        local_summary(self.kind, self.pinned.repair(), locator) == Some(declared)
            || self.agreed.as_ref().and_then(|agreed| agreed.at(locator)) == Some(declared)
    }

    /// Take the children of a NODE the peer sent as announcements: each
    /// whose digest this side's tree has at its locator is held by the peer,
    /// so the locator and everything queued under it is dropped, and the
    /// locator is kept to skip when its parent is visited.
    fn announce(&mut self, branch: &PatchBranch) -> Result<(), Failure> {
        let end = usize::from(branch.end_depth);
        let base = &branch.representative[..end];
        let mut equal = [false; 256];
        let mut any = false;
        for child in &branch.children {
            let locator = child_locator(branch, child);
            let mine = local_summary(self.kind, self.pinned.repair(), &locator);
            if mine.is_some_and(|mine| mine.root() == Some(child.digest)) {
                equal[usize::from(child.edge)] = true;
                any = true;
                if self.announced.len() >= FLOOD_LOCATORS as u64 {
                    return Err(Failure::Protocol);
                }
                self.announced.insert(&Entry::new(&locator_key(&locator)));
            }
        }
        if any {
            let announced = &mut self.announced;
            self.queue.retain(|queued| {
                let under =
                    queued.len() > end && queued[..end] == *base && equal[usize::from(queued[end])];
                if under && queued.len() == end + 1 {
                    announced.remove(&locator_key(queued));
                }
                !under
            });
        }
        Ok(())
    }

    /// The peer declared the subtrees `children` at their locators: each
    /// this side holds is accounted, the rest are owed, unless that would
    /// exceed the explicit locator budget. An honest wider delta is refused
    /// too; the map stays as it was rather than changing FIFO scheduling.
    fn owe(
        &mut self,
        children: impl IntoIterator<Item = (Vec<u8>, [u8; 32], u64)>,
    ) -> Result<(), Failure> {
        let mut owed = Vec::new();
        for (locator, digest, leaf_count) in children {
            let declared =
                PatchSummary::new(Some(digest), leaf_count).map_err(|_| Failure::BadNode)?;
            if self.holds(&locator, declared) {
                if !self.sends
                    && local_summary(self.kind, self.pinned.repair(), &locator) == Some(declared)
                {
                    self.next
                        .include_at(&Tree::pinned(self.kind, self.pinned.repair()), &locator);
                }
                self.accounted = self
                    .accounted
                    .checked_add(leaf_count)
                    .ok_or(Failure::CountMismatch)?;
            } else {
                owed.push((locator, (digest, leaf_count)));
            }
        }
        if self.owed.len() as usize + owed.len() > FLOOD_LOCATORS {
            return Err(Failure::Protocol);
        }
        for (locator, declared) in owed {
            let key = locator_key(&locator);
            if self.owed.get(&key).is_some() {
                return Err(Failure::BadNode);
            }
            self.owed.insert(&Entry::with_value(&key, declared));
        }
        Ok(())
    }

    /// Count one pushed leaf; one the live store lacks is wanted, and one it
    /// holds joins the next agreed tree at once. More waiting leaves than
    /// the explicit withheld-value budget permits fails the exchange.
    fn leaf(&mut self, key: [u8; KEY_BYTES]) -> Result<(), Failure> {
        self.accounted = self
            .accounted
            .checked_add(1)
            .ok_or(Failure::CountMismatch)?;
        if self.remember(key)? {
            return Ok(());
        }
        if self.wanted.len() >= FLOOD_WANTED {
            return Err(Failure::Protocol);
        }
        self.wanted.push_back(key);
        Ok(())
    }

    /// A leaf the peer streamed joins the next agreed tree with the value
    /// the live store holds for it, if any: whether it holds one.
    fn remember(&mut self, key: [u8; KEY_BYTES]) -> Result<bool, Failure> {
        let live = self.live()?;
        let Some(value) = value(self.kind, live.repair(), key) else {
            return Ok(false);
        };
        self.next.insert(key, value);
        Ok(true)
    }

    fn admit(&mut self, admit: Admit, outs: &mut Vec<Out>) {
        match admit {
            Admit::Land(events) => {
                self.unlanded += events.len();
                outs.push(Out::Land(events));
            }
            Admit::Fetch { handle, proof } => {
                self.fetching += 1;
                outs.push(Out::Fetch { handle, proof });
            }
            Admit::Defer => self.deferred = true,
            Admit::Fail => self.failed += 1,
        }
    }

    fn fail(&mut self, failure: Failure) {
        self.outcome = Some(Outcome::Failed(failure));
    }

    /// Ask for wanted leaves while the window has room, send LANDED once the
    /// peer's delta is in and landed, and end once both LANDEDs crossed.
    fn settle(&mut self, outs: &mut Vec<Out>) {
        if self.outcome.is_some() {
            return;
        }
        while self.requests.len() as usize + self.fetching < MAX_WALK_REQUESTS
            && let Some(key) = self.wanted.pop_front()
        {
            match admit_missing(self.kind, self.collection, key, self.snapshot.as_deref()) {
                Some(admit) => {
                    self.next.insert(key, Value::Handle);
                    self.admit(admit, outs);
                }
                None => {
                    self.requests.insert(&Entry::new(&key));
                    outs.push(Out::Send(Frame::ValueRequest { key }));
                }
            }
        }
        if !self.landed_sent
            && self.peer_done
            && self.wanted.is_empty()
            && self.requests.is_empty()
            && self.fetching == 0
            && self.unlanded == 0
        {
            if self.failed > 0 {
                return self.fail(Failure::InsertFailed);
            }
            if self.deferred {
                return self.fail(Failure::DeferredProof);
            }
            self.landed_sent = true;
            outs.push(Out::Send(Frame::Landed));
        }
        if self.landed_sent && self.landed_received {
            self.outcome = Some(Outcome::Confirmed);
        }
    }
}

/// The locator of `child` under `branch`: the representative up to the end
/// depth, then the child's edge.
fn child_locator(branch: &PatchBranch, child: &PatchChild) -> Vec<u8> {
    let mut locator = branch.representative[..usize::from(branch.end_depth)].to_vec();
    locator.push(child.edge);
    locator
}

fn declared(child: &PatchChild) -> Option<PatchSummary> {
    PatchSummary::new(Some(child.digest), child.leaf_count).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use triblespace_core::capability::CapabilityProofId;
    use triblespace_core::collection::{
        CollectionData, CollectionMerge, CollectionRecord, CollectionRecordFingerprint,
        CollectionStore,
    };

    use crate::collection_delta::{decode_record, encode_record};
    use crate::walk::tests::walking::{Node, open};
    use crate::walk::tests::{branches, paths};

    fn roundtrip(frame: Frame) -> Frame {
        let (kind, payload) = frame.encode();
        Frame::decode(kind, &payload).unwrap().unwrap()
    }

    /// One node and its exchange, driven by hand: every frame crosses the
    /// codec, landings run as the landing task does unless held back, and
    /// fetches are noted for the test to answer.
    pub(crate) struct Side {
        pub(crate) node: Node,
        pub(crate) exchange: Exchange,
        /// Every frame this side sent, in order.
        pub(crate) sent: Vec<Frame>,
        /// Every frame this side heard, in order.
        pub(crate) heard: Vec<Frame>,
        outbox: VecDeque<Frame>,
        pub(crate) hold: bool,
        /// Whether this harness publishes a new serving observation for each
        /// individual landing. Physical insertion/ack is still immediate.
        observe_landings: bool,
        pub(crate) held: Vec<Vec<NetEvent>>,
        pub(crate) fetches: Vec<(RawHash, Option<CapabilityProof>)>,
    }

    impl Side {
        /// `node`'s side of an exchange of C's `kind` tree against `agreed`.
        pub(crate) fn new(
            node: Node,
            collection: CollectionHandle,
            kind: WalkKind,
            agreed: Option<Arc<Tree>>,
            sends: bool,
            receives: bool,
        ) -> Self {
            let pinned = node.pinned(collection);
            Self {
                exchange: Exchange::start(collection, kind, pinned, agreed, sends, receives),
                node,
                sent: Vec::new(),
                heard: Vec::new(),
                outbox: VecDeque::new(),
                hold: false,
                observe_landings: true,
                held: Vec::new(),
                fetches: Vec::new(),
            }
        }

        /// Both ways, against nothing.
        pub(crate) fn both(node: Node, collection: CollectionHandle, kind: WalkKind) -> Self {
            Self::new(node, collection, kind, None, true, true)
        }

        /// Hear one frame, keeping the answers for [`Self::next`].
        pub(crate) fn hear(&mut self, frame: Frame) {
            let frame = roundtrip(frame);
            self.heard.push(frame.clone());
            let outs = self.exchange.on_frame(frame, Some(self.node.snapshot()));
            self.outputs(outs);
        }

        /// Hear one frame; the frames sent back.
        pub(crate) fn feed(&mut self, frame: Frame) -> Vec<Frame> {
            self.hear(frame);
            self.replies()
        }

        /// Take every frame waiting to be sent.
        pub(crate) fn replies(&mut self) -> Vec<Frame> {
            let replies = std::mem::take(&mut self.outbox);
            self.sent.extend(replies.iter().cloned());
            replies.into()
        }

        /// The next frame to send: an answer, or the next of the delta.
        pub(crate) fn next(&mut self) -> Option<Frame> {
            let frame = self
                .outbox
                .pop_front()
                .or_else(|| self.exchange.next_delta())?;
            self.sent.push(frame.clone());
            Some(frame)
        }

        pub(crate) fn outputs(&mut self, outs: Vec<Out>) {
            for out in outs {
                match out {
                    Out::Send(frame) => self.outbox.push_back(frame),
                    Out::Land(events) if self.hold => self.held.push(events),
                    Out::Land(events) => self.land(events),
                    Out::Fetch { handle, proof } => self.fetches.push((handle, proof)),
                }
            }
        }

        /// Insert, publish and acknowledge, as the landing task does.
        pub(crate) fn land(&mut self, events: Vec<NetEvent>) {
            let (landed, failed) = self.node.insert(events);
            if self.observe_landings {
                self.node.observe();
            }
            let outs = self.exchange.on_landed_ack(landed, failed);
            self.outputs(outs);
        }

        pub(crate) fn release(&mut self) {
            self.hold = false;
            for events in std::mem::take(&mut self.held) {
                self.land(events);
            }
        }

        pub(crate) fn requested(&self) -> BTreeSet<[u8; 32]> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::ValueRequest { key } => Some(*key),
                    _ => None,
                })
                .collect()
        }

        /// The prefixes of the NODEs sent, in order.
        pub(crate) fn nodes(&self) -> Vec<Vec<u8>> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Node { prefix, .. } => Some(prefix.clone()),
                    _ => None,
                })
                .collect()
        }

        /// The keys of the LEAFs sent, in order.
        pub(crate) fn leaves(&self) -> Vec<[u8; 32]> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Leaf { key } => Some(*key),
                    _ => None,
                })
                .collect()
        }

        pub(crate) fn count(&self, same: impl Fn(&Frame) -> bool) -> usize {
            self.sent.iter().filter(|frame| same(frame)).count()
        }

        pub(crate) fn outcome(&self) -> Option<Outcome> {
            self.exchange.outcome()
        }

        /// The agreed root the exchange ended with, if it confirmed.
        pub(crate) fn agreed(&self) -> Option<PatchSummary> {
            (self.outcome() == Some(Outcome::Confirmed)).then(|| self.exchange.next.summary())
        }
    }

    /// Carry frames both ways, one each way in turn, until neither side has
    /// anything to send: an exchange whose every announcement arrives as
    /// early as the other side's delta allows.
    pub(crate) fn carry(a: &mut Side, b: &mut Side) {
        loop {
            let mut moved = false;
            if let Some(frame) = a.next() {
                b.hear(frame);
                moved = true;
            }
            if let Some(frame) = b.next() {
                a.hear(frame);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    /// Carry everything one side has to send before the other sends a
    /// frame: a delta that goes out in one burst, as over a stream whose
    /// round trip is longer than the burst.
    pub(crate) fn burst(a: &mut Side, b: &mut Side) {
        loop {
            let mut moved = false;
            while let Some(frame) = a.next() {
                b.hear(frame);
                moved = true;
            }
            while let Some(frame) = b.next() {
                a.hear(frame);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    fn fingerprints(records: impl IntoIterator<Item = CollectionRecord>) -> BTreeSet<[u8; 32]> {
        records
            .into_iter()
            .map(|record| record.fingerprint().raw())
            .collect()
    }

    /// The value under `key` at `node`, as its exchange serves it.
    fn value_of(
        node: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        key: [u8; 32],
    ) -> Vec<u8> {
        let overlay = node.pinned(collection);
        match kind {
            WalkKind::Records => overlay
                .repair()
                .records()
                .get(CollectionRecordFingerprint::from_raw(key))
                .map(|record| encode_record(collection, record).unwrap())
                .unwrap(),
            WalkKind::Authorization => overlay
                .repair()
                .authorization_evidence()
                .get(CapabilityProofId::new(key))
                .map(|proof| proof.as_bytes().to_vec())
                .unwrap(),
            WalkKind::References => panic!("held references carry no values"),
        }
    }

    /// `sender`'s `kind` tree of C as a scripted peer streams it, breadth
    /// first and heeding no announcement: ROOT, every node and leaf, and
    /// DONE, leaving out the leaves in `omit`.
    fn tree(
        sender: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        omit: &BTreeSet<[u8; 32]>,
    ) -> Vec<Frame> {
        let overlay = sender.pinned(collection);
        let overlay = overlay.repair();
        let mut frames = vec![Frame::Root {
            summary: summary(kind, overlay),
        }];
        let mut queue = VecDeque::new();
        if summary(kind, overlay).root().is_some() {
            queue.push_back(Vec::new());
        }
        while let Some(prefix) = queue.pop_front() {
            match node(kind, overlay, &prefix).unwrap() {
                PatchNode::Leaf { leaf, .. } => {
                    let key = leaf.key.try_into().unwrap();
                    if !omit.contains(&key) {
                        frames.push(Frame::Leaf { key });
                    }
                }
                node @ PatchNode::Branch { .. } => {
                    let PatchNode::Branch { branch, .. } = &node else {
                        unreachable!()
                    };
                    for child in &branch.children {
                        queue.push_back(child_locator(branch, child));
                    }
                    frames.push(Frame::Node { prefix, node });
                }
            }
        }
        frames.push(Frame::Done);
        frames
    }

    /// Stream `sender`'s `kind` tree of C into `side` as a scripted peer,
    /// answering every value request at once and the side's DONE with
    /// LANDED, and leaving out the leaves in `omit`. Returns the frames
    /// streamed, values included.
    fn stream(
        side: &mut Side,
        sender: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        omit: &BTreeSet<[u8; 32]>,
    ) -> Vec<Frame> {
        let mut streamed = Vec::new();
        let mut landed = false;
        let mut send = |side: &mut Side, frame: Frame| {
            streamed.push(frame.clone());
            let mut replies = side.feed(frame);
            while let Some(reply) = replies.pop() {
                match reply {
                    Frame::ValueRequest { key } => {
                        let value = Frame::Value {
                            key,
                            bytes: value_of(sender, collection, kind, key),
                        };
                        streamed.push(value.clone());
                        replies.extend(side.feed(value));
                    }
                    Frame::Done if !landed => {
                        landed = true;
                        streamed.push(Frame::Landed);
                        replies.extend(side.feed(Frame::Landed));
                    }
                    _ => {}
                }
            }
        };
        for frame in tree(sender, collection, kind, omit) {
            send(side, frame);
        }
        // The side's own delta, which the scripted peer ignores.
        while let Some(frame) = side.next() {
            if frame == Frame::Done && !landed {
                landed = true;
                streamed.push(Frame::Landed);
                for reply in side.feed(Frame::Landed) {
                    if let Frame::ValueRequest { key } = reply {
                        let value = Frame::Value {
                            key,
                            bytes: value_of(sender, collection, kind, key),
                        };
                        streamed.push(value.clone());
                        side.feed(value);
                    }
                }
            }
        }
        streamed
    }

    /// A tree the receiving side takes as the peer's, fabricated without a
    /// PATCH: `wide` branches under the root, each of `deep` leaves, every
    /// digest as the PATCH hashes it. The root and its NODE, then each
    /// branch's NODE with its LEAFs.
    fn fabricated(wide: usize, deep: usize) -> (PatchSummary, Frame, Vec<(Frame, Vec<Frame>)>) {
        let tree_to_key = (0..KEY_BYTES).collect::<Vec<_>>();
        let branch = |representative: Vec<u8>, end_depth: usize, children: Vec<PatchChild>| {
            let leaf_count = children.iter().map(|child| child.leaf_count).sum();
            let mut state = <Blake3Merkle as PatchHash>::begin_branch(
                &representative,
                &tree_to_key,
                end_depth,
                children.len(),
                leaf_count,
            );
            for child in &children {
                <Blake3Merkle as PatchHash>::push_child(
                    &mut state,
                    child.edge,
                    child.leaf_count,
                    child.digest,
                );
            }
            PatchNode::Branch {
                digest: <Blake3Merkle as PatchHash>::finish_branch(state),
                leaf_count,
                branch: PatchBranch {
                    representative,
                    end_depth: end_depth as u8,
                    children,
                },
            }
        };
        let mut branches = Vec::new();
        let mut children = Vec::new();
        for edge in 0..wide {
            let edge = u8::try_from(edge).unwrap();
            let (mut leaves, mut under) = (Vec::new(), Vec::new());
            for leaf in 0..deep {
                let mut key = [0; KEY_BYTES];
                key[0] = edge;
                key[1] = u8::try_from(leaf).unwrap();
                under.push(PatchChild {
                    edge: key[1],
                    digest: <Blake3Merkle as PatchHash>::leaf(&key),
                    leaf_count: 1,
                });
                leaves.push(Frame::Leaf { key });
            }
            let mut representative = vec![0; KEY_BYTES];
            representative[0] = edge;
            let node = branch(representative, 1, under);
            children.push(PatchChild {
                edge,
                digest: node.digest(),
                leaf_count: node.leaf_count(),
            });
            branches.push((
                Frame::Node {
                    prefix: vec![edge],
                    node,
                },
                leaves,
            ));
        }
        let node = branch(vec![0; KEY_BYTES], 0, children);
        let root = PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap();
        (
            root,
            Frame::Node {
                prefix: Vec::new(),
                node,
            },
            branches,
        )
    }

    /// A node holding `count` records of a fresh collection, observed.
    fn holding(
        byte: u8,
        name: &str,
        count: u64,
    ) -> (Node, CollectionHandle, Vec<CollectionRecord>) {
        let mut node = Node::new(byte);
        let collection = node.hold(name, open());
        let records = (0..count)
            .map(|data| node.commit(collection, data))
            .collect::<Vec<_>>();
        node.observe();
        (node, collection, records)
    }

    /// A node holding `records` of the collection `name`, observed.
    fn sharing(byte: u8, name: &str, records: &[CollectionRecord]) -> (Node, CollectionHandle) {
        let mut node = Node::new(byte);
        let collection = node.hold(name, open());
        for record in records {
            node.store.insert(*record).unwrap();
        }
        node.observe();
        (node, collection)
    }

    /// A first exchange with an empty peer streams the whole tree: ROOT,
    /// every branch as a NODE and every leaf as a LEAF, then DONE, without
    /// a frame from the peer in between; the peer sends only its ROOT and
    /// DONE, a request per value and LANDED. Both confirm, and both agree
    /// on the full side's tree.
    #[test]
    fn a_first_exchange_streams_the_whole_tree_to_an_empty_peer() {
        let (full, collection, records) = holding(30, "whole", 300);
        let (empty, _) = sharing(31, "whole", &[]);
        let root = summary(WalkKind::Records, full.pinned(collection).repair());
        let mut full = Side::both(full, collection, WalkKind::Records);
        let mut empty = Side::both(empty, collection, WalkKind::Records);
        burst(&mut full, &mut empty);

        assert_eq!(full.outcome(), Some(Outcome::Confirmed));
        assert_eq!(empty.outcome(), Some(Outcome::Confirmed));
        assert_eq!(full.sent[0], Frame::Root { summary: root });
        let mut expected = Vec::new();
        branches(
            full.node.pinned(collection).repair().records().patch(),
            Vec::new(),
            &mut expected,
        );
        let nodes = full.nodes();
        assert!(expected.len() > 1);
        assert_eq!(nodes.len(), expected.len());
        assert_eq!(
            nodes.iter().collect::<BTreeSet<_>>(),
            expected.iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(full.leaves().len(), records.len());
        assert_eq!(
            full.leaves().into_iter().collect::<BTreeSet<_>>(),
            fingerprints(records.iter().copied())
        );
        // The delta came before anything the peer sent after its ROOT.
        let last_node = full
            .sent
            .iter()
            .rposition(|frame| matches!(frame, Frame::Node { .. }))
            .unwrap();
        assert!(
            full.sent[..last_node]
                .iter()
                .all(|frame| !matches!(frame, Frame::Value { .. }))
        );
        assert_eq!(
            empty
                .sent
                .iter()
                .filter(|frame| matches!(frame, Frame::Node { .. } | Frame::Leaf { .. }))
                .count(),
            0
        );
        assert_eq!(empty.requested(), fingerprints(records.iter().copied()));
        assert_eq!(empty.count(|frame| *frame == Frame::Done), 1);
        assert_eq!(empty.count(|frame| *frame == Frame::Landed), 1);
        assert_eq!(empty.count(|frame| matches!(frame, Frame::Root { .. })), 1);
        assert_eq!(empty.sent.len(), 303);
        for frame in &full.sent {
            if let Frame::Value { key, bytes } = frame {
                let record = decode_record(collection, bytes).unwrap();
                assert_eq!(record.fingerprint().raw(), *key);
            }
        }
        assert_eq!(
            empty.node.records(collection),
            records.iter().copied().collect()
        );
        assert_eq!(full.agreed(), Some(root));
        assert_eq!(empty.agreed(), Some(root));
    }

    /// Against the agreed tree, an unchanged tree is ROOT then DONE, and
    /// LANDED answers it; an empty tree is the same against nothing.
    #[test]
    fn an_unchanged_tree_against_the_agreed_tree_is_root_then_done() {
        let (a, collection, records) = holding(32, "same", 50);
        let (b, _) = sharing(33, "same", &records);
        let kind = WalkKind::Records;
        let mut a = Side::both(a, collection, kind);
        let mut b = Side::both(b, collection, kind);
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        let agreed = Arc::new(Tree::pinned(kind, a.node.pinned(collection).repair()));
        assert_eq!(a.agreed(), Some(agreed.summary()));

        let mut a = Side::new(a.node, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b.node, collection, kind, Some(agreed), true, true);
        carry(&mut a, &mut b);
        for side in [&a, &b] {
            assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            // ROOT, then DONE and LANDED, the answer to the peer's DONE
            // going first.
            assert_eq!(
                side.sent[0],
                Frame::Root {
                    summary: summary(kind, side.node.pinned(collection).repair())
                }
            );
            assert!(
                side.sent[1..] == [Frame::Done, Frame::Landed]
                    || side.sent[1..] == [Frame::Landed, Frame::Done],
                "{:?}",
                side.sent
            );
        }

        let (blank, collection) = sharing(34, "empty", &[]);
        let mut blank = Side::both(blank, collection, WalkKind::Authorization);
        assert_eq!(blank.next(), Some(Frame::Root { summary: empty() }));
        assert_eq!(blank.next(), Some(Frame::Done));
        assert_eq!(blank.next(), None);
    }

    /// A tree the peer announces at a locator this side had already
    /// descended below is not sent on: the announcement drops what was
    /// queued under it, so nothing under that locator follows.
    #[test]
    fn a_match_that_arrives_mid_level_drops_the_work_queued_under_it() {
        let (a, collection, _) = holding(35, "mid", 300);
        let kind = WalkKind::Records;
        let mut a = Side::new(a, collection, kind, None, true, false);
        assert!(matches!(a.next(), Some(Frame::Root { .. })));
        let Some(Frame::Node { prefix, node: root }) = a.next() else {
            panic!("the root node");
        };
        assert!(prefix.is_empty());
        let PatchNode::Branch { branch, .. } = &root else {
            panic!("300 records branch at the root");
        };
        // Level 1 is queued. Visit its first branch, which queues level 2
        // under it.
        let first = loop {
            match a.next() {
                Some(Frame::Node { prefix, .. }) => break prefix,
                Some(Frame::Leaf { .. }) => continue,
                other => panic!("some first byte branches: {other:?}"),
            }
        };
        assert_eq!(first.len(), 1);
        assert!(
            a.exchange
                .queue
                .iter()
                .any(|queued| queued.starts_with(&first))
        );

        // The peer's root NODE, with the same digest at `first` and a
        // digest of its own everywhere else.
        let mut announced = branch.clone();
        for child in &mut announced.children {
            if child.edge != first[0] {
                child.digest = [0xAA; 32];
            }
        }
        let mut state = <Blake3Merkle as PatchHash>::begin_branch(
            &announced.representative,
            &(0..KEY_BYTES).collect::<Vec<_>>(),
            usize::from(announced.end_depth),
            announced.children.len(),
            root.leaf_count(),
        );
        for child in &announced.children {
            <Blake3Merkle as PatchHash>::push_child(
                &mut state,
                child.edge,
                child.leaf_count,
                child.digest,
            );
        }
        let digest = <Blake3Merkle as PatchHash>::finish_branch(state);
        a.hear(Frame::Root {
            summary: PatchSummary::new(Some(digest), root.leaf_count()).unwrap(),
        });
        a.hear(Frame::Node {
            prefix: Vec::new(),
            node: PatchNode::Branch {
                digest,
                leaf_count: root.leaf_count(),
                branch: announced,
            },
        });
        assert!(
            a.exchange
                .queue
                .iter()
                .all(|queued| !queued.starts_with(&first))
        );
        let mut rest = Vec::new();
        while let Some(frame) = a.next() {
            rest.push(frame);
        }
        assert_eq!(rest.last(), Some(&Frame::Done));
        for frame in &rest {
            match frame {
                Frame::Node { prefix, .. } => assert!(!prefix.starts_with(&first), "{prefix:?}"),
                Frame::Leaf { key } => assert!(!key.starts_with(&first), "{key:?}"),
                _ => {}
            }
        }
        // Every other level-1 child went on.
        let below = rest
            .iter()
            .filter_map(|frame| match frame {
                Frame::Node { prefix, .. } => Some(prefix[0]),
                Frame::Leaf { key } => Some(key[0]),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(below.len(), branch.children.len() - 1);
    }

    /// An announcement of the whole tree, the peer's ROOT with this side's
    /// root, ends the delta at once.
    #[test]
    fn an_equal_root_announcement_ends_the_delta() {
        let (a, collection, _) = holding(36, "equal", 300);
        let kind = WalkKind::Records;
        let root = summary(kind, a.pinned(collection).repair());
        let mut a = Side::new(a, collection, kind, None, true, true);
        assert_eq!(a.next(), Some(Frame::Root { summary: root }));
        assert_eq!(a.feed(Frame::Root { summary: root }), []);
        assert_eq!(a.next(), Some(Frame::Done));
        assert_eq!(a.feed(Frame::Done), [Frame::Landed]);
        assert_eq!(a.feed(Frame::Landed), []);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.agreed(), Some(root));
    }

    /// Two sides holding overlapping records end with the same agreed tree:
    /// the union, which both now hold.
    #[test]
    fn both_sides_compute_the_same_agreed_tree() {
        let (a, collection, records) = holding(37, "union", 200);
        let (mut b, _) = sharing(38, "union", &records[100..]);
        let own = (0..100)
            .map(|data| b.commit(collection, 1_000 + data))
            .collect::<Vec<_>>();
        b.observe();
        let kind = WalkKind::Records;
        let mut a = Side::both(a, collection, kind);
        let mut b = Side::both(b, collection, kind);
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.requested().len(), 100);
        assert_eq!(b.requested().len(), 100);
        let union = records.iter().chain(&own).copied().collect::<BTreeSet<_>>();
        assert_eq!(a.node.records(collection), union);
        assert_eq!(b.node.records(collection), union);
        let expected = summary(kind, a.node.pinned(collection).repair());
        assert_eq!(a.agreed(), Some(expected));
        assert_eq!(b.agreed(), Some(expected));
        for locator in [
            &[][..],
            &[own[0].fingerprint().raw()[0]],
            &records[0].fingerprint().raw()[..2],
        ] {
            assert_eq!(a.exchange.next.at(locator), b.exchange.next.at(locator));
        }
    }

    /// A side that sends nothing agrees on the peer's tree: against it the
    /// peer's unchanged tree is ROOT then DONE, however much more this side
    /// holds.
    #[test]
    fn a_side_that_sends_nothing_agrees_on_the_peer_s_tree() {
        let (writer, collection, records) = holding(39, "one way", 20);
        let (mut owner, _) = sharing(40, "one way", &records[..10]);
        owner.commit(collection, 1_000);
        owner.observe();
        let kind = WalkKind::Records;
        let mut writer = Side::new(writer, collection, kind, None, true, false);
        let mut owner = Side::new(owner, collection, kind, None, false, true);
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.requested().len(), 10);
        assert_eq!(owner.node.records(collection).len(), 21);
        assert_eq!(owner.sent.first(), Some(&Frame::Root { summary: empty() }));
        assert!(
            owner.sent.iter().all(|frame| !matches!(
                frame,
                Frame::Node { .. } | Frame::Leaf { .. } | Frame::Value { .. }
            )),
            "a non-sending peer discloses no private tree or values"
        );
        assert_eq!(writer.node.records(collection).len(), 20);
        let agreed = summary(kind, writer.node.pinned(collection).repair());
        assert_eq!(writer.agreed(), Some(agreed));
        assert_eq!(owner.agreed(), Some(agreed));
        let tree = Arc::new(Tree::pinned(kind, writer.node.pinned(collection).repair()));

        let mut writer = Side::new(
            writer.node,
            collection,
            kind,
            Some(tree.clone()),
            true,
            false,
        );
        let mut owner = Side::new(owner.node, collection, kind, Some(tree), false, true);
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(
            writer.sent,
            [Frame::Root { summary: agreed }, Frame::Done, Frame::Landed]
        );
        assert_eq!(owner.sent.len(), 3);
        assert_eq!(owner.sent.first(), Some(&Frame::Root { summary: empty() }));
        assert_eq!(owner.agreed(), Some(agreed));
    }

    /// Leaves a side lacks are asked for and land; it ends with the union
    /// and says so, and so does the other side with the one record only
    /// the first held.
    #[test]
    fn missing_leaves_are_requested_and_land() {
        let (sender, collection, records) = holding(41, "missing", 300);
        let (mut receiver, _) = sharing(42, "missing", &records[..100]);
        let foreign = receiver.commit(collection, 1_000);
        receiver.observe();
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.sent.last(), Some(&Frame::Landed));
        let requested = receiver.requested();
        assert_eq!(requested.len(), 200);
        assert!(
            records
                .iter()
                .skip(100)
                .all(|record| requested.contains(&record.fingerprint().raw()))
        );
        assert_eq!(
            sender.requested(),
            BTreeSet::from([foreign.fingerprint().raw()])
        );
        let mut union = records.iter().copied().collect::<BTreeSet<_>>();
        union.insert(foreign);
        assert_eq!(receiver.node.records(collection), union);
        assert_eq!(sender.node.records(collection), union);
    }

    /// A subtree the peer announces is neither streamed below its node nor
    /// asked for: the sender's leaves under it never go out, and the peer
    /// never asks for them.
    #[test]
    fn a_subtree_the_peer_announces_is_neither_streamed_nor_asked_for() {
        let (sender, collection, records) = holding(43, "pruned", 400);
        let Some(PatchNode::Branch { branch, .. }) =
            node(WalkKind::Records, sender.pinned(collection).repair(), &[])
        else {
            panic!("400 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        let edge = branch.children[0].edge;
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw()[0] == edge)
            .copied()
            .collect::<Vec<_>>();
        assert!(!shared.is_empty() && shared.len() < records.len());
        let (receiver, _) = sharing(44, "pruned", &shared);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        let streamed = sender.leaves().into_iter().collect::<BTreeSet<_>>();
        let requested = receiver.requested();
        for record in &shared {
            assert!(!streamed.contains(&record.fingerprint().raw()));
            assert!(!requested.contains(&record.fingerprint().raw()));
        }
        assert_eq!(streamed.len(), records.len() - shared.len());
        assert_eq!(requested, streamed);
        assert!(
            sender
                .nodes()
                .iter()
                .all(|prefix| prefix.len() < 2 || prefix[0] != edge)
        );
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
    }

    /// The peer's root NODE announces exactly the children it holds, and
    /// the delta goes on below every other one.
    #[test]
    fn the_root_node_s_announcements_prune_exactly_the_children_the_peer_holds() {
        let (sender, collection, records) = holding(45, "bitmap", 3000);
        let Some(PatchNode::Branch { branch, .. }) =
            node(WalkKind::Records, sender.pinned(collection).repair(), &[])
        else {
            panic!("3000 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        assert_eq!(
            branch.children.len(),
            256,
            "3000 keys fill every branch byte"
        );
        let edges = [0, 7, 8, 255];
        let held = records
            .iter()
            .filter(|record| edges.contains(&record.fingerprint().raw()[0]))
            .copied()
            .collect::<Vec<_>>();
        let (receiver, _) = sharing(46, "bitmap", &held);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        carry(&mut sender, &mut receiver);
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        let below = sender
            .sent
            .iter()
            .filter_map(|frame| match frame {
                Frame::Node { prefix, .. } if !prefix.is_empty() => Some(prefix[0]),
                Frame::Leaf { key } => Some(key[0]),
                _ => None,
            })
            .collect::<BTreeSet<u8>>();
        assert_eq!(below.len(), 256 - edges.len());
        for edge in edges {
            assert!(!below.contains(&edge), "child {edge} was pruned");
        }
        assert_eq!(receiver.requested().len(), records.len() - held.len());
        // The receiver's delta is its root NODE, which the sender's root
        // children announce whole, and nothing below it.
        assert_eq!(receiver.nodes(), [Vec::<u8>::new()]);
        assert!(receiver.leaves().is_empty());
    }

    /// The delta goes breadth first: no NODE's prefix is shorter than the
    /// one before it, so each level's announcements go out before the next
    /// level does.
    #[test]
    fn the_delta_goes_breadth_first() {
        let (sender, collection, _) = holding(47, "breadth", 3000);
        let mut sender = Side::new(sender, collection, WalkKind::Records, None, true, false);
        let mut depths = Vec::new();
        while let Some(frame) = sender.next() {
            if let Frame::Node { prefix, .. } = frame {
                depths.push(prefix.len());
            }
        }
        assert!(depths.len() > 256, "{}", depths.len());
        assert!(depths.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(sender.exchange.queue.is_empty());
    }

    /// A delta that leaves out a leaf does not add up to its root's count,
    /// and fails at the end; what landed stays.
    #[test]
    fn the_count_proof_fails_on_a_delta_that_omits_a_leaf() {
        let (sender, collection, records) = holding(48, "omitted", 60);
        let (receiver, _) = sharing(49, "omitted", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        let omit = BTreeSet::from([records[7].fingerprint().raw()]);
        stream(&mut receiver, &sender, collection, kind, &omit);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
        assert_eq!(receiver.node.records(collection).len(), 59);
    }

    /// A value that fails to land, or does not decode, fails the exchange
    /// without a LANDED; what landed stays.
    #[test]
    fn a_failed_insert_yields_no_landed() {
        let (sender, collection, _) = holding(50, "failed", 20);
        let (receiver, _) = sharing(51, "failed", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.hold = true;
        stream(&mut receiver, &sender, collection, kind, &BTreeSet::new());
        assert_eq!(receiver.outcome(), None);
        assert_eq!(receiver.held.len(), 20);
        // One landing comes back failed.
        let failed = receiver.held.pop().unwrap();
        receiver.release();
        assert_eq!(receiver.outcome(), None, "a landing is still owed");
        let outs = receiver.exchange.on_landed_ack(0, failed.len() as u64);
        receiver.outputs(outs);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::InsertFailed))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
        assert_eq!(receiver.node.records(collection).len(), 19);

        // A value that is not a foundation record fails the exchange at
        // once.
        let (receiver, _) = sharing(52, "failed", &[]);
        let mut receiver = Side::both(receiver, collection, kind);
        let Some(Frame::ValueRequest { key }) = tree(&sender, collection, kind, &BTreeSet::new())
            .into_iter()
            .find_map(|frame| {
                receiver
                    .feed(frame)
                    .into_iter()
                    .find(|reply| matches!(reply, Frame::ValueRequest { .. }))
            })
        else {
            panic!("a value was requested");
        };
        let merge = CollectionRecord::Merge(
            CollectionMerge::sign(
                &sender.key,
                collection,
                [CollectionData::new([2; 32]), CollectionData::new([3; 32])],
                CollectionData::new([4; 32]),
            )
            .unwrap(),
        );
        receiver.feed(Frame::Value {
            key,
            bytes: merge.to_bytes(),
        });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadValue)));
        assert!(receiver.node.records(collection).is_empty());
    }

    /// Values are asked for [`MAX_WALK_REQUESTS`] at a time, the leaves
    /// beyond that waiting until a value arrives, while the stream is read
    /// on; reading stops at [`MAX_WALK_UNLANDED`] values with the landing
    /// task, and resumes as they land.
    #[test]
    fn requests_are_windowed_and_reading_stops_at_unlanded_values() {
        let (sender, collection, records) = holding(53, "window", MAX_WALK_UNLANDED as u64 + 100);
        let (receiver, _) = sharing(54, "window", &[]);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.hold = true;
        let mut requests = Vec::new();
        for frame in tree(&sender, collection, kind, &BTreeSet::new()) {
            assert!(receiver.exchange.want_read(), "a value is owed");
            requests.extend(
                receiver
                    .feed(frame)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
        }
        assert_eq!(requests.len(), MAX_WALK_REQUESTS);
        assert_eq!(
            receiver.exchange.wanted.len(),
            records.len() - MAX_WALK_REQUESTS
        );
        // Each value answered lets the next leaf be asked for, until the
        // landing task holds the most it may.
        let mut answered = 0;
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value_of(&sender, collection, kind, key),
            };
            requests.extend(
                receiver
                    .feed(value)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
            answered += 1;
            if !receiver.exchange.want_read() {
                break;
            }
        }
        assert_eq!(answered, MAX_WALK_UNLANDED);
        assert_eq!(receiver.held.len(), MAX_WALK_UNLANDED);
        assert!(!receiver.exchange.want_read());
        assert_eq!(receiver.exchange.requests.len(), MAX_WALK_REQUESTS as u64);
        receiver.release();
        assert!(receiver.exchange.want_read());
        // The rest is answered, and once the peer's DONE is in and its
        // LANDED too, everything landed.
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value_of(&sender, collection, kind, key),
            };
            requests.extend(
                receiver
                    .feed(value)
                    .into_iter()
                    .filter(|reply| matches!(reply, Frame::ValueRequest { .. })),
            );
        }
        assert!(receiver.sent.contains(&Frame::Landed));
        while receiver.next().is_some() {}
        receiver.feed(Frame::Landed);
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
    }

    /// Frames out of their place fail the exchange: a node before the root,
    /// a value nobody asked for, a LANDED before this side's DONE, a second
    /// ROOT, an OPEN, a value request from a peer this side does not send
    /// to or for a key the tree lacks, and a frame after the peer's DONE.
    #[test]
    fn frames_out_of_place_fail_the_exchange() {
        let (sender, collection, _) = holding(55, "order", 1);
        let kind = WalkKind::Records;
        let root = summary(kind, sender.pinned(collection).repair());
        let node = node(kind, sender.pinned(collection).repair(), &[]).unwrap();
        let fresh = |byte| {
            let (receiver, _) = sharing(byte, "order", &[]);
            Side::both(receiver, collection, kind)
        };
        let mut receiver = fresh(56);
        receiver.feed(Frame::Node {
            prefix: Vec::new(),
            node: node.clone(),
        });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));

        let mut receiver = fresh(57);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Value {
            key: [1; 32],
            bytes: vec![0],
        });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));

        for frame in [
            Frame::Landed,
            Frame::Open { collection, kind },
            Frame::ValueRequest { key: [9; 32] },
            Frame::Done,
        ] {
            let mut receiver = fresh(58);
            receiver.feed(frame.clone());
            assert_eq!(
                receiver.outcome(),
                Some(Outcome::Failed(Failure::Protocol)),
                "{frame:?}"
            );
        }
        let mut receiver = fresh(59);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Root { summary: root });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));

        // A frame after the peer's DONE, and a LANDED twice.
        let mut receiver = fresh(60);
        receiver.feed(Frame::Root { summary: empty() });
        receiver.feed(Frame::Done);
        while receiver.next().is_some() {}
        assert_eq!(receiver.outcome(), None);
        receiver.feed(Frame::Landed);
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        let mut receiver = fresh(61);
        receiver.feed(Frame::Root { summary: empty() });
        receiver.feed(Frame::Done);
        receiver.feed(Frame::Leaf { key: [1; 32] });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));

        // A side that sends nothing serves no value, and a references
        // exchange serves none either.
        let (owner, _) = sharing(62, "order", &[]);
        let mut owner = Side::new(owner, collection, kind, None, false, true);
        owner.feed(Frame::ValueRequest { key: [9; 32] });
        assert_eq!(owner.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        let mut held = Side::new(sender, collection, WalkKind::References, None, true, true);
        held.feed(Frame::ValueRequest { key: [9; 32] });
        assert_eq!(held.outcome(), Some(Outcome::Failed(Failure::Protocol)));
    }

    /// An exchange that ends before both LANDEDs crossed is not confirmed
    /// and agrees on nothing, whether the peer never confirmed or the
    /// stream closed mid-delta.
    #[test]
    fn an_exchange_that_ends_before_both_landed_is_not_confirmed() {
        let (sender, collection, _) = holding(63, "closed", 30);
        let (receiver, _) = sharing(64, "closed", &[]);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::new(receiver, collection, kind, None, true, true);
        // The receiver's LANDED never crosses.
        loop {
            let mut moved = false;
            if let Some(frame) = sender.next() {
                receiver.hear(frame);
                moved = true;
            }
            if let Some(frame) = receiver.next() {
                if frame != Frame::Landed {
                    sender.hear(frame);
                }
                moved = true;
            }
            if !moved {
                break;
            }
        }
        // The receiver heard the sender's LANDED and sent its own: from
        // where it stands the exchange confirmed. The sender never heard
        // it: not confirmed, and no agreed tree.
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert_eq!(sender.outcome(), None);
        assert!(sender.sent.contains(&Frame::Landed));
        let ended = sender.exchange.end();
        assert!(!ended.confirmed && ended.landed && ended.agreed.is_none());
        // Closed mid-delta: nothing confirmed, nothing landed.
        let (sender, collection, _) = holding(86, "closed", 30);
        let mut sender = Side::both(sender, collection, kind);
        assert!(matches!(sender.next(), Some(Frame::Root { .. })));
        assert!(matches!(sender.next(), Some(Frame::Node { .. })));
        let ended = sender.exchange.end();
        assert!(!ended.confirmed && !ended.landed && ended.agreed.is_none());
    }

    #[test]
    fn the_peer_s_landed_counts_a_push_but_not_a_shared_agreement() {
        let (sender, collection, _) = holding(100, "one LANDED", 1);
        let mut sender = Side::both(sender, collection, WalkKind::Records);
        while sender.next().is_some() {}
        sender.feed(Frame::Landed);
        assert_eq!(sender.outcome(), None);
        let ended = sender.exchange.end();
        assert!(ended.confirmed);
        assert!(!ended.landed);
        assert!(ended.agreed.is_none());
    }

    /// A proof over another resource routed to C waits for that resource's
    /// descriptor, fetched from the peer. An exchange whose fetch of it
    /// fails does not confirm; the next lands the proof with the
    /// descriptor.
    #[test]
    fn a_deferred_proof_fails_the_exchange_until_its_descriptor_arrives() {
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::{resource_collection, resource_policy};
        use triblespace_core::capability::{CapabilityProof, CapabilityResource};
        use triblespace_core::collection::AdmissionPolicy;
        use triblespace_core::macros::entity;
        use triblespace_core::repo::{
            BlobStoreGet, BlobStorePut, CapabilityProofStore, SnapshotSource,
        };

        use crate::walk::tests::walking::key;

        let mut sender = Node::new(65);
        let mut receiver = Node::new(66);
        let collection = sender.hold("deferred", open());
        receiver.hold("deferred", open());
        let resource_root = key(67);
        let capability = triblespace_core::inline::Inline::new([10; 32]);
        let resource = sender
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
            receiver.key.verifying_key(),
        );
        sender.store.insert_proof(proof.clone()).unwrap();
        sender.observe();
        receiver.observe();
        let evidence = |node: &Node| {
            node.pinned(collection)
                .repair()
                .authorization_evidence()
                .get(proof.id())
                .cloned()
        };
        assert_eq!(evidence(&sender), Some(proof.clone()));
        let kind = WalkKind::Authorization;

        for attempt in 0..2 {
            let mut side = Side::both(receiver, collection, kind);
            stream(&mut side, &sender, collection, kind, &BTreeSet::new());
            assert_eq!(side.outcome(), None, "a fetch is owed");
            let (descriptor, fetched) = side.fetches.pop().unwrap();
            assert_eq!((fetched, descriptor), (Some(proof.clone()), resource.raw));
            // The first fetch fails; the second gets the descriptor.
            let blob = (attempt == 1).then(|| {
                BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(
                    &sender.store.snapshot().unwrap(),
                    triblespace_core::inline::Inline::new(resource.raw),
                )
                .unwrap()
            });
            let outs = side
                .exchange
                .on_fetched(resource.raw, Some(proof.clone()), blob);
            side.outputs(outs);
            if attempt == 0 {
                assert_eq!(
                    side.outcome(),
                    Some(Outcome::Failed(Failure::DeferredProof))
                );
            } else {
                assert!(side.replies().contains(&Frame::Landed));
                side.feed(Frame::Landed);
                assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            }
            assert_eq!(evidence(&side.node).is_some(), attempt == 1);
            receiver = side.node;
        }
    }

    /// A count proof closed by repeating a leaf is no proof: each leaf is
    /// owed once, at the locator its parent declared. Sixty records, one
    /// whose branch byte is its own, so the genuine root NODE owes its LEAF
    /// alone at that byte: sent once it is asked for, sent again it fails
    /// the exchange at once, the locator owed no more, and the count never
    /// closes. And ROOT, sixty LEAFs and DONE with no NODE to owe them
    /// under fails too.
    #[test]
    fn a_duplicated_or_foreign_leaf_does_not_close_the_count_proof() {
        let (sender, collection, records) = holding(68, "duplicated", 60);
        let alone = records
            .iter()
            .find(|record| {
                let edge = record.fingerprint().raw()[0];
                records
                    .iter()
                    .filter(|other| other.fingerprint().raw()[0] == edge)
                    .count()
                    == 1
            })
            .copied()
            .expect("some first byte is one record's own");
        let kind = WalkKind::Records;
        let root = summary(kind, sender.pinned(collection).repair());
        let node = node(kind, sender.pinned(collection).repair(), &[]).unwrap();
        let key = alone.fingerprint().raw();

        let (receiver, _) = sharing(69, "duplicated", &[]);
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Node {
            prefix: Vec::new(),
            node,
        });
        assert_eq!(
            receiver.feed(Frame::Leaf { key }),
            [Frame::ValueRequest { key }]
        );
        assert_eq!(receiver.outcome(), None);
        assert!(receiver.feed(Frame::Leaf { key }).is_empty());
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(receiver.feed(Frame::Done).is_empty());
        assert!(!receiver.sent.contains(&Frame::Landed));
        assert_eq!(receiver.requested().len(), 1);

        // Without a NODE, no leaf is owed at all.
        let mut receiver = Side::both(receiver.node, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        for record in &records {
            receiver.feed(Frame::Leaf {
                key: record.fingerprint().raw(),
            });
        }
        receiver.feed(Frame::Done);
        assert!(
            matches!(receiver.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            receiver.outcome()
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    /// A NODE at a locator its parent declared, canonical in itself and of
    /// the leaf count declared there but not the node the parent's child
    /// entry names, fails the exchange: a node is checked against the
    /// digest its parent declared, so every node hash-chains to the root.
    #[test]
    fn a_node_whose_digest_is_not_the_parent_s_child_digest_fails_the_exchange() {
        let (sender, collection, _) = holding(70, "chained", 400);
        let mut other = Node::new(71);
        other.hold("chained", open());
        for data in 0..400 {
            other.commit(collection, 400 + data);
        }
        other.observe();
        let (receiver, _) = sharing(72, "chained", &[]);
        let kind = WalkKind::Records;
        let pinned = sender.pinned(collection);
        let foreign = other.pinned(collection);
        let root = summary(kind, pinned.repair());
        let root_node = node(kind, pinned.repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_node else {
            panic!("400 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        // A branch byte under which both trees branch with as many leaves,
        // so that only the digest tells the foreign node from the declared
        // one.
        let (edge, foreign_node) = branch
            .children
            .iter()
            .find_map(|child| {
                let node = node(kind, foreign.repair(), &[child.edge])?;
                (matches!(node, PatchNode::Branch { .. }) && node.leaf_count() == child.leaf_count)
                    .then_some((child.edge, node))
            })
            .expect("400 records each: some first byte branches alike in both");
        let declared = branch.children.iter().find(|child| child.edge == edge);
        assert_ne!(
            declared.map(|child| child.digest),
            Some(foreign_node.digest())
        );

        let mut receiver = Side::both(receiver, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node.clone(),
        });
        assert_eq!(receiver.outcome(), None);
        receiver.feed(Frame::Node {
            prefix: vec![edge],
            node: foreign_node,
        });
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadNode)));
    }

    /// A LEAF under no locator the peer owes, a key neither tree holds,
    /// fails the exchange at once, and so does one under a locator owed
    /// with one leaf whose key does not bind the digest declared there:
    /// nothing is asked for, and nothing is remembered as landed from it. A
    /// LEAF this side holds, in flight before its announcement reached the
    /// peer, is taken as what it is.
    #[test]
    fn a_leaf_outside_the_peer_s_tree_fails_the_exchange() {
        let (sender, collection, records) = holding(73, "outside", 60);
        let (receiver, _) = sharing(74, "outside", &[]);
        let kind = WalkKind::Records;
        let pinned = sender.pinned(collection);
        let root = summary(kind, pinned.repair());
        let root_node = node(kind, pinned.repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_node else {
            panic!("60 records branch at the root");
        };
        // A key under a branch byte the tree does not use.
        let edge = (0..=255u8)
            .find(|edge| branch.children.iter().all(|child| child.edge != *edge))
            .unwrap();
        let mut key = [7; 32];
        key[0] = edge;

        let mut receiver = Side::both(receiver, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node.clone(),
        });
        assert!(receiver.feed(Frame::Leaf { key }).is_empty());
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(receiver.requested().is_empty());
        assert!(!receiver.sent.contains(&Frame::Landed));

        // A key under a branch byte the root owes with one leaf, which is
        // not the key whose digest the root declared there.
        let single = branch
            .children
            .iter()
            .find(|child| child.leaf_count == 1)
            .expect("60 records: some first byte holds one");
        let mut key = [7; 32];
        key[0] = single.edge;
        assert!(
            records
                .iter()
                .all(|record| record.fingerprint().raw() != key)
        );
        let mut receiver = Side::both(receiver.node, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        receiver.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node.clone(),
        });
        assert!(receiver.feed(Frame::Leaf { key }).is_empty());
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::BadNode)));
        assert!(receiver.requested().is_empty());
        assert!(!receiver.sent.contains(&Frame::Landed));
        let ended = receiver.exchange.end();
        assert!(!ended.landed && ended.agreed.is_none());

        // A leaf this side holds, under no owed locator, is in flight.
        let (holder, _) = sharing(75, "outside", &records[..1]);
        let mut holder = Side::both(holder, collection, kind);
        holder.feed(Frame::Root { summary: root });
        holder.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node,
        });
        let held = records[0].fingerprint().raw();
        assert!(holder.feed(Frame::Leaf { key: held }).is_empty());
        assert_eq!(holder.outcome(), None);
        assert!(holder.requested().is_empty());
    }

    /// A peer that streams leaves and withholds their values makes this
    /// side queue what it wants to ask for. The stream stays read, since
    /// only reading brings the values owed, and the queue fails the
    /// exchange once it exceeds the explicit waiting-leaf budget. A
    /// sixty-first leaf against a root of sixty fails at once, before DONE.
    #[test]
    fn a_leaf_flood_with_withheld_values_fails_the_exchange_and_an_overcount_fails_at_once() {
        let (receiver, collection) = sharing(76, "flood", &[]);
        let (root, root_node, branches) = fabricated(256, FLOOD_WANTED / 256 + 2);
        assert!(root.leaf_count() as usize > FLOOD_WANTED + MAX_WALK_REQUESTS);
        let kind = WalkKind::Records;
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.feed(Frame::Root { summary: root });
        assert!(receiver.feed(root_node).is_empty());
        let mut fed = 0;
        'flood: for (node, leaves) in branches {
            receiver.feed(node);
            for leaf in leaves {
                assert!(receiver.exchange.want_read(), "values are owed");
                receiver.feed(leaf);
                fed += 1;
                if receiver.outcome().is_some() {
                    break 'flood;
                }
            }
        }
        assert_eq!(receiver.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert_eq!(receiver.exchange.wanted.len(), FLOOD_WANTED);
        assert_eq!(fed, FLOOD_WANTED + MAX_WALK_REQUESTS + 1);
        assert_eq!(receiver.requested().len(), MAX_WALK_REQUESTS);

        // A sixty-first leaf against a root of sixty fails at once.
        let (sender, collection, _) = holding(77, "overcount", 60);
        let (receiver, _) = sharing(78, "overcount", &[]);
        let mut receiver = Side::both(receiver, collection, kind);
        let mut frames = tree(&sender, collection, kind, &BTreeSet::new());
        assert_eq!(frames.pop(), Some(Frame::Done));
        let again = frames
            .iter()
            .find(|frame| matches!(frame, Frame::Leaf { .. }))
            .unwrap()
            .clone();
        for frame in frames {
            receiver.feed(frame);
        }
        assert_eq!(receiver.outcome(), None);
        receiver.feed(again);
        assert!(
            matches!(receiver.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            receiver.outcome()
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    /// A canonical wide frontier is not a withheld-value flood. All 65,536
    /// leaf locators can be owed before any leaf arrives; DONE still cannot
    /// close that membership proof while those locators remain.
    #[test]
    fn a_wide_owed_frontier_is_not_mistaken_for_withheld_values() {
        let (receiver, collection) = sharing(79, "nodes", &[]);
        let (root, root_node, branches) = fabricated(256, 256);
        let mut receiver = Side::both(receiver, collection, WalkKind::Records);
        receiver.feed(Frame::Root { summary: root });
        assert!(receiver.feed(root_node).is_empty());
        assert_eq!(receiver.exchange.owed.len(), 256);
        for (node, _) in &branches {
            // The branch's own locator is consumed, its 256 children owed.
            let after = receiver.exchange.owed.len() - 1 + 256;
            receiver.feed(node.clone());
            assert!(receiver.exchange.owed.len() <= FLOOD_LOCATORS as u64);
            assert_eq!(receiver.outcome(), None);
            assert_eq!(receiver.exchange.owed.len(), after);
        }
        assert_eq!(receiver.exchange.owed.len(), 65_536);
        receiver.feed(Frame::Done);
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!receiver.sent.contains(&Frame::Landed));
    }

    #[test]
    fn a_first_exchange_above_32k_frontier_completes_without_dfs() {
        let (sender, collection, records) = holding(90, "wide FIFO", 70_000);
        let (receiver, _) = sharing(91, "wide FIFO", &[]);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let mut receiver = Side::both(receiver, collection, kind);
        receiver.observe_landings = false;
        let mut peak = 0;
        let mut depths = Vec::new();
        loop {
            let mut moved = false;
            if let Some(frame) = sender.next() {
                if let Frame::Node { prefix, .. } = &frame {
                    depths.push(prefix.len());
                }
                peak = peak.max(sender.exchange.queue.len());
                receiver.hear(frame);
                moved = true;
            }
            if let Some(frame) = receiver.next() {
                sender.hear(frame);
                moved = true;
            }
            if !moved {
                break;
            }
        }
        assert!(peak > 32_768, "frontier only {peak}");
        assert!(depths.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(sender.outcome(), Some(Outcome::Confirmed));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert!(receiver.exchange.owed.is_empty());
        receiver.node.observe();
        assert_eq!(
            receiver.node.records(collection),
            records.into_iter().collect()
        );
        assert_eq!(sender.agreed(), receiver.agreed());
        eprintln!(
            "W8_WIDE leaves=70000 peak_fifo_locators={peak} locator_ceiling={FLOOD_LOCATORS} scheduling=one_frame_each_direction immediate_individual_insert_ack frozen_resident_observation_until_end"
        );
    }

    #[test]
    fn a_shared_subtree_is_announced_once_each_way_on_the_first_exchange() {
        let (mut a, collection, records) = holding(93, "first shared", 1000);
        let (mut b, _) = sharing(94, "first shared", &records);
        let own_a = a.commit(collection, 1_000);
        let own_b = b.commit(collection, 2_000);
        a.observe();
        b.observe();
        let kind = WalkKind::Records;
        let root_a = node(kind, a.pinned(collection).repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_a else {
            panic!("the root branches");
        };
        let shared = branch
            .children
            .iter()
            .find(|child| {
                child.leaf_count > 1
                    && child.edge != own_a.fingerprint().raw()[0]
                    && child.edge != own_b.fingerprint().raw()[0]
            })
            .unwrap();
        let prefix = vec![shared.edge];
        let mut a = Side::both(a, collection, kind);
        let mut b = Side::both(b, collection, kind);
        carry(&mut a, &mut b);
        for side in [&a, &b] {
            assert_eq!(side.outcome(), Some(Outcome::Confirmed));
            let announcements = side.sent.iter().filter(|frame| matches!(frame,
                Frame::Node { prefix: at, node: PatchNode::Branch { branch, .. } }
                if at.is_empty() && branch.children.iter().any(|child| child.edge == shared.edge && child.digest == shared.digest)
            )).count();
            assert_eq!(announcements, 1);
            assert!(side.nodes().iter().all(|at| !at.starts_with(&prefix)));
            assert!(side.leaves().iter().all(|key| !key.starts_with(&prefix)));
            assert_eq!(side.requested().len(), 1);
        }
        assert_eq!(a.agreed(), b.agreed());
        eprintln!(
            "W8_FIRST_SHARED agreed_before=none shared_leaves={} announcements_per_direction=1 descendants_streamed=0 scheduling=one_frame_each_direction",
            shared.leaf_count
        );
    }

    #[test]
    fn a_receive_only_side_remembers_accounted_subtrees_without_leaf_frames() {
        let (sender, collection, records) = holding(95, "one-way shared", 1000);
        let kind = WalkKind::Records;
        let root = node(kind, sender.pinned(collection).repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root else {
            panic!("the root branches");
        };
        let child = branch
            .children
            .iter()
            .find(|child| child.leaf_count > 1)
            .unwrap();
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw()[0] == child.edge)
            .copied()
            .collect::<Vec<_>>();
        let (receiver, _) = sharing(96, "one-way shared", &shared);
        let expected = summary(kind, sender.pinned(collection).repair());
        let mut receiver = Side::new(receiver, collection, kind, None, false, true);
        // A scripted delta omits an already-held authenticated subtree;
        // this is a membership/agreement-construction control, not a claim
        // that a send-disabled peer emitted subtree announcements.
        stream(
            &mut receiver,
            &sender,
            collection,
            kind,
            &fingerprints(shared),
        );
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert!(
            receiver
                .heard
                .iter()
                .all(|frame| !matches!(frame, Frame::Leaf { key } if key[0] == child.edge))
        );
        assert_eq!(receiver.agreed(), Some(expected));
    }

    #[test]
    fn a_lagging_pinned_snapshot_cannot_shrink_the_agreed_union() {
        let (b, collection, records) = holding(101, "lagged union", 100);
        let (a, _) = sharing(102, "lagged union", &records[..50]);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, b.pinned(collection).repair()));
        let expected = agreed.summary();
        let mut a = Side::new(a, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b, collection, kind, Some(agreed), true, true);
        // The physical store holds the agreement; only the exchange's
        // captured serving observation lagged those previous landings.
        for record in &records[50..] {
            a.node.store.insert(*record).unwrap();
        }
        a.node.observe();
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.agreed(), Some(expected));
        assert_eq!(b.agreed(), Some(expected));
        assert!(a.requested().is_empty() && b.requested().is_empty());
    }

    #[test]
    fn a_receive_only_lagged_root_cannot_shrink_prior_agreement() {
        let (prior, collection, records) = holding(111, "one-way lag", 100);
        let (writer, _) = sharing(112, "one-way lag", &records[..50]);
        let (owner, _) = sharing(113, "one-way lag", &records[..50]);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, prior.pinned(collection).repair()));
        let expected = agreed.summary();
        let mut writer = Side::new(writer, collection, kind, Some(agreed.clone()), true, false);
        let mut owner = Side::new(owner, collection, kind, Some(agreed), false, true);
        for side in [&mut writer, &mut owner] {
            for record in &records[50..] {
                side.node.store.insert(*record).unwrap();
            }
            side.node.observe();
        }
        carry(&mut writer, &mut owner);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed));
        assert_eq!(owner.outcome(), Some(Outcome::Confirmed));
        assert_eq!(writer.agreed(), Some(expected));
        assert_eq!(owner.agreed(), Some(expected));
        assert!(writer.requested().is_empty() && owner.requested().is_empty());
        assert_eq!(owner.sent.first(), Some(&Frame::Root { summary: empty() }));
    }

    #[test]
    fn an_already_held_node_authenticates_children_before_announcing_them() {
        let (node, collection, _) = holding(97, "late canonical", 300);
        let kind = WalkKind::Records;
        let root = summary(kind, node.pinned(collection).repair());
        let mut malformed = crate::walk::node(kind, node.pinned(collection).repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &mut malformed else {
            panic!("the root branches");
        };
        branch.end_depth = 255; // Would panic if announce sliced first.
        let mut side = Side::both(node, collection, kind);
        side.feed(Frame::Root { summary: root });
        assert!(side.exchange.owed.is_empty());
        // Bypass the codec deliberately: the state machine protects its own
        // canonical bounds even for an already-accounted in-flight node.
        let outs = side.exchange.on_frame(
            Frame::Node {
                prefix: Vec::new(),
                node: malformed,
            },
            Some(side.node.snapshot()),
        );
        assert!(outs.is_empty());
        assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::BadNode)));
    }

    #[test]
    fn exceeding_the_locator_budget_fails_instead_of_switching_to_dfs() {
        let (sender, collection, _) = holding(92, "bounded FIFO", 300);
        let mut sender = Side::both(sender, collection, WalkKind::Records);
        sender.exchange.root_sent = true;
        sender.exchange.queue = std::iter::repeat_n(Vec::new(), FLOOD_LOCATORS).collect();
        assert_eq!(sender.next(), None);
        assert_eq!(sender.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(sender.agreed().is_none());
    }

    /// A ROOT equal to this side's tree is accounted whole and never
    /// descended; one equal to the agreed tree too, at a side that holds
    /// more now, so ROOT then DONE lands with nothing between. Without the
    /// agreed tree a superset neither holds the root nor accounts for it,
    /// and ROOT then DONE fails the count proof.
    #[test]
    fn an_equal_or_agreed_root_is_accounted_whole() {
        let (sender, collection, records) = holding(80, "equal", 50);
        let (receiver, _) = sharing(81, "equal", &records);
        let kind = WalkKind::Records;
        let root = summary(kind, sender.pinned(collection).repair());
        let mut receiver = Side::both(receiver, collection, kind);
        let streamed = stream(&mut receiver, &sender, collection, kind, &BTreeSet::new());
        assert!(matches!(
            &streamed[..],
            [
                Frame::Root { .. },
                Frame::Node { .. },
                ..,
                Frame::Done,
                Frame::Landed
            ]
        ));
        assert_eq!(receiver.outcome(), Some(Outcome::Confirmed));
        assert!(receiver.requested().is_empty());
        // The peer's ROOT, heard first, announced the whole tree.
        assert!(receiver.nodes().is_empty(), "{:?}", receiver.sent);
        assert_eq!(receiver.agreed(), Some(root));
        let agreed = Arc::new(Tree::pinned(kind, sender.pinned(collection).repair()));

        // The side holds more than it agreed on: the agreed root still
        // satisfies the count proof.
        let mut superset = receiver.node;
        superset.commit(collection, 100);
        superset.observe();
        let mut receiver = Side::new(superset, collection, kind, Some(agreed), false, true);
        assert!(receiver.feed(Frame::Root { summary: root }).is_empty());
        assert_eq!(receiver.feed(Frame::Done), [Frame::Landed]);
        assert!(receiver.exchange.owed.is_empty());

        // Without that memory a superset neither holds the root nor
        // accounts for it.
        let mut receiver = Side::new(receiver.node, collection, kind, None, false, true);
        assert!(receiver.feed(Frame::Root { summary: root }).is_empty());
        assert!(receiver.feed(Frame::Done).is_empty());
        assert_eq!(
            receiver.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
    }

    /// A side that gained records under a subtree the peer left unchanged
    /// still accounts for that subtree: the peer skips it as equal to the
    /// agreed tree, and this side holds the agreed tree.
    #[test]
    fn a_subtree_equal_to_the_agreed_tree_is_accounted_however_this_side_grew() {
        let (a, collection, records) = holding(82, "grew", 300);
        let (b, _) = sharing(83, "grew", &records);
        let kind = WalkKind::Records;
        let agreed = Arc::new(Tree::pinned(kind, a.pinned(collection).repair()));
        let mut a = Side::new(a, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b, collection, kind, Some(agreed.clone()), true, true);
        // A gains one record, B three: every exchange lands only those.
        let one = a.node.commit(collection, 1_000);
        a.node.observe();
        let three = (0..3)
            .map(|data| b.node.commit(collection, 2_000 + data))
            .collect::<Vec<_>>();
        b.node.observe();
        let mut a = Side::new(a.node, collection, kind, Some(agreed.clone()), true, true);
        let mut b = Side::new(b.node, collection, kind, Some(agreed), true, true);
        burst(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.outcome(), Some(Outcome::Confirmed));
        assert_eq!(a.requested(), fingerprints(three.iter().copied()));
        assert_eq!(b.requested(), fingerprints([one]));
        let expected = paths(
            a.node.pinned(collection).repair().records().patch(),
            &[one.fingerprint().raw()],
        );
        assert_eq!(a.nodes().into_iter().collect::<BTreeSet<_>>(), expected);
        assert_eq!(a.agreed(), b.agreed());
        assert_eq!(a.node.records(collection).len(), 304);
        assert_eq!(b.node.records(collection), a.node.records(collection));
    }

    /// The pinned tree's values serve VALUE_REQUESTs, and a request for a
    /// key the tree lacks fails the exchange.
    #[test]
    fn values_are_served_from_the_pinned_tree() {
        let (sender, collection, records) = holding(84, "served", 5);
        let kind = WalkKind::Records;
        let mut sender = Side::both(sender, collection, kind);
        let key = records[0].fingerprint().raw();
        let replies = sender.feed(Frame::ValueRequest { key });
        let [Frame::Value { key: served, bytes }] = &replies[..] else {
            panic!("one value: {replies:?}");
        };
        assert_eq!(*served, key);
        assert_eq!(decode_record(collection, bytes).unwrap(), records[0]);
        sender.feed(Frame::ValueRequest { key: [9; 32] });
        assert_eq!(sender.outcome(), Some(Outcome::Failed(Failure::Protocol)));
    }

    /// The agreed tree of each kind summarises and locates like the
    /// overlay's own tree, and an inserted key changes it as the overlay
    /// would.
    #[test]
    fn the_agreed_tree_mirrors_the_overlay_s_tree() {
        let (mut node, collection, records) = holding(85, "tree", 40);
        for kind in [
            WalkKind::Records,
            WalkKind::Authorization,
            WalkKind::References,
        ] {
            let pinned = node.pinned(collection);
            let tree = Tree::pinned(kind, pinned.repair());
            assert_eq!(tree.summary(), summary(kind, pinned.repair()));
            for locator in [&[][..], &records[0].fingerprint().raw()[..1]] {
                assert_eq!(
                    tree.at(locator),
                    local_summary(kind, pinned.repair(), locator)
                );
            }
        }
        let before = Tree::pinned(WalkKind::Records, node.pinned(collection).repair());
        let mut tree = before.clone();
        let record = node.commit(collection, 1_000);
        node.observe();
        tree.insert(record.fingerprint().raw(), Value::Record(record));
        assert_eq!(
            tree.summary(),
            summary(WalkKind::Records, node.pinned(collection).repair())
        );
        assert_ne!(before.summary(), tree.summary(), "the clone is its own");
        assert!(
            !tree.has_new_keys(&before),
            "a lagging subset is not a local append"
        );
        assert!(
            before.has_new_keys(&tree),
            "a genuinely new key needs another exchange"
        );
    }
}
