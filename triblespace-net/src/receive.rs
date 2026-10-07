//! The receiving side of a walk stream.
//!
//! A [`Receive`] takes what one sender pushes on one `walk/1` stream
//! ([`crate::walk_stream`]) of one collection and kind and decides, frame by
//! frame, what to send back and what to land; it does no I/O of its own, and
//! [`crate::walk`] drives it. The pushed root is never answered. It is
//! compared with the live tree and with the root of the last push from the
//! same sender that landed here: while it equals either, every pushed node
//! is answered with every child held and pushed leaves are ignored, so the
//! root alone satisfies the proof and a push of ROOT then DONE lands at
//! once, at a receiver that holds the tree or a superset of it. Otherwise
//! the receiver keeps the locators the sender owes it, each with the digest
//! and leaf count declared for it: the root's by ROOT, then every accepted
//! node's children the live tree does not hold under the same digest and
//! count, whose subtrees the sender skips. A node is accepted only at a
//! locator owed and checked against the digest declared there, so every
//! node hash-chains to the root; a leaf only under a locator owed with one
//! leaf and the digest its key binds; and each locator is owed once. Every
//! pushed leaf whose value the live store lacks is asked for and lands as
//! it arrives. A held reference carries no value: one resident here is
//! noted held as it is, another is fetched by hash.
//!
//! The push ends in one of two ways. It lands when its membership proof
//! closes (every locator owed was pushed, so the leaves pushed plus the
//! leaves of every skipped subtree are exactly the root's count), every
//! value asked for landed without a failed insert, no fetch failed and no
//! proof stayed deferred: [`Frame::Landed`] goes back, and the sender
//! confirms its root. Anything else fails it, and what landed stays.
//!
//! Three bounds keep what a push costs here. Values are asked for
//! [`MAX_WALK_REQUESTS`] at a time, and the leaves beyond that wait their
//! turn. Nodes are answered only while fewer than [`MAX_WANTED`] leaves wait,
//! so the sender's window of unanswered nodes holds its push, and a push
//! with [`FLOOD_WANTED`] leaves waiting, more than that window can push, is
//! a flood and fails. And [`Receive::want_read`] is false while
//! [`MAX_WALK_UNLANDED`] values are with the landing task, so the driver
//! stops reading and QUIC flow control holds the sender. The stream is read
//! on while a value is owed to it: only reading brings the value, so
//! stopping for owed values would wait forever. After DONE it is read only
//! while a value asked for is still to come, and the driver times its wait
//! for a frame only while one is owed ([`Receive::awaits`]): the fetches
//! and landings that follow DONE take what time they take.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::CollectionHandle;
use triblespace_core::patch::{Blake3Merkle, PatchHash};

use crate::channel::NetEvent;
use crate::host::{CollectionSnapshot, StoreSnapshot};
use crate::patch_repair::{PatchNode, PatchRepairRequest, PatchSummary, validate_patch_node};
use crate::protocol::RawHash;
use crate::transport::PeerId;
use crate::walk::{
    Admit, KEY_BYTES, MAX_WALK_REQUESTS, MAX_WALK_UNLANDED, WalkKind, admit_fetched, admit_missing,
    admit_value,
};
use crate::walk_stream::{Frame, hold};

/// Leaves waiting to be asked for before pushed nodes go unanswered.
pub(crate) const MAX_WANTED: usize = 1024;
/// Leaves waiting to be asked for beyond which the push is a flood and
/// fails. A sender whose HELDs are withheld can push at most the children
/// of the nodes answered before, a window of 64 nodes of 256 each on top
/// of [`MAX_WANTED`], so twice that is out of any honest sender's reach.
pub(crate) const FLOOD_WANTED: usize = 32 * MAX_WANTED;

/// What a receive asks of its driver.
#[derive(Debug)]
pub(crate) enum Out {
    Send(Frame),
    /// Values for the landing task, acknowledged with
    /// [`Receive::on_landed_ack`].
    Land(Vec<NetEvent>),
    /// Fetch a blob by hash from the sender, answered with
    /// [`Receive::on_fetched`]: a held reference, or the routing descriptor
    /// a deferred `proof` names.
    Fetch {
        handle: RawHash,
        proof: Option<CapabilityProof>,
    },
}

/// How a push ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Everything pushed is here, and [`Frame::Landed`] was sent.
    Landed,
    Failed(Failure),
}

/// Why a push failed. What landed stays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    /// The collection is not active here.
    Unavailable,
    /// A frame out of its place: a node, leaf or end before the root, a
    /// second root, a node or leaf at a locator the sender does not owe or
    /// owes no more, a leaf beyond what a sender's window can push, a value
    /// nobody asked for, a frame after the end, or one only a receiver
    /// sends.
    Protocol,
    /// A pushed node is not canonical, or is not the node its parent (or
    /// the root) declared at its locator.
    BadNode,
    /// A value that does not decode, is not under its key, or is not
    /// evidence for the collection.
    BadValue,
    /// The leaves pushed and skipped do not add up to the root's count, or
    /// a locator owed was never pushed.
    CountMismatch,
    /// A value failed to land, or a held reference could not be fetched.
    InsertFailed,
    /// A proof waits for a descriptor that did not arrive.
    DeferredProof,
}

/// One push being received.
pub(crate) struct Receive {
    collection: CollectionHandle,
    kind: WalkKind,
    /// The store as of the last frame: what missing leaves are checked
    /// against between frames.
    snapshot: Option<Arc<StoreSnapshot>>,
    root: Option<PatchSummary>,
    /// The root of the last push of this tree from the sender that landed
    /// here, which the sender may push again as ROOT then DONE.
    landed: Option<PatchSummary>,
    /// The pushed root equals the live tree, or landed here before:
    /// everything is held.
    equal: bool,
    /// Leaves pushed, and the leaves of the subtrees skipped as held.
    accounted: u64,
    /// The nodes the sender owes, by locator: the digest and leaf count
    /// declared for each by its parent, or by ROOT for the root. Consumed
    /// by the node or leaf pushed at each; DONE needs every one consumed.
    expected: HashMap<Vec<u8>, ([u8; 32], u64)>,
    /// Replies to pushed nodes, sent while few leaves wait.
    held: VecDeque<Frame>,
    /// Missing leaves not yet asked for, in the order pushed.
    wanted: VecDeque<[u8; KEY_BYTES]>,
    /// Value requests in flight.
    requests: HashSet<[u8; KEY_BYTES]>,
    /// Blob fetches in flight.
    fetching: usize,
    /// Values with the landing task.
    unlanded: usize,
    failed: u64,
    deferred: bool,
    done: bool,
    outcome: Option<Outcome>,
}

impl Receive {
    /// Take the sender's open of C's `kind` tree. `admitted` is whether this
    /// side receives C from the peer; a push it does not admit is refused
    /// (`None`), and the driver resets the stream. `landed` is the root of
    /// the last push of this tree from the peer that landed here.
    pub(crate) fn on_open(
        _peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        admitted: bool,
        landed: Option<PatchSummary>,
    ) -> Option<Self> {
        admitted.then(|| Self {
            collection,
            kind,
            snapshot: None,
            root: None,
            landed,
            equal: false,
            accounted: 0,
            expected: HashMap::new(),
            held: VecDeque::new(),
            wanted: VecDeque::new(),
            requests: HashSet::new(),
            fetching: 0,
            unlanded: 0,
            failed: 0,
            deferred: false,
            done: false,
            outcome: None,
        })
    }

    /// Take one frame from the sender, seeing the live store as `snapshot`.
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

    /// Whether the driver should read the next frame: not while
    /// [`MAX_WALK_UNLANDED`] values are with the landing task, not once the
    /// push ended, and not after DONE unless a value asked for is still to
    /// come: then nothing is owed either way, and the fetches and landings
    /// left take what time they take.
    pub(crate) fn want_read(&self) -> bool {
        self.outcome.is_none()
            && self.unlanded < MAX_WALK_UNLANDED
            && (!self.done || !self.requests.is_empty())
    }

    /// Whether the sender owes this side a frame while this side owes it
    /// nothing, so the driver times its wait for one: before DONE the next
    /// node, leaf or DONE, unless a HELD is withheld here and the sender's
    /// walk waits on it; after DONE the values asked for.
    pub(crate) fn awaits(&self) -> bool {
        !self.requests.is_empty() || (!self.done && self.held.is_empty())
    }

    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// The pushed root, once it arrived.
    pub(crate) fn root(&self) -> Option<PatchSummary> {
        self.root
    }

    fn frame(&mut self, frame: Frame, outs: &mut Vec<Out>) -> Result<(), Failure> {
        let live = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(self.collection))
            .ok_or(Failure::Unavailable)?;
        let overlay = live.repair();
        match frame {
            Frame::Root { summary } => {
                if self.root.is_some() {
                    return Err(Failure::Protocol);
                }
                self.root = Some(summary);
                if summary == crate::walk::summary(self.kind, overlay)
                    || Some(summary) == self.landed
                {
                    self.equal = true;
                    self.accounted = summary.leaf_count();
                } else if let Some(root) = summary.root() {
                    self.expected
                        .insert(Vec::new(), (root, summary.leaf_count()));
                }
            }
            Frame::Node { prefix, node } => {
                let root = self.pushing()?;
                if self.equal {
                    // The whole tree is here: every child of every node.
                    self.held.push_back(Frame::Held {
                        prefix,
                        children: [0xFF; 32],
                    });
                    return Ok(());
                }
                // The node declared at this locator, owed once.
                let (digest, leaf_count) =
                    self.expected.remove(&prefix).ok_or(Failure::Protocol)?;
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
                let mut children = [0; 32];
                match node {
                    PatchNode::Leaf { leaf, .. } => {
                        let key =
                            <[u8; KEY_BYTES]>::try_from(leaf.key).map_err(|_| Failure::BadNode)?;
                        self.leaf(key, &live)?;
                    }
                    PatchNode::Branch { branch, .. } => {
                        // A child is held when the live subtree under its
                        // locator is the same set: compressed paths need not
                        // line up, so the live node at `prefix` may branch
                        // elsewhere and still hold the child whole. The
                        // others are owed at their locators.
                        let end = usize::from(branch.end_depth);
                        for child in &branch.children {
                            let mut locator = branch.representative[..end].to_vec();
                            locator.push(child.edge);
                            let mine = crate::walk::local_summary(self.kind, overlay, &locator);
                            let pushed = PatchSummary::new(Some(child.digest), child.leaf_count)
                                .map_err(|_| Failure::BadNode)?;
                            if mine == Some(pushed) {
                                hold(&mut children, child.edge);
                                self.accounted = self
                                    .accounted
                                    .checked_add(child.leaf_count)
                                    .ok_or(Failure::CountMismatch)?;
                            } else if self
                                .expected
                                .insert(locator, (child.digest, child.leaf_count))
                                .is_some()
                            {
                                return Err(Failure::BadNode);
                            }
                        }
                    }
                }
                self.held.push_back(Frame::Held { prefix, children });
            }
            Frame::Leaf { key } => {
                self.pushing()?;
                if !self.equal {
                    // The leaf owed at the longest locator on its key's
                    // path, once, with the digest its key binds.
                    let locator = (0..=KEY_BYTES)
                        .rev()
                        .find(|len| self.expected.contains_key(&key[..*len]))
                        .ok_or(Failure::Protocol)?;
                    let (digest, leaf_count) = self
                        .expected
                        .remove(&key[..locator])
                        .expect("the locator was just found");
                    let base = crate::walk::base(self.kind, self.collection);
                    let absolute = [&base[..], &key[..]].concat();
                    if leaf_count != 1 || digest != <Blake3Merkle as PatchHash>::leaf(&absolute) {
                        return Err(Failure::BadNode);
                    }
                    self.leaf(key, &live)?;
                }
            }
            Frame::Value { key, bytes } => {
                if !self.requests.remove(&key) {
                    return Err(Failure::Protocol);
                }
                let evidence = overlay.authorization_evidence();
                let admit = admit_value(self.kind, self.collection, key, &bytes, evidence)
                    .map_err(|_| Failure::BadValue)?;
                self.admit(admit, outs);
            }
            Frame::Done => {
                let root = self.pushing()?;
                self.done = true;
                if !self.expected.is_empty() || self.accounted != root.leaf_count() {
                    return Err(Failure::CountMismatch);
                }
            }
            Frame::Open { .. }
            | Frame::Held { .. }
            | Frame::ValueRequest { .. }
            | Frame::Landed => {
                return Err(Failure::Protocol);
            }
        }
        Ok(())
    }

    /// The root, while the sender pushes: after its root and before its end.
    fn pushing(&self) -> Result<PatchSummary, Failure> {
        match self.root {
            Some(root) if !self.done => Ok(root),
            _ => Err(Failure::Protocol),
        }
    }

    /// Count one pushed leaf, and want its value unless the live tree has
    /// it. More leaves wanted than a sender's window can push is a flood.
    fn leaf(&mut self, key: [u8; KEY_BYTES], live: &CollectionSnapshot) -> Result<(), Failure> {
        self.accounted = self
            .accounted
            .checked_add(1)
            .ok_or(Failure::CountMismatch)?;
        if !crate::walk::contains(self.kind, live.repair(), &key) {
            if self.wanted.len() >= FLOOD_WANTED {
                return Err(Failure::Protocol);
            }
            self.wanted.push_back(key);
        }
        Ok(())
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

    /// Ask for wanted leaves while the window has room, answer pushed nodes
    /// while few leaves wait, and end the push once nothing is owed.
    fn settle(&mut self, outs: &mut Vec<Out>) {
        if self.outcome.is_some() {
            return;
        }
        while self.requests.len() + self.fetching < MAX_WALK_REQUESTS
            && let Some(key) = self.wanted.pop_front()
        {
            match admit_missing(self.kind, self.collection, key, self.snapshot.as_deref()) {
                Some(admit) => self.admit(admit, outs),
                None => {
                    self.requests.insert(key);
                    outs.push(Out::Send(Frame::ValueRequest { key }));
                }
            }
        }
        while self.wanted.len() < MAX_WANTED
            && let Some(frame) = self.held.pop_front()
        {
            outs.push(Out::Send(frame));
        }
        if !self.done
            || !self.wanted.is_empty()
            || !self.requests.is_empty()
            || self.fetching > 0
            || self.unlanded > 0
        {
            return;
        }
        if self.failed > 0 {
            self.fail(Failure::InsertFailed);
        } else if self.deferred {
            self.fail(Failure::DeferredProof);
        } else {
            outs.push(Out::Send(Frame::Landed));
            self.outcome = Some(Outcome::Landed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use triblespace_core::capability::CapabilityProofId;
    use triblespace_core::collection::{
        CollectionData, CollectionMerge, CollectionRecord, CollectionRecordFingerprint,
        CollectionStore,
    };

    use crate::collection_activation::CollectionRepairOverlay;
    use crate::collection_delta::encode_record;
    use crate::walk::tests::walking::{Node, open};
    use crate::walk_stream::held;

    /// One receiving node and the push it receives: the frames it sends,
    /// the landings it carries out (or holds back) and the fetches it asks
    /// for.
    struct Harness {
        node: Node,
        receive: Receive,
        /// Every frame the receiver sent.
        sent: Vec<Frame>,
        /// Frames the receiver sent that the sender has not taken yet.
        pending: Vec<Frame>,
        held: Vec<Vec<NetEvent>>,
        hold: bool,
        fetches: Vec<(RawHash, Option<CapabilityProof>)>,
    }

    impl Harness {
        fn new(node: Node, collection: CollectionHandle, kind: WalkKind) -> Self {
            Self::landed(node, collection, kind, None)
        }

        /// A harness whose receiver landed a push with root `landed` from
        /// the sender before.
        fn landed(
            node: Node,
            collection: CollectionHandle,
            kind: WalkKind,
            landed: Option<PatchSummary>,
        ) -> Self {
            Self {
                receive: Receive::on_open([0; 32], collection, kind, true, landed).unwrap(),
                node,
                sent: Vec::new(),
                pending: Vec::new(),
                held: Vec::new(),
                hold: false,
                fetches: Vec::new(),
            }
        }

        /// Feed one frame through the codec; the frames sent back.
        fn feed(&mut self, frame: Frame) -> Vec<Frame> {
            let (kind, payload) = frame.encode();
            let frame = Frame::decode(kind, &payload).unwrap().unwrap();
            let outs = self.receive.on_frame(frame, Some(self.node.snapshot()));
            self.outputs(outs);
            std::mem::take(&mut self.pending)
        }

        fn outputs(&mut self, outs: Vec<Out>) {
            for out in outs {
                match out {
                    Out::Send(frame) => {
                        self.sent.push(frame.clone());
                        self.pending.push(frame);
                    }
                    Out::Land(events) if self.hold => self.held.push(events),
                    Out::Land(events) => self.land(events),
                    Out::Fetch { handle, proof } => self.fetches.push((handle, proof)),
                }
            }
        }

        /// Insert, publish and acknowledge, as the landing task does.
        fn land(&mut self, events: Vec<NetEvent>) {
            let (landed, failed) = self.node.insert(events);
            self.node.observe();
            let outs = self.receive.on_landed_ack(landed, failed);
            self.outputs(outs);
        }

        fn release(&mut self) {
            self.hold = false;
            for events in std::mem::take(&mut self.held) {
                self.land(events);
            }
        }

        fn requested(&self) -> BTreeSet<[u8; 32]> {
            self.sent
                .iter()
                .filter_map(|frame| match frame {
                    Frame::ValueRequest { key } => Some(*key),
                    _ => None,
                })
                .collect()
        }
    }

    /// The value under `key` at the sender, as its responder serves it.
    fn value(kind: WalkKind, overlay: &CollectionRepairOverlay, key: [u8; 32]) -> Vec<u8> {
        match kind {
            WalkKind::Records => overlay
                .records()
                .get(CollectionRecordFingerprint::from_raw(key))
                .map(|record| encode_record(overlay.collection(), record).unwrap())
                .unwrap(),
            WalkKind::Authorization => overlay
                .authorization_evidence()
                .get(CapabilityProofId::new(key))
                .map(|proof| proof.as_bytes().to_vec())
                .unwrap(),
            WalkKind::References => panic!("held references carry no values"),
        }
    }

    /// A scripted sender: push `sender`'s `kind` tree of C to the harness,
    /// skipping what each reply says is held, answering every value request
    /// at once, and leaving out the leaves in `omit`. Returns the frames
    /// pushed, leaves included.
    fn push(
        harness: &mut Harness,
        sender: &Node,
        collection: CollectionHandle,
        kind: WalkKind,
        omit: &BTreeSet<[u8; 32]>,
    ) -> Vec<Frame> {
        let overlay = sender.serving().collection(collection).unwrap();
        let overlay = overlay.repair();
        let mut pushed = Vec::new();
        let mut send = |harness: &mut Harness, frame: Frame| {
            pushed.push(frame.clone());
            let mut replies = harness.feed(frame);
            let mut helds = Vec::new();
            while let Some(reply) = replies.pop() {
                match reply {
                    Frame::ValueRequest { key } => {
                        let value = Frame::Value {
                            key,
                            bytes: value(kind, overlay, key),
                        };
                        pushed.push(value.clone());
                        replies.extend(harness.feed(value));
                    }
                    Frame::Held { prefix, children } => helds.push((prefix, children)),
                    Frame::Landed => {}
                    other => panic!("a sender's frame from the receiver: {other:?}"),
                }
            }
            helds
        };
        let root = crate::walk::summary(kind, overlay);
        assert!(send(harness, Frame::Root { summary: root }).is_empty());
        let mut stack = vec![Vec::new()];
        while let Some(prefix) = stack.pop() {
            match crate::walk::node(kind, overlay, &prefix).expect("a pushed prefix is present") {
                PatchNode::Leaf { leaf, .. } => {
                    let key = <[u8; 32]>::try_from(leaf.key).unwrap();
                    if !omit.contains(&key) {
                        send(harness, Frame::Leaf { key });
                    }
                }
                node @ PatchNode::Branch { .. } => {
                    let helds = send(
                        harness,
                        Frame::Node {
                            prefix: prefix.clone(),
                            node: node.clone(),
                        },
                    );
                    let (_, children) = helds
                        .into_iter()
                        .find(|(answered, _)| *answered == prefix)
                        .expect("a pushed node is answered");
                    let PatchNode::Branch { branch, .. } = node else {
                        unreachable!()
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
        send(harness, Frame::Done);
        pushed
    }

    /// The sender's `kind` tree of C as a receiver holding nothing hears
    /// it: ROOT, then every node and leaf depth first, without DONE.
    fn tree(sender: &Node, collection: CollectionHandle, kind: WalkKind) -> Vec<Frame> {
        let overlay = sender.serving().collection(collection).unwrap();
        let overlay = overlay.repair();
        let mut frames = vec![Frame::Root {
            summary: crate::walk::summary(kind, overlay),
        }];
        let mut stack = vec![Vec::new()];
        while let Some(prefix) = stack.pop() {
            match crate::walk::node(kind, overlay, &prefix).unwrap() {
                PatchNode::Leaf { leaf, .. } => frames.push(Frame::Leaf {
                    key: leaf.key.try_into().unwrap(),
                }),
                node @ PatchNode::Branch { .. } => {
                    let PatchNode::Branch { branch, .. } = &node else {
                        unreachable!()
                    };
                    let end = usize::from(branch.end_depth);
                    for child in branch.children.iter().rev() {
                        let mut locator = branch.representative[..end].to_vec();
                        locator.push(child.edge);
                        stack.push(locator);
                    }
                    frames.push(Frame::Node { prefix, node });
                }
            }
        }
        frames
    }

    /// The value requests among a receiver's replies.
    fn requested(replies: Vec<Frame>) -> impl Iterator<Item = Frame> {
        replies
            .into_iter()
            .filter(|reply| matches!(reply, Frame::ValueRequest { .. }))
    }

    /// A tree the receiver takes as pushed, fabricated without a PATCH:
    /// `wide` branches under the root, each of `deep` leaves, every digest
    /// as the PATCH hashes it. The root and its NODE, then each branch's
    /// NODE with its LEAFs.
    fn fabricated(wide: usize, deep: usize) -> (PatchSummary, Frame, Vec<(Frame, Vec<Frame>)>) {
        use crate::patch_repair::{PatchBranch, PatchChild};
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

    fn leaves(frames: &[Frame]) -> BTreeSet<[u8; 32]> {
        frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Leaf { key } => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// A push of a tree the receiver already holds is held whole at its
    /// first node and ends with the sender's end; one of the confirmed tree,
    /// ROOT then DONE, is answered with LANDED alone, at a receiver whose
    /// tree equals it or that landed it before and holds more now. A push
    /// whose root the receiver's tree does not equal, and that it never
    /// landed, is not held at its first node, and ROOT then DONE fails its
    /// count proof there.
    #[test]
    fn an_equal_or_landed_root_is_held_whole_and_never_answered() {
        let mut sender = Node::new(30);
        let mut receiver = Node::new(31);
        let collection = sender.hold("equal", open());
        receiver.hold("equal", open());
        for data in 0..50 {
            let record = sender.commit(collection, data);
            receiver.store.insert(record).unwrap();
        }
        sender.observe();
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let pushed = push(
            &mut harness,
            &sender,
            collection,
            WalkKind::Records,
            &BTreeSet::new(),
        );
        assert!(matches!(
            &pushed[..],
            [Frame::Root { .. }, Frame::Node { .. }, Frame::Done]
        ));
        assert_eq!(
            harness.sent,
            [
                Frame::Held {
                    prefix: Vec::new(),
                    children: [0xFF; 32],
                },
                Frame::Landed,
            ]
        );
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));

        let root = crate::walk::summary(
            WalkKind::Records,
            sender.serving().collection(collection).unwrap().repair(),
        );
        let mut harness = Harness::new(harness.node, collection, WalkKind::Records);
        assert!(harness.feed(Frame::Root { summary: root }).is_empty());
        assert_eq!(harness.receive.root(), Some(root));
        assert_eq!(harness.feed(Frame::Done), [Frame::Landed]);
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));

        // The receiver holds more than it landed: the landed root still
        // satisfies the count proof.
        let mut superset = harness.node;
        superset.commit(collection, 100);
        superset.observe();
        let mut harness = Harness::landed(superset, collection, WalkKind::Records, Some(root));
        assert!(harness.feed(Frame::Root { summary: root }).is_empty());
        assert_eq!(harness.feed(Frame::Done), [Frame::Landed]);
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));

        // Without that memory a superset neither holds the root nor
        // accounts for it.
        let mut harness = Harness::new(harness.node, collection, WalkKind::Records);
        assert!(harness.feed(Frame::Root { summary: root }).is_empty());
        assert!(harness.feed(Frame::Done).is_empty());
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );

        let mut other = Node::new(32);
        other.hold("equal", open());
        other.commit(collection, 100);
        other.observe();
        let mut harness = Harness::new(other, collection, WalkKind::Records);
        assert!(harness.feed(Frame::Root { summary: root }).is_empty());
        let node = crate::walk::node(
            WalkKind::Records,
            sender.serving().collection(collection).unwrap().repair(),
            &[],
        )
        .unwrap();
        let [Frame::Held { prefix, children }] = &harness.feed(Frame::Node {
            prefix: Vec::new(),
            node,
        })[..] else {
            panic!("one HELD");
        };
        assert!(prefix.is_empty() && *children == [0; 32]);
    }

    /// Leaves the receiver lacks are asked for and land; it ends with the
    /// union and says so.
    #[test]
    fn missing_leaves_are_requested_and_land() {
        let mut sender = Node::new(33);
        let mut receiver = Node::new(34);
        let collection = sender.hold("missing", open());
        receiver.hold("missing", open());
        let records = (0..300)
            .map(|data| sender.commit(collection, data))
            .collect::<BTreeSet<_>>();
        for record in records.iter().take(100) {
            receiver.store.insert(*record).unwrap();
        }
        let foreign = receiver.commit(collection, 1000);
        sender.observe();
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        push(
            &mut harness,
            &sender,
            collection,
            WalkKind::Records,
            &BTreeSet::new(),
        );
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));
        assert_eq!(harness.sent.last(), Some(&Frame::Landed));
        let requested = harness.requested();
        assert_eq!(requested.len(), 200);
        assert!(
            records
                .iter()
                .skip(100)
                .all(|record| requested.contains(&record.fingerprint().raw()))
        );
        let mut union = records;
        union.insert(foreign);
        assert_eq!(harness.node.records(collection), union);
    }

    /// A subtree the receiver holds under the same digest is skipped: the
    /// sender never pushes its leaves, and the receiver never asks for them.
    #[test]
    fn a_held_subtree_is_pruned() {
        let mut sender = Node::new(35);
        let mut receiver = Node::new(36);
        let collection = sender.hold("pruned", open());
        receiver.hold("pruned", open());
        let records = (0..400)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        // The receiver holds every record under one top-level edge of the
        // sender's root, and nothing else.
        let overlay = sender.serving().collection(collection).unwrap();
        let Some(PatchNode::Branch { branch, .. }) =
            crate::walk::node(WalkKind::Records, overlay.repair(), &[])
        else {
            panic!("400 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        let edge = branch.children[0].edge;
        let shared = records
            .iter()
            .filter(|record| record.fingerprint().raw()[0] == edge)
            .copied()
            .collect::<BTreeSet<_>>();
        assert!(!shared.is_empty() && shared.len() < records.len());
        for record in &shared {
            receiver.store.insert(*record).unwrap();
        }
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let pushed = push(
            &mut harness,
            &sender,
            collection,
            WalkKind::Records,
            &BTreeSet::new(),
        );
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));
        let pushed_leaves = leaves(&pushed);
        let requested = harness.requested();
        for record in &shared {
            assert!(!pushed_leaves.contains(&record.fingerprint().raw()));
            assert!(!requested.contains(&record.fingerprint().raw()));
        }
        assert_eq!(pushed_leaves.len(), records.len() - shared.len());
        assert_eq!(requested, pushed_leaves);
        assert_eq!(
            harness.node.records(collection),
            records.into_iter().collect()
        );
    }

    /// A push that leaves out a leaf does not add up to its root's count, and
    /// fails at the end; what landed stays.
    #[test]
    fn the_count_proof_fails_on_a_push_that_omits_a_leaf() {
        let mut sender = Node::new(37);
        let mut receiver = Node::new(38);
        let collection = sender.hold("omitted", open());
        receiver.hold("omitted", open());
        let records = (0..60)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let omit = BTreeSet::from([records[7].fingerprint().raw()]);
        push(&mut harness, &sender, collection, WalkKind::Records, &omit);
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::CountMismatch))
        );
        assert!(!harness.sent.contains(&Frame::Landed));
        assert_eq!(harness.node.records(collection).len(), 59);
    }

    /// A value that fails to land, or does not decode, fails the push
    /// without a Landed; what landed stays.
    #[test]
    fn a_failed_insert_yields_no_landed() {
        let mut sender = Node::new(39);
        let mut receiver = Node::new(40);
        let collection = sender.hold("failed", open());
        receiver.hold("failed", open());
        for data in 0..20 {
            sender.commit(collection, data);
        }
        sender.observe();
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.hold = true;
        push(
            &mut harness,
            &sender,
            collection,
            WalkKind::Records,
            &BTreeSet::new(),
        );
        assert_eq!(harness.receive.outcome(), None);
        assert_eq!(harness.held.len(), 20);
        // One landing comes back failed.
        let failed = harness.held.pop().unwrap();
        harness.release();
        assert_eq!(harness.receive.outcome(), None, "a landing is still owed");
        let outs = harness.receive.on_landed_ack(0, failed.len() as u64);
        harness.outputs(outs);
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::InsertFailed))
        );
        assert!(!harness.sent.contains(&Frame::Landed));
        assert_eq!(harness.node.records(collection).len(), 19);

        // A value that is not a foundation record fails the push at once.
        let mut receiver = Node::new(41);
        receiver.hold("failed", open());
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let Some(Frame::ValueRequest { key }) = tree(&sender, collection, WalkKind::Records)
            .into_iter()
            .find_map(|frame| requested(harness.feed(frame)).next())
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
        harness.feed(Frame::Value {
            key,
            bytes: merge.to_bytes(),
        });
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::BadValue))
        );
        assert!(harness.node.records(collection).is_empty());
    }

    /// Values are asked for [`MAX_WALK_REQUESTS`] at a time, the leaves
    /// beyond that waiting until a value arrives, while the stream is read
    /// on; reading stops at [`MAX_WALK_UNLANDED`] values with the landing
    /// task, and resumes as they land.
    #[test]
    fn requests_are_windowed_and_reading_stops_at_unlanded_values() {
        let mut sender = Node::new(42);
        let mut receiver = Node::new(43);
        let collection = sender.hold("window", open());
        receiver.hold("window", open());
        let records = (0..MAX_WALK_UNLANDED as u64 + 100)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.hold = true;
        let mut requests = Vec::new();
        for frame in tree(&sender, collection, WalkKind::Records) {
            assert!(harness.receive.want_read(), "a value is owed");
            requests.extend(requested(harness.feed(frame)));
        }
        assert_eq!(requests.len(), MAX_WALK_REQUESTS);
        assert_eq!(
            harness.receive.wanted.len(),
            records.len() - MAX_WALK_REQUESTS
        );
        // Each value answered lets the next leaf be asked for, until the
        // landing task holds the most it may.
        let mut answered = 0;
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value(WalkKind::Records, overlay.repair(), key),
            };
            requests.extend(requested(harness.feed(value)));
            answered += 1;
            if !harness.receive.want_read() {
                break;
            }
        }
        assert_eq!(answered, MAX_WALK_UNLANDED);
        assert_eq!(harness.held.len(), MAX_WALK_UNLANDED);
        assert!(!harness.receive.want_read());
        assert_eq!(harness.receive.requests.len(), MAX_WALK_REQUESTS);
        harness.release();
        assert!(harness.receive.want_read());
        // The rest is answered, the push ends, and everything landed.
        while let Some(Frame::ValueRequest { key }) = requests.pop() {
            let value = Frame::Value {
                key,
                bytes: value(WalkKind::Records, overlay.repair(), key),
            };
            requests.extend(requested(harness.feed(value)));
        }
        harness.feed(Frame::Done);
        assert_eq!(harness.receive.outcome(), Some(Outcome::Landed));
        assert_eq!(
            harness.node.records(collection),
            records.into_iter().collect()
        );
    }

    /// A pushed node goes unanswered while [`MAX_WANTED`] leaves wait, and
    /// is answered once values arrive: the sender's window holds its push
    /// without the stream going unread.
    #[test]
    fn nodes_go_unanswered_while_too_many_leaves_wait() {
        let mut sender = Node::new(44);
        let mut receiver = Node::new(45);
        let collection = sender.hold("wanted", open());
        receiver.hold("wanted", open());
        // Two more than the window and the wanted bound together: a branch
        // of two is pushed last, after every other leaf.
        for data in 0..(MAX_WANTED + MAX_WALK_REQUESTS + 3) as u64 {
            sender.commit(collection, data);
        }
        sender.observe();
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let frames = tree(&sender, collection, WalkKind::Records);
        let late = frames
            .iter()
            .find_map(|frame| match frame {
                Frame::Node { prefix, node } if prefix.len() == 1 && node.leaf_count() == 2 => {
                    Some(prefix[0])
                }
                _ => None,
            })
            .expect("some branch byte holds exactly two records");
        let under = |frame: &Frame| match frame {
            Frame::Node { prefix, .. } => prefix.first() == Some(&late),
            Frame::Leaf { key } => key[0] == late,
            _ => false,
        };
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let mut requests = Vec::new();
        for frame in frames.iter().filter(|frame| !under(frame)) {
            requests.extend(requested(harness.feed(frame.clone())));
        }
        assert_eq!(harness.receive.wanted.len(), MAX_WANTED + 1);
        let node = frames
            .iter()
            .find(|frame| matches!(frame, Frame::Node { prefix, .. } if *prefix == [late]))
            .unwrap()
            .clone();
        let replies = harness.feed(node);
        assert!(replies.is_empty(), "{replies:?}");
        // One value lets one more leaf be asked for, which leaves exactly
        // MAX_WANTED waiting: still too many. The next one frees the reply.
        let answer = |harness: &mut Harness, requests: &mut Vec<Frame>| {
            let Some(Frame::ValueRequest { key }) = requests.pop() else {
                panic!("a value was requested");
            };
            harness.feed(Frame::Value {
                key,
                bytes: value(WalkKind::Records, overlay.repair(), key),
            })
        };
        let replies = answer(&mut harness, &mut requests);
        assert_eq!(harness.receive.wanted.len(), MAX_WANTED);
        assert!(
            !replies
                .iter()
                .any(|reply| matches!(reply, Frame::Held { .. })),
            "{replies:?}"
        );
        let replies = answer(&mut harness, &mut requests);
        assert!(replies.iter().any(|reply| matches!(
            reply,
            Frame::Held { prefix, children } if *prefix == [late] && *children == [0; 32]
        )));
    }

    /// Frames out of their place fail the push: a node before the root, and
    /// a value nobody asked for.
    #[test]
    fn frames_out_of_place_fail_the_push() {
        let mut sender = Node::new(46);
        let collection = sender.hold("order", open());
        sender.commit(collection, 1);
        sender.observe();
        let mut receiver = Node::new(47);
        receiver.hold("order", open());
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let node = crate::walk::node(WalkKind::Records, overlay.repair(), &[]).unwrap();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Node {
            prefix: Vec::new(),
            node,
        });
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::Protocol))
        );

        let mut receiver = Node::new(48);
        receiver.hold("order", open());
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root {
            summary: crate::walk::summary(WalkKind::Records, overlay.repair()),
        });
        harness.feed(Frame::Value {
            key: [1; 32],
            bytes: vec![0],
        });
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::Protocol))
        );
        assert!(Receive::on_open([0; 32], collection, WalkKind::Records, false, None).is_none());
    }

    /// A proof over another resource routed to C waits for that resource's
    /// descriptor, fetched from the sender. A push whose fetch of it fails
    /// does not land; the next push lands the proof with the descriptor.
    #[test]
    fn a_deferred_proof_fails_the_push_until_its_descriptor_arrives() {
        use triblespace_core::blob::Blob;
        use triblespace_core::blob::encodings::UnknownBlob;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::{resource_collection, resource_policy};
        use triblespace_core::capability::{CapabilityProof, CapabilityResource};
        use triblespace_core::collection::AdmissionPolicy;
        use triblespace_core::macros::entity;
        use triblespace_core::repo::{
            BlobStoreGet, BlobStorePut, CapabilityProofStore, SnapshotSource,
        };

        use crate::walk::tests::walking::key;

        let mut sender = Node::new(49);
        let mut receiver = Node::new(50);
        let collection = sender.hold("deferred", open());
        receiver.hold("deferred", open());
        let resource_root = key(51);
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
            node.serving()
                .collection(collection)
                .unwrap()
                .repair()
                .authorization_evidence()
                .get(proof.id())
                .cloned()
        };
        assert_eq!(evidence(&sender), Some(proof.clone()));

        for attempt in 0..2 {
            let mut harness = Harness::new(receiver, collection, WalkKind::Authorization);
            push(
                &mut harness,
                &sender,
                collection,
                WalkKind::Authorization,
                &BTreeSet::new(),
            );
            assert_eq!(harness.receive.outcome(), None, "a fetch is owed");
            let (descriptor, fetched) = harness.fetches.pop().unwrap();
            assert_eq!((fetched, descriptor), (Some(proof.clone()), resource.raw));
            // The first fetch fails; the second gets the descriptor.
            let blob = (attempt == 1).then(|| {
                BlobStoreGet::get::<Blob<UnknownBlob>, UnknownBlob>(
                    &sender.store.snapshot().unwrap(),
                    triblespace_core::inline::Inline::new(resource.raw),
                )
                .unwrap()
            });
            let outs = harness
                .receive
                .on_fetched(resource.raw, Some(proof.clone()), blob);
            harness.outputs(outs);
            let expected = if attempt == 0 {
                Outcome::Failed(Failure::DeferredProof)
            } else {
                Outcome::Landed
            };
            assert_eq!(harness.receive.outcome(), Some(expected));
            assert_eq!(evidence(&harness.node).is_some(), attempt == 1);
            receiver = harness.node;
        }
    }

    /// A count proof closed by repeating a leaf is no proof: each leaf is
    /// expected once, at the locator its parent declared. Sixty records,
    /// the receiver holding one whose branch byte is its own: the genuine
    /// root NODE, that record's LEAF fifty-nine times and DONE fails the
    /// push instead of landing it, and so does ROOT, sixty LEAFs and DONE
    /// with no NODE to expect them under.
    #[test]
    fn a_duplicated_or_foreign_leaf_does_not_close_the_count_proof() {
        let mut sender = Node::new(52);
        let mut receiver = Node::new(53);
        let collection = sender.hold("duplicated", open());
        receiver.hold("duplicated", open());
        let records = (0..60)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
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
        receiver.store.insert(alone).unwrap();
        sender.observe();
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, overlay.repair());
        let node = crate::walk::node(WalkKind::Records, overlay.repair(), &[]).unwrap();
        let held = alone.fingerprint().raw();

        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        harness.feed(Frame::Node {
            prefix: Vec::new(),
            node,
        });
        for _ in 1..60 {
            harness.feed(Frame::Leaf { key: held });
        }
        harness.feed(Frame::Done);
        assert!(
            matches!(harness.receive.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            harness.receive.outcome()
        );
        assert!(!harness.sent.contains(&Frame::Landed));
        assert!(harness.requested().is_empty());

        // Without a NODE, no leaf is expected at all.
        let mut harness = Harness::new(harness.node, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        for record in &records {
            harness.feed(Frame::Leaf {
                key: record.fingerprint().raw(),
            });
        }
        harness.feed(Frame::Done);
        assert!(
            matches!(harness.receive.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            harness.receive.outcome()
        );
        assert!(!harness.sent.contains(&Frame::Landed));
    }

    /// A NODE at a locator its parent declared, canonical in itself but not
    /// the node the parent's child entry names, fails the push and gets no
    /// HELD: a node is checked against the digest its parent declared, so
    /// every node hash-chains to the root.
    #[test]
    fn a_node_whose_digest_is_not_the_parent_s_child_digest_fails_the_push() {
        let mut sender = Node::new(54);
        let mut other = Node::new(55);
        let mut receiver = Node::new(56);
        let collection = sender.hold("chained", open());
        other.hold("chained", open());
        receiver.hold("chained", open());
        for data in 0..400 {
            sender.commit(collection, data);
            other.commit(collection, 400 + data);
        }
        sender.observe();
        other.observe();
        receiver.observe();
        let pinned = sender.serving().collection(collection).unwrap();
        let foreign = other.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, pinned.repair());
        let root_node = crate::walk::node(WalkKind::Records, pinned.repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_node else {
            panic!("400 records branch at the root");
        };
        assert_eq!(branch.end_depth, 0);
        // A branch byte under which both trees branch.
        let (edge, foreign_node) = branch
            .children
            .iter()
            .find_map(|child| {
                let node = crate::walk::node(WalkKind::Records, foreign.repair(), &[child.edge])?;
                matches!(node, PatchNode::Branch { .. }).then_some((child.edge, node))
            })
            .expect("400 records each: some first byte branches in both");

        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        let replies = harness.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node.clone(),
        });
        assert!(matches!(&replies[..], [Frame::Held { .. }]), "{replies:?}");
        let replies = harness.feed(Frame::Node {
            prefix: vec![edge],
            node: foreign_node,
        });
        assert!(replies.is_empty(), "{replies:?}");
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::BadNode))
        );
    }

    /// A LEAF under no locator the sender owes, a key the pushed tree does
    /// not hold, fails the push at once: nothing is asked for, and nothing
    /// is remembered as landed from it.
    #[test]
    fn a_leaf_outside_the_pushed_tree_fails_the_push() {
        let mut sender = Node::new(57);
        let mut receiver = Node::new(58);
        let collection = sender.hold("outside", open());
        receiver.hold("outside", open());
        for data in 0..60 {
            sender.commit(collection, data);
        }
        sender.observe();
        receiver.observe();
        let pinned = sender.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, pinned.repair());
        let root_node = crate::walk::node(WalkKind::Records, pinned.repair(), &[]).unwrap();
        let PatchNode::Branch { branch, .. } = &root_node else {
            panic!("60 records branch at the root");
        };
        // A key under a branch byte the tree does not use.
        let edge = (0..=255u8)
            .find(|edge| branch.children.iter().all(|child| child.edge != *edge))
            .unwrap();
        let mut key = [7; 32];
        key[0] = edge;

        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        harness.feed(Frame::Node {
            prefix: Vec::new(),
            node: root_node.clone(),
        });
        let replies = harness.feed(Frame::Leaf { key });
        assert!(replies.is_empty(), "{replies:?}");
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::Protocol))
        );
        assert!(harness.requested().is_empty());
        assert!(!harness.sent.contains(&Frame::Landed));
        // Reported as it ended, the walks remember no landed root from it.
        let now = crate::clock::mono_now();
        let root = harness.receive.root();
        let mut node = harness.node;
        node.walks
            .received(sender.id(), collection, WalkKind::Records, root, false, now);
        let health = node.health.snapshot();
        assert_eq!(health.collections[0].peers[0].received.records, None);
    }

    /// A sender that pushes leaves and withholds their values makes the
    /// receiver queue what it wants to ask for. The stream stays read, since
    /// only reading brings the values owed, and the queue fails the push
    /// once it holds more than a window of answered nodes could have pushed:
    /// a flood. A sixty-first leaf against a root of sixty fails at once,
    /// before DONE.
    #[test]
    fn a_leaf_flood_with_withheld_values_fails_the_push_and_an_overcount_fails_at_once() {
        let mut receiver = Node::new(59);
        let collection = receiver.hold("flood", open());
        receiver.observe();
        let (root, root_node, branches) = fabricated(256, FLOOD_WANTED / 256 + 2);
        assert!(root.leaf_count() as usize > FLOOD_WANTED + MAX_WALK_REQUESTS);
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        assert!(matches!(&harness.feed(root_node)[..], [Frame::Held { .. }]));
        let mut fed = 0;
        'flood: for (node, leaves) in branches {
            harness.feed(node);
            for leaf in leaves {
                assert!(harness.receive.want_read(), "values are owed");
                harness.feed(leaf);
                fed += 1;
                if harness.receive.outcome().is_some() {
                    break 'flood;
                }
            }
        }
        assert_eq!(
            harness.receive.outcome(),
            Some(Outcome::Failed(Failure::Protocol))
        );
        assert_eq!(harness.receive.wanted.len(), FLOOD_WANTED);
        assert_eq!(fed, FLOOD_WANTED + MAX_WALK_REQUESTS + 1);
        assert_eq!(harness.requested().len(), MAX_WALK_REQUESTS);

        // A sixty-first leaf against a root of sixty fails at once.
        let mut sender = Node::new(60);
        let collection = sender.hold("overcount", open());
        let mut receiver = Node::new(61);
        receiver.hold("overcount", open());
        for data in 0..60 {
            sender.commit(collection, data);
        }
        sender.observe();
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let frames = tree(&sender, collection, WalkKind::Records);
        let again = frames
            .iter()
            .find(|frame| matches!(frame, Frame::Leaf { .. }))
            .unwrap()
            .clone();
        for frame in frames {
            harness.feed(frame);
        }
        assert_eq!(harness.receive.outcome(), None);
        harness.feed(again);
        assert!(
            matches!(harness.receive.outcome(), Some(Outcome::Failed(_))),
            "{:?}",
            harness.receive.outcome()
        );
        assert!(!harness.sent.contains(&Frame::Landed));
    }
}
