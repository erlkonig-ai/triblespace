//! The receiving side of a walk stream.
//!
//! A [`Receive`] takes what one sender pushes on one `walk/1` stream
//! ([`crate::walk_stream`]) of one collection and kind and decides, frame by
//! frame, what to send back and what to land; it does no I/O of its own, and
//! [`crate::walk`] drives it. The pushed root is compared with the live tree:
//! an equal root is answered with everything held, and the push ends there.
//! Every pushed node is answered with the children the live tree holds under
//! the same digest, whose subtrees the sender then skips; every pushed leaf
//! whose value the live store lacks is asked for and lands as it arrives. A
//! held reference carries no value: one resident here is noted held as it
//! is, another is fetched by hash.
//!
//! The push ends in one of two ways. It lands when its count proof closes
//! (the leaves pushed plus the leaves of every skipped subtree are exactly
//! the root's count), every value asked for landed without a failed insert,
//! no fetch failed and no proof stayed deferred: [`Frame::Landed`] goes back,
//! and the sender confirms its root. Anything else fails it, and what landed
//! stays.
//!
//! Three bounds keep what a push costs here. Values are asked for
//! [`MAX_WALK_REQUESTS`] at a time, and the leaves beyond that wait their
//! turn. Nodes are answered only while fewer than [`MAX_WANTED`] leaves wait,
//! so the sender's window of unanswered nodes holds its push. And
//! [`Receive::want_read`] is false while [`MAX_WALK_UNLANDED`] values are
//! with the landing task, so the driver stops reading and QUIC flow control
//! holds the sender. The stream is read on while a value is owed to it: only
//! reading brings the value, so stopping for owed values would wait forever.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::CollectionHandle;

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
    /// second root, a value nobody asked for, a frame after the end, or one
    /// only a receiver sends.
    Protocol,
    /// A pushed node is not canonical, or the root node does not match the
    /// pushed root.
    BadNode,
    /// A value that does not decode, is not under its key, or is not
    /// evidence for the collection.
    BadValue,
    /// The leaves pushed and skipped do not add up to the root's count.
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
    /// The pushed root equals the live tree: everything is held.
    equal: bool,
    /// Leaves pushed, and the leaves of the subtrees skipped as held.
    accounted: u64,
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
    /// (`None`), and the driver resets the stream.
    pub(crate) fn on_open(
        _peer: PeerId,
        collection: CollectionHandle,
        kind: WalkKind,
        admitted: bool,
    ) -> Option<Self> {
        admitted.then(|| Self {
            collection,
            kind,
            snapshot: None,
            root: None,
            equal: false,
            accounted: 0,
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
    /// [`MAX_WALK_UNLANDED`] values are with the landing task, and not once
    /// the push ended.
    pub(crate) fn want_read(&self) -> bool {
        self.outcome.is_none() && self.unlanded < MAX_WALK_UNLANDED
    }

    pub(crate) fn outcome(&self) -> Option<Outcome> {
        self.outcome
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
                if summary == crate::walk::summary(self.kind, overlay) {
                    self.equal = true;
                    self.accounted = summary.leaf_count();
                    self.held.push_back(Frame::Held {
                        prefix: Vec::new(),
                        children: [0xFF; 32],
                    });
                }
            }
            Frame::Node { prefix, node } => {
                let root = self.pushing()?;
                if self.equal {
                    // Held whole at the root; the sender may have pushed on
                    // before it read that.
                    self.held.push_back(Frame::Held {
                        prefix,
                        children: [0xFF; 32],
                    });
                    return Ok(());
                }
                let base = crate::walk::base(self.kind, self.collection);
                let request =
                    PatchRepairRequest::new((), root, KEY_BYTES, prefix.clone(), node.digest())
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
                        // elsewhere and still hold the child whole.
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
                            }
                        }
                    }
                }
                self.held.push_back(Frame::Held { prefix, children });
            }
            Frame::Leaf { key } => {
                self.pushing()?;
                if !self.equal {
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
                if self.accounted != root.leaf_count() {
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
    /// it.
    fn leaf(&mut self, key: [u8; KEY_BYTES], live: &CollectionSnapshot) -> Result<(), Failure> {
        self.accounted = self
            .accounted
            .checked_add(1)
            .ok_or(Failure::CountMismatch)?;
        if !crate::walk::contains(self.kind, live.repair(), &key) {
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
            Self {
                receive: Receive::on_open([0; 32], collection, kind, true).unwrap(),
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
        let helds = send(harness, Frame::Root { summary: root });
        if helds
            .iter()
            .any(|(prefix, children)| prefix.is_empty() && *children == [0xFF; 32])
        {
            send(harness, Frame::Done);
            return pushed;
        }
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

    fn leaves(frames: &[Frame]) -> BTreeSet<[u8; 32]> {
        frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Leaf { key } => Some(*key),
                _ => None,
            })
            .collect()
    }

    /// A push of a tree the receiver already holds is answered at the root
    /// and ends with the sender's end: two frames each way.
    #[test]
    fn an_equal_root_ends_in_one_exchange() {
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
        assert!(matches!(&pushed[..], [Frame::Root { .. }, Frame::Done]));
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
    }

    /// Leaves the receiver lacks are asked for and land; it ends with the
    /// union and says so.
    #[test]
    fn missing_leaves_are_requested_and_land() {
        let mut sender = Node::new(32);
        let mut receiver = Node::new(33);
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
        let mut sender = Node::new(34);
        let mut receiver = Node::new(35);
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
        let mut sender = Node::new(36);
        let mut receiver = Node::new(37);
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
        let mut sender = Node::new(38);
        let mut receiver = Node::new(39);
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
        let mut receiver = Node::new(40);
        receiver.hold("failed", open());
        receiver.observe();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        let overlay = sender.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, overlay.repair());
        harness.feed(Frame::Root { summary: root });
        let key = [1; 32];
        let requests = harness.feed(Frame::Leaf { key });
        assert_eq!(requests, [Frame::ValueRequest { key }]);
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
        let mut sender = Node::new(41);
        let mut receiver = Node::new(42);
        let collection = sender.hold("window", open());
        receiver.hold("window", open());
        let records = (0..MAX_WALK_UNLANDED as u64 + 100)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, overlay.repair());
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.hold = true;
        harness.feed(Frame::Root { summary: root });
        let mut requests = Vec::new();
        for record in &records {
            assert!(harness.receive.want_read(), "a value is owed");
            requests.extend(harness.feed(Frame::Leaf {
                key: record.fingerprint().raw(),
            }));
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
            requests.extend(harness.feed(value));
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
            requests.extend(harness.feed(value));
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
        let mut sender = Node::new(43);
        let mut receiver = Node::new(44);
        let collection = sender.hold("wanted", open());
        receiver.hold("wanted", open());
        let records = (0..MAX_WANTED as u64 + MAX_WALK_REQUESTS as u64 + 1)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        receiver.observe();
        let overlay = sender.serving().collection(collection).unwrap();
        let root = crate::walk::summary(WalkKind::Records, overlay.repair());
        let node = crate::walk::node(WalkKind::Records, overlay.repair(), &[]).unwrap();
        let mut harness = Harness::new(receiver, collection, WalkKind::Records);
        harness.feed(Frame::Root { summary: root });
        let mut requests = Vec::new();
        for record in &records {
            requests.extend(harness.feed(Frame::Leaf {
                key: record.fingerprint().raw(),
            }));
        }
        assert_eq!(harness.receive.wanted.len(), MAX_WANTED + 1);
        let replies = harness.feed(Frame::Node {
            prefix: Vec::new(),
            node,
        });
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
            Frame::Held { prefix, children } if prefix.is_empty() && *children == [0; 32]
        )));
    }

    /// Frames out of their place fail the push: a node before the root, and
    /// a value nobody asked for.
    #[test]
    fn frames_out_of_place_fail_the_push() {
        let mut sender = Node::new(45);
        let collection = sender.hold("order", open());
        sender.commit(collection, 1);
        sender.observe();
        let mut receiver = Node::new(46);
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

        let mut receiver = Node::new(47);
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
        assert!(!Receive::on_open([0; 32], collection, WalkKind::Records, false).is_some());
    }
}
