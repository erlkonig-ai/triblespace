//! The sender of a `walk/1` push (design: walk streams).
//!
//! A push sends one neighbour the part of one collection tree it does not
//! hold, as its own stream ([`crate::walk_stream`]). The sender pins a
//! snapshot and sends its root. A root the neighbour confirmed before is
//! followed by DONE at once. Otherwise the sender walks the pinned tree depth
//! first: every branch it reaches goes out as a NODE, and the neighbour
//! answers each with the children it already holds with the same digest,
//! which the sender skips; what the neighbour holds as more than the pushed
//! subtree is walked on, so the count proof closes at a neighbour that holds
//! a superset. A ROOT is never answered: a neighbour whose own tree equals
//! it, or that landed it before, answers the root NODE with every child held,
//! and nothing below it is owed. A leaf goes out as a LEAF, and the neighbour
//! asks for the values it lacks. At most [`MAX_OUTSTANDING_NODES`] NODEs
//! wait for their HELD, and the walk pauses while that window is full. DONE
//! follows the last answered NODE, and once the neighbour's LANDED arrives
//! the pinned root is its confirmed root, so an unchanged tree is one
//! exchange next time. A push that ends before LANDED leaves the confirmed
//! root as it was, and one to a neighbour never pushed to starts from none,
//! so the first push and a later one are one path.
//!
//! [`Push`] is the state machine without its stream, which the walks task
//! drives ([`crate::walk`]). [`Push::start`] and [`Push::on_frame`] yield
//! the frames to write, after the stream's tag and Open; an `Err` from
//! `on_frame` resets the stream
//! [`RESET_WALK_FAILED`](crate::connection::RESET_WALK_FAILED); and once the
//! stream ended, however it ended, [`Push::outcome`] settles the
//! [`ConfirmedRoots`] the walks task keeps
//! ([`crate::walk::Walks::pushed`]).

use std::collections::HashMap;
use std::sync::Arc;

use crate::host::CollectionSnapshot;
use crate::patch_repair::{PatchNode, PatchSummary};
use crate::protocol::RawHash;
use crate::transport::PeerId;
use crate::walk::{WalkKind, node, summary, value};
use crate::walk_stream::{Frame, held};

/// NODE frames one push keeps outstanding: sent, with no HELD yet.
pub(crate) const MAX_OUTSTANDING_NODES: usize = 64;

/// One push, as the walks task and the confirmed roots name it: its peer,
/// collection and kind.
pub(crate) type PushKey = (PeerId, RawHash, WalkKind);

/// How a push ended: the root it pushed, and whether LANDED arrived, which
/// makes that root the neighbour's confirmed root. A stream that ended
/// before LANDED leaves the confirmed root unchanged.
pub(crate) struct Outcome {
    pub(crate) root: PatchSummary,
    pub(crate) confirmed: bool,
}

/// The receiver broke the protocol; its stream is reset
/// [`RESET_WALK_FAILED`](crate::connection::RESET_WALK_FAILED).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Failed(pub(crate) &'static str);

/// The confirmed roots of this side's pushes: per peer, collection and kind,
/// the root of the last push the peer confirmed landed. Never persisted: a
/// restarted side pushes everything again, and the neighbour holds it.
#[derive(Default)]
pub(crate) struct ConfirmedRoots(HashMap<PushKey, PatchSummary>);

impl ConfirmedRoots {
    pub(crate) fn root(&self, key: PushKey) -> Option<PatchSummary> {
        self.0.get(&key).copied()
    }

    /// A push under `key` ended: a confirmed one sets the root, a failed one
    /// forgets it. Keeping it would make an unchanged tree repeat a push the
    /// peer cannot land (a peer that restarted holds no landed roots, so a
    /// Root-then-Done push to it fails its count proof) until this side's
    /// tree moved; forgetting costs the next push one root NODE, which the
    /// peer's HELD prunes.
    pub(crate) fn settle(&mut self, key: PushKey, outcome: Outcome) {
        if outcome.confirmed {
            self.0.insert(key, outcome.root);
        } else {
            self.0.remove(&key);
        }
    }
}

/// The sender of one push.
pub(crate) struct Push {
    kind: WalkKind,
    pinned: Arc<CollectionSnapshot>,
    /// Prefixes to visit, the last first: the walk is depth first.
    pending: Vec<Vec<u8>>,
    /// NODEs sent without a HELD, by prefix: their children, each its edge
    /// and prefix.
    outstanding: HashMap<Vec<u8>, Vec<(u8, Vec<u8>)>>,
    done: bool,
    landed: bool,
}

impl Push {
    /// Start a push of the `kind` tree of `pinned` to a neighbour whose
    /// confirmed root is `confirmed`: the push and its first frames, ROOT
    /// first.
    pub(crate) fn start(
        kind: WalkKind,
        pinned: Arc<CollectionSnapshot>,
        confirmed: Option<PatchSummary>,
    ) -> (Self, Vec<Frame>) {
        let root = summary(kind, pinned.repair());
        let mut push = Self {
            kind,
            pinned,
            pending: Vec::new(),
            outstanding: HashMap::new(),
            done: false,
            landed: false,
        };
        if root.root().is_some() && confirmed != Some(root) {
            push.pending.push(Vec::new());
        }
        let mut frames = vec![Frame::Root { summary: root }];
        push.pump(&mut frames);
        (push, frames)
    }

    /// Take one frame from the receiver; the frames to send in answer.
    pub(crate) fn on_frame(&mut self, frame: Frame) -> Result<Vec<Frame>, Failed> {
        if self.landed {
            return Err(Failed("a frame after LANDED"));
        }
        let mut frames = Vec::new();
        match frame {
            Frame::Held { prefix, children } => {
                let Some(unheld) = self.outstanding.remove(&prefix) else {
                    return Err(Failed("a HELD for no outstanding NODE"));
                };
                // Pushed in reverse, so the walk takes ascending edges
                // first.
                for (edge, child) in unheld.into_iter().rev() {
                    if !held(&children, edge) {
                        self.pending.push(child);
                    }
                }
                self.pump(&mut frames);
            }
            Frame::ValueRequest { key } => match value(self.kind, self.pinned.repair(), key) {
                Some(bytes) => frames.push(Frame::Value { key, bytes }),
                None => return Err(Failed("a VALUE_REQUEST for a key the pinned tree lacks")),
            },
            Frame::Landed => {
                if !self.done {
                    return Err(Failed("a LANDED before DONE"));
                }
                self.landed = true;
            }
            Frame::Open { .. }
            | Frame::Root { .. }
            | Frame::Node { .. }
            | Frame::Leaf { .. }
            | Frame::Value { .. }
            | Frame::Done => return Err(Failed("a sender's frame from the receiver")),
        }
        Ok(frames)
    }

    /// The push's outcome once its stream ended, however it ended.
    pub(crate) fn outcome(self) -> Outcome {
        Outcome {
            root: summary(self.kind, self.pinned.repair()),
            confirmed: self.landed,
        }
    }

    /// Visit pending prefixes while the window has room, then send DONE if
    /// the walk is over.
    fn pump(&mut self, frames: &mut Vec<Frame>) {
        while self.outstanding.len() < MAX_OUTSTANDING_NODES {
            let Some(prefix) = self.pending.pop() else {
                break;
            };
            self.visit(prefix, frames);
        }
        if !self.done && self.pending.is_empty() && self.outstanding.is_empty() {
            self.done = true;
            frames.push(Frame::Done);
        }
    }

    /// Send the pinned node at `prefix`: a leaf as a LEAF, a branch as a
    /// NODE whose children wait for its HELD.
    fn visit(&mut self, prefix: Vec<u8>, frames: &mut Vec<Frame>) {
        let visited = node(self.kind, self.pinned.repair(), &prefix)
            .expect("a pinned tree holds the nodes its own branches name");
        let PatchNode::Branch { ref branch, .. } = visited else {
            let PatchNode::Leaf { leaf, .. } = visited else {
                unreachable!()
            };
            let key = leaf.key.try_into().expect("a walked key is 32 bytes");
            return frames.push(Frame::Leaf { key });
        };
        let children = branch
            .children
            .iter()
            .map(|child| {
                let mut prefix = branch.representative[..usize::from(branch.end_depth)].to_vec();
                prefix.push(child.edge);
                (child.edge, prefix)
            })
            .collect();
        self.outstanding.insert(prefix.clone(), children);
        frames.push(Frame::Node {
            prefix,
            node: visited,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    use triblespace_core::collection::{
        AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
        CollectionRecord, CollectionStore, empty_metadata_handle,
    };
    use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH};

    use crate::collection_delta::decode_record;
    use crate::health::PeeringHealth;
    use crate::walk::tests::walking::{Node, open};
    use crate::walk_stream::hold;

    /// A scripted receiver: it holds `local`, answers every NODE with the
    /// children it holds with the same digest, asks for every leaf's value
    /// it lacks, and sends LANDED once DONE and every value it asked for
    /// arrived. Every frame crosses the codec.
    struct Receiver {
        kind: WalkKind,
        local: Option<Arc<CollectionSnapshot>>,
        /// Every frame the sender sent, in order.
        heard: Vec<Frame>,
        wanted: BTreeSet<[u8; 32]>,
        values: BTreeMap<[u8; 32], Vec<u8>>,
        done: bool,
        lands: bool,
        landed: bool,
        /// NODEs not answered, when the test answers them itself.
        unanswered: VecDeque<Vec<u8>>,
        holds_answers: bool,
    }

    impl Receiver {
        fn new(kind: WalkKind, local: Option<Arc<CollectionSnapshot>>) -> Self {
            Self {
                kind,
                local,
                heard: Vec::new(),
                wanted: BTreeSet::new(),
                values: BTreeMap::new(),
                done: false,
                lands: true,
                landed: false,
                unanswered: VecDeque::new(),
                holds_answers: false,
            }
        }

        /// Whether the local tree has a node at `prefix` with `digest`, or
        /// with `None`, any node there: a full key's leaf.
        fn holds(&self, prefix: &[u8], digest: Option<[u8; 32]>) -> bool {
            self.local
                .as_deref()
                .and_then(|local| node(self.kind, local.repair(), prefix))
                .is_some_and(|node| digest.is_none_or(|digest| node.digest() == digest))
        }

        fn hear(&mut self, frame: Frame) -> Vec<Frame> {
            self.heard.push(frame.clone());
            let mut replies = Vec::new();
            match frame {
                Frame::Node { prefix, node } => {
                    if self.holds_answers {
                        self.unanswered.push_back(prefix);
                    } else {
                        replies.push(self.answer(prefix, &node));
                    }
                }
                Frame::Leaf { key } => {
                    if !self.holds(&key, None) {
                        self.wanted.insert(key);
                        replies.push(Frame::ValueRequest { key });
                    }
                }
                Frame::Value { key, bytes } => {
                    assert!(self.wanted.remove(&key), "a value nobody asked for");
                    self.values.insert(key, bytes);
                }
                Frame::Done => self.done = true,
                Frame::Root { .. } => {}
                other => panic!("a receiver's frame from the sender: {other:?}"),
            }
            if self.done && self.wanted.is_empty() && self.lands && !self.landed {
                self.landed = true;
                replies.push(Frame::Landed);
            }
            replies
        }

        /// The HELD for a NODE: the children held with the same digest.
        fn answer(&self, prefix: Vec<u8>, node: &PatchNode<()>) -> Frame {
            let mut children = [0; 32];
            if let PatchNode::Branch { branch, .. } = node {
                for child in &branch.children {
                    let mut prefix =
                        branch.representative[..usize::from(branch.end_depth)].to_vec();
                    prefix.push(child.edge);
                    if self.holds(&prefix, Some(child.digest)) {
                        hold(&mut children, child.edge);
                    }
                }
            }
            Frame::Held { prefix, children }
        }

        fn nodes(&self) -> Vec<Vec<u8>> {
            self.heard
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Node { prefix, .. } => Some(prefix.clone()),
                    _ => None,
                })
                .collect()
        }

        fn leaves(&self) -> Vec<[u8; 32]> {
            self.heard
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Leaf { key } => Some(*key),
                    _ => None,
                })
                .collect()
        }

        fn count(&self, same: impl Fn(&Frame) -> bool) -> usize {
            self.heard.iter().filter(|frame| same(frame)).count()
        }
    }

    fn roundtrip(frame: Frame) -> Frame {
        let (kind, payload) = frame.encode();
        Frame::decode(kind, &payload).unwrap().unwrap()
    }

    /// Carry frames both ways until neither side sends.
    fn carry(push: &mut Push, receiver: &mut Receiver, frames: Vec<Frame>) -> Result<(), Failed> {
        let mut queue = VecDeque::from(frames);
        while let Some(frame) = queue.pop_front() {
            for reply in receiver.hear(roundtrip(frame)) {
                queue.extend(push.on_frame(roundtrip(reply))?);
            }
        }
        Ok(())
    }

    fn snapshot(node: &Node, collection: CollectionHandle) -> Arc<CollectionSnapshot> {
        node.serving().collection(collection).unwrap()
    }

    fn fingerprints(records: impl IntoIterator<Item = CollectionRecord>) -> BTreeSet<[u8; 32]> {
        records
            .into_iter()
            .map(|record| record.fingerprint().raw())
            .collect()
    }

    /// Every branch prefix of a records tree, by the PATCH's own view.
    fn branches(
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

    #[test]
    fn a_push_against_no_confirmed_root_carries_the_whole_tree() {
        let mut sender = Node::new(30);
        let collection = sender.hold("whole", open());
        let records = (0..300)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        let pinned = snapshot(&sender, collection);
        let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), None);
        let mut receiver = Receiver::new(WalkKind::Records, None);
        carry(&mut push, &mut receiver, frames).unwrap();

        assert_eq!(
            receiver.heard[0],
            Frame::Root {
                summary: pinned.repair().records().summary()
            }
        );
        let mut expected = Vec::new();
        branches(pinned.repair().records().patch(), Vec::new(), &mut expected);
        let nodes = receiver.nodes();
        assert!(expected.len() > 1);
        assert_eq!(nodes.len(), expected.len());
        assert_eq!(
            nodes.iter().collect::<BTreeSet<_>>(),
            expected.iter().collect::<BTreeSet<_>>()
        );
        let leaves = receiver.leaves();
        assert_eq!(leaves.len(), records.len());
        assert_eq!(
            leaves.iter().copied().collect::<BTreeSet<_>>(),
            fingerprints(records.iter().copied())
        );
        assert_eq!(
            receiver.values.keys().copied().collect::<BTreeSet<_>>(),
            fingerprints(records.iter().copied())
        );
        for (key, bytes) in &receiver.values {
            let record = decode_record(collection, bytes).unwrap();
            assert_eq!(record.fingerprint().raw(), *key);
        }
        assert_eq!(receiver.count(|frame| *frame == Frame::Done), 1);
        let outcome = push.outcome();
        assert!(outcome.confirmed, "LANDED arrived");
        assert_eq!(outcome.root, pinned.repair().records().summary());
    }

    #[test]
    fn a_push_of_the_confirmed_tree_is_root_then_done() {
        let mut sender = Node::new(31);
        let collection = sender.hold("same", open());
        for data in 0..50 {
            sender.commit(collection, data);
        }
        sender.observe();
        let pinned = snapshot(&sender, collection);
        let summary = pinned.repair().records().summary();
        let root = Frame::Root { summary };
        let (_, frames) = Push::start(WalkKind::Records, pinned.clone(), Some(summary));
        assert_eq!(frames, [root.clone(), Frame::Done]);
        // Any other confirmed root walks the tree, from its root node.
        let other = PatchSummary::new(Some([9; 32]), 50).unwrap();
        let (_, frames) = Push::start(WalkKind::Records, pinned, Some(other));
        assert!(
            matches!(frames[..], [Frame::Root { .. }, Frame::Node { .. }]),
            "{frames:?}"
        );
        // An empty tree is root then done too, confirmed or not.
        let mut empty = Node::new(32);
        let collection = empty.hold("empty", open());
        let pinned = snapshot(&empty, collection);
        let (_, frames) = Push::start(WalkKind::Authorization, pinned, None);
        assert_eq!(
            frames,
            [
                Frame::Root {
                    summary: crate::patch_repair::PatchSummary::new(None, 0).unwrap()
                },
                Frame::Done
            ]
        );
    }

    /// A sender with twenty records, one more chosen by `wanted` from its
    /// first byte's company among them: the snapshots before and after, and
    /// the new record's key.
    fn one_more(
        byte: u8,
        wanted: impl Fn(Option<&usize>) -> bool,
    ) -> (Node, CollectionHandle, Arc<CollectionSnapshot>, [u8; 32]) {
        let mut sender = Node::new(byte);
        let collection = sender.hold("path", open());
        let mut company = BTreeMap::new();
        for data in 0..20 {
            let key = sender.commit(collection, data).fingerprint().raw();
            *company.entry(key[0]).or_insert(0) += 1;
        }
        sender.observe();
        let before = snapshot(&sender, collection);
        let record = (100..)
            .map(|data: u64| {
                CollectionRecord::Commit(CollectionCommit::sign(
                    &sender.key,
                    collection,
                    CollectionData::new(*blake3::hash(&data.to_be_bytes()).as_bytes()),
                    empty_metadata_handle(),
                ))
            })
            .find(|record| wanted(company.get(&record.fingerprint().raw()[0])))
            .unwrap();
        sender.store.insert(record).unwrap();
        sender.observe();
        (sender, collection, before, record.fingerprint().raw())
    }

    /// The receiver holds the tree as it was before one record: its HELD
    /// prunes the walk to the new record's path, whether or not the sender
    /// has a confirmed root. A receiver holding nothing is pushed the whole
    /// tree even under a confirmed root: the confirmed root skips only an
    /// unchanged tree.
    #[test]
    fn a_push_of_one_new_record_walks_only_its_path_at_a_receiver_holding_the_rest() {
        // The new key's first byte is its own: the root gains a leaf.
        let (sender, collection, before, key) = one_more(33, |company| company.is_none());
        let pinned = snapshot(&sender, collection);
        let confirmed = before.repair().records().summary();
        let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), Some(confirmed));
        let mut receiver = Receiver::new(WalkKind::Records, Some(before));
        carry(&mut push, &mut receiver, frames).unwrap();
        assert_eq!(receiver.nodes(), [Vec::<u8>::new()]);
        assert_eq!(receiver.leaves(), [key]);
        assert_eq!(receiver.values.keys().copied().collect::<Vec<_>>(), [key]);
        assert!(push.outcome().confirmed);

        // The new key shares its first byte with one record: that leaf
        // becomes a branch of two, and only the new leaf goes out.
        let (sender, collection, before, key) = one_more(34, |company| company == Some(&1));
        let pinned = snapshot(&sender, collection);
        let confirmed = before.repair().records().summary();
        for confirmed in [Some(confirmed), None] {
            let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), confirmed);
            let mut receiver = Receiver::new(WalkKind::Records, Some(before.clone()));
            carry(&mut push, &mut receiver, frames).unwrap();
            assert_eq!(receiver.nodes(), [Vec::new(), vec![key[0]]]);
            assert_eq!(receiver.leaves(), [key]);
            assert_eq!(receiver.values.keys().copied().collect::<Vec<_>>(), [key]);
            assert_eq!(receiver.count(|frame| *frame == Frame::Done), 1);
            assert!(push.outcome().confirmed);
        }

        // A receiver holding nothing gets every leaf, confirmed root or not.
        let (mut push, frames) = Push::start(WalkKind::Records, pinned, Some(confirmed));
        let mut receiver = Receiver::new(WalkKind::Records, None);
        carry(&mut push, &mut receiver, frames).unwrap();
        assert_eq!(receiver.leaves().len(), 21);
        assert!(push.outcome().confirmed);
    }

    #[test]
    fn a_held_with_every_child_prunes_the_tree_below_the_root() {
        let mut sender = Node::new(35);
        let collection = sender.hold("held", open());
        for data in 0..300 {
            sender.commit(collection, data);
        }
        sender.observe();
        let pinned = snapshot(&sender, collection);
        let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), None);
        let mut receiver = Receiver::new(WalkKind::Records, Some(pinned.clone()));
        carry(&mut push, &mut receiver, frames).unwrap();
        assert_eq!(
            receiver.heard,
            [
                Frame::Root {
                    summary: pinned.repair().records().summary()
                },
                Frame::Node {
                    prefix: Vec::new(),
                    node: node(WalkKind::Records, pinned.repair(), &[]).unwrap(),
                },
                Frame::Done,
            ]
        );
        assert!(receiver.values.is_empty());
        assert!(push.outcome().confirmed);
    }

    #[test]
    fn a_push_keeps_at_most_sixty_four_nodes_outstanding() {
        let mut sender = Node::new(36);
        let collection = sender.hold("window", open());
        for data in 0..3000 {
            sender.commit(collection, data);
        }
        sender.observe();
        let pinned = snapshot(&sender, collection);
        let mut expected = Vec::new();
        branches(pinned.repair().records().patch(), Vec::new(), &mut expected);
        assert!(
            expected.len() > 2 * MAX_OUTSTANDING_NODES,
            "{}",
            expected.len()
        );

        let (mut push, frames) = Push::start(WalkKind::Records, pinned, None);
        let mut receiver = Receiver::new(WalkKind::Records, None);
        receiver.holds_answers = true;
        carry(&mut push, &mut receiver, frames).unwrap();
        // Every NODE the sender sent is unanswered until the test answers
        // it, so the unanswered count is the sender's window.
        let mut most = receiver.unanswered.len();
        while let Some(prefix) = receiver.unanswered.pop_front() {
            let held = Frame::Held {
                prefix,
                children: [0; 32],
            };
            let frames = push.on_frame(roundtrip(held)).unwrap();
            carry(&mut push, &mut receiver, frames).unwrap();
            most = most.max(receiver.unanswered.len());
            assert!(receiver.unanswered.len() <= MAX_OUTSTANDING_NODES);
        }
        assert_eq!(most, MAX_OUTSTANDING_NODES);
        assert_eq!(receiver.nodes().len(), expected.len());
        assert_eq!(receiver.leaves().len(), 3000);
        assert_eq!(receiver.count(|frame| *frame == Frame::Done), 1);
        assert!(push.outcome().confirmed);
    }

    #[test]
    fn a_close_before_landed_leaves_the_root_unconfirmed() {
        let mut sender = Node::new(37);
        let collection = sender.hold("closed", open());
        for data in 0..30 {
            sender.commit(collection, data);
        }
        sender.observe();
        let pinned = snapshot(&sender, collection);

        // The receiver never confirms.
        let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), None);
        let mut receiver = Receiver::new(WalkKind::Records, None);
        receiver.lands = false;
        carry(&mut push, &mut receiver, frames).unwrap();
        assert!(receiver.done);
        assert!(!push.outcome().confirmed);

        // The stream closes mid-walk.
        let (push, frames) = Push::start(WalkKind::Records, pinned.clone(), None);
        assert!(!frames.contains(&Frame::Done));
        assert!(!push.outcome().confirmed);

        // LANDED before DONE, a VALUE_REQUEST for a key the tree lacks, a HELD
        // for no NODE and a sender's frame fail the push.
        for frame in [
            Frame::Landed,
            Frame::ValueRequest { key: [9; 32] },
            Frame::Held {
                prefix: vec![1],
                children: [0; 32],
            },
            Frame::Done,
        ] {
            let (mut push, _) = Push::start(WalkKind::Records, pinned.clone(), None);
            assert!(push.on_frame(frame.clone()).is_err(), "{frame:?}");
            assert!(!push.outcome().confirmed);
        }
        // A push of the confirmed tree has no NODE outstanding: a HELD for
        // the root, held whole, is a HELD for no NODE.
        let confirmed = pinned.repair().records().summary();
        let (mut push, frames) = Push::start(WalkKind::Records, pinned.clone(), Some(confirmed));
        assert!(matches!(frames[..], [Frame::Root { .. }, Frame::Done]));
        assert!(
            push.on_frame(Frame::Held {
                prefix: Vec::new(),
                children: [0xFF; 32],
            })
            .is_err()
        );
        assert!(!push.outcome().confirmed);
        // A references push serves no values.
        let (mut push, _) = Push::start(WalkKind::References, pinned, None);
        assert!(push.on_frame(Frame::ValueRequest { key: [9; 32] }).is_err());
    }

    #[test]
    fn walks_push_pins_admits_and_runs_one_push_per_key() {
        let mut owner = Node::new(38);
        let stranger = Node::new(39);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.key.verifying_key()),
            AdmissionPolicy::direct(owner.key.verifying_key()),
        );
        let collection = owner.hold("admitted", policy);
        owner.commit(collection, 1);
        owner.observe();
        let peer = stranger.id();
        let kind = WalkKind::Records;

        // The stranger lacks READ and is not a flagged peering.
        assert!(owner.walks.push(peer, collection, kind).is_none());
        owner.health.update(|health| {
            health.peerings.push(PeeringHealth {
                collection,
                peer,
                asked: false,
                peered: true,
                sends: true,
                receives: true,
                refused_by_me: false,
                refused_by_them: false,
            })
        });
        let (push, frames) = owner.walks.push(peer, collection, kind).unwrap();
        assert!(frames.len() > 2, "{frames:?}");
        // One push per peer, collection and kind; the other kinds run beside it.
        assert!(owner.walks.push(peer, collection, kind).is_none());
        assert!(
            owner
                .walks
                .push(peer, collection, WalkKind::Authorization)
                .is_some()
        );
        assert!(
            owner
                .walks
                .push(peer, CollectionHandle::new([1; 32]), kind)
                .is_none()
        );

        // An unconfirmed end leaves the root empty: the next push carries
        // the tree again. The tree is as pushed, so nothing follows at once.
        let now = crate::clock::mono_now();
        assert!(
            !owner
                .walks
                .pushed(peer, collection, kind, push.outcome(), now)
        );
        let (mut push, frames) = owner.walks.push(peer, collection, kind).unwrap();
        assert!(frames.len() > 2, "{frames:?}");
        let mut receiver = Receiver::new(kind, None);
        carry(&mut push, &mut receiver, frames).unwrap();
        assert!(
            !owner
                .walks
                .pushed(peer, collection, kind, push.outcome(), now)
        );

        // A confirmed end pins the root: the unchanged tree is root then
        // done, and a new record walks only its path at a receiver holding
        // the rest. A record committed while a confirmed push runs makes
        // its end ask for the next push at once.
        let (mut push, frames) = owner.walks.push(peer, collection, kind).unwrap();
        assert!(matches!(frames[..], [Frame::Root { .. }, Frame::Done]));
        let before = snapshot(&owner, collection);
        carry(&mut push, &mut Receiver::new(kind, None), frames).unwrap();
        let key = owner.commit(collection, 2).fingerprint().raw();
        owner.observe();
        assert!(
            owner
                .walks
                .pushed(peer, collection, kind, push.outcome(), now)
        );
        let (mut push, frames) = owner.walks.push(peer, collection, kind).unwrap();
        let mut receiver = Receiver::new(kind, Some(before));
        carry(&mut push, &mut receiver, frames).unwrap();
        assert_eq!(receiver.leaves(), [key]);
        assert!(
            !owner
                .walks
                .pushed(peer, collection, kind, push.outcome(), now)
        );

        // Health saw every end: three confirmed, one not, and the confirmed
        // records root is the tree as it is now.
        let health = owner.health.snapshot();
        let pair = &health.collections[0].peers[0];
        assert_eq!(pair.peer, peer);
        assert_eq!((pair.pushes.ok, pair.pushes.failed), (3, 1));
        assert_eq!(
            pair.confirmed.records,
            Some(summary(kind, snapshot(&owner, collection).repair()))
        );
    }

    /// A push that ended unconfirmed is not repeated at once however the
    /// tree moved meanwhile: it is left to the collection's timer, which
    /// paces retries to a neighbour that cannot land it. Only a confirmed
    /// push of a tree that changed while it ran is followed at once.
    #[test]
    fn a_failed_push_of_a_tree_that_changed_meanwhile_waits_for_the_timer() {
        let mut owner = Node::new(42);
        let collection = owner.hold("timer", open());
        owner.commit(collection, 1);
        owner.observe();
        let peer = Node::new(43).id();
        let kind = WalkKind::Records;
        let now = crate::clock::mono_now();

        // A record lands while the push runs, and the push fails.
        let (push, _) = owner.walks.push(peer, collection, kind).unwrap();
        owner.commit(collection, 2);
        owner.observe();
        let outcome = push.outcome();
        assert!(!outcome.confirmed);
        assert!(
            !owner.walks.pushed(peer, collection, kind, outcome, now),
            "a failed push waits for the timer"
        );

        // The same change under a confirmed push is followed at once.
        let (mut push, frames) = owner.walks.push(peer, collection, kind).unwrap();
        let mut receiver = Receiver::new(kind, None);
        carry(&mut push, &mut receiver, frames).unwrap();
        owner.commit(collection, 3);
        owner.observe();
        assert!(
            owner
                .walks
                .pushed(peer, collection, kind, push.outcome(), now)
        );
    }

    /// The receiver builds its HELD bitmap through [`hold`] and the sender
    /// reads it through [`held`]: a receiver holding the sender's subtrees
    /// at branch bytes 0, 7, 8 and 255 answers the root NODE with exactly
    /// those bits, and the sender prunes exactly those children.
    #[test]
    fn the_sender_prunes_exactly_the_children_the_receiver_holds() {
        use crate::receive::{Out, Receive};

        let mut sender = Node::new(40);
        let collection = sender.hold("bitmap", open());
        let records = (0..3000)
            .map(|data| sender.commit(collection, data))
            .collect::<Vec<_>>();
        sender.observe();
        let pinned = snapshot(&sender, collection);
        let Some(PatchNode::Branch { branch, .. }) = node(WalkKind::Records, pinned.repair(), &[])
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
        let mut receiver = Node::new(41);
        receiver.hold("bitmap", open());
        for record in &records {
            if edges.contains(&record.fingerprint().raw()[0]) {
                receiver.store.insert(*record).unwrap();
            }
        }
        receiver.observe();

        // The receiver takes the ROOT and the root NODE; its one reply is
        // the HELD it built through `hold`.
        let mut receive =
            Receive::on_open(sender.id(), collection, WalkKind::Records, true, None).unwrap();
        let (mut push, frames) = Push::start(WalkKind::Records, pinned, None);
        let mut replies = Vec::new();
        for frame in frames {
            for out in receive.on_frame(roundtrip(frame), Some(receiver.snapshot())) {
                match out {
                    Out::Send(reply) => replies.push(reply),
                    other => panic!("the receiver lands or fetches nothing yet: {other:?}"),
                }
            }
        }
        let [Frame::Held { prefix, children }] = &replies[..] else {
            panic!("one HELD for the root NODE: {replies:?}");
        };
        assert!(prefix.is_empty());
        let mut expected = [0; 32];
        for edge in edges {
            hold(&mut expected, edge);
        }
        assert_eq!(*children, expected);

        // The sender reads it through `held`: the walk goes on below every
        // other child, visited now or pending.
        let answers = push.on_frame(roundtrip(replies.pop().unwrap())).unwrap();
        let mut below = answers
            .iter()
            .filter_map(|frame| match frame {
                Frame::Node { prefix, .. } => Some(prefix[0]),
                Frame::Leaf { key } => Some(key[0]),
                _ => None,
            })
            .collect::<BTreeSet<u8>>();
        assert_eq!(below.len(), MAX_OUTSTANDING_NODES.min(answers.len()));
        below.extend(push.pending.iter().map(|prefix| prefix[0]));
        assert_eq!(below.len(), 256 - edges.len());
        for edge in edges {
            assert!(!below.contains(&edge), "child {edge} was pruned");
        }
    }

    /// A failed push forgets the confirmed root, so the next push starts from
    /// the root NODE and lets the peer's HELD prune, instead of repeating a
    /// Root-then-Done the peer may be unable to land.
    #[test]
    fn a_failed_push_forgets_the_confirmed_root() {
        let key: PushKey = ([7; 32], [1; 32], WalkKind::Records);
        let root = PatchSummary::new(Some([9; 32]), 3).unwrap();
        let mut roots = ConfirmedRoots::default();
        roots.settle(
            key,
            Outcome {
                root,
                confirmed: true,
            },
        );
        assert_eq!(roots.root(key), Some(root));
        roots.settle(
            key,
            Outcome {
                root,
                confirmed: false,
            },
        );
        assert_eq!(roots.root(key), None);
    }
}
