//! Per-collection announcements on `recon/1` (design 2.3, 2.5, 2.9).
//!
//! An announcement says "my root for C is R", where R is C's [`record_root`]:
//! the root of what a record pull walks, so the root a completed pull walked
//! compares with later announcements. Between two neighbours that both
//! replicate C in full it also carries the sender's held digest, the
//! [`held_digest`] of the blobs it holds in C; other neighbours get none.
//! Each selected collection has one [`WakeSchedule`]: when it fires, this
//! side announces C to each neighbour for C it sends to, except one that
//! announced an equal state during the interval. A local append resets the
//! timer to its shortest interval. A root that changes while a record pull
//! of C runs is that pull landing and resets nothing; the pull resets the
//! timer once when it completes, so the merged root goes out once (D4). A
//! changed held set resets nothing: the next announcement carries it.
//!
//! An announcement ends the comparison when its root equals this side's, and
//! so does its held digest where both sides replicate C in full; a held
//! digest from any other neighbour is ignored. Otherwise a root that differs,
//! and is not the root of the last record pull from its sender that
//! completed, starts a record pull from the sender; a held digest that
//! differs, and is not the one the last completed reference pull from it
//! walked, starts a reference pull. If this side sends to the sender and the
//! announcement is not itself a reply, a pull also gets an immediate reply
//! with this side's state, from which the sender pulls in turn. The reply
//! counts as the interval's announcement to that neighbour and is never
//! answered. An announcement heard while a pull from its sender runs waits
//! for every pull from it to end, the latest replacing earlier ones.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_activation::{held_digest, record_root};
use crate::connection::Link;
use crate::host::StoreSnapshot;
use crate::patch_repair::PatchSummary;
use crate::protocol::RawHash;
use crate::recon::Frame;
use crate::transport::PeerId;
use crate::wake_schedule::WakeSchedule;
use crate::walk::{PullDone, PullKind};

/// A pull of a collection from a peer.
pub(crate) type Pull = (PeerId, CollectionHandle, PullKind);

/// One collection's state as an announcement carries it: the record root,
/// and the held digest when the collection is replicated in full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct State {
    pub(crate) root: RawHash,
    pub(crate) held: Option<RawHash>,
}

struct Neighbour {
    link: Link,
    /// This side sends the collection to the neighbour.
    sends: bool,
    /// Both sides replicate the collection in full.
    full: bool,
    /// The root of the last record pull from the neighbour that completed.
    completed: Option<RawHash>,
    /// The held digest of the last reference pull from the neighbour that
    /// completed.
    completed_held: Option<RawHash>,
}

struct Announcing {
    state: State,
    schedule: WakeSchedule<PeerId>,
    neighbours: HashMap<PeerId, Neighbour>,
}

impl Announcing {
    /// This side's announcement to a neighbour; `full` says both sides
    /// replicate the collection in full, and only then is the held digest
    /// in it.
    fn announcement(&self, collection: CollectionHandle, full: bool, reply: bool) -> Frame {
        Frame::Announce {
            collection,
            root: self.state.root,
            held_digest: self.state.held.filter(|_| full),
            reply,
        }
    }
}

/// The pulls from one peer of one collection that run, and the latest
/// announcement heard from that peer meanwhile, with whether it was a
/// reply.
struct Running {
    kinds: Vec<PullKind>,
    pending: Option<(State, bool)>,
}

/// The announcements of every selected collection of one node.
#[derive(Default)]
pub(crate) struct Announcements {
    collections: HashMap<RawHash, Announcing>,
    /// By collection and peer.
    pulls: HashMap<(RawHash, PeerId), Running>,
}

/// The selected collections of `snapshot` and their states.
pub(crate) fn states(snapshot: &StoreSnapshot) -> impl Iterator<Item = (CollectionHandle, State)> {
    snapshot.active().filter_map(|collection| {
        let selected = snapshot.selected(collection)?;
        let repair = selected.repair();
        let root = record_root(
            collection,
            repair.records().summary(),
            repair.authorization_evidence().summary(),
        );
        let held = snapshot
            .full(collection)
            .then(|| held_digest(PatchSummary::from_patch(repair.blob_inventory())));
        Some((collection, State { root, held }))
    })
}

impl Announcements {
    /// Follow the selected collections and their states: start and stop
    /// announcing collections, and reset the timer of one whose root changed
    /// while no record pull of it runs.
    pub(crate) fn observe(
        &mut self,
        selected: impl IntoIterator<Item = (CollectionHandle, State)>,
        now: Mono,
    ) {
        let selected = selected
            .into_iter()
            .map(|(collection, state)| (collection.raw, state))
            .collect::<HashMap<_, _>>();
        self.collections.retain(|raw, _| selected.contains_key(raw));
        for (raw, state) in selected {
            match self.collections.entry(raw) {
                Entry::Vacant(entry) => {
                    entry.insert(Announcing {
                        state,
                        schedule: WakeSchedule::new(now, rand::random()),
                        neighbours: HashMap::new(),
                    });
                }
                Entry::Occupied(mut entry) => {
                    let announcing = entry.get_mut();
                    let landing = self.pulls.iter().any(|((pulled, _), running)| {
                        *pulled == raw && running.kinds.contains(&PullKind::Records)
                    });
                    if announcing.state.root != state.root && !landing {
                        announcing.schedule.local_changed(now, rand::random());
                    }
                    announcing.state = state;
                }
            }
        }
    }

    /// Follow the peerings: each with its collection and its connection,
    /// whether this side sends on it, and whether both sides replicate the
    /// collection in full. A neighbour this side starts sending to is offered
    /// the state within two minimum intervals.
    pub(crate) fn neighbours<'a>(
        &mut self,
        peerings: impl IntoIterator<Item = (CollectionHandle, &'a Link, bool, bool)>,
        now: Mono,
    ) {
        let mut current = HashMap::<RawHash, HashMap<PeerId, (Link, bool, bool)>>::new();
        for (collection, link, sends, full) in peerings {
            let peers = current.entry(collection.raw).or_default();
            // While a tie-break settles, a peer can be peered on two
            // connections; the newer one carries the announcements.
            if peers
                .get(&link.peer())
                .is_none_or(|(kept, _, _)| kept.id() < link.id())
            {
                peers.insert(link.peer(), (link.clone(), sends, full));
            }
        }
        for (raw, announcing) in &mut self.collections {
            let peers = current.remove(raw).unwrap_or_default();
            announcing
                .neighbours
                .retain(|peer, _| peers.contains_key(peer));
            for (peer, (link, sends, full)) in peers {
                let neighbour = announcing
                    .neighbours
                    .entry(peer)
                    .or_insert_with(|| Neighbour {
                        link: link.clone(),
                        sends: false,
                        full,
                        completed: None,
                        completed_held: None,
                    });
                if sends && !neighbour.sends {
                    announcing
                        .schedule
                        .neighbor_joined(now, rand::random(), peer);
                }
                neighbour.link = link;
                neighbour.sends = sends;
                neighbour.full = full;
            }
        }
    }

    /// Hear `peer` announce `state` for `collection`. Returns the pulls to
    /// start.
    pub(crate) fn heard(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        state: State,
        reply: bool,
        now: Mono,
    ) -> Vec<Pull> {
        let Some(announcing) = self.collections.get_mut(&collection.raw) else {
            return Vec::new();
        };
        let Some(neighbour) = announcing.neighbours.get(&peer) else {
            return Vec::new();
        };
        let pulls = match self.pulls.entry((collection.raw, peer)) {
            Entry::Occupied(mut running) => {
                running.get_mut().pending = Some((state, reply));
                return Vec::new();
            }
            Entry::Vacant(pulls) => pulls,
        };
        // Held digests compare only between two neighbours that replicate
        // the collection in full.
        let held = state
            .held
            .filter(|_| neighbour.full)
            .zip(announcing.state.held)
            .filter(|(theirs, mine)| theirs != mine)
            .map(|(theirs, _)| theirs);
        if state.root == announcing.state.root && held.is_none() {
            announcing.schedule.consistent_root(now, peer);
            return Vec::new();
        }
        let mut kinds = Vec::new();
        if state.root != announcing.state.root && neighbour.completed != Some(state.root) {
            kinds.push(PullKind::Records);
        }
        if held.is_some() && neighbour.completed_held != held {
            kinds.push(PullKind::References);
        }
        if kinds.is_empty() {
            return Vec::new();
        }
        if neighbour.sends && !reply {
            neighbour
                .link
                .send(announcing.announcement(collection, neighbour.full, true));
            announcing.schedule.replied(now, peer);
        }
        pulls.insert(Running {
            kinds: kinds.clone(),
            pending: None,
        });
        kinds
            .into_iter()
            .map(|kind| (peer, collection, kind))
            .collect()
    }

    /// A pull ended. A completed pull's root becomes the last completed one
    /// of its kind from its neighbour, and a completed record pull resets the
    /// timer once. Once no pull from the neighbour runs, an announcement
    /// heard meanwhile is heard now. Returns the pulls to start.
    pub(crate) fn ended(&mut self, done: PullDone, now: Mono) -> Vec<Pull> {
        let PullDone {
            peer,
            collection,
            kind,
            root,
            completed,
        } = done;
        let mut pending = None;
        if let Entry::Occupied(mut running) = self.pulls.entry((collection.raw, peer)) {
            running.get_mut().kinds.retain(|running| *running != kind);
            if running.get().kinds.is_empty() {
                pending = running.remove().pending;
            }
        }
        let Some(announcing) = self.collections.get_mut(&collection.raw) else {
            return Vec::new();
        };
        if completed {
            if let Some(neighbour) = announcing.neighbours.get_mut(&peer) {
                match kind {
                    PullKind::Records => neighbour.completed = Some(root),
                    PullKind::References => neighbour.completed_held = Some(root),
                }
            }
            if kind == PullKind::Records {
                announcing.schedule.local_changed(now, rand::random());
            }
        }
        let Some((state, reply)) = pending else {
            return Vec::new();
        };
        self.heard(peer, collection, state, reply, now)
    }

    /// When [`Self::poll`] next has work.
    pub(crate) fn deadline(&self) -> Option<Mono> {
        self.collections
            .values()
            .map(|announcing| announcing.schedule.deadline())
            .min()
    }

    /// Announce each collection whose opportunity is due to the neighbours
    /// its schedule picks.
    pub(crate) fn poll(&mut self, now: Mono) {
        for (raw, announcing) in &mut self.collections {
            if announcing.schedule.deadline() > now {
                continue;
            }
            let sends = announcing
                .neighbours
                .iter()
                .filter(|(_, neighbour)| neighbour.sends)
                .map(|(peer, _)| *peer)
                .collect::<Vec<_>>();
            for peer in announcing.schedule.poll(now, rand::random(), sends) {
                let neighbour = &announcing.neighbours[&peer];
                neighbour.link.send(announcing.announcement(
                    CollectionHandle::new(*raw),
                    neighbour.full,
                    false,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use tokio::sync::mpsc::UnboundedReceiver;

    const STEP: Duration = Duration::from_millis(100);
    const A: PeerId = [0xA; 32];
    const B: PeerId = [0xB; 32];

    fn collection(byte: u8) -> CollectionHandle {
        CollectionHandle::new([byte; 32])
    }

    fn root(number: u32) -> RawHash {
        let mut root = [0; 32];
        root[..4].copy_from_slice(&number.to_be_bytes());
        root
    }

    /// The state of a collection replicated on demand: no held digest.
    fn state(number: u32) -> State {
        State {
            root: root(number),
            held: None,
        }
    }

    /// A link to `peer` and the frames sent on it.
    struct Wire {
        link: Link,
        frames: UnboundedReceiver<Frame>,
    }

    fn wire(id: u64, peer: PeerId) -> Wire {
        let (link, frames) = Link::detached(id, peer);
        Wire { link, frames }
    }

    /// The announcements sent on `wire` since the last call: collection,
    /// root and reply flag.
    fn sent(wire: &mut Wire) -> Vec<(CollectionHandle, RawHash, bool)> {
        std::iter::from_fn(|| wire.frames.try_recv().ok())
            .map(|frame| match frame {
                Frame::Announce {
                    collection,
                    root,
                    reply,
                    held_digest: None,
                } => (collection, root, reply),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    /// The state of a collection replicated in full.
    fn full(number: u32, held: u32) -> State {
        State {
            root: root(number),
            held: Some(root(held)),
        }
    }

    /// The announcements sent on `wire` since the last call: root, held
    /// digest and reply flag.
    fn announced(wire: &mut Wire) -> Vec<(RawHash, Option<RawHash>, bool)> {
        std::iter::from_fn(|| wire.frames.try_recv().ok())
            .map(|frame| match frame {
                Frame::Announce {
                    root,
                    held_digest,
                    reply,
                    ..
                } => (root, held_digest, reply),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    /// Poll `node` every step for `by`.
    fn advance(node: &mut Announcements, now: &mut Mono, by: Duration) {
        let until = *now + by;
        while *now < until {
            *now = *now + STEP;
            node.poll(*now);
        }
    }

    #[test]
    fn an_equal_announcement_gets_no_reply_and_suppresses_its_sender() {
        let c = collection(1);
        let mut now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, state(1))], now);
        let (mut a, mut b) = (wire(1, A), wire(2, B));
        node.neighbours([(c, &a.link, true, false), (c, &b.link, true, false)], now);
        // The first interval offers the root to both new neighbours.
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut a), [(c, root(1), false)]);
        assert_eq!(sent(&mut b), [(c, root(1), false)]);

        assert!(node.heard(A, c, state(1), false, now).is_empty());
        assert!(sent(&mut a).is_empty());
        // The joins asked for a second short interval, two to four seconds,
        // and it skips A only.
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert!(sent(&mut a).is_empty());
        assert_eq!(sent(&mut b), [(c, root(1), false)]);
        // The next, four to eight seconds, does not remember it.
        advance(&mut node, &mut now, Duration::from_secs(4));
        assert_eq!(sent(&mut a), [(c, root(1), false)]);
        assert_eq!(sent(&mut b), [(c, root(1), false)]);
    }

    /// Y announces first. X answers at once, which is its announcement to Y
    /// for the interval; Y answers nothing. Both pull.
    #[test]
    fn a_different_announcement_gets_one_reply_and_the_reply_none() {
        let c = collection(2);
        let start = crate::clock::mono_now();
        let (mut x, mut y) = (Announcements::default(), Announcements::default());
        let (x_id, y_id) = ([1; 32], [2; 32]);
        let (mut to_x, mut to_y) = (wire(1, x_id), wire(1, y_id));
        y.observe([(c, state(20))], start);
        y.neighbours([(c, &to_x.link, true, false)], start);
        let mut now = start;
        advance(&mut y, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut to_x), [(c, root(20), false)]);

        // X's first opportunity comes later, between 2.5 and 3.5 seconds.
        let joined = start + Duration::from_millis(1_500);
        x.observe([(c, state(10))], joined);
        x.neighbours([(c, &to_y.link, true, false)], joined);
        assert_eq!(
            x.heard(y_id, c, state(20), false, now),
            [(y_id, c, PullKind::Records)]
        );
        assert_eq!(sent(&mut to_y), [(c, root(10), true)]);
        advance(&mut x, &mut now, Duration::from_millis(1_500));
        assert!(sent(&mut to_y).is_empty(), "the reply was the announcement");
        // While its pull runs, X answers Y's announcements no more.
        assert!(x.heard(y_id, c, state(21), false, now).is_empty());
        assert!(sent(&mut to_y).is_empty());

        assert_eq!(
            y.heard(x_id, c, state(10), true, now),
            [(x_id, c, PullKind::Records)]
        );
        assert!(sent(&mut to_x).is_empty());
    }

    #[test]
    fn a_busy_collection_announces_every_two_seconds_beside_a_quiet_one() {
        let (busy, quiet) = (collection(3), collection(4));
        let start = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(busy, state(0)), (quiet, state(0))], start);
        let mut peer = wire(1, A);
        node.neighbours(
            [
                (busy, &peer.link, true, false),
                (quiet, &peer.link, true, false),
            ],
            start,
        );
        let mut announced = HashMap::<CollectionHandle, Vec<Duration>>::new();
        let mut now = start;
        for step in 1..=2_400_u32 {
            now = now + STEP;
            node.poll(now);
            // A local append to the busy collection every second.
            if step % 10 == 0 {
                node.observe([(busy, state(step)), (quiet, state(0))], now);
            }
            for (collection, _, _) in sent(&mut peer) {
                announced
                    .entry(collection)
                    .or_default()
                    .push(now.duration_since(start));
            }
        }
        let gaps = |collection| {
            announced[&collection]
                .windows(2)
                .map(|pair| pair[1] - pair[0])
                .collect::<Vec<_>>()
        };
        let busy_gaps = gaps(busy);
        assert!(busy_gaps.len() >= 100, "{busy_gaps:?}");
        assert!(
            busy_gaps
                .iter()
                .all(|gap| *gap <= Duration::from_millis(3_100)),
            "{busy_gaps:?}"
        );
        // Intervals of 2, 4, 8, 16, 32 and then 60 seconds.
        let quiet_gaps = gaps(quiet);
        assert!((6..=8).contains(&quiet_gaps.len()), "{quiet_gaps:?}");
        assert!(
            quiet_gaps[quiet_gaps.len() - 2..]
                .iter()
                .all(|gap| *gap >= Duration::from_secs(30)),
            "{quiet_gaps:?}"
        );
    }

    /// The pull lands for fifty seconds without resetting the timer: other
    /// neighbours hear at most the announcement already due. Completing
    /// resets it once, and they hear the merged root.
    #[test]
    fn after_a_long_pull_completes_other_neighbours_get_one_announcement() {
        let c = collection(5);
        let mut now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, state(0))], now);
        let (mut a, mut b) = (wire(1, A), wire(2, B));
        node.neighbours([(c, &a.link, true, false), (c, &b.link, true, false)], now);
        // Quiet long enough to reach sixty-second intervals.
        advance(&mut node, &mut now, Duration::from_secs(200));
        sent(&mut a);
        sent(&mut b);

        assert_eq!(
            node.heard(A, c, state(100), false, now),
            [(A, c, PullKind::Records)]
        );
        assert_eq!(sent(&mut a), [(c, root(0), true)]);
        let mut during = Vec::new();
        for landed in 1..=50 {
            advance(&mut node, &mut now, Duration::from_secs(1));
            node.observe([(c, state(landed))], now);
            during.extend(sent(&mut b));
        }
        assert!(during.len() <= 1, "{during:?}");

        let merged = root(50);
        let ended = PullDone {
            kind: PullKind::Records,
            peer: A,
            collection: c,
            root: root(100),
            completed: true,
        };
        assert!(node.ended(ended, now).is_empty());
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut b), [(c, merged, false)]);
        // A's walked root now ends a comparison as an equal one would.
        sent(&mut a);
        assert!(node.heard(A, c, state(100), false, now).is_empty());
        assert!(sent(&mut a).is_empty());
    }

    #[test]
    fn an_announcement_heard_during_a_pull_starts_the_next_pull_if_it_differs() {
        let c = collection(6);
        let now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, state(0))], now);
        let a = wire(1, A);
        node.neighbours([(c, &a.link, true, false)], now);
        let walked = |number| PullDone {
            kind: PullKind::Records,
            peer: A,
            collection: c,
            root: root(number),
            completed: true,
        };

        assert_eq!(
            node.heard(A, c, state(1), false, now),
            [(A, c, PullKind::Records)]
        );
        assert!(node.heard(A, c, state(2), false, now).is_empty());
        assert!(node.heard(A, c, state(1), true, now).is_empty());
        // The latest one equals the walked root.
        assert!(node.ended(walked(1), now).is_empty());

        assert_eq!(
            node.heard(A, c, state(3), false, now),
            [(A, c, PullKind::Records)]
        );
        assert!(node.heard(A, c, state(4), true, now).is_empty());
        assert_eq!(node.ended(walked(3), now), [(A, c, PullKind::Records)]);
        // A pull that did not complete leaves no walked root behind.
        let failed = PullDone {
            completed: false,
            ..walked(4)
        };
        assert!(node.ended(failed, now).is_empty());
        assert_eq!(
            node.heard(A, c, state(4), true, now),
            [(A, c, PullKind::Records)]
        );
    }

    /// A side that replicates C in full announces its held digest only to
    /// neighbours that do too, periodically and in replies.
    #[test]
    fn demand_neighbours_get_no_held_digest() {
        let c = collection(7);
        let mut now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, full(1, 2))], now);
        let (mut a, mut b) = (wire(1, A), wire(2, B));
        node.neighbours([(c, &a.link, true, true), (c, &b.link, true, false)], now);
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(announced(&mut a), [(root(1), Some(root(2)), false)]);
        assert_eq!(announced(&mut b), [(root(1), None, false)]);

        for (peer, wire) in [(A, &mut a), (B, &mut b)] {
            assert_eq!(
                node.heard(peer, c, state(3), false, now),
                [(peer, c, PullKind::Records)]
            );
            let held = (peer == A).then_some(root(2));
            assert_eq!(announced(wire), [(root(1), held, true)]);
        }
    }

    /// A held digest from a neighbour whose peering is not Full on both
    /// sides starts no reference pull: the comparison runs only between two
    /// Full neighbours.
    #[test]
    fn a_demand_neighbour_cannot_start_a_reference_pull() {
        let c = collection(9);
        let now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, full(1, 1))], now);
        let a = wire(1, A);
        node.neighbours([(c, &a.link, false, false)], now);
        assert_eq!(node.heard(A, c, full(1, 2), false, now), []);
    }

    /// Quiet Full neighbours with equal records: a different held digest
    /// starts a reference pull and one reply, and the reply starts the
    /// reverse pull. The digest a completed reference pull walked then ends a
    /// comparison, and once both hold the union, announcements are equal.
    #[test]
    fn a_different_held_digest_starts_a_reference_pull_and_one_reply() {
        let c = collection(8);
        let now = crate::clock::mono_now();
        let (mut x, mut y) = (Announcements::default(), Announcements::default());
        let (x_id, y_id) = ([1; 32], [2; 32]);
        let (mut to_x, mut to_y) = (wire(1, x_id), wire(1, y_id));
        x.observe([(c, full(1, 10))], now);
        y.observe([(c, full(1, 20))], now);
        x.neighbours([(c, &to_y.link, true, true)], now);
        y.neighbours([(c, &to_x.link, true, true)], now);

        let references = |peer| [(peer, c, PullKind::References)];
        assert_eq!(x.heard(y_id, c, full(1, 20), false, now), references(y_id));
        assert_eq!(announced(&mut to_y), [(root(1), Some(root(10)), true)]);
        assert_eq!(y.heard(x_id, c, full(1, 10), true, now), references(x_id));
        assert!(announced(&mut to_x).is_empty(), "a reply is never answered");

        let walked = |peer, held| PullDone {
            peer,
            collection: c,
            kind: PullKind::References,
            root: root(held),
            completed: true,
        };
        assert!(x.ended(walked(y_id, 20), now).is_empty());
        assert!(y.ended(walked(x_id, 10), now).is_empty());
        // An announcement without a digest compares the root alone.
        assert!(y.heard(x_id, c, state(1), false, now).is_empty());
        // Before the union lands, the walked digest ends a comparison.
        assert!(x.heard(y_id, c, full(1, 20), false, now).is_empty());
        assert!(announced(&mut to_y).is_empty());
        x.observe([(c, full(1, 30))], now);
        y.observe([(c, full(1, 30))], now);
        assert!(x.heard(y_id, c, full(1, 30), false, now).is_empty());
        assert!(y.heard(x_id, c, full(1, 30), false, now).is_empty());
        assert!(announced(&mut to_x).is_empty() && announced(&mut to_y).is_empty());
    }
}
