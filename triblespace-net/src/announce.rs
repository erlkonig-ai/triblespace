//! Per-collection announcements on `recon/1` (design 2.3, 2.5).
//!
//! An announcement says "my root for C is R", where R is C's [`record_root`]:
//! the root of what a record pull walks, so the root a completed pull walked
//! compares with later announcements. Each selected collection has one
//! [`WakeSchedule`]: when it fires, this side announces C to each neighbour
//! for C it sends to, except one that announced an equal root during the
//! interval. A local append resets the timer to its shortest interval. A
//! root that changes while a pull of C runs is that pull landing and resets
//! nothing; the pull resets the timer once when it completes, so the merged
//! root goes out once (D4).
//!
//! An announcement ends the comparison when it equals this side's root, or
//! the root of the last pull from its sender that completed. Otherwise it
//! starts a record pull from the sender and, if this side sends to it and
//! the announcement is not itself a reply, an immediate reply with this
//! side's root, from which the sender pulls in turn. The reply counts as the
//! interval's announcement to that neighbour and is never answered. An
//! announcement heard while a pull from its sender runs waits for that pull
//! to end, the latest replacing earlier ones.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_activation::record_root;
use crate::connection::Link;
use crate::host::StoreSnapshot;
use crate::protocol::RawHash;
use crate::recon::Frame;
use crate::transport::PeerId;
use crate::wake_schedule::WakeSchedule;
use crate::walk::RecordPullDone;

/// A record pull of a collection from a peer.
pub(crate) type Pull = (PeerId, CollectionHandle);

struct Neighbour {
    link: Link,
    /// This side sends the collection to the neighbour.
    sends: bool,
    /// The root of the last pull from the neighbour that completed.
    completed: Option<RawHash>,
}

struct Announcing {
    root: RawHash,
    schedule: WakeSchedule<PeerId>,
    neighbours: HashMap<PeerId, Neighbour>,
}

/// The announcements of every selected collection of one node.
#[derive(Default)]
pub(crate) struct Announcements {
    collections: HashMap<RawHash, Announcing>,
    /// Record pulls running, by collection and peer, each with the latest
    /// announcement heard from that peer meanwhile: its root and whether it
    /// was a reply.
    pulls: HashMap<(RawHash, PeerId), Option<(RawHash, bool)>>,
}

/// The selected collections of `snapshot` and their record roots.
pub(crate) fn roots(snapshot: &StoreSnapshot) -> impl Iterator<Item = (CollectionHandle, RawHash)> {
    snapshot.active().filter_map(|collection| {
        let selected = snapshot.selected(collection)?;
        let repair = selected.repair();
        let root = record_root(
            collection,
            repair.records().summary(),
            repair.authorization_evidence().summary(),
        );
        Some((collection, root))
    })
}

impl Announcements {
    /// Follow the selected collections and their roots: start and stop
    /// announcing collections, and reset the timer of one whose root changed
    /// while no pull of it runs.
    pub(crate) fn observe(
        &mut self,
        selected: impl IntoIterator<Item = (CollectionHandle, RawHash)>,
        now: Mono,
    ) {
        let selected = selected
            .into_iter()
            .map(|(collection, root)| (collection.raw, root))
            .collect::<HashMap<_, _>>();
        self.collections.retain(|raw, _| selected.contains_key(raw));
        for (raw, root) in selected {
            match self.collections.entry(raw) {
                Entry::Vacant(entry) => {
                    entry.insert(Announcing {
                        root,
                        schedule: WakeSchedule::new(now, rand::random()),
                        neighbours: HashMap::new(),
                    });
                }
                Entry::Occupied(mut entry) => {
                    let announcing = entry.get_mut();
                    if announcing.root != root {
                        announcing.root = root;
                        if !self.pulls.keys().any(|(pulled, _)| *pulled == raw) {
                            announcing.schedule.local_changed(now, rand::random());
                        }
                    }
                }
            }
        }
    }

    /// Follow the peerings: each with its collection, its connection and
    /// whether this side sends on it. A neighbour this side starts sending to
    /// is offered the root within two minimum intervals.
    pub(crate) fn neighbours<'a>(
        &mut self,
        peerings: impl IntoIterator<Item = (CollectionHandle, &'a Link, bool)>,
        now: Mono,
    ) {
        let mut current = HashMap::<RawHash, HashMap<PeerId, (Link, bool)>>::new();
        for (collection, link, sends) in peerings {
            let peers = current.entry(collection.raw).or_default();
            // While a tie-break settles, a peer can be peered on two
            // connections; the newer one carries the announcements.
            if peers
                .get(&link.peer())
                .is_none_or(|(kept, _)| kept.id() < link.id())
            {
                peers.insert(link.peer(), (link.clone(), sends));
            }
        }
        for (raw, announcing) in &mut self.collections {
            let peers = current.remove(raw).unwrap_or_default();
            announcing
                .neighbours
                .retain(|peer, _| peers.contains_key(peer));
            for (peer, (link, sends)) in peers {
                let neighbour = announcing
                    .neighbours
                    .entry(peer)
                    .or_insert_with(|| Neighbour {
                        link: link.clone(),
                        sends: false,
                        completed: None,
                    });
                if sends && !neighbour.sends {
                    announcing
                        .schedule
                        .neighbor_joined(now, rand::random(), peer);
                }
                neighbour.link = link;
                neighbour.sends = sends;
            }
        }
    }

    /// Hear `peer` announce `root` for `collection`. Returns the record pull
    /// to start, if any.
    pub(crate) fn heard(
        &mut self,
        peer: PeerId,
        collection: CollectionHandle,
        root: RawHash,
        reply: bool,
        now: Mono,
    ) -> Option<Pull> {
        let announcing = self.collections.get_mut(&collection.raw)?;
        let neighbour = announcing.neighbours.get(&peer)?;
        let pull = match self.pulls.entry((collection.raw, peer)) {
            Entry::Occupied(mut running) => {
                running.insert(Some((root, reply)));
                return None;
            }
            Entry::Vacant(pull) => pull,
        };
        if root == announcing.root {
            announcing.schedule.consistent_root(now, peer);
            return None;
        }
        if neighbour.completed == Some(root) {
            return None;
        }
        pull.insert(None);
        if neighbour.sends && !reply {
            neighbour.link.send(Frame::Announce {
                collection,
                root: announcing.root,
                held_digest: None,
                reply: true,
            });
            announcing.schedule.replied(now, peer);
        }
        Some((peer, collection))
    }

    /// A record pull ended. A completed pull's root becomes the last
    /// completed one of its neighbour, and resets the timer once. An
    /// announcement heard during the pull is heard now. Returns the record
    /// pull to start, if any.
    pub(crate) fn ended(&mut self, done: RecordPullDone, now: Mono) -> Option<Pull> {
        let RecordPullDone {
            peer,
            collection,
            root,
            completed,
        } = done;
        let pending = self.pulls.remove(&(collection.raw, peer)).flatten();
        let announcing = self.collections.get_mut(&collection.raw)?;
        if completed {
            if let Some(neighbour) = announcing.neighbours.get_mut(&peer) {
                neighbour.completed = Some(root);
            }
            announcing.schedule.local_changed(now, rand::random());
        }
        let (root, reply) = pending?;
        self.heard(peer, collection, root, reply, now)
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
                announcing.neighbours[&peer].link.send(Frame::Announce {
                    collection: CollectionHandle::new(*raw),
                    root: announcing.root,
                    held_digest: None,
                    reply: false,
                });
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
        node.observe([(c, root(1))], now);
        let (mut a, mut b) = (wire(1, A), wire(2, B));
        node.neighbours([(c, &a.link, true), (c, &b.link, true)], now);
        // The first interval offers the root to both new neighbours.
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut a), [(c, root(1), false)]);
        assert_eq!(sent(&mut b), [(c, root(1), false)]);

        assert_eq!(node.heard(A, c, root(1), false, now), None);
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
        y.observe([(c, root(20))], start);
        y.neighbours([(c, &to_x.link, true)], start);
        let mut now = start;
        advance(&mut y, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut to_x), [(c, root(20), false)]);

        // X's first opportunity comes later, between 2.5 and 3.5 seconds.
        let joined = start + Duration::from_millis(1_500);
        x.observe([(c, root(10))], joined);
        x.neighbours([(c, &to_y.link, true)], joined);
        assert_eq!(x.heard(y_id, c, root(20), false, now), Some((y_id, c)));
        assert_eq!(sent(&mut to_y), [(c, root(10), true)]);
        advance(&mut x, &mut now, Duration::from_millis(1_500));
        assert!(sent(&mut to_y).is_empty(), "the reply was the announcement");
        // While its pull runs, X answers Y's announcements no more.
        assert_eq!(x.heard(y_id, c, root(21), false, now), None);
        assert!(sent(&mut to_y).is_empty());

        assert_eq!(y.heard(x_id, c, root(10), true, now), Some((x_id, c)));
        assert!(sent(&mut to_x).is_empty());
    }

    #[test]
    fn a_busy_collection_announces_every_two_seconds_beside_a_quiet_one() {
        let (busy, quiet) = (collection(3), collection(4));
        let start = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(busy, root(0)), (quiet, root(0))], start);
        let mut peer = wire(1, A);
        node.neighbours([(busy, &peer.link, true), (quiet, &peer.link, true)], start);
        let mut announced = HashMap::<CollectionHandle, Vec<Duration>>::new();
        let mut now = start;
        for step in 1..=2_400_u32 {
            now = now + STEP;
            node.poll(now);
            // A local append to the busy collection every second.
            if step % 10 == 0 {
                node.observe([(busy, root(step)), (quiet, root(0))], now);
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
        node.observe([(c, root(0))], now);
        let (mut a, mut b) = (wire(1, A), wire(2, B));
        node.neighbours([(c, &a.link, true), (c, &b.link, true)], now);
        // Quiet long enough to reach sixty-second intervals.
        advance(&mut node, &mut now, Duration::from_secs(200));
        sent(&mut a);
        sent(&mut b);

        assert_eq!(node.heard(A, c, root(100), false, now), Some((A, c)));
        assert_eq!(sent(&mut a), [(c, root(0), true)]);
        let mut during = Vec::new();
        for landed in 1..=50 {
            advance(&mut node, &mut now, Duration::from_secs(1));
            node.observe([(c, root(landed))], now);
            during.extend(sent(&mut b));
        }
        assert!(during.len() <= 1, "{during:?}");

        let merged = root(50);
        let ended = RecordPullDone {
            peer: A,
            collection: c,
            root: root(100),
            completed: true,
        };
        assert_eq!(node.ended(ended, now), None);
        advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(sent(&mut b), [(c, merged, false)]);
        // A's walked root now ends a comparison as an equal one would.
        sent(&mut a);
        assert_eq!(node.heard(A, c, root(100), false, now), None);
        assert!(sent(&mut a).is_empty());
    }

    #[test]
    fn an_announcement_heard_during_a_pull_starts_the_next_pull_if_it_differs() {
        let c = collection(6);
        let now = crate::clock::mono_now();
        let mut node = Announcements::default();
        node.observe([(c, root(0))], now);
        let a = wire(1, A);
        node.neighbours([(c, &a.link, true)], now);
        let walked = |number| RecordPullDone {
            peer: A,
            collection: c,
            root: root(number),
            completed: true,
        };

        assert_eq!(node.heard(A, c, root(1), false, now), Some((A, c)));
        assert_eq!(node.heard(A, c, root(2), false, now), None);
        assert_eq!(node.heard(A, c, root(1), true, now), None);
        // The latest one equals the walked root.
        assert_eq!(node.ended(walked(1), now), None);

        assert_eq!(node.heard(A, c, root(3), false, now), Some((A, c)));
        assert_eq!(node.heard(A, c, root(4), true, now), None);
        assert_eq!(node.ended(walked(3), now), Some((A, c)));
        // A pull that did not complete leaves no walked root behind.
        let failed = RecordPullDone {
            completed: false,
            ..walked(4)
        };
        assert_eq!(node.ended(failed, now), None);
        assert_eq!(node.heard(A, c, root(4), true, now), Some((A, c)));
    }
}
