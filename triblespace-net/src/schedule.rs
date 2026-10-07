//! The push scheduler: when each selected collection's trees go out
//! (design: walk streams).
//!
//! Each selected collection has one [`WakeSchedule`]. When it fires, this
//! side starts a push of C's records tree and its authorization tree to each
//! neighbour its peering for C sends to, and of its references tree to each
//! of those with which it replicates C in full; the ROOT frame of each push
//! is the announcement, and a push already running for a neighbour and tree
//! is skipped, not queued. A local append resets the timer to its shortest
//! interval. A root that changes while a push of C's records or evidence is
//! being received here is that push landing and resets nothing; the receive
//! resets the timer once when it lands, so the merged root goes out once
//! (D4). A receive that lands without changing the root, the common case of
//! an unchanged root pushed again, resets nothing: otherwise two neighbours
//! would push each other every shortest interval forever. A changed held
//! set resets nothing: the next push carries it. A neighbour this side
//! starts sending to is pushed to within two minimum intervals.
//!
//! When a push is confirmed, the walks task compares the tree with the one
//! pushed and pushes again at once if they differ
//! ([`crate::walk::Walks::pushed`]); a push that ends any other way waits
//! for the timer, so retries to a neighbour that cannot land it are paced
//! like any push. The scheduler does not see pushes end.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_activation::record_root;
use crate::connection::Link;
use crate::host::StoreSnapshot;
use crate::protocol::RawHash;
use crate::transport::PeerId;
use crate::wake_schedule::WakeSchedule;
use crate::walk::{Event, WalkKind};

/// A push to start: to a peer, of one tree of a collection.
pub(crate) type Start = (PeerId, CollectionHandle, WalkKind);

struct Neighbour {
    /// The connection the peering is on; the newer of two wins while a
    /// tie-break settles.
    link: u64,
    /// This side sends the collection to the neighbour.
    sends: bool,
    /// Both sides replicate the collection in full.
    full: bool,
}

struct Scheduled {
    root: RawHash,
    schedule: WakeSchedule,
    neighbours: HashMap<PeerId, Neighbour>,
    /// Pushes of the records or authorization tree being received.
    receiving: usize,
    /// The root changed while one was: the merged root goes out once they
    /// end.
    merged: bool,
}

/// The push schedules of every selected collection of one node.
#[derive(Default)]
pub(crate) struct Schedules {
    collections: HashMap<RawHash, Scheduled>,
}

/// The selected collections of `snapshot` and their record roots.
pub(crate) fn roots(snapshot: &StoreSnapshot) -> impl Iterator<Item = (CollectionHandle, RawHash)> {
    snapshot.active().filter_map(|collection| {
        let repair = snapshot.selected(collection)?;
        let repair = repair.repair();
        Some((
            collection,
            record_root(
                collection,
                repair.records().summary(),
                repair.authorization_evidence().summary(),
            ),
        ))
    })
}

impl Schedules {
    /// Follow the selected collections and their roots: start and stop
    /// scheduling collections, and reset the timer of one whose root
    /// changed while no push of it is being received.
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
                    entry.insert(Scheduled {
                        root,
                        schedule: WakeSchedule::new(now, rand::random()),
                        neighbours: HashMap::new(),
                        receiving: 0,
                        merged: false,
                    });
                }
                Entry::Occupied(mut entry) => {
                    let scheduled = entry.get_mut();
                    if scheduled.root != root {
                        if scheduled.receiving == 0 {
                            scheduled.schedule.local_changed(now, rand::random());
                        } else {
                            scheduled.merged = true;
                        }
                    }
                    scheduled.root = root;
                }
            }
        }
    }

    /// Follow the peerings: each with its collection and its connection,
    /// whether this side sends on it, and whether both sides replicate the
    /// collection in full. A neighbour this side starts sending to is pushed
    /// to within two minimum intervals.
    pub(crate) fn neighbours<'a>(
        &mut self,
        peerings: impl IntoIterator<Item = (CollectionHandle, &'a Link, bool, bool)>,
        now: Mono,
    ) {
        let mut current = HashMap::<RawHash, HashMap<PeerId, Neighbour>>::new();
        for (collection, link, sends, full) in peerings {
            let peers = current.entry(collection.raw).or_default();
            if peers
                .get(&link.peer())
                .is_none_or(|kept| kept.link < link.id())
            {
                peers.insert(
                    link.peer(),
                    Neighbour {
                        link: link.id(),
                        sends,
                        full,
                    },
                );
            }
        }
        for (raw, scheduled) in &mut self.collections {
            let peers = current.remove(raw).unwrap_or_default();
            scheduled
                .neighbours
                .retain(|peer, _| peers.contains_key(peer));
            for (peer, neighbour) in peers {
                let joined = neighbour.sends
                    && !scheduled
                        .neighbours
                        .get(&peer)
                        .is_some_and(|known| known.sends);
                if joined {
                    scheduled.schedule.neighbour_joined(now, rand::random());
                }
                scheduled.neighbours.insert(peer, neighbour);
            }
        }
    }

    /// A push of a tree is being received here, or ended. A root that
    /// changes while one of C's records or evidence is received resets
    /// nothing; once the last of them ends, having landed, the change resets
    /// C's timer once.
    pub(crate) fn event(&mut self, event: Event, now: Mono) {
        let (collection, kind, landed) = match event {
            Event::Receiving { collection, kind } => (collection, kind, None),
            Event::Received {
                collection,
                kind,
                landed,
            } => (collection, kind, Some(landed)),
        };
        if kind == WalkKind::References {
            return;
        }
        let Some(scheduled) = self.collections.get_mut(&collection.raw) else {
            return;
        };
        match landed {
            None => scheduled.receiving += 1,
            Some(landed) => {
                scheduled.receiving = scheduled.receiving.saturating_sub(1);
                if scheduled.receiving == 0 && std::mem::take(&mut scheduled.merged) && landed {
                    scheduled.schedule.local_changed(now, rand::random());
                }
            }
        }
    }

    /// When [`Self::poll`] next has work.
    pub(crate) fn deadline(&self) -> Option<Mono> {
        self.collections
            .values()
            .map(|scheduled| scheduled.schedule.deadline())
            .min()
    }

    /// The pushes to start: of each collection whose opportunity is due, its
    /// records and authorization trees to every neighbour this side sends
    /// to, and its references tree to those it replicates in full with.
    pub(crate) fn poll(&mut self, now: Mono) -> Vec<Start> {
        let mut starts = Vec::new();
        for (raw, scheduled) in &mut self.collections {
            if scheduled.schedule.deadline() > now || !scheduled.schedule.poll(now, rand::random())
            {
                continue;
            }
            let collection = CollectionHandle::new(*raw);
            for (peer, neighbour) in &scheduled.neighbours {
                if !neighbour.sends {
                    continue;
                }
                starts.push((*peer, collection, WalkKind::Records));
                starts.push((*peer, collection, WalkKind::Authorization));
                if neighbour.full {
                    starts.push((*peer, collection, WalkKind::References));
                }
            }
        }
        starts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

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

    fn link(id: u64, peer: PeerId) -> Link {
        Link::detached(id, peer).0
    }

    /// Poll `node` every step for `by`; the pushes started, in order.
    fn advance(node: &mut Schedules, now: &mut Mono, by: Duration) -> Vec<Start> {
        let until = *now + by;
        let mut starts = Vec::new();
        while *now < until {
            *now = *now + STEP;
            starts.extend(node.poll(*now));
        }
        starts
    }

    fn to(starts: &[Start], peer: PeerId) -> Vec<(CollectionHandle, WalkKind)> {
        starts
            .iter()
            .filter(|(to, _, _)| *to == peer)
            .map(|(_, collection, kind)| (*collection, *kind))
            .collect()
    }

    /// A timer's opportunity pushes the records and authorization trees to
    /// every neighbour this side sends to, and the references tree only to
    /// one it replicates the collection in full with. A neighbour this side
    /// does not send to gets nothing.
    #[test]
    fn an_opportunity_pushes_two_trees_to_each_sending_neighbour_and_three_to_a_full_one() {
        let c = collection(1);
        let mut now = crate::clock::mono_now();
        let mut node = Schedules::default();
        node.observe([(c, root(1))], now);
        let (a, b) = (link(1, A), link(2, B));
        node.neighbours([(c, &a, true, true), (c, &b, false, true)], now);
        let starts = advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(
            to(&starts, A),
            [
                (c, WalkKind::Records),
                (c, WalkKind::Authorization),
                (c, WalkKind::References)
            ]
        );
        assert!(to(&starts, B).is_empty());

        // B starts sending on demand: records and evidence only, within two
        // minimum intervals, at one or both of their opportunities.
        node.neighbours([(c, &a, true, true), (c, &b, true, false)], now);
        let starts = advance(&mut node, &mut now, Duration::from_secs(4));
        let to_b = to(&starts, B);
        assert!(!to_b.is_empty() && to_b.len() <= 4, "{to_b:?}");
        for pair in to_b.chunks(2) {
            assert_eq!(pair, [(c, WalkKind::Records), (c, WalkKind::Authorization)]);
        }
        assert_eq!(to(&starts, A).len() / 3, to_b.len() / 2);
    }

    #[test]
    fn a_busy_collection_pushes_every_two_seconds_beside_a_quiet_one() {
        let (busy, quiet) = (collection(3), collection(4));
        let start = crate::clock::mono_now();
        let mut node = Schedules::default();
        node.observe([(busy, root(0)), (quiet, root(0))], start);
        let peer = link(1, A);
        node.neighbours(
            [(busy, &peer, true, false), (quiet, &peer, true, false)],
            start,
        );
        let mut pushed = HashMap::<CollectionHandle, Vec<Duration>>::new();
        let mut now = start;
        for step in 1..=2_400_u32 {
            now = now + STEP;
            for (_, collection, kind) in node.poll(now) {
                if kind == WalkKind::Records {
                    pushed
                        .entry(collection)
                        .or_default()
                        .push(now.duration_since(start));
                }
            }
            // A local append to the busy collection every second.
            if step % 10 == 0 {
                node.observe([(busy, root(step)), (quiet, root(0))], now);
            }
        }
        let gaps = |collection| {
            pushed[&collection]
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

    /// A push from A lands here for fifty seconds without resetting the
    /// timer: B gets at most the push already due. Landing resets it once,
    /// and B gets the merged root.
    #[test]
    fn after_a_long_receive_lands_other_neighbours_get_one_push() {
        let c = collection(5);
        let mut now = crate::clock::mono_now();
        let mut node = Schedules::default();
        node.observe([(c, root(0))], now);
        let b = link(2, B);
        node.neighbours([(c, &b, true, false)], now);
        // Quiet long enough to reach sixty-second intervals.
        advance(&mut node, &mut now, Duration::from_secs(200));

        node.event(
            Event::Receiving {
                collection: c,
                kind: WalkKind::Records,
            },
            now,
        );
        let mut during = Vec::new();
        for landed in 1..=50 {
            during.extend(advance(&mut node, &mut now, Duration::from_secs(1)));
            node.observe([(c, root(landed))], now);
        }
        assert!(during.len() <= 2, "{during:?}");

        node.event(
            Event::Received {
                collection: c,
                kind: WalkKind::Records,
                landed: true,
            },
            now,
        );
        let starts = advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(
            to(&starts, B),
            [(c, WalkKind::Records), (c, WalkKind::Authorization)]
        );
        // Twelve seconds on, the interval has doubled past the minimum, so
        // a reset would move the deadline. A receive during which the root
        // did not change resets nothing, landed or not, a references receive
        // never counts, and a change during a receive that fails waits for
        // the next opportunity.
        advance(&mut node, &mut now, Duration::from_secs(12));
        for (kind, landed, changed) in [
            (WalkKind::Records, false, false),
            (WalkKind::Records, true, false),
            (WalkKind::References, true, false),
            (WalkKind::Records, false, true),
        ] {
            let deadline = node.deadline();
            node.event(
                Event::Receiving {
                    collection: c,
                    kind,
                },
                now,
            );
            if changed {
                node.observe([(c, root(100 + u32::from(landed)))], now);
            }
            node.event(
                Event::Received {
                    collection: c,
                    kind,
                    landed,
                },
                now,
            );
            assert_eq!(node.deadline(), deadline, "{kind:?} {landed} {changed}");
        }
        // A change during a receive that lands resets once it ends, even
        // when another receive is still running.
        let deadline = node.deadline();
        for kind in [WalkKind::Records, WalkKind::Authorization] {
            node.event(
                Event::Receiving {
                    collection: c,
                    kind,
                },
                now,
            );
        }
        node.observe([(c, root(200))], now);
        node.event(
            Event::Received {
                collection: c,
                kind: WalkKind::Authorization,
                landed: true,
            },
            now,
        );
        assert_eq!(node.deadline(), deadline);
        node.event(
            Event::Received {
                collection: c,
                kind: WalkKind::Records,
                landed: true,
            },
            now,
        );
        assert!(node.deadline() <= Some(now + Duration::from_secs(2)));
    }

    /// An unselected collection is scheduled no more, and a selected one
    /// starts within its first interval.
    #[test]
    fn selection_starts_and_stops_a_schedule() {
        let (c, d) = (collection(6), collection(7));
        let mut now = crate::clock::mono_now();
        let mut node = Schedules::default();
        node.observe([(c, root(0))], now);
        let a = link(1, A);
        node.neighbours([(c, &a, true, false), (d, &a, true, false)], now);
        assert!(node.deadline().is_some());
        let starts = advance(&mut node, &mut now, Duration::from_secs(2));
        assert_eq!(to(&starts, A).len(), 2);
        assert!(starts.iter().all(|(_, collection, _)| *collection == c));

        node.observe([(d, root(0))], now);
        node.neighbours([(c, &a, true, false), (d, &a, true, false)], now);
        let starts = advance(&mut node, &mut now, Duration::from_secs(2));
        assert!(starts.iter().all(|(_, collection, _)| *collection == d));
        node.observe([], now);
        assert_eq!(node.deadline(), None);
        assert!(advance(&mut node, &mut now, Duration::from_secs(60)).is_empty());
    }
}
