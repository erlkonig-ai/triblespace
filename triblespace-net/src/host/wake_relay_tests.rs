//! Host-scheduler proof on a forced A—B—C line, not an Iroh topology test.
//!
//! A supplies controlled signed observations, B runs the actual
//! `spawn_wake_topic`, and C records neighbor delivery. Only the test may
//! publish B's repaired serving snapshot. The transport never forwards and
//! cannot create an A—C shortcut, even when a signed origin is learned.
//! Real-Iroh wire/relay tests live in `wake::tests`.
//!
//! These tests use bounded real time: the process-global core clock cannot
//! safely be replaced in this shared unit-test binary. The lost-first-offer
//! test deliberately waits through the production 60-second replay interval.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use iroh_gossip::proto::DeliveryScope;
use tokio::sync::{Notify, mpsc};
use triblespace_core::collection::CollectionHandle;

use super::{WakeNotice, WakeTopic, spawn_wake_topic};
use crate::wake::{
    CollectionWake, CollectionWakeEvent, CollectionWakeNetwork, CollectionWakeRoot,
    CollectionWakeSubscription, ReceivedCollectionWake,
};

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const CHANNEL_CAPACITY: usize = 128;
const ATTEMPT_CAPACITY: usize = 256;

struct Attempt {
    from: usize,
    to: usize,
    wake: CollectionWake,
    at: Instant,
    dropped: bool,
}

struct State {
    inboxes: [Option<mpsc::Sender<CollectionWakeEvent>>; 3],
    c_connected: bool,
    drop_first_b_to_c: bool,
    attempts: VecDeque<Attempt>,
}

#[derive(Clone)]
struct Line {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    keys: [Arc<SigningKey>; 3],
    collection: CollectionHandle,
}

impl Line {
    fn new(c_connected: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                inboxes: std::array::from_fn(|_| None),
                c_connected,
                drop_first_b_to_c: false,
                attempts: VecDeque::new(),
            })),
            changed: Arc::new(Notify::new()),
            keys: [21, 22, 23].map(|byte| Arc::new(SigningKey::from_bytes(&[byte; 32]))),
            collection: CollectionHandle::new([24; 32]),
        }
    }

    fn id(&self, node: usize) -> EndpointId {
        EndpointId::from_bytes(self.keys[node].verifying_key().as_bytes()).unwrap()
    }

    fn adjacent(state: &State, from: usize, to: usize) -> bool {
        matches!((from, to), (A, B) | (B, A))
            || (state.c_connected && matches!((from, to), (B, C) | (C, B)))
    }

    fn offer(&self, node: usize, root: CollectionWakeRoot) -> CollectionWake {
        CollectionWake::sign(self.collection, root, [25; 16], &self.keys[node])
    }

    fn deliver(&self, from: usize, wake: &CollectionWake) -> anyhow::Result<()> {
        wake.verify(self.collection)?;
        let mut state = self.state.lock().unwrap();
        for to in 0..3 {
            if !Self::adjacent(&state, from, to) {
                continue;
            }
            let Some(inbox) = state.inboxes[to].clone() else {
                continue;
            };
            let dropped = from == B && to == C && state.drop_first_b_to_c;
            if dropped {
                state.drop_first_b_to_c = false;
            } else {
                inbox
                    .try_send(CollectionWakeEvent::Received(ReceivedCollectionWake {
                        wake: wake.clone(),
                        delivered_from: self.id(from),
                        scope: DeliveryScope::Neighbors,
                    }))
                    .expect("bounded fixture inbox must not overflow or disappear");
            }
            if state.attempts.len() == ATTEMPT_CAPACITY {
                state.attempts.pop_front();
            }
            state.attempts.push_back(Attempt {
                from,
                to,
                wake: wake.clone(),
                at: Instant::now(),
                dropped,
            });
        }
        drop(state);
        self.changed.notify_one();
        Ok(())
    }

    fn connect_c(&self) {
        let mut state = self.state.lock().unwrap();
        assert!(!state.c_connected);
        state.c_connected = true;
        for (node, neighbor) in [(B, C), (C, B)] {
            state.inboxes[node]
                .as_ref()
                .expect("both endpoints exist before healing topology")
                .try_send(CollectionWakeEvent::NeighborUp(self.id(neighbor)))
                .unwrap();
        }
        drop(state);
        self.changed.notify_one();
    }

    async fn wait_for(&self, bound: Duration, condition: impl Fn(&State) -> bool) {
        tokio::time::timeout(bound, async {
            loop {
                if condition(&self.state.lock().unwrap()) {
                    return;
                }
                self.changed.notified().await;
            }
        })
        .await
        .expect("fixture positive control did not occur within its bound");
    }
}

#[derive(Clone)]
struct Plane {
    line: Line,
    node: usize,
}

struct Topic {
    plane: Plane,
    events: mpsc::Receiver<CollectionWakeEvent>,
}

impl CollectionWakeNetwork for Plane {
    type Topic = Topic;

    async fn subscribe_network(
        &self,
        collection: CollectionHandle,
        _bootstrap: Vec<EndpointId>,
    ) -> anyhow::Result<Topic> {
        assert_eq!(collection, self.line.collection);
        let (tx, events) = mpsc::channel(CHANNEL_CAPACITY);
        let mut state = self.line.state.lock().unwrap();
        assert!(state.inboxes[self.node].is_none(), "no fixture restarts");
        state.inboxes[self.node] = Some(tx.clone());
        for neighbor in 0..3 {
            if !Line::adjacent(&state, self.node, neighbor) {
                continue;
            }
            if let Some(other) = &state.inboxes[neighbor] {
                tx.try_send(CollectionWakeEvent::NeighborUp(self.line.id(neighbor)))
                    .unwrap();
                other
                    .try_send(CollectionWakeEvent::NeighborUp(self.line.id(self.node)))
                    .unwrap();
            }
        }
        drop(state);
        self.line.changed.notify_one();
        Ok(Topic {
            plane: self.clone(),
            events,
        })
    }
}

impl CollectionWakeSubscription for Topic {
    async fn join_wake_peers(&self, _peers: Vec<EndpointId>) -> anyhow::Result<()> {
        // Learning A's signed origin at C must not create a physical shortcut.
        Ok(())
    }

    async fn broadcast_wake(&self, root: CollectionWakeRoot) -> anyhow::Result<CollectionWake> {
        let wake = self.plane.line.offer(self.plane.node, root);
        self.plane.line.deliver(self.plane.node, &wake)?;
        Ok(wake)
    }

    async fn relay_wake(&self, wake: &CollectionWake) -> anyhow::Result<()> {
        self.plane.line.deliver(self.plane.node, wake)
    }

    async fn next_wake_event(&mut self) -> anyhow::Result<Option<CollectionWakeEvent>> {
        Ok(self.events.recv().await)
    }
}

impl Drop for Topic {
    fn drop(&mut self) {
        self.plane.line.state.lock().unwrap().inboxes[self.plane.node] = None;
    }
}

struct Fixture {
    line: Line,
    b: WakeTopic,
    notices: mpsc::Receiver<WakeNotice>,
    _a: Topic,
    c: Topic,
}

impl Fixture {
    async fn new(advertise: bool, c_connected: bool) -> Self {
        let line = Line::new(c_connected);
        let a = Plane {
            line: line.clone(),
            node: A,
        }
        .subscribe_network(line.collection, Vec::new())
        .await
        .unwrap();
        let c = Plane {
            line: line.clone(),
            node: C,
        }
        .subscribe_network(line.collection, Vec::new())
        .await
        .unwrap();
        let (notices_tx, notices) = mpsc::channel(CHANNEL_CAPACITY);
        let b = spawn_wake_topic(
            Plane {
                line: line.clone(),
                node: B,
            },
            line.collection,
            advertise,
            vec![line.id(A)],
            notices_tx,
        );
        line.wait_for(Duration::from_secs(2), |state| state.inboxes[B].is_some())
            .await;
        Self {
            line,
            b,
            notices,
            _a: a,
            c,
        }
    }

    async fn receive_at_b(&mut self, offer: &CollectionWake) {
        self.line.deliver(A, offer).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let WakeNotice::Received {
                    collection,
                    received,
                } = self
                    .notices
                    .recv()
                    .await
                    .expect("B's actual topic task must stay alive")
                {
                    assert_eq!(collection, self.line.collection);
                    if received.wake == *offer {
                        assert_eq!(received.delivered_from, self.line.id(A));
                        return;
                    }
                }
            }
        })
        .await
        .expect("B must observe the upstream root before the test changes its snapshot");
    }

    async fn receive_at_c(
        &mut self,
        root: CollectionWakeRoot,
        bound: Duration,
    ) -> ReceivedCollectionWake {
        tokio::time::timeout(bound, async {
            loop {
                if let CollectionWakeEvent::Received(received) = self
                    .c
                    .next_wake_event()
                    .await
                    .unwrap()
                    .expect("C's receiver must stay alive")
                    && received.wake.root() == root
                {
                    assert_eq!(received.delivered_from, self.line.id(B));
                    assert_eq!(received.scope, DeliveryScope::Neighbors);
                    return received;
                }
            }
        })
        .await
        .expect("C must receive the root across B within the bound")
    }
}

#[tokio::test]
async fn repaired_bridge_publishes_its_contact_before_fallback_despite_equal_upstream() {
    let mut fixture = Fixture::new(true, true).await;
    let root = CollectionWakeRoot::new([31; 32]);
    let offered = fixture.line.offer(A, root);
    fixture.b.observe(Some(CollectionWakeRoot::new([30; 32])));
    fixture.receive_at_b(&offered).await;
    let repaired_at = Instant::now();
    // This is the sole simulated repair: publish the actual resulting snapshot.
    fixture.b.observe(Some(root));
    for _ in 0..12 {
        fixture.line.deliver(A, &offered).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let received = fixture.receive_at_c(root, Duration::from_secs(3)).await;
    assert_eq!(received.wake.origin(), fixture.line.id(B));
    assert_eq!(received.wake.dedup_id(), offered.dedup_id());
    assert!(repaired_at.elapsed() < Duration::from_secs(4));
    assert!(
        fixture
            .line
            .state
            .lock()
            .unwrap()
            .attempts
            .iter()
            .all(|attempt| {
                attempt.to != C
                    || attempt.wake.root() != root
                    || attempt.wake.origin() == fixture.line.id(B)
            })
    );
}

async fn fallback_crosses_line_without_repair(advertise: bool) {
    let mut fixture = Fixture::new(advertise, true).await;
    let root = CollectionWakeRoot::new([41; 32]);
    let offered = fixture.line.offer(A, root);
    // A nonserving reader can hold R without offering itself. A failed serving
    // repair remains at a different root and may only relay the original offer.
    fixture.b.observe(Some(if advertise {
        CollectionWakeRoot::new([40; 32])
    } else {
        root
    }));
    let start = Instant::now();
    fixture.receive_at_b(&offered).await;
    for _ in 0..55 {
        fixture.line.deliver(A, &offered).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let received = fixture.receive_at_c(root, Duration::from_secs(1)).await;
    assert_eq!(received.wake.to_bytes(), offered.to_bytes());
    assert_ne!(received.wake.origin(), received.delivered_from);
    let state = fixture.line.state.lock().unwrap();
    let first = state
        .attempts
        .iter()
        .find(|attempt| attempt.from == B && attempt.to == C && attempt.wake.root() == root)
        .unwrap();
    assert!(
        first.at.duration_since(start) <= Duration::from_secs(7),
        "five-second fallback plus two-second scheduler margin"
    );
}

#[tokio::test]
async fn read_only_bridge_relays_original_despite_repeated_equal_upstream() {
    fallback_crosses_line_without_repair(false).await;
}

#[tokio::test]
async fn failed_repair_bridge_relays_original_without_waiting_for_success() {
    fallback_crosses_line_without_repair(true).await;
}

#[tokio::test]
async fn lost_first_relay_is_replayed_without_new_write_nonce_or_restart() {
    let mut fixture = Fixture::new(false, true).await;
    let root = CollectionWakeRoot::new([51; 32]);
    let offered = fixture.line.offer(A, root);
    fixture.line.state.lock().unwrap().drop_first_b_to_c = true;
    fixture.receive_at_b(&offered).await;
    fixture
        .line
        .wait_for(Duration::from_secs(7), |state| {
            state.attempts.iter().any(|attempt| {
                attempt.from == B && attempt.to == C && attempt.wake == offered && attempt.dropped
            })
        })
        .await;
    // Neither another observation nor a snapshot update is supplied. The
    // first attempt's loss is repaired solely by B's retained replay deadline.
    let received = fixture.receive_at_c(root, Duration::from_secs(63)).await;
    assert_eq!(received.wake.to_bytes(), offered.to_bytes());
    let state = fixture.line.state.lock().unwrap();
    let attempts: Vec<_> = state
        .attempts
        .iter()
        .filter(|attempt| attempt.from == B && attempt.to == C && attempt.wake.root() == root)
        .collect();
    assert_eq!(attempts.len(), 2);
    assert!(attempts[0].dropped);
    assert!(!attempts[1].dropped);
    assert!(attempts[1].at.duration_since(attempts[0].at) <= Duration::from_secs(63));
}

#[tokio::test]
async fn late_downstream_neighbor_gets_retained_offer_without_a_new_upstream_wake() {
    let mut fixture = Fixture::new(false, false).await;
    let root = CollectionWakeRoot::new([61; 32]);
    let offered = fixture.line.offer(A, root);
    fixture.receive_at_b(&offered).await;
    // The first fallback opportunity can be suppressed: A is the only known
    // neighbor and has itself signed this root. That redundant upstream echo
    // is not a prerequisite for retaining state for a later downstream join.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        fixture.c.events.try_recv().is_err(),
        "C has no A shortcut or B link yet"
    );
    fixture.line.connect_c();
    let received = fixture.receive_at_c(root, Duration::from_secs(3)).await;
    assert_eq!(received.wake.to_bytes(), offered.to_bytes());
}
