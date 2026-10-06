//! The landing task: what walks receive reaches the store here (design 2.5).
//!
//! One task per host lands the values of every walk in arrival order. It
//! inserts each drained group in one pass and publishes one serving snapshot,
//! so later leaves of every walk see what landed, and then tells each walk how
//! many of its values landed and how many inserts failed. The store side
//! installs the [`Land`] that does the inserting, holding its own store
//! handle; the host never holds the store.
//!
//! The task also reobserves the store every [`REOBSERVE_INTERVAL`], so that
//! appends by other processes reach the serving snapshot.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::channel::{MAX_ADMISSION_BATCH_ITEMS, NetEvent};

/// How often the store is reobserved for appends made elsewhere.
pub(crate) const REOBSERVE_INTERVAL: Duration = Duration::from_secs(2);

/// The store side of landing.
pub(crate) trait Land: Send + Sync + 'static {
    /// Insert each event, then publish one serving snapshot. Returns, per
    /// event, whether it landed.
    fn land(&self, events: Vec<NetEvent>) -> Vec<bool>;

    /// Publish a serving snapshot if the store changed since the last one.
    fn reobserve(&self);
}

/// Where the store side installs its [`Land`].
pub(crate) type LandSlot = watch::Receiver<Option<Arc<dyn Land>>>;

/// What landed of one walk's values since its last acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Landed<K> {
    pub(crate) key: K,
    pub(crate) landed: u64,
    pub(crate) failed: u64,
}

/// Land `items`, each a walk's key and its values, and acknowledge them on
/// `acks`, until either channel closes. Nothing lands before the store side
/// installs its [`Land`]; the items wait.
pub(crate) async fn run<K>(
    mut slot: LandSlot,
    mut items: mpsc::UnboundedReceiver<(K, Vec<NetEvent>)>,
    acks: mpsc::UnboundedSender<Landed<K>>,
) where
    K: Copy + Eq + Hash + Send + 'static,
{
    let mut reobserve = tokio::time::interval(REOBSERVE_INTERVAL);
    reobserve.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The slot is read afresh each time: the store side's handle must not
        // outlive the store side through this task.
        let mut group = Vec::new();
        tokio::select! {
            item = items.recv() => {
                let Some(item) = item else {
                    return;
                };
                group.push(item);
            }
            _ = reobserve.tick() => {
                let Some(lander) = slot.borrow().clone() else {
                    continue;
                };
                if tokio::task::spawn_blocking(move || lander.reobserve()).await.is_err() {
                    return;
                }
                continue;
            }
        }
        let mut events = group[0].1.len();
        while events < MAX_ADMISSION_BATCH_ITEMS
            && let Ok(item) = items.try_recv()
        {
            events += item.1.len();
            group.push(item);
        }
        let Ok(lander) = slot
            .wait_for(Option::is_some)
            .await
            .map(|lander| lander.clone())
        else {
            return;
        };
        let lander = lander.expect("waited for an installed lander");
        let keys = group
            .iter()
            .map(|(key, events)| (*key, events.len()))
            .collect::<Vec<_>>();
        let events = group.into_iter().flat_map(|(_, events)| events).collect();
        let Ok(landed) = tokio::task::spawn_blocking(move || lander.land(events)).await else {
            return;
        };
        let mut landed = landed.into_iter();
        let mut counts = HashMap::<K, (u64, u64)>::new();
        for (key, events) in keys {
            let count = counts.entry(key).or_default();
            for ok in landed.by_ref().take(events) {
                if ok {
                    count.0 += 1;
                } else {
                    count.1 += 1;
                }
            }
        }
        for (key, (landed, failed)) in counts {
            if acks
                .send(Landed {
                    key,
                    landed,
                    failed,
                })
                .is_err()
            {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use ed25519_dalek::SigningKey;
    use triblespace_core::capability::{CapabilityProof, CapabilityResource};
    use triblespace_core::collection::{
        CollectionCommit, CollectionData, CollectionHandle, CollectionRecord,
        empty_metadata_handle, read_capability,
    };

    /// Lands records, fails every other event, and counts reobservations.
    #[derive(Default)]
    struct Recorder {
        landed: Mutex<Vec<usize>>,
        reobserved: Mutex<usize>,
    }

    impl Land for Recorder {
        fn land(&self, events: Vec<NetEvent>) -> Vec<bool> {
            self.landed.lock().unwrap().push(events.len());
            events
                .iter()
                .map(|event| matches!(event, NetEvent::CollectionRecord(_)))
                .collect()
        }

        fn reobserve(&self) {
            *self.reobserved.lock().unwrap() += 1;
        }
    }

    fn record(byte: u8) -> NetEvent {
        NetEvent::CollectionRecord(CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[1; 32]),
            CollectionHandle::new([2; 32]),
            CollectionData::new([byte; 32]),
            empty_metadata_handle(),
        )))
    }

    /// Items queued before the store side installs its lander land once it
    /// does, in one group, and each walk hears its own counts.
    #[tokio::test(start_paused = true)]
    async fn queued_items_land_once_installed_and_each_walk_hears_its_counts() {
        let (install, slot) = watch::channel(None::<Arc<dyn Land>>);
        let (items, queued) = mpsc::unbounded_channel();
        let (acks, mut heard) = mpsc::unbounded_channel();
        tokio::spawn(run(slot, queued, acks));
        items.send((1_u8, vec![record(0), record(1)])).unwrap();
        items.send((2_u8, vec![record(2)])).unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::new([3; 32]),
            &SigningKey::from_bytes(&[4; 32]),
            read_capability(),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
        );
        items
            .send((1_u8, vec![NetEvent::CapabilityProof(proof)]))
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(heard.try_recv().is_err(), "nothing lands without a lander");

        let recorder = Arc::new(Recorder::default());
        install.send_replace(Some(recorder.clone()));
        let mut counts = [heard.recv().await.unwrap(), heard.recv().await.unwrap()];
        counts.sort_unstable_by_key(|landed| landed.key);
        assert_eq!(
            counts,
            [
                Landed {
                    key: 1,
                    landed: 2,
                    failed: 1
                },
                Landed {
                    key: 2,
                    landed: 1,
                    failed: 0
                }
            ]
        );
        assert_eq!(*recorder.landed.lock().unwrap(), [4]);

        tokio::time::sleep(REOBSERVE_INTERVAL * 3).await;
        assert!(*recorder.reobserved.lock().unwrap() >= 2);
    }
}
