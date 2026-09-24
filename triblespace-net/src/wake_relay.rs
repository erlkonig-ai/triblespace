//! Bounded state-hint forwarding over a collection's neighbor mesh.
//!
//! Identity is the root, not the signed contact annotation. A first downstream
//! offer is independent of periodic duplicate suppression: an equal upstream
//! does not prove that a downstream neighbor heard anything. Repairs run in
//! the host concurrently; only a published serving root can replace the contact.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::clock::Mono;
use crate::wake::{CollectionWake, CollectionWakeRoot};

const REPAIR_OPPORTUNITY: Duration = Duration::from_secs(5);
const READY_OFFER_DELAY: Duration = Duration::from_secs(1);
const REPLAY_INTERVAL: Duration = Duration::from_secs(60);
const OFFER_LIFETIME: Duration = Duration::from_secs(300);
const MAX_ROOTS: usize = 128;

struct Offer {
    wake: CollectionWake,
    observed: Mono,
    relay_at: Mono,
}

/// At most one latest observation per serving contact, not a queue of roots.
/// Multiple contacts/nonces for one root share one replay obligation.
#[derive(Default)]
pub(crate) struct WakeRelay {
    offers: BTreeMap<iroh_base::EndpointId, Offer>,
    neighbors: BTreeMap<iroh_base::EndpointId, Option<CollectionWakeRoot>>,
}

pub(crate) enum RelayOffer {
    Local(CollectionWakeRoot),
    Original(CollectionWake),
}

impl WakeRelay {
    pub(crate) fn received_from(&mut self, wake: &CollectionWake, hop: iroh_base::EndpointId) {
        // A transport forwarder is not a holder. Only a signed offer by this
        // immediate neighbor demonstrates that it has the offered state.
        if wake.origin() == hop
            && (self.neighbors.len() < MAX_ROOTS || self.neighbors.contains_key(&hop))
        {
            self.neighbors.insert(hop, Some(wake.root()));
        }
    }

    pub(crate) fn neighbor_up(&mut self, peer: iroh_base::EndpointId, now: Mono) {
        if self.neighbors.len() < MAX_ROOTS || self.neighbors.contains_key(&peer) {
            self.neighbors.insert(peer, None);
        }
        self.neighbor_joined(now);
    }

    pub(crate) fn neighbor_down(&mut self, peer: iroh_base::EndpointId) {
        self.neighbors.remove(&peer);
    }

    pub(crate) fn observe(
        &mut self,
        wake: &CollectionWake,
        serving: Option<CollectionWakeRoot>,
        now: Mono,
    ) {
        self.expire(now);
        let prior_deadline = self.offers.get(&wake.origin()).map(|offer| offer.relay_at);
        if let Some(offer) = self.offers.get_mut(&wake.origin()) {
            if offer.wake.root() == wake.root() {
                // Annotation changes never renew the root episode or its
                // lease. Alternating old signed envelopes is not freshness.
                offer.wake = wake.clone();
                return;
            }
            self.offers.remove(&wake.origin());
        }
        if self.offers.len() == MAX_ROOTS {
            return;
        }
        let delay = if serving == Some(wake.root()) {
            READY_OFFER_DELAY
        } else {
            REPAIR_OPPORTUNITY
        };
        // Another contact for the same state shares its existing deadline,
        // including one already sent. It is not a fresh dissemination event.
        let (observed, relay_at) = self
            .offers
            .values()
            .find(|offer| offer.wake.root() == wake.root())
            .map_or((now, now + delay), |offer| (offer.observed, offer.relay_at));
        let relay_at = prior_deadline.map_or(relay_at, |prior| prior.min(relay_at));
        self.offers.insert(
            wake.origin(),
            Offer {
                wake: wake.clone(),
                observed,
                relay_at,
            },
        );
    }

    /// The store published a coherent new serving snapshot. This does not
    /// infer that a different root covers a pending upstream root.
    pub(crate) fn refreshed(&mut self, serving: Option<CollectionWakeRoot>, now: Mono) {
        for offer in self.offers.values_mut() {
            if serving == Some(offer.wake.root()) {
                offer.relay_at = offer.relay_at.min(now + READY_OFFER_DELAY);
            }
        }
    }

    /// New topology needs current retained observations, including when this
    /// node is only a read-only bridge and cannot originate a serving offer.
    pub(crate) fn neighbor_joined(&mut self, now: Mono) {
        self.expire(now);
        for offer in self.offers.values_mut() {
            offer.relay_at = offer.relay_at.min(now + READY_OFFER_DELAY);
        }
    }

    pub(crate) fn deadline(&self) -> Option<Mono> {
        self.offers.values().map(|offer| offer.relay_at).min()
    }

    /// Schedule one attempt at most per root per replay interval. Taking an
    /// offer is not proof of delivery; bounded replay repairs lost attempts.
    pub(crate) fn poll(
        &mut self,
        serving: Option<CollectionWakeRoot>,
        now: Mono,
    ) -> Vec<RelayOffer> {
        self.expire(now);
        let mut due = Vec::new();
        let mut roots = BTreeSet::new();
        for offer in self.offers.values_mut() {
            if now < offer.relay_at {
                continue;
            }
            offer.relay_at = now + REPLAY_INTERVAL;
            let root = offer.wake.root();
            if !roots.insert(root) {
                continue;
            }
            // Fully observed equal neighbors need no forced repeat. Missing
            // downstream evidence still gets recovery opportunities. This is
            // per-link knowledge, not the unsafe global k=1 inference.
            if !self.neighbors.is_empty()
                && self.neighbors.values().all(|known| *known == Some(root))
            {
                continue;
            }
            due.push(if serving == Some(root) {
                RelayOffer::Local(root)
            } else {
                RelayOffer::Original(offer.wake.clone())
            });
        }
        due
    }

    fn expire(&mut self, now: Mono) {
        self.offers
            .retain(|_, offer| now.duration_since(offer.observed) < OFFER_LIFETIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use triblespace_core::collection::CollectionHandle;

    fn wake(root: u8, origin: u8, nonce: u8) -> CollectionWake {
        CollectionWake::sign(
            CollectionHandle::new([1; 32]),
            CollectionWakeRoot::new([root; 32]),
            [nonce; 16],
            &SigningKey::from_bytes(&[origin; 32]),
        )
    }

    #[test]
    fn same_root_contact_changes_never_restart_the_episode() {
        let now = crate::clock::mono_now();
        let mut relay = WakeRelay::default();
        relay.observe(&wake(1, 2, 0), None, now);
        let deadline = relay.deadline().unwrap();
        for i in 0..100 {
            relay.observe(&wake(1, 3, i), None, now + Duration::from_millis(i as u64));
        }
        assert_eq!(relay.offers.len(), 2);
        assert_eq!(relay.deadline(), Some(deadline));
        let due = relay.poll(None, deadline);
        let [RelayOffer::Original(offer)] = due.as_slice() else {
            panic!("original fallback required")
        };
        assert!(
            offer.origin() == wake(1, 2, 0).origin() || offer.origin() == wake(1, 3, 99).origin()
        );
    }

    #[test]
    fn repairing_bridge_offers_its_actual_published_root() {
        let now = crate::clock::mono_now();
        let incoming = wake(2, 2, 0);
        let mut relay = WakeRelay::default();
        relay.observe(&incoming, None, now);
        let serving = Some(incoming.root());
        relay.refreshed(serving, now);
        // Equal upstream notices do not cancel the first downstream offer.
        relay.observe(&incoming, serving, now);
        assert!(
            matches!(relay.poll(serving, now + READY_OFFER_DELAY).as_slice(), [RelayOffer::Local(root)] if *root == incoming.root())
        );
        assert!(relay.poll(serving, now + READY_OFFER_DELAY).is_empty());
    }

    #[test]
    fn read_only_or_slow_bridge_preserves_original_contact_and_replays() {
        let now = crate::clock::mono_now();
        let incoming = wake(2, 2, 0);
        let mut relay = WakeRelay::default();
        relay.observe(&incoming, None, now);
        for i in 0..50 {
            relay.observe(&incoming, None, now + Duration::from_millis(i));
        }
        let due = now + REPAIR_OPPORTUNITY;
        assert!(
            matches!(relay.poll(None, due).as_slice(), [RelayOffer::Original(w)] if w == &incoming)
        );
        // The first attempt may be lost. No writes or fresh nonce required.
        assert!(
            matches!(relay.poll(None, due + REPLAY_INTERVAL).as_slice(), [RelayOffer::Original(w)] if w == &incoming)
        );
    }

    #[test]
    fn a_different_union_root_cannot_impersonate_the_original() {
        let now = crate::clock::mono_now();
        let incoming = wake(2, 2, 0);
        let serving = Some(CollectionWakeRoot::new([3; 32]));
        let mut relay = WakeRelay::default();
        relay.observe(&incoming, serving, now);
        relay.refreshed(serving, now);
        assert!(
            matches!(relay.poll(serving, now + REPAIR_OPPORTUNITY).as_slice(), [RelayOffer::Original(w)] if w == &incoming)
        );
    }

    #[test]
    fn duplicates_cannot_create_an_immediate_echo_or_unbounded_state() {
        let now = crate::clock::mono_now();
        let mut relay = WakeRelay::default();
        for r in 0..=255 {
            relay.observe(&wake(r, r, 0), None, now);
        }
        assert_eq!(relay.offers.len(), MAX_ROOTS);
        assert!(relay.poll(None, now).is_empty());
        let due = now + REPAIR_OPPORTUNITY;
        assert_eq!(relay.poll(None, due).len(), MAX_ROOTS);
        for r in 0..128 {
            relay.observe(&wake(r, r, 1), None, due);
        }
        assert!(relay.poll(None, due).is_empty());
    }

    #[test]
    fn unchanged_relay_does_not_renew_stale_offer_and_late_join_replays() {
        let now = crate::clock::mono_now();
        let incoming = wake(2, 2, 0);
        let mut relay = WakeRelay::default();
        relay.observe(&incoming, None, now);
        relay.poll(None, now + REPAIR_OPPORTUNITY);
        relay.neighbor_joined(now + Duration::from_secs(10));
        assert_eq!(relay.poll(None, now + Duration::from_secs(11)).len(), 1);
        relay.observe(&incoming, None, now + Duration::from_secs(299));
        assert!(relay.poll(None, now + OFFER_LIFETIME).is_empty());
        assert!(relay.offers.is_empty());
    }

    #[test]
    fn one_changing_origin_retains_only_its_latest_state() {
        let now = crate::clock::mono_now();
        let mut relay = WakeRelay::default();
        for root in 0..=255 {
            relay.observe(&wake(root, 2, 0), None, now);
        }
        assert_eq!(relay.offers.len(), 1);
        assert!(
            matches!(relay.poll(None, now + REPAIR_OPPORTUNITY).as_slice(), [RelayOffer::Original(w)] if w.root() == wake(255, 2, 0).root())
        );
    }

    #[test]
    fn equal_upstream_does_not_cover_downstream_but_all_equal_neighbors_suppress_replay() {
        let now = crate::clock::mono_now();
        let a = wake(2, 2, 0);
        let c = wake(2, 3, 0);
        let mut relay = WakeRelay::default();
        relay.neighbor_up(a.origin(), now);
        relay.neighbor_up(c.origin(), now);
        relay.observe(&a, Some(a.root()), now);
        relay.received_from(&a, a.origin());
        assert_eq!(relay.poll(Some(a.root()), now + READY_OFFER_DELAY).len(), 1);
        relay.received_from(&c, c.origin());
        assert!(
            relay
                .poll(Some(a.root()), now + REPLAY_INTERVAL + READY_OFFER_DELAY)
                .is_empty()
        );
        relay.neighbor_down(c.origin());
        relay.neighbor_up(c.origin(), now + REPLAY_INTERVAL);
        assert_eq!(
            relay
                .poll(Some(a.root()), now + REPLAY_INTERVAL + READY_OFFER_DELAY)
                .len(),
            1
        );
    }
}
