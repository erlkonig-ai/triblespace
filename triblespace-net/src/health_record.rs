//! Local, append-only observations of a network host, not another sync protocol.
//!
//! A reporter publishes into a deliberately unreplicated collection. A reader
//! selects the latest report per observer, applies its own maximum sample age,
//! then queries the conditions it names. Thus broken replication cannot hide
//! its own warning.
//! Reports are observations, not promises about an entire unknown swarm or the
//! residency of every blob. All IDs below were minted with `trible genid` on
//! 2026-09-09; attributes use encoding-derived, not literal-pinned identities.

use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use hifitime::Epoch;
use triblespace_core::collection::CollectionHandle;
use triblespace_core::macros::{attributes, entity, id_hex};
use triblespace_core::metadata;
use triblespace_core::prelude::*;

pub const COLLECTION_NAME: &str = "swarm-health";
pub const DEFAULT_SCOPE_ID: Id = id_hex!("CF3A399CA5EB9BAAD5EF283002F5A4D3");
pub const KIND_REPORT: Id = id_hex!("D470B317FA1790BDB89C3D47921A4EEC");
pub const KIND_CONDITION: Id = id_hex!("6B8ECE083B6F850837A71FFE3ED155DA");
pub const KIND_ALERT: Id = id_hex!("50A83054AEDA2C4696137E4B61BC0701");
pub const KIND_RECOVERED: Id = id_hex!("83A44BA6C6BE2B782521A19418C0C9ED");
pub const HOST: Id = id_hex!("2F1E16D4B71DA46FB54F6A77E40E7BCA");
pub const STORE: Id = id_hex!("166B05676A0FE4BC203378C4E71B60EE");
pub const COLLECTION: Id = id_hex!("2FB954F7D9CC495DF420C9842E042409");
pub const DHT: Id = id_hex!("5E9E10B93F3D2C8A44AE94269B3E5EB8");
pub const CURRENT: Id = id_hex!("7550149E20D8658EB657FA51808D6797");
pub const PROGRESSING: Id = id_hex!("439306D0EA812CC42BA0113545FBBF4B");
pub const UNKNOWN: Id = id_hex!("1627047B72FDB5B071ABBC51C664909E");
pub const STALLED: Id = id_hex!("1DE9C9CA3F8A012F4EF2BDBA468BB9A5");

pub mod attrs {
    use super::*;

    attributes! {
        /// Observer anchor; its endpoint key is a separate queryable fact.
        "7021AD1FB8034F9ADB2A817B06B65498" as node: inlineencodings::GenId;
        "B96FB346494598B4EC8ADAF66DE8BE33" as endpoint: inlineencodings::ED25519PublicKey;
        /// One reporter process lifetime, not a replicated mutable generation.
        "54C94AC6FE045AA34AEF42BD522DBFA6" as session: inlineencodings::GenId;
        "FC4308E9B8914E09E38455F49FA0EA69" as collection: inlineencodings::Handle<blobencodings::SimpleArchive>;
        "898F9988C3C1628C3289C1D37174FF9B" as peer: inlineencodings::ED25519PublicKey;
        /// Report -> current condition episode (repeated).
        "1564F6960F06D906CD895A9D3C8522F4" as condition: inlineencodings::GenId;
        "FA15D65DEA8480F799AD9210D516DF16" as state: inlineencodings::GenId;
    }
}

/// One component of a local observation; no global health bit is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Component {
    Host,
    Store,
    Collection,
    Dht,
}

impl Component {
    pub fn tag(self) -> Id {
        match self {
            Self::Host => HOST,
            Self::Store => STORE,
            Self::Collection => COLLECTION,
            Self::Dht => DHT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Current,
    Progressing,
    Unknown,
    Stalled,
}

impl State {
    pub fn tag(self) -> Id {
        match self {
            Self::Current => CURRENT,
            Self::Progressing => PROGRESSING,
            Self::Unknown => UNKNOWN,
            Self::Stalled => STALLED,
        }
    }
}

/// One fresh measurement supplied by the network observer, not loaded state.
#[derive(Clone, Debug)]
pub struct Condition {
    pub component: Component,
    pub collection: Option<CollectionHandle>,
    pub peer: Option<VerifyingKey>,
    pub state: State,
    /// An actionable condition, after any startup/recovery grace period.
    pub alert: bool,
}

/// Conservative reporting policy for a continuously running replica. These
/// durations are observer policy, not part of the collection or wire algebra.
pub const REPORT_EVERY: Duration = Duration::from_secs(60);
/// Default reader/comparison policy, not a lifetime asserted by the reporter.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(180);
pub const HOST_MAX_AGE: Duration = Duration::from_secs(30);
/// Two complete repair deadlines allow a cold/startup repair to finish.
pub const PROGRESS_GRACE: Duration = Duration::from_secs(600);

/// Interpret bounded runtime evidence, without causing any network work.
///
/// Comparisons are per recently observed participant, never an assertion that
/// every node in a globally enumerable swarm has the same data. A received
/// delta is not a durability receipt. Repeated identical replies and unrelated
/// local writes cannot postpone a stalled-peer warning.
pub fn conditions(
    health: &crate::health::HealthSnapshot,
    now: crate::clock::Mono,
) -> Vec<Condition> {
    use crate::health::ComparisonState;

    let within = |at: Option<crate::clock::Mono>, duration| {
        at.is_some_and(|at| at <= now && now.duration_since(at) <= duration)
    };
    let starting = within(health.started_at, PROGRESS_GRACE);
    let host_fresh = health.is_fresh(now, HOST_MAX_AGE);
    let mut conditions = vec![Condition {
        component: Component::Host,
        collection: None,
        peer: None,
        state: if host_fresh {
            State::Current
        } else {
            State::Unknown
        },
        alert: !host_fresh
            && health.started_at.is_some()
            && !within(health.started_at, HOST_MAX_AGE),
    }];
    let store_current = health.store.serving_snapshot
        && !health.store.pending_flush
        && within(health.store.last_snapshot_observed_at, HOST_MAX_AGE)
        && health.store.last_failure_at <= health.store.last_snapshot_observed_at;
    conditions.push(Condition {
        component: Component::Store,
        collection: None,
        peer: None,
        state: if store_current {
            State::Current
        } else {
            State::Unknown
        },
        alert: !store_current && !starting,
    });

    for collection in &health.collections {
        if collection.peers.is_empty()
            || health.direction.is_some_and(|direction| !direction.pulls())
        {
            conditions.push(Condition {
                component: Component::Collection,
                collection: Some(collection.collection),
                peer: None,
                state: State::Unknown,
                alert: !starting && health.direction.is_some_and(|direction| direction.pulls()),
            });
        }
        for peer in &collection.peers {
            let remote_progress = within(peer.last_remote_change_at, PROGRESS_GRACE);
            let peer_starting = within(peer.first_started_at, PROGRESS_GRACE);
            let comparison =
                health.comparison(collection.collection, peer.peer, now, DEFAULT_MAX_AGE);
            let state = match comparison {
                ComparisonState::Matching => State::Current,
                ComparisonState::Different if remote_progress || peer_starting => {
                    State::Progressing
                }
                ComparisonState::Different => State::Stalled,
                ComparisonState::Unknown | ComparisonState::NotApplicable => State::Unknown,
            };
            let measured_recently = within(
                peer.comparison.map(|comparison| comparison.observed_at),
                PROGRESS_GRACE,
            );
            // Comparison age alone is scheduler/observation churn. It becomes
            // actionable only when the latest completed pull actually failed;
            // a later success supersedes the retained historical failure.
            let latest_repair_failed =
                peer.last_failure_at.is_some() && peer.last_failure_at == peer.last_completed_at;
            // Unrelated local writes cannot disguise persistent divergence.
            let alert = comparison != ComparisonState::NotApplicable
                && !peer_starting
                && (state == State::Stalled || (!measured_recently && latest_repair_failed));
            conditions.push(Condition {
                component: Component::Collection,
                collection: Some(collection.collection),
                peer: Some(
                    VerifyingKey::from_bytes(&peer.peer)
                        .expect("transport peer keys are validated Ed25519 points"),
                ),
                state,
                alert,
            });
        }
    }

    let publication = &health.publication;
    let acknowledged = within(publication.last_acknowledged_at, PROGRESS_GRACE);
    let pending =
        publication.startup_pending + publication.incremental_pending + publication.retry_pending;
    let expected = publication.resident > 0 && !publication.budget_exhausted;
    // Renewal is paced over hours. Silence while idle is not a failed probe;
    // only a continuous observed failure episode earns a stall warning.
    let outstanding = pending > 0 || publication.in_flight > 0;
    let no_progress_since = publication.unacknowledged_since.or_else(|| {
        outstanding
            .then_some(
                publication
                    .last_started_at
                    .max(publication.last_acknowledged_at)
                    .or(health.started_at),
            )
            .flatten()
    });
    let failed =
        no_progress_since.is_some_and(|at| at <= now && now.duration_since(at) > PROGRESS_GRACE);
    conditions.push(Condition {
        component: Component::Dht,
        collection: None,
        peer: None,
        state: if !expected {
            State::Unknown
        } else if acknowledged && !outstanding {
            State::Current
        } else if acknowledged || (outstanding && !failed) {
            State::Progressing
        } else if failed {
            State::Stalled
        } else {
            State::Unknown
        },
        alert: expected && failed,
    });
    conditions
}

type Subject = (Component, Option<[u8; 32]>, Option<[u8; 32]>);

#[derive(Clone)]
struct Episode {
    state: State,
    alert: bool,
    facts: Fragment,
}

/// Turns a process's own observations into facts. Only unchanged condition
/// episodes are retained in memory, so periodic heartbeats do not generate a
/// new Orient alert each time. Nothing is reconstructed into a shadow catalog.
pub struct Recorder {
    node: Fragment,
    session: Id,
    episodes: BTreeMap<Subject, Episode>,
}

impl Recorder {
    pub fn new(endpoint: VerifyingKey) -> Self {
        Self {
            node: entity! { attrs::endpoint: endpoint },
            session: genid().forget(),
            episodes: BTreeMap::new(),
        }
    }

    /// Construct one heartbeat and its current conditions. Callers publish
    /// this whole fragment with their explicit local reporting signer.
    ///
    /// The report records only its creation time. Readers decide when its age
    /// makes it a stale-report attention event; producer expiry annotations do
    /// not control that policy. A fresh report uses its ALERT/RECOVERED IDs.
    /// Readers never need to invent an event identity or hash one for lookup.
    pub fn record(
        &mut self,
        at: Epoch,
        conditions: impl IntoIterator<Item = Condition>,
    ) -> anyhow::Result<Fragment> {
        let created = point(at)?;
        let mut next = BTreeMap::new();
        for condition in conditions {
            let subject = (
                condition.component,
                condition.collection.map(|handle| handle.raw),
                condition.peer.map(|key| key.to_bytes()),
            );
            let previous = self.episodes.get(&subject);
            let episode = match previous {
                Some(previous)
                    if previous.state == condition.state && previous.alert == condition.alert =>
                {
                    previous.clone()
                }
                _ => {
                    // Recovery is evidence of a previously reported failure,
                    // not an alert on an ordinary healthy startup.
                    let recovered = previous.is_some_and(|episode| episode.alert)
                        && !condition.alert
                        && condition.state == State::Current;
                    let tags = [
                        Some(KIND_CONDITION),
                        Some(condition.component.tag()),
                        condition.alert.then_some(KIND_ALERT),
                        recovered.then_some(KIND_RECOVERED),
                    ];
                    Episode {
                        state: condition.state,
                        alert: condition.alert,
                        facts: entity! {
                            metadata::tag*: tags.into_iter().flatten(),
                            attrs::node*: self.node.clone(),
                            attrs::session: &self.session,
                            attrs::collection?: condition.collection,
                            attrs::peer?: condition.peer,
                            attrs::state: &condition.state.tag(),
                            metadata::started_at: created,
                        },
                    }
                }
            };
            next.insert(subject, episode);
        }
        self.episodes = next;
        let mut current = Fragment::empty();
        for episode in self.episodes.values() {
            current += episode.facts.clone();
        }
        Ok(entity! {
            metadata::tag: &KIND_REPORT,
            attrs::node*: self.node.clone(),
            attrs::session: &self.session,
            metadata::created_at: created,
            attrs::condition*: current,
        })
    }
}

fn point(epoch: Epoch) -> anyhow::Result<Inline<inlineencodings::NsTAIInterval>> {
    (epoch, epoch)
        .try_to_inline()
        .map_err(|error| anyhow::anyhow!("encode health observation time: {error:?}"))
}

/// Queryable names for health tags, published alongside the first report.
pub fn vocabulary() -> Fragment {
    let mut facts = Fragment::empty();
    for (id, name) in [
        (KIND_REPORT, "swarm health report"),
        (KIND_CONDITION, "swarm health condition"),
        (KIND_ALERT, "needs attention"),
        (KIND_RECOVERED, "recovered"),
        (HOST, "network event loop"),
        (STORE, "local serving snapshot"),
        (COLLECTION, "collection record/proof repair"),
        (DHT, "DHT provider publication"),
        (CURRENT, "current"),
        (PROGRESSING, "catching up"),
        (UNKNOWN, "unknown"),
        (STALLED, "stalled"),
    ] {
        facts += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name };
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace_core::macros::{find, pattern};

    fn observed(at: crate::clock::Mono) -> crate::health::HealthSnapshot {
        crate::health::HealthSnapshot {
            node: iroh_base::SecretKey::from_bytes(&[5; 32]).public().into(),
            direction: Some(crate::inventory::ReconcileDirection::Bidirectional),
            started_at: Some(at),
            observed_at: Some(at),
            store: crate::health::StoreHealth {
                last_snapshot_observed_at: Some(at),
                serving_snapshot: true,
                ..Default::default()
            },
            collections: Vec::new(),
            publication: crate::health::PublicationHealth::default(),
        }
    }

    #[test]
    fn fresh_reporting_cannot_disguise_an_unpolled_host() {
        let at = crate::clock::mono_now();
        let mut health = observed(at);
        health.observed_at = None;
        let startup = super::conditions(&health, at + Duration::from_secs(1));
        let host = startup
            .iter()
            .find(|c| c.component == Component::Host)
            .unwrap();
        assert_eq!(host.state, State::Unknown);
        assert!(
            !host.alert,
            "give the loop time to publish its first observation"
        );
        let conditions = super::conditions(&health, at + Duration::from_secs(31));
        let host = conditions
            .iter()
            .find(|c| c.component == Component::Host)
            .unwrap();
        assert_eq!(host.state, State::Unknown);
        assert!(host.alert);
    }

    #[test]
    fn fresh_local_writes_and_identical_remote_replies_cannot_hide_a_stalled_pair() {
        use crate::health::{CollectionHealth, Health, RepairComparison, RepairFrontier};
        use crate::patch_repair::PatchSummary;

        let at = crate::clock::mono_now();
        let now = at + PROGRESS_GRACE + Duration::from_secs(1);
        let mut sample = observed(at);
        sample.observed_at = Some(now);
        sample.store.last_snapshot_observed_at = Some(now);
        let collection = Inline::new([3; 32]);
        let remote_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let frontier = |byte, count| RepairFrontier {
            wake_root: [byte; 32],
            records: PatchSummary::new(Some([byte; 32]), count).unwrap(),
            authorization_evidence: PatchSummary::new(None, 0).unwrap(),
        };
        let local = frontier(5, 10);
        sample.collections.push(CollectionHealth {
            collection,
            local_frontier: Some(local),
            last_local_change_at: Some(now),
            peers: Vec::new(),
        });
        let health = Health::new(sample.node);
        health.update(|value| *value = sample);
        health.with_peer(collection, remote_key, |peer| {
            peer.started(at);
            peer.compared(
                RepairComparison {
                    observed_at: at,
                    local: frontier(4, 9),
                    remote: frontier(6, 1),
                    records_received: 0,
                    proofs_received: 0,
                    more: false,
                },
                at,
            );
            peer.compared(
                RepairComparison {
                    observed_at: now,
                    local,
                    ..peer.comparison.unwrap()
                },
                now,
            );
        });
        let conditions = super::conditions(&health.snapshot(), now);
        let pair = conditions
            .iter()
            .find(|c| c.component == Component::Collection)
            .unwrap();
        assert_eq!(pair.state, State::Stalled);
        assert!(pair.alert);
    }

    fn aged_matching_pair(
        at: crate::clock::Mono,
        now: crate::clock::Mono,
    ) -> (
        crate::health::Health,
        CollectionHandle,
        crate::transport::PeerId,
    ) {
        use crate::health::{CollectionHealth, Health, RepairComparison, RepairFrontier};
        use crate::patch_repair::PatchSummary;

        let mut sample = observed(at);
        sample.observed_at = Some(now);
        sample.store.last_snapshot_observed_at = Some(now);
        let collection = Inline::new([3; 32]);
        let remote_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        let frontier = RepairFrontier {
            wake_root: [5; 32],
            records: PatchSummary::new(Some([5; 32]), 10).unwrap(),
            authorization_evidence: PatchSummary::new(None, 0).unwrap(),
        };
        sample.collections.push(CollectionHealth {
            collection,
            local_frontier: Some(frontier),
            last_local_change_at: Some(at),
            peers: Vec::new(),
        });
        let health = Health::new(sample.node);
        health.update(|value| *value = sample);
        health.with_peer(collection, remote_key, |peer| {
            peer.started(at);
            peer.in_flight = false;
            peer.compared(
                RepairComparison {
                    observed_at: at,
                    local: frontier,
                    remote: frontier,
                    records_received: 0,
                    proofs_received: 0,
                    more: false,
                },
                at,
            );
            peer.last_completed_at = Some(at);
        });
        (health, collection, remote_key)
    }

    #[test]
    fn an_aged_successful_comparison_is_unknown_but_not_actionable() {
        let at = crate::clock::mono_now();
        let now = at + PROGRESS_GRACE + Duration::from_secs(1);
        let (health, _, _) = aged_matching_pair(at, now);

        let conditions = super::conditions(&health.snapshot(), now);
        let pair = conditions
            .iter()
            .find(|condition| condition.component == Component::Collection)
            .unwrap();
        assert_eq!(pair.state, State::Unknown);
        assert!(!pair.alert);
    }

    #[test]
    fn an_aged_comparison_alerts_after_failure_until_a_later_success() {
        use crate::health::RepairFailure;

        let at = crate::clock::mono_now();
        let failed_at = at + PROGRESS_GRACE + Duration::from_secs(1);
        let (health, collection, remote_key) = aged_matching_pair(at, failed_at);
        health.with_peer(collection, remote_key, |peer| {
            peer.last_completed_at = Some(failed_at);
            peer.last_failure_at = Some(failed_at);
            peer.last_failure = Some(RepairFailure::Failed);
        });

        let failed = super::conditions(&health.snapshot(), failed_at);
        let pair = failed
            .iter()
            .find(|condition| condition.component == Component::Collection)
            .unwrap();
        assert_eq!(pair.state, State::Unknown);
        assert!(pair.alert);

        let recovered_at = failed_at + Duration::from_secs(1);
        health.update(|health| {
            health.observed_at = Some(recovered_at);
            health.store.last_snapshot_observed_at = Some(recovered_at);
        });
        health.with_peer(collection, remote_key, |peer| {
            let mut comparison = peer.comparison.unwrap();
            comparison.observed_at = recovered_at;
            peer.compared(comparison, recovered_at);
            peer.last_completed_at = Some(recovered_at);
        });
        let recovered = super::conditions(&health.snapshot(), recovered_at);
        let pair = recovered
            .iter()
            .find(|condition| condition.component == Component::Collection)
            .unwrap();
        assert_eq!(pair.state, State::Current);
        assert!(!pair.alert);
    }

    #[test]
    fn idle_dht_renewal_is_unknown_not_a_failed_probe() {
        let at = crate::clock::mono_now();
        let now = at + Duration::from_secs(3600);
        let mut health = observed(at);
        health.observed_at = Some(now);
        health.store.last_snapshot_observed_at = Some(now);
        health.publication.resident = 1;
        health.publication.last_acknowledged_at = Some(at);
        health.publication.renewal_remaining = 1;
        let conditions = super::conditions(&health, now);
        let dht = conditions
            .iter()
            .find(|c| c.component == Component::Dht)
            .unwrap();
        assert_eq!(dht.state, State::Unknown);
        assert!(!dht.alert);
    }

    #[test]
    fn continuous_publication_failure_expires_its_grace_then_ack_recovers() {
        let at = crate::clock::mono_now();
        let mut health = observed(at);
        health.publication.resident = 1;
        health.publication.retry_pending = 1;
        health.publication.unacknowledged_since = Some(at);
        let soon = super::conditions(&health, at + Duration::from_secs(10));
        assert!(
            !soon
                .iter()
                .find(|c| c.component == Component::Dht)
                .unwrap()
                .alert
        );
        let now = at + PROGRESS_GRACE + Duration::from_secs(1);
        let late = super::conditions(&health, now);
        let dht = late.iter().find(|c| c.component == Component::Dht).unwrap();
        assert_eq!(dht.state, State::Stalled);
        assert!(dht.alert);
        health.publication.last_acknowledged_at = Some(now);
        health.publication.unacknowledged_since = None;
        health.publication.retry_pending = 0;
        let recovered = super::conditions(&health, now);
        let dht = recovered
            .iter()
            .find(|c| c.component == Component::Dht)
            .unwrap();
        assert_eq!(dht.state, State::Current);
        assert!(!dht.alert);
    }

    #[test]
    fn a_publication_that_never_completes_cannot_stay_progressing_forever() {
        let at = crate::clock::mono_now();
        let mut health = observed(at);
        health.publication.resident = 1;
        health.publication.in_flight = 1;
        health.publication.last_started_at = Some(at);
        let now = at + PROGRESS_GRACE + Duration::from_secs(1);
        let conditions = super::conditions(&health, now);
        let dht = conditions
            .iter()
            .find(|c| c.component == Component::Dht)
            .unwrap();
        assert_eq!(dht.state, State::Stalled);
        assert!(dht.alert);
    }

    fn condition(state: State, alert: bool) -> Condition {
        Condition {
            component: Component::Host,
            collection: None,
            peer: None,
            state,
            alert,
        }
    }

    fn conditions(facts: &Fragment, tag: Id) -> Vec<Id> {
        find!(id: Id, pattern!(facts.facts(), [{
            ?id @ metadata::tag: &KIND_CONDITION, metadata::tag: &tag,
        }]))
        .collect()
    }

    #[test]
    fn healthy_heartbeats_only_record_creation_time_and_remain_quiet() {
        let endpoint = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key();
        let mut recorder = Recorder::new(endpoint);
        let at = Epoch::from_unix_seconds(1_700_000_000.0);
        let first = recorder
            .record(at, [condition(State::Current, false)])
            .unwrap();
        let next = recorder
            .record(at + 60.0, [condition(State::Current, false)])
            .unwrap();
        assert_ne!(first.root(), next.root());
        assert_eq!(
            conditions(&first, KIND_CONDITION),
            conditions(&next, KIND_CONDITION)
        );
        assert_eq!(conditions(&first, KIND_CONDITION).len(), 1);
        for (facts, created) in [(&first, at), (&next, at + 60.0)] {
            let report = facts.root().expect("one report root");
            let created = created.to_tai_duration().total_nanoseconds();
            assert_eq!(
                find!(at: (i128, i128), pattern!(facts.facts(), [{
                    report @ metadata::created_at: ?at,
                }]))
                .collect::<Vec<_>>(),
                vec![(created, created)]
            );
            assert!(
                find!(expiry: (i128, i128), pattern!(facts.facts(), [{
                    report @ metadata::expires_at: ?expiry,
                }]))
                .next()
                .is_none()
            );
            assert!(conditions(facts, KIND_ALERT).is_empty());
            assert!(conditions(facts, KIND_RECOVERED).is_empty());
        }
    }

    #[test]
    fn heartbeat_changes_report_but_not_alert_episode() {
        let endpoint = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key();
        let mut recorder = Recorder::new(endpoint);
        let at = Epoch::from_unix_seconds(1_700_000_000.0);
        let first = recorder
            .record(at, [condition(State::Stalled, true)])
            .unwrap();
        let next = recorder
            .record(at + 60.0, [condition(State::Stalled, true)])
            .unwrap();
        assert_ne!(first.root(), next.root());
        assert_eq!(
            conditions(&first, KIND_ALERT),
            conditions(&next, KIND_ALERT)
        );
        assert_eq!(conditions(&first, KIND_ALERT).len(), 1);
    }

    #[test]
    fn recovery_is_once_per_episode_and_restart_is_not_recovery() {
        let endpoint = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key();
        let mut recorder = Recorder::new(endpoint);
        let at = Epoch::from_unix_seconds(1_700_000_000.0);
        let initial = recorder
            .record(at, [condition(State::Current, false)])
            .unwrap();
        assert!(conditions(&initial, KIND_RECOVERED).is_empty());
        recorder
            .record(at + 1.0, [condition(State::Stalled, true)])
            .unwrap();
        let recovery = recorder
            .record(at + 2.0, [condition(State::Current, false)])
            .unwrap();
        let heartbeat = recorder
            .record(at + 3.0, [condition(State::Current, false)])
            .unwrap();
        assert_eq!(conditions(&recovery, KIND_RECOVERED).len(), 1);
        assert_eq!(
            conditions(&recovery, KIND_RECOVERED),
            conditions(&heartbeat, KIND_RECOVERED)
        );
        let failure = recorder
            .record(at + 4.0, [condition(State::Stalled, true)])
            .unwrap();
        assert_ne!(
            conditions(&failure, KIND_ALERT),
            conditions(&recovery, KIND_RECOVERED)
        );
        let unknown = recorder
            .record(at + 5.0, [condition(State::Unknown, false)])
            .unwrap();
        assert!(conditions(&unknown, KIND_RECOVERED).is_empty());
    }
}
