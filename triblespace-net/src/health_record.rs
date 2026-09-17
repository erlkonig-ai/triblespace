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
        /// Exact local blob count in the observer's frozen store snapshot.
        "8593367EF64B9466AA37ABAD8CEE1BD0" as resident_blobs: inlineencodings::U256BE;
        /// Locally observed collection-record leaves.
        "1B8BAA2BC79AF3981143A3B505C11080" as local_records: inlineencodings::U256BE;
        /// Locally observed authorization-evidence leaves.
        "E30053A332B8DE94643A05F9F6FC5455" as local_authorizations: inlineencodings::U256BE;
        /// Remotely reported collection-record leaves in one pairwise comparison.
        "EBB986FACE961CB32B1276CCAF39A74D" as remote_records: inlineencodings::U256BE;
        /// Remotely reported authorization-evidence leaves in one comparison.
        "CA19BB7964D2F6DD562416CC39CA13AA" as remote_authorizations: inlineencodings::U256BE;
        /// Opaque provider keys considered resident by the publication worker.
        "7ECCF364F3C49A7F14341786D9D4C601" as publication_keys: inlineencodings::U256BE;
        "C5FB5EBD91865A4FE7BA0AA9601CE165" as publication_startup_pending: inlineencodings::U256BE;
        "99D3AC84E6C66D7948323A5FBD23E36B" as publication_incremental_pending: inlineencodings::U256BE;
        "6FD08FDE74BFEB2EA616D0DE69924272" as publication_retry_pending: inlineencodings::U256BE;
        "2EE8D9BB92F63B7E4DD85DE5DB28ED0F" as publication_renewal_remaining: inlineencodings::U256BE;
        "B261CB11C1221C0C730BA3261A7C8F7B" as publication_in_flight: inlineencodings::U256BE;
        "EB66C8D9ED7BE171C14B4F89527F7722" as publication_attempts: inlineencodings::U256BE;
        "519C3B9557ABCDBA9E998954DFA1D86B" as publication_acknowledged: inlineencodings::U256BE;
        "53FEF77F051518368F95D2D820B24BB0" as publication_rejected: inlineencodings::U256BE;
        "148A0E8E56CB3193316960D7B40F013C" as publication_unavailable: inlineencodings::U256BE;
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

/// Optional quantitative evidence attached to one condition episode.
///
/// Absence remains distinct from zero: older reporters and components which
/// cannot observe a quantity must not be rendered as empty or complete.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Evidence {
    pub resident_blobs: Option<u64>,
    pub local_records: Option<u64>,
    pub local_authorizations: Option<u64>,
    pub remote_records: Option<u64>,
    pub remote_authorizations: Option<u64>,
    pub publication_keys: Option<u64>,
    pub publication_startup_pending: Option<u64>,
    pub publication_incremental_pending: Option<u64>,
    pub publication_retry_pending: Option<u64>,
    pub publication_renewal_remaining: Option<u64>,
    pub publication_in_flight: Option<u64>,
    pub publication_attempts: Option<u64>,
    pub publication_acknowledged: Option<u64>,
    pub publication_rejected: Option<u64>,
    pub publication_unavailable: Option<u64>,
}

/// A condition and the exact counters observed alongside it.
#[derive(Clone, Debug)]
pub struct Measurement {
    pub condition: Condition,
    pub evidence: Evidence,
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

/// Interpret qualitative conditions and retain their independently observed
/// counters. This does not turn pairwise roots into blob availability claims.
pub fn measurements(
    health: &crate::health::HealthSnapshot,
    now: crate::clock::Mono,
) -> Vec<Measurement> {
    conditions(health, now)
        .into_iter()
        .map(|condition| {
            let evidence = match condition.component {
                Component::Host => Evidence::default(),
                Component::Store => Evidence {
                    resident_blobs: Some(health.store.resident_blobs),
                    ..Evidence::default()
                },
                Component::Collection => {
                    let collection = condition.collection.and_then(|handle| {
                        health
                            .collections
                            .iter()
                            .find(|collection| collection.collection == handle)
                    });
                    let local = collection.and_then(|collection| collection.local_frontier);
                    let remote = condition.peer.as_ref().and_then(|peer| {
                        collection?
                            .peers
                            .iter()
                            .find(|entry| entry.peer == peer.to_bytes())?
                            .comparison
                            .map(|comparison| comparison.remote)
                    });
                    Evidence {
                        local_records: local.map(|frontier| frontier.records.leaf_count()),
                        local_authorizations: local
                            .map(|frontier| frontier.authorization_evidence.leaf_count()),
                        remote_records: remote.map(|frontier| frontier.records.leaf_count()),
                        remote_authorizations: remote
                            .map(|frontier| frontier.authorization_evidence.leaf_count()),
                        ..Evidence::default()
                    }
                }
                Component::Dht => {
                    let publication = &health.publication;
                    Evidence {
                        publication_keys: Some(publication.resident),
                        publication_startup_pending: Some(publication.startup_pending),
                        publication_incremental_pending: Some(publication.incremental_pending),
                        publication_retry_pending: Some(publication.retry_pending),
                        publication_renewal_remaining: Some(publication.renewal_remaining),
                        publication_in_flight: Some(
                            u64::try_from(publication.in_flight).unwrap_or(u64::MAX),
                        ),
                        publication_attempts: Some(publication.attempts),
                        publication_acknowledged: Some(publication.acknowledged),
                        publication_rejected: Some(publication.rejected),
                        publication_unavailable: Some(publication.unavailable),
                        ..Evidence::default()
                    }
                }
            };
            Measurement {
                condition,
                evidence,
            }
        })
        .collect()
}

type Subject = (Component, Option<[u8; 32]>, Option<[u8; 32]>);

#[derive(Clone)]
struct Episode {
    state: State,
    alert: bool,
    evidence: Evidence,
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
        self.record_measurements(
            at,
            conditions.into_iter().map(|condition| Measurement {
                condition,
                evidence: Evidence::default(),
            }),
        )
    }

    /// Construct one heartbeat with quantitative evidence. A counter change
    /// starts a new episode even when the qualitative state is unchanged, so
    /// the latest report never keeps stale measurements alive.
    pub fn record_measurements(
        &mut self,
        at: Epoch,
        measurements: impl IntoIterator<Item = Measurement>,
    ) -> anyhow::Result<Fragment> {
        let created = point(at)?;
        let mut next = BTreeMap::new();
        for measurement in measurements {
            let condition = measurement.condition;
            let evidence = measurement.evidence;
            let subject = (
                condition.component,
                condition.collection.map(|handle| handle.raw),
                condition.peer.map(|key| key.to_bytes()),
            );
            let previous = self.episodes.get(&subject);
            let episode = match previous {
                Some(previous)
                    if previous.state == condition.state
                        && previous.alert == condition.alert
                        && previous.evidence == evidence =>
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
                        evidence: evidence.clone(),
                        facts: entity! {
                            metadata::tag*: tags.into_iter().flatten(),
                            attrs::node*: self.node.clone(),
                            attrs::session: &self.session,
                            attrs::collection?: condition.collection,
                            attrs::peer?: condition.peer,
                            attrs::state: &condition.state.tag(),
                            attrs::resident_blobs?: evidence.resident_blobs,
                            attrs::local_records?: evidence.local_records,
                            attrs::local_authorizations?: evidence.local_authorizations,
                            attrs::remote_records?: evidence.remote_records,
                            attrs::remote_authorizations?: evidence.remote_authorizations,
                            attrs::publication_keys?: evidence.publication_keys,
                            attrs::publication_startup_pending?: evidence.publication_startup_pending,
                            attrs::publication_incremental_pending?: evidence.publication_incremental_pending,
                            attrs::publication_retry_pending?: evidence.publication_retry_pending,
                            attrs::publication_renewal_remaining?: evidence.publication_renewal_remaining,
                            attrs::publication_in_flight?: evidence.publication_in_flight,
                            attrs::publication_attempts?: evidence.publication_attempts,
                            attrs::publication_acknowledged?: evidence.publication_acknowledged,
                            attrs::publication_rejected?: evidence.publication_rejected,
                            attrs::publication_unavailable?: evidence.publication_unavailable,
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
            blob_serving: crate::health::BlobServeHealth::default(),
            links: Vec::new(),
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
    fn changed_measurement_starts_a_new_episode_but_equal_measurement_reuses_it() {
        let endpoint = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key();
        let mut recorder = Recorder::new(endpoint);
        let at = Epoch::from_unix_seconds(1_700_000_000.0);
        let measurement = |resident_blobs| Measurement {
            condition: Condition {
                component: Component::Store,
                collection: None,
                peer: None,
                state: State::Current,
                alert: false,
            },
            evidence: Evidence {
                resident_blobs: Some(resident_blobs),
                ..Evidence::default()
            },
        };

        let first = recorder.record_measurements(at, [measurement(17)]).unwrap();
        let same = recorder
            .record_measurements(at + 60.0, [measurement(17)])
            .unwrap();
        let changed = recorder
            .record_measurements(at + 120.0, [measurement(18)])
            .unwrap();

        assert_eq!(
            conditions(&first, KIND_CONDITION),
            conditions(&same, KIND_CONDITION)
        );
        assert_ne!(
            conditions(&same, KIND_CONDITION),
            conditions(&changed, KIND_CONDITION)
        );
        let changed_condition = conditions(&changed, KIND_CONDITION)[0];
        assert_eq!(
            find!(count: u128, pattern!(changed.facts(), [{
                changed_condition @ attrs::resident_blobs: ?count,
            }]))
            .collect::<Vec<_>>(),
            vec![18]
        );
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
