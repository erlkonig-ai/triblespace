//! CLI commands for collection-scoped pile repair.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use triblespace_core::collection::CollectionHandle;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::repo::pile::Pile;
use triblespace_net::health_record::{self, Recorder, DEFAULT_MAX_AGE, REPORT_EVERY};
use triblespace_net::peer::{Peer, PeerConfig, ReconcileDirection, ReconcileQos};
use triblespace_net::reconcile::{Reconciler, ReplicationMode};

fn open_pile(path: &PathBuf) -> Result<Pile> {
    crate::cli::pile::open_refreshed(path)
}

fn parse_peers(values: &[String]) -> Result<Vec<EndpointAddr>> {
    values
        .iter()
        .map(|value| {
            if let Ok(ticket) = value.parse::<EndpointTicket>() {
                return Ok(ticket.into());
            }
            let public = value.parse::<iroh_base::PublicKey>().map_err(|_| {
                anyhow!(
                    "invalid peer {value:?}: expected an iroh endpoint ticket or 64-char endpoint id"
                )
            })?;
            Ok(EndpointAddr::from(EndpointId::from(public)))
        })
        .collect()
}

fn parse_collection(value: &str) -> Result<CollectionHandle> {
    let trimmed = value.trim();
    let prefixed;
    let value = if trimmed.contains(':') {
        trimmed
    } else {
        prefixed = format!("blake3:{trimmed}");
        &prefixed
    };
    let handle = crate::cli::util::parse_blob_handle(value)?;
    Ok(CollectionHandle::new(handle.raw))
}

fn load_existing_key(path: Option<PathBuf>, pile_path: &PathBuf) -> Result<SigningKey> {
    let path = triblespace_core::signing_key_file::resolve_path(path.as_deref(), pile_path);
    triblespace_core::signing_key_file::load_existing(&path).map_err(Into::into)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum DirectionArg {
    Bidirectional,
    ReadOnly,
    WriteOnly,
}

impl From<DirectionArg> for ReconcileDirection {
    fn from(direction: DirectionArg) -> Self {
        match direction {
            DirectionArg::Bidirectional => Self::Bidirectional,
            DirectionArg::ReadOnly => Self::ReadOnly,
            DirectionArg::WriteOnly => Self::WriteOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ReplicationArg {
    /// Repair records and fulfill explicit WANTs only (default).
    Demand,
    /// Also fetch the direct blob references of selected collection records.
    Shallow,
    /// Also conservatively walk their recursively referenced blobs.
    Full,
}

impl From<ReplicationArg> for ReplicationMode {
    fn from(mode: ReplicationArg) -> Self {
        match mode {
            ReplicationArg::Demand => Self::Demand,
            ReplicationArg::Shallow => Self::Shallow,
            ReplicationArg::Full => Self::Full,
        }
    }
}

#[derive(Parser)]
pub enum Command {
    /// Show this node's network identity.
    Identity {
        /// Path to the node's signing key.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Show locally recorded swarm health; never performs a network probe.
    ///
    /// These are time-bounded observations of known participants, not a claim
    /// about every possible replica or the availability of every blob.
    Health {
        pile: PathBuf,
        /// Reporting author, not the daemon's transport identity.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Maximum report age accepted by this reader; producer expiry is ignored.
        #[arg(
            long,
            value_name = "SECONDS",
            env = "TRIBLESPACE_HEALTH_MAX_AGE_SECS",
            default_value_t = DEFAULT_MAX_AGE.as_secs()
        )]
        max_age: u64,
    },
    /// Repair explicitly named collections with peers.
    Sync {
        pile: PathBuf,
        /// Canonical iroh endpoint tickets or bare endpoint ids.
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
        /// Path to the node's signing key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Exact collection descriptor handle to activate. Repeat as needed.
        #[arg(long = "collection", value_name = "HANDLE", required = true)]
        collections: Vec<String>,
        /// Whether to pull collections, serve them, or do both.
        #[arg(long, value_enum, default_value = "bidirectional")]
        direction: DirectionArg,
        /// Local blob acquisition for exactly the --collection selections.
        /// READ grants alone never subscribe this process to hydration.
        /// Select a producer-maintained reference-summary collection as well
        /// to accelerate full walks; missing summaries leave them unfiltered.
        #[arg(long, value_enum, default_value = "demand")]
        replication: ReplicationArg,
        /// Maximum DHT provider-announcement attempts for this process.
        ///
        /// Zero disables announcements without disabling exact-blob serving.
        /// Retries and renewals consume the same budget as first publication.
        #[arg(long, value_name = "ATTEMPTS")]
        provider_publication_budget: Option<u64>,
        /// Publish local, timestamped swarm-health observations signed by this
        /// existing key. The transport key is not implicitly a reporting author.
        /// The health collection is not automatically activated for sync.
        #[arg(long, value_name = "PATH")]
        health_key: Option<PathBuf>,
        /// Stop after at most N seconds.
        #[arg(long, value_name = "SECS")]
        duration: Option<u64>,
        /// Stop after N seconds with no admitted repair or fulfilled WANT.
        #[arg(long, value_name = "SECS")]
        quiescent_for: Option<u64>,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Identity { key } => run_identity(key),
        Command::Health { pile, key, max_age } => run_health(pile, key, max_age),
        Command::Sync {
            pile,
            peers,
            key,
            collections,
            direction,
            replication,
            provider_publication_budget,
            health_key,
            duration,
            quiescent_for,
        } => run_sync(
            pile,
            peers,
            key,
            collections,
            ReconcileQos {
                direction: direction.into(),
            },
            replication.into(),
            provider_publication_budget,
            health_key,
            duration,
            quiescent_for,
        ),
    }
}

fn run_identity(key: Option<PathBuf>) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let default_anchor = cwd.join("identity.pile");
    let path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &default_anchor);
    let key = triblespace_core::signing_key_file::init(&path)?;
    println!(
        "node: {}",
        triblespace_net::identity::iroh_secret(&key).public()
    );
    Ok(())
}

fn run_sync(
    pile_path: PathBuf,
    peer_values: Vec<String>,
    key_path: Option<PathBuf>,
    collection_values: Vec<String>,
    qos: ReconcileQos,
    replication: ReplicationMode,
    provider_publication_budget: Option<u64>,
    health_key_path: Option<PathBuf>,
    duration: Option<u64>,
    quiescent_for: Option<u64>,
) -> Result<()> {
    let key = load_existing_key(key_path, &pile_path)?;
    let peers = parse_peers(&peer_values)?;
    let collections = collection_values
        .iter()
        .map(|value| parse_collection(value))
        .collect::<Result<Vec<_>>>()?;
    let mut pile = open_pile(&pile_path)?;
    let reporting_key = health_key_path
        .map(|path| load_existing_key(Some(path), &pile_path))
        .transpose()?;
    let mut recorder = Recorder::new(key.verifying_key());
    let health_collection = if let Some(signer) = reporting_key.as_ref() {
        let authority = signer.verifying_key();
        let collection = pile.collection(
            health_record::COLLECTION_NAME,
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority),
                AdmissionPolicy::direct(authority),
            ),
        )?;
        // Publish before endpoint startup: failure to start must not look like
        // a monitor that was never configured at all.
        let mut fragment = recorder.record(
            triblespace_core::clock::epoch_now(),
            [health_record::Condition {
                component: health_record::Component::Host,
                collection: None,
                peer: None,
                state: health_record::State::Unknown,
                alert: false,
            }],
        )?;
        fragment += health_record::vocabulary();
        pile.commit(collection, signer, fragment)?;
        Some(collection)
    } else {
        None
    };
    let mut peer = Peer::new(
        pile,
        key,
        PeerConfig {
            peers,
            qos,
            provider_publication_budget,
        },
    )?;
    peer.activate_collections(collections.iter().copied());

    eprintln!("node: {}", peer.id());
    eprintln!("active collections: {}", collections.len());
    eprintln!("local replication: {replication:?}");
    if health_collection.is_some() {
        eprintln!("local swarm health: every 60s; freshness is reader policy");
    } else {
        eprintln!("local swarm health: not recording (set --health-key)");
    }
    eprintln!(
        "direction: {}",
        match qos.direction {
            ReconcileDirection::Bidirectional => "bidirectional",
            ReconcileDirection::ReadOnly => "read-only (no collection serve)",
            ReconcileDirection::WriteOnly => "write-only (no collection pull)",
        }
    );
    match provider_publication_budget {
        None => eprintln!("provider publication budget: unlimited"),
        Some(0) => eprintln!(
            "provider publication budget: 0 (DHT announcements disabled; exact serving enabled)"
        ),
        Some(attempts) => eprintln!("provider publication budget: {attempts} attempts"),
    }
    if let Some(seconds) = duration {
        eprintln!("stop after: {seconds}s");
    }
    if let Some(seconds) = quiescent_for {
        eprintln!("quiescent stop: {seconds}s without events");
    }
    eprintln!("live collection repair active. (Ctrl-C to stop)\n");

    let started = std::time::Instant::now();
    let duration_limit = duration.map(std::time::Duration::from_secs);
    let quiescent_limit = quiescent_for.map(std::time::Duration::from_secs);
    let mut reconciler = Reconciler::new().with_replication(replication, collections);
    let reconcile_every = std::time::Duration::from_secs(1);
    let mut next_reconcile = std::time::Instant::now();
    let mut next_health = std::time::Instant::now();
    let mut wants_fulfilled_total = 0_u64;
    let mut wants_pending = 0_usize;
    let mut last_pending_logged = None;
    let mut last_want_progress = std::time::Instant::now();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow!("reconcile runtime: {error}"))?;

    let result = (|| -> Result<()> {
        loop {
            if duration_limit.is_some_and(|limit| started.elapsed() >= limit) {
                break;
            }
            if quiescent_limit.is_some_and(|limit| {
                peer.last_event_at().elapsed() >= limit && last_want_progress.elapsed() >= limit
            }) {
                break;
            }

            peer.refresh();
            if let (Some(collection), Some(signer)) = (health_collection, reporting_key.as_ref()) {
                if std::time::Instant::now() >= next_health {
                    let health = peer.health();
                    let fragment = recorder.record(
                        triblespace_core::clock::epoch_now(),
                        health_record::conditions(&health, triblespace_core::clock::mono_now()),
                    )?;
                    peer.store().commit(collection, signer, fragment)?;
                    next_health = std::time::Instant::now() + REPORT_EVERY;
                }
            }
            if next_reconcile <= std::time::Instant::now() {
                let stats = runtime.block_on(reconciler.tick(&mut peer));
                next_reconcile = std::time::Instant::now() + reconcile_every;
                wants_fulfilled_total += stats.fulfilled as u64;
                wants_pending = stats.pending;
                if stats.fulfilled > 0 || stats.replication.acquired > 0 {
                    last_want_progress = std::time::Instant::now();
                }
                if stats.replication.acquired > 0 || stats.replication.speculative_attempted > 0 {
                    eprintln!(
                        "  hydration: {} roots, {} pending, {} acquired; {} candidates, {} filtered, {} speculative reads, {} misses",
                        stats.replication.roots,
                        stats.replication.pending,
                        stats.replication.acquired,
                        stats.replication.candidates,
                        stats.replication.filtered,
                        stats.replication.speculative_attempted,
                        stats.replication.speculative_misses,
                    );
                }
                if stats.fulfilled > 0 || last_pending_logged != Some(stats.pending) {
                    eprintln!(
                        "  wants: {} seen, {} fulfilled this pass ({} total), {} pending",
                        stats.wants, stats.fulfilled, wants_fulfilled_total, stats.pending,
                    );
                    last_pending_logged = Some(stats.pending);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        eprintln!(
            "wants: {wants_fulfilled_total} fulfilled this run; {wants_pending} still pending"
        );
        Ok(())
    })();
    let close = peer
        .into_store()
        .close()
        .map_err(|error| anyhow!("close pile: {error}"));
    result.and(close)
}

fn run_health(pile_path: PathBuf, key_path: Option<PathBuf>, max_age: u64) -> Result<()> {
    use health_record::{attrs, KIND_REPORT};
    use triblespace_core::blob::encodings::succinctarchive::{
        OrderedUniverse, SuccinctArchiveBlob, UnionArchive,
    };
    use triblespace_core::collection::lww_register::{LwwIndex, LwwRegisterBlob};
    use triblespace_core::macros::{find, pattern};
    use triblespace_core::metadata;
    use triblespace_core::prelude::*;

    let signer = load_existing_key(key_path, &pile_path)?;
    let authority = signer.verifying_key();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut pile = open_pile(&pile_path)?;
    let result = (|| -> Result<()> {
        let source = pile.collection(health_record::COLLECTION_NAME, policy.clone())?;
        let facts = pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
        let latest = pile.derive::<LwwRegisterBlob>(
            source,
            (attrs::node.id(), metadata::created_at.id()),
            policy,
        )?;
        // Pile is local-only: missing report bytes cannot start acquisition.
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            drop(pile.maintain(facts, &signer).await?);
            drop(pile.maintain(latest, &signer).await?);
            Ok::<_, anyhow::Error>(())
        })?;
        let snapshot = pile.snapshot()?;
        let facts = snapshot
            .collection(facts)?
            .view::<UnionArchive<OrderedUniverse>>()?;
        let latest = snapshot.collection(latest)?.view::<LwwIndex>()?.query()?;
        let now = snapshot.instant().to_tai_duration().total_nanoseconds();
        let mut count = 0;
        for (report, node, session, endpoint, created) in find!(
            (report: Id, node: Id, session: Id, endpoint: ed25519_dalek::VerifyingKey,
             created: (i128, i128)),
            and!(
                pattern!(&facts, [
                    { ?report @ metadata::tag: &KIND_REPORT, attrs::node: ?node,
                      attrs::session: ?session,
                      metadata::created_at: ?created },
                    { ?node @ attrs::endpoint: ?endpoint },
                ]),
                latest.has(report),
            )
        ) {
            count += 1;
            let age = now.saturating_sub(created.1).max(0) / 1_000_000_000;
            let stale_at = created
                .1
                .saturating_add(i128::from(max_age) * 1_000_000_000);
            let fresh = created.1 <= now && now < stale_at;
            println!(
                "node {}: {} (report {age}s ago)",
                hex::encode(endpoint.as_bytes()),
                if now < created.1 {
                    "UNKNOWN — report is in the future"
                } else if fresh {
                    "fresh observation"
                } else {
                    "STALE — current health unknown"
                }
            );
            if !fresh {
                continue;
            }
            for (condition, component, state) in find!(
                (condition: Id, component: Id, state: Id),
                pattern!(&facts, [
                    { report @ attrs::condition: ?condition },
                    { ?condition @ metadata::tag: &health_record::KIND_CONDITION,
                      metadata::tag: ?component, attrs::node: &node,
                      attrs::session: &session, attrs::state: ?state },
                ])
            ) {
                let label = match component {
                    health_record::HOST => "host",
                    health_record::STORE => "store",
                    health_record::COLLECTION => "collection",
                    health_record::DHT => "DHT publication",
                    _ => continue,
                };
                let state = match state {
                    health_record::CURRENT => "current",
                    health_record::PROGRESSING => "catching up",
                    health_record::UNKNOWN => "unknown",
                    health_record::STALLED => "stalled",
                    _ => continue,
                };
                let collection = find!(c: CollectionHandle, pattern!(&facts, [{ condition @ attrs::collection: ?c }])).next();
                let remote = find!(key: ed25519_dalek::VerifyingKey, pattern!(&facts, [{ condition @ attrs::peer: ?key }])).next();
                let collection = collection
                    .map(|c| format!(" {}", &hex::encode(c.raw)[..12]))
                    .unwrap_or_default();
                let remote = remote
                    .map(|key| format!(" ↔ {}", &hex::encode(key.as_bytes())[..12]))
                    .unwrap_or_default();
                println!("  {label}{collection}{remote}: {state}");
            }
        }
        if count == 0 {
            println!(
                "Swarm health: not observed. Enable sync --health-key with this reporting key."
            );
        }
        println!(
            "Scope: recent known-participant record/proof comparisons; no all-swarm or all-blob availability claim."
        );
        Ok(())
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    result.and(close)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::{SecretKey, TransportAddr};

    #[test]
    fn peers_accept_bare_ids_and_endpoint_tickets() {
        let secret = SecretKey::from_bytes(&[7; 32]);
        let id = EndpointId::from(secret.public());
        let direct =
            EndpointAddr::from_parts(id, [TransportAddr::Ip("10.55.0.2:49152".parse().unwrap())]);
        let ticket = EndpointTicket::new(direct.clone()).to_string();
        assert_eq!(parse_peers(&[id.to_string()]).unwrap(), vec![id.into()]);
        assert_eq!(parse_peers(&[ticket]).unwrap(), vec![direct]);
        assert!(parse_peers(&["not-a-peer".to_owned()]).is_err());
    }

    #[test]
    fn collection_handles_are_explicit_exact_hashes() {
        let raw = [0xAB; 32];
        assert_eq!(parse_collection(&hex::encode(raw)).unwrap().raw, raw);
        assert!(parse_collection("not-a-handle").is_err());
    }

    #[test]
    fn replication_is_explicit_and_defaults_to_demand() {
        let handle = hex::encode([0xCD; 32]);
        let parse = |mode: Option<&str>| {
            let mut args = vec!["net", "sync", "test.pile", "--collection", handle.as_str()];
            if let Some(mode) = mode {
                args.extend(["--replication", mode]);
            }
            let Command::Sync { replication, .. } = Command::try_parse_from(args).unwrap() else {
                panic!("sync expected")
            };
            ReplicationMode::from(replication)
        };
        assert_eq!(parse(None), ReplicationMode::Demand);
        assert_eq!(parse(Some("demand")), ReplicationMode::Demand);
        assert_eq!(parse(Some("shallow")), ReplicationMode::Shallow);
        assert_eq!(parse(Some("full")), ReplicationMode::Full);
        assert!(Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
            "--collection",
            &handle,
            "--replication",
            "everything",
        ])
        .is_err());
    }

    #[test]
    fn health_reporting_requires_an_explicit_author_key() {
        let handle = hex::encode([0xCD; 32]);
        let Command::Sync { health_key, .. } =
            Command::try_parse_from(["net", "sync", "test.pile", "--collection", &handle]).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(health_key.is_none());
        let Command::Sync { health_key, .. } = Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
            "--collection",
            &handle,
            "--health-key",
            "observer.key",
        ])
        .unwrap() else {
            panic!("sync expected")
        };
        assert_eq!(health_key, Some(PathBuf::from("observer.key")));
        assert!(matches!(
            Command::try_parse_from(["net", "health", "test.pile"]).unwrap(),
            Command::Health { .. }
        ));
    }

    #[test]
    fn health_max_age_accepts_nonnegative_seconds_only() {
        for seconds in ["0", "60", "180", "18446744073709551615"] {
            let Command::Health { max_age, .. } =
                Command::try_parse_from(["net", "health", "test.pile", "--max-age", seconds])
                    .unwrap()
            else {
                panic!("health expected")
            };
            assert_eq!(max_age, seconds.parse::<u64>().unwrap());
        }
        for invalid in ["-1", "1.5", "forever", "18446744073709551616"] {
            assert!(
                Command::try_parse_from(["net", "health", "test.pile", "--max-age", invalid])
                    .is_err()
            );
        }
    }

    #[test]
    fn provider_publication_budget_defaults_unlimited_and_accepts_zero_or_n() {
        let handle = hex::encode([0xCD; 32]);
        let parse = |budget: Option<&str>| {
            let mut args = vec!["net", "sync", "test.pile", "--collection", handle.as_str()];
            if let Some(budget) = budget {
                args.extend(["--provider-publication-budget", budget]);
            }
            let Command::Sync {
                provider_publication_budget,
                ..
            } = Command::try_parse_from(args).unwrap()
            else {
                panic!("parsed sync command")
            };
            provider_publication_budget
        };

        assert_eq!(parse(None), None);
        assert_eq!(parse(Some("0")), Some(0));
        assert_eq!(parse(Some("256")), Some(256));
    }
}
