//! CLI commands for collection-scoped pile repair.

mod dashboard;
mod telemetry;

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::CollectionHandle;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;
use triblespace_net::health_record::{self, Recorder, DEFAULT_MAX_AGE, REPORT_EVERY};
use triblespace_net::peer::{Peer, PeerConfig, ReconcileDirection, ReconcileQos};
use triblespace_net::reconcile::ReplicationMode;

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
    /// Also fetch positive recursive-residency hints from authorized peers.
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
        /// Path to the node's durable signing key.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Read this existing health collection (descriptor handle) instead of
        /// the key's own `swarm-health` generation.
        #[arg(long, value_name = "HANDLE")]
        collection: Option<String>,
        /// Maximum report age accepted by this reader; producer expiry is ignored.
        #[arg(
            long,
            value_name = "SECONDS",
            env = "TRIBLESPACE_HEALTH_MAX_AGE_SECS",
            default_value_t = DEFAULT_MAX_AGE.as_secs()
        )]
        max_age: u64,
    },
    /// Inspect current colony work from resident telemetry and local health.
    ///
    /// The terminal view is the default. `--gui` embeds a GORBIE notebook.
    /// Neither view probes the network, maintains collections or scans blobs.
    Dashboard {
        pile: PathBuf,
        /// Reporting author used to identify this pile's health collection.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Maximum report age accepted by this reader.
        #[arg(
            long,
            value_name = "SECONDS",
            env = "TRIBLESPACE_HEALTH_MAX_AGE_SECS",
            default_value_t = DEFAULT_MAX_AGE.as_secs()
        )]
        max_age: u64,
        /// Existing telemetry source collection, already resident locally.
        /// Repeat for separate node-authorized collections. No selection,
        /// grant or collection is created by this read.
        #[arg(long = "telemetry-collection", value_name = "HANDLE")]
        telemetry: Vec<String>,
        /// Seconds between observations (one bounded sampler, no probe).
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
        /// Print one terminal observation. Redirected stdout also prints once.
        #[arg(long, conflicts_with = "gui")]
        once: bool,
        /// Explicitly select the default terminal renderer.
        #[arg(long, conflicts_with = "gui")]
        tui: bool,
        /// Run the embedded GORBIE notebook on the native main thread.
        #[arg(long, conflicts_with = "tui")]
        gui: bool,
        /// Also project the collection lattice: which collections exist, which
        /// derives from which, and how much of each one's endorsed work is
        /// actually resident here.
        ///
        /// Off by default because it walks every stored record and every
        /// resident blob once per observation, which is seconds to minutes on
        /// a large pile, while the rest of the dashboard is cheap.
        #[arg(long)]
        lattice: bool,
    },
    /// Repair explicitly named collections with peers.
    Sync {
        pile: PathBuf,
        /// Canonical iroh endpoint tickets or bare endpoint ids.
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
        /// Existing durable key for the endpoint, health and telemetry signatures.
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
        /// Full mode also acquires positive resident-blob handles learned through
        /// READ-authorized collection repair; it never probes arbitrary payload words.
        #[arg(long, value_enum, default_value = "demand")]
        replication: ReplicationArg,
        /// Maximum DHT provider-announcement attempts for this process.
        ///
        /// Zero disables announcements without disabling exact-blob serving.
        /// Retries and renewals consume the same budget as first publication.
        #[arg(long, value_name = "ATTEMPTS")]
        provider_publication_budget: Option<u64>,
        /// Publish local, timestamped swarm-health observations using the node key.
        /// The health collection is not automatically activated for sync.
        #[arg(long)]
        health: bool,
        /// Record swarm health into this existing collection (descriptor
        /// handle) instead of the reporting key's own `swarm-health`
        /// generation; the node key must be admitted there. Enables reporting.
        #[arg(long, value_name = "HANDLE")]
        health_collection: Option<String>,
        #[command(flatten)]
        telemetry: telemetry::Options,
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
        Command::Health {
            pile,
            key,
            collection,
            max_age,
        } => run_health(pile, key, collection, max_age),
        Command::Dashboard {
            pile,
            key,
            max_age,
            telemetry,
            interval,
            once,
            tui: _,
            gui,
            lattice,
        } => dashboard::run(dashboard::Options {
            pile,
            key,
            telemetry: telemetry
                .iter()
                .map(|value| parse_collection(value))
                .collect::<Result<_>>()?,
            max_age: std::time::Duration::from_secs(max_age),
            interval: std::time::Duration::from_secs(interval),
            once,
            gui,
            lattice,
        }),
        Command::Sync {
            pile,
            peers,
            key,
            collections,
            direction,
            replication,
            provider_publication_budget,
            health,
            health_collection,
            telemetry,
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
            health,
            health_collection,
            telemetry,
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
    health: bool,
    health_collection_value: Option<String>,
    telemetry_options: telemetry::Options,
    duration: Option<u64>,
    quiescent_for: Option<u64>,
) -> Result<()> {
    let key = load_existing_key(key_path, &pile_path)?;
    let peers = parse_peers(&peer_values)?;
    let collections = collection_values
        .iter()
        .map(|value| parse_collection(value))
        .collect::<Result<Vec<_>>>()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow!("reconcile runtime: {error}"))?;
    let stop = {
        let _entered = runtime.enter();
        crate::cli::util::shutdown_signal()?
    };
    let mut pile = open_pile(&pile_path)?;
    let mut telemetry = telemetry::Publisher::open(&mut pile, &key, telemetry_options)?;
    let mut recorder = Recorder::new(key.verifying_key());
    let health_collection = if health || health_collection_value.is_some() {
        let collection = open_health_collection(
            &mut pile,
            key.verifying_key(),
            health_collection_value.as_deref(),
        )?;
        // Local appends are deliberately permissive. This producer must not
        // silently publish reports that its selected destination cannot read.
        let admission = (|| -> Result<()> {
            use triblespace_core::collection::descriptor;
            use triblespace_core::repo::BlobStoreGet;
            let snapshot = pile.snapshot()?;
            let facts: triblespace_core::trible::TribleSet = snapshot.get(collection.handle())?;
            if descriptor::source(&facts)?.is_some() {
                return Err(anyhow!("health destination must be a source collection"));
            }
            if !collection.writer_is_admitted(&snapshot, key.verifying_key())? {
                return Err(anyhow!(
                    "node key is not admitted by the health destination"
                ));
            }
            Ok(())
        })();
        if let Err(error) = admission {
            pile.close()?;
            return Err(error);
        }
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
        pile.commit(collection, &key, fragment)?;
        Some(collection)
    } else {
        None
    };
    let mut peer = Peer::new(
        pile,
        key.clone(),
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
        eprintln!("local swarm health: not recording (set --health or --health-collection)");
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
    eprintln!("live collection repair active. (Ctrl-C to stop; also SIGTERM on Unix)\n");

    let started = std::time::Instant::now();
    let duration_limit = duration.map(std::time::Duration::from_secs);
    let quiescent_limit = quiescent_for.map(std::time::Duration::from_secs);
    peer.set_replication(replication, collections);
    let reconcile_every = std::time::Duration::from_secs(1);
    let mut next_reconcile = std::time::Instant::now();
    let mut next_health = std::time::Instant::now();
    let mut next_telemetry = std::time::Instant::now();
    let mut wants_fulfilled_total = 0_u64;
    let mut wants_pending = 0_usize;
    let mut last_pending_logged = None;
    let mut last_want_progress = std::time::Instant::now();
    let work = async {
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
            if let Some(telemetry) = telemetry.as_ref() {
                if std::time::Instant::now() >= next_telemetry {
                    // Sampling is passive and publication uses only the
                    // explicitly selected destination. A failed observation
                    // never becomes an empty or healthy replacement sample.
                    if telemetry
                        .publish(&mut *peer.store(), &peer.health())
                        .is_err()
                    {
                        eprintln!("sync telemetry publication failed; previous samples will age");
                    }
                    next_telemetry = std::time::Instant::now() + REPORT_EVERY;
                }
            }
            if let Some(collection) = health_collection {
                if std::time::Instant::now() >= next_health {
                    let health = peer.health();
                    let fragment = recorder.record_measurements(
                        triblespace_core::clock::epoch_now(),
                        health_record::measurements(&health, triblespace_core::clock::mono_now()),
                    )?;
                    peer.store().commit(collection, &key, fragment)?;
                    next_health = std::time::Instant::now() + REPORT_EVERY;
                }
            }
            if next_reconcile <= std::time::Instant::now() {
                let measured = telemetry.as_ref().map(|_| std::time::Instant::now());
                let stats = peer.reconcile().await;
                if let (Some(telemetry), Some(measured)) = (telemetry.as_mut(), measured) {
                    telemetry.reconciled(&stats, measured.elapsed());
                }
                next_reconcile = std::time::Instant::now() + reconcile_every;
                wants_fulfilled_total += stats.fulfilled as u64;
                wants_pending = stats.pending;
                if stats.fulfilled > 0 || stats.replication.acquired > 0 {
                    last_want_progress = std::time::Instant::now();
                }
                if stats.replication.acquired > 0 || stats.replication.inventory > 0 {
                    eprintln!(
                        "  hydration: {} direct roots, {} pending; {} positive inventory hints, {} still missing; {} acquired",
                        stats.replication.roots,
                        stats.replication.pending,
                        stats.replication.inventory,
                        stats.replication.inventory_pending,
                        stats.replication.acquired,
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = runtime.block_on(async {
        tokio::select! {
            biased;
            stopped = stop => {
                stopped?;
                eprintln!("sync stopped; closing pile");
                Ok(())
            }
            result = work => result,
        }
    });
    eprintln!("wants: {wants_fulfilled_total} fulfilled this run; {wants_pending} still pending");
    let close = peer
        .into_store()
        .close()
        .map_err(|error| anyhow!("close pile: {error}"));
    result.and(close)
}

/// The health collection reports go into: an explicit existing generation by
/// handle, or the reporting key's own `swarm-health` generation (a direct
/// policy on both sides, so the generation is a function of the key).
fn open_health_collection(
    pile: &mut Pile,
    authority: ed25519_dalek::VerifyingKey,
    value: Option<&str>,
) -> Result<Collection<SimpleArchive>> {
    match value {
        Some(value) => {
            let handle = parse_collection(value)?;
            let snapshot = pile.snapshot()?;
            Collection::<SimpleArchive>::open(&snapshot, handle)
                .map_err(|error| anyhow!("open health collection {value}: {error}"))
        }
        None => Ok(pile.collection(
            health_record::COLLECTION_NAME,
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority),
                AdmissionPolicy::direct(authority),
            ),
        )?),
    }
}

fn run_health(
    pile_path: PathBuf,
    key_path: Option<PathBuf>,
    collection_value: Option<String>,
    max_age: u64,
) -> Result<()> {
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
    let mut pile = open_pile(&pile_path)?;
    let result = (|| -> Result<()> {
        let source = open_health_collection(&mut pile, authority, collection_value.as_deref())?;
        // Derived chains carry the source's policy, so an explicit shared
        // generation yields the same chain handles every reader derives.
        let policy = source.policy(&pile.snapshot()?)?;
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
        let now = triblespace_core::clock::epoch_now()
            .to_tai_duration()
            .total_nanoseconds();
        let snapshot = pile.snapshot()?;
        let facts = snapshot
            .collection(facts)?
            .view::<UnionArchive<OrderedUniverse>>()?;
        let latest = snapshot.collection(latest)?.view::<LwwIndex>()?.query()?;
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
            println!("Swarm health: not observed. Enable sync --health with this node key.");
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
    fn health_reporting_is_opt_in_without_a_second_key() {
        let handle = hex::encode([0xCD; 32]);
        let Command::Sync { health, .. } =
            Command::try_parse_from(["net", "sync", "test.pile", "--collection", &handle]).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(!health);
        let Command::Sync { health, .. } = Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
            "--collection",
            &handle,
            "--health",
        ])
        .unwrap() else {
            panic!("sync expected")
        };
        assert!(health);
        assert!(Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
            "--collection",
            &handle,
            "--health-key",
            "observer.key",
        ])
        .is_err());
        assert!(matches!(
            Command::try_parse_from(["net", "health", "test.pile"]).unwrap(),
            Command::Health { .. }
        ));
    }

    #[test]
    fn an_explicit_health_collection_enables_reporting_with_the_node_key() {
        let handle = hex::encode([0xCD; 32]);
        let Command::Sync {
            health_collection, ..
        } = Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
            "--collection",
            &handle,
            "--health-collection",
            &handle,
        ])
        .unwrap()
        else {
            panic!("sync expected")
        };
        assert_eq!(health_collection.as_deref(), Some(handle.as_str()));
        let Command::Health { collection, .. } =
            Command::try_parse_from(["net", "health", "test.pile", "--collection", &handle])
                .unwrap()
        else {
            panic!("health expected")
        };
        assert_eq!(collection.as_deref(), Some(handle.as_str()));
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
    fn dashboard_defaults_to_terminal_and_modes_are_exclusive() {
        let Command::Dashboard {
            max_age,
            telemetry,
            interval,
            once,
            tui,
            gui,
            ..
        } = Command::try_parse_from(["net", "dashboard", "test.pile"]).unwrap()
        else {
            panic!("dashboard expected")
        };
        assert_eq!(max_age, DEFAULT_MAX_AGE.as_secs());
        assert!(telemetry.is_empty());
        assert_eq!(interval, 2);
        assert!(!once);
        assert!(!tui);
        assert!(!gui);

        assert!(matches!(
            Command::try_parse_from(["net", "dashboard", "test.pile", "--gui"]).unwrap(),
            Command::Dashboard { gui: true, .. }
        ));
        assert!(
            Command::try_parse_from(["net", "dashboard", "test.pile", "--tui", "--gui",]).is_err()
        );
        assert!(
            Command::try_parse_from(["net", "dashboard", "test.pile", "--interval", "0"]).is_err()
        );
        assert!(
            Command::try_parse_from(["net", "dashboard", "test.pile", "--gui", "--once"]).is_err()
        );
        // No arbitrary local-blob samples and no external renderer switch.
        assert!(
            Command::try_parse_from(["net", "dashboard", "test.pile", "--sample", "10"]).is_err()
        );
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
