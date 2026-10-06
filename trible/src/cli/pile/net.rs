//! CLI commands for collection-scoped pile repair.

mod dashboard;
mod telemetry;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::selection::{
    config_facts, sync_collection, sync_selection, Selection,
};
use triblespace_core::collection::CollectionHandle;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;
use triblespace_net::health_record::{self, Recorder, DEFAULT_MAX_AGE, REPORT_EVERY};
use triblespace_net::peer::{Peer, PeerConfig};
use triblespace_net::reconcile::ReplicationMode;

/// Open the pile, as `host` when the command publishes or reads MERGEs or MAPs
/// and with no host otherwise (the rule is on
/// [`crate::cli::pile::open_refreshed`]).
fn open_pile(path: &PathBuf, host: Option<ed25519_dalek::VerifyingKey>) -> Result<Pile> {
    crate::cli::pile::open_refreshed_with(path, host)
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
        /// Also print the ticket of a sync daemon started with this key and
        /// `--bind <ADDR>`, so a peer can be given it before either starts.
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<std::net::SocketAddr>,
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
    /// Select collections for sync.
    ///
    /// The sync daemon peers for a collection only while this pile's own
    /// configuration selects it. Each handle gets one new register state that
    /// supersedes every head, so a conflict between earlier writers is settled
    /// here. A running daemon picks the change up from the pile.
    Select {
        pile: PathBuf,
        /// Path to the pile's signing key; the configuration is private to it.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Collection descriptor handles. Repeat as needed.
        #[arg(value_name = "HANDLE", required = true)]
        collections: Vec<String>,
    },
    /// Stop syncing collections.
    ///
    /// Writes an unselect state rather than removing anything, so the
    /// register's history stays readable and a later select supersedes it.
    Unselect {
        pile: PathBuf,
        /// Path to the pile's signing key; the configuration is private to it.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Collection descriptor handles. Repeat as needed.
        #[arg(value_name = "HANDLE", required = true)]
        collections: Vec<String>,
    },
    /// List every collection this pile's configuration has a selection for.
    ///
    /// Reads the configuration only; it never writes or probes the network.
    Selection {
        pile: PathBuf,
        /// Path to the pile's signing key; the configuration is private to it.
        #[arg(long)]
        key: Option<PathBuf>,
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
    /// Sync the collections this pile selects with peers.
    ///
    /// The selection is the register in the pile's own configuration
    /// collection, under the key; the daemon follows changes to it while
    /// it runs.
    Sync {
        pile: PathBuf,
        /// Canonical iroh endpoint tickets or bare endpoint ids.
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
        /// Existing durable key for the endpoint, health and telemetry signatures.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Local blob acquisition for exactly the selected collections.
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
        /// Bind the endpoint to exactly this local socket (for example
        /// `127.0.0.1:7001`) instead of iroh's default sockets. Printed at
        /// startup as `bound: <ip:port>`.
        #[arg(long, value_name = "IP:PORT")]
        bind: Option<std::net::SocketAddr>,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Identity { key, bind } => run_identity(key, bind),
        Command::Health {
            pile,
            key,
            collection,
            max_age,
        } => run_health(pile, key, collection, max_age),
        Command::Select {
            pile,
            key,
            collections,
        } => run_select(pile, key, collections, true),
        Command::Unselect {
            pile,
            key,
            collections,
        } => run_select(pile, key, collections, false),
        Command::Selection { pile, key } => run_selection(pile, key),
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
            replication,
            provider_publication_budget,
            health,
            health_collection,
            telemetry,
            duration,
            quiescent_for,
            bind,
        } => run_sync(
            pile,
            peers,
            key,
            replication.into(),
            provider_publication_budget,
            health,
            health_collection,
            telemetry,
            duration,
            quiescent_for,
            bind,
        ),
    }
}

/// The name a resident descriptor gives `collection`, if the snapshot holds it.
///
/// A selection may name a collection whose descriptor has not arrived yet,
/// so an absent name is reported, never an error.
fn resident_collection_name<S>(snapshot: &S, collection: CollectionHandle) -> Option<String>
where
    S: triblespace_core::repo::BlobStoreGet,
{
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::blob::Blob;
    use triblespace_core::collection::descriptor;
    use triblespace_core::trible::TribleSet;

    let facts: TribleSet = snapshot.get(collection).ok()?;
    let named = descriptor::name(&facts).ok().flatten()?;
    let blob: Blob<UTF8String> = snapshot.get(named).ok()?;
    std::str::from_utf8(&blob.bytes).ok().map(str::to_owned)
}

/// Write one sync selection state for each collection into this pile's own
/// configuration; `selected == false` unselects.
fn run_select(
    pile_path: PathBuf,
    key_path: Option<PathBuf>,
    collections: Vec<String>,
    selected: bool,
) -> Result<()> {
    use triblespace_core::collection::private_policy;
    use triblespace_core::collection::selection::{write_sync_selection, CONFIG_COLLECTION_NAME};

    let collections = collections
        .iter()
        .map(|value| parse_collection(value))
        .collect::<Result<Vec<_>>>()?;
    let signer = load_existing_key(key_path, &pile_path)?;
    let authority = signer.verifying_key();
    // The daemon reads the configuration as this key, so write it as this key.
    let mut pile = open_pile(&pile_path, Some(authority))?;
    let result = (|| -> Result<()> {
        // Registering is idempotent: the handle is a function of the name
        // and the key, the same one `selection::config_handle` derives.
        let config = pile.collection(CONFIG_COLLECTION_NAME, private_policy(authority))?;
        let verb = if selected { "selected" } else { "unselected" };
        for collection in collections {
            write_sync_selection(&mut pile, config, &signer, collection, selected)?;
            let snapshot = pile.snapshot()?;
            match resident_collection_name(&snapshot, collection) {
                Some(name) => println!("{verb} {} ({name})", hex::encode(collection.raw)),
                None => println!(
                    "{verb} {} (no descriptor resident here yet; the selection stands and applies once it arrives)",
                    hex::encode(collection.raw)
                ),
            }
        }
        Ok(())
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    result.and(close)
}

/// Print the register value of every collection the configuration names.
fn run_selection(pile_path: PathBuf, key_path: Option<PathBuf>) -> Result<()> {
    use triblespace_core::collection::selection::{
        config_facts, sync_collection, sync_selection, Selection,
    };
    use triblespace_core::id::Id;
    use triblespace_core::macros::{find, pattern};

    let signer = load_existing_key(key_path, &pile_path)?;
    let authority = signer.verifying_key();
    let mut pile = open_pile(&pile_path, Some(authority))?;
    let result = (|| -> Result<()> {
        let snapshot = pile.snapshot()?;
        let facts = config_facts(&snapshot, authority)?;
        let mut collections: Vec<CollectionHandle> = find!(
            (state: Id, collection: CollectionHandle),
            pattern!(&facts, [{ ?state @ sync_collection: ?collection }])
        )
        .map(|(_, collection)| collection)
        .collect();
        collections.sort_by_key(|collection| collection.raw);
        collections.dedup();
        let (mut on, mut off) = (0usize, 0usize);
        for collection in &collections {
            let value = match sync_selection(&facts, *collection) {
                // A collection named only by heads this reader cannot decode.
                Selection::Unset => "unset".to_owned(),
                Selection::Selected => {
                    on += 1;
                    "selected".to_owned()
                }
                Selection::Unselected => {
                    off += 1;
                    "unselected".to_owned()
                }
                Selection::Conflicted(heads) => format!(
                    "conflicted between {} heads (select or unselect once to settle)",
                    heads.len()
                ),
            };
            let name = resident_collection_name(&snapshot, *collection)
                .unwrap_or_else(|| "no descriptor resident".to_owned());
            println!("{} {value:<10} {name}", hex::encode(collection.raw));
        }
        println!(
            "{} collection(s) named in this pile's configuration: {on} selected, {off} unselected.",
            collections.len()
        );
        Ok(())
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    result.and(close)
}

fn run_identity(key: Option<PathBuf>, bind: Option<std::net::SocketAddr>) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let default_anchor = cwd.join("identity.pile");
    let path = triblespace_core::signing_key_file::resolve_path(key.as_deref(), &default_anchor);
    let key = triblespace_core::signing_key_file::init(&path)?;
    let public = triblespace_net::identity::iroh_secret(&key).public();
    let addr = bind.map(ticket_address).transpose()?;
    println!("node: {public}");
    if let Some(addr) = addr {
        println!("ticket: {}", bound_ticket(public, addr));
    }
    Ok(())
}

/// The address a ticket written before launch may name: the daemon binds it
/// later, so it must be a concrete address a peer can reach and a fixed port.
/// Port 0 and the unspecified addresses (0.0.0.0, ::) name no socket the
/// daemon will have.
fn ticket_address(addr: std::net::SocketAddr) -> Result<std::net::SocketAddr> {
    if addr.port() == 0 || addr.ip().is_unspecified() {
        return Err(anyhow!(
            "--bind {addr}: a ticket written before launch needs a concrete reachable address and a nonzero port"
        ));
    }
    Ok(addr)
}

/// The ticket of an endpoint reached at exactly `addr`.
fn bound_ticket(id: EndpointId, addr: std::net::SocketAddr) -> String {
    use iroh_tickets::Ticket;
    EndpointTicket::new(EndpointAddr::new(id).with_ip_addr(addr)).encode_string()
}

/// The startup line naming the sockets the endpoint bound:
/// `bound: <ip:port>[ <ip:port>...]`.
fn bound_line(sockets: &[std::net::SocketAddr]) -> String {
    let sockets: Vec<String> = sockets.iter().map(ToString::to_string).collect();
    format!("bound: {}", sockets.join(" "))
}

/// The collections the configuration of the pile `authority` signs for
/// selects for sync.
fn selected_collections(
    pile: &mut Pile,
    authority: ed25519_dalek::VerifyingKey,
) -> Result<BTreeSet<CollectionHandle>> {
    use triblespace_core::macros::{find, pattern};

    let snapshot = pile.snapshot()?;
    let facts = config_facts(&snapshot, authority)?;
    Ok(find!(
        collection: CollectionHandle,
        pattern!(&facts, [{ _?state @ sync_collection: ?collection }])
    )
    .filter(|collection| sync_selection(&facts, *collection) == Selection::Selected)
    .collect())
}

fn run_sync(
    pile_path: PathBuf,
    peer_values: Vec<String>,
    key_path: Option<PathBuf>,
    replication: ReplicationMode,
    provider_publication_budget: Option<u64>,
    health: bool,
    health_collection_value: Option<String>,
    telemetry_options: telemetry::Options,
    duration: Option<u64>,
    quiescent_for: Option<u64>,
    bind: Option<std::net::SocketAddr>,
) -> Result<()> {
    let key = load_existing_key(key_path, &pile_path)?;
    let peers = parse_peers(&peer_values)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow!("reconcile runtime: {error}"))?;
    let stop = {
        let _entered = runtime.enter();
        crate::cli::util::shutdown_signal()?
    };
    // Sync writes and serves records and never publishes or reads a MERGE,
    // so it opens with no host, whichever key signs its telemetry.
    let mut pile = open_pile(&pile_path, None)?;
    let mut selected = selected_collections(&mut pile, key.verifying_key())?;
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
            provider_publication_budget,
            bind,
        },
    )?;
    peer.activate_collections(selected.iter().copied());

    eprintln!("node: {}", peer.id());
    eprintln!("{}", bound_line(&peer.bound_sockets()));
    eprintln!("selected collections: {}", selected.len());
    eprintln!("local replication: {replication:?}");
    if health_collection.is_some() {
        eprintln!("local swarm health: every 60s; freshness is reader policy");
    } else {
        eprintln!("local swarm health: not recording (set --health or --health-collection)");
    }
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
    let node = *peer.id().as_bytes();
    let mut rounds_seen = RoundsSeen::new();

    let started = std::time::Instant::now();
    let duration_limit = duration.map(std::time::Duration::from_secs);
    let quiescent_limit = quiescent_for.map(std::time::Duration::from_secs);
    peer.set_replication(replication, selected.iter().copied());
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
                // A selection written while the daemon runs takes effect
                // here. An unselected collection stays active and is no
                // longer peered.
                let now_selected = selected_collections(&mut *peer.store(), key.verifying_key())?;
                if now_selected != selected {
                    selected = now_selected;
                    peer.activate_collections(selected.iter().copied());
                    peer.set_replication(replication, selected.iter().copied());
                    eprintln!("selected collections: {}", selected.len());
                }
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
                if stats.replication.acquired > 0 {
                    eprintln!(
                        "  hydration: {} direct roots, {} pending; {} acquired",
                        stats.replication.roots,
                        stats.replication.pending,
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
            let health = peer.health();
            let rounds = health.collections.iter().flat_map(|collection| {
                collection
                    .peers
                    .iter()
                    .filter(|repair| repair.peer != node)
                    .map(|repair| {
                        (
                            repair.peer,
                            collection.collection.raw,
                            repair.last_completed_at,
                            repair.last_failure_at,
                        )
                    })
            });
            for (remote, count) in completed_rounds(rounds, &mut rounds_seen) {
                eprintln!("{}", reconciled_line(&remote, count));
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

/// The line printed, on stderr and without colour, for each peer with which
/// at least one collection repair round completed without failure since the
/// previous check: `reconciled with peer <endpoint id hex>: <n> collections`.
/// The prefix and shape are stable for scripts.
fn reconciled_line(peer: &[u8; 32], collections: usize) -> String {
    format!(
        "reconciled with peer {}: {collections} collections",
        hex::encode(peer)
    )
}

/// The last completed repair round per `peer || collection`, kept across the
/// daemon's passes.
type RoundsSeen<T> = triblespace_core::patch::PATCH<64, triblespace_core::patch::IdentitySchema, T>;

/// Collection repair rounds with a peer that completed without failure since
/// the last call, counted per peer. Each round is `(peer, collection,
/// completed at, failed at)`; a round that failed has both times equal.
/// `seen` keeps the last completion per peer and collection.
fn completed_rounds<T: Copy + Ord>(
    rounds: impl IntoIterator<Item = ([u8; 32], [u8; 32], Option<T>, Option<T>)>,
    seen: &mut RoundsSeen<T>,
) -> std::collections::BTreeMap<[u8; 32], usize> {
    // Scratch for this call: the count per peer.
    let mut completed = std::collections::BTreeMap::new();
    for (peer, collection, completed_at, failed_at) in rounds {
        let Some(at) = completed_at else {
            continue;
        };
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&peer);
        key[32..].copy_from_slice(&collection);
        if seen.get(&key).is_some_and(|previous| *previous >= at) {
            continue;
        }
        seen.replace(&triblespace_core::patch::Entry::with_value(&key, at));
        if failed_at != Some(at) {
            *completed.entry(peer).or_default() += 1;
        }
    }
    completed
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
    // This command maintains the health views and reads through their
    // merges and attachments: the MERGEs and MAPs their upkeep publishes are
    // signed with `signer`, and only a store opened as that key believes them.
    let mut pile = open_pile(&pile_path, Some(authority))?;
    let result = (|| -> Result<()> {
        let source = open_health_collection(&mut pile, authority, collection_value.as_deref())?;
        // Attached indexes name the source and their mapping and nothing
        // else, so every reader of the same source attaches the same ones.
        let facts = pile.attach::<SuccinctArchiveBlob>(source, ())?;
        let latest =
            pile.attach::<LwwRegisterBlob>(source, (attrs::node.id(), metadata::created_at.id()))?;
        // Pile is local-only: missing report bytes cannot start acquisition.
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            drop(pile.maintain_attached(facts, &signer).await?);
            drop(pile.maintain_attached(latest, &signer).await?);
            Ok::<_, anyhow::Error>(())
        })?;
        let now = triblespace_core::clock::epoch_now()
            .to_tai_duration()
            .total_nanoseconds();
        let snapshot = pile.snapshot()?;
        let facts = snapshot
            .attached(facts)?
            .view::<UnionArchive<OrderedUniverse>>()?;
        let latest = snapshot.attached(latest)?.view::<LwwIndex>()?.query()?;
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
    #[test]
    fn a_bound_ticket_names_exactly_the_bound_socket() {
        use iroh_base::{EndpointId, SecretKey};
        let id: EndpointId = SecretKey::from_bytes(&[7; 32]).public();
        let addr: std::net::SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let ticket = super::bound_ticket(id, addr);
        let peers = super::parse_peers(&[ticket]).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].id, id);
        assert_eq!(peers[0].ip_addrs().copied().collect::<Vec<_>>(), vec![addr]);
        assert_eq!(super::bound_line(&[addr]), "bound: 127.0.0.1:7001");
        let v6: std::net::SocketAddr = "[::1]:7002".parse().unwrap();
        assert_eq!(
            super::bound_line(&[addr, v6]),
            "bound: 127.0.0.1:7001 [::1]:7002"
        );
    }

    /// Two production peers, each bound to a chosen loopback port and given
    /// the other's ticket, written before either starts, repair a collection
    /// in both directions. This proves the bind, the tickets and collection
    /// record repair between them, with synthetic commit handles; it says
    /// nothing about payload residency.
    #[test]
    fn two_bound_peers_reach_each_other_from_tickets_written_before_launch() {
        use ed25519_dalek::SigningKey;
        use triblespace_core::collection::selection::{
            write_sync_selection, CONFIG_COLLECTION_NAME,
        };
        use triblespace_core::collection::{
            empty_metadata_handle, private_policy, AdmissionPolicy, CollectionCommit,
            CollectionData, CollectionPolicy, CollectionRead, CollectionRecord, CollectionStore,
            CollectionStoreExt,
        };
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_net::peer::{Peer, PeerConfig};

        fn free_port() -> std::net::SocketAddr {
            // Released at once; the peer binds it a moment later.
            std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
        }
        let keys = [
            SigningKey::from_bytes(&[0x51; 32]),
            SigningKey::from_bytes(&[0x52; 32]),
        ];
        let addrs = [free_port(), free_port()];
        let tickets: Vec<String> = keys
            .iter()
            .zip(addrs)
            .map(|(key, addr)| {
                super::bound_ticket(triblespace_net::identity::iroh_secret(key).public(), addr)
            })
            .collect();
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut peers = Vec::new();
        let mut collection = None;
        for (index, key) in keys.iter().enumerate() {
            let mut store = MemoryRepo::default();
            let handle = store
                .collection("bound loopback pair", policy.clone())
                .unwrap()
                .handle();
            collection = Some(handle);
            // Each selects the collection, so each peers for it with the
            // other, which it finds as a provider of it.
            let config = store
                .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
                .unwrap();
            write_sync_selection(&mut store, config, key, handle, true).unwrap();
            let other = super::parse_peers(&[tickets[1 - index].clone()]).unwrap();
            let mut peer = Peer::new(
                store,
                key.clone(),
                PeerConfig {
                    peers: other,
                    provider_publication_budget: Some(0),
                    bind: Some(addrs[index]),
                },
            )
            .unwrap();
            assert_eq!(peer.bound_sockets(), vec![addrs[index]]);
            peer.activate_collection(handle);
            peers.push(peer);
        }
        let collection = collection.unwrap();
        for (index, key) in keys.iter().enumerate() {
            peers[index]
                .store()
                .insert(CollectionRecord::Commit(CollectionCommit::sign(
                    key,
                    collection,
                    CollectionData::new([0x60 + index as u8; 32]),
                    empty_metadata_handle(),
                )))
                .unwrap();
            peers[index].refresh();
        }
        let started = std::time::Instant::now();
        loop {
            let counts: Vec<usize> = peers
                .iter_mut()
                .map(|peer| {
                    peer.refresh();
                    peer.snapshot()
                        .unwrap()
                        .records()
                        .unwrap()
                        .filter(|record| record.as_ref().unwrap().collection() == collection)
                        .count()
                })
                .collect();
            if counts == [2, 2] {
                break;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(90),
                "the bound peers did not repair each other: {counts:?} records"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        for peer in peers {
            drop(peer.into_store());
        }
    }

    #[test]
    fn a_prelaunch_ticket_refuses_port_zero_and_unspecified_addresses() {
        for refused in ["127.0.0.1:0", "0.0.0.0:7001", "[::]:7001", "0.0.0.0:0"] {
            let addr: std::net::SocketAddr = refused.parse().unwrap();
            let error = super::ticket_address(addr).unwrap_err().to_string();
            assert!(
                error.contains("concrete reachable address and a nonzero port"),
                "{refused}: {error}"
            );
        }
        for accepted in ["127.0.0.1:7001", "[::1]:7002", "192.0.2.7:7003"] {
            let addr: std::net::SocketAddr = accepted.parse().unwrap();
            assert_eq!(super::ticket_address(addr).unwrap(), addr);
        }
    }

    #[test]
    fn sync_takes_a_bind_address() {
        let super::Command::Sync { bind, .. } =
            super::Command::try_parse_from(["net", "sync", "pile", "--bind", "127.0.0.1:7001"])
                .unwrap()
        else {
            panic!("sync");
        };
        assert_eq!(bind, Some("127.0.0.1:7001".parse().unwrap()));
    }

    #[test]
    fn sync_takes_its_collections_from_the_selection_alone() {
        assert!(
            super::Command::try_parse_from(["net", "sync", "pile", "--collection", "00"]).is_err()
        );
    }

    #[test]
    fn a_reconciled_line_per_peer_for_new_successful_rounds_only() {
        let mut seen = super::RoundsSeen::new();
        let (first, second) = ([1; 32], [2; 32]);
        let (a, b) = ([10; 32], [11; 32]);
        let rounds = [
            (first, a, Some(5_u64), None),
            (first, b, Some(6), Some(3)),
            (second, a, Some(7), Some(7)),
            (second, b, None, None),
        ];
        let completed = super::completed_rounds(rounds, &mut seen);
        assert_eq!(
            completed,
            std::collections::BTreeMap::from([(first, 2)]),
            "a failed round and a round never completed print nothing"
        );
        assert!(
            super::completed_rounds(rounds, &mut seen).is_empty(),
            "a round is reported once"
        );
        let later = [(first, a, Some(9_u64), None), (second, a, Some(8), Some(7))];
        assert_eq!(
            super::completed_rounds(later, &mut seen),
            std::collections::BTreeMap::from([(first, 1), (second, 1)])
        );
        assert_eq!(
            super::reconciled_line(&first, 2),
            format!("reconciled with peer {}: 2 collections", "01".repeat(32))
        );
    }

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
        let parse = |mode: Option<&str>| {
            let mut args = vec!["net", "sync", "test.pile"];
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
            "--replication",
            "everything"
        ])
        .is_err());
    }

    #[test]
    fn health_reporting_is_opt_in_without_a_second_key() {
        let Command::Sync { health, .. } =
            Command::try_parse_from(["net", "sync", "test.pile"]).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(!health);
        let Command::Sync { health, .. } =
            Command::try_parse_from(["net", "sync", "test.pile", "--health"]).unwrap()
        else {
            panic!("sync expected")
        };
        assert!(health);
        assert!(Command::try_parse_from([
            "net",
            "sync",
            "test.pile",
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
        } = Command::try_parse_from(["net", "sync", "test.pile", "--health-collection", &handle])
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
        let parse = |budget: Option<&str>| {
            let mut args = vec!["net", "sync", "test.pile"];
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
