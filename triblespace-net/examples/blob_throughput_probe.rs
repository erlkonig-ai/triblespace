//! Bounded real-network, known-positive blob throughput diagnostic (not a daemon).
//!
//! See `blob_throughput_probe/README.md` for the exact invocation, caps, stage
//! meanings and limitations. No collection, WANT, live pile, or persistent key
//! is used. Only the protected fixture manifest/stdin contains raw Hs.

#[path = "blob_throughput_probe/measured.rs"]
mod measured;
#[path = "blob_throughput_probe/runtime.rs"]
mod runtime;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use futures::stream::{FuturesUnordered, StreamExt};
use iroh_base::{EndpointAddr, EndpointId};
use tokio::time::timeout_at;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, Bytes};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStorePut, SnapshotSource, StorageClose, WantRead};
use triblespace_net::host::{NetSender, PeerConfig};
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::peer::Peer;
use triblespace_net::protocol::{PILE_SYNC_ALPN, op_get_blob};
use triblespace_net::transport::Transport;

use measured::{MeasuredConn, Metrics};
use runtime::{Host, Watchdog};

const MIB: u64 = 1024 * 1024;
const MAX_BLOB: u64 = 64 * MIB;
const MAX_TOTAL: u64 = 256 * MIB;
const MAX_HANDLES: usize = 4096;
const QOS: ReconcileQos = ReconcileQos {
    direction: ReconcileDirection::ReadOnly,
};

fn number(value: &str, maximum: u64) -> Result<u64> {
    let value: u64 = value
        .parse()
        .map_err(|_| anyhow!("invalid numeric argument"))?;
    ensure!(
        value > 0 && value <= maximum,
        "numeric argument outside diagnostic cap"
    );
    Ok(value)
}

fn fixture_size(value: &str) -> Result<u64> {
    let size = number(value, MAX_BLOB)?;
    ensure!(
        size >= 8,
        "fixture needs eight bytes for its unique ordinal"
    );
    Ok(size)
}

fn handles(input: impl Read, size: u64) -> Result<Vec<[u8; 32]>> {
    let cap = MAX_HANDLES * 65;
    let mut bytes = Vec::new();
    input.take((cap + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "stdin handle-list cap exceeded");
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("invalid handle-list encoding"))?;
    let mut unique = BTreeSet::new();
    let mut result = Vec::new();
    for line in text.lines() {
        let mut h = [0; 32];
        ensure!(line.len() == 64, "expected one 64-hex H per line");
        hex::decode_to_slice(line, &mut h).map_err(|_| anyhow!("invalid handle-list entry"))?;
        ensure!(
            unique.insert(h),
            "duplicate H would turn a fresh-Pile arm into dedup work"
        );
        result.push(h);
    }
    ensure!(
        !result.is_empty() && result.len() <= MAX_HANDLES,
        "invalid handle count"
    );
    ensure!(
        size * result.len() as u64 <= MAX_TOTAL,
        "requested payload cap exceeded"
    );
    Ok(result)
}

fn config(peer: Option<EndpointAddr>) -> PeerConfig {
    PeerConfig {
        peers: peer.into_iter().collect(),
        qos: QOS,
        provider_publication_budget: Some(0),
    }
}

async fn serve(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5,
        "serve-fixture BIND_IP:0 SIZE_BYTES COUNT SECONDS HANDLES_FILE"
    );
    let bind: SocketAddr = args[0].parse()?;
    let size = fixture_size(&args[1])?;
    let count = number(&args[2], MAX_HANDLES as u64)?;
    let seconds = number(&args[3], 600)?;
    ensure!(size * count <= MAX_TOTAL, "fixture payload cap exceeded");
    let _watchdog = Watchdog::start(Duration::from_secs(seconds + 30));
    // Never overwrite an existing manifest. Its contents are bearer handles;
    // only the explicitly requested 0600 file receives them, not diagnostics.
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[4])?;
    let mut store = MemoryRepo::default();
    for ordinal in 0..count {
        let mut bytes = vec![0; size as usize];
        getrandom::fill(&mut bytes).map_err(|_| anyhow!("fixture entropy unavailable"))?;
        // Distinct fixtures must not depend on random samples being unique,
        // especially at small sizes. The remaining bytes stay random.
        bytes[..8].copy_from_slice(&ordinal.to_be_bytes());
        let h = store.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(bytes)))?;
        writeln!(manifest, "{}", hex::encode(h.raw))?;
    }
    manifest.flush()?;
    drop(manifest);
    let metrics = Arc::new(Metrics::new(size, MAX_TOTAL * 2));
    let (host, sender, receiver) = Host::start(bind, config(None), metrics.clone()).await?;
    let mut peer = Peer::with_wiring(store, QOS, sender, receiver);
    peer.try_refresh()?;
    println!(
        "fixture=ready blobs={count} bytes={} duration_s={seconds} backing=memory publications_budget=0",
        size * count
    );
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    ensure!(
        peer.health().publication.attempts == 0,
        "unexpected fixture publication"
    );
    peer.close()?;
    host.close().await?;
    println!("fixture=closed");
    Ok(())
}

#[derive(Clone)]
enum Fetch {
    Direct(MeasuredConn, [u8; 32]),
    Discovery(NetSender),
}

enum Fetched {
    Blob(Blob<UnknownBlob>),
    Unavailable,
    Indeterminate,
    Error,
    Deadline,
}

impl Fetch {
    async fn one(
        self,
        h: [u8; 32],
        deadline: tokio::time::Instant,
    ) -> ([u8; 32], Fetched, Duration) {
        let start = Instant::now();
        let result = timeout_at(deadline, async {
            match self {
                Self::Direct(conn, requester) => match op_get_blob(&conn, requester, &h).await {
                    Ok(Some(blob)) => Fetched::Blob(blob),
                    Ok(None) => Fetched::Unavailable,
                    Err(_) => Fetched::Error,
                },
                Self::Discovery(sender) => match sender
                    .fetch_blob(
                        h,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await
                {
                    Some(blob) => Fetched::Blob(blob),
                    // The production Option API conflates absence and transport/
                    // readiness/deadline errors. Never call this known absence.
                    None => Fetched::Indeterminate,
                },
            }
        })
        .await
        .unwrap_or(Fetched::Deadline);
        (h, result, start.elapsed())
    }
}

enum Destination {
    Network(Peer<MemoryRepo>),
    Pile(Peer<Pile>, tempfile::TempDir, PathBuf),
}

impl Destination {
    fn accept(&mut self, blob: Blob<UnknownBlob>, flush: bool, metrics: &Metrics) -> Result<()> {
        if let Self::Pile(peer, _, path) = self {
            let start = Instant::now();
            // Carry the verified Blob and its cached H straight to Pile. No
            // Bytes conversion, new hash, readback, or acquire/WANT operation.
            let put = peer.store().put::<UnknownBlob, _>(blob);
            metrics.put.record(start.elapsed());
            put.inspect_err(|_| eprintln!("landing_failure=pile_put"))?;
            if flush {
                let start = Instant::now();
                let flushed = peer.store().flush();
                metrics.flush.record(start.elapsed());
                flushed.inspect_err(|_| eprintln!("landing_failure=pile_flush"))?;
            }
            let start = Instant::now();
            let refreshed = peer.try_refresh();
            metrics.refresh.record(start.elapsed());
            refreshed.inspect_err(|_| eprintln!("landing_failure=peer_refresh"))?;
            ensure!(
                path.metadata()?.len() <= MAX_TOTAL + (MAX_HANDLES as u64 + 1) * 512,
                "disposable Pile size cap exceeded"
            );
        }
        Ok(())
    }

    fn close(self, metrics: &Metrics) -> Result<()> {
        let start = Instant::now();
        match self {
            Self::Network(mut peer) => {
                ensure!(peer.snapshot()?.wants()?.count() == 0, "unexpected WANT");
                ensure!(
                    peer.health().collections.is_empty(),
                    "unexpected collection activation"
                );
                ensure!(
                    peer.health().publication.attempts == 0,
                    "unexpected publication"
                );
                peer.close()?;
            }
            Self::Pile(mut peer, directory, path) => {
                ensure!(peer.snapshot()?.wants()?.count() == 0, "unexpected WANT");
                ensure!(
                    peer.health().collections.is_empty(),
                    "unexpected collection activation"
                );
                ensure!(
                    peer.health().publication.attempts == 0,
                    "unexpected publication"
                );
                peer.close()?; // The close-only arm's sole Pile durability barrier.
                metrics.close.record(start.elapsed());
                println!("pile_bytes={} pile_closed=true", path.metadata()?.len());
                directory.close()?;
                return Ok(());
            }
        }
        metrics.close.record(start.elapsed());
        Ok(())
    }
}

async fn fetch(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 9,
        "fetch BIND_IP:0 PEER_ID PEER_IP:PORT direct|discovery network-only|close-only|flush-each CONCURRENCY SIZE_BYTES SECONDS SCRATCH_PARENT"
    );
    let bind: SocketAddr = args[0].parse()?;
    let provider: EndpointId = args[1]
        .parse()
        .map_err(|_| anyhow!("invalid public endpoint ID"))?;
    let addr: SocketAddr = args[2].parse()?;
    ensure!(
        !addr.ip().is_unspecified() && addr.port() != 0,
        "need exact provider socket"
    );
    ensure!(
        matches!(args[3].as_str(), "direct" | "discovery"),
        "unknown route mode"
    );
    ensure!(
        matches!(
            args[4].as_str(),
            "network-only" | "close-only" | "flush-each"
        ),
        "unknown landing mode"
    );
    let concurrency = number(&args[5], 16)? as usize;
    ensure!(
        [1, 4, 16].contains(&concurrency),
        "concurrency must be 1, 4 or 16"
    );
    let size = number(&args[6], MAX_BLOB)?;
    let seconds = number(&args[7], 60)?;
    let _watchdog = Watchdog::start(Duration::from_secs(seconds + 30));
    let hs = handles(std::io::stdin().lock(), size)?;
    let count = hs.len();
    let metrics = Arc::new(Metrics::new(size, MAX_TOTAL * 2));
    let cfg = config(Some(EndpointAddr::from(provider).with_ip_addr(addr)));
    let startup = Instant::now();
    let (host, sender, receiver) = Host::start(bind, cfg, metrics.clone()).await?;
    let mut destination = if args[4] == "network-only" {
        Destination::Network(Peer::with_wiring(
            MemoryRepo::default(),
            QOS,
            sender.clone(),
            receiver,
        ))
    } else {
        let dir = tempfile::Builder::new()
            .prefix("blob-throughput-")
            .tempdir_in(&args[8])?;
        let path = dir.path().join("fresh.pile");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        println!("disposable_directory={}", dir.path().display());
        Destination::Pile(
            Peer::with_wiring(Pile::open(&path)?, QOS, sender.clone(), receiver),
            dir,
            path,
        )
    };
    let host_setup = startup.elapsed();
    let setup = Instant::now();
    let fetcher = if args[3] == "direct" {
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            host.transport.dial(*provider.as_bytes(), PILE_SYNC_ALPN),
        )
        .await??;
        conn.report_path("established");
        Fetch::Direct(conn, host.transport.local_id())
    } else {
        Fetch::Discovery(sender.clone())
    };
    println!(
        "arm={} landing={} concurrency={concurrency} blobs={count} size={size} host_setup_ms={} connection_setup_ms={} receive_backing=anonymous-file tmpdir={} server_limits=unchanged",
        args[3],
        args[4],
        host_setup.as_millis(),
        setup.elapsed().as_millis(),
        std::env::temp_dir().display()
    );
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut pending = FuturesUnordered::new();
    let mut hs = hs.into_iter();
    for h in hs.by_ref().take(concurrency) {
        pending.push(fetcher.clone().one(h, deadline));
    }
    let mut success = 0usize;
    let mut failures = [0usize; 4];
    let mut bytes = 0u64;
    let mut landing_error = false;
    while let Some((h, result, elapsed)) = pending.next().await {
        metrics.fetch.record(elapsed);
        match result {
            Fetched::Blob(blob) => {
                // Native wire verification already did the hash. Only compare
                // cached H and known fixture size at this boundary.
                ensure!(
                    blob.get_handle().raw == h && blob.bytes.len() as u64 == size,
                    "wrong requested payload or fixture size"
                );
                if destination
                    .accept(blob, args[4] == "flush-each", &metrics)
                    .is_err()
                {
                    landing_error = true;
                    break;
                }
                success += 1;
                bytes += size;
            }
            Fetched::Unavailable => failures[0] += 1,
            Fetched::Indeterminate => failures[1] += 1,
            Fetched::Error => failures[2] += 1,
            Fetched::Deadline => failures[3] += 1,
        }
        if tokio::time::Instant::now() >= deadline || metrics.cap_failed() {
            break;
        }
        if let Some(h) = hs.next() {
            pending.push(fetcher.clone().one(h, deadline));
        }
    }
    drop(pending); // Cancel only this example's requests; release body owners.
    drop(fetcher);
    let active_elapsed = started.elapsed();
    let close = destination.close(&metrics);
    let durable_elapsed = started.elapsed();
    drop(sender);
    host.report_paths();
    host.close().await?;
    metrics.report();
    println!(
        "complete={success} requested={count} bytes={bytes} unavailable={} indeterminate={} protocol_or_io_error={} deadline={} landing_error={landing_error} active_ms={} through_close_ms={} active_mib_s={:.3} through_close_mib_s={:.3}",
        failures[0],
        failures[1],
        failures[2],
        failures[3],
        active_elapsed.as_millis(),
        durable_elapsed.as_millis(),
        bytes as f64 / MIB as f64 / active_elapsed.as_secs_f64(),
        bytes as f64 / MIB as f64 / durable_elapsed.as_secs_f64()
    );
    close?;
    ensure!(
        success == count && !landing_error && !metrics.cap_failed(),
        "arm incomplete; no throughput success claim"
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        None | Some("--help" | "-h")
    ) {
        println!(
            "blob_throughput_probe serve-fixture BIND_IP:0 SIZE_BYTES COUNT SECONDS HANDLES_FILE\nblob_throughput_probe fetch BIND_IP:0 PEER_ID PEER_IP:PORT direct|discovery network-only|close-only|flush-each CONCURRENCY SIZE_BYTES SECONDS SCRATCH_PARENT < protected-handles\nCaps and exact measurement meanings: examples/blob_throughput_probe/README.md"
        );
        return;
    }
    let result = match args.first().map(String::as_str) {
        Some("serve-fixture") => serve(&args[1..]).await,
        Some("fetch") => fetch(&args[1..]).await,
        _ => Err(anyhow!("use serve-fixture or fetch; see example README")),
    };
    if let Err(error) = result {
        // Never render an arbitrary nested storage/transport error: it could
        // contain a bearer H. Counts identify its stage; no false empty result.
        eprintln!(
            "probe=failed error_kind={} (details suppressed to protect bearer handles)",
            if error.is::<std::io::Error>() {
                "io"
            } else {
                "argument-or-stage"
            }
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_size_requires_room_for_a_distinct_ordinal() {
        for size in ["0", "1", "7"] {
            assert!(fixture_size(size).is_err());
        }
        assert_eq!(fixture_size("8").unwrap(), 8);
        assert_eq!(fixture_size("65536").unwrap(), 65536);
        assert!(fixture_size(&(MAX_BLOB + 1).to_string()).is_err());
    }

    #[test]
    fn handle_list_is_bounded_and_rejects_dedup_work() {
        let one = format!("{}\n", "01".repeat(32));
        assert!(handles(one.as_bytes(), 1).is_ok());
        assert!(handles(format!("{one}{one}").as_bytes(), 1).is_err());
        assert!(handles(b"".as_slice(), 1).is_err());
        assert!(handles(b"not-a-handle".as_slice(), 1).is_err());
        assert!(handles(one.as_bytes(), MAX_TOTAL + 1).is_err());
        assert!(handles(vec![b' '; MAX_HANDLES * 65 + 1].as_slice(), 1).is_err());
    }

    #[test]
    fn pile_arms_count_explicit_flushes_and_close_delete_only_their_fresh_directory() {
        for flush_each in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("fresh.pile");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let secret = iroh_base::SecretKey::from_bytes(&[89; 32]);
            let (sender, receiver, _wiring) = triblespace_net::host::wire(secret.public());
            // Inert wiring: no host thread, transport, or live peer is needed
            // to exercise these ordinary put/flush/snapshot/close boundaries.
            let peer = Peer::with_wiring(Pile::open(&path).unwrap(), QOS, sender, receiver);
            let mut destination = Destination::Pile(peer, dir, path.clone());
            let metrics = Metrics::new(8, 16);
            for byte in [7, 8] {
                destination
                    .accept(
                        Blob::<UnknownBlob>::new(Bytes::from_source(vec![byte; 8])),
                        flush_each,
                        &metrics,
                    )
                    .unwrap();
            }
            assert_eq!(metrics.put.count(), 2);
            assert_eq!(metrics.refresh.count(), 2);
            assert_eq!(metrics.flush.count(), if flush_each { 2 } else { 0 });
            assert!(path.exists());
            destination.close(&metrics).unwrap();
            assert_eq!(metrics.close.count(), 1);
            assert!(!path.exists());
        }
    }
}
