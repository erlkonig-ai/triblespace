//! One bounded normal DHT/bearer fetch into an empty in-memory client.
//!
//! Pass public bootstrap endpoint IDs as arguments and one exact 64-hex H on
//! stdin. H and payload bytes are never printed or persisted. No collection is
//! activated, no WANT is inserted, and the provider-publication budget is zero.
//! The caller should also impose a process timeout of at most 60 seconds.

use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId, SecretKey};
use tokio::time::timeout;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{SnapshotSource, StorageClose, WantRead};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::peer::Peer;
use triblespace_net::transport::Transport;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let peers = std::env::args()
        .skip(1)
        .map(|arg| {
            arg.parse::<EndpointId>()
                .map(EndpointAddr::from)
                .map_err(|_| anyhow!("invalid bootstrap endpoint ID"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !peers.is_empty(),
        "usage: blob_fetch_probe PEER_ID... < handle-input"
    );
    let mut input = String::new();
    std::io::stdin().take(129).read_to_string(&mut input)?;
    let mut handle = [0; 32];
    hex::decode_to_slice(input.trim(), &mut handle)
        .map_err(|_| anyhow!("stdin must contain exactly one 64-hex handle"))?;
    drop(input);
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy).map_err(|_| anyhow!("ephemeral key entropy unavailable"))?;
    let signing_key = SigningKey::from_bytes(&entropy);
    let secret = SecretKey::from_bytes(&signing_key.to_bytes());
    let qos = ReconcileQos {
        direction: ReconcileDirection::ReadOnly,
    };
    let config = PeerConfig {
        peers,
        qos,
        provider_publication_budget: Some(0),
    };
    // Own the production host task so endpoint shutdown can be awaited. The
    // Peer acquisition path is unchanged; there is no direct-GET fallback.
    let (sender, receiver, wiring) = host::wire(secret.public());
    let harness = timeout(
        Duration::from_secs(10),
        triblespace_net::transport::iroh::bind(secret, &config),
    )
    .await
    .context("endpoint bind deadline")??;
    let transport = harness.transport.clone();
    let mut host_task = tokio::spawn(host::run_host(harness, config, wiring));
    let mut peer = Peer::with_wiring(MemoryRepo::default(), qos, sender, receiver);
    let started = Instant::now();
    let fetched = peer
        .fetch_blob_with_deadline(handle, Duration::from_secs(20))
        .await
        .map(|bytes| (bytes.len(), *blake3::hash(&bytes).as_bytes() == handle));
    let elapsed_ms = started.elapsed().as_millis();
    let health = peer.health();
    let wants = (|| -> Result<usize> {
        let snapshot = peer.snapshot().context("observe in-memory client")?;
        Ok(snapshot.wants().context("observe in-memory WANTs")?.count())
    })();
    let closed = peer.close();
    match timeout(Duration::from_secs(10), &mut host_task).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            timeout(Duration::from_secs(5), transport.shutdown()).await?;
            bail!("host task failed; endpoint shut down");
        }
        Err(_) => {
            host_task.abort();
            let _ = host_task.await;
            timeout(Duration::from_secs(5), transport.shutdown()).await?;
            bail!("host shutdown deadline; endpoint shut down");
        }
    }
    closed.context("close in-memory client")?;
    ensure!(wants? == 0, "unexpected in-memory WANT");
    ensure!(
        health.collections.is_empty(),
        "unexpected active collection"
    );
    ensure!(
        health.publication.attempts == 0,
        "unexpected provider publication"
    );
    match fetched {
        Some((length, matches)) => {
            println!("fetch=ok bytes={length} hash_matches={matches} elapsed_ms={elapsed_ms}");
            ensure!(matches, "recomputed blob hash mismatch");
        }
        None => println!("fetch=no_bytes elapsed_ms={elapsed_ms}"),
    }
    println!("wants=0 active_collections=0 publications=0 shutdown=ok");
    Ok(())
}
