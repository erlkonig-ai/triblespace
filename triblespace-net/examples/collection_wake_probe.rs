//! Observe one explicitly named collection topic with an ephemeral identity.
//! No pile, keys, root advertisement, repair, blob fetch or provider publication.
//! Joining changes gossip topology temporarily; output does not prove READ(C).
//! Usage: collection_wake_probe C SECONDS PEER_ID...

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use iroh_base::{EndpointAddr, EndpointId, SecretKey};
use tokio::time::{Instant, timeout, timeout_at};
use triblespace_core::collection::CollectionHandle;
use triblespace_net::host::PeerConfig;
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::transport::Transport;
use triblespace_net::wake::CollectionWakeEvent;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();
    let mut args = std::env::args().skip(1);
    let mut raw = [0; 32];
    hex::decode_to_slice(args.next().context("collection required")?, &mut raw)?;
    let seconds: u64 = args.next().context("duration required")?.parse()?;
    ensure!(
        (1..=300).contains(&seconds),
        "duration must be 1..=300 seconds"
    );
    let peers = args
        .map(|arg| arg.parse::<EndpointId>().map(EndpointAddr::from))
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(!peers.is_empty(), "at least one explicit peer required");
    let config = PeerConfig {
        peers,
        qos: ReconcileQos {
            direction: ReconcileDirection::ReadOnly,
        },
        provider_publication_budget: Some(0),
    };
    let harness = timeout(
        Duration::from_secs(10),
        triblespace_net::transport::iroh::bind(SecretKey::generate(), &config),
    )
    .await
    .context("bind deadline")??;
    let plane = harness.transport.wake_plane();
    let mut topic = timeout(
        Duration::from_secs(10),
        plane.subscribe(
            CollectionHandle::new(raw),
            config.peers.iter().map(|peer| peer.id).collect(),
        ),
    )
    .await
    .context("subscribe deadline")??;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut received = 0;
    loop {
        let event = match timeout_at(deadline, topic.next_event()).await {
            Ok(Ok(Some(event))) => event,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                println!("topic_error={error}");
                break;
            }
            Err(_) => break,
        };
        let elapsed = started.elapsed().as_secs_f32();
        match event {
            CollectionWakeEvent::NeighborUp(peer) => println!("t={elapsed:.2} neighbor_up={peer}"),
            CollectionWakeEvent::NeighborDown(peer) => {
                println!("t={elapsed:.2} neighbor_down={peer}")
            }
            CollectionWakeEvent::Received(event) => {
                received += 1;
                println!(
                    "t={elapsed:.2} offer_origin={} hop={} root_prefix={}",
                    event.wake.origin(),
                    event.delivered_from,
                    hex::encode(&event.wake.root().as_bytes()[..8])
                );
            }
            CollectionWakeEvent::Lagged => println!("t={elapsed:.2} lagged"),
            CollectionWakeEvent::Rejected { error, .. } => {
                println!("t={elapsed:.2} rejected={error}")
            }
        }
    }
    println!(
        "offers={received} final_neighbors={}",
        topic.neighbors().count()
    );
    drop(topic);
    drop(plane);
    timeout(Duration::from_secs(10), harness.transport.shutdown())
        .await
        .context("shutdown deadline")?;
    Ok(())
}
