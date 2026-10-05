//! Probe explicit DHT directories, without attempting a blob transfer.
//!
//! `cargo run --release -p triblespace-net --example blob_directory -- [--pile PATH] H PEER_ID...`
//!
//! H is an exact 64-hex-character bearer handle; it is never printed or sent.
//! Each supplied peer is queried with one FIND_VALUE for its opaque locator.
//! Returned routes are counted, never followed. Matching tokens prove
//! knowledge of H, not current blob residency or successful GET_BLOB transport.
//! A valid self token may be synthesized from the answering node's snapshot;
//! foreign entries in this host's replies come from retained advertisements.
//! These source counts are not cryptographic receipts of publication.
//! Empty replies describe only these directories at this moment.
//!
//! Optional pile enumeration reports a zero-based rank among resident blob
//! locators and also probes the minimum resident locator. It retains only
//! counters and one minimum, reads no payloads, and never modifies the pile.
//! Transport identity is ephemeral: no key file, host loop, collection, WANT,
//! provider publication, or GET_BLOB is used. Bind, each dial/RPC, and shutdown
//! have independent ten-second deadlines. Output contains status/counts only.
//! Peer indices use the supplied argument order; unknown routes mean only that
//! their IDs were not among those arguments, not that they are unreachable.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use iroh_base::{EndpointAddr, EndpointId, SecretKey};
use tokio::time::timeout;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStoreList, SnapshotSource};
use triblespace_net::host::PeerConfig;
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::protocol::{PILE_SYNC_ALPN, op_find_value};
use triblespace_net::provider::{blob_locator, blob_provider_token};
use triblespace_net::transport::{Conn, Transport};

const DEADLINE: Duration = Duration::from_secs(10);
const USAGE: &str = "usage: blob_directory [--pile PATH] H PEER_ID...";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut raw_handle = args.next().context(USAGE)?;
    if matches!(raw_handle.as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let pile_path = if raw_handle == "--pile" {
        let path = PathBuf::from(args.next().context(USAGE)?);
        raw_handle = args.next().context(USAGE)?;
        Some(path)
    } else {
        None
    };
    let mut handle = [0_u8; 32];
    hex::decode_to_slice(&raw_handle, &mut handle)
        .map_err(|_| anyhow!("H must be exactly 64 hexadecimal characters"))?;
    let peers = args
        .map(|arg| {
            arg.parse::<EndpointId>()
                .map_err(|_| anyhow!("invalid directory endpoint ID"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!peers.is_empty(), "{USAGE}");

    let requested_locator = blob_locator(handle);
    let mut targets = vec![("requested", handle)];
    if let Some(path) = pile_path {
        let mut pile = Pile::open(&path).context("open inventory pile")?;
        let snapshot = pile.snapshot().context("freeze inventory snapshot")?;
        let mut total = 0_u64;
        let mut preceding = 0_u64;
        let mut resident = false;
        let mut minimum = None::<([u8; 32], [u8; 32])>;
        for info in snapshot.blobs() {
            let candidate = info.context("enumerate resident blobs")?.handle.raw;
            let locator = blob_locator(candidate);
            total += 1;
            preceding += u64::from(locator < requested_locator);
            resident |= candidate == handle;
            if minimum.is_none_or(|(current, _)| locator < current) {
                minimum = Some((locator, candidate));
            }
        }
        pile.close().context("close inventory pile")?;
        println!(
            "inventory blobs={total} requested_resident={resident} requested_preceding={preceding}"
        );
        if let Some((locator, minimum_handle)) = minimum {
            let same = locator == requested_locator;
            println!("inventory minimum_is_requested={same}");
            if !same {
                targets.push(("minimum", minimum_handle));
            }
        }
    }

    // Reuse production Iroh reachability, but never start the store host loop.
    let config = PeerConfig {
        peers: peers.iter().copied().map(EndpointAddr::from).collect(),
        qos: ReconcileQos {
            direction: ReconcileDirection::ReadOnly,
        },
        provider_publication_budget: Some(0),
        bind: None,
    };
    let harness = timeout(
        DEADLINE,
        triblespace_net::transport::iroh::bind(SecretKey::generate(), &config),
    )
    .await
    .context("endpoint bind deadline")??;
    let mut failed = false;
    for (index, peer) in peers.iter().enumerate() {
        let conn = match timeout(
            DEADLINE,
            harness.transport.dial(*peer.as_bytes(), PILE_SYNC_ALPN),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(error)) => {
                println!("peer={index} connect=error detail={error:#}");
                failed = true;
                continue;
            }
            Err(_) => {
                println!("peer={index} connect=deadline");
                failed = true;
                continue;
            }
        };
        for (label, target_handle) in &targets {
            let locator = blob_locator(*target_handle);
            let distance =
                |route: [u8; 32]| -> [u8; 32] { std::array::from_fn(|i| route[i] ^ locator[i]) };
            match timeout(DEADLINE, op_find_value(&conn, &locator)).await {
                Ok(Ok((routes, providers))) => {
                    let known = routes
                        .iter()
                        .filter(|route| peers.iter().any(|peer| peer.as_bytes() == *route))
                        .count();
                    let closer = routes
                        .iter()
                        .filter(|route| distance(**route) < distance(*peer.as_bytes()))
                        .count();
                    let mut valid_self = 0;
                    let mut valid_foreign = 0;
                    for (provider, token) in &providers {
                        if blob_provider_token(*target_handle, *provider) != *token {
                            continue;
                        }
                        if provider == peer.as_bytes() {
                            valid_self += 1;
                        } else {
                            valid_foreign += 1;
                        }
                    }
                    let valid = valid_self + valid_foreign;
                    println!(
                        "peer={index} target={label} find_value=ok routes={} known={known} unknown={} closer_than_directory={closer} providers={} valid_tokens={valid} valid_self_tokens={valid_self} valid_foreign_tokens={valid_foreign} invalid_tokens={}",
                        routes.len(),
                        routes.len() - known,
                        providers.len(),
                        providers.len() - valid
                    );
                }
                Ok(Err(error)) => {
                    println!("peer={index} target={label} find_value=error detail={error:#}");
                    failed = true;
                }
                Err(_) => {
                    println!("peer={index} target={label} find_value=deadline");
                    failed = true;
                }
            }
        }
        conn.close(0, b"directory probe complete");
    }
    timeout(DEADLINE, harness.transport.shutdown())
        .await
        .context("endpoint shutdown deadline")?;
    ensure!(!failed, "one or more directory operations failed");
    Ok(())
}
