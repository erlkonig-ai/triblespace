//! Production [`Transport`] adapter over iroh QUIC.
//!
//! Everything iroh-specific that used to live inline in the host
//! loop's startup — endpoint building (relay map, CA roots, mDNS +
//! pkarr + mDNS address lookup) and protocol-handler registration — happens in [`bind`], which returns the
//! transport-agnostic [`Harness`] the host loop runs against.

use std::sync::Arc;

use futures::StreamExt;
use iroh_base::{EndpointAddr, EndpointId};
use tokio::sync::mpsc;
use tracing::{Instrument as _, debug, warn};
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};

use super::{Alpn, Conn, Harness, Incoming, PeerId, Transport};
use crate::host::PeerConfig;
use crate::wake::CollectionWakePlane;

/// Capacity for the inbound-connection channel. Inbound connection forwarding
/// fails closed when this queue is full so
/// router handler tasks cannot accumulate behind an awaited send.
const CHANNEL_CAP: usize = 64;

/// The protocol ALPN forwarded into the host loop.
const FORWARDED_ALPNS: [Alpn; 1] = [crate::protocol::PILE_SYNC_ALPN];

#[derive(Clone)]
pub struct IrohTransport {
    ep: iroh::Endpoint,
    wake_plane: CollectionWakePlane,
    /// Explicitly configured routes, keyed by endpoint identity.
    ///
    /// `Endpoint::connect(EndpointId, ..)` delegates route selection to
    /// discovery.  That is useful for ordinary internet peers, but it silently
    /// discards a caller-supplied direct address (notably the Spark cluster's
    /// 200 Gbit fabric).  Retaining the full address here makes an explicit
    /// route authoritative for outbound protocol connections while preserving
    /// discovery as the fallback for address-less peers.
    peers: Arc<PATCH<32, IdentitySchema, EndpointAddr>>,
    /// Keeps the router (and through it the registered protocol handlers)
    /// alive for the transport's lifetime. The host loop never touches these;
    /// they exist below the seam.
    _alive: Arc<Anchors>,
}

impl IrohTransport {
    /// Collection wake plane sharing this transport's endpoint and router.
    pub fn wake_plane(&self) -> CollectionWakePlane {
        self.wake_plane.clone()
    }
}

/// Owner of everything that must not drop while the node runs.
struct Anchors {
    _router: iroh::protocol::Router,
    /// Runtime that owns the endpoint and router. Outbound handshakes are
    /// spawned here so cancelling a caller does not drop iroh's `Connecting`
    /// future before endpoint shutdown has observed and closed it.
    _runtime: tokio::runtime::Handle,
}

#[derive(Clone)]
pub struct IrohConn(pub iroh::endpoint::Connection);

impl Conn for IrohConn {
    type SendHalf = iroh::endpoint::SendStream;
    type RecvHalf = iroh::endpoint::RecvStream;

    fn remote_id(&self) -> PeerId {
        *self.0.remote_id().as_bytes()
    }

    async fn open_bi(&self) -> anyhow::Result<(Self::SendHalf, Self::RecvHalf)> {
        self.0
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("open_bi: {e}"))
    }

    async fn accept_bi(&self) -> Option<(Self::SendHalf, Self::RecvHalf)> {
        self.0.accept_bi().await.ok()
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(code.into(), reason);
    }
}

impl Transport for IrohTransport {
    type Conn = IrohConn;
    type WakePlane = CollectionWakePlane;

    fn local_id(&self) -> PeerId {
        *self.ep.id().as_bytes()
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<Self::Conn> {
        let id = EndpointId::from_bytes(&peer).map_err(|e| anyhow::anyhow!("peer id: {e}"))?;
        let addr = self
            .peers
            .get(id.as_bytes())
            .cloned()
            .unwrap_or_else(|| EndpointAddr::from(id));
        let ep = self.ep.clone();
        let connect = self._alive._runtime.spawn(async move {
            debug!(target: "triblespace_net::handoff", peer = %id, "iroh outbound connection started");
            let result = ep.connect(addr, alpn).await;
            match &result {
                Ok(connection) => debug!(
                    target: "triblespace_net::handoff",
                    peer = %id,
                    connection = connection.stable_id(),
                    "iroh outbound connection registered"
                ),
                Err(error) => debug!(target: "triblespace_net::handoff", peer = %id, %error, "iroh outbound connection failed"),
            }
            result
        });
        let conn = connect
            .await
            .map_err(|e| anyhow::anyhow!("connect task: {e}"))?
            .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
        // Subscribe before taking the snapshot so a selection change between
        // the two operations is observed rather than silently lost.
        let mut path_events = conn.path_events();
        let paths = conn.paths();
        if let Some(path) = paths.iter().find(|path| path.is_selected()) {
            tracing::info!(
                peer = %conn.remote_id(),
                remote = ?path.remote_addr(),
                direct = path.is_ip(),
                "iroh connection selected path"
            );
        }
        let remote_id = conn.remote_id();
        tokio::spawn(async move {
            while let Some(event) = path_events.next().await {
                match event {
                    iroh::endpoint::PathEvent::Selected {
                        id,
                        remote_addr,
                        local_addr,
                        ..
                    } => tracing::info!(
                        peer = %remote_id,
                        ?id,
                        remote = ?remote_addr,
                        local = ?local_addr,
                        direct = remote_addr.is_ip(),
                        "iroh connection selected path changed"
                    ),
                    iroh::endpoint::PathEvent::Lagged { missed, .. } => tracing::warn!(
                        peer = %remote_id,
                        missed,
                        "iroh connection path observer lagged"
                    ),
                    _ => {}
                }
            }
        });
        Ok(IrohConn(conn))
    }

    async fn shutdown(&self) {
        // The router owns the endpoint accept loop and performs the required
        // ordering: stop protocol handlers, cancel accepts, then await
        // Endpoint::close. Closing the endpoint directly while the router is
        // still accepting can deadlock shutdown.
        if let Err(error) = self._alive._router.shutdown().await {
            warn!(%error, "iroh router shutdown failed");
        }
    }

    fn collection_wake_plane(&self) -> CollectionWakePlane {
        self.wake_plane.clone()
    }
}

/// Thin `ProtocolHandler` that forwards accepted connections (tagged
/// with their ALPN) into the harness channel. The host loop owns the
/// conversation from there.
///
/// The handler returns as soon as the connection is forwarded; the
/// `Connection` is internally reference-counted, so the clone living
/// in the channel (and later in the host's per-connection task) keeps
/// it alive after the router's accept task completes.
#[derive(Clone)]
struct ForwardHandler {
    alpn: Alpn,
    tx: mpsc::Sender<Incoming<IrohConn>>,
}

impl std::fmt::Debug for ForwardHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for ForwardHandler {
    async fn on_accepting(
        &self,
        accepting: iroh::endpoint::Accepting,
    ) -> Result<iroh::endpoint::Connection, iroh::protocol::AcceptError> {
        // ALPN selection precedes this hook, but a successful QUIC handshake
        // does not yet mean iroh has registered the connection with its socket
        // actor. Keep that handoff visible without changing its cancellation
        // or acceptance semantics.
        let span = tracing::debug_span!(
            target: "triblespace_net::handoff",
            "iroh_accept",
            alpn = %String::from_utf8_lossy(self.alpn),
            remote = ?accepting.remote_addr(),
        )
        .or_current();
        async move {
            debug!(target: "triblespace_net::handoff", "awaiting iroh connection completion");
            let connection = accepting.await?;
            debug!(
                target: "triblespace_net::handoff",
                peer = %connection.remote_id(),
                connection = connection.stable_id(),
                "iroh connection registered; protocol handler ready"
            );
            Ok(connection)
        }
        .instrument(span)
        .await
    }

    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let peer = connection.remote_id();
        let connection_id = connection.stable_id();
        let incoming = Incoming {
            alpn: self.alpn,
            conn: IrohConn(connection),
        };
        match self.tx.try_send(incoming) {
            Ok(()) => debug!(
                target: "triblespace_net::handoff",
                %peer,
                connection = connection_id,
                "iroh connection forwarded to host"
            ),
            Err(tokio::sync::mpsc::error::TrySendError::Full(incoming)) => {
                warn!(%peer, connection = connection_id, "inbound connection queue full; rejecting connection");
                incoming
                    .conn
                    .close(1, b"inbound connection queue capacity exceeded");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(incoming)) => {
                debug!(target: "triblespace_net::handoff", %peer, "inbound host queue closed");
                incoming
                    .conn
                    .close(1, b"inbound connection handler stopped");
            }
        }
        Ok(())
    }
}

/// Build one ordinary internet-capable iroh endpoint.
///
/// Binding is deliberately not gated on [`iroh::Endpoint::online`]. A relay
/// outage must not prevent a node with a usable direct route from starting;
/// relay selection and address publication continue in iroh's background
/// tasks after this function returns.
async fn bind_n0_endpoint(builder: iroh::endpoint::Builder) -> anyhow::Result<iroh::Endpoint> {
    let ep = builder
        .bind()
        .await
        .map_err(|error| anyhow::anyhow!("iroh endpoint bind: {error}"))?;

    // mDNS is best-effort — add it post-bind so a failure (e.g. no multicast
    // on the interface) degrades to N0 discovery rather than failing the
    // endpoint.
    match iroh_mdns_address_lookup::MdnsAddressLookup::builder().build(ep.id()) {
        Ok(mdns) => {
            if let Ok(lookups) = ep.address_lookup() {
                lookups.add(mdns);
            }
        }
        Err(error) => {
            warn!(%error, "mDNS discovery init failed; continuing without LAN discovery")
        }
    }
    Ok(ep)
}

/// Start from the same ordinary iroh/N0 reachability policy everywhere.
///
/// Authorization and inventory-reconciliation semantics are layered above this builder;
/// neither a direct address nor relay reachability grants an operation.
fn n0_endpoint_builder(secret: iroh_base::SecretKey) -> iroh::endpoint::Builder {
    let relay_map = crate::host::dot_stripped_default_relay_map();
    iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret)
        .ca_tls_config(iroh::tls::CaTlsConfig::system())
        .relay_mode(iroh::RelayMode::Custom(relay_map))
}

/// Build the production transport: bind the ordinary iroh endpoint, register
/// the protocol-forwarding handler, and spawn the router.
///
/// Binding failure is returned to the caller so constructing a production
/// peer can never appear to succeed with an already-dead network thread.
pub async fn bind(
    secret: iroh_base::SecretKey,
    config: &PeerConfig,
) -> anyhow::Result<Harness<IrohTransport>> {
    let ep = bind_n0_endpoint(n0_endpoint_builder(secret)).await?;
    Ok(bind_with_endpoint(ep, config).await)
}

/// Wire the protocol forwarder and router over an already-bound endpoint, then
/// return the [`Harness`] the host loop runs against.
///
/// Factored out of [`bind`] so a caller can supply its own endpoint —
/// notably an `iroh::test_utils` `TestNetwork` endpoint for integration
/// tests that wire two real `Peer`s over a virtual transport (no relays,
/// no DNS), the way the real-transport integration tests do.
pub async fn bind_with_endpoint(ep: iroh::Endpoint, config: &PeerConfig) -> Harness<IrohTransport> {
    use iroh::address_lookup::{EndpointInfo, MemoryLookup};
    use iroh::protocol::Router;

    let peers = Arc::new(configured_routes(&config.peers));

    // Make configured routes available to iroh's discovery services as well
    // as `IrohTransport::dial`. A memory lookup bridges endpoint ids back to
    // the exact direct/fabric addresses supplied by the caller.
    if !config.peers.is_empty() {
        let lookup =
            MemoryLookup::from_endpoint_info(config.peers.iter().cloned().map(EndpointInfo::from));
        match ep.address_lookup() {
            Ok(services) => services.add(lookup),
            Err(error) => warn!(%error, "configured peer routes unavailable to iroh sub-protocols"),
        }
    }
    let mut router_builder = Router::builder(ep.clone());

    // Stock iroh-gossip owns membership and wake dissemination on the same
    // endpoint. Its typed facade exposes no general application payload path.
    let wake_plane = CollectionWakePlane::spawn(&ep);
    router_builder = router_builder.accept(iroh_gossip::ALPN, wake_plane.protocol_handler());

    // Protocol ALPNs forward into the harness channel; the host loop
    // dispatches them to the protocol handlers above the seam.
    let (inc_tx, inc_rx) = mpsc::channel::<Incoming<IrohConn>>(CHANNEL_CAP);
    for alpn in FORWARDED_ALPNS {
        router_builder = router_builder.accept(
            alpn,
            ForwardHandler {
                alpn,
                tx: inc_tx.clone(),
            },
        );
    }

    let router = router_builder.spawn();

    let transport = IrohTransport {
        ep,
        wake_plane,
        peers,
        _alive: Arc::new(Anchors {
            _router: router,
            _runtime: tokio::runtime::Handle::current(),
        }),
    };

    Harness {
        transport,
        incoming: inc_rx,
    }
}

fn configured_routes(peers: &[EndpointAddr]) -> PATCH<32, IdentitySchema, EndpointAddr> {
    let mut routes = PATCH::new();
    for addr in peers {
        // Configuration order remains authoritative for repeated identities.
        routes.replace(&PatchEntry::with_value(addr.id.as_bytes(), addr.clone()));
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_configured_identity_keeps_the_last_complete_address() {
        let first_id = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let other_id = iroh_base::SecretKey::from_bytes(&[8; 32]).public();
        let first = EndpointAddr::new(first_id).with_ip_addr("127.0.0.1:1001".parse().unwrap());
        let last = EndpointAddr::new(first_id).with_ip_addr("127.0.0.1:1002".parse().unwrap());
        let other = EndpointAddr::new(other_id);
        let routes = configured_routes(&[first, other.clone(), last.clone()]);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes.get(first_id.as_bytes()), Some(&last));
        assert_eq!(routes.get(other_id.as_bytes()), Some(&other));
    }
}
