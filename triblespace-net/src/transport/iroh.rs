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

use super::{Alpn, Conn, Harness, Incoming, PeerId, Transport};
use crate::host::PeerConfig;

/// Capacity for the inbound-connection channel. Inbound connection forwarding
/// fails closed when this queue is full so
/// router handler tasks cannot accumulate behind an awaited send.
const CHANNEL_CAP: usize = 64;

/// The protocol ALPN forwarded into the host loop.
const FORWARDED_ALPNS: [Alpn; 1] = [crate::protocol::PILE_SYNC_ALPN];

#[derive(Clone)]
pub struct IrohTransport {
    ep: iroh::Endpoint,
    /// Keeps the router (and through it the registered protocol handlers)
    /// alive for the transport's lifetime. The host loop never touches these;
    /// they exist below the seam.
    _alive: Arc<Anchors>,
}

impl IrohTransport {
    /// The endpoint the transport runs on.
    pub fn endpoint(&self) -> &iroh::Endpoint {
        &self.ep
    }

    /// Tell the endpoint where `address`'s endpoint listens, beside what
    /// discovery finds. A host learns its pile's sync daemon this way, and a
    /// test can give a loopback peer's address the same way.
    pub fn learn(&self, address: EndpointAddr) {
        use iroh::address_lookup::{EndpointInfo, MemoryLookup};
        match self.ep.address_lookup() {
            Ok(services) => services.add(MemoryLookup::from_endpoint_info([EndpointInfo::from(
                address,
            )])),
            Err(error) => warn!(%error, "endpoint closed; address not learned"),
        }
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

impl super::SendStream for iroh::endpoint::SendStream {
    fn reset(&mut self, code: u32) {
        // An already finished or reset stream has nothing left to abandon.
        let _ = iroh::endpoint::SendStream::reset(self, code.into());
    }

    /// The owned buffer goes to the stream as it is. `write_many_chunks`
    /// takes a fully written chunk out of the slice (leaving `bytes` empty)
    /// and splits a partly written one in place (leaving the unwritten
    /// suffix), and is cancel safe. noq may copy and coalesce small chunks
    /// into its send buffer and can retain a larger owned chunk as it is,
    /// holding its owner until the bytes are acknowledged or abandoned.
    fn write_owned<'a>(&'a mut self, bytes: &'a mut bytes::Bytes) -> super::WriteOwned<'a> {
        Box::pin(async move {
            if bytes.is_empty() {
                return Ok(0);
            }
            let mut chunks: &mut [bytes::Bytes] = std::slice::from_mut(bytes);
            self.write_many_chunks(&mut chunks)
                .await
                .map_err(std::io::Error::from)
        })
    }
}

impl super::RecvStream for iroh::endpoint::RecvStream {
    fn stop(&mut self, code: u32) {
        let _ = iroh::endpoint::RecvStream::stop(self, code.into());
    }
}

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

    fn local_id(&self) -> PeerId {
        *self.ep.id().as_bytes()
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<Self::Conn> {
        let id = EndpointId::from_bytes(&peer).map_err(|e| anyhow::anyhow!("peer id: {e}"))?;
        let ep = self.ep.clone();
        let connect = self._alive._runtime.spawn(async move {
            debug!(target: "triblespace_net::handoff", peer = %id, "iroh outbound connection started");
            let result = ep.connect(id, alpn).await;
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
    let mut builder = n0_endpoint_builder(secret);
    if let Some(addr) = config.bind {
        // Exactly this socket: the default wildcard sockets are dropped.
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|error| anyhow::anyhow!("iroh bind address {addr}: {error}"))?;
    }
    let ep = bind_n0_endpoint(builder).await?;
    Ok(bind_with_endpoint(ep).await)
}

/// Wire the protocol forwarder and router over an already-bound endpoint, then
/// return the [`Harness`] the host loop runs against.
///
/// Factored out of [`bind`] so a caller can supply its own endpoint —
/// notably an `iroh::test_utils` `TestNetwork` endpoint for integration
/// tests that wire two real `Peer`s over a virtual transport (no relays,
/// no DNS), the way the real-transport integration tests do.
pub async fn bind_with_endpoint(ep: iroh::Endpoint) -> Harness<IrohTransport> {
    use iroh::protocol::Router;

    let mut router_builder = Router::builder(ep.clone());

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::{SecretKey, TransportAddr};

    use super::*;
    use crate::protocol::PILE_SYNC_ALPN;

    /// An endpoint on one loopback socket that finds no address by itself:
    /// no relay and no address lookup.
    async fn loopback(byte: u8) -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(SecretKey::from_bytes(&[byte; 32]))
            .relay_mode(iroh::RelayMode::Disabled)
            .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    /// A dial by key goes where the transport learned the key listens: the
    /// addresses a daemon recorded in its pile, or a test's loopback socket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_by_key_goes_to_the_learned_address() {
        let listener = bind_with_endpoint(loopback(1).await).await;
        let dialler = bind_with_endpoint(loopback(2).await).await;
        let id = listener.transport.local_id();
        let deadline = Duration::from_secs(5);
        let unknown =
            tokio::time::timeout(deadline, dialler.transport.dial(id, PILE_SYNC_ALPN)).await;
        assert!(
            !matches!(unknown, Ok(Ok(_))),
            "nothing told the dialler where the listener is"
        );
        dialler.transport.learn(EndpointAddr::from_parts(
            EndpointId::from_bytes(&id).unwrap(),
            listener
                .transport
                .endpoint()
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        ));
        let conn = tokio::time::timeout(deadline, dialler.transport.dial(id, PILE_SYNC_ALPN))
            .await
            .expect("the learned address answers")
            .unwrap();
        assert_eq!(conn.remote_id(), id);
        dialler.transport.shutdown().await;
        listener.transport.shutdown().await;
    }

    /// The QUIC override of `write_owned`: a buffer larger than the stream
    /// accepts at once is written in order across several calls, a fully
    /// written buffer is left empty (or the caller would write it again), and
    /// FIN after the owned writes ends the stream where the bytes end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_writes_reach_the_peer_in_order_and_empty_the_buffer() {
        use tokio::io::AsyncWriteExt as _;

        use crate::transport::SendStream as _;

        let mut listener = bind_with_endpoint(loopback(3).await).await;
        let dialler = bind_with_endpoint(loopback(4).await).await;
        let id = listener.transport.local_id();
        dialler.transport.learn(EndpointAddr::from_parts(
            EndpointId::from_bytes(&id).unwrap(),
            listener
                .transport
                .endpoint()
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        ));
        let deadline = Duration::from_secs(10);
        let conn = tokio::time::timeout(deadline, dialler.transport.dial(id, PILE_SYNC_ALPN))
            .await
            .unwrap()
            .unwrap();
        let payload: Vec<u8> = (0..8 << 20).map(|i: u32| (i % 251) as u8).collect();
        let expected = payload.clone();
        let reader = tokio::spawn(async move {
            let incoming = listener.incoming.recv().await.unwrap();
            let (_send, mut recv) = incoming.conn.accept_bi().await.unwrap();
            let mut got = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut got).await.unwrap();
            (got, listener)
        });
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let mut owned = bytes::Bytes::from(payload);
        let mut calls = 0;
        while !owned.is_empty() {
            let before = owned.len();
            let written = tokio::time::timeout(deadline, send.write_owned(&mut owned))
                .await
                .unwrap()
                .unwrap();
            assert!(written > 0);
            assert_eq!(owned.len(), before - written, "advanced by exactly what was written");
            calls += 1;
        }
        assert_eq!(send.write_owned(&mut owned).await.unwrap(), 0);
        send.shutdown().await.unwrap();
        let (got, listener) = tokio::time::timeout(deadline, reader).await.unwrap().unwrap();
        assert_eq!(got.len(), expected.len());
        assert!(got == expected, "bytes arrive in order, once");
        assert!(calls > 1, "8 MiB exceeds one write's stream credit");
        dialler.transport.shutdown().await;
        listener.transport.shutdown().await;
    }
}
