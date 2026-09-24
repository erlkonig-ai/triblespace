//! Saturated request slots must not kill unrelated streams on a shared connection.

use crate::transport::sim::SimConn;

use super::*;

#[derive(Clone)]
struct AcceptedConn {
    inner: SimConn,
    accepted: tokio::sync::watch::Sender<usize>,
}

impl Conn for AcceptedConn {
    type SendHalf = <SimConn as Conn>::SendHalf;
    type RecvHalf = <SimConn as Conn>::RecvHalf;

    fn remote_id(&self) -> PeerId {
        self.inner.remote_id()
    }

    async fn open_bi(&self) -> anyhow::Result<(Self::SendHalf, Self::RecvHalf)> {
        self.inner.open_bi().await
    }

    async fn accept_bi(&self) -> Option<(Self::SendHalf, Self::RecvHalf)> {
        let stream = self.inner.accept_bi().await?;
        self.accepted.send_modify(|count| *count += 1);
        Some(stream)
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

#[derive(Clone)]
struct AcceptedTransport {
    inner: SimTransport,
    accepted: tokio::sync::watch::Sender<usize>,
}

impl Transport for AcceptedTransport {
    type Conn = AcceptedConn;
    type WakePlane = <SimTransport as Transport>::WakePlane;

    fn local_id(&self) -> PeerId {
        self.inner.local_id()
    }

    async fn dial(&self, peer: PeerId, alpn: crate::transport::Alpn) -> anyhow::Result<Self::Conn> {
        Ok(AcceptedConn {
            inner: self.inner.dial(peer, alpn).await?,
            accepted: self.accepted.clone(),
        })
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }

    fn collection_wake_plane(&self) -> Self::WakePlane {
        self.inner.collection_wake_plane()
    }
}

async fn saturated_requests_complete_without_closing_connection(connection_count: usize) {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let net = SimNet::new(
        0xBACC_0051,
        SimConfig {
            latency: Duration::ZERO..Duration::ZERO,
        },
    );
    let provider_key = SigningKey::from_bytes(&[111; 32]);
    let client_key = SigningKey::from_bytes(&[112; 32]);
    let provider = provider_key.verifying_key().to_bytes();
    let mut provider_harness = net.join(&provider_key);
    let client_harness = net.join(&client_key);
    let (snapshot_tx, snapshot) = tokio::sync::watch::channel(None);
    let (events, _events_rx) = tokio::sync::mpsc::channel(1);
    let requests = Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS_GLOBAL));
    let handler = SnapshotHandler {
        snapshot,
        health: Health::new(EndpointId::from_bytes(&provider).unwrap()),
        candidates: Arc::new(Mutex::new(RoutingTable::new(provider, []))),
        providers: Arc::new(Mutex::new(ProviderDirectory::new(provider))),
        serve_collections: false,
        local_id: provider,
        events,
        inbound_connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
        inbound_requests: requests.clone(),
    };
    let (accepted_tx, mut accepted_rx) = tokio::sync::watch::channel(0usize);
    let mut connections = Vec::new();
    let mut owners = Vec::new();
    for _ in 0..connection_count {
        let connection = client_harness
            .transport
            .dial(provider, PILE_SYNC_ALPN)
            .await
            .unwrap();
        let incoming = provider_harness.incoming.recv().await.unwrap();
        assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
        let permit = handler
            .inbound_connections
            .clone()
            .try_acquire_owned()
            .unwrap();
        let server_connection = AcceptedConn {
            inner: incoming.conn,
            accepted: accepted_tx.clone(),
        };
        let handler = handler.clone();
        owners.push(tokio::spawn(async move {
            handler
                .handle::<AcceptedTransport>(server_connection, permit)
                .await;
        }));
        connections.push(connection);
    }

    assert_eq!(MAX_REQUESTS_GLOBAL % connection_count, 0);
    let per_connection = MAX_REQUESTS_GLOBAL / connection_count;
    assert!(per_connection <= MAX_REQUESTS_PER_CONNECTION);
    let target = *blake3::hash(b"request saturation control").as_bytes();
    let mut held_streams = Vec::new();
    for connection in &connections {
        for _ in 0..per_connection {
            let (mut send, recv) = connection.open_bi().await.unwrap();
            send_u8(&mut send, OP_FIND_NODE).await.unwrap();
            send_hash(&mut send, &target).await.unwrap();
            // FIND_NODE waits for EOF before responding. These are legitimate
            // in-flight requests; no artificial semaphore acquisition is used.
            held_streams.push((send, recv));
        }
    }
    tokio::time::timeout(
        Duration::from_secs(1),
        accepted_rx.wait_for(|count| *count == MAX_REQUESTS_GLOBAL),
    )
    .await
    .expect("handler did not accept the initial requests")
    .unwrap();
    assert_eq!(requests.available_permits(), 0);

    // The acceptance notification is the barrier: the production handler has
    // received this stream while all request slots are still occupied. No sleep
    // or scheduler-iteration count guesses when the overload branch ran.
    let (mut queued_send, mut queued_recv) = connections[0].open_bi().await.unwrap();
    send_u8(&mut queued_send, OP_FIND_NODE).await.unwrap();
    send_hash(&mut queued_send, &target).await.unwrap();
    queued_send.shutdown().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        accepted_rx.wait_for(|count| *count == MAX_REQUESTS_GLOBAL + 1),
    )
    .await
    .expect("handler did not accept the waiting request")
    .unwrap();
    assert_eq!(requests.available_permits(), 0);
    assert!(
        !owners[0].is_finished(),
        "a legitimate request at capacity terminated the entire connection"
    );

    for (send, _) in &mut held_streams {
        send.shutdown().await.unwrap();
    }
    for (_, mut recv) in held_streams {
        assert_eq!(recv_u8(&mut recv).await.unwrap(), 0);
        require_stream_eof(&mut recv).await.unwrap();
    }
    assert_eq!(recv_u8(&mut queued_recv).await.unwrap(), 0);
    require_stream_eof(&mut queued_recv).await.unwrap();

    // Do not let a reconnect mask connection destruction. A further request
    // must use the exact same Conn object and complete normally.
    let (mut send, mut recv) = connections[0].open_bi().await.unwrap();
    send_u8(&mut send, OP_FIND_NODE).await.unwrap();
    send_hash(&mut send, &target).await.unwrap();
    send.shutdown().await.unwrap();
    assert_eq!(recv_u8(&mut recv).await.unwrap(), 0);
    require_stream_eof(&mut recv).await.unwrap();
    for connection in connections {
        connection.close(0, b"test complete");
    }
    for owner in owners {
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .expect("connection handler did not stop")
            .unwrap();
    }
    drop(snapshot_tx);
}

#[tokio::test(start_paused = true)]
async fn per_connection_saturation_backpressures_without_closing_active_streams() {
    saturated_requests_complete_without_closing_connection(1).await;
}

#[tokio::test(start_paused = true)]
async fn global_saturation_backpressures_without_closing_active_streams() {
    // Eight held requests on each connection exhaust the global sixteen while
    // leaving room under either connection's own sixteen-request limit.
    assert!(MAX_REQUESTS_GLOBAL / 2 < MAX_REQUESTS_PER_CONNECTION);
    saturated_requests_complete_without_closing_connection(2).await;
}
