//! One connection per peer pair over real QUIC: crossed dials converge on the
//! connection dialled by the lower key, and it carries both directions.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::{Endpoint, endpoint::presets, test_utils::test_transport::TestNetwork};
use iroh_base::SecretKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use triblespace_net::connection::{Connection, ConnectionTable, Service};
use triblespace_net::host::PeerConfig;
use triblespace_net::protocol::TAG_DHT;
use triblespace_net::transport::iroh::{IrohConn, IrohTransport, bind_with_endpoint};
use triblespace_net::transport::{Conn, Harness, PeerId, Transport};

async fn endpoint(network: &TestNetwork) -> Endpoint {
    let key = SecretKey::generate();
    let transport = network.create_transport(key.public()).unwrap();
    Endpoint::builder(presets::N0)
        .secret_key(key)
        .relay_mode(iroh::RelayMode::Disabled)
        .add_custom_transport(transport)
        .clear_ip_transports()
        .clear_address_lookup()
        .address_lookup(network.address_lookup())
        .bind()
        .await
        .unwrap()
}

/// Answers each request with the bytes that followed its tag.
#[derive(Clone)]
struct Echo;

impl Service for Echo {
    async fn serve<W, R>(
        &self,
        _peer: PeerId,
        _tag: u8,
        send: &mut W,
        recv: &mut R,
    ) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
        R: AsyncRead + Unpin + Send,
    {
        let mut request = Vec::new();
        recv.read_to_end(&mut request).await?;
        send.write_all(&request).await?;
        Ok(())
    }
}

struct Node {
    id: PeerId,
    table: ConnectionTable<IrohTransport, Echo>,
    accepted: Arc<AtomicUsize>,
    accept: tokio::task::JoinHandle<()>,
}

async fn node(network: &TestNetwork) -> Node {
    let Harness {
        transport,
        mut incoming,
    } = bind_with_endpoint(
        endpoint(network).await,
        &PeerConfig {
            peers: vec![],
            qos: Default::default(),
            provider_publication_budget: Some(0),
            bind: None,
        },
    )
    .await;
    let id = transport.local_id();
    let table = ConnectionTable::new(transport, Echo);
    let accepted = Arc::new(AtomicUsize::new(0));
    let (connections, counted) = (table.clone(), accepted.clone());
    let accept = tokio::spawn(async move {
        while let Some(incoming) = incoming.recv().await {
            counted.fetch_add(1, Ordering::SeqCst);
            connections.accept(incoming.conn);
        }
    });
    Node {
        id,
        table,
        accepted,
        accept,
    }
}

async fn echo(connection: &Connection<IrohConn>, bytes: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&[TAG_DHT]).await.unwrap();
    send.write_all(bytes).await.unwrap();
    send.shutdown().await.unwrap();
    let mut reply = Vec::new();
    recv.read_to_end(&mut reply).await.unwrap();
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crossed_dials_converge_on_the_connection_dialled_by_the_lower_key() {
    let network = TestNetwork::new();
    let (left, right) = tokio::join!(node(&network), node(&network));
    // Both look for a connection before either exists, so both dial.
    let (from_left, from_right) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(left.table.connect(right.id), right.table.connect(left.id))
    })
    .await
    .expect("crossed dials did not establish");
    from_left.unwrap();
    from_right.unwrap();

    let lower = left.id.min(right.id);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let kept = left
                .table
                .current(right.id)
                .zip(right.table.current(left.id));
            if let Some((on_left, on_right)) = kept
                && on_left.dialler() == lower
                && on_right.dialler() == lower
                && on_left.sequence() == on_right.sequence()
                && left.table.len() == 1
                && right.table.len() == 1
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("crossed dials did not converge on one connection");
    assert_eq!(left.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(right.accepted.load(Ordering::SeqCst), 1);

    let on_left = left.table.current(right.id).unwrap();
    let on_right = right.table.current(left.id).unwrap();
    assert_eq!(echo(&on_left, b"from left").await, b"from left");
    assert_eq!(echo(&on_right, b"from right").await, b"from right");
    assert_eq!(left.accepted.load(Ordering::SeqCst), 1, "no third dial");
    assert_eq!(right.accepted.load(Ordering::SeqCst), 1, "no third dial");

    left.accept.abort();
    right.accept.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            left.table.transport().shutdown(),
            right.table.transport().shutdown()
        )
    })
    .await
    .expect("transport shutdown stalled");
}
