//! One connection per peer pair over real QUIC: crossed dials converge on the
//! connection dialled by the lower key, and it carries both directions; a
//! stream with an unknown tag is reset and stopped without the connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::endpoint::{ReadError, VarInt, WriteError, presets};
use iroh::{Endpoint, test_utils::test_transport::TestNetwork};
use iroh_base::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use triblespace_net::connection::{Connection, ConnectionTable, RESET_UNKNOWN, Service};
use triblespace_net::protocol::TAG_DHT;
use triblespace_net::transport::iroh::{IrohConn, IrohTransport, bind_with_endpoint};
use triblespace_net::transport::{Conn, Harness, PeerId, RecvStream, SendStream, Transport};

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
        W: SendStream,
        R: RecvStream,
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
    } = bind_with_endpoint(endpoint(network).await).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_tag_resets_and_stops_only_its_stream() {
    let network = TestNetwork::new();
    let (client, server) = tokio::join!(node(&network), node(&network));
    let connection = tokio::time::timeout(Duration::from_secs(5), client.table.connect(server.id))
        .await
        .expect("dial did not establish")
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    // No stream type uses this byte.
    send.write_all(&[0x7E]).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut [0; 1]))
        .await
        .expect("the stream was neither reset nor finished");
    let error = read.unwrap_err();
    // A finish would read as a clean end of the stream instead.
    assert_eq!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ReadError>()),
        Some(&ReadError::Reset(VarInt::from_u32(RESET_UNKNOWN))),
        "{error}"
    );
    let error = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(error) = send.write_all(b"unread").await {
                return error;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the stream was not stopped");
    assert_eq!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<WriteError>()),
        Some(&WriteError::Stopped(VarInt::from_u32(RESET_UNKNOWN))),
        "{error}"
    );
    drop((send, recv));

    assert_eq!(echo(&connection, b"still serving").await, b"still serving");
    assert!(client.table.current(server.id) == Some(connection));
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1, "no second dial");

    client.accept.abort();
    server.accept.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            client.table.transport().shutdown(),
            server.table.transport().shutdown()
        )
    })
    .await
    .expect("transport shutdown stalled");
}
