//! The connection table: shared and cancelled dials, tie-breaks, typed
//! streams, idle deadlines and eviction.

use std::time::Duration;

use futures::poll;
use tokio::io::AsyncWriteExt as _;

use crate::connection::{
    CONNECTION_IDLE_DEADLINE, DRAIN_GRACE, FRAME_OPEN, MAX_CONNECTIONS,
    MAX_HELD_REQUESTS_PER_CONNECTION, MAX_RECON_FRAME_BYTES, MAX_REQUESTS_GLOBAL, RESET_BUSY,
    RESET_REPLACED, RESET_UNKNOWN, write_frame,
};
use crate::protocol::{OP_FIND_VALUE, TAG_DHT, TAG_RECON, op_find_value, send_hash};
use crate::transport::sim::{SimConfig, SimConn, SimNet, SimTransport};

use super::*;

fn network(latency: Duration) -> SimNet {
    SimNet::new(
        0xCACE_11ED,
        SimConfig {
            latency: latency..latency,
        },
    )
}

fn key(index: usize) -> SigningKey {
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

/// Let every runnable task reach its next wait before time moves on.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

/// A node whose table dials, accepts and serves an empty snapshot.
struct Node {
    peer: PeerId,
    client: ProviderClient<SimTransport>,
    table: ConnectionTable<SimTransport, SnapshotHandler>,
    server: tokio::task::JoinHandle<()>,
}

impl Node {
    fn join(net: &SimNet, key: &SigningKey) -> Self {
        let mut harness = net.join(key);
        let peer = harness.transport.local_id();
        let client =
            ProviderClient::for_test(harness.transport.clone(), RoutingTable::new(peer, []));
        let table = client.connections.clone();
        let connections = table.clone();
        let server = tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                connections.accept(incoming.conn);
            }
        });
        Self {
            peer,
            client,
            table,
            server,
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Open the dialler's `recon/1` stream by hand on a raw connection.
async fn open_recon(conn: &SimConn, sequence: u64) -> <SimConn as Conn>::SendHalf {
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send_u8(&mut send, TAG_RECON).await.unwrap();
    write_frame(&mut send, FRAME_OPEN, &sequence.to_be_bytes())
        .await
        .unwrap();
    send
}

/// Open a FIND_VALUE request and withhold its end: the server holds the
/// stream, serving or waiting for a permit, until the request ends.
async fn held_find_value<C: Conn>(conn: &C) -> (C::SendHalf, C::RecvHalf) {
    let (mut send, recv) = conn.open_bi().await.unwrap();
    send_u8(&mut send, TAG_DHT).await.unwrap();
    send_u8(&mut send, OP_FIND_VALUE).await.unwrap();
    send_hash(&mut send, &[0; 32]).await.unwrap();
    (send, recv)
}

/// Whether one FIND_VALUE on `conn` is answered, with nothing: these
/// nodes know no routes and hold no leases.
async fn answers_empty<C: Conn>(conn: &C) -> bool {
    op_find_value(conn, &[0; 32]).await.unwrap() == (vec![], vec![])
}

/// Whether a read fails with the stream reset carrying `code`.
async fn reads_reset<R: tokio::io::AsyncRead + Unpin>(recv: &mut R, code: u32) -> bool {
    match tokio::time::timeout(Duration::from_secs(1), recv.read(&mut [0; 1])).await {
        Ok(Err(error)) => {
            error.kind() == std::io::ErrorKind::ConnectionReset
                && error.to_string().contains(&format!("code {code}"))
        }
        _ => false,
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_unique_dials_leave_no_dials_behind() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &SigningKey::from_bytes(&[255; 32]));
    for index in 0..(MAX_CONNECTIONS * 4) {
        let server = net.join(&key(index));
        let peer = server.transport.local_id();
        net.stall_dials(peer);
        assert!(client.table.connect(peer).now_or_never().is_none());
        assert_eq!(net.dial_count(client.peer, peer), 1);
        tokio::task::yield_now().await;
    }
    assert!(
        client.table.peers().is_empty(),
        "cancelled dials must not accumulate outside the bounded table"
    );
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_follower_keeps_the_shared_dial_and_its_connection() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &SigningKey::from_bytes(&[255; 32]));
    let server = Node::join(&net, &key(1));
    let mut first = Box::pin(client.table.connect(server.peer));
    let mut follower = Box::pin(client.table.connect(server.peer));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut follower).is_pending());
    drop(follower);
    assert_eq!(client.table.peers(), BTreeSet::from([server.peer]));

    let mut late = Box::pin(client.table.connect(server.peer));
    assert!(poll!(&mut late).is_pending());
    assert_eq!(net.dial_count(client.peer, server.peer), 1);
    let (first, late) = tokio::join!(first, late);
    let first = first.unwrap();
    assert!(first == late.unwrap());

    let cached = client.table.connect(server.peer).await.unwrap();
    assert!(cached == first);
    assert_eq!(net.dial_count(client.peer, server.peer), 1);
    assert_eq!(client.table.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_initializer_preserves_waiter_takeover() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &SigningKey::from_bytes(&[255; 32]));
    let server = Node::join(&net, &key(2));
    net.stall_dials(server.peer);
    let mut first = Box::pin(client.table.connect(server.peer));
    let mut follower = Box::pin(client.table.connect(server.peer));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut follower).is_pending());
    net.unstall_dials(server.peer);
    drop(first);
    assert!(poll!(&mut follower).is_pending());

    let mut late = Box::pin(client.table.connect(server.peer));
    assert!(poll!(&mut late).is_pending());
    assert_eq!(net.dial_count(client.peer, server.peer), 2);
    let (follower, late) = tokio::join!(follower, late);
    assert!(follower.unwrap() == late.unwrap());
    assert_eq!(net.dial_count(client.peer, server.peer), 2);
}

#[tokio::test(start_paused = true)]
async fn cancelling_every_waiter_removes_the_dial_in_either_order() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &SigningKey::from_bytes(&[255; 32]));
    let server = Node::join(&net, &key(3));
    net.stall_dials(server.peer);
    for initializer_first in [true, false] {
        let mut first = Box::pin(client.table.connect(server.peer));
        let mut follower = Box::pin(client.table.connect(server.peer));
        assert!(poll!(&mut first).is_pending());
        assert!(poll!(&mut follower).is_pending());
        if initializer_first {
            drop(first);
            assert_eq!(client.table.peers().len(), 1);
            drop(follower);
        } else {
            drop(follower);
            assert_eq!(client.table.peers().len(), 1);
            drop(first);
        }
        assert!(client.table.peers().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn failed_and_timed_out_dials_are_retryable_and_leave_nothing_behind() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &SigningKey::from_bytes(&[255; 32]));
    let server = Node::join(&net, &key(5));
    net.crash(server.peer);
    assert!(client.table.connect(server.peer).await.is_err());
    assert!(client.table.peers().is_empty());
    net.revive(server.peer);
    net.stall_dials(server.peer);
    assert!(client.table.connect(server.peer).await.is_err());
    assert!(client.table.peers().is_empty());
    net.unstall_dials(server.peer);
    assert!(client.table.connect(server.peer).await.is_ok());
    assert_eq!(client.table.len(), 1);
    assert_eq!(net.dial_count(client.peer, server.peer), 3);
}

#[tokio::test(start_paused = true)]
async fn crossed_dials_keep_the_connection_dialled_by_the_lower_key() {
    let net = network(Duration::from_secs(1));
    let left = Node::join(&net, &key(1));
    let right = Node::join(&net, &key(2));
    let (from_left, from_right) = tokio::join!(
        left.table.connect(right.peer),
        right.table.connect(left.peer)
    );
    from_left.unwrap();
    from_right.unwrap();
    assert_eq!(net.dial_count(left.peer, right.peer), 1);
    assert_eq!(net.dial_count(right.peer, left.peer), 1);
    settle().await;

    let lower = left.peer.min(right.peer);
    let on_left = left.table.current(right.peer).unwrap();
    let on_right = right.table.current(left.peer).unwrap();
    assert_eq!(on_left.dialler(), lower);
    assert_eq!(on_right.dialler(), lower);
    assert_eq!(on_left.sequence(), on_right.sequence());
    assert!(on_left.sequence().is_some());

    // The loser drains and closes; one connection carries both directions.
    tokio::time::sleep(DRAIN_GRACE + Duration::from_secs(1)).await;
    assert_eq!((left.table.len(), right.table.len()), (1, 1));
    assert!(answers_empty(&on_left).await);
    assert!(answers_empty(&on_right).await);
    assert!(left.table.current(right.peer) == Some(on_left));
    assert_eq!(net.dial_count(left.peer, right.peer), 1);
    assert_eq!(net.dial_count(right.peer, left.peer), 1);
}

#[tokio::test(start_paused = true)]
async fn a_double_dial_from_one_side_keeps_the_higher_sequence() {
    for newer_first in [false, true] {
        let net = network(Duration::from_secs(1));
        let server = Node::join(&net, &key(1));
        // Two tables under one key: the same node before and after a restart.
        // Joining again replaces the simulated address, so join both before
        // dialling.
        let older = Node::join(&net, &key(2));
        let newer = Node::join(&net, &key(2));
        let (old, new) = if newer_first {
            let new = newer.table.connect(server.peer).await.unwrap();
            (older.table.connect(server.peer).await.unwrap(), new)
        } else {
            let old = older.table.connect(server.peer).await.unwrap();
            (old, newer.table.connect(server.peer).await.unwrap())
        };
        assert!(new.sequence() > old.sequence());
        settle().await;

        let kept = server.table.current(newer.peer).unwrap();
        assert_eq!(kept.dialler(), newer.peer);
        assert_eq!(kept.sequence(), new.sequence());
        tokio::time::sleep(DRAIN_GRACE + Duration::from_secs(1)).await;
        assert_eq!(
            server.table.len(),
            1,
            "the lower sequence drains and closes"
        );
        assert!(older.table.current(server.peer).is_none());
        assert!(answers_empty(&new).await);
    }
}

#[tokio::test(start_paused = true)]
async fn an_unknown_tag_or_operation_resets_its_stream_and_the_connection_keeps_serving() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &key(1));
    let server = Node::join(&net, &key(2));
    let connection = client.table.connect(server.peer).await.unwrap();
    // No stream type uses the first byte, and no dht/1 operation the second:
    // 0x07 and 0x0C were PROVIDER_GET and FIND_NODE, which FIND_VALUE replaced.
    for request in [
        &[0x7E][..],
        &[TAG_DHT, 0x7E],
        &[TAG_DHT, 0x07],
        &[TAG_DHT, 0x0C],
    ] {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(request).await.unwrap();
        // A finish would read as a clean end of the stream instead.
        assert!(reads_reset(&mut recv, RESET_UNKNOWN).await, "{request:x?}");
        let error = send.write_all(b"unread").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "{error}");
        drop((send, recv));
        // The failure stayed on its stream, so the client keeps the
        // connection it shares with the server's own requests.
        client.table.invalidate(&connection);

        assert!(answers_empty(&connection).await);
        assert!(client.table.current(server.peer) == Some(connection.clone()));
    }
    assert_eq!(net.dial_count(client.peer, server.peer), 1);
    assert_eq!(server.table.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn find_value_is_served_under_the_dht_tag() {
    let net = network(Duration::from_secs(1));
    let client = Node::join(&net, &key(1));
    let server = Node::join(&net, &key(2));
    let locator = [7; 32];
    let lease = (key(3).verifying_key().to_bytes(), [3; 32]);
    let route = key(4).verifying_key().to_bytes();
    assert!(server.client.providers.lock().unwrap().put(
        locator,
        lease.0,
        lease.1,
        crate::clock::mono_now()
    ));
    server
        .client
        .candidates
        .lock()
        .unwrap()
        .promote_authenticated(route);
    let connection = client.table.connect(server.peer).await.unwrap();

    // FIND_VALUE is a dht/1 operation: the table dispatches the tag and the
    // handler the operation. One reply carries the route and the lease.
    let (routes, hints) = op_find_value(&connection, &locator).await.unwrap();
    assert_eq!(routes, [route]);
    assert_eq!(hints, [lease]);
    assert_eq!(net.dial_count(client.peer, server.peer), 1);
}

#[tokio::test(start_paused = true)]
async fn a_request_deadline_keeps_the_connection_the_peer_is_using() {
    let net = network(Duration::from_secs(1));
    let left = Node::join(&net, &key(1));
    let right = Node::join(&net, &key(2));
    let connection = left.table.connect(right.peer).await.unwrap();
    settle().await;
    // The right side has a request of its own in flight on the connection.
    let on_right = right.table.current(left.peer).unwrap();
    let (mut own_send, mut own_recv) = held_find_value(&on_right).await;

    // A third peer occupies every request slot on the right, so a request
    // from the left waits there until its deadline.
    let harness = net.join(&key(3));
    let third = harness
        .transport
        .dial(right.peer, PILE_SYNC_ALPN)
        .await
        .unwrap();
    let mut occupying = Vec::new();
    for _ in 0..MAX_REQUESTS_GLOBAL {
        occupying.push(held_find_value(&third).await);
    }
    settle().await;
    assert_eq!(right.table.available_requests(), 0);
    let error = left
        .client
        .find_value(right.peer, [7; 32])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"), "{error}");

    // The deadline closed nothing: the right side's request completes.
    assert!(left.table.current(right.peer) == Some(connection.clone()));
    own_send.shutdown().await.unwrap();
    crate::protocol::recv_find_value_response(&mut own_recv)
        .await
        .unwrap();
    for (mut send, _recv) in occupying {
        send.shutdown().await.unwrap();
    }
    left.client.find_value(right.peer, [0; 32]).await.unwrap();
    assert!(left.table.current(right.peer) == Some(connection));
    assert_eq!(net.dial_count(left.peer, right.peer), 1);
    assert_eq!(net.dial_count(right.peer, left.peer), 0);
}

#[tokio::test(start_paused = true)]
async fn request_streams_beyond_the_held_bound_are_reset() {
    let net = network(Duration::from_secs(1));
    let server = Node::join(&net, &key(1));
    let client = net.join(&key(2));
    let client_id = client.transport.local_id();
    let conn = client
        .transport
        .dial(server.peer, PILE_SYNC_ALPN)
        .await
        .unwrap();
    let _recon = open_recon(&conn, 1).await;
    // Every request slot is busy, and the opener abandons the next requests
    // while the server still holds them, waiting for a slot.
    let mut serving = Vec::new();
    for _ in 0..MAX_REQUESTS_GLOBAL {
        serving.push(held_find_value(&conn).await);
    }
    for _ in MAX_REQUESTS_GLOBAL..MAX_HELD_REQUESTS_PER_CONNECTION {
        let (mut send, recv) = held_find_value(&conn).await;
        send.shutdown().await.unwrap();
        drop((send, recv));
    }
    settle().await;
    assert_eq!(server.table.available_requests(), 0);

    // The connection holds no more: the next request is reset at once, so the
    // abandoned ones cannot take the opener's stream credit from recon/1.
    let (mut send, mut recv) = held_find_value(&conn).await;
    send.shutdown().await.unwrap();
    assert!(reads_reset(&mut recv, RESET_BUSY).await);
    let _reopened = open_recon(&conn, 1).await;
    settle().await;
    assert!(server.table.current(client_id).is_some());

    for (mut send, _recv) in serving {
        send.shutdown().await.unwrap();
    }
    assert!(answers_empty(&conn).await);
}

#[tokio::test(start_paused = true)]
async fn a_recon_stream_opened_later_replaces_one_whose_tag_arrives_later() {
    let net = network(Duration::from_secs(1));
    let server = Node::join(&net, &key(1));
    let client = net.join(&key(2));
    let client_id = client.transport.local_id();
    let conn = client
        .transport
        .dial(server.peer, PILE_SYNC_ALPN)
        .await
        .unwrap();
    let (mut earlier, mut earlier_recv) = conn.open_bi().await.unwrap();
    let (mut later, mut later_recv) = conn.open_bi().await.unwrap();
    let mut open = vec![TAG_RECON];
    open.extend_from_slice(&[FRAME_OPEN, 0, 0, 0, 8]);
    open.extend_from_slice(&5_u64.to_be_bytes());
    // The later stream's tag arrives first.
    later.write_all(&open).await.unwrap();
    settle().await;
    earlier.write_all(&open).await.unwrap();
    settle().await;

    assert!(reads_reset(&mut earlier_recv, RESET_REPLACED).await);
    assert!(poll!(Box::pin(later_recv.read(&mut [0; 1]))).is_pending());
    write_frame(&mut later, 0x7F, b"still read").await.unwrap();
    settle().await;
    assert!(server.table.current(client_id).is_some());
}

#[tokio::test(start_paused = true)]
async fn recon_protocol_violations_close_the_connection() {
    let net = network(Duration::from_secs(1));
    let server = Node::join(&net, &key(1));
    let open = |sequence: u64| {
        let mut frame = vec![FRAME_OPEN, 0, 0, 0, 8];
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame
    };
    let oversized = [
        &[FRAME_OPEN][..],
        &(MAX_RECON_FRAME_BYTES + 1).to_be_bytes(),
    ]
    .concat();
    let cases: [(&str, Vec<u8>, bool); 6] = [
        ("an oversized frame", oversized, false),
        (
            "a malformed opening frame",
            vec![FRAME_OPEN, 0, 0, 0, 3, 1, 2, 3],
            false,
        ),
        (
            "a frame before the opening one",
            vec![0x7F, 0, 0, 0, 0],
            false,
        ),
        ("a second opening frame", [open(1), open(1)].concat(), false),
        (
            "a frame cut short",
            vec![FRAME_OPEN, 0, 0, 0, 8, 1, 2, 3],
            true,
        ),
        (
            "a well-formed opening and a later kind",
            [open(1), vec![0x7F, 0, 0, 0, 0]].concat(),
            false,
        ),
    ];
    for (index, (case, frames, finish)) in cases.into_iter().enumerate() {
        let harness = net.join(&key(100 + index));
        let client = harness.transport.local_id();
        let conn = harness
            .transport
            .dial(server.peer, PILE_SYNC_ALPN)
            .await
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send_u8(&mut send, TAG_RECON).await.unwrap();
        send.write_all(&frames).await.unwrap();
        if finish {
            send.shutdown().await.unwrap();
        }
        let closed = tokio::time::timeout(Duration::from_secs(1), conn.accept_bi()).await;
        settle().await;
        if index == 5 {
            // Unknown kinds are skipped, so later milestones can add frames.
            assert!(closed.is_err(), "{case} closed the connection");
            assert!(server.table.current(client).is_some());
        } else {
            assert!(closed.unwrap().is_none(), "{case} kept the connection");
            assert!(server.table.current(client).is_none());
        }
    }

    // Only the dialler opens recon/1: one opened by the accepting side is a
    // violation too.
    let mut harness = net.join(&key(200));
    let acceptor = harness.transport.local_id();
    let dialled = server.table.connect(acceptor).await.unwrap();
    let conn = harness.incoming.recv().await.unwrap().conn;
    let _dialler_recon = conn.accept_bi().await.unwrap();
    let _send = open_recon(&conn, 7).await;
    let closed = tokio::time::timeout(Duration::from_secs(1), conn.accept_bi()).await;
    assert!(
        closed.unwrap().is_none(),
        "a recon/1 stream from the accepting side kept the connection"
    );
    settle().await;
    assert!(server.table.current(acceptor).is_none());
    assert!(dialled.open_bi().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn recon_frames_keep_a_connection_open_past_the_idle_deadline() {
    let net = network(Duration::from_secs(1));
    let server = Node::join(&net, &key(1));
    let quiet = net.join(&key(2));
    let chatty = net.join(&key(3));
    let (quiet_id, chatty_id) = (quiet.transport.local_id(), chatty.transport.local_id());
    let quiet = quiet
        .transport
        .dial(server.peer, PILE_SYNC_ALPN)
        .await
        .unwrap();
    let chatty = chatty
        .transport
        .dial(server.peer, PILE_SYNC_ALPN)
        .await
        .unwrap();
    let _quiet_recon = open_recon(&quiet, 1).await;
    let mut chatty_recon = open_recon(&chatty, 1).await;
    settle().await;
    assert!(server.table.current(quiet_id).is_some());

    // Frames every fifty seconds, on recon/1 alone, keep one connection open
    // well past the deadline; the other closes after it without a frame.
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(50)).await;
        write_frame(&mut chatty_recon, 0x7F, b"a later frame kind")
            .await
            .unwrap();
    }
    settle().await;
    assert!(server.table.current(quiet_id).is_none());
    assert!(quiet.accept_bi().await.is_none());
    assert!(server.table.current(chatty_id).is_some());
    assert!(answers_empty(&chatty).await);

    tokio::time::sleep(CONNECTION_IDLE_DEADLINE - Duration::from_secs(1)).await;
    assert!(server.table.current(chatty_id).is_some());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(server.table.current(chatty_id).is_none());
    assert!(chatty.accept_bi().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_retired_connection_with_a_stalled_request_still_goes_idle() {
    let net = network(Duration::from_secs(1));
    let server = Node::join(&net, &key(1));
    let client = net.join(&key(2));
    let dial = || client.transport.dial(server.peer, PILE_SYNC_ALPN);
    let older = dial().await.unwrap();
    let _older_recon = open_recon(&older, 1).await;
    // A request on the older connection stalls: no frame crosses it again.
    let (_stalled_send, mut stalled_recv) = held_find_value(&older).await;
    settle().await;
    let newer = dial().await.unwrap();
    let mut newer_recon = open_recon(&newer, 2).await;
    settle().await;
    assert_eq!(
        server
            .table
            .current(client.transport.local_id())
            .unwrap()
            .sequence(),
        Some(2)
    );

    // The request keeps the retired connection from draining, but not from
    // the idle deadline every connection has.
    tokio::time::sleep(DRAIN_GRACE * 10).await;
    assert_eq!(server.table.len(), 2);
    write_frame(&mut newer_recon, 0x7F, b"keep the winner")
        .await
        .unwrap();
    tokio::time::sleep(CONNECTION_IDLE_DEADLINE - DRAIN_GRACE * 5).await;
    assert_eq!(server.table.len(), 1);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), older.accept_bi())
            .await
            .unwrap()
            .is_none()
    );
    assert!(stalled_recv.read(&mut [0; 1]).await.is_err());
}

/// Fill one direction of `center`'s table past the cap, with its oldest
/// connection marked as a neighbour.
async fn eviction_spares_a_neighbour(inbound: bool) {
    // Short dials, so the whole fill stays far inside the idle deadline.
    let net = network(Duration::from_millis(10));
    let center = Node::join(&net, &key(100_000));
    let others = (0..MAX_CONNECTIONS + 2)
        .map(|index| Node::join(&net, &key(index)))
        .collect::<Vec<_>>();
    for (index, other) in others.iter().enumerate() {
        if index == MAX_CONNECTIONS {
            center
                .table
                .current(others[0].peer)
                .unwrap()
                .set_neighbour(true);
        }
        if inbound {
            other.table.connect(center.peer).await.unwrap();
        } else {
            center.table.connect(other.peer).await.unwrap();
        }
        settle().await;
    }
    // Neighbours do not count against the cap and are never chosen; the
    // least recently used of the others is closed on both sides.
    assert_eq!(center.table.len(), MAX_CONNECTIONS + 1);
    assert!(center.table.current(others[0].peer).is_some());
    assert!(center.table.current(others[1].peer).is_none());
    assert!(others[1].table.current(center.peer).is_none());
    for other in &others[2..] {
        assert!(center.table.current(other.peer).is_some());
    }
    assert_eq!(others[0].table.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn inbound_eviction_spares_a_neighbour_connection() {
    eviction_spares_a_neighbour(true).await;
}

#[tokio::test(start_paused = true)]
async fn outbound_eviction_spares_a_neighbour_and_stale_invalidation_is_harmless() {
    eviction_spares_a_neighbour(false).await;
    let net = network(Duration::from_millis(10));
    let client = Node::join(&net, &key(100_000));
    let server = Node::join(&net, &key(1));
    let old = client.table.connect(server.peer).await.unwrap();
    client.table.invalidate(&old);
    settle().await;
    let replacement = client.table.connect(server.peer).await.unwrap();
    assert!(replacement != old);
    client.table.invalidate(&old);
    settle().await;
    assert!(client.table.current(server.peer) == Some(replacement.clone()));
    assert!(answers_empty(&replacement).await);
    assert_eq!(net.dial_count(client.peer, server.peer), 2);
}

#[tokio::test(start_paused = true)]
async fn outbound_eviction_spares_a_connection_a_caller_holds() {
    let net = network(Duration::from_millis(10));
    let center = Node::join(&net, &key(100_000));
    let others = (0..MAX_CONNECTIONS + 1)
        .map(|index| Node::join(&net, &key(index)))
        .collect::<Vec<_>>();
    // The oldest connection is held by a caller that has not used it yet.
    let held = center.table.connect(others[0].peer).await.unwrap();
    for other in &others[1..] {
        center.table.connect(other.peer).await.unwrap();
        settle().await;
    }
    assert_eq!(center.table.len(), MAX_CONNECTIONS);
    assert!(center.table.current(others[0].peer) == Some(held.clone()));
    assert!(center.table.current(others[1].peer).is_none());
    assert!(answers_empty(&held).await);
}
