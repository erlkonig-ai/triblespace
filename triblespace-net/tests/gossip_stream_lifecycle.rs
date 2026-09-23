//! Clean half-closes preserve the other gossip leg; framing errors do not.

use std::time::Duration;

use futures::StreamExt;
use iroh::{Endpoint, endpoint::presets, test_utils::test_transport::TestNetwork};
use iroh_base::SecretKey;
use iroh_gossip::{
    Gossip, TopicId,
    api::{Event, GossipTopic},
};
use tokio::io::AsyncReadExt;
use triblespace_core::collection::CollectionHandle;
use triblespace_net::{host::PeerConfig, transport::Transport};

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

async fn receive_half_termination(malformed: bool) {
    let network = TestNetwork::new();
    let receiving_endpoint = endpoint(&network).await;
    let receiving_id = receiving_endpoint.id();
    let receiver = triblespace_net::transport::iroh::bind_with_endpoint(
        receiving_endpoint,
        &PeerConfig {
            peers: vec![],
            qos: Default::default(),
            provider_publication_budget: Some(0),
        },
    )
    .await;
    let sender = endpoint(&network).await;
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        sender.connect(receiving_id, iroh_gossip::ALPN),
    )
    .await
    .expect("virtual gossip connection did not establish")
    .unwrap();
    let mut stream = connection.open_uni().await.unwrap();
    if malformed {
        // A complete u32 length prefix followed by an invalid ProtoMessage.
        // Do not FIN: decoding this complete malformed frame must wake the
        // idle send half and retire the connection without waiting for EOF.
        stream.write_all(&[0, 0, 0, 1, 0xff]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), connection.closed())
            .await
            .expect("malformed gossip frame left an idle writer alive");
    } else {
        stream.finish().unwrap();
        // Clean receive EOF is not a topic Disconnect: a replacement may
        // legitimately leave the opposite send direction on this connection.
        let collection = CollectionHandle::new([81; 32]);
        let plane = receiver.transport.wake_plane();
        let topic = plane
            .subscribe(collection, vec![sender.id()])
            .await
            .unwrap();
        let (_incoming, frame) = tokio::time::timeout(Duration::from_secs(3), async {
            let mut incoming = connection.accept_uni().await.unwrap();
            let length = incoming.read_u32().await.unwrap() as usize;
            assert!(
                (35..=544).contains(&length),
                "bounded topic-tagged Join frame"
            );
            let mut bytes = vec![0; length];
            incoming.read_exact(&mut bytes).await.unwrap();
            // Keep the receive leg alive through the open-connection check;
            // dropping it here would send STOP_SENDING to the healthy writer.
            (incoming, bytes)
        })
        .await
        .expect("clean receive FIN prevented the opposite gossip Join");
        assert_eq!(
            &frame[..32],
            triblespace_net::wake::CollectionWakePlane::topic_id(collection).as_bytes()
        );
        // Stock postcard discriminants: Message::Swarm, hyparview::Join,
        // followed by an optional opaque PeerData byte vector. This checks the
        // emitted Join shape without adding a second protocol decoder/dependency.
        assert_eq!(&frame[32..34], &[0, 0]);
        match frame[34] {
            0 => assert_eq!(frame.len(), 35),
            1 => {
                let mut length = 0_u64;
                let mut end = None;
                for (index, &byte) in frame[35..].iter().enumerate() {
                    assert!(index < 10 && (index < 9 || byte <= 1));
                    length |= u64::from(byte & 0x7f) << (7 * index);
                    if byte & 0x80 == 0 {
                        end = Some(36 + index);
                        break;
                    }
                }
                assert_eq!(
                    end.expect("terminated PeerData length") as u64 + length,
                    frame.len() as u64
                );
            }
            other => panic!("invalid Join PeerData option: {other}"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), connection.closed())
                .await
                .is_err(),
            "clean receive FIN closed the working opposite gossip leg"
        );
        drop(topic);
    }

    connection.close(0u32.into(), b"lifecycle test finished");
    tokio::time::timeout(Duration::from_secs(5), receiver.transport.shutdown())
        .await
        .expect("receive EOF prevented transport shutdown");
    sender.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_receive_fin_preserves_the_opposite_gossip_send_leg() {
    receive_half_termination(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_frame_closes_connection_even_with_an_idle_send_leg() {
    receive_half_termination(true).await;
}

fn forward_connections(endpoint: Endpoint, gossip: Gossip) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let connection = incoming.await.unwrap();
            gossip.handle_connection(connection).await.unwrap();
        }
    })
}

async fn settle_topic(topic: &mut GossipTopic, expected: iroh_base::EndpointId) {
    loop {
        topic.joined().await.unwrap();
        match tokio::time::timeout(Duration::from_millis(100), topic.next()).await {
            Ok(Some(Ok(Event::NeighborUp(_) | Event::NeighborDown(_)))) => {}
            Ok(other) => panic!("unexpected event before fresh offers: {other:?}"),
            Err(_) => {
                assert_eq!(topic.neighbors().collect::<Vec<_>>(), [expected]);
                return;
            }
        }
    }
}

async fn receive_fresh(topic: &mut GossipTopic, expected: &[u8]) {
    match topic.next().await.unwrap().unwrap() {
        Event::Received(message) => assert_eq!(message.content.as_ref(), expected),
        other => panic!("settled cross-dial lost membership before fresh offer: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crossed_connection_replacements_recover_stable_bidirectional_topics() {
    let network = TestNetwork::new();
    let left_endpoint = endpoint(&network).await;
    let right_endpoint = endpoint(&network).await;
    left_endpoint.set_alpns(vec![iroh_gossip::ALPN.to_vec()]);
    right_endpoint.set_alpns(vec![iroh_gossip::ALPN.to_vec()]);
    let left = Gossip::builder().spawn(left_endpoint.clone());
    let right = Gossip::builder().spawn(right_endpoint.clone());

    // Let the real gossip dialers establish their outgoing connections. Hold
    // the accepting halves out of the actors until both send streams exist;
    // supplying outgoing connections through handle_connection would wrongly
    // classify those fixtures as Accept rather than exercising the Dial path.
    let mut topics = Vec::new();
    for number in 0_u8..3 {
        // Ephemeral topic fixture, not a new stable protocol identity.
        let topic = TopicId::from_bytes([number; 32]);
        // Topic 0 induces both dials. The other topics each have exactly one
        // bootstrap Join, so opposite redundant Joins cannot mask a control
        // frame discarded while upgrading to the preferred connection.
        let left_bootstrap = if number == 2 {
            vec![]
        } else {
            vec![right_endpoint.id()]
        };
        let right_bootstrap = if number == 1 {
            vec![]
        } else {
            vec![left_endpoint.id()]
        };
        let (a, b) = tokio::join!(
            left.subscribe(topic, left_bootstrap),
            right.subscribe(topic, right_bootstrap),
        );
        topics.push((a.unwrap(), b.unwrap()));
    }
    let (left_y, right_x) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            async { left_endpoint.accept().await.unwrap().await.unwrap() },
            async { right_endpoint.accept().await.unwrap().await.unwrap() },
        )
    })
    .await
    .expect("controlled cross-dial did not establish both connections");
    tokio::time::timeout(Duration::from_secs(5), async {
        while left_y.stats().frame_rx.stream == 0
            || right_x.stats().frame_rx.stream == 0
            || left.metrics().msgs_ctrl_sent.get() < 2
            || right.metrics().msgs_ctrl_sent.get() < 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both original send streams and all four bootstrap Joins must precede replacement");
    let original_x = right_x.clone();
    let original_y = left_y.clone();

    // A now adopts Y, while B adopts X. Their previous senders are dropped
    // and FIN their streams. The corresponding receive EOF must neither
    // strand the actor nor prevent ordinary mesh recovery.
    let (adopted_left, adopted_right) = tokio::join!(
        left.handle_connection(left_y),
        right.handle_connection(right_x)
    );
    adopted_left.unwrap();
    adopted_right.unwrap();
    let left_accept = forward_connections(left_endpoint.clone(), left.clone());
    let right_accept = forward_connections(right_endpoint.clone(), right.clone());

    let exchanged = tokio::time::timeout(Duration::from_secs(10), async {
        for (a, b) in &mut topics {
            tokio::join!(
                settle_topic(a, right_endpoint.id()),
                settle_topic(b, left_endpoint.id())
            );
        }
        // Distinct fresh payloads cannot be satisfied by a buffered initial
        // Join or an old data message. Check both directions on every topic,
        // then repeat after the replacement cleanup has had time to run.
        for phase in 0_u8..3 {
            for (number, (a, b)) in topics.iter_mut().enumerate() {
                let from_left = vec![phase, number as u8, 0];
                let from_right = vec![phase, number as u8, 1];
                let (sent_left, sent_right) = tokio::join!(
                    a.broadcast_neighbors(from_left.clone().into()),
                    b.broadcast_neighbors(from_right.clone().into()),
                );
                sent_left.unwrap();
                sent_right.unwrap();
                tokio::join!(receive_fresh(a, &from_right), receive_fresh(b, &from_left));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    eprintln!(
        "crossed old connection close reasons: X={:?}, Y={:?}",
        original_x.close_reason(),
        original_y.close_reason()
    );
    let kept_a_connection =
        original_x.close_reason().is_none() || original_y.close_reason().is_none();
    drop(topics);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (a, b) = tokio::join!(left.shutdown(), right.shutdown());
        a.unwrap();
        b.unwrap();
    })
    .await
    .expect("crossed gossip replacement prevented shutdown");
    left_accept.abort();
    right_accept.abort();
    let _ = tokio::join!(left_accept, right_accept);
    tokio::join!(left_endpoint.close(), right_endpoint.close());
    assert!(
        kept_a_connection,
        "opposite replacement FINs closed both healthy connections; recovery must not depend on a third dial"
    );
    assert!(
        exchanged.is_ok(),
        "crossed connections did not recover stable bidirectional topic traffic"
    );
}
