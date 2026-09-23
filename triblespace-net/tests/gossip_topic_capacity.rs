//! Production-sized collection topics must not exhaust the shared QUIC path.

use std::time::Duration;

use iroh::{Endpoint, endpoint::presets, test_utils::test_transport::TestNetwork};
use iroh_base::SecretKey;
use triblespace_core::collection::CollectionHandle;
use triblespace_net::{host::PeerConfig, transport::Transport};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_than_one_hundred_collection_topics_remain_connected() {
    topic_capacity(130, None, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collection_topics_share_one_ordered_stream_without_a_fixed_topic_cliff() {
    topic_capacity(257, Some(1), false).await;
}

async fn endpoint(network: &TestNetwork, streams: Option<u32>) -> Endpoint {
    let key = SecretKey::generate();
    let transport = network.create_transport(key.public()).unwrap();
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(key)
        .relay_mode(iroh::RelayMode::Disabled)
        .add_custom_transport(transport)
        .clear_ip_transports()
        .clear_address_lookup()
        .address_lookup(network.address_lookup());
    if let Some(streams) = streams {
        builder = builder.transport_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .max_concurrent_uni_streams(streams.into())
                .build(),
        );
    }
    builder.bind().await.unwrap()
}

fn config() -> PeerConfig {
    PeerConfig {
        peers: vec![],
        qos: Default::default(),
        provider_publication_budget: Some(0),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_with_no_stream_credit_cannot_block_other_collection_neighbors() {
    let network = TestNetwork::new();
    let blocked = triblespace_net::transport::iroh::bind_with_endpoint(
        endpoint(&network, Some(0)).await,
        &config(),
    )
    .await;
    let source = triblespace_net::transport::iroh::bind_with_endpoint(
        endpoint(&network, None).await,
        &config(),
    )
    .await;
    let healthy = triblespace_net::transport::iroh::bind_with_endpoint(
        endpoint(&network, None).await,
        &config(),
    )
    .await;
    let source_plane = source.transport.wake_plane();
    let healthy_plane = healthy.transport.wake_plane();
    let blocked_id = blocked.transport.wake_plane().origin();
    let mut topics = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        for number in 0_u64..257 {
            let mut raw = [0; 32];
            raw[..8].copy_from_slice(&number.to_le_bytes());
            topics.push(
                source_plane
                    .subscribe(CollectionHandle::new(raw), vec![blocked_id])
                    .await
                    .unwrap(),
            );
            if number == 0 {
                // Let the virtual QUIC handshake finish before filling the
                // active writer queue, rather than only its pending-dial list.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        let mut good_topic = healthy_plane
            .subscribe(topics[0].collection(), vec![source_plane.origin()])
            .await
            .unwrap();
        good_topic.joined().await.unwrap();
        let wake = topics[0].broadcast([7; 32].into()).await.unwrap();
        loop {
            if let Some(triblespace_net::wake::CollectionWakeEvent::Received(received)) =
                good_topic.next_event().await.unwrap()
            {
                assert_eq!(received.wake, wake);
                break;
            }
        }
    })
    .await
    .expect("one peer's exhausted stream credit stalled healthy gossip");
    drop(topics);
    tokio::time::timeout(Duration::from_secs(10), async {
        source.transport.shutdown().await;
        healthy.transport.shutdown().await;
        blocked.transport.shutdown().await;
    })
    .await
    .expect("blocked peer prevented shutdown");
}

async fn topic_capacity(count: u64, streams: Option<u32>, join_each: bool) {
    let network = TestNetwork::new();
    let config = PeerConfig {
        peers: vec![],
        qos: Default::default(),
        provider_publication_budget: Some(0),
    };
    let left = triblespace_net::transport::iroh::bind_with_endpoint(
        endpoint(&network, streams).await,
        &config,
    )
    .await;
    let right = triblespace_net::transport::iroh::bind_with_endpoint(
        endpoint(&network, streams).await,
        &config,
    )
    .await;
    let left_plane = left.transport.wake_plane();
    let right_plane = right.transport.wake_plane();
    let mut topics = Vec::new();
    let mut joined = 0;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        for number in 0_u64..count {
            // Ephemeral test handles, not stable schema or protocol identities.
            let mut raw = [0; 32];
            raw[..8].copy_from_slice(&number.to_le_bytes());
            let collection = CollectionHandle::new(raw);
            let first = left_plane.subscribe(collection, vec![]).await.unwrap();
            let mut second = right_plane
                .subscribe(collection, vec![left_plane.origin()])
                .await
                .unwrap();
            if join_each {
                second.joined().await.unwrap();
                joined += 1;
            }
            topics.push((first, second));
        }
        if !join_each {
            // Match cold startup: subscribe the whole collection set before
            // waiting for membership; a healthy burst is not a slow peer.
            for (_, second) in &mut topics {
                second.joined().await.unwrap();
                joined += 1;
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "only {joined}/{count} collection topics joined"
    );
    // Exercise every topic after all subscriptions exist. The tagged shared
    // stream must neither starve early topics nor deliver to the wrong topic.
    tokio::time::timeout(Duration::from_secs(10), async {
        for (number, (first, second)) in topics.iter_mut().enumerate() {
            let mut root = [0; 32];
            root[..8].copy_from_slice(&(number as u64).to_le_bytes());
            let offered = first.broadcast(root.into()).await.unwrap();
            loop {
                if let Some(triblespace_net::wake::CollectionWakeEvent::Received(received)) =
                    second.next_event().await.unwrap()
                {
                    assert_eq!(received.wake, offered);
                    break;
                }
            }
        }
    })
    .await
    .expect("subscribed topics stopped exchanging roots");
    drop(topics);
    left.transport.shutdown().await;
    right.transport.shutdown().await;
}
