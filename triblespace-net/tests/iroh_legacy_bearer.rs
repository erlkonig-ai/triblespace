//! Installed ALPN26 bearer clients remain compatible with the new repair opcode.
//! Client bytes deliberately do not use this crate's current protocol constants.

use std::time::Duration;

use anybytes::Bytes;
use iroh::Endpoint;
use iroh::endpoint::{Connection, presets};
use iroh::test_utils::test_transport::TestNetwork;
use iroh_base::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::repo::BlobStorePut;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::ReconcileQos;
use triblespace_net::peer::Peer;

async fn endpoint(network: &TestNetwork, byte: u8) -> Endpoint {
    let secret = SecretKey::from_bytes(&[byte; 32]);
    let transport = network.create_transport(secret.public()).unwrap();
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .relay_mode(iroh::RelayMode::Disabled)
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .add_custom_transport(transport)
        .clear_ip_transports()
        .clear_address_lookup()
        .address_lookup(network.address_lookup())
        .bind()
        .await
        .unwrap()
}

fn legacy_proof(
    handle: [u8; 32],
    domain: &[u8],
    requester: [u8; 32],
    provider: [u8; 32],
) -> [u8; 32] {
    let locator = blake3::derive_key("triblespace.net/blob-locator/v1", &handle);
    let mut hasher = blake3::Hasher::new_keyed(&handle);
    hasher.update(domain);
    hasher.update(&requester);
    hasher.update(&provider);
    hasher.update(&locator);
    *hasher.finalize().as_bytes()
}

async fn legacy_get(conn: &Connection, requester: [u8; 32], handle: [u8; 32]) -> Vec<u8> {
    let provider = *conn.remote_id().as_bytes();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let mut request = vec![0x02];
    request.extend_from_slice(&blake3::derive_key(
        "triblespace.net/blob-locator/v1",
        &handle,
    ));
    send.write_all(&request).await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0x01);
    let mut proof = [0; 32];
    recv.read_exact(&mut proof).await.unwrap();
    assert_eq!(
        proof,
        legacy_proof(
            handle,
            b"triblespace.net/blob-provider-proof/v1\0",
            requester,
            provider
        )
    );
    send.write_all(&legacy_proof(
        handle,
        b"triblespace.net/blob-requester-proof/v1\0",
        requester,
        provider,
    ))
    .await
    .unwrap();
    send.shutdown().await.unwrap();
    let length = recv.read_u64().await.unwrap();
    assert!(
        length < 1024,
        "fixture GET must not allocate from an unchecked length"
    );
    let mut bytes = vec![0; length as usize];
    recv.read_exact(&mut bytes).await.unwrap();
    let mut trailing = [0];
    assert_eq!(
        AsyncReadExt::read(&mut recv, &mut trailing).await.unwrap(),
        0
    );
    assert_eq!(*blake3::hash(&bytes).as_bytes(), handle);
    bytes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn literal_alpn26_get_survives_old_repair_rejection_on_the_same_connection() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let network = TestNetwork::new();
        let server_endpoint = endpoint(&network, 0xD1).await;
        let client_endpoint = endpoint(&network, 0xD2).await;
        let mut store = MemoryRepo::default();
        let payload = b"installed Leech bearer bytes survive the repair cutover";
        let handle = store
            .put::<UnknownBlob, _>(Bytes::from_source(payload.to_vec()))
            .unwrap();
        let config = PeerConfig {
            peers: Vec::new(),
            qos: ReconcileQos::default(),
            provider_publication_budget: Some(0),
        };
        let harness =
            triblespace_net::transport::iroh::bind_with_endpoint(server_endpoint.clone(), &config)
                .await;
        let (sender, receiver, wiring) = host::wire(server_endpoint.id());
        let owner = tokio::spawn(host::run_host(harness, config, wiring));
        let mut server = Peer::with_wiring(store, ReconcileQos::default(), sender, receiver);
        server.refresh();
        let conn = client_endpoint
            .connect(server_endpoint.addr(), b"/triblespace/pile-sync/26")
            .await
            .expect("the new host must accept the installed client's literal ALPN");
        let requester = *client_endpoint.id().as_bytes();
        assert_eq!(legacy_get(&conn, requester, handle.raw).await, payload);

        // Complete old hello for an absent C: an old 0x0D decoder would emit
        // an Unavailable byte, not EOF. Reject before interpreting its body.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut old_hello = vec![0x0D];
        old_hello.extend_from_slice(&[0xC1; 32]);
        old_hello.extend_from_slice(&0_u32.to_be_bytes());
        send.write_all(&old_hello).await.unwrap();
        send.shutdown().await.unwrap();
        let mut response = [0];
        assert_eq!(
            AsyncReadExt::read(&mut recv, &mut response).await.unwrap(),
            0
        );
        assert!(conn.close_reason().is_none());
        assert_eq!(legacy_get(&conn, requester, handle.raw).await, payload);

        // The fresh opcode is recognized on that same common connection.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut new_hello = old_hello;
        new_hello[0] = 0x0E;
        send.write_all(&new_hello).await.unwrap();
        send.shutdown().await.unwrap();
        assert_eq!(
            recv.read_u8().await.unwrap(),
            0x02,
            "absent C is Unavailable"
        );
        assert_eq!(
            AsyncReadExt::read(&mut recv, &mut response).await.unwrap(),
            0
        );
        assert_eq!(legacy_get(&conn, requester, handle.raw).await, payload);

        drop(server);
        owner.abort();
        let _ = owner.await;
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await
    .expect("literal old-client compatibility exchange must finish");
}
