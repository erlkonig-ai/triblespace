//! Expected per-collection refusals must not evict a shared transport.

use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy, CollectionRecord,
    CollectionStore, CollectionStoreExt, empty_metadata_handle,
};

use crate::collection_session::CollectionRepairRefusal;
use crate::collection_wire::recv_repair_collection;
use crate::protocol::{TAG_DHT, TAG_REPAIR, recv_find_value_response};

use super::*;

struct RepairFixture {
    net: SimNet,
    client: ProviderClient<SimTransport>,
    provider: PeerId,
    snapshot: StoreSnapshot,
    allowed: CollectionHandle,
    rejected: CollectionHandle,
    unavailable: CollectionHandle,
    record: CollectionRecord,
    events: tokio::sync::mpsc::Sender<NetEventBatch>,
    received: tokio::sync::mpsc::Receiver<NetEventBatch>,
    health: Health,
    server_connections: ConnectionTable<SimTransport, SnapshotHandler>,
    server: tokio::task::JoinHandle<()>,
}

impl RepairFixture {
    fn new(malformed_reply: bool) -> Self {
        let net = SimNet::new(
            0xC011_EC77,
            SimConfig {
                latency: Duration::ZERO..Duration::ZERO,
            },
        );
        let provider_key = SigningKey::from_bytes(&[113; 32]);
        let client_key = SigningKey::from_bytes(&[114; 32]);
        let provider = provider_key.verifying_key().to_bytes();
        let client_id = client_key.verifying_key().to_bytes();
        let mut provider_harness = net.join(&provider_key);
        let client = ProviderClient::for_test(
            net.join(&client_key).transport,
            RoutingTable::new(client_id, [provider]),
        );
        let mut remote = MemoryRepo::default();
        let mut local = MemoryRepo::default();
        let open = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let private = CollectionPolicy::new(
            AdmissionPolicy::direct(provider_key.verifying_key()),
            AdmissionPolicy::direct(provider_key.verifying_key()),
        );
        let allowed = remote
            .collection("repair-refusal-allowed", open.clone())
            .unwrap()
            .handle();
        let rejected = remote
            .collection("repair-refusal-private", private.clone())
            .unwrap()
            .handle();
        assert_eq!(
            local
                .collection("repair-refusal-allowed", open.clone())
                .unwrap()
                .handle(),
            allowed
        );
        assert_eq!(
            local
                .collection("repair-refusal-private", private)
                .unwrap()
                .handle(),
            rejected
        );
        let unavailable = local
            .collection("repair-refusal-absent", open)
            .unwrap()
            .handle();
        let data = remote
            .put::<UnknownBlob, _>(Bytes::from_source(
                b"legitimate repair after refusal".to_vec(),
            ))
            .unwrap();
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &provider_key,
            allowed,
            CollectionData::new(data.raw),
            empty_metadata_handle(),
        ));
        remote.insert(record).unwrap();
        let mut remote_active = ActiveCollections::new();
        for collection in [allowed, rejected] {
            remote_active.insert(&PatchEntry::new(&collection.raw));
        }
        let mut local_active = remote_active.clone();
        local_active.insert(&PatchEntry::new(&unavailable.raw));
        let remote_snapshot = StoreSnapshot::from_store_changes(
            remote.snapshot().unwrap(),
            &remote_active,
            provider_key.verifying_key(),
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap();
        let snapshot = StoreSnapshot::from_store_changes(
            local.snapshot().unwrap(),
            &local_active,
            client_key.verifying_key(),
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap();
        let handler = SnapshotHandler {
            snapshot: tokio::sync::watch::channel(Some(Arc::new(remote_snapshot))).1,
            health: Health::new(EndpointId::from_bytes(&provider).unwrap()),
            candidates: Arc::new(Mutex::new(RoutingTable::new(provider, []))),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(provider))),
            serve_collections: true,
            local_id: provider,
            recon: None,
        };
        let server_connections = ConnectionTable::new(provider_harness.transport.clone(), handler);
        let connections = server_connections.clone();
        let server = tokio::spawn(async move {
            while let Some(incoming) = provider_harness.incoming.recv().await {
                if !malformed_reply {
                    connections.accept(incoming.conn);
                    continue;
                }
                tokio::spawn(async move {
                    // Negative control: this is not an expected admission
                    // refusal; the peer emits an invalid wire discriminant.
                    let _recon = incoming.conn.accept_bi().await.unwrap();
                    let (mut send, mut recv) = incoming.conn.accept_bi().await.unwrap();
                    assert_eq!(recv_u8(&mut recv).await.unwrap(), TAG_REPAIR);
                    recv_repair_collection(&mut recv).await.unwrap();
                    send_u8(&mut send, 0xff).await.unwrap();
                    send.shutdown().await.unwrap();
                });
            }
        });
        let (events, received) = tokio::sync::mpsc::channel(16);
        Self {
            net,
            client,
            provider,
            snapshot,
            allowed,
            rejected,
            unavailable,
            record,
            events,
            received,
            health: Health::new(EndpointId::from_bytes(&client_id).unwrap()),
            server_connections,
            server,
        }
    }

    async fn repair(&self, collection: CollectionHandle) -> anyhow::Result<bool> {
        reconcile_collection_peer(
            &self.client.connections,
            RepairTarget {
                collection,
                peer: self.provider,
            },
            self.snapshot.collection(collection).unwrap(),
            &self.events,
            &self.health,
            None,
        )
        .await
        .map(|(retry, _)| retry)
    }
}

impl Drop for RepairFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn refusal_preserves_other_streams(expected: CollectionRepairRefusal) {
    let mut fixture = RepairFixture::new(false);
    let connection = fixture
        .client
        .connections
        .connect(fixture.provider)
        .await
        .unwrap();
    let (mut held_send, mut held_recv) = connection.open_bi().await.unwrap();
    send_u8(&mut held_send, TAG_DHT).await.unwrap();
    send_u8(&mut held_send, OP_FIND_VALUE).await.unwrap();
    send_hash(&mut held_send, &[0; 32]).await.unwrap();
    // Withhold EOF: a real served stream and its permit remain live across
    // the collection refusal, not merely an unused client handle.
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.server_connections.available_requests()
            == crate::connection::MAX_REQUESTS_GLOBAL
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("unrelated FIND_VALUE did not reach the server");
    let collection = match expected {
        CollectionRepairRefusal::Rejected => fixture.rejected,
        CollectionRepairRefusal::Unavailable => fixture.unavailable,
    };
    let error = fixture
        .repair(collection)
        .await
        .expect_err("collection should refuse repair");
    assert_eq!(
        error.downcast_ref::<CollectionRepairRefusal>(),
        Some(&expected)
    );
    assert!(
        fixture.received.try_recv().is_err(),
        "refusal must not admit data"
    );
    assert!(
        fixture.client.connections.current(fixture.provider) == Some(connection.clone()),
        "an expected per-collection refusal evicted the shared connection"
    );

    held_send
        .shutdown()
        .await
        .expect("refusal closed an unrelated request");
    assert_eq!(
        recv_find_value_response(&mut held_recv).await.unwrap(),
        (vec![], vec![])
    );
    assert!(
        !fixture
            .repair(fixture.allowed)
            .await
            .expect("legitimate repair after refusal")
    );
    let received = fixture
        .received
        .recv()
        .await
        .unwrap()
        .into_events()
        .collect::<Vec<_>>();
    assert!(received.iter().any(
        |event| matches!(event, NetEvent::CollectionRecord(record) if *record == fixture.record)
    ));
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        1,
        "redial must not mask destruction of the original shared connection"
    );
    assert!(fixture.client.connections.current(fixture.provider) == Some(connection.clone()));
    connection.close(0, b"test complete");
}

#[tokio::test(start_paused = true)]
async fn unavailable_collection_preserves_shared_connection_and_other_streams() {
    refusal_preserves_other_streams(CollectionRepairRefusal::Unavailable).await;
}

#[tokio::test(start_paused = true)]
async fn rejected_collection_preserves_shared_connection_and_other_streams() {
    refusal_preserves_other_streams(CollectionRepairRefusal::Rejected).await;
}

#[tokio::test(start_paused = true)]
async fn malformed_repair_reply_still_invalidates_shared_connection() {
    let fixture = RepairFixture::new(true);
    let connection = fixture
        .client
        .connections
        .connect(fixture.provider)
        .await
        .unwrap();
    let error = fixture
        .repair(fixture.allowed)
        .await
        .expect_err("invalid admission tag must fail");
    assert!(error.downcast_ref::<CollectionRepairRefusal>().is_none());
    assert!(
        fixture
            .client
            .connections
            .current(fixture.provider)
            .is_none()
    );
    assert!(
        connection.open_bi().await.is_err(),
        "malformed peer must not keep its shared connection"
    );
}
