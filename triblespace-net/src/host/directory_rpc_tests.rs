//! The directory RPCs through the production stream handler, over in-memory
//! pipes instead of a simulated network, so they run without `sim`.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};

use crate::protocol::{OP_FIND_VALUE, TAG_DHT, recv_find_value_response, send_hash};
use crate::provider::MAX_PROVIDERS_PER_REPLY;

use super::*;

/// One direction of an in-memory stream. The directory RPCs never abandon
/// their streams, so a reset or a stop here fails the test.
struct Pipe(DuplexStream);

impl AsyncRead for Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl SendStream for Pipe {
    fn reset(&mut self, code: u32) {
        panic!("a directory RPC reset its stream with code {code}");
    }
}

impl RecvStream for Pipe {
    fn stop(&mut self, code: u32) {
        panic!("a directory RPC stopped its stream with code {code}");
    }
}

/// Every opened stream has its tag read, as the connection table's accept
/// loop reads it, and is then one `Service::serve` call, finished as the
/// accept loop finishes it.
#[derive(Clone)]
struct PipeConn {
    handler: SnapshotHandler,
    requester: VerifyingKey,
}

impl Conn for PipeConn {
    type SendHalf = Pipe;
    type RecvHalf = Pipe;

    fn remote_id(&self) -> PeerId {
        self.handler.local_id
    }

    async fn open_bi(&self) -> anyhow::Result<(Pipe, Pipe)> {
        let (request, serve_recv) = duplex(1 << 16);
        let (serve_send, reply) = duplex(1 << 16);
        let (handler, requester) = (self.handler.clone(), self.requester);
        tokio::spawn(async move {
            let (mut serve_send, mut serve_recv) = (Pipe(serve_send), Pipe(serve_recv));
            let tag = recv_u8(&mut serve_recv).await.unwrap();
            handler
                .serve(requester.to_bytes(), tag, &mut serve_send, &mut serve_recv)
                .await
                .unwrap();
            serve_send.shutdown().await.unwrap();
        });
        Ok((Pipe(request), Pipe(reply)))
    }

    async fn accept_bi(&self) -> Option<(Pipe, Pipe)> {
        None
    }

    fn close(&self, _code: u32, _reason: &[u8]) {}
}

struct CountedBlobReader {
    inner: Arc<dyn BlobSnapshotReader>,
    reads: Arc<AtomicUsize>,
}

impl BlobSnapshotReader for CountedBlobReader {
    fn get_blob(&self, hash: RawHash) -> Option<Bytes> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get_blob(hash)
    }
}

async fn find_value(
    connection: &PipeConn,
    key: ProviderKey,
) -> (Vec<PeerId>, Vec<(PeerId, ProviderToken)>) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send_u8(&mut send, TAG_DHT).await.unwrap();
    send_u8(&mut send, OP_FIND_VALUE).await.unwrap();
    send_hash(&mut send, &key).await.unwrap();
    send.shutdown().await.unwrap();
    recv_find_value_response(&mut recv).await.unwrap()
}

#[tokio::test]
async fn find_value_answers_routes_and_provider_hints_in_one_reply() {
    let provider_key = SigningKey::from_bytes(&[91; 32]);
    let requester_key = SigningKey::from_bytes(&[92; 32]);
    let provider = provider_key.verifying_key().to_bytes();
    let requester = requester_key.verifying_key().to_bytes();

    let mut store = MemoryRepo::default();
    let hash = store
        .put::<UnknownBlob, _>(Bytes::from_source(b"resident directory blob".to_vec()))
        .unwrap()
        .raw;
    let mut snapshot = StoreSnapshot::from_store_changes(
        store.snapshot().unwrap(),
        &ActiveCollections::new(),
        provider_key.verifying_key(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let blob_reads = Arc::new(AtomicUsize::new(0));
    snapshot.blobs = Arc::new(CountedBlobReader {
        inner: snapshot.blobs,
        reads: blob_reads.clone(),
    });
    let (_publisher, snapshot) = tokio::sync::watch::channel(Some(Arc::new(snapshot)));
    let routes = Arc::new(Mutex::new(RoutingTable::new(provider)));
    let directory = Arc::new(Mutex::new(ProviderDirectory::new(provider)));
    let connection = PipeConn {
        handler: SnapshotHandler {
            snapshot,
            health: Health::new(EndpointId::from_bytes(&provider).unwrap()),
            candidates: routes.clone(),
            providers: directory.clone(),
            local_id: provider,
            recon: None,
            walks: None,
        },
        requester: requester_key.verifying_key(),
    };

    // A key equal to the requester's id puts the requester nearest of all,
    // among more verified routes than one reply carries.
    let unheld = requester;
    {
        let mut routes = routes.lock().unwrap();
        routes.promote_authenticated(requester);
        for byte in 1..=3 * K as u8 {
            routes.promote_authenticated(
                SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .to_bytes(),
            );
        }
        assert!(routes.closest_verified(unheld, K + 1).len() > K);
    }
    let mut nearest = routes.lock().unwrap().closest_verified(unheld, K);
    nearest.retain(|route| *route != requester);
    let resident = blob_locator(hash);
    let foreign = (100..200_u8)
        .map(|byte| {
            (
                SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .to_bytes(),
                [byte; 32],
            )
        })
        .collect::<BTreeMap<_, _>>();
    {
        let mut directory = directory.lock().unwrap();
        let now = crate::clock::mono_now();
        for (peer, token) in &foreign {
            assert!(directory.put(resident, *peer, *token, now));
        }
        for (peer, token) in foreign.iter().take(10) {
            assert!(directory.put(unheld, *peer, *token, now));
        }
    }

    let (routes, hints) = find_value(&connection, unheld).await;
    assert_eq!(routes.len(), K - 1, "the K closest, less the requester");
    assert_eq!(routes, nearest);
    assert_eq!(
        hints,
        foreign
            .iter()
            .take(10)
            .map(|(peer, token)| (*peer, *token))
            .collect::<Vec<_>>()
    );

    // Above the reply limit a reply samples the stored leases behind this
    // node's own resident hint, and repeated requests reach every lease, the
    // highest peer id included. A lease is missed by one reply with
    // probability 37/100, so by 64 replies with probability below 1e-27.
    let own = (provider, blob_provider_token(hash, provider));
    let mut seen = BTreeMap::new();
    for _ in 0..64 {
        let hints = find_value(&connection, resident).await.1;
        assert_eq!(hints.len(), MAX_PROVIDERS_PER_REPLY);
        assert_eq!(hints[0], own);
        assert!(hints[1..].windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(
            hints[1..]
                .iter()
                .all(|(peer, token)| foreign.get(peer) == Some(token))
        );
        seen.extend(hints[1..].iter().copied());
    }
    assert_eq!(seen, foreign);
    assert_eq!(blob_reads.load(Ordering::Relaxed), 0);
}
