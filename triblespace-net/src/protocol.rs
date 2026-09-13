//! Binary wire protocol primitives.
//!
//! One QUIC stream carries one operation. Establishing the TLS connection
//! grants no collection authority: `COLLECTION_REPAIR` carries READ(C)
//! evidence in its own request. Exact blob reads use only bearer-handle key
//! confirmation. Collection identity and collection authority do not
//! participate in exact discovery or transfer.

use anybytes::{ByteArea, Bytes};
use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bearer::{blob_locator, proof_matches, provider_proof, requester_proof};
use crate::transport::Conn;
use crate::transport::PeerId;

/// Clean collection-scoped protocol generation.
pub const PILE_SYNC_ALPN: &[u8] = b"/triblespace/pile-sync/25";

// Operation types — first byte on each stream.
// 0x01 was branch-list; 0x03 was blob-children; 0x04 was branch-head;
// 0x05 was connection AUTH. None are accepted in v25.
pub const OP_GET_BLOB: u8 = 0x02;
pub const OP_PROVIDER_PUT: u8 = 0x06;
pub const OP_PROVIDER_GET: u8 = 0x07;
pub const OP_FIND_NODE: u8 = 0x0C;
// 0x0D is OP_COLLECTION_REPAIR, owned by collection_wire.

pub const PROVIDER_PUT_OK: u8 = 0x00;
pub const PROVIDER_PUT_FULL: u8 = 0x01;

const BLOB_UNAVAILABLE: u8 = 0x00;
const BLOB_PROVIDER_PROOF: u8 = 0x01;

pub type RawHash = [u8; 32];
/// File-backed exact-transfer ceiling. Receives are serialized and land in a
/// temporary mmap rather than allocating one in-memory `Vec` per route.
pub(crate) const MAX_EXACT_BLOB_BYTES: u64 = 64 * 1024 * 1024 * 1024;
static EXACT_BLOB_RECEIVES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

pub async fn send_u8<W: AsyncWrite + Unpin>(send: &mut W, value: u8) -> Result<()> {
    send.write_all(&[value])
        .await
        .map_err(|error| anyhow!("send: {error}"))
}

pub async fn send_hash<W: AsyncWrite + Unpin>(send: &mut W, hash: &RawHash) -> Result<()> {
    send.write_all(hash)
        .await
        .map_err(|error| anyhow!("send: {error}"))
}

pub async fn send_u32_be<W: AsyncWrite + Unpin>(send: &mut W, value: u32) -> Result<()> {
    send.write_all(&value.to_be_bytes())
        .await
        .map_err(|error| anyhow!("send: {error}"))
}

pub async fn send_u64_be<W: AsyncWrite + Unpin>(send: &mut W, value: u64) -> Result<()> {
    send.write_all(&value.to_be_bytes())
        .await
        .map_err(|error| anyhow!("send: {error}"))
}

pub async fn recv_u8<R: AsyncRead + Unpin>(recv: &mut R) -> Result<u8> {
    let mut bytes = [0; 1];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|error| anyhow!("recv: {error}"))?;
    Ok(bytes[0])
}

pub async fn recv_hash<R: AsyncRead + Unpin>(recv: &mut R) -> Result<RawHash> {
    let mut bytes = [0; 32];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|error| anyhow!("recv: {error}"))?;
    Ok(bytes)
}

pub async fn recv_u32_be<R: AsyncRead + Unpin>(recv: &mut R) -> Result<u32> {
    let mut bytes = [0; 4];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|error| anyhow!("recv: {error}"))?;
    Ok(u32::from_be_bytes(bytes))
}

pub async fn recv_u64_be<R: AsyncRead + Unpin>(recv: &mut R) -> Result<u64> {
    let mut bytes = [0; 8];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|error| anyhow!("recv: {error}"))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Bearer exact GET without revealing the content handle.
///
/// The directory or caller has already selected a candidate. This stream
/// discloses only `KDF(H)`. The candidate proves knowledge of `H` before the
/// requester sends its own endpoint-bound proof.
pub async fn op_get_blob<C: Conn>(
    conn: &C,
    requester: PeerId,
    hash: &RawHash,
) -> Result<Option<Bytes>> {
    let provider = conn.remote_id();
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| anyhow!("open_bi: {error}"))?;
    send_u8(&mut send, OP_GET_BLOB).await?;
    fetch_get_blob_stream(&mut send, &mut recv, requester, provider, hash).await
}

async fn fetch_get_blob_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    requester: PeerId,
    provider: PeerId,
    hash: &RawHash,
) -> Result<Option<Bytes>>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    send_hash(send, &blob_locator(*hash)).await?;
    let proof = match recv_u8(recv).await? {
        BLOB_UNAVAILABLE => {
            send.shutdown()
                .await
                .map_err(|error| anyhow!("finish: {error}"))?;
            require_response_eof(recv).await?;
            return Ok(None);
        }
        BLOB_PROVIDER_PROOF => recv_hash(recv).await?,
        other => return Err(anyhow!("unknown exact-blob response: {other:#x}")),
    };
    let expected = provider_proof(*hash, requester, provider);
    if !proof_matches(&proof, &expected) {
        return Err(anyhow!("candidate failed bearer provider proof"));
    }
    send_hash(send, &requester_proof(*hash, requester, provider)).await?;
    send.shutdown()
        .await
        .map_err(|error| anyhow!("finish: {error}"))?;
    let bytes = recv_blob_response(recv).await?;
    if let Some(bytes) = bytes.as_ref()
        && blake3::hash(bytes).as_bytes() != hash
    {
        return Err(anyhow!("exact blob bytes do not match bearer handle"));
    }
    Ok(bytes)
}

/// Serve one provider-first bearer key-confirmation exchange.
pub(crate) async fn serve_get_blob<R, W>(
    recv: &mut R,
    send: &mut W,
    requester: PeerId,
    provider: PeerId,
    resolve: impl FnOnce(RawHash) -> Option<RawHash>,
    get: impl FnOnce(RawHash) -> Option<Bytes>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let locator = recv_hash(recv).await?;
    let Some(handle) = resolve(locator) else {
        send_u8(send, BLOB_UNAVAILABLE).await?;
        send.shutdown()
            .await
            .map_err(|error| anyhow!("finish: {error}"))?;
        return Ok(());
    };
    send_u8(send, BLOB_PROVIDER_PROOF).await?;
    send_hash(send, &provider_proof(handle, requester, provider)).await?;
    let supplied = recv_hash(recv).await?;
    require_response_eof(recv).await?;
    let expected = requester_proof(handle, requester, provider);
    if !proof_matches(&supplied, &expected) {
        return Err(anyhow!("requester failed bearer proof"));
    }
    let bytes = get(handle);
    send_blob_response(send, bytes.as_deref()).await?;
    send.shutdown()
        .await
        .map_err(|error| anyhow!("finish: {error}"))?;
    Ok(())
}

async fn send_blob_response<W: AsyncWrite + Unpin>(
    send: &mut W,
    bytes: Option<&[u8]>,
) -> Result<()> {
    match bytes {
        Some(bytes) => {
            send_u64_be(
                send,
                u64::try_from(bytes.len()).expect("an addressable blob length fits u64"),
            )
            .await?;
            send.write_all(bytes)
                .await
                .map_err(|error| anyhow!("send exact blob: {error}"))?;
        }
        None => send_u64_be(send, u64::MAX).await?,
    }
    Ok(())
}

/// Install or renew one opaque provider key for the TLS-authenticated caller.
pub(crate) async fn op_provider_put<C: Conn>(
    conn: &C,
    key: &RawHash,
    token: &RawHash,
) -> Result<bool> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| anyhow!("open_bi: {error}"))?;
    send_u8(&mut send, OP_PROVIDER_PUT).await?;
    send_hash(&mut send, key).await?;
    send_hash(&mut send, token).await?;
    send.shutdown()
        .await
        .map_err(|error| anyhow!("finish: {error}"))?;
    let stored = match recv_u8(&mut recv).await? {
        PROVIDER_PUT_OK => true,
        PROVIDER_PUT_FULL => false,
        other => return Err(anyhow!("unknown provider-put response: {other:#x}")),
    };
    require_response_eof(&mut recv).await?;
    Ok(stored)
}

/// Return bounded provider hints for one derived rendezvous key.
pub async fn op_provider_get<C: Conn>(conn: &C, key: &RawHash) -> Result<Vec<(RawHash, RawHash)>> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| anyhow!("open_bi: {error}"))?;
    send_u8(&mut send, OP_PROVIDER_GET).await?;
    send_hash(&mut send, key).await?;
    send.shutdown()
        .await
        .map_err(|error| anyhow!("finish: {error}"))?;
    let count = recv_u8(&mut recv).await? as usize;
    if count > crate::provider::MAX_PROVIDERS_PER_KEY {
        return Err(anyhow!(
            "provider-get response has {count} entries; limit is {}",
            crate::provider::MAX_PROVIDERS_PER_KEY
        ));
    }
    let mut providers = Vec::with_capacity(count);
    for _ in 0..count {
        providers.push((recv_hash(&mut recv).await?, recv_hash(&mut recv).await?));
    }
    require_response_eof(&mut recv).await?;
    Ok(providers)
}

/// Return at most K verified routes nearest an arbitrary XOR target.
pub async fn op_find_node<C: Conn>(
    conn: &C,
    target: &crate::routing::RoutingKey,
) -> Result<Vec<crate::transport::PeerId>> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| anyhow!("open_bi: {error}"))?;
    send_u8(&mut send, OP_FIND_NODE).await?;
    send_hash(&mut send, target).await?;
    send.shutdown()
        .await
        .map_err(|error| anyhow!("finish: {error}"))?;
    recv_find_node_response(&mut recv).await
}

pub(crate) async fn recv_find_node_response<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Vec<crate::transport::PeerId>> {
    let count = recv_u8(recv).await? as usize;
    if count > crate::routing::K {
        return Err(anyhow!(
            "FIND_NODE response has {count} entries; limit is {}",
            crate::routing::K
        ));
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        peers.push(recv_hash(recv).await?);
    }
    require_response_eof(recv).await?;
    Ok(peers)
}

async fn require_response_eof<R: AsyncRead + Unpin>(recv: &mut R) -> Result<()> {
    let mut trailing = [0; 1];
    if recv.read(&mut trailing).await? != 0 {
        return Err(anyhow!("response contains trailing bytes"));
    }
    Ok(())
}

async fn recv_blob_response<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Option<Bytes>> {
    let len = recv_u64_be(recv).await?;
    if len == u64::MAX {
        return Ok(None);
    }
    if len > MAX_EXACT_BLOB_BYTES {
        return Err(anyhow!(
            "blob response exceeds the {MAX_EXACT_BLOB_BYTES}-byte transport bound"
        ));
    }
    let len = usize::try_from(len)
        .map_err(|_| anyhow!("blob response length does not fit this address space"))?;
    let data = recv_exact_blob_body(recv, len).await?;
    require_response_eof(recv).await?;
    Ok(Some(data))
}

pub(crate) async fn recv_exact_blob_body<R: AsyncRead + Unpin>(
    recv: &mut R,
    len: usize,
) -> Result<Bytes> {
    let _permit = EXACT_BLOB_RECEIVES.acquire().await?;
    let mut area = ByteArea::new().map_err(|error| anyhow!("create blob receive area: {error}"))?;
    let mut remaining = len;
    let mut chunk = vec![0_u8; remaining.min(1 << 20)];
    while remaining != 0 {
        let take = remaining.min(chunk.len());
        recv.read_exact(&mut chunk[..take])
            .await
            .map_err(|error| anyhow!("recv blob body: {error}"))?;
        {
            let mut writer = area.sections();
            let mut section = writer
                .reserve::<u8>(take)
                .map_err(|error| anyhow!("reserve file-backed blob response: {error}"))?;
            section.as_mut_slice().copy_from_slice(&chunk[..take]);
        }
        remaining -= take;
    }
    area.freeze()
        .map_err(|error| anyhow!("freeze blob receive area: {error}"))
}

/// Independent test runtimes must not time each other's shared receive permit.
/// A paused Tokio clock advances while a permit's owner on another test thread
/// is still running. Hold this before exercising any body receive in a unit test;
/// contention within that test's own runtime still uses the production semaphore.
#[cfg(test)]
pub(crate) fn exact_blob_receive_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, duplex, split};

    fn handle(bytes: &[u8]) -> RawHash {
        *blake3::hash(bytes).as_bytes()
    }

    #[tokio::test]
    async fn exact_get_mutual_proof_succeeds_without_a_collection() {
        let _guard = exact_blob_receive_test_guard();
        let requester = [7; 32];
        let provider = [8; 32];
        let content = b"bearer capability";
        let content_handle = handle(content);
        let (client, server) = duplex(4096);
        let (mut client_recv, mut client_send) = split(client);
        let (mut server_recv, mut server_send) = split(server);

        let serving = tokio::spawn(async move {
            serve_get_blob(
                &mut server_recv,
                &mut server_send,
                requester,
                provider,
                |locator| (locator == blob_locator(content_handle)).then_some(content_handle),
                |hash| (hash == content_handle).then(|| Bytes::from_source(content.to_vec())),
            )
            .await
        });
        let received = fetch_get_blob_stream(
            &mut client_send,
            &mut client_recv,
            requester,
            provider,
            &content_handle,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&*received, content);
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fake_locator_advertiser_learns_no_handle_or_requester_proof() {
        let requester = [11; 32];
        let provider = [12; 32];
        let content_handle = handle(b"secret bytes");
        let expected_locator = blob_locator(content_handle);
        let (client, server) = duplex(4096);
        let (mut client_recv, mut client_send) = split(client);
        let (mut server_recv, mut server_send) = split(server);

        let fake = tokio::spawn(async move {
            let observed = recv_hash(&mut server_recv).await.unwrap();
            send_u8(&mut server_send, BLOB_PROVIDER_PROOF)
                .await
                .unwrap();
            send_hash(&mut server_send, &[0; 32]).await.unwrap();
            server_send.shutdown().await.unwrap();
            let mut disclosed = Vec::new();
            server_recv.read_to_end(&mut disclosed).await.unwrap();
            (observed, disclosed)
        });
        let result = fetch_get_blob_stream(
            &mut client_send,
            &mut client_recv,
            requester,
            provider,
            &content_handle,
        )
        .await;
        drop(client_send);
        drop(client_recv);
        let (observed, disclosed) = fake.await.unwrap();

        assert!(result.is_err());
        assert_eq!(observed, expected_locator);
        assert_ne!(observed, content_handle);
        assert!(disclosed.is_empty());
    }

    #[tokio::test]
    async fn bad_requester_proof_reveals_no_blob_bytes() {
        let requester = [17; 32];
        let provider = [18; 32];
        let content_handle = handle(b"provider-held secret");
        let (client, server) = duplex(4096);
        let (mut client_recv, mut client_send) = split(client);
        let (mut server_recv, mut server_send) = split(server);

        let serving = tokio::spawn(async move {
            serve_get_blob(
                &mut server_recv,
                &mut server_send,
                requester,
                provider,
                |locator| (locator == blob_locator(content_handle)).then_some(content_handle),
                |_| panic!("blob storage must not be read before requester key confirmation"),
            )
            .await
        });

        send_hash(&mut client_send, &blob_locator(content_handle))
            .await
            .unwrap();
        assert_eq!(
            recv_u8(&mut client_recv).await.unwrap(),
            BLOB_PROVIDER_PROOF
        );
        assert!(proof_matches(
            &recv_hash(&mut client_recv).await.unwrap(),
            &provider_proof(content_handle, requester, provider)
        ));
        send_hash(&mut client_send, &[0; 32]).await.unwrap();
        client_send.shutdown().await.unwrap();

        assert!(serving.await.unwrap().is_err());
        let mut disclosed = Vec::new();
        client_recv.read_to_end(&mut disclosed).await.unwrap();
        assert!(disclosed.is_empty());
    }

    #[tokio::test]
    async fn exact_get_with_wrong_handle_is_unavailable() {
        let requester = [13; 32];
        let provider = [14; 32];
        let actual = handle(b"resident");
        let requested = handle(b"not resident");
        let (client, server) = duplex(4096);
        let (mut client_recv, mut client_send) = split(client);
        let (mut server_recv, mut server_send) = split(server);

        let serving = tokio::spawn(async move {
            serve_get_blob(
                &mut server_recv,
                &mut server_send,
                requester,
                provider,
                |locator| (locator == blob_locator(actual)).then_some(actual),
                |_| unreachable!("an unresolved locator cannot reach blob storage"),
            )
            .await
        });
        let received = fetch_get_blob_stream(
            &mut client_send,
            &mut client_recv,
            requester,
            provider,
            &requested,
        )
        .await
        .unwrap();

        assert!(received.is_none());
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn exact_get_rejects_bytes_that_do_not_hash_to_the_handle() {
        let _guard = exact_blob_receive_test_guard();
        let requester = [15; 32];
        let provider = [16; 32];
        let expected = handle(b"expected");
        let (client, server) = duplex(4096);
        let (mut client_recv, mut client_send) = split(client);
        let (mut server_recv, mut server_send) = split(server);

        let serving = tokio::spawn(async move {
            serve_get_blob(
                &mut server_recv,
                &mut server_send,
                requester,
                provider,
                |locator| (locator == blob_locator(expected)).then_some(expected),
                |_| Some(Bytes::from_source(b"wrong bytes".to_vec())),
            )
            .await
        });
        let result = fetch_get_blob_stream(
            &mut client_send,
            &mut client_recv,
            requester,
            provider,
            &expected,
        )
        .await;

        assert!(result.is_err());
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn find_node_enforces_count_and_exact_eof() {
        let oversized = [u8::try_from(crate::routing::K + 1).unwrap()];
        assert!(
            recv_find_node_response(&mut oversized.as_slice())
                .await
                .is_err()
        );
        assert!(
            recv_find_node_response(&mut [0, 1].as_slice())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn exact_get_accepts_empty_content_and_rejects_trailing_bytes() {
        let _guard = exact_blob_receive_test_guard();
        assert_eq!(
            recv_blob_response(&mut [0; 8].as_slice()).await.unwrap(),
            Some(Bytes::from_source(Vec::<u8>::new()))
        );
        let mut trailing = [0; 9];
        trailing[8] = 1;
        assert!(recv_blob_response(&mut trailing.as_slice()).await.is_err());
    }
}
