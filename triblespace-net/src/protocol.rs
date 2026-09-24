//! Binary wire protocol primitives.
//!
//! One QUIC stream carries one operation. Establishing the TLS connection
//! grants no collection authority: `COLLECTION_REPAIR` carries READ(C)
//! evidence in its own request. Exact blob reads use only bearer-handle key
//! confirmation. Collection identity and collection authority do not
//! participate in exact discovery or transfer.

use anybytes::Bytes;
use anyhow::{Result, anyhow};
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;

use crate::bearer::{blob_locator, proof_matches, provider_proof, requester_proof};
use crate::transport::Conn;
use crate::transport::PeerId;

/// Shared bearer/DHT transport generation. Collection repair versions its own
/// operation byte so unchanged exact-H clients need not replace their endpoint.
pub const PILE_SYNC_ALPN: &[u8] = b"/triblespace/pile-sync/26";

// Operation types — first byte on each stream.
// 0x01 was branch-list; 0x03 was blob-children; 0x04 was branch-head;
// 0x05 was connection AUTH; 0x0D was record/AUTH-only collection repair.
// None are accepted. Incompatible operation layouts require a fresh byte.
pub const OP_GET_BLOB: u8 = 0x02;
pub const OP_PROVIDER_PUT: u8 = 0x06;
pub const OP_PROVIDER_GET: u8 = 0x07;
pub const OP_FIND_NODE: u8 = 0x0C;
// 0x0E is OP_COLLECTION_REPAIR, owned by collection_wire.

pub const PROVIDER_PUT_OK: u8 = 0x00;
pub const PROVIDER_PUT_FULL: u8 = 0x01;

const BLOB_UNAVAILABLE: u8 = 0x00;
const BLOB_PROVIDER_PROOF: u8 = 0x01;

pub type RawHash = [u8; 32];
/// File-backed exact-transfer ceiling. An idle body holds one admission slot,
/// never the shared scratch buffer needed by another body's ready local work.
pub(crate) const MAX_EXACT_BLOB_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const EXACT_BLOB_CHUNK_BYTES: usize = 1 << 20;
const EXACT_BLOB_POLLS_PER_CHUNK: usize = 128;
const MAX_EXACT_BLOB_STORAGE_UNITS: usize =
    (MAX_EXACT_BLOB_BYTES / EXACT_BLOB_CHUNK_BYTES as u64) as usize;
// Bound live body futures and open receive files separately from byte storage.
// Like the host's inbound request limit, sixteen is an admission policy, not a
// throughput guarantee. Exhaustion is a local error, not an awaited FIFO queue.
const MAX_EXACT_BLOB_RECEIVERS: usize = 16;
static EXACT_BLOB_RECEIVES: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_EXACT_BLOB_RECEIVERS);
static EXACT_BLOB_STORAGE_UNITS: AtomicUsize = AtomicUsize::new(0);
static EXACT_BLOB_SCRATCH: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Local saturation says nothing about the provider or its connection. Callers
/// can distinguish it through anyhow::Error::is/downcast_ref without parsing text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactBlobReceiveResourceError {
    BodySlotsExhausted,
    TemporaryStorageExhausted,
}

impl std::fmt::Display for ExactBlobReceiveResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BodySlotsExhausted => "local exact-blob receive capacity exhausted",
            Self::TemporaryStorageExhausted => {
                "local exact-blob temporary storage capacity exhausted"
            }
        })
    }
}

impl std::error::Error for ExactBlobReceiveResourceError {}

/// Charge actual file growth, rounded up to a MiB per nonempty backing. An idle
/// announcement reserves no disk; tiny completed mappings still cost one unit.
/// The aggregate covers partial files AND returned mappings until their last
/// owner drops. It bounds rounded logical lengths, not filesystem metadata,
/// transport buffers, page-cache residency, or the caller's other allocations.
/// A caller retaining returned Bytes (including cache-owned clones/slices) keeps
/// its charge. Such retention can exhaust the budget until the owner is dropped;
/// copying to an independent destination and dropping the receive releases it.
#[derive(Default)]
struct ExactBlobStorage {
    units: usize,
}

impl ExactBlobStorage {
    fn grow(&mut self, bytes: usize) -> Result<()> {
        let units = bytes.div_ceil(EXACT_BLOB_CHUNK_BYTES);
        let additional = units - self.units;
        if additional == 0 {
            return Ok(());
        }
        EXACT_BLOB_STORAGE_UNITS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(additional)
                    .filter(|&next| next <= MAX_EXACT_BLOB_STORAGE_UNITS)
            })
            .map_err(|_| ExactBlobReceiveResourceError::TemporaryStorageExhausted)?;
        self.units = units;
        Ok(())
    }
}

impl Drop for ExactBlobStorage {
    fn drop(&mut self) {
        EXACT_BLOB_STORAGE_UNITS.fetch_sub(self.units, Ordering::Relaxed);
    }
}

struct ReceivedExactBlob {
    // Declaration order matters: unmap the backing before returning its credit.
    bytes: Bytes,
    _storage: ExactBlobStorage,
}

// SAFETY: moving this owner only moves the immutable Bytes handle, never its
// backing allocation. That handle and its storage charge remain owned together
// through every clone/slice of the outer Bytes, until the final owner is dropped.
unsafe impl anybytes::ByteSource for ReceivedExactBlob {
    type Owner = Self;

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn get_owner(self) -> Self {
        self
    }
}

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
) -> Result<Option<Blob<UnknownBlob>>> {
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
) -> Result<Option<Blob<UnknownBlob>>>
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
    let Some(bytes) = recv_blob_response(recv).await? else {
        return Ok(None);
    };
    // Hash once at ingress, then carry Blob's cached handle through local
    // landing. The requested handle is not trusted as the payload's identity.
    let blob = Blob::<UnknownBlob>::new(bytes);
    if blob.get_handle().raw != *hash {
        return Err(anyhow!("exact blob bytes do not match bearer handle"));
    }
    Ok(Some(blob))
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
    if len as u64 > MAX_EXACT_BLOB_BYTES {
        return Err(anyhow!(
            "blob response exceeds the {MAX_EXACT_BLOB_BYTES}-byte transport bound"
        ));
    }
    if len == 0 {
        return Ok(Bytes::default());
    }
    let _receiver = EXACT_BLOB_RECEIVES
        .try_acquire()
        .map_err(|_| ExactBlobReceiveResourceError::BodySlotsExhausted)?;
    // On cancellation/error, reverse local drop order closes the file BEFORE
    // its storage charge is returned. Success transfers the charge to Bytes.
    let mut storage = ExactBlobStorage::default();
    let mut file =
        tempfile::tempfile().map_err(|error| anyhow!("create blob receive file: {error}"))?;
    let mut remaining = len;
    while remaining != 0 {
        let take = poll_fn(|cx| {
            // The mutex protects one process-wide scratch allocation only for
            // a bounded batch of immediately-ready polls and one local write.
            // AsyncRead::Pending consumes no bytes and registers its own wake;
            // first stage any earlier Ready bytes, then release scratch. Do not
            // replace this with read_exact, which retains partial bytes while
            // waiting for more input.
            let mut scratch = EXACT_BLOB_SCRATCH
                .lock()
                // Unwinding cannot invalidate the Vec or leave semantic state
                // in scratch. Every poll starts with a fresh empty ReadBuf.
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            scratch.resize(EXACT_BLOB_CHUNK_BYTES, 0);
            let take = remaining.min(scratch.len());
            let mut buffer = tokio::io::ReadBuf::new(&mut scratch[..take]);
            for _ in 0..EXACT_BLOB_POLLS_PER_CHUNK {
                let before = buffer.filled().len();
                match Pin::new(&mut *recv).poll_read(cx, &mut buffer) {
                    Poll::Pending => {
                        if buffer.filled().len() != before {
                            return Poll::Ready(Err(anyhow!(
                                "blob reader returned Pending after consuming bytes"
                            )));
                        }
                        if before == 0 {
                            return Poll::Pending;
                        }
                        break;
                    }
                    Poll::Ready(result) => {
                        result.map_err(|error| anyhow!("recv blob body: {error}"))?;
                        if buffer.filled().len() == before {
                            return Poll::Ready(Err(anyhow!(
                                "recv blob body: unexpected end of file"
                            )));
                        }
                        if buffer.remaining() == 0 {
                            break;
                        }
                    }
                }
            }
            let chunk = buffer.filled();
            // Charge before extending the file. Refuse saturation rather than
            // waiting while partial receives hold all the remaining capacity.
            storage.grow(len - remaining + chunk.len())?;
            // A ready read can be much smaller than a MiB. Append it without
            // remapping the entire growing tail for every transport fragment.
            std::io::Write::write_all(&mut file, chunk)
                .map_err(|error| anyhow!("write file-backed blob response: {error}"))?;
            Poll::Ready(Ok(chunk.len()))
        })
        .await?;
        remaining -= take;
        if remaining != 0 {
            // Bound each ready-reader turn to one chunk and give cancellation
            // and unrelated readers a scheduling point. Synchronous file I/O
            // remains cooperative work, not a hard wall-clock timeout bound.
            tokio::task::yield_now().await;
        }
    }
    // SAFETY: this fresh anonymous file has no other writer or mutable mapping,
    // and this function never writes it again. The immutable map outlives the
    // file descriptor and is owned with the corresponding storage charge.
    let bytes = unsafe { Bytes::map_file(&file) }
        .map_err(|error| anyhow!("map completed blob response: {error}"))?;
    Ok(Bytes::from_source(ReceivedExactBlob {
        bytes,
        _storage: storage,
    }))
}

/// Independent test runtimes must not exhaust each other's process-wide receive
/// budgets. Hold this before exercising a body receive in a unit test; contention
/// within that test's own runtime still uses the production budgets.
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
    use std::task::Context;
    use tokio::io::{AsyncReadExt, duplex, split};

    struct Fragmented<'a> {
        bytes: &'a [u8],
        fragment: usize,
        stall: bool,
        pause: bool,
    }

    impl AsyncRead for Fragmented<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.bytes.is_empty() && self.stall {
                return Poll::Pending;
            }
            if self.pause {
                self.pause = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let take = self.bytes.len().min(buffer.remaining()).min(self.fragment);
            buffer.put_slice(&self.bytes[..take]);
            self.bytes = &self.bytes[take..];
            self.pause = true;
            Poll::Ready(Ok(()))
        }
    }

    fn storage_units() -> usize {
        EXACT_BLOB_STORAGE_UNITS.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn premature_eof_after_a_ready_prefix_is_not_polled_again() {
        struct PrefixThenEof<'a>(&'a AtomicUsize);

        impl AsyncRead for PrefixThenEof<'_> {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                match self.0.fetch_add(1, Ordering::Relaxed) {
                    0 => buffer.put_slice(b"ab"),
                    1 => {}
                    _ => panic!("body reader was polled after premature EOF"),
                }
                Poll::Ready(Ok(()))
            }
        }

        let _guard = exact_blob_receive_test_guard();
        let polls = AtomicUsize::new(0);
        let error = recv_exact_blob_body(&mut PrefixThenEof(&polls), 4)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unexpected end of file"));
        assert_eq!(polls.load(Ordering::Relaxed), 2);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn immediately_ready_fragments_yield_at_the_poll_budget() {
        struct ReadyBytes<'a>(&'a AtomicUsize);

        impl AsyncRead for ReadyBytes<'_> {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                buffer.put_slice(b"x");
                Poll::Ready(Ok(()))
            }
        }

        let _guard = exact_blob_receive_test_guard();
        let polls = AtomicUsize::new(0);
        let mut reader = ReadyBytes(&polls);
        let len = 2 * EXACT_BLOB_POLLS_PER_CHUNK + 1;
        let mut body = Box::pin(recv_exact_blob_body(&mut reader, len));
        assert!(futures::poll!(&mut body).is_pending());
        assert_eq!(polls.load(Ordering::Relaxed), EXACT_BLOB_POLLS_PER_CHUNK);
        assert!(futures::poll!(&mut body).is_pending());
        assert_eq!(
            polls.load(Ordering::Relaxed),
            2 * EXACT_BLOB_POLLS_PER_CHUNK
        );
        let bytes = match futures::poll!(&mut body) {
            Poll::Ready(Ok(bytes)) => bytes,
            other => panic!("final byte must complete the receive: {other:?}"),
        };
        assert_eq!(bytes.as_ref(), vec![b'x'; len]);
        assert_eq!(polls.load(Ordering::Relaxed), len);
        drop(body);
        drop(bytes);
        assert_eq!(storage_units(), 0);
    }

    #[tokio::test]
    async fn storage_saturation_releases_an_already_staged_prefix() {
        let _guard = exact_blob_receive_test_guard();
        // Reserve accounting only, leaving room for precisely one real chunk.
        let mut occupied = ExactBlobStorage::default();
        occupied
            .grow((MAX_EXACT_BLOB_STORAGE_UNITS - 1) * EXACT_BLOB_CHUNK_BYTES)
            .unwrap();
        let input = vec![b'x'; EXACT_BLOB_CHUNK_BYTES + 1];
        let mut reader = input.as_slice();
        let mut body = Box::pin(recv_exact_blob_body(&mut reader, input.len()));
        assert!(futures::poll!(&mut body).is_pending());
        assert_eq!(storage_units(), MAX_EXACT_BLOB_STORAGE_UNITS);
        let error = match futures::poll!(&mut body) {
            Poll::Ready(Err(error)) => error,
            other => panic!("growth must fail without waiting for credit: {other:?}"),
        };
        assert_eq!(
            error.downcast_ref::<ExactBlobReceiveResourceError>(),
            Some(&ExactBlobReceiveResourceError::TemporaryStorageExhausted)
        );
        drop(body);
        assert_eq!(storage_units(), MAX_EXACT_BLOB_STORAGE_UNITS - 1);
        drop(occupied);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn panicking_reader_releases_budgets_and_does_not_disable_scratch() {
        use futures::FutureExt as _;

        struct PanickingReader;
        impl AsyncRead for PanickingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                panic!("injected local reader panic");
            }
        }

        let _guard = exact_blob_receive_test_guard();
        assert!(
            std::panic::AssertUnwindSafe(recv_exact_blob_body(&mut PanickingReader, 1))
                .catch_unwind()
                .await
                .is_err()
        );
        assert_eq!(storage_units(), 0);
        let bytes = recv_exact_blob_body(&mut b"ok".as_slice(), 2)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"ok");
        drop(bytes);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn invalid_pending_reader_is_rejected_without_losing_resource_credit() {
        struct InvalidPendingReader;
        impl AsyncRead for InvalidPendingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buffer: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                buffer.put_slice(b"x");
                Poll::Pending
            }
        }

        let _guard = exact_blob_receive_test_guard();
        let error = recv_exact_blob_body(&mut InvalidPendingReader, 1)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Pending after consuming bytes"));
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn idle_and_partial_bodies_do_not_block_a_ready_body() {
        let _guard = exact_blob_receive_test_guard();
        assert_eq!(storage_units(), 0);
        for prefix in [b"".as_slice(), b"partial".as_slice()] {
            let mut reader = Fragmented {
                bytes: prefix,
                fragment: EXACT_BLOB_CHUNK_BYTES,
                stall: true,
                pause: false,
            };
            let mut slow = Box::pin(recv_exact_blob_body(&mut reader, 1 << 30));
            // The second poll passes any yield after the partial write and
            // reaches network Pending. No timer controls this interleaving.
            assert!(futures::poll!(&mut slow).is_pending());
            assert!(futures::poll!(&mut slow).is_pending());
            assert_eq!(storage_units(), usize::from(!prefix.is_empty()));
            let ready = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                recv_exact_blob_body(&mut b"ready".as_slice(), 5),
            )
            .await
            .expect("an idle network body must not own the shared scratch")
            .unwrap();
            assert_eq!(ready.as_ref(), b"ready");
            drop(ready);
            drop(slow);
            assert_eq!(
                storage_units(),
                0,
                "cancellation returns partial-file credit"
            );
            assert_eq!(
                EXACT_BLOB_RECEIVES.available_permits(),
                MAX_EXACT_BLOB_RECEIVERS
            );
        }
    }

    #[tokio::test]
    async fn fragmented_body_preserves_partial_reads_across_pending() {
        let _guard = exact_blob_receive_test_guard();
        for (len, fragment) in [(4099, 7), (EXACT_BLOB_CHUNK_BYTES + 17, 16384)] {
            let input: Vec<_> = (0..len).map(|index| (index % 251) as u8).collect();
            let mut reader = Fragmented {
                bytes: &input,
                fragment,
                stall: false,
                pause: false,
            };
            let bytes = recv_exact_blob_body(&mut reader, len).await.unwrap();
            assert_eq!(bytes.as_ref(), input);
            assert_eq!(storage_units(), len.div_ceil(EXACT_BLOB_CHUNK_BYTES));
            drop(bytes);
            assert_eq!(storage_units(), 0);
        }
    }

    #[tokio::test]
    async fn retained_slices_keep_storage_credit_and_saturation_fails_without_waiting() {
        let _guard = exact_blob_receive_test_guard();
        assert_eq!(storage_units(), 0);
        // Reserve accounting units only: this test never allocates a huge file.
        let mut occupied = ExactBlobStorage::default();
        occupied
            .grow((MAX_EXACT_BLOB_STORAGE_UNITS - 1) * EXACT_BLOB_CHUNK_BYTES)
            .unwrap();
        let bytes = recv_exact_blob_body(&mut b"ready".as_slice(), 5)
            .await
            .unwrap();
        let retained = bytes.slice(1..3);
        drop(bytes);
        assert_eq!(storage_units(), MAX_EXACT_BLOB_STORAGE_UNITS);
        let result = recv_exact_blob_body(&mut b"x".as_slice(), 1).await;
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<ExactBlobReceiveResourceError>(),
            Some(&ExactBlobReceiveResourceError::TemporaryStorageExhausted)
        );
        assert_eq!(retained.as_ref(), b"ea");
        drop(retained);
        assert_eq!(storage_units(), MAX_EXACT_BLOB_STORAGE_UNITS - 1);
        drop(occupied);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn idle_body_admission_is_bounded_and_cancellation_reopens_it() {
        let _guard = exact_blob_receive_test_guard();
        let mut readers: Vec<_> = (0..MAX_EXACT_BLOB_RECEIVERS)
            .map(|_| Fragmented {
                bytes: b"",
                fragment: 1,
                stall: true,
                pause: false,
            })
            .collect();
        let mut bodies: Vec<_> = readers
            .iter_mut()
            .map(|reader| Box::pin(recv_exact_blob_body(reader, 1)))
            .collect();
        for body in &mut bodies {
            assert!(futures::poll!(body).is_pending());
        }
        assert_eq!(storage_units(), 0, "an announcement alone reserves no disk");
        assert_eq!(EXACT_BLOB_RECEIVES.available_permits(), 0);
        let result = recv_exact_blob_body(&mut b"x".as_slice(), 1).await;
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<ExactBlobReceiveResourceError>(),
            Some(&ExactBlobReceiveResourceError::BodySlotsExhausted)
        );
        drop(bodies);
        let bytes = recv_exact_blob_body(&mut b"x".as_slice(), 1).await.unwrap();
        assert_eq!(bytes.as_ref(), b"x");
        drop(bytes);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    #[tokio::test]
    async fn failed_body_and_trailing_response_release_storage() {
        let _guard = exact_blob_receive_test_guard();
        assert!(
            recv_exact_blob_body(&mut b"short".as_slice(), 9)
                .await
                .is_err()
        );
        assert_eq!(storage_units(), 0);
        let mut response = 5_u64.to_be_bytes().to_vec();
        response.extend_from_slice(b"short!");
        assert!(recv_blob_response(&mut response.as_slice()).await.is_err());
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
        assert_eq!(
            recv_exact_blob_body(&mut b"".as_slice(), 0)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(storage_units(), 0);
    }

    #[cfg(feature = "sim")]
    #[tokio::test(start_paused = true)]
    async fn stalled_body_still_obeys_the_callers_deadline() {
        let _guard = exact_blob_receive_test_guard();
        let mut reader = Fragmented {
            bytes: b"partial",
            fragment: 7,
            stall: true,
            pause: false,
        };
        let budget = std::time::Duration::from_secs(10);
        let started = tokio::time::Instant::now();
        assert!(
            tokio::time::timeout(budget, recv_exact_blob_body(&mut reader, 100))
                .await
                .is_err()
        );
        assert_eq!(started.elapsed(), budget);
        assert_eq!(storage_units(), 0);
        assert_eq!(
            EXACT_BLOB_RECEIVES.available_permits(),
            MAX_EXACT_BLOB_RECEIVERS
        );
    }

    fn handle(bytes: &[u8]) -> RawHash {
        *blake3::hash(bytes).as_bytes()
    }

    #[tokio::test]
    async fn pile_put_releases_receive_credit_without_losing_stored_bytes() {
        use triblespace_core::blob::encodings::UnknownBlob;
        use triblespace_core::repo::pile::Pile;
        use triblespace_core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};

        let _guard = exact_blob_receive_test_guard();
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let content = b"independent pile backing";
        let bytes = recv_exact_blob_body(&mut content.as_slice(), content.len())
            .await
            .unwrap();
        assert_eq!(storage_units(), 1);
        // This is PeerSnapshot's actual boundary: move the network Blob, with
        // its cached handle and receive owner, into the independent pile.
        let blob = Blob::<UnknownBlob>::new(bytes);
        let expected = blob.get_handle();
        assert_eq!(expected.raw, handle(content));
        assert_eq!(storage_units(), 1);
        let stored = pile.put::<UnknownBlob, _>(blob).unwrap();
        assert_eq!(stored, expected);
        assert_eq!(storage_units(), 0);
        let snapshot = pile.snapshot().unwrap();
        let reread: Bytes = snapshot.get(stored).unwrap();
        assert_eq!(reread.as_ref(), content);
        assert_eq!(storage_units(), 0);

        // An independent caller-held clone still owns receive credit even
        // when Pile's duplicate-blob path has already consumed its argument.
        let bytes = recv_exact_blob_body(&mut content.as_slice(), content.len())
            .await
            .unwrap();
        let blob = Blob::<UnknownBlob>::new(bytes);
        let retained = blob.clone();
        assert_eq!(pile.put::<UnknownBlob, _>(blob).unwrap(), stored);
        assert_eq!(storage_units(), 1);
        drop(retained);
        assert_eq!(storage_units(), 0);
        pile.close().unwrap();
        assert_eq!(reread.as_ref(), content);
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

        assert_eq!(received.get_handle().raw, content_handle);
        assert_eq!(&*received.bytes, content);
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
