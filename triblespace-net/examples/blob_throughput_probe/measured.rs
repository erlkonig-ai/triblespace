//! Example-only observation/cap wrapper. The production protocol still owns
//! framing, endpoint-bound bearer proofs, receive storage and the one hash.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use triblespace_net::transport::iroh::{IrohConn, IrohTransport};
use triblespace_net::transport::{Alpn, Conn, PeerId, Transport};

const GET: u8 = triblespace_net::protocol::OP_GET_BLOB;

#[derive(Default)]
pub struct Timing {
    count: AtomicU64,
    nanos: AtomicU64,
}

impl Timing {
    #[cfg(test)]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn record(&self, duration: Duration) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.nanos
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    fn report(&self, name: &str) {
        println!(
            "stage={name} count={} sum_ms={:.3}",
            self.count.load(Ordering::Relaxed),
            self.nanos.load(Ordering::Relaxed) as f64 / 1e6
        );
    }
}

pub struct Metrics {
    pub fetch: Timing,
    pub put: Timing,
    pub flush: Timing,
    pub refresh: Timing,
    pub close: Timing,
    pub ticks: AtomicU64,
    pub tick_gap_us: AtomicU64,
    dial: Timing,
    get: Timing,
    control: Timing,
    read_errors: AtomicU64,
    announced: AtomicU64,
    body_bytes: AtomicU64,
    failed: AtomicBool,
    size: u64,
    budget: u64,
}

impl Metrics {
    pub fn new(size: u64, budget: u64) -> Self {
        Self {
            fetch: Timing::default(),
            put: Timing::default(),
            flush: Timing::default(),
            refresh: Timing::default(),
            close: Timing::default(),
            ticks: AtomicU64::new(0),
            tick_gap_us: AtomicU64::new(0),
            dial: Timing::default(),
            get: Timing::default(),
            control: Timing::default(),
            read_errors: AtomicU64::new(0),
            announced: AtomicU64::new(0),
            body_bytes: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            size,
            budget,
        }
    }

    fn reserve(&self, size: u64) -> io::Result<()> {
        // u64::MAX is the native "lost residency after bearer proof" response,
        // not an announced allocation. Preserve its ordinary None semantics.
        if size == u64::MAX {
            return Ok(());
        }
        if size != self.size
            || self
                .announced
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    n.checked_add(size).filter(|n| *n <= self.budget)
                })
                .is_err()
        {
            self.failed.store(true, Ordering::Relaxed);
            return Err(io::Error::other("example body-size/aggregate-byte cap"));
        }
        Ok(())
    }

    pub fn cap_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    pub fn report(&self) {
        for (name, timing) in [
            ("fetch_e2e", &self.fetch),
            ("dial_including_setup", &self.dial),
            ("get_stream_receive_and_hash", &self.get),
            ("directory_routing_control_stream", &self.control),
            ("pile_put", &self.put),
            ("pile_explicit_flush", &self.flush),
            ("peer_refresh", &self.refresh),
            ("destination_close", &self.close),
        ] {
            timing.report(name);
        }
        println!(
            "announced_body_bytes={} observed_body_bytes={} stream_read_errors={} byte_cap_failed={} host_ticks={} host_max_tick_gap_us={}",
            self.announced.load(Ordering::Relaxed),
            self.body_bytes.load(Ordering::Relaxed),
            self.read_errors.load(Ordering::Relaxed),
            self.cap_failed(),
            self.ticks.load(Ordering::Relaxed),
            self.tick_gap_us.load(Ordering::Relaxed)
        );
    }
}

#[derive(Clone)]
pub struct MeasuredTransport {
    pub inner: IrohTransport,
    pub metrics: Arc<Metrics>,
    pub connections: Arc<Mutex<Vec<MeasuredConn>>>,
}

impl Transport for MeasuredTransport {
    type Conn = MeasuredConn;
    type WakePlane = <IrohTransport as Transport>::WakePlane;

    fn local_id(&self) -> PeerId {
        self.inner.local_id()
    }
    fn collection_wake_plane(&self) -> Self::WakePlane {
        self.inner.collection_wake_plane()
    }
    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<MeasuredConn> {
        let start = Instant::now();
        let conn = self.inner.dial(peer, alpn).await;
        self.metrics.dial.record(start.elapsed());
        let conn = MeasuredConn {
            inner: conn?,
            metrics: self.metrics.clone(),
        };
        let mut connections = self.connections.lock().unwrap();
        if connections.len() < 32 {
            connections.push(conn.clone());
        }
        Ok(conn)
    }
}

#[derive(Clone)]
pub struct MeasuredConn {
    pub inner: IrohConn,
    pub metrics: Arc<Metrics>,
}

impl MeasuredConn {
    pub fn report_path(&self, phase: &str) {
        let paths = self.inner.0.paths();
        let mut selected = false;
        for path in paths.iter().filter(|p| p.is_selected()) {
            println!(
                "path_phase={phase} peer={} local={:?} remote={:?} direct={}",
                self.inner.0.remote_id(),
                path.local_addr(),
                path.remote_addr(),
                path.is_ip()
            );
            selected = true;
        }
        if !selected {
            println!("path_phase={phase} selected_path=unavailable");
        }
    }

    fn halves(
        &self,
        send: <IrohConn as Conn>::SendHalf,
        recv: <IrohConn as Conn>::RecvHalf,
        outgoing: bool,
        start: Instant,
    ) -> (
        SendMeter<<IrohConn as Conn>::SendHalf>,
        RecvMeter<<IrohConn as Conn>::RecvHalf>,
    ) {
        let op = Arc::new(AtomicU8::new(0));
        (
            SendMeter {
                inner: send,
                op: op.clone(),
            },
            RecvMeter::new(recv, op, self.metrics.clone(), outgoing, start),
        )
    }
}

impl Conn for MeasuredConn {
    type SendHalf = SendMeter<<IrohConn as Conn>::SendHalf>;
    type RecvHalf = RecvMeter<<IrohConn as Conn>::RecvHalf>;

    fn remote_id(&self) -> PeerId {
        self.inner.remote_id()
    }
    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason);
    }
    async fn open_bi(&self) -> anyhow::Result<(Self::SendHalf, Self::RecvHalf)> {
        let start = Instant::now();
        let (send, recv) = self.inner.open_bi().await?;
        Ok(self.halves(send, recv, true, start))
    }
    async fn accept_bi(&self) -> Option<(Self::SendHalf, Self::RecvHalf)> {
        let (send, recv) = self.inner.accept_bi().await?;
        Some(self.halves(send, recv, false, Instant::now()))
    }
}

pub struct SendMeter<W> {
    inner: W,
    op: Arc<AtomicU8>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for SendMeter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            // Capture only opcode, never L, proof bytes, or H.
            let _ = self
                .op
                .compare_exchange(0, bytes[0], Ordering::Relaxed, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct RecvMeter<R> {
    inner: R,
    op: Arc<AtomicU8>,
    metrics: Arc<Metrics>,
    outgoing: bool,
    start: Instant,
    position: usize,
    length: [u8; 8],
    body: bool,
    unavailable: bool,
}

impl<R> RecvMeter<R> {
    fn new(
        inner: R,
        op: Arc<AtomicU8>,
        metrics: Arc<Metrics>,
        outgoing: bool,
        start: Instant,
    ) -> Self {
        Self {
            inner,
            op,
            metrics,
            outgoing,
            start,
            position: 0,
            length: [0; 8],
            body: false,
            unavailable: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RecvMeter<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let get = this.outgoing && this.op.load(Ordering::Relaxed) == GET;
        if !get || this.body || this.unavailable {
            let before = destination.filled().len();
            let result = Pin::new(&mut this.inner).poll_read(cx, destination);
            if get && this.body {
                this.metrics.body_bytes.fetch_add(
                    (destination.filled().len() - before) as u64,
                    Ordering::Relaxed,
                );
            }
            if matches!(&result, Poll::Ready(Err(_))) {
                this.metrics.read_errors.fetch_add(1, Ordering::Relaxed);
            }
            return result;
        }
        // Keep only position and length. The 32 proof bytes pass through and
        // are checked by the unmodified protocol, never saved or interpreted.
        // The length is checked BEFORE returning it to recv_blob_response,
        // which is the point before anonymous receive-file growth can start.
        let limit = if this.position == 0 {
            1
        } else if this.position < 33 {
            33 - this.position
        } else {
            41 - this.position
        };
        let mut header = [0; 32];
        let mut buf = ReadBuf::new(&mut header[..limit.min(destination.remaining())]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.metrics.read_errors.fetch_add(1, Ordering::Relaxed);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) => {}
        }
        let bytes = buf.filled();
        if this.position == 0 && bytes.first().is_some_and(|tag| *tag != 1) {
            // Both unavailable and unknown tags stay the native parser's job.
            this.unavailable = true;
        }
        if this.position >= 33 {
            let offset = this.position - 33;
            this.length[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        this.position += bytes.len();
        if this.position == 41 {
            if let Err(error) = this.metrics.reserve(u64::from_be_bytes(this.length)) {
                return Poll::Ready(Err(error));
            }
            this.body = true;
        }
        destination.put_slice(bytes);
        Poll::Ready(Ok(()))
    }
}

impl<R> Drop for RecvMeter<R> {
    fn drop(&mut self) {
        if self.outgoing {
            // op_get_blob drops its receive half after Blob::new/handle check,
            // so this includes native receive+hash (or failure/cancellation).
            if self.op.load(Ordering::Relaxed) == GET {
                self.metrics.get.record(self.start.elapsed());
            } else {
                self.metrics.control.record(self.start.elapsed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn response(length: u64) -> Vec<u8> {
        let mut bytes = vec![1; 33];
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&[9; 8]);
        bytes
    }

    #[tokio::test]
    async fn cap_rejects_announced_length_before_body_or_length_reaches_native_reader() {
        let bytes = response(8);
        let metrics = Arc::new(Metrics::new(4, 8));
        let mut reader = RecvMeter::new(
            bytes.as_slice(),
            Arc::new(AtomicU8::new(GET)),
            metrics.clone(),
            true,
            Instant::now(),
        );
        let mut proof = [0; 33];
        reader.read_exact(&mut proof).await.unwrap();
        let mut length = [0; 8];
        assert!(reader.read_exact(&mut length).await.is_err());
        assert!(metrics.cap_failed());
        assert_eq!(reader.inner.len(), 8);
        assert_eq!(metrics.body_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn native_header_and_body_are_unchanged_and_budget_counts_attempts() {
        let bytes = response(8);
        let metrics = Arc::new(Metrics::new(8, 8));
        let mut reader = RecvMeter::new(
            bytes.as_slice(),
            Arc::new(AtomicU8::new(GET)),
            metrics.clone(),
            true,
            Instant::now(),
        );
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, bytes);
        assert_eq!(metrics.body_bytes.load(Ordering::Relaxed), 8);
        assert!(metrics.reserve(8).is_err());
        assert!(metrics.reserve(u64::MAX).is_ok());
    }

    #[tokio::test]
    async fn other_rpc_bytes_and_native_unavailable_are_not_interpreted_as_lengths() {
        for (op, bytes) in [(0x0c, vec![4; 64]), (GET, vec![0])] {
            let metrics = Arc::new(Metrics::new(1, 1));
            let mut reader = RecvMeter::new(
                bytes.as_slice(),
                Arc::new(AtomicU8::new(op)),
                metrics.clone(),
                true,
                Instant::now(),
            );
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, bytes);
            assert!(!metrics.cap_failed());
        }
    }

    #[tokio::test]
    async fn truncated_proof_and_residency_loss_keep_native_eof_and_none_semantics() {
        for bytes in [vec![1; 12], response(u64::MAX)[..41].to_vec()] {
            let metrics = Arc::new(Metrics::new(8, 8));
            let mut reader = RecvMeter::new(
                bytes.as_slice(),
                Arc::new(AtomicU8::new(GET)),
                metrics.clone(),
                true,
                Instant::now(),
            );
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, bytes);
            assert!(!metrics.cap_failed());
            assert_eq!(metrics.announced.load(Ordering::Relaxed), 0);
        }
    }
}
