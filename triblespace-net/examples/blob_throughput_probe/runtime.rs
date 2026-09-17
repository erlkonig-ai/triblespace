//! Owned, independent production-host runtime. No installed daemon is used.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use iroh_base::SecretKey;
use tokio::sync::oneshot;
use triblespace_net::host::{self, NetReceiver, NetSender, PeerConfig};
use triblespace_net::transport::{Conn, Harness, Incoming, Transport};

use super::measured::{MeasuredConn, MeasuredTransport, Metrics};

pub struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    pub fn start(limit: Duration) -> Self {
        let (done, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(limit),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("probe=hard-deadline exceeded; disposable artifacts may require cleanup");
                std::process::exit(124); // Only this owned example process.
            }
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub struct Host {
    pub transport: MeasuredTransport,
    stop: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<Result<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Host {
    pub async fn start(
        bind: SocketAddr,
        config: PeerConfig,
        metrics: Arc<Metrics>,
    ) -> Result<(Self, NetSender, NetReceiver)> {
        ensure!(
            !bind.ip().is_unspecified() && bind.port() == 0,
            "bind to one explicit interface IP and an ephemeral port"
        );
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|_| anyhow!("endpoint entropy unavailable"))?;
        let secret = SecretKey::from_bytes(&entropy);
        let (sender, receiver, wiring) = host::wire(secret.public());
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let (done_tx, done) = oneshot::channel();
        let thread = std::thread::Builder::new().name("throughput-net-host".into()).spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
                runtime.block_on(async move {
                    // Deliberately direct-only fixture network: same Iroh/host/
                    // bearer protocol, no relay, DNS publication, or live peers.
                    let endpoint = tokio::time::timeout(Duration::from_secs(10), iroh::Endpoint::builder(iroh::endpoint::presets::Minimal).secret_key(secret).relay_mode(iroh::RelayMode::Disabled).clear_ip_transports().bind_addr(bind)?.bind()).await??;
                    println!("endpoint={} bound_sockets={:?} relay=disabled address_discovery=explicit", endpoint.id(), endpoint.bound_sockets());
                    let harness = triblespace_net::transport::iroh::bind_with_endpoint(endpoint, &config).await;
                    let transport = MeasuredTransport { inner: harness.transport, metrics: metrics.clone(), connections: Arc::new(Mutex::new(Vec::new())) };
                    let mut incoming = harness.incoming;
                    let (tx, rx) = tokio::sync::mpsc::channel(64);
                    let forwarding_metrics = metrics.clone();
                    let forward = tokio::spawn(async move {
                        while let Some(incoming) = incoming.recv().await {
                            let conn = MeasuredConn { inner: incoming.conn, metrics: forwarding_metrics.clone() };
                            match tx.try_send(Incoming { alpn: incoming.alpn, conn }) {
                                Ok(()) => {},
                                Err(tokio::sync::mpsc::error::TrySendError::Full(incoming)) => incoming.conn.close(1, b"example incoming queue full"),
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        }
                    });
                    let ticking = tokio::spawn(async move {
                        let mut last = Instant::now();
                        loop {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            let now = Instant::now();
                            metrics.tick_gap_us.fetch_max(now.duration_since(last).as_micros() as u64, Ordering::Relaxed);
                            metrics.ticks.fetch_add(1, Ordering::Relaxed);
                            last = now;
                        }
                    });
                    let _ = ready_tx.send(transport.clone());
                    let host = host::run_host(Harness { transport: transport.clone(), incoming: rx }, config, wiring);
                    tokio::pin!(host);
                    tokio::select! { _ = &mut host => {}, _ = stopped => {} }
                    forward.abort();
                    ticking.abort();
                    let _ = forward.await;
                    let _ = ticking.await;
                    tokio::time::timeout(Duration::from_secs(10), transport.shutdown()).await?;
                    Ok(())
                })
            })();
            let _ = done_tx.send(result);
        })?;
        let transport = tokio::time::timeout(Duration::from_secs(12), ready_rx).await??;
        Ok((
            Self {
                transport,
                stop: Some(stop),
                done,
                thread: Some(thread),
            },
            sender,
            receiver,
        ))
    }

    pub fn report_paths(&self) {
        let connections = self.transport.connections.lock().unwrap();
        println!("retained_path_samples={} maximum=32", connections.len());
        for conn in connections.iter() {
            conn.report_path("arm-end");
        }
    }

    pub async fn close(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(Duration::from_secs(12), &mut self.done).await???;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("owned network thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // An early argument/IO failure still asks our host to drain. The outer
        // owned-process watchdog bounds the exceptional shutdown path.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
