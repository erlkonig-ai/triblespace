//! Independent regressions through the production codec, writer and driver.
//! The scripted peer deliberately separates discovery, bodies and landing ACKs.

use super::*;
use anybytes::Bytes;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, DuplexStream, ReadHalf, WriteHalf};
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

use crate::exchange::Failure;
use crate::riblt_cache::CacheError;
use crate::transport::sim::{SimConfig, SimNet};
use crate::walk::tests::walking::{Node, open};
use crate::walk_stream::Algorithm;

#[derive(Clone)]
struct NoRequests;

impl Service for NoRequests {
    async fn serve<W: SendStream, R: RecvStream>(
        &self,
        _peer: PeerId,
        _tag: u8,
        _send: &mut W,
        _recv: &mut R,
    ) -> anyhow::Result<()> {
        anyhow::bail!("this records-only fixture must not fetch blobs")
    }
}

struct Tx(WriteHalf<DuplexStream>, Arc<Mutex<Option<u32>>>);
struct Rx(ReadHalf<DuplexStream>, Arc<Mutex<Option<u32>>>);

impl AsyncWrite for Tx {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl SendStream for Tx {
    fn reset(&mut self, code: u32) {
        *self.1.lock().unwrap() = Some(code);
    }
}

/// Fault injection at actual shutdown, not at channel closure or readiness.
struct FinishTx(Tx, bool, Arc<Mutex<bool>>);

impl AsyncWrite for FinishTx {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        *self.2.lock().unwrap() = true;
        if self.1 {
            Poll::Pending
        } else {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "scripted FIN failure")))
        }
    }
}

impl SendStream for FinishTx {
    fn reset(&mut self, code: u32) {
        self.0.reset(code);
    }
}
impl AsyncRead for Rx {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, bytes)
    }
}
impl RecvStream for Rx {
    fn stop(&mut self, code: u32) {
        *self.1.lock().unwrap() = Some(code);
    }
}

fn pair() -> (Node, Node, CollectionHandle, CollectionRecord) {
    let mut local = Node::new(131);
    let mut peer = Node::new(132);
    let collection = local.hold("riblt-runtime-boundaries", open());
    assert_eq!(peer.hold("riblt-runtime-boundaries", open()), collection);
    let record = peer.commit(collection, 7);
    peer.observe();
    (local, peer, collection, record)
}

fn root(node: &Node, collection: CollectionHandle) -> Frame {
    let generation = node.pinned(collection).cache(WalkKind::Commit);
    Frame::RibltRoot {
        summary: generation.summary(),
    }
}

fn cell(node: &Node, collection: CollectionHandle, index: usize) -> Frame {
    let cell = node
        .pinned(collection)
        .cache(WalkKind::Commit)
        .cell(index)
        .unwrap();
    Frame::RibltCell {
        index: index as u32,
        symbol: cell.symbol.0,
        hash: cell.hash,
        count: cell.count,
    }
}

fn receiver(node: &Node, collection: CollectionHandle) -> Exchange {
    Exchange::start_riblt(collection, WalkKind::Commit, node.pinned(collection))
}

#[test]
fn riblt_runtime_rejects_count_index_and_retired_controls_before_landing() {
    let (local, peer, collection, _) = pair();
    let valid = cell(&peer, collection, 0);
    let Frame::RibltCell { symbol, hash, .. } = valid else {
        unreachable!()
    };
    let malformed = [
        Frame::RibltCell {
            index: 1,
            symbol,
            hash,
            count: 1,
        },
        Frame::RibltCell {
            index: 0,
            symbol,
            hash,
            count: -1,
        },
        Frame::RibltCell {
            index: 0,
            symbol,
            hash,
            count: 2,
        },
        Frame::RibltCell {
            index: 0,
            symbol,
            hash,
            count: i64::MAX,
        },
        Frame::RibltCell {
            index: 0,
            symbol,
            hash,
            count: i64::MIN,
        },
        Frame::Done,
        Frame::Landed,
    ];
    for frame in malformed {
        let mut exchange = receiver(&local, collection);
        exchange.on_frame(root(&peer, collection), Some(local.snapshot()));
        let outs = exchange.on_frame(frame, Some(local.snapshot()));
        assert!(outs.is_empty());
        assert_eq!(exchange.outcome(), Some(Outcome::Failed(Failure::Protocol)));
        assert!(!exchange.discovery_stopped());
        assert!(exchange.end().agreed.is_none());
    }
    let mut exchange = receiver(&local, collection);
    exchange.on_frame(root(&peer, collection), Some(local.snapshot()));
    assert!(exchange.on_fin().is_empty());
    assert_eq!(exchange.outcome(), Some(Outcome::Failed(Failure::Protocol)));

    let mut exchange = receiver(&local, collection);
    exchange.on_frame(valid, Some(local.snapshot()));
    assert_eq!(exchange.outcome(), Some(Outcome::Failed(Failure::Protocol)));
}

#[test]
fn riblt_runtime_nonzero_symbol_is_not_a_zero_residual() {
    let (local, peer, collection, _) = pair();
    let mut exchange = receiver(&local, collection);
    exchange.on_frame(root(&peer, collection), Some(local.snapshot()));
    // A zero count/checksum does not discharge nonzero symbol bytes.
    let outs = exchange.on_frame(
        Frame::RibltCell {
            index: 0,
            symbol: [0xA5; 32],
            hash: 0,
            count: 0,
        },
        Some(local.snapshot()),
    );
    assert!(outs.is_empty());
    assert_ne!(exchange.outcome(), Some(Outcome::Confirmed));
    assert!(!exchange.discovery_stopped());
    assert!(exchange.end().agreed.is_none());
}

#[test]
fn riblt_runtime_large_source_summaries_do_not_impose_a_small_absolute_n_limit() {
    let (local, _, collection, _) = pair();
    for kind in [
        WalkKind::Commit,
        WalkKind::Derive,
        WalkKind::References,
    ] {
        let cache = local.pinned(collection).cache(kind);
        // The retired cell budget plus one, and the largest i64 count.
        for count in [(1 << 20) + 1, i64::MAX as u64] {
            let summary = PatchSummary::new(Some([0x44; 32]), count).unwrap();
            let mut exchange = Exchange::start_riblt(collection, kind, local.pinned(collection));
            assert!(
                exchange
                    .on_frame(
                        Frame::RibltRoot { summary },
                        Some(local.snapshot())
                    )
                    .is_empty()
            );
            assert_eq!(exchange.outcome(), None);
            assert!(
                !exchange.discovery_stopped(),
                "an accepted summary is not a peer proof"
            );
            assert_eq!(
                cache.prepared().unwrap(),
                0,
                "no million-object fixture/preparation"
            );
            assert!(exchange.end().agreed.is_none());

            let mut prefix =
                Exchange::start(collection, kind, local.pinned(collection), None, true, true);
            prefix.on_frame(
                Frame::Subtree {
                    prefix: Vec::new(),
                    summary,
                },
                Some(local.snapshot()),
            );
            assert_eq!(
                prefix.outcome(),
                Some(Outcome::Failed(Failure::Protocol)),
                "the existing Prefix absolute cardinality guard is unchanged"
            );
        }
        let mut exchange = Exchange::start_riblt(collection, kind, local.pinned(collection));
        exchange.on_frame(
            Frame::RibltRoot {
                summary: PatchSummary::new(Some([0x44; 32]), i64::MAX as u64 + 1).unwrap(),
            },
            Some(local.snapshot()),
        );
        assert_eq!(
            exchange.outcome(),
            Some(Outcome::Failed(Failure::ResourceLimit))
        );
        assert!(exchange.end().agreed.is_none());
    }
}

#[test]
fn riblt_runtime_residual_counts_are_bounded_by_the_peer_root_not_a_budget() {
    let (local, _, collection, _) = pair();
    // Above the retired 1_048_576 decoder support: only the peer root bounds it.
    let advertised = (1 << 21) + 100;
    for (count, failure) in [
        ((1 << 21) + 1, None),
        (advertised as i64, None),
        (advertised as i64 + 1, Some(Failure::Protocol)),
        (-1, Some(Failure::Protocol)),
    ] {
        let mut exchange = receiver(&local, collection);
        exchange.on_frame(
            Frame::RibltRoot {
                summary: PatchSummary::new(Some([0x44; 32]), advertised).unwrap(),
            },
            Some(local.snapshot()),
        );
        assert_eq!(exchange.outcome(), None);
        exchange.on_frame(
            Frame::RibltCell {
                index: 0,
                symbol: [0; 32],
                hash: 0,
                count,
            },
            Some(local.snapshot()),
        );
        assert_eq!(exchange.outcome(), failure.map(Outcome::Failed));
        assert!(!exchange.discovery_stopped());
        assert!(exchange.end().agreed.is_none());
    }
}

#[test]
fn riblt_runtime_transient_cow_frontier_can_exceed_absolute_source_limit() {
    let mut local = Node::new(211);
    let mut peer = Node::new(212);
    let collection = local.hold("riblt-small-injected-proof-limit", open());
    assert_eq!(
        peer.hold("riblt-small-injected-proof-limit", open()),
        collection
    );
    local.commit(collection, 0);
    local.commit(collection, 1);
    let eager = peer.commit(collection, 10);
    peer.commit(collection, 11);
    local.observe();
    peer.observe();
    assert_eq!(
        local
            .pinned(collection)
            .cache(WalkKind::Commit)
            .summary()
            .leaf_count(),
        2
    );
    assert_eq!(
        peer.pinned(collection)
            .cache(WalkKind::Commit)
            .summary()
            .leaf_count(),
        2
    );
    let mut exchange = receiver(&local, collection);
    exchange.on_frame(root(&peer, collection), Some(local.snapshot()));
    let outs = exchange.on_frame(
        Frame::Value {
            key: eager.fingerprint().raw(),
            bytes: encode_record(collection, eager).unwrap(),
        },
        Some(local.snapshot()),
    );
    assert!(matches!(&outs[..], [Out::Land(events)] if events.len() == 1));
    assert_eq!(exchange.proof_budget_with_limit(2), Ok(()));
    assert!(!exchange.discovery_stopped());
    let ended = exchange.end();
    assert_eq!(
        ended.peer_root.unwrap().leaf_count(),
        3,
        "the COW peer still includes both not-yet-peeled local-only records"
    );
    assert!(
        ended.agreed.is_none(),
        "an intermediate frontier is not confirmation"
    );

    let mut prefix_node = Node::new(213);
    assert_eq!(
        prefix_node.hold("riblt-small-injected-proof-limit", open()),
        collection
    );
    for number in 0..3 {
        prefix_node.commit(collection, number);
    }
    prefix_node.observe();
    let mut prefix = Exchange::start(
        collection,
        WalkKind::Commit,
        prefix_node.pinned(collection),
        None,
        true,
        true,
    );
    prefix.on_frame(
        Frame::Subtree {
            prefix: Vec::new(),
            summary: prefix_node
                .pinned(collection)
                .cache(WalkKind::Commit)
                .summary(),
        },
        Some(prefix_node.snapshot()),
    );
    assert_eq!(prefix.outcome(), None);
    assert_eq!(prefix.proof_budget_with_limit(2), Err(Failure::Protocol));
    assert_eq!(prefix.end().peer_root.unwrap().leaf_count(), 3);
}

#[test]
fn riblt_runtime_local_cache_failures_are_not_malformed_peer_errors() {
    assert_eq!(Failure::from(CacheError::Exhausted), Failure::ResourceLimit);
    assert_eq!(Failure::from(CacheError::Storage), Failure::ResourceLimit);
    assert_eq!(
        Failure::from(CacheError::Poisoned),
        Failure::CacheUnavailable
    );
    assert_eq!(
        Failure::from(CacheError::CountOverflow),
        Failure::CacheUnavailable
    );
    assert_eq!(
        Failure::from(crate::riblt_decode::DecodeError::Storage),
        Failure::ResourceLimit
    );
}

#[test]
fn riblt_runtime_stop_requires_written_matching_prefix_but_not_bodies() {
    let (local, peer, collection, _) = pair();
    let mut exchange = receiver(&local, collection);
    assert_eq!(exchange.next_delta(), Some(root(&local, collection)));
    assert!(exchange.on_root_written().is_empty());
    exchange.on_frame(root(&peer, collection), Some(local.snapshot()));
    assert!(matches!(
        exchange.next_delta(),
        Some(Frame::RibltCell { index: 0, .. })
    ));
    let outs = exchange.on_frame(cell(&peer, collection, 0), Some(local.snapshot()));
    assert!(
        outs.is_empty(),
        "honest RIBLT uses eager bodies, not pull requests"
    );
    assert!(
        !exchange.discovery_stopped(),
        "generation/queue admission is not a write receipt"
    );
    assert!(exchange.on_written(1).is_empty());
    assert!(
        exchange.discovery_stopped(),
        "exact sparse root closes before the owed body"
    );
    assert_eq!(exchange.next_delta(), None);
    assert!(!exchange.ready_to_finish(), "an owed body forbids local FIN");
    assert!(
        exchange.awaits(),
        "a body remains owed after coded discovery stops"
    );
    assert!(exchange.end().agreed.is_none());
}

#[test]
fn riblt_runtime_codec_pins_lengths_and_rejects_unknown_algorithm() {
    let (local, peer, collection, _) = pair();
    for frame in [root(&local, collection), cell(&peer, collection, 0)] {
        let (kind, bytes) = frame.encode();
        assert_eq!(Frame::decode(kind, &bytes).unwrap(), Some(frame));
        for length in 0..bytes.len() {
            assert!(Frame::decode(kind, &bytes[..length]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(Frame::decode(kind, &trailing).is_err());
    }
    let (kind, mut bytes) = Frame::Open {
        collection,
        kind: WalkKind::Commit,
        algorithm: Algorithm::CachedRiblt,
        offer: None,
    }
    .encode();
    bytes[33] = 255;
    assert!(Frame::decode(kind, &bytes).is_err());
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_writer_receipts_exclude_partial_frames_and_cancelled_tails() {
    let (script, driven) = tokio::io::duplex(1);
    let (_, send) = tokio::io::split(driven);
    let (mut recv, _script_send) = tokio::io::split(script);
    let reset_note = Arc::new(Mutex::new(None));
    let (frames, queued) = mpsc::channel(1);
    let (reset, resetting) = oneshot::channel();
    let (failed, _failures) = oneshot::channel();
    let (progress, mut receipts) = watch::channel(Written::default());
    let writer = tokio::spawn(write_stream_progress(
        Box::new(Tx(send, reset_note.clone())),
        queued,
        resetting,
        failed,
        Some(progress),
    ));
    let frame = Frame::RibltRoot {
        summary: PatchSummary::new(None, 0).unwrap(),
    };
    let wire_len = 5 + frame.encode().1.len();
    frames.send(frame).await.unwrap();
    let mut partial = vec![0; wire_len - 2];
    recv.read_exact(&mut partial).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(*receipts.borrow(), Written::default(), "partial ROOT is not a receipt");
    let mut tail = [0; 2];
    recv.read_exact(&mut tail).await.unwrap();
    receipts.changed().await.unwrap();
    assert_eq!(*receipts.borrow_and_update(), Written { root: true, cells: 0 });
    let frame = Frame::RibltCell {
        index: 0,
        symbol: [1; 32],
        hash: 3,
        count: 1,
    };
    let wire_len = 5 + frame.encode().1.len();
    frames.send(frame).await.unwrap();
    // Consume all but two bytes; one more fits the pipe, leaving the last byte unwritten.
    let mut partial = vec![0; wire_len - 2];
    recv.read_exact(&mut partial).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(*receipts.borrow(), Written { root: true, cells: 0 });
    let mut tail = [0; 2];
    recv.read_exact(&mut tail).await.unwrap();
    receipts.changed().await.unwrap();
    assert_eq!(*receipts.borrow_and_update(), Written { root: true, cells: 1 });
    frames
        .send(Frame::RibltCell {
            index: 1,
            symbol: [2; 32],
            hash: 5,
            count: 1,
        })
        .await
        .unwrap();
    tokio::task::yield_now().await;
    reset.send(RESET_WALK_FAILED).unwrap();
    assert_eq!(writer.await.unwrap(), (false, false));
    assert_eq!(*receipts.borrow(), Written { root: true, cells: 1 });
    assert_eq!(*reset_note.lock().unwrap(), Some(RESET_WALK_FAILED));
}

struct Driven {
    send: WriteHalf<DuplexStream>,
    recv: ReadHalf<DuplexStream>,
    done: tokio::task::JoinHandle<(Ended, bool)>,
    _replace: oneshot::Sender<()>,
    acked: mpsc::UnboundedSender<(u64, u64)>,
    landings: mpsc::UnboundedReceiver<(u64, Vec<NetEvent>)>,
    reset: Arc<Mutex<Option<u32>>>,
    _snapshots: watch::Sender<Option<StoreSnapshot>>,
}

fn driven(local: &Node, peer: &Node, collection: CollectionHandle) -> Driven {
    driven_with_capacity(local, peer, collection, 128)
}

fn driven_with_capacity(
    local: &Node,
    peer: &Node,
    collection: CollectionHandle,
    capacity: usize,
) -> Driven {
    driven_with_writer(local, peer, collection, capacity, |tx| Box::new(tx))
}

fn driven_with_writer(
    local: &Node,
    peer: &Node,
    collection: CollectionHandle,
    capacity: usize,
    wrap: impl FnOnce(Tx) -> Box<dyn SendStream>,
) -> Driven {
    let net = SimNet::new(0xC011, SimConfig::default());
    let harness = net.join(&local.key);
    let (snapshots, observed) = watch::channel(Some(local.snapshot()));
    let (landing, landings) = mpsc::unbounded_channel();
    let (commands, _commanded) = mpsc::unbounded_channel();
    let driver = Driver {
        connections: ConnectionTable::new(harness.transport, NoRequests),
        snapshots: observed,
        landing,
        grants: mpsc::unbounded_channel().0,
        commands,
        id: 1,
        peer: peer.id(),
        collection,
        kind: WalkKind::Commit,
    };
    let (script, stream) = tokio::io::duplex(capacity);
    let (recv, send) = tokio::io::split(stream);
    let reset = Arc::new(Mutex::new(None));
    let tx = wrap(Tx(send, reset.clone()));
    let rx = Rx(recv, reset.clone());
    let exchange = receiver(local, collection);
    let (acked, acks) = mpsc::unbounded_channel();
    let (replace, replaced) = oneshot::channel();
    let done = tokio::spawn(async move {
        drive(
            &driver,
            exchange,
            tx,
            Box::new(rx),
            acks,
            replaced,
        )
        .await
    });
    let (recv, send) = tokio::io::split(script);
    Driven {
        send,
        recv,
        done,
        _replace: replace,
        acked,
        landings,
        reset,
        _snapshots: snapshots,
    }
}

async fn send_frame(send: &mut WriteHalf<DuplexStream>, frame: Frame) {
    let (kind, bytes) = frame.encode();
    write_frame(send, kind, &bytes).await.unwrap();
}

async fn receive_frame(recv: &mut ReadHalf<DuplexStream>) -> Frame {
    receive_or_fin(recv).await.expect("expected a complete frame")
}

async fn receive_or_fin(recv: &mut ReadHalf<DuplexStream>) -> Option<Frame> {
    read_frame(recv).await.unwrap().map(|(kind, bytes)| {
        Frame::decode(kind, &bytes).unwrap().expect("known frame")
    })
}

async fn discover_without_body(
    run: &mut Driven,
    local: &Node,
    peer: &Node,
    collection: CollectionHandle,
) -> usize {
    assert_eq!(receive_frame(&mut run.recv).await, root(local, collection));
    send_frame(&mut run.send, root(peer, collection)).await;
    send_frame(&mut run.send, cell(peer, collection, 0)).await;
    let mut cells = 0;
    for _ in 0..32 {
        // A stopped coded stream owes a body, so neither side may send FIN.
        // The duplex writer can finish each small cell immediately as we read;
        // one second of idle virtual time is below the frame-progress deadline.
        match tokio::time::timeout(Duration::from_secs(1), receive_or_fin(&mut run.recv)).await {
            Ok(Some(Frame::RibltCell { index, .. })) => {
                assert_eq!(index as usize, cells);
                cells += 1;
            }
            Err(_) => {
                assert!(
                    (1..16).contains(&cells),
                    "prepared capacity must not be queued wholesale"
                );
                assert!(run.landings.try_recv().is_err());
                return cells;
            }
            unexpected => panic!("unexpected discovery frame: {unexpected:?}"),
        }
    }
    panic!("the writer did not stop discovery");
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_driver_stops_large_prepared_cache_then_waits_for_body_and_land_ack() {
    let (local, peer, collection, record) = pair();
    let cache = local.pinned(collection).cache(WalkKind::Commit);
    cache.cell(65_535).unwrap(); // 3 MiB prepared, not 3 MiB queued.
    assert_eq!(cache.prepared().unwrap(), 65_536);
    let mut run = driven(&local, &peer, collection);
    discover_without_body(&mut run, &local, &peer, collection).await;
    assert!(!run.done.is_finished());
    send_frame(
        &mut run.send,
        Frame::Value {
            key: record.fingerprint().raw(),
            bytes: encode_record(collection, record).unwrap(),
        },
    )
    .await;
    let (id, events) = run.landings.recv().await.unwrap();
    assert_eq!(id, 1);
    assert!(matches!(&events[..], [NetEvent::CollectionRecord(value)] if *value == record));
    run.send.shutdown().await.unwrap();
    tokio::task::yield_now().await;
    assert!(
        !run.done.is_finished(),
        "received bytes and peer FIN do not acknowledge local insertion"
    );
    run.acked.send((1, 0)).unwrap();
    assert_eq!(receive_or_fin(&mut run.recv).await, None);
    let (ended, duplicate) = run.done.await.unwrap();
    assert!(!duplicate);
    assert!(ended.landed && ended.confirmed && ended.agreed.is_some());
    assert_eq!(
        ended.agreed.unwrap().summary(),
        peer.pinned(collection).cache(WalkKind::Commit).summary()
    );
    assert_eq!(*run.reset.lock().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_equal_empty_roots_finish_without_cells_or_cache_preparation() {
    let mut local = Node::new(201);
    let mut peer = Node::new(202);
    let collection = local.hold("riblt-empty-early-fin", open());
    assert_eq!(peer.hold("riblt-empty-early-fin", open()), collection);
    let cache = local.pinned(collection).cache(WalkKind::Commit);
    // Peer FIN arrives before the local ROOT write completes. A zero-cell
    // receipt cannot stand in for the complete ROOT receipt.
    let mut exchange = receiver(&local, collection);
    exchange.next_delta();
    assert!(
        exchange
            .on_frame(root(&peer, collection), Some(local.snapshot()))
            .is_empty()
    );
    assert!(exchange.on_fin().is_empty());
    assert_eq!(exchange.next_delta(), None);
    assert!(exchange.on_written(0).is_empty());
    assert!(!exchange.ready_to_finish());
    assert_eq!(exchange.outcome(), None);
    assert!(exchange.on_root_written().is_empty());
    assert!(exchange.ready_to_finish());
    assert_eq!(exchange.outcome(), Some(Outcome::Confirmed));

    // Actual reader/driver/writer: deliver peer ROOT+FIN while the one-byte
    // outbound pipe still blocks this side's initial ROOT write.
    let mut run = driven_with_capacity(&local, &peer, collection, 1);
    send_frame(&mut run.send, root(&peer, collection)).await;
    run.send.shutdown().await.unwrap();
    tokio::task::yield_now().await;
    assert!(!run.done.is_finished(), "the outbound ROOT is still blocked");
    assert_eq!(receive_frame(&mut run.recv).await, root(&local, collection));
    assert_eq!(receive_or_fin(&mut run.recv).await, None);
    let (ended, duplicate) = run.done.await.unwrap();
    assert!(!duplicate && ended.landed && ended.confirmed);
    assert_eq!(ended.agreed.unwrap().summary(), cache.summary());
    assert_eq!(cache.prepared().unwrap(), 0);
    assert_eq!(
        peer.pinned(collection)
            .cache(WalkKind::Commit)
            .prepared()
            .unwrap(),
        0
    );
    assert!(run.landings.try_recv().is_err());
    assert_eq!(*run.reset.lock().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_driver_eof_or_stall_with_owed_body_never_confirms() {
    for eof in [true, false] {
        let (local, peer, collection, _) = pair();
        let mut run = driven(&local, &peer, collection);
        discover_without_body(&mut run, &local, &peer, collection).await;
        if eof {
            run.send.shutdown().await.unwrap();
        } else {
            tokio::time::advance(WALK_DEADLINE + Duration::from_secs(1)).await;
        }
        let (ended, duplicate) = run.done.await.unwrap();
        assert!(!duplicate);
        assert!(!ended.landed && !ended.confirmed && ended.agreed.is_none());
        assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
        assert!(run.landings.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_driver_eagerly_writes_each_local_only_body_once() {
    let (empty, full, collection, record) = pair();
    let mut run = driven(&full, &empty, collection);
    assert_eq!(receive_frame(&mut run.recv).await, root(&full, collection));
    send_frame(&mut run.send, root(&empty, collection)).await;
    send_frame(&mut run.send, cell(&empty, collection, 0)).await;
    run.send.shutdown().await.unwrap();
    let mut bodies = 0;
    let mut cells = 0;
    let mut fin = false;
    for _ in 0..32 {
        match receive_or_fin(&mut run.recv).await {
            Some(Frame::RibltCell { index, .. }) => {
                assert_eq!(index as usize, cells);
                cells += 1;
            }
            Some(Frame::Value { key, bytes }) => {
                assert_eq!(key, record.fingerprint().raw());
                assert_eq!(decode_record(collection, &bytes).unwrap(), record);
                bodies += 1;
            }
            None => {
                fin = true;
                break;
            }
            unexpected => panic!("unexpected eager transfer frame: {unexpected:?}"),
        }
    }
    assert_eq!(bodies, 1);
    assert!(fin);
    assert!((1..16).contains(&cells));
    let (ended, _) = run.done.await.unwrap();
    assert!(ended.landed && ended.confirmed && ended.agreed.is_some());
    assert!(
        run.landings.try_recv().is_err(),
        "the empty peer owed no body"
    );
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_peer_fin_cannot_hide_a_failed_insertion_ack() {
    let (local, peer, collection, record) = pair();
    let mut run = driven(&local, &peer, collection);
    discover_without_body(&mut run, &local, &peer, collection).await;
    send_frame(&mut run.send, Frame::Value {
        key: record.fingerprint().raw(),
        bytes: encode_record(collection, record).unwrap(),
    }).await;
    assert!(matches!(&run.landings.recv().await.unwrap().1[..],
        [NetEvent::CollectionRecord(value)] if *value == record));
    run.send.shutdown().await.unwrap();
    tokio::task::yield_now().await;
    assert!(!run.done.is_finished());
    run.acked.send((0, 1)).unwrap();
    let (ended, duplicate) = run.done.await.unwrap();
    // A processed peer FIN may independently confirm the sending direction;
    // it cannot establish local landing or a shared agreement after this ACK.
    assert!(!duplicate && !ended.landed && ended.agreed.is_none());
    assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_late_first_value_after_local_fin_reopens_insertion_debt() {
    for failed in [false, true] {
        let (mut local, peer, collection, record) = pair();
        let mut run = driven(&local, &peer, collection);
        let pinned_root = root(&local, collection);
        // The exchange pins an empty source, but remember() sees this newer
        // publication before the decoded remote-only key's eager VALUE arrives.
        assert_eq!(local.insert(vec![NetEvent::CollectionRecord(record)]), (1, 0));
        local.observe();
        run._snapshots.send(Some(local.snapshot())).unwrap();
        assert_eq!(receive_frame(&mut run.recv).await, pinned_root);
        send_frame(&mut run.send, root(&peer, collection)).await;
        send_frame(&mut run.send, cell(&peer, collection, 0)).await;
        let mut cells = 0;
        loop {
            match receive_or_fin(&mut run.recv).await {
                Some(Frame::RibltCell { index, .. }) => {
                    assert_eq!(index as usize, cells);
                    cells += 1;
                    assert!(cells < 16);
                }
                None => break,
                other => panic!("unexpected frame before local FIN: {other:?}"),
            }
        }
        assert!(cells > 0);
        assert!(!run.done.is_finished(), "local FIN does not wait for peer FIN");
        assert!(run.landings.try_recv().is_err(), "remember used resident evidence");

        send_frame(&mut run.send, Frame::Value {
            key: record.fingerprint().raw(),
            bytes: encode_record(collection, record).unwrap(),
        }).await;
        assert!(matches!(&run.landings.recv().await.unwrap().1[..],
            [NetEvent::CollectionRecord(value)] if *value == record));
        run.send.shutdown().await.unwrap();
        tokio::task::yield_now().await;
        assert!(!run.done.is_finished(), "peer FIN cannot latch the earlier readiness");
        run.acked.send(if failed { (0, 1) } else { (1, 0) }).unwrap();
        let (ended, duplicate) = run.done.await.unwrap();
        assert!(!duplicate);
        if failed {
            assert!(!ended.landed && ended.agreed.is_none());
            assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
        } else {
            assert!(ended.landed && ended.confirmed);
            assert_eq!(ended.agreed.unwrap().summary().leaf_count(), 1);
            assert_eq!(*run.reset.lock().unwrap(), None);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_local_fin_does_not_wait_for_peer_fin_and_replacement_still_resets() {
    for replace in [false, true] {
        let mut local = Node::new(203);
        let mut peer = Node::new(204);
        let collection = local.hold("riblt-half-close-ownership", open());
        assert_eq!(peer.hold("riblt-half-close-ownership", open()), collection);
        let mut run = driven(&local, &peer, collection);
        assert_eq!(receive_frame(&mut run.recv).await, root(&local, collection));
        send_frame(&mut run.send, root(&peer, collection)).await;
        assert_eq!(receive_or_fin(&mut run.recv).await, None,
            "equal roots permit local FIN while the peer's write half stays open");
        assert!(!run.done.is_finished());
        if replace {
            run._replace.send(()).unwrap();
        } else {
            run.send.shutdown().await.unwrap();
        }
        let (ended, duplicate) = run.done.await.unwrap();
        assert!(!duplicate);
        if replace {
            assert!(!ended.confirmed && ended.agreed.is_none());
            assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
        } else {
            assert!(ended.landed && ended.confirmed && ended.agreed.is_some());
            assert_eq!(*run.reset.lock().unwrap(), None);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_failed_or_blocked_finish_never_retains_agreement() {
    // Immediate shutdown error, a stalled shutdown deadline, and replacement
    // while shutdown is blocked are distinct from semantic eligibility.
    for mode in 0..3 {
        let mut local = Node::new(205);
        let mut peer = Node::new(206);
        let collection = local.hold("riblt-finish-failure", open());
        assert_eq!(peer.hold("riblt-finish-failure", open()), collection);
        let attempted = Arc::new(Mutex::new(false));
        let note = attempted.clone();
        let mut run = driven_with_writer(&local, &peer, collection, 128, |tx| {
            Box::new(FinishTx(tx, mode != 0, note))
        });
        assert_eq!(receive_frame(&mut run.recv).await, root(&local, collection));
        send_frame(&mut run.send, root(&peer, collection)).await;
        run.send.shutdown().await.unwrap();
        // Keep virtual time still until actual poll_shutdown is observed.
        for _ in 0..100 {
            if *attempted.lock().unwrap() { break; }
            tokio::task::yield_now().await;
        }
        assert!(*attempted.lock().unwrap());
        if mode != 0 {
            assert!(!run.done.is_finished());
            if mode == 1 {
                tokio::time::advance(WALK_DEADLINE + Duration::from_secs(1)).await;
            } else {
                run._replace.send(()).unwrap();
            }
        }
        let (ended, duplicate) = run.done.await.unwrap();
        assert!(!duplicate && !ended.landed && ended.agreed.is_none());
        assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
    }
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_truncated_value_is_not_clean_fin() {
    let (local, peer, collection, record) = pair();
    let mut run = driven(&local, &peer, collection);
    discover_without_body(&mut run, &local, &peer, collection).await;
    let (kind, bytes) = Frame::Value {
        key: record.fingerprint().raw(),
        bytes: encode_record(collection, record).unwrap(),
    }.encode();
    run.send.write_all(&[kind]).await.unwrap();
    run.send.write_all(&(bytes.len() as u32).to_be_bytes()).await.unwrap();
    run.send.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
    run.send.shutdown().await.unwrap();
    let (ended, duplicate) = run.done.await.unwrap();
    assert!(!duplicate && !ended.landed && !ended.confirmed && ended.agreed.is_none());
    assert!(run.landings.try_recv().is_err());
    assert_eq!(*run.reset.lock().unwrap(), Some(RESET_WALK_FAILED));
}

#[test]
fn riblt_runtime_peer_fin_leaves_more_than_one_reference_fetch_window_alive() {
    use triblespace_core::collection::HeldStore;

    let mut local = Node::new(207);
    let mut peer = Node::new(208);
    let collection = local.hold("riblt-reference-fin", open());
    assert_eq!(peer.hold("riblt-reference-fin", open()), collection);
    local.store.track_held([collection]);
    peer.store.track_held([collection]);
    let blobs: Vec<_> = (0u64..130).map(|index| {
        let blob = Blob::<UnknownBlob>::new(Bytes::from_source(index.to_be_bytes().to_vec()));
        let handle = blob.get_handle().raw;
        assert_eq!(peer.insert(vec![NetEvent::Blob(blob.clone()),
            NetEvent::Held { collection, handle }]), (2, 0));
        (handle, blob)
    }).collect();
    local.observe();
    peer.observe();
    let kind = WalkKind::References;
    let cache = peer.pinned(collection).cache(kind);
    let mut exchange = Exchange::start_riblt(collection, kind, local.pinned(collection));
    assert!(matches!(exchange.next_delta(), Some(Frame::RibltRoot { .. })));
    assert!(exchange.on_root_written().is_empty());
    assert!(exchange.on_frame(Frame::RibltRoot { summary: cache.summary() },
        Some(local.snapshot())).is_empty());
    let mut pending = VecDeque::new();
    for index in 0..8192 {
        assert!(matches!(exchange.next_delta(), Some(Frame::RibltCell { .. })));
        assert!(exchange.on_written(index + 1).is_empty());
        let item = cache.cell(index).unwrap();
        for out in exchange.on_frame(Frame::RibltCell {
            index: index as u32, symbol: item.symbol.0, hash: item.hash, count: item.count,
        }, Some(local.snapshot())) {
            match out {
                Out::Fetch(handle) => pending.push_back(handle),
                other => panic!("unexpected reference discovery work: {other:?}"),
            }
        }
        if exchange.discovery_stopped() { break; }
    }
    assert!(exchange.discovery_stopped());
    assert_eq!(pending.len(), 64, "remaining references have not entered the fetch window");
    assert!(exchange.on_fin().is_empty());
    assert_eq!(exchange.outcome(), None);
    assert!(!exchange.awaits(), "remaining work is local fetch/landing, not peer frames");
    assert!(!exchange.ready_to_finish());
    let mut fetched = Vec::new();
    while let Some(handle) = pending.pop_front() {
        fetched.push(handle);
        let blob = blobs.iter().find(|(key, _)| *key == handle).unwrap().1.clone();
        let mut landed = 0;
        for out in exchange.on_fetched(handle, Some(blob)) {
            match out {
                Out::Fetch(handle) => pending.push_back(handle),
                Out::Land(events) => {
                    assert!(matches!(&events[..], [NetEvent::Blob(_), NetEvent::Held { .. }]));
                    let (ok, failed) = local.insert(events);
                    assert_eq!((ok, failed), (2, 0));
                    landed += ok;
                }
                other => panic!("unexpected reference completion work: {other:?}"),
            }
        }
        assert_eq!(landed, 2);
        assert_eq!(exchange.outcome(), None, "the current fetched blob still owes its ACK");
        assert!(exchange.on_landed_ack(landed, 0).is_empty());
    }
    assert_eq!(fetched.len(), 130, "each remote-only blob is fetched once");
    fetched.sort_unstable();
    fetched.dedup();
    assert_eq!(fetched.len(), 130);
    assert!(exchange.ready_to_finish());
    assert_eq!(exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(exchange.end().agreed.unwrap().summary(), cache.summary());
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_one_way_walks_use_prefix_and_refuse_incoming_riblt() {
    let mut local = Node::new(141);
    let peer = Node::new(142);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(local.key.verifying_key()),
        AdmissionPolicy::Open,
    );
    let collection = local.hold("riblt-one-way-privacy", policy);
    local.commit(collection, 99);
    local.observe();
    local.walks.algorithm = Algorithm::CachedRiblt;
    let mut exchange = local
        .walks
        .start(peer.id(), collection, WalkKind::Commit)
        .unwrap();
    assert_eq!(exchange.algorithm(), Algorithm::Prefix);
    assert!(exchange.receives());
    assert_eq!(
        exchange.next_delta(),
        Some(Frame::Subtree {
            prefix: Vec::new(),
            summary: PatchSummary::new(None, 0).unwrap(),
        })
    );
    assert_eq!(exchange.next_delta(), Some(Frame::Done));

    let net = SimNet::new(0xC012, SimConfig::default());
    let harness = net.join(&local.key);
    let (_snapshots, observed) = watch::channel(Some(local.snapshot()));
    let (commands, _commanded) = mpsc::unbounded_channel();
    let (landing, _landings) = mpsc::unbounded_channel();
    let (events, _events) = mpsc::unbounded_channel();
    let mut task = Task {
        connections: ConnectionTable::new(harness.transport, NoRequests),
        snapshots: observed,
        walks: local.walks,
        commands: WalksHandle(commands),
        landing,
        events,
        grants: mpsc::unbounded_channel().0,
        grant_queue: GrantQueue::default(),
        unknown_joins: PATCH::new(),
        running: HashMap::new(),
        next_id: 0,
    };
    let (mut script, stream) = tokio::io::duplex(128);
    let (recv, send) = tokio::io::split(stream);
    let reset = Arc::new(Mutex::new(None));
    task.incoming(
        peer.id(),
        collection,
        WalkKind::Commit,
        Algorithm::CachedRiblt,
        None,
        Box::new(Tx(send, reset.clone())),
        Box::new(Rx(recv, reset.clone())),
    );
    assert!(task.running.is_empty());
    assert_eq!(task.next_id, 0);
    assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_REFUSED));
    let mut bytes = Vec::new();
    script.read_to_end(&mut bytes).await.unwrap();
    assert!(
        bytes.is_empty(),
        "no RIBLT root, cells or private bodies before refusal"
    );
}

#[test]
fn riblt_runtime_more_than_one_body_window_cannot_finish_at_an_empty_current_window() {
    let mut a = Node::new(161);
    let mut b = Node::new(162);
    let collection = a.hold("riblt-multiple-body-windows", open());
    assert_eq!(b.hold("riblt-multiple-body-windows", open()), collection);
    for number in 0..130 {
        a.commit(collection, number);
        b.commit(collection, number + 1000);
    }
    a.observe();
    b.observe();
    let mut left = receiver(&a, collection);
    let mut right = receiver(&b, collection);
    let a_root = left.next_delta().unwrap();
    let b_root = right.next_delta().unwrap();
    assert!(left.on_root_written().is_empty());
    assert!(right.on_root_written().is_empty());
    assert!(left.on_frame(b_root, Some(a.snapshot())).is_empty());
    assert!(right.on_frame(a_root, Some(b.snapshot())).is_empty());
    for prefix in 1..8192 {
        let a_cell = left.next_delta().expect("a cell before proof");
        let b_cell = right.next_delta().expect("a cell before proof");
        assert!(matches!(a_cell, Frame::RibltCell { .. }));
        assert!(matches!(b_cell, Frame::RibltCell { .. }));
        assert!(left.on_written(prefix).is_empty());
        assert!(right.on_written(prefix).is_empty());
        assert!(left.on_frame(b_cell, Some(a.snapshot())).is_empty());
        assert!(right.on_frame(a_cell, Some(b.snapshot())).is_empty());
        assert_eq!(left.discovery_stopped(), right.discovery_stopped());
        if left.discovery_stopped() {
            break;
        }
    }
    assert!(left.discovery_stopped() && right.discovery_stopped());
    assert_eq!(left.next_delta(), None);
    assert_eq!(right.next_delta(), None);
    assert!(!left.ready_to_finish() && !right.ready_to_finish());

    let mut a_bodies = Vec::new();
    let mut b_bodies = Vec::new();
    while let Some(body) = left.next_body() {
        a_bodies.push(body);
    }
    while let Some(body) = right.next_body() {
        b_bodies.push(body);
    }
    assert_eq!(a_bodies.len(), 130);
    assert_eq!(b_bodies.len(), 130);
    for bodies in [&a_bodies, &b_bodies] {
        let mut keys: Vec<_> = bodies
            .iter()
            .map(|body| match body {
                Frame::Value { key, .. } => *key,
                _ => panic!("only eager values are body work"),
            })
            .collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 130, "each local-only body is pushed once");
    }
    // All current 64-entry windows drain more than once; withhold the last body
    // in each direction until coded discovery stops and all other ACKs arrive.
    let a_last = a_bodies.pop().unwrap();
    let b_last = b_bodies.pop().unwrap();
    for (a_body, b_body) in a_bodies.into_iter().zip(b_bodies) {
        let a_outs = left.on_frame(b_body, Some(a.snapshot()));
        let b_outs = right.on_frame(a_body, Some(b.snapshot()));
        assert!(matches!(&a_outs[..], [Out::Land(events)] if events.len() == 1));
        assert!(matches!(&b_outs[..], [Out::Land(events)] if events.len() == 1));
        assert!(left.on_landed_ack(1, 0).is_empty());
        assert!(right.on_landed_ack(1, 0).is_empty());
        assert!(
            left.awaits() && right.awaits(),
            "later decoded body work remains owed"
        );
        assert_eq!(left.outcome(), None);
        assert_eq!(right.outcome(), None);
    }
    assert!(matches!(
        &left.on_frame(b_last, Some(a.snapshot()))[..],
        [Out::Land(_)]
    ));
    assert!(matches!(
        &right.on_frame(a_last, Some(b.snapshot()))[..],
        [Out::Land(_)]
    ));
    assert!(left.on_landed_ack(1, 0).is_empty());
    assert!(right.on_landed_ack(1, 0).is_empty());
    assert!(left.ready_to_finish() && right.ready_to_finish(),
        "both halves may finish without waiting for the other's FIN");
    assert_eq!(left.outcome(), None);
    assert_eq!(right.outcome(), None);
    left.on_fin();
    right.on_fin();
    assert_eq!(left.outcome(), Some(Outcome::Confirmed));
    assert_eq!(right.outcome(), Some(Outcome::Confirmed));
    let a_union = left.end().agreed.unwrap();
    let b_union = right.end().agreed.unwrap();
    assert_eq!(a_union.summary(), b_union.summary());
    assert_eq!(a_union.summary().leaf_count(), 260);
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_simultaneous_open_tie_break_preserves_winners_explicit_algorithm() {
    let low_first = Node::new(191).id() < Node::new(192).id();
    for local_is_lower in [true, false] {
        for incoming in [Algorithm::Prefix, Algorithm::CachedRiblt] {
            let byte = if local_is_lower == low_first {
                191
            } else {
                192
            };
            let other = if byte == 191 { 192 } else { 191 };
            let mut local = Node::new(byte);
            let peer = Node::new(other);
            assert_eq!(local.id() < peer.id(), local_is_lower);
            let collection = local.hold("riblt-mixed-profile-collision", open());
            local.walks.algorithm = match incoming {
                Algorithm::Prefix => Algorithm::CachedRiblt,
                Algorithm::CachedRiblt => Algorithm::Prefix,
            };
            assert_eq!(
                local
                    .walks
                    .start(peer.id(), collection, WalkKind::Commit)
                    .unwrap()
                    .algorithm(),
                local.walks.algorithm
            );
            let net = SimNet::new(0xC013, SimConfig::default());
            let harness = net.join(&local.key);
            let (_snapshots, observed) = watch::channel(Some(local.snapshot()));
            let (commands, mut commanded) = mpsc::unbounded_channel();
            let (landing, _landings) = mpsc::unbounded_channel();
            let (events, _events) = mpsc::unbounded_channel();
            let mut task = Task {
                connections: ConnectionTable::new(harness.transport, NoRequests),
                snapshots: observed,
                walks: local.walks,
                commands: WalksHandle(commands),
                landing,
                events,
                grants: mpsc::unbounded_channel().0,
                grant_queue: GrantQueue::default(),
                unknown_joins: PATCH::new(),
                running: HashMap::new(),
                next_id: 778,
            };
            let (old_acks, _old_acked) = mpsc::unbounded_channel();
            let (old_replace, mut old_replaced) = oneshot::channel();
            let exchange_key = (peer.id(), collection.raw, WalkKind::Commit);
            task.running.insert(
                exchange_key,
                Running {
                    id: 777,
                    opened: true,
                    acks: old_acks,
                    _replace: old_replace,
                },
            );
            let (script, stream) = tokio::io::duplex(128);
            let (recv, send) = tokio::io::split(stream);
            let (mut read, _write) = tokio::io::split(script);
            let reset = Arc::new(Mutex::new(None));
            task.incoming(
                peer.id(),
                collection,
                WalkKind::Commit,
                incoming,
                None,
                Box::new(Tx(send, reset.clone())),
                Box::new(Rx(recv, reset.clone())),
            );
            if local_is_lower {
                assert_eq!(task.running[&exchange_key].id, 777);
                assert!(task.running[&exchange_key].opened);
                assert!(matches!(
                    old_replaced.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ));
                assert_eq!(*reset.lock().unwrap(), Some(RESET_WALK_DUPLICATE));
                let mut bytes = Vec::new();
                read.read_to_end(&mut bytes).await.unwrap();
                assert!(bytes.is_empty(), "losing incoming profile writes no root");
            } else {
                assert!(
                    old_replaced.await.is_err(),
                    "losing local driver is cancelled"
                );
                assert!(!task.running[&exchange_key].opened);
                assert_ne!(task.running[&exchange_key].id, 777);
                let first = receive_frame(&mut read).await;
                assert!(
                    match incoming {
                        Algorithm::Prefix => matches!(first, Frame::Subtree { .. }),
                        Algorithm::CachedRiblt => matches!(first, Frame::RibltRoot { .. }),
                    },
                    "incoming winner owns the algorithm despite opposite local preference"
                );
                task.running.remove(&exchange_key);
                assert!(matches!(
                    commanded.recv().await,
                    Some(Command::Ended { .. })
                ));
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_task_retains_prefix_agreement_but_releases_cached_source_pin() {
    for selected in [Algorithm::Prefix, Algorithm::CachedRiblt] {
        let mut local = Node::new(211);
        let peer = Node::new(212).id();
        let collection = local.hold("riblt-no-retained-peer-source", open());
        local.commit(collection, 1);
        local.observe();
        let kind = WalkKind::Commit;
        let snapshot = local.snapshot();
        let source = Arc::new(Tree::pinned(kind, local.pinned(collection).repair()));
        let source_summary = source.summary();
        assert_eq!(source_summary.leaf_count(), 1);
        let previous = Arc::downgrade(&source);
        let agreement_key = agreed_key(peer, collection.raw, kind);
        // Seed a prior Prefix G. Explicit incoming selection must determine
        // retention even when the local opener preference is the opposite.
        local
            .walks
            .agreed
            .replace(&Entry::with_value(&agreement_key, source));
        local.walks.algorithm = match selected {
            Algorithm::Prefix => Algorithm::CachedRiblt,
            Algorithm::CachedRiblt => Algorithm::Prefix,
        };
        let health = local.health.clone();
        let net = SimNet::new(0xC014, SimConfig::default());
        let harness = net.join(&local.key);
        let (_snapshots, observed) = watch::channel(Some(snapshot.clone()));
        let (commands, _commanded) = mpsc::unbounded_channel();
        let (landing, _landings) = mpsc::unbounded_channel();
        let (events, _events) = mpsc::unbounded_channel();
        let mut task = Task {
            connections: ConnectionTable::new(harness.transport, NoRequests),
            snapshots: observed,
            walks: local.walks,
            commands: WalksHandle(commands),
            landing,
            events,
            grants: mpsc::unbounded_channel().0,
            grant_queue: GrantQueue::default(),
            unknown_joins: PATCH::new(),
            running: HashMap::new(),
            next_id: 1,
        };
        let mut exchange = task
            .walks
            .start_selected(peer, collection, kind, Some(selected))
            .unwrap();
        assert_eq!(exchange.algorithm(), selected);
        let key = (peer, collection.raw, kind);
        let (driver, _acked, _replaced) = task.register(key, false, &exchange);
        let root = exchange.next_delta().unwrap();
        match &root {
            Frame::Subtree { summary, .. } => {
                assert_eq!(selected, Algorithm::Prefix);
                assert_eq!(summary.leaf_count(), 0, "Prefix subtracts prior G");
            }
            Frame::RibltRoot { summary, .. } => {
                assert_eq!(selected, Algorithm::CachedRiblt);
                assert_eq!(*summary, source_summary, "Cached ignores prior G");
            }
            _ => panic!("expected the explicitly selected root"),
        }
        assert!(exchange.on_frame(root, Some(snapshot.clone())).is_empty());
        match selected {
            Algorithm::Prefix => {
                assert_eq!(exchange.next_delta(), Some(Frame::Done));
                exchange.on_written(0);
                assert!(matches!(
                    &exchange.on_frame(Frame::Done, Some(snapshot.clone()))[..],
                    [Out::Send(Frame::Landed)]
                ));
                exchange.on_frame(Frame::Landed, Some(snapshot));
            }
            Algorithm::CachedRiblt => {
                assert_eq!(exchange.next_delta(), None);
                assert!(exchange.on_root_written().is_empty());
                assert!(exchange.ready_to_finish());
                exchange.on_fin();
            }
        }
        assert_eq!(exchange.outcome(), Some(Outcome::Confirmed));
        let ended = exchange.end();
        assert_eq!(ended.retain_agreement, selected == Algorithm::Prefix);
        let completed = Arc::downgrade(ended.agreed.as_ref().unwrap());
        assert_eq!(ended.agreed.as_ref().unwrap().summary(), source_summary);
        task.command(Command::Ended {
            id: driver.id,
            peer,
            collection,
            kind,
            duplicate: false,
            ended,
        });
        assert!(task.running.is_empty());
        assert!(
            previous.upgrade().is_none(),
            "the old Prefix Arc is released"
        );
        assert_eq!(
            task.walks.agreed.get(&agreement_key).is_some(),
            selected == Algorithm::Prefix
        );
        assert_eq!(
            completed.upgrade().is_some(),
            selected == Algorithm::Prefix,
            "Cached completion retains no per-peer source Arc"
        );
        let health = health.snapshot();
        let pair = health
            .collections
            .iter()
            .find(|item| item.collection == collection)
            .unwrap()
            .peers
            .iter()
            .find(|item| item.peer == peer)
            .unwrap();
        assert!(pair.pushes.last_ok && pair.receives.last_ok);
        assert_eq!(pair.confirmed.commits, Some(source_summary));
        assert_eq!(pair.received.commits, Some(source_summary));
    }
}

/// Anonymous and file-backed resident memory, from /proc/self/status.
fn rss_kib() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap_or(0)
    };
    (field("RssAnon:"), field("RssFile:") + field("RssShmem:"))
}

/// The 2026-10-27 incident shape, beyond every retired budget: 1,500,000
/// differing held references need about two million cells (MAX_CELLS was
/// 1,048,576) and recover 1,200,000 keys of one sign (MAX_SUPPORT and
/// FLOOD_LOCATORS were 1,048,576 each). Both production exchanges run in
/// lockstep, every fetch is answered with the real blob and every landing is
/// acknowledged at once; both must confirm the same union.
///
/// Too slow and large for the default suite. Run it explicitly:
/// `cargo test --release -p triblespace-net riblt_runtime_reference_difference_beyond_retired_budgets -- --ignored --nocapture`
#[test]
#[ignore = "1.5M-key difference; run explicitly in release"]
fn riblt_runtime_reference_difference_beyond_retired_budgets_converges() {
    const SHARED: u64 = 100_000;
    const LOCAL_ONLY: u64 = 300_000;
    const PEER_ONLY: u64 = 1_200_000;
    const RETIRED: usize = 1 << 20;
    let started = std::time::Instant::now();
    let mut local = Node::new(223);
    let mut peer = Node::new(224);
    let collection = local.hold("riblt-unbounded-references", open());
    assert_eq!(peer.hold("riblt-unbounded-references", open()), collection);
    local.observe();
    peer.observe();
    let blob = |n: u64| Blob::<UnknownBlob>::new(Bytes::from_source(n.to_be_bytes().to_vec()));
    let mut handles: Vec<([u8; 32], u64)> = (0..SHARED + LOCAL_ONLY + PEER_ONLY)
        .map(|n| (blob(n).get_handle().raw, n))
        .collect();
    let held = |numbers: &mut dyn Iterator<Item = u64>| {
        let mut patch = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
        for n in numbers {
            patch.insert(&Entry::new(&handles[n as usize].0));
        }
        patch
    };
    let all = held(&mut (0..SHARED + LOCAL_ONLY + PEER_ONLY));
    let a_pin = local
        .pinned(collection)
        .with_inventory(held(&mut (0..SHARED + LOCAL_ONLY)));
    let b_pin = peer.pinned(collection).with_inventory(held(
        &mut (0..SHARED).chain(SHARED + LOCAL_ONLY..SHARED + LOCAL_ONLY + PEER_ONLY),
    ));
    handles.sort_unstable();
    let body = |handle: [u8; 32]| {
        let at = handles
            .binary_search_by_key(&handle, |(key, _)| *key)
            .unwrap();
        blob(handles[at].1)
    };
    let (a_snapshot, b_snapshot) = (local.snapshot(), peer.snapshot());
    let kind = WalkKind::References;
    let mut a = Exchange::start_riblt(collection, kind, a_pin.clone());
    let mut b = Exchange::start_riblt(collection, kind, b_pin.clone());
    let fixture = started.elapsed();
    let baseline = rss_kib();
    let started = std::time::Instant::now();

    let mut a_fetches = VecDeque::new();
    let mut b_fetches = VecDeque::new();
    let collect = |outs: Vec<Out>, fetches: &mut VecDeque<[u8; 32]>| {
        for out in outs {
            match out {
                Out::Fetch(handle) => fetches.push_back(handle),
                other => panic!("unexpected discovery work: {other:?}"),
            }
        }
    };
    let (mut a_sent, mut b_sent) = (0, 0);
    loop {
        let mut moved = false;
        if let Some(frame) = a.next_delta() {
            if matches!(frame, Frame::RibltCell { .. }) {
                a_sent += 1;
                assert!(a.on_written(a_sent).is_empty());
            } else {
                assert!(a.on_root_written().is_empty());
            }
            collect(b.on_frame(frame, Some(b_snapshot.clone())), &mut b_fetches);
            moved = true;
        }
        if let Some(frame) = b.next_delta() {
            if matches!(frame, Frame::RibltCell { .. }) {
                b_sent += 1;
                assert!(b.on_written(b_sent).is_empty());
            } else {
                assert!(b.on_root_written().is_empty());
            }
            collect(a.on_frame(frame, Some(a_snapshot.clone())), &mut a_fetches);
            moved = true;
        }
        assert_eq!(a.outcome(), None, "after {a_sent} cells");
        assert_eq!(b.outcome(), None, "after {b_sent} cells");
        if !moved {
            break;
        }
    }
    assert!(a.discovery_stopped() && b.discovery_stopped());
    assert!(
        a_sent > RETIRED && b_sent > RETIRED,
        "{a_sent}/{b_sent} cells"
    );
    let discovery = started.elapsed();
    let peak = rss_kib();
    let a_prepared = a_pin.cache(kind).prepared().unwrap();
    let a_file = a_pin.cache(kind).retained_bytes().unwrap();

    // Fetch, land and acknowledge until both sides can finish; each FIN
    // reaches the other side once.
    let (mut a_fin, mut b_fin) = (false, false);
    let (mut a_fetched, mut b_fetched) = (0u64, 0u64);
    loop {
        let mut moved = false;
        for (exchange, fetches, fetched) in [
            (&mut a, &mut a_fetches, &mut a_fetched),
            (&mut b, &mut b_fetches, &mut b_fetched),
        ] {
            while let Some(handle) = fetches.pop_front() {
                moved = true;
                *fetched += 1;
                let mut outs = VecDeque::from(exchange.on_fetched(handle, Some(body(handle))));
                while let Some(out) = outs.pop_front() {
                    match out {
                        Out::Fetch(handle) => fetches.push_back(handle),
                        Out::Land(events) => {
                            assert!(matches!(
                                &events[..],
                                [NetEvent::Blob(_), NetEvent::Held { .. }]
                            ));
                            outs.extend(exchange.on_landed_ack(events.len() as u64, 0));
                        }
                        other => panic!("unexpected completion work: {other:?}"),
                    }
                }
            }
        }
        if a.ready_to_finish() && !a_fin {
            a_fin = true;
            moved = true;
            collect(b.on_fin(), &mut b_fetches);
        }
        if b.ready_to_finish() && !b_fin {
            b_fin = true;
            moved = true;
            collect(a.on_fin(), &mut a_fetches);
        }
        if !moved {
            break;
        }
    }
    assert_eq!(a.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.outcome(), Some(Outcome::Confirmed));
    assert_eq!((a_fetched, b_fetched), (PEER_ONLY, LOCAL_ONLY));
    let (a_end, b_end) = (a.end(), b.end());
    let union = crate::exchange::Tree::References(all).summary();
    let a_agreed = a_end.agreed.unwrap().summary();
    assert_eq!(a_agreed, b_end.agreed.unwrap().summary());
    assert_eq!(a_agreed, union);
    assert_eq!(union.leaf_count(), SHARED + LOCAL_ONLY + PEER_ONLY);
    eprintln!(
        "RIBLT_UNBOUNDED_RECEIPT sample=1 shared={SHARED} local_only={LOCAL_ONLY} peer_only={PEER_ONLY} cells_a_sent={a_sent} cells_b_sent={b_sent} a_cache_prepared={a_prepared} a_cache_file_bytes={a_file} fixture_ms={} discovery_ms={} total_exchange_ms={} rss_anon_kib_baseline={} rss_file_kib_baseline={} rss_anon_kib_after_discovery={} rss_file_kib_after_discovery={}",
        fixture.as_millis(),
        discovery.as_millis(),
        started.elapsed().as_millis(),
        baseline.0,
        baseline.1,
        peak.0,
        peak.1,
    );
}
