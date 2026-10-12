//! Independent regressions through the production codec, writer and driver.
//! The scripted peer deliberately separates discovery, bodies and landing ACKs.

use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, DuplexStream, ReadHalf, WriteHalf};
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

use crate::exchange::Failure;
use crate::riblt_cache::{CacheError, MAX_CELLS};
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
    let generation = node.pinned(collection).cache(WalkKind::Records);
    Frame::RibltRoot {
        key: generation.key(),
        summary: generation.summary(),
    }
}

fn cell(node: &Node, collection: CollectionHandle, index: usize) -> Frame {
    let cell = node
        .pinned(collection)
        .cache(WalkKind::Records)
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
    Exchange::start_riblt(collection, WalkKind::Records, node.pinned(collection))
}

#[test]
fn riblt_runtime_rejects_profile_count_index_and_premature_done_before_landing() {
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
    let Frame::RibltRoot { mut key, summary } = root(&peer, collection) else {
        unreachable!()
    };
    key[0] ^= 1;
    assert!(
        exchange
            .on_frame(Frame::RibltRoot { key, summary }, Some(local.snapshot()))
            .is_empty()
    );
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
        WalkKind::Records,
        WalkKind::Authorization,
        WalkKind::References,
    ] {
        let cache = local.pinned(collection).cache(kind);
        for count in [MAX_CELLS as u64 + 1, i64::MAX as u64] {
            let summary = PatchSummary::new(Some([0x44; 32]), count).unwrap();
            let mut exchange = Exchange::start_riblt(collection, kind, local.pinned(collection));
            assert!(
                exchange
                    .on_frame(
                        Frame::RibltRoot {
                            key: cache.key(),
                            summary
                        },
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
                key: cache.key(),
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
fn riblt_runtime_large_source_still_bounds_actual_residual_difference() {
    let (local, _, collection, _) = pair();
    let cache = local.pinned(collection).cache(WalkKind::Records);
    let advertised = MAX_CELLS as u64 + 100;
    for (count, failure) in [
        (MAX_CELLS as i64 + 1, Failure::ResourceLimit),
        (advertised as i64 + 1, Failure::Protocol),
        (-1, Failure::Protocol),
    ] {
        let mut exchange = receiver(&local, collection);
        exchange.on_frame(
            Frame::RibltRoot {
                key: cache.key(),
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
        assert_eq!(exchange.outcome(), Some(Outcome::Failed(failure)));
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
            .cache(WalkKind::Records)
            .summary()
            .leaf_count(),
        2
    );
    assert_eq!(
        peer.pinned(collection)
            .cache(WalkKind::Records)
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
        WalkKind::Records,
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
                .cache(WalkKind::Records)
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
    assert_eq!(
        Failure::from(CacheError::Poisoned),
        Failure::CacheUnavailable
    );
    assert_eq!(
        Failure::from(CacheError::CountOverflow),
        Failure::CacheUnavailable
    );
    assert_eq!(
        Failure::from(crate::riblt_decode::DecodeError::Limit),
        Failure::ResourceLimit
    );
}

#[test]
fn riblt_runtime_stop_requires_written_matching_prefix_but_not_bodies() {
    let (local, peer, collection, _) = pair();
    let mut exchange = receiver(&local, collection);
    assert_eq!(exchange.next_delta(), Some(root(&local, collection)));
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
    assert_eq!(exchange.next_delta(), Some(Frame::Done));
    assert!(
        exchange
            .on_frame(Frame::Done, Some(local.snapshot()))
            .is_empty()
    );
    assert!(
        exchange.awaits(),
        "a body remains owed after discovery Done"
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
        kind: WalkKind::Records,
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
    let (progress, mut receipts) = watch::channel(0usize);
    let writer = tokio::spawn(write_stream_progress(
        Box::new(Tx(send, reset_note.clone())),
        queued,
        resetting,
        failed,
        Some(progress),
    ));
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
    assert_eq!(*receipts.borrow(), 0);
    let mut tail = [0; 2];
    recv.read_exact(&mut tail).await.unwrap();
    receipts.changed().await.unwrap();
    assert_eq!(*receipts.borrow_and_update(), 1);
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
    assert_eq!(*receipts.borrow(), 1);
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
    _snapshots: watch::Sender<Option<Arc<StoreSnapshot>>>,
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
    let net = SimNet::new(0xC011, SimConfig::default());
    let harness = net.join(&local.key);
    let (snapshots, observed) = watch::channel(Some(local.snapshot()));
    let (landing, landings) = mpsc::unbounded_channel();
    let (commands, _commanded) = mpsc::unbounded_channel();
    let driver = Driver {
        connections: ConnectionTable::new(harness.transport, NoRequests),
        snapshots: observed,
        landing,
        commands,
        id: 1,
        peer: peer.id(),
        collection,
        kind: WalkKind::Records,
    };
    let (script, stream) = tokio::io::duplex(capacity);
    let (recv, send) = tokio::io::split(stream);
    let reset = Arc::new(Mutex::new(None));
    let tx = Tx(send, reset.clone());
    let rx = Rx(recv, reset.clone());
    let exchange = receiver(local, collection);
    let (acked, acks) = mpsc::unbounded_channel();
    let (replace, replaced) = oneshot::channel();
    let done = tokio::spawn(async move {
        drive(
            &driver,
            exchange,
            Box::new(tx),
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
    let (kind, bytes) = read_frame(recv)
        .await
        .unwrap()
        .expect("expected a complete frame");
    Frame::decode(kind, &bytes).unwrap().unwrap()
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
    send_frame(&mut run.send, Frame::Done).await;
    let mut cells = 0;
    for _ in 0..32 {
        match receive_frame(&mut run.recv).await {
            Frame::RibltCell { index, .. } => {
                assert_eq!(index as usize, cells);
                cells += 1;
            }
            Frame::Done => {
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
    let cache = local.pinned(collection).cache(WalkKind::Records);
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
    send_frame(&mut run.send, Frame::Landed).await;
    tokio::task::yield_now().await;
    assert!(
        !run.done.is_finished(),
        "received bytes and peer LANDED do not acknowledge local insertion"
    );
    run.acked.send((1, 0)).unwrap();
    assert_eq!(receive_frame(&mut run.recv).await, Frame::Landed);
    let (ended, duplicate) = run.done.await.unwrap();
    assert!(!duplicate);
    assert!(ended.landed && ended.confirmed && ended.agreed.is_some());
    assert_eq!(
        ended.agreed.unwrap().summary(),
        peer.pinned(collection).cache(WalkKind::Records).summary()
    );
    assert_eq!(*run.reset.lock().unwrap(), None);
}

#[tokio::test(start_paused = true)]
async fn riblt_runtime_equal_empty_roots_finish_without_cells_or_cache_preparation() {
    let mut local = Node::new(201);
    let mut peer = Node::new(202);
    let collection = local.hold("riblt-empty-early-done", open());
    assert_eq!(peer.hold("riblt-empty-early-done", open()), collection);
    let cache = local.pinned(collection).cache(WalkKind::Records);
    // Pin the exact edge independently of scheduler order: peer DONE before our
    // DONE was generated. Its completed write must wake settling even at prefix0.
    let mut exchange = receiver(&local, collection);
    exchange.next_delta();
    assert!(
        exchange
            .on_frame(root(&peer, collection), Some(local.snapshot()))
            .is_empty()
    );
    assert!(
        exchange
            .on_frame(Frame::Done, Some(local.snapshot()))
            .is_empty()
    );
    assert_eq!(exchange.next_delta(), Some(Frame::Done));
    assert!(matches!(
        &exchange.on_written(0)[..],
        [Out::Send(Frame::Landed)]
    ));

    // Actual reader/driver/writer: deliver peer ROOT+DONE while the one-byte
    // outbound pipe still blocks this side's initial ROOT write.
    let mut run = driven_with_capacity(&local, &peer, collection, 1);
    send_frame(&mut run.send, root(&peer, collection)).await;
    send_frame(&mut run.send, Frame::Done).await;
    assert_eq!(receive_frame(&mut run.recv).await, root(&local, collection));
    assert_eq!(receive_frame(&mut run.recv).await, Frame::Done);
    assert_eq!(receive_frame(&mut run.recv).await, Frame::Landed);
    send_frame(&mut run.send, Frame::Landed).await;
    let (ended, duplicate) = run.done.await.unwrap();
    assert!(!duplicate && ended.landed && ended.confirmed);
    assert_eq!(ended.agreed.unwrap().summary(), cache.summary());
    assert_eq!(cache.prepared().unwrap(), 0);
    assert_eq!(
        peer.pinned(collection)
            .cache(WalkKind::Records)
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
    send_frame(&mut run.send, Frame::Done).await;
    let mut bodies = 0;
    let mut cells = 0;
    let mut done = false;
    let mut landed = false;
    for _ in 0..32 {
        match receive_frame(&mut run.recv).await {
            Frame::RibltCell { index, .. } => {
                assert_eq!(index as usize, cells);
                cells += 1;
            }
            Frame::Value { key, bytes } => {
                assert_eq!(key, record.fingerprint().raw());
                assert_eq!(decode_record(collection, &bytes).unwrap(), record);
                bodies += 1;
            }
            Frame::Done => {
                done = true;
                send_frame(&mut run.send, Frame::Landed).await;
            }
            Frame::Landed => {
                landed = true;
                break;
            }
            unexpected => panic!("unexpected eager transfer frame: {unexpected:?}"),
        }
    }
    assert_eq!(bodies, 1);
    assert!(done && landed);
    assert!((1..16).contains(&cells));
    let (ended, _) = run.done.await.unwrap();
    assert!(ended.landed && ended.confirmed && ended.agreed.is_some());
    assert!(
        run.landings.try_recv().is_err(),
        "the empty peer owed no body"
    );
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
        .start(peer.id(), collection, WalkKind::Records)
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
        running: HashMap::new(),
        next_id: 0,
    };
    let (mut script, stream) = tokio::io::duplex(128);
    let (recv, send) = tokio::io::split(stream);
    let reset = Arc::new(Mutex::new(None));
    task.incoming(
        peer.id(),
        collection,
        WalkKind::Records,
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
    assert_eq!(left.next_delta(), Some(Frame::Done));
    assert_eq!(right.next_delta(), Some(Frame::Done));
    assert!(left.on_frame(Frame::Done, Some(a.snapshot())).is_empty());
    assert!(right.on_frame(Frame::Done, Some(b.snapshot())).is_empty());

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
    // in each direction until after both coded DONEs and all other landing ACKs.
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
    assert!(matches!(
        &left.on_landed_ack(1, 0)[..],
        [Out::Send(Frame::Landed)]
    ));
    assert!(matches!(
        &right.on_landed_ack(1, 0)[..],
        [Out::Send(Frame::Landed)]
    ));
    left.on_frame(Frame::Landed, Some(a.snapshot()));
    right.on_frame(Frame::Landed, Some(b.snapshot()));
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
                    .start(peer.id(), collection, WalkKind::Records)
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
                running: HashMap::new(),
                next_id: 778,
            };
            let (old_acks, _old_acked) = mpsc::unbounded_channel();
            let (old_replace, mut old_replaced) = oneshot::channel();
            let exchange_key = (peer.id(), collection.raw, WalkKind::Records);
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
                WalkKind::Records,
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
        let kind = WalkKind::Records;
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
        assert_eq!(exchange.next_delta(), Some(Frame::Done));
        exchange.on_written(0);
        assert!(matches!(
            &exchange.on_frame(Frame::Done, Some(snapshot.clone()))[..],
            [Out::Send(Frame::Landed)]
        ));
        exchange.on_frame(Frame::Landed, Some(snapshot));
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
        assert_eq!(pair.confirmed.records, Some(source_summary));
        assert_eq!(pair.received.records, Some(source_summary));
    }
}
