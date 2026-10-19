//! Cached-only completion: local readiness permits a write half-close without
//! waiting for peer FIN. The reader and local landing/fetch work remain alive.
//! Prefix deliberately keeps its independent DONE/LANDED/request semantics.

use super::*;

pub(super) async fn drive<T: Transport, S: Service>(
    driver: &Driver<T, S>,
    mut exchange: Exchange,
    mut send: Box<dyn SendStream>,
    recv: Box<dyn RecvStream>,
    mut acked: mpsc::UnboundedReceiver<(u64, u64)>,
    mut replaced: oneshot::Receiver<()>,
) -> (Ended, bool) {
    let (frames, mut framed) = mpsc::channel(1);
    let reader = tokio::spawn(read(recv, frames));
    let (outgoing, queued) = mpsc::channel(1);
    let mut outgoing = Some(outgoing);
    let (reset, resetting) = oneshot::channel();
    let (release, released) = oneshot::channel::<()>();
    let (write_failed, mut writer_failed) = oneshot::channel();
    let (finish_note, mut finished) = oneshot::channel();
    let (progress, mut progressed) = watch::channel(Written::default());
    let writer = tokio::spawn(async move {
        let mut resetting = futures::FutureExt::fuse(resetting);
        let (_, finished) = write_stream_inner(
            &mut send, queued, &mut resetting, write_failed, Some(progress),
        ).await;
        let _ = finish_note.send(finished);
        if finished {
            // Half-close is not task retirement. Keep reset ownership until
            // the peer finishes too, or replacement/failure retires this walk.
            tokio::select! {
                biased;
                Ok(code) = &mut resetting => send.reset(code),
                _ = released => {}
            }
        }
    });
    let (fetches, mut fetched) = mpsc::unbounded_channel::<Fetched>();
    let mut outbox = VecDeque::new();
    let mut pending = exchange.next_delta(); // ROOT always precedes other work.
    let mut deferred_delta = None;
    let mut heard_at = tokio::time::Instant::now();
    let mut peer_fin = false;
    let mut local_finished = false;
    let mut finish_seen = false;
    let mut progress_open = true;
    let mut failure_open = true;
    let mut duplicate = false;
    let failed = 'drive: loop {
        if let Some(Outcome::Failed(failure)) = exchange.outcome() {
            debug!(?failure, "cached walk/1 exchange failed");
            break true;
        }
        if local_finished && peer_fin && exchange.outcome() == Some(Outcome::Confirmed) {
            break false;
        }
        if exchange.discovery_stopped() {
            if matches!(pending, Some(Frame::RibltCell { .. })) {
                pending = None;
            }
            deferred_delta = None;
        }
        if outgoing.is_some() {
            if matches!(pending, Some(Frame::RibltCell { .. })) {
                if let Some(body) = outbox.pop_front().or_else(|| exchange.next_body()) {
                    deferred_delta = pending.replace(body);
                }
            }
            if pending.is_none() {
                pending = outbox.pop_front()
                    .or_else(|| exchange.next_body())
                    .or_else(|| deferred_delta.take())
                    .or_else(|| exchange.next_delta());
            }
            // No peer-FIN dependency. Closing the sender makes the writer
            // drain its FIFO (including any active body) before shutdown.
            if exchange.ready_to_finish() && pending.is_none() && outbox.is_empty() {
                drop(outgoing.take());
            }
        }
        if matches!(exchange.outcome(), Some(Outcome::Failed(_))) {
            continue;
        }
        let deadline = exchange.awaits().then(|| heard_at + WALK_DEADLINE);
        let outs = tokio::select! {
            permit = async { outgoing.as_ref().unwrap().reserve().await },
                if outgoing.is_some() && pending.is_some() => match permit {
                    Ok(permit) => {
                        permit.send(pending.take().expect("pending frame"));
                        Vec::new()
                    }
                    Err(_) => break 'drive true,
                },
            frame = next(&mut framed, deadline), if !peer_fin && exchange.want_read() => match frame {
                Some(Ok(Some(frame))) => {
                    heard_at = tokio::time::Instant::now();
                    exchange.on_frame(frame, driver.snapshots.borrow().clone())
                }
                Some(Ok(None)) => {
                    peer_fin = true;
                    exchange.on_fin()
                }
                Some(Err(code)) => {
                    duplicate = code == Some(RESET_WALK_DUPLICATE);
                    break 'drive true;
                }
                None => break 'drive true,
            },
            Some((landed, failed)) = acked.recv() => exchange.on_landed_ack(landed, failed),
            Some((handle, blob)) = fetched.recv() => exchange.on_fetched(handle, blob),
            changed = progressed.changed(), if progress_open => {
                if changed.is_err() {
                    // Normal writer completion closes this channel too.
                    progress_open = false;
                    Vec::new()
                } else {
                    let written = *progressed.borrow_and_update();
                    let mut outs = exchange.on_written(written.cells);
                    if written.root { outs.extend(exchange.on_root_written()); }
                    outs
                }
            },
            failure = &mut writer_failed, if failure_open => {
                failure_open = false;
                if failure.is_ok() { break 'drive true; }
                Vec::new() // Sender drop is not an I/O failure receipt.
            },
            result = &mut finished, if !finish_seen => {
                finish_seen = true;
                local_finished = matches!(result, Ok(true));
                if !local_finished { break 'drive true; }
                Vec::new()
            },
            _ = &mut replaced => break 'drive true,
        };
        for out in outs {
            match out {
                Out::Send(frame) => {
                    if outgoing.is_none() { break 'drive true; }
                    outbox.push_back(frame);
                }
                Out::Land(events) => {
                    let _ = driver.landing.send((driver.id, events));
                }
                Out::Fetch(handle) => {
                    let connections = driver.connections.clone();
                    let fetches = fetches.clone();
                    let peer = driver.peer;
                    tokio::spawn(async move {
                        let blob = fetch_blob(connections, peer, handle).await;
                        let _ = fetches.send((handle, blob));
                    });
                }
            }
        }
    };
    reader.abort();
    if failed {
        let _ = reset.send(RESET_WALK_FAILED);
    }
    drop(outgoing);
    drop(release);
    let writer_retired = writer.await.is_ok();
    let mut ended = exchange.end();
    ended.landed &= local_finished;
    if failed || !writer_retired || !local_finished || !peer_fin {
        ended.agreed = None;
    }
    (ended, duplicate)
}

type Incoming = Result<Option<Frame>, Option<u32>>;

async fn next(
    frames: &mut mpsc::Receiver<Incoming>,
    deadline: Option<tokio::time::Instant>,
) -> Option<Incoming> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, frames.recv())
            .await.unwrap_or(Some(Err(None))),
        None => frames.recv().await,
    }
}

/// Only framing-level clean EOF becomes FIN. Truncation, reset and malformed
/// known frames remain failures, in FIFO order after all preceding frames.
async fn read(mut recv: Box<dyn RecvStream>, frames: mpsc::Sender<Incoming>) {
    loop {
        let frame = match read_frame(&mut recv).await {
            Ok(Some((kind, payload))) => match Frame::decode(kind, &payload) {
                Ok(Some(frame)) => Ok(Some(frame)),
                Ok(None) => continue,
                Err(_) => Err(None),
            },
            Ok(None) => Ok(None),
            Err(error) => Err(match error {
                FrameError::Transport(error) => reset_code(&error),
                FrameError::Violation(_) | FrameError::Stalled => None,
            }),
        };
        let ended = !matches!(frame, Ok(Some(_)));
        if frames.send(frame).await.is_err() || ended { return; }
    }
}
