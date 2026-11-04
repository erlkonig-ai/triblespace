use super::*;
use crate::blob::encodings::UnknownBlob;
use crate::blob::{BlobEncoding, TryFromBlob};
use crate::inline::Inline;
use crate::repo::async_store::AsyncBlobStoreGet;
use crate::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use crate::repo::{BlobStorePut, MissingBlob, SnapshotSource};
use anybytes::Bytes;
use futures::channel::oneshot;
use futures::future::BoxFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// One test's observation and pending exact read; no retained catalogue.
#[derive(Clone)]
struct WaitingSnapshot {
    source: MemoryRepoSnapshot,
    ready: Shared<BoxFuture<'static, ()>>,
    started: mpsc::Sender<()>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

struct PendingOwner(Arc<AtomicUsize>);
impl Drop for PendingOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncBlobStoreGet for WaitingSnapshot {
    type GetError<E: Error + Send + Sync + 'static> = ReadFailure;

    fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> impl Future<Output = Result<T, ReadFailure>> + Send
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        let raw = handle.raw;
        async move {
            self.polls.fetch_add(1, Ordering::SeqCst);
            let _owner = PendingOwner(self.drops.clone());
            let _ = self.started.send(());
            // Rescue timeout keeps a broken cancellation test joinable.
            let _ = tokio::time::timeout(Duration::from_secs(3), self.ready.clone()).await;
            self.source
                .get(Inline::<Handle<E>>::new(raw))
                .map_err(ReadFailure::new)
        }
    }
}

fn fixture() -> (
    WaitingSnapshot,
    Inline<Handle<UnknownBlob>>,
    oneshot::Sender<()>,
    mpsc::Receiver<()>,
) {
    let mut source =
        MemoryRepo::for_host(ed25519_dalek::SigningKey::from_bytes(&[93; 32]).verifying_key());
    let handle = source
        .put::<UnknownBlob, _>(Bytes::from(b"exact bytes".to_vec()))
        .unwrap();
    let (release, ready) = oneshot::channel();
    let (started, starts) = mpsc::channel();
    (
        WaitingSnapshot {
            source: source.snapshot().unwrap(),
            ready: ready.map(|_| ()).boxed().shared(),
            started,
            polls: Default::default(),
            drops: Default::default(),
        },
        handle,
        release,
        starts,
    )
}

fn interruption(mut error: &(dyn Error + 'static)) -> Option<AcquiringReadInterrupted> {
    loop {
        if let Some(value) = error.downcast_ref::<AcquiringReadInterrupted>() {
            return Some(*value);
        }
        error = error.source()?;
    }
}

#[test]
fn cancelled_or_expired_before_get_does_not_poll() {
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    for expected in [
        AcquiringReadInterrupted::Cancelled,
        AcquiringReadInterrupted::DeadlineExceeded,
    ] {
        let (snapshot, handle, _release, _starts) = fixture();
        let control = AcquiringReadControl::new(Some(Instant::now()));
        if expected == AcquiringReadInterrupted::Cancelled {
            control.cancel();
        }
        let reader = AcquiringReader::new(snapshot.clone(), runtime.clone()).with_control(control);
        let error = BlobStoreGet::get::<Bytes, _>(&reader, handle).unwrap_err();
        assert_eq!(interruption(&error), Some(expected));
        assert!(!crate::repo::is_missing_blob(&error));
        assert_eq!(snapshot.polls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot.drops.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn synchronous_pending_get_is_cancelled_and_joined_once() {
    let (snapshot, handle, release, starts) = fixture();
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let control = AcquiringReadControl::new(None);
    let reader = AcquiringReader::with_handle(snapshot.clone(), runtime.handle().clone())
        .with_control(control.clone());
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = BlobStoreGet::get::<Bytes, _>(&reader, handle);
        done.send(result).unwrap();
    });
    let started = starts.recv_timeout(Duration::from_secs(2));
    control.cancel();
    let completed = result.recv_timeout(Duration::from_secs(2));
    let _ = release.send(());
    worker.join().unwrap();
    started.unwrap();
    let error = completed.unwrap().unwrap_err();
    assert_eq!(
        interruption(&error),
        Some(AcquiringReadInterrupted::Cancelled)
    );
    assert_eq!(snapshot.polls.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cloned_control_wakes_both_async_gets() {
    let (snapshot, handle, release, starts) = fixture();
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let control = AcquiringReadControl::new(None);
    let reader =
        AcquiringReader::new(snapshot.clone(), runtime.clone()).with_control(control.clone());
    let second = reader.clone();
    let cancel = std::thread::spawn(move || {
        let first = starts.recv_timeout(Duration::from_secs(2));
        let second = starts.recv_timeout(Duration::from_secs(2));
        control.cancel();
        // Release is retained until after cancellation, never used to make the
        // successful path appear cancelled. The read has its own rescue timeout.
        (first, second, release)
    });
    let (first, second) = runtime.block_on(async {
        futures::join!(
            AsyncBlobStoreGet::get::<Bytes, _>(&reader, handle),
            AsyncBlobStoreGet::get::<Bytes, _>(&second, handle),
        )
    });
    let (started_a, started_b, _release) = cancel.join().unwrap();
    started_a.unwrap();
    started_b.unwrap();
    for error in [first.unwrap_err(), second.unwrap_err()] {
        assert_eq!(
            interruption(&error),
            Some(AcquiringReadInterrupted::Cancelled)
        );
    }
    assert_eq!(snapshot.polls.load(Ordering::SeqCst), 2);
    assert_eq!(snapshot.drops.load(Ordering::SeqCst), 2);
}

#[test]
fn one_absolute_deadline_covers_sequential_gets() {
    let (snapshot, handle, _release, _starts) = fixture();
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let deadline = Instant::now() + Duration::from_millis(100);
    let control = AcquiringReadControl::new(Some(deadline));
    // First exact read uses the same frozen bytes and control, without waiting.
    let first = runtime
        .block_on(controlled_get(
            futures::future::ready(snapshot.source.get::<Bytes, _>(handle)),
            Some(control.clone()),
        ))
        .unwrap();
    assert_eq!(first.as_ref(), b"exact bytes");
    let reader =
        AcquiringReader::new(snapshot.clone(), runtime.clone()).with_control(control.clone());
    let error = BlobStoreGet::get::<Bytes, _>(&reader, handle).unwrap_err();
    assert_eq!(control.deadline(), Some(deadline));
    assert_eq!(
        interruption(&error),
        Some(AcquiringReadInterrupted::DeadlineExceeded)
    );
    assert!(Instant::now() >= deadline);
    assert_eq!(snapshot.polls.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn repeated_polling_does_not_restart_the_exact_get() {
    let (snapshot, handle, release, _starts) = fixture();
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let reader = AcquiringReader::new(snapshot.clone(), runtime.clone())
        .with_control(AcquiringReadControl::new(None));
    let bytes = runtime.block_on(async {
        let future = AsyncBlobStoreGet::get::<Bytes, _>(&reader, handle);
        futures::pin_mut!(future);
        for _ in 0..4 {
            assert!(futures::poll!(future.as_mut()).is_pending());
        }
        assert_eq!(snapshot.polls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        future.await.unwrap()
    });
    assert_eq!(bytes.as_ref(), b"exact bytes");
    assert_eq!(snapshot.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn source_chains_distinguish_missing_fault_and_interruption() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let missing = runtime
        .block_on(controlled_get(
            futures::future::ready(Err::<(), _>(MissingBlob {
                handle: Inline::new([7; 32]),
            })),
            Some(AcquiringReadControl::new(None)),
        ))
        .unwrap_err();
    assert!(crate::repo::is_missing_blob(&missing));
    assert_eq!(interruption(&missing), None);
    let fault = runtime
        .block_on(controlled_get(
            futures::future::ready(Err::<(), _>(std::io::Error::other(
                "injected backend fault",
            ))),
            None,
        ))
        .unwrap_err();
    assert!(!crate::repo::is_missing_blob(&fault));
    assert!(fault.source().unwrap().is::<std::io::Error>());
    let (snapshot, handle, _release, _starts) = fixture();
    let control = AcquiringReadControl::new(None);
    control.cancel();
    let reader =
        AcquiringReader::with_handle(snapshot, runtime.handle().clone()).with_control(control);
    let attempt = crate::repo::read_attempt::ReadAttempt::new(&reader);
    let error = attempt.get::<Bytes, _>(handle).unwrap_err();
    assert!(!crate::repo::is_missing_blob(&error));
    assert_eq!(
        interruption(&attempt.finish().unwrap_err()),
        Some(AcquiringReadInterrupted::Cancelled)
    );
}

#[test]
fn cancellation_waits_for_synchronous_poll_then_rejects_its_result() {
    let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
    let control = AcquiringReadControl::new(None);
    let worker_control = control.clone();
    let (entered, started) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let (done, completed) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = runtime.block_on(controlled_get(
            async move {
                entered.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok::<_, std::io::Error>(42)
            },
            Some(worker_control),
        ));
        done.send(result).unwrap();
    });
    let started = started.recv_timeout(Duration::from_secs(2));
    control.cancel();
    let before_release = completed.try_recv();
    let _ = release.send(());
    worker.join().unwrap();
    started.unwrap();
    assert!(matches!(before_release, Err(mpsc::TryRecvError::Empty)));
    let error = completed
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        interruption(&error),
        Some(AcquiringReadInterrupted::Cancelled)
    );
}
