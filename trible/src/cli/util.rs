use anyhow::Result;
use std::future::Future;
use std::io;
use triblespace::prelude::TryToInline;
use triblespace_core::inline::encodings::hash::Blake3;
use triblespace_core::inline::encodings::hash::Hash;

pub fn parse_blob_handle(handle: &str) -> Result<triblespace_core::inline::Inline<Hash<Blake3>>> {
    handle.try_to_inline().map_err(|e| anyhow::anyhow!("{e:?}"))
}

/// Cumulative user + system CPU time of this process, across all its threads.
/// Missing/unsupported observations remain unknown. This does not measure
/// elapsed time, child processes, thread capacity, or one particular stage.
pub(super) fn process_cpu_ns() -> Option<u128> {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage writes a full rusage to this properly aligned
        // allocation on success. Do not inspect the allocation after failure.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: the preceding successful call initialized the value.
        let usage = unsafe { usage.assume_init() };
        let user = cpu_timeval_ns(usage.ru_utime)?;
        let system = cpu_timeval_ns(usage.ru_stime)?;
        user.checked_add(system)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(unix)]
fn cpu_timeval_ns(value: libc::timeval) -> Option<u128> {
    let seconds = u128::try_from(value.tv_sec).ok()?;
    let micros = u128::try_from(value.tv_usec).ok()?;
    if micros >= 1_000_000 {
        return None;
    }
    seconds
        .checked_mul(1_000_000_000)?
        .checked_add(micros * 1_000)
}

#[cfg(all(test, unix))]
mod cpu_tests {
    use super::*;

    #[test]
    fn process_cpu_is_a_monotonic_observation_not_elapsed_time() {
        let before = process_cpu_ns().expect("getrusage on the test host");
        let after = process_cpu_ns().expect("getrusage on the test host");
        assert!(after >= before);
    }

    #[test]
    fn invalid_cpu_times_stay_unknown() {
        assert_eq!(
            cpu_timeval_ns(libc::timeval {
                tv_sec: -1,
                tv_usec: 0
            }),
            None
        );
        assert_eq!(
            cpu_timeval_ns(libc::timeval {
                tv_sec: 0,
                tv_usec: -1
            }),
            None
        );
        assert_eq!(
            cpu_timeval_ns(libc::timeval {
                tv_sec: 0,
                tv_usec: 1_000_000
            }),
            None
        );
        assert_eq!(
            cpu_timeval_ns(libc::timeval {
                tv_sec: 2,
                tv_usec: 3
            }),
            Some(2_000_003_000)
        );
    }
}

/// Construct while entered into the command's Tokio runtime, before opening
/// its writable store. Unix handlers are installed now, not at the first poll.
/// The returned future requests cooperative shutdown; it cannot preempt a
/// synchronous store operation or CPU section.
pub(super) fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::signal::ctrl_c())
    }
}
