use anyhow::Result;
use std::future::Future;
use std::io;
use triblespace::prelude::TryToInline;
use triblespace_core::inline::encodings::hash::Blake3;
use triblespace_core::inline::encodings::hash::Hash;

pub fn parse_blob_handle(handle: &str) -> Result<triblespace_core::inline::Inline<Hash<Blake3>>> {
    handle.try_to_inline().map_err(|e| anyhow::anyhow!("{e:?}"))
}

/// Construct while entered into the command's Tokio runtime, before opening
/// its writable store. Unix handlers are installed now, not at the first poll.
/// The returned future requests cooperative shutdown; it cannot preempt a
/// synchronous store operation or CPU section.
pub(super) fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

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
