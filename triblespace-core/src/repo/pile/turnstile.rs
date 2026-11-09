//! Writer preference for the pile's file lock.
//!
//! The pile's correctness lock is `flock` on the pile file: replay and atomic
//! appends hold it shared, multi-syscall appends and amputation hold it
//! exclusive. `flock` grants a new shared lock while an exclusive request is
//! queued, so readers whose holds overlap can keep a writer out for as long as
//! they keep arriving.
//!
//! The turnstile is a second lock, on the same inode, that only orders
//! ARRIVALS at the correctness lock. A writer holds it exclusive while it
//! waits for the exclusive `flock`; a reader holds it shared only across
//! acquiring the shared `flock`. Once a writer is waiting, new readers queue
//! behind it instead of overlapping in front of it, and the writer waits only
//! for the shared holds already in progress.
//!
//! It is an open-file-description byte-range lock (`F_OFD_SETLKW`) on one
//! byte far past any real pile length, so it needs no sidecar file and keys on
//! the inode itself: every path, symlink, hard link or bind mount that reaches
//! the file reaches the same turnstile. Like `flock` it belongs to the open
//! file description and is released when the descriptor closes, including on
//! a crash. On Linux local filesystems OFD byte-range locks and `flock` are
//! independent lock spaces.
//!
//! The turnstile carries no correctness. A handle that cannot take it (another
//! platform, a network filesystem where the kernel emulates `flock` with
//! byte-range locks, a read-only descriptor asked for a write lock, any error)
//! simply proceeds to the `flock` without it, which is exactly the behaviour
//! before the turnstile existed. So does a process built before it.

use std::fs::File;

/// Whether this descriptor's file can take part in the turnstile.
pub(super) fn supported(file: &File) -> bool {
    imp::supported(file)
}

/// Enters the turnstile for a shared (`exclusive == false`) or exclusive
/// arrival. Returns whether it was entered; on `false` the caller proceeds
/// without it.
pub(super) fn enter(file: &File, exclusive: bool) -> bool {
    imp::enter(file, exclusive)
}

/// Leaves a turnstile entered with [`enter`].
pub(super) fn leave(file: &File) {
    imp::leave(file)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    /// One byte at the largest offset a lock can name. A pile can never grow
    /// to it, and byte-range locks may cover offsets past end of file.
    const START: libc::off_t = libc::off_t::MAX - 1;

    /// Filesystems on which Linux emulates `flock` with byte-range locks, so
    /// the turnstile would share a lock space with the correctness lock.
    const EMULATED_FLOCK: [i64; 3] = [
        0x0000_6969, // NFS
        0xFE53_4D42, // SMB2
        0xFF53_4D42, // CIFS
    ];

    pub(super) fn supported(file: &File) -> bool {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is open for the lifetime of `file`, and
        // `stat` is a valid out-pointer.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
            return false;
        }
        !EMULATED_FLOCK.contains(&(stat.f_type as i64))
    }

    fn set(file: &File, kind: libc::c_int, wait: bool) -> bool {
        // SAFETY: an all-zero `flock` is a valid value; OFD locks require
        // `l_pid == 0`.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = kind as _;
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_start = START;
        lock.l_len = 1;
        let cmd = if wait {
            libc::F_OFD_SETLKW
        } else {
            libc::F_OFD_SETLK
        };
        loop {
            // SAFETY: `lock` is a valid `flock` for the duration of the call.
            if unsafe { libc::fcntl(file.as_raw_fd(), cmd, &lock) } == 0 {
                return true;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return false;
            }
        }
    }

    pub(super) fn enter(file: &File, exclusive: bool) -> bool {
        let kind = if exclusive {
            libc::F_WRLCK
        } else {
            libc::F_RDLCK
        };
        set(file, kind, true)
    }

    pub(super) fn leave(file: &File) {
        // Unlocking a range this description holds cannot block, and cannot
        // fail on a valid descriptor; if it ever did, closing the descriptor
        // still releases it.
        let _ = set(file, libc::F_UNLCK, false);
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::fs::File;

    pub(super) fn supported(_file: &File) -> bool {
        false
    }

    pub(super) fn enter(_file: &File, _exclusive: bool) -> bool {
        false
    }

    pub(super) fn leave(_file: &File) {}
}
