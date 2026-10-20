//! Observational custody check, not a lock or a proof that a file is immutable.
//!
//! Observe vnode descriptors in readable tables of same-effective-UID processes.
//! Other users, this process, denied tables, fileports and mappings whose fd was
//! closed are outside the scope. Enumeration is not atomic: processes/fds may
//! appear, disappear or be reused during/after it. The operator must independently
//! keep every input frozen throughout the command. No privilege is requested.
use std::io;
use std::mem::size_of;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{ensure, Context, Result};

// Public macOS sys/proc_info.h ABI, not application protocol identifiers.
const PROC_UID_ONLY: u32 = 4;
const PROC_PIDFDVNODEINFO: i32 = 1;

#[repr(C)]
struct ProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard_flags: u32,
}

#[repr(C)]
struct VnodeFdInfo {
    file: ProcFileInfo,
    vnode: libc::vnode_info,
}

#[derive(Default)]
struct Observation {
    readable: usize,
    denied: Vec<i32>,
    vanished_processes: usize,
    vanished_descriptors: usize,
}

#[derive(Debug, PartialEq)]
enum VnodeRead {
    Complete,
    ProcessGone,
    DescriptorGone,
}

impl Observation {
    fn table_size(&mut self, pid: i32, result: io::Result<usize>) -> Result<Option<usize>> {
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if vanished(&error) => {
                self.vanished_processes += 1;
                Ok(None)
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
                self.denied.push(pid);
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn vnode_read(&mut self, result: io::Result<usize>) -> Result<VnodeRead> {
        match result {
            Ok(bytes) => {
                ensure!(
                    bytes == size_of::<VnodeFdInfo>(),
                    "incomplete vnode observation: {bytes} bytes"
                );
                Ok(VnodeRead::Complete)
            }
            Err(error) if vanished(&error) => {
                self.vanished_processes += 1;
                Ok(VnodeRead::ProcessGone)
            }
            Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
                self.vanished_descriptors += 1;
                Ok(VnodeRead::DescriptorGone)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn finish(&self) -> Result<()> {
        ensure!(
            self.readable != 0,
            "no other process table was readable; observation unavailable"
        );
        Ok(())
    }
}

// libproc reports errors as zero as well as -1. Clear errno so a genuinely
// empty table cannot accidentally inherit an earlier permission/disappearance.
fn call(mut f: impl FnMut() -> i32) -> io::Result<usize> {
    // SAFETY: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() = 0 };
    let bytes = f();
    let error = io::Error::last_os_error();
    if bytes < 0 || (bytes == 0 && error.raw_os_error() != Some(0)) {
        Err(error)
    } else {
        Ok(bytes as usize)
    }
}

fn count<T>(bytes: usize, capacity: usize) -> Result<usize> {
    ensure!(
        bytes % size_of::<T>() == 0 && bytes < capacity,
        "incomplete libproc list: {bytes} bytes for {capacity}-byte buffer"
    );
    Ok(bytes / size_of::<T>())
}

/// A bounded, zero-initialized native list. A full buffer is ambiguous and
/// refuses, rather than treating a possibly truncated observation as complete.
fn list<T: Copy>(
    estimate: usize,
    empty: T,
    mut read: impl FnMut(*mut libc::c_void, i32) -> i32,
) -> Result<Vec<T>> {
    ensure!(
        estimate % size_of::<T>() == 0 && estimate <= 16 * 1024 * 1024,
        "invalid or excessive libproc list estimate: {estimate}"
    );
    let slots = estimate / size_of::<T>() + 32;
    let capacity = slots * size_of::<T>();
    // The initialized allocation remains alive and aligned throughout the call,
    // with its exact writable capacity supplied.
    let mut values = vec![empty; slots];
    let bytes = call(|| read(values.as_mut_ptr().cast(), capacity as i32))?;
    values.truncate(count::<T>(bytes, capacity)?);
    Ok(values)
}

fn vanished(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

fn same_vnode(dev: u64, ino: u64, stat: &libc::vinfo_stat) -> bool {
    // Darwin's Metadata dev_t is signed i32, widened to u64 by std, whereas
    // libproc exposes its identical 32 bits as u32. Normalize, don't zero-
    // extend only one side and lose devices whose native sign bit is set.
    stat.vst_dev == dev as u32 && stat.vst_ino == ino
}

pub(super) fn other_openers(path: &Path) -> Result<Vec<u32>> {
    let target = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut observation = Observation::default();
    let result = observe(target.dev(), target.ino(), uid, &mut observation);
    eprintln!(
        "macOS observational opener guard for {}: effective uid {uid}, {} readable process \
         tables, permission-excluded pids {:?}, {} vanished processes, {} vanished vnode \
         descriptors. Scope excludes self, other users, denied tables, fileports and mappings \
         without open fds; enumeration is non-atomic and cannot prevent later opens/writes. \
         Operator-frozen input custody is required; this is not an immutability guarantee.",
        path.display(),
        observation.readable,
        observation.denied,
        observation.vanished_processes,
        observation.vanished_descriptors,
    );
    result.context("macOS opener observation incomplete or custody violated")
}

fn observe(dev: u64, ino: u64, uid: u32, observation: &mut Observation) -> Result<Vec<u32>> {
    // SAFETY: null/zero requests the byte estimate; list supplies a valid buffer.
    let estimate =
        call(|| unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) })
            .context("enumerate same-effective-UID processes")?;
    let processes = list::<i32>(estimate, 0, |buffer, bytes| unsafe {
        libc::proc_listpids(PROC_UID_ONLY, uid, buffer, bytes)
    })
    .context("enumerate same-effective-UID processes")?;
    let own = std::process::id() as i32;
    ensure!(
        processes.contains(&own),
        "process enumeration omitted self; observation unavailable"
    );
    ensure!(
        processes.iter().all(|pid| *pid >= 0),
        "invalid process identifier"
    );
    let mut openers = Vec::new();
    for pid in processes.into_iter().filter(|pid| *pid > 0 && *pid != own) {
        // SAFETY: null/zero requests the descriptor-list byte estimate.
        let result = call(|| unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
        });
        let Some(estimate) = observation
            .table_size(pid, result)
            .with_context(|| format!("size fd table of pid {pid}"))?
        else {
            continue;
        };
        // After entering a readable table, permission loss and other failures
        // are incomplete observations, not newly invented scope exclusions.
        let descriptors = match list(
            estimate,
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            },
            |buffer, bytes| unsafe {
                libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buffer, bytes)
            },
        ) {
            Ok(descriptors) => descriptors,
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(vanished) => {
                observation.vanished_processes += 1;
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("read fd table of pid {pid}")),
        };
        ensure!(
            descriptors.iter().all(|fd| fd.proc_fd >= 0),
            "invalid descriptor in fd table of pid {pid}"
        );
        observation.readable += 1;
        let mut found = false;
        for fd in descriptors
            .into_iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32)
        {
            // SAFETY: integer-only C ABI struct; initialized, aligned storage
            // with the exact size. Do not inspect it unless the full size returns.
            let mut info: VnodeFdInfo = unsafe { std::mem::zeroed() };
            let result = call(|| unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    PROC_PIDFDVNODEINFO,
                    (&mut info as *mut VnodeFdInfo).cast(),
                    size_of::<VnodeFdInfo>() as i32,
                )
            });
            match observation
                .vnode_read(result)
                .with_context(|| format!("read vnode pid {pid} fd {}", fd.proc_fd))?
            {
                VnodeRead::Complete => {}
                VnodeRead::ProcessGone => break,
                VnodeRead::DescriptorGone => continue,
            };
            let stat = info.vnode.vi_stat;
            // Identity, not path text: hardlinks count, and every open mode
            // (including read-only) is custody evidence, just as on Linux.
            found |= same_vnode(dev, ino, &stat);
        }
        if found {
            openers.push(pid as u32);
        }
    }
    observation.finish()?;
    Ok(openers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_failed_native_lists_refuse() {
        assert!(count::<i32>(16, 16).is_err(), "full may mean truncated");
        assert!(count::<i32>(17, 16).is_err(), "oversized");
        assert!(count::<i32>(3, 16).is_err(), "partial element");
        assert!(list::<i32>(usize::MAX, 0, |_, _| 0).is_err());
        assert!(list::<i32>(4, 0, |_, capacity| capacity).is_err());
        let error = list::<i32>(4, 0, |_, _| {
            unsafe { *libc::__error() = libc::EPERM };
            0
        })
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    fn empty_native_list_does_not_inherit_stale_errno() {
        unsafe { *libc::__error() = libc::EPERM };
        assert!(list::<i32>(0, 0, |_, _| 0).unwrap().is_empty());
    }

    #[test]
    fn process_disappearance_is_not_permission_denial() {
        assert!(vanished(&io::Error::from_raw_os_error(libc::ESRCH)));
        for code in [libc::EPERM, libc::EACCES, libc::EIO, libc::EBADF] {
            assert!(!vanished(&io::Error::from_raw_os_error(code)));
        }
    }

    #[test]
    fn initial_permission_exclusions_cannot_become_vacuous_success() {
        let mut observed = Observation::default();
        for code in [libc::EPERM, libc::EACCES] {
            assert_eq!(
                observed
                    .table_size(17, Err(io::Error::from_raw_os_error(code)))
                    .unwrap(),
                None
            );
        }
        assert_eq!(observed.denied, vec![17, 17]);
        assert!(observed.finish().is_err());
        assert!(observed
            .table_size(18, Err(io::Error::from_raw_os_error(libc::EIO)))
            .is_err());
        assert_eq!(observed.table_size(19, Ok(0)).unwrap(), Some(0));
    }

    #[test]
    fn vnode_observation_refuses_short_reads_and_permission_loss_but_counts_disappearance() {
        let mut observed = Observation::default();
        for bytes in [
            0,
            size_of::<VnodeFdInfo>() - 1,
            size_of::<VnodeFdInfo>() + 1,
        ] {
            assert!(observed.vnode_read(Ok(bytes)).is_err());
        }
        // ENOENT is ambiguous (revoked vnode or another stat failure), not
        // evidence that the descriptor disappeared. Keep that native refusal.
        for code in [libc::EPERM, libc::EACCES, libc::EIO, libc::ENOENT] {
            assert!(observed
                .vnode_read(Err(io::Error::from_raw_os_error(code)))
                .is_err());
        }
        assert!(observed.denied.is_empty(), "no late permission exclusions");
        assert_eq!(
            observed
                .vnode_read(Err(io::Error::from_raw_os_error(libc::ESRCH)))
                .unwrap(),
            VnodeRead::ProcessGone
        );
        assert_eq!(
            observed
                .vnode_read(Err(io::Error::from_raw_os_error(libc::EBADF)))
                .unwrap(),
            VnodeRead::DescriptorGone
        );
        assert_eq!(observed.vanished_processes, 1);
        assert_eq!(observed.vanished_descriptors, 1);
        assert_eq!(
            observed.vnode_read(Ok(size_of::<VnodeFdInfo>())).unwrap(),
            VnodeRead::Complete
        );
    }

    #[test]
    fn vnode_identity_preserves_native_device_sign_bit() {
        let mut stat: libc::vinfo_stat = unsafe { std::mem::zeroed() };
        stat.vst_dev = 0x8000_0001;
        stat.vst_ino = 17;
        assert!(same_vnode(i64::from(stat.vst_dev as i32) as u64, 17, &stat));
        assert!(!same_vnode(1, 17, &stat));
        assert!(!same_vnode(
            i64::from(stat.vst_dev as i32) as u64,
            18,
            &stat
        ));
    }
}
