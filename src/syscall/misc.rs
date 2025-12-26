use crate::{
    mm::{translated_byte_buffer, read_user_value, write_user_value},
    task::processor::{current_process, current_task},
    trap::get_current_token,
    time::get_time,
};
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---- Linux-like TID encoding ------------------------------------------------
//
// Internally, CongCore uses a small per-process `tid` index for locating per-thread resources
// (trap context pages, optional kernel-managed stacks). glibc expects a Linux-style `gettid()`
// that is:
// - equal to `getpid()` for the main thread, and
// - unique across all threads in the system.
//
// To avoid refactoring the internal resource indexing, we encode non-main thread IDs into
// a 32-bit range with a magic bit so they won't collide with normal PIDs.
const LINUX_TID_MAGIC: usize = 1 << 30;
// Use 15 bits for per-process thread index to avoid overlapping the magic bit:
// (tgid << 15) occupies bits [15..29] for typical OSComp PID ranges (< 32768).
const LINUX_TID_PID_SHIFT: usize = 15;

pub(crate) fn encode_linux_tid(tgid: usize, tid_index: usize) -> usize {
    if tid_index == 0 {
        tgid
    } else {
        LINUX_TID_MAGIC | (tgid << LINUX_TID_PID_SHIFT) | (tid_index & 0x7fff)
    }
}

fn current_tid_index() -> usize {
    current_task()
        .unwrap()
        .borrow_mut()
        .res
        .as_ref()
        .unwrap()
        .tid
}

fn current_linux_tid() -> usize {
    encode_linux_tid(current_process().getpid(), current_tid_index())
}

// -----------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

fn write_cstr(dst: &mut [u8; 65], s: &str) {
    dst.fill(0);
    let bytes = s.as_bytes();
    let n = bytes.len().min(64);
    dst[..n].copy_from_slice(&bytes[..n]);
}

pub fn syscall_uname(buf: usize) -> isize {
    if buf == 0 {
        return -1;
    }
    let mut un = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_cstr(&mut un.sysname, "CongCore");
    write_cstr(&mut un.nodename, "localhost");
    // glibc/busybox may abort early if the reported kernel release is "too old".
    // Report a modern Linux-like release string for compatibility.
    write_cstr(&mut un.release, "5.15.0");
    write_cstr(&mut un.version, "CongCore");
    write_cstr(&mut un.machine, "riscv64");
    write_cstr(&mut un.domainname, "localdomain");

    let token = get_current_token();
    write_user_value(token, buf as *mut UtsName, &un);
    0
}

pub fn syscall_mount(
    _special: usize,
    _dir: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    0
}

pub fn syscall_umount2(_special: usize, _flags: usize) -> isize {
    0
}

pub fn syscall_getppid() -> isize {
    let process = current_process();
    let parent = { process.borrow_mut().parent.as_ref().and_then(|p| p.upgrade()) };
    parent.map(|p| p.getpid() as isize).unwrap_or(0)
}

/// Linux `setpgid(2)` (syscall 154 on riscv64).
///
/// Process groups are not modeled; accept and return success for compatibility.
pub fn syscall_setpgid(_pid: usize, _pgid: usize) -> isize {
    0
}

/// Linux `getsid(2)` (syscall 156 on riscv64).
pub fn syscall_getsid(pid: usize) -> isize {
    if pid == 0 {
        current_process().getpid() as isize
    } else {
        pid as isize
    }
}

/// Linux `setsid(2)` (syscall 157 on riscv64).
///
/// We don't model sessions; treat the process PID as SID and return it.
pub fn syscall_setsid() -> isize {
    current_process().getpid() as isize
}

/// Linux `set_tid_address(2)` (syscall 96 on riscv64).
///
/// We currently run a single-threaded process model for glibc apps; we accept the
/// pointer and return a Linux-like TID (use PID as TID).
pub fn syscall_set_tid_address(_tidptr: usize) -> isize {
    let task = current_task().unwrap();
    let tid_index = {
        let mut inner = task.borrow_mut();
        if _tidptr != 0 {
            inner.clear_child_tid = Some(_tidptr);
        }
        inner.res.as_ref().unwrap().tid
    };
    encode_linux_tid(current_process().getpid(), tid_index) as isize
}

pub fn syscall_getuid() -> isize {
    0
}
pub fn syscall_geteuid() -> isize {
    0
}
pub fn syscall_getgid() -> isize {
    0
}
pub fn syscall_getegid() -> isize {
    0
}

/// Linux `gettid(2)` (syscall 178 on riscv64).
pub fn syscall_gettid_linux() -> isize {
    current_linux_tid() as isize
}

/// Linux `set_robust_list(2)` (syscall 99 on riscv64).
///
/// glibc uses this for mutex robustness; we don't implement robust futexes yet,
/// but returning success keeps single-threaded apps progressing.
pub fn syscall_set_robust_list(_head: usize, _len: usize) -> isize {
    0
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

/// Linux `prlimit64(2)` (syscall 261 on riscv64).
///
/// Provide a permissive "unlimited" answer for common queries (e.g. RLIMIT_STACK).
pub fn syscall_prlimit64(_pid: usize, _resource: usize, _new_limit: usize, old_limit: usize) -> isize {
    if old_limit != 0 {
        let token = get_current_token();
        let rl = RLimit64 {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };
        write_user_value(token, old_limit as *mut RLimit64, &rl);
    }
    0
}

/// Linux `getrandom(2)` (syscall 278 on riscv64).
///
/// Fill the buffer with a simple xorshift PRNG seeded from time and pid/tid.
pub fn syscall_getrandom(buf: usize, len: usize, _flags: u32) -> isize {
    if buf == 0 {
        return 0;
    }
    let token = get_current_token();
    let mut seed = (get_time() as u64)
        ^ ((current_process().getpid() as u64) << 32)
        ^ (current_linux_tid() as u64);
    let chunks = translated_byte_buffer(token, buf as *mut u8, len);
    let mut written = 0usize;
    for chunk in chunks {
        for b in chunk {
            // xorshift64*
            let mut x = seed;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545F4914F6CDD1D);
            seed = x;
            *b = (x & 0xff) as u8;
            written += 1;
        }
    }
    written as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// Linux `ppoll(2)` (syscall 73 on riscv64).
///
/// Minimal readiness reporting for shells (busybox/ash) and glibc helpers.
/// We conservatively mark fds as ready if they are readable/writable.
pub fn syscall_ppoll(fds_ptr: usize, nfds: usize, _tmo_p: usize, _sigmask: usize, _sigsetsize: usize) -> isize {
    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const EBADF: isize = -9;

    if nfds == 0 || fds_ptr == 0 {
        return 0;
    }

    let token = get_current_token();
    let process = current_process();

    // `ppoll(NULL)` means "wait forever" (no timeout). Many libc `poll(-1)` wrappers
    // map to `ppoll(..., NULL, ...)`.
    let infinite = _tmo_p == 0;

    loop {
        let mut ready = 0isize;
        for i in 0..nfds {
            let pfd_ptr = (fds_ptr + i * size_of::<PollFd>()) as *mut PollFd;
            let mut pfd = read_user_value(token, pfd_ptr as *const PollFd);
            if pfd.fd < 0 {
                pfd.revents = 0;
                write_user_value(token, pfd_ptr, &pfd);
                continue;
            }
            let fd = pfd.fd as usize;
            let file = {
                let inner = process.borrow_mut();
                if fd >= inner.fd_table.len() {
                    None
                } else {
                    inner.fd_table[fd].clone()
                }
            };
            let Some(file) = file else {
                pfd.revents = 0;
                return EBADF;
            };

            let mut revents: i16 = 0;

            // Pipes and our socketpair endpoints need real readiness (buffer-based),
            // not just "is readable/writable" capability.
            if let Some(pipe) = file.as_any().downcast_ref::<crate::fs::Pipe>() {
                if (pfd.events & POLLIN) != 0 && pipe.poll_readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && pipe.poll_writable() {
                    revents |= POLLOUT;
                }
            } else if let Some(sp) = file.as_any().downcast_ref::<crate::fs::SocketPairEnd>() {
                if (pfd.events & POLLIN) != 0 && sp.poll_readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && sp.poll_writable() {
                    revents |= POLLOUT;
                }
            } else {
                if (pfd.events & POLLIN) != 0 && file.readable() {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 && file.writable() {
                    revents |= POLLOUT;
                }
            }

            pfd.revents = revents;
            write_user_value(token, pfd_ptr, &pfd);
            if revents != 0 {
                ready += 1;
            }
        }

        if ready != 0 || !infinite {
            return ready;
        }

        // Block (best-effort): yield and retry until something becomes ready.
        crate::task::processor::suspend_current_and_run_next();
    }
}

/// Linux `umask(2)` (syscall 166 on riscv64).
///
/// A minimal implementation for daemon() and common utilities.
pub fn syscall_umask(mask: usize) -> isize {
    static UMASK: AtomicUsize = AtomicUsize::new(0);
    let prev = UMASK.swap(mask & 0o777, Ordering::Relaxed);
    prev as isize
}

/// Linux `ioctl(2)` (syscall 29 on riscv64).
///
/// We don't model TTYs yet; return `ENOTTY` for most requests to avoid `ENOSYS`
/// aborts in busybox/glibc helpers.
pub fn syscall_ioctl(fd: usize, _request: usize, _argp: usize) -> isize {
    const EBADF: isize = -9;
    const ENOTTY: isize = -25;

    let process = current_process();
    let file = {
        let inner = process.borrow_mut();
        if fd >= inner.fd_table.len() {
            None
        } else {
            inner.fd_table[fd].clone()
        }
    };
    let Some(file) = file else {
        return EBADF;
    };

    // Best-effort support for `/dev/misc/rtc` (busybox `hwclock`).
    if file.as_any().downcast_ref::<crate::fs::RtcFile>().is_some() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct RtcTime {
            tm_sec: i32,
            tm_min: i32,
            tm_hour: i32,
            tm_mday: i32,
            tm_mon: i32,
            tm_year: i32,
            tm_wday: i32,
            tm_yday: i32,
            tm_isdst: i32,
        }

        if _argp != 0 {
            let secs = (crate::time::get_time_ms() / 1000) as i64;
            let tm_sec = (secs % 60) as i32;
            let tm_min = ((secs / 60) % 60) as i32;
            let tm_hour = ((secs / 3600) % 24) as i32;
            let tm_mday = 1 + (secs / 86400) as i32;
            let rt = RtcTime {
                tm_sec,
                tm_min,
                tm_hour,
                tm_mday,
                tm_mon: 0,
                tm_year: 70,
                tm_wday: 4,
                tm_yday: 0,
                tm_isdst: 0,
            };
            let token = get_current_token();
            write_user_value(token, _argp as *mut RtcTime, &rt);
        }
        return 0;
    }

    ENOTTY
}

/// Linux `syslog(2)` / `klogctl(2)` (syscall 116 on riscv64).
///
/// Busybox `dmesg` calls this. We don't maintain a kernel log buffer for userspace;
/// return success and (for read requests) an empty buffer.
pub fn syscall_syslog(_type: usize, bufp: usize, len: usize) -> isize {
    const EINVAL: isize = -22;

    // `klogctl` actions (Linux uapi).
    const SYSLOG_ACTION_READ: usize = 2;
    const SYSLOG_ACTION_READ_ALL: usize = 3;
    const SYSLOG_ACTION_READ_CLEAR: usize = 4;
    const SYSLOG_ACTION_CLEAR: usize = 5;
    const SYSLOG_ACTION_SIZE_BUFFER: usize = 10;
    const SYSLOG_ACTION_SIZE_UNREAD: usize = 11;

    match _type {
        SYSLOG_ACTION_SIZE_BUFFER => return crate::klog::capacity() as isize,
        SYSLOG_ACTION_SIZE_UNREAD => return crate::klog::len() as isize,
        SYSLOG_ACTION_CLEAR => {
            crate::klog::clear();
            return 0;
        }
        _ => {}
    }

    if bufp == 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }

    let data = match _type {
        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL => crate::klog::snapshot(len),
        SYSLOG_ACTION_READ_CLEAR => crate::klog::snapshot_and_clear(len),
        _ => return EINVAL,
    };

    let token = get_current_token();
    let bufs = translated_byte_buffer(token, bufp as *mut u8, len);
    let mut off = 0usize;
    for b in bufs {
        if off >= data.len() {
            break;
        }
        let n = core::cmp::min(b.len(), data.len() - off);
        b[..n].copy_from_slice(&data[off..off + n]);
        off += n;
        if n < b.len() {
            break;
        }
    }
    data.len() as isize
}
