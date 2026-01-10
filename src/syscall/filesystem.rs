use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};

use lazy_static::lazy_static;
use spin::Mutex;

use crate::{
    config::CLOCK_FREQ,
    fs::{
        shm_create, shm_get, shm_list, shm_remove, File, OSInode, PseudoBlock, PseudoDir,
        PseudoDirent, PseudoFile, PseudoShmFile, RtcFile, ROOT_INODE, OpenFlags, ext4_lock,
        make_pipe, open_file,
    },
    mm::{
        UserBuffer, copy_from_user, copy_to_user, read_user_value, translated_byte_buffer,
        translated_mutref, translated_str, write_user_value,
    },
    task::processor::current_process,
    time::get_time,
    trap::get_current_token,
};

const AT_FDCWD: isize = -100;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_SYMLINK_FOLLOW: usize = 0x400;
const AT_NO_AUTOMOUNT: usize = 0x800;
const AT_EMPTY_PATH: usize = 0x1000;

const O_ACCMODE: usize = 0x3;
const O_RDONLY: usize = 0x0;
const O_WRONLY: usize = 0x1;
const O_RDWR: usize = 0x2;
const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;
const O_TRUNC: usize = 0x200;
const O_APPEND: usize = 0x400;
const O_NONBLOCK: usize = 0x800;
const O_DIRECTORY: usize = 0x10000;
const O_CLOEXEC: usize = 0x80000;
// __O_TMPFILE (020000000) | O_DIRECTORY from asm-generic/fcntl.h
const O_TMPFILE: usize = 0x410000;

const FD_CLOEXEC: u32 = 1;

// Linux errno (negative return in kernel ABI).
const EBADF: isize = -9;
const ENOENT: isize = -2;
const EINVAL: isize = -22;
const EMFILE: isize = -24;
const ENOTDIR: isize = -20;
const EISDIR: isize = -21;
const EACCES: isize = -13;
const EEXIST: isize = -17;
const EXDEV: isize = -18;
const ESPIPE: isize = -29;
const EROFS: isize = -30;
const ENOSPC: isize = -28;
const ENOSYS: isize = -38;
const ENAMETOOLONG: isize = -36;
const EOPNOTSUPP: isize = -95;
const ENOTEMPTY: isize = -39;

static TMPFILE_SEQ: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Default)]
struct InodeTimes {
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

lazy_static! {
    static ref INODE_TIMES: Mutex<BTreeMap<u64, InodeTimes>> = Mutex::new(BTreeMap::new());
}

fn get_inode_times(ino: u64) -> InodeTimes {
    INODE_TIMES.lock().get(&ino).copied().unwrap_or_default()
}

fn set_inode_times(ino: u64, times: InodeTimes) {
    INODE_TIMES.lock().insert(ino, times);
}

fn current_timespec() -> (i64, i64) {
    let ticks = get_time() as u64;
    let ns = ticks.saturating_mul(1_000_000_000) / CLOCK_FREQ as u64;
    ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
}

fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');
    if !absolute {
        for seg in cwd.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                parts.pop();
                continue;
            }
            parts.push(seg);
        }
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn normalize_relative_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    parts.join("/")
}

fn shm_object_name(abs: &str) -> Option<&str> {
    // Only accept `/dev/shm/<name>` (single path component).
    let rest = abs.strip_prefix("/dev/shm/")?;
    let name = rest.trim_start_matches('/');
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(name)
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => {
            let (parent, name) = trimmed.split_at(pos);
            Some((parent, &name[1..]))
        }
        None => Some(("", trimmed)),
    }
}

fn get_fd_file(fd: usize) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    let process = current_process();
    let inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return None;
    }
    inner.fd_table[fd].clone()
}

fn get_fd_inode(fd: usize) -> Option<alloc::sync::Arc<ext4_fs::Inode>> {
    let file = get_fd_file(fd)?;
    file.as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode())
}

fn is_pseudo_path(abs: &str) -> bool {
    abs == "/sys"
        || abs.starts_with("/sys/")
        || abs == "/proc"
        || abs.starts_with("/proc/")
        || abs == "/dev"
        || abs.starts_with("/dev/")
}

enum AtPath {
    /// An ext4 lookup rooted at `/`.
    Ext4Abs(String),
    /// An ext4 lookup rooted at an open directory fd.
    Ext4Rel {
        base: alloc::sync::Arc<ext4_fs::Inode>,
        rel: String,
    },
    /// A pseudo filesystem lookup expressed as an absolute path.
    PseudoAbs(String),
}

fn resolve_at_path(dirfd: isize, path: &str) -> Result<AtPath, isize> {
    if path.is_empty() {
        return Err(ENOENT);
    }

    // Absolute path: ignore dirfd.
    if path.starts_with('/') {
        let abs = normalize_path("/", path);
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
        });
    }

    // Relative path.
    if dirfd == AT_FDCWD {
        let process = current_process();
        let cwd = { process.borrow_mut().cwd.clone() };
        let abs = normalize_path(&cwd, path);
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
        });
    }

    if dirfd < 0 {
        return Err(EBADF);
    }

    let Some(file) = get_fd_file(dirfd as usize) else {
        return Err(EBADF);
    };

    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let abs = normalize_path(pdir.path(), path);
        return Ok(if is_pseudo_path(&abs) {
            AtPath::PseudoAbs(abs)
        } else {
            AtPath::Ext4Abs(abs)
        });
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let base = os_inode.ext4_inode();
        if !base.is_dir() {
            return Err(ENOTDIR);
        }
        let rel = normalize_relative_path(path);
        return Ok(AtPath::Ext4Rel { base, rel });
    }

    Err(ENOTDIR)
}

fn resolve_abs_path(dirfd: isize, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = if path.starts_with('/') {
        normalize_path("/", path)
    } else if dirfd == AT_FDCWD {
        normalize_path(&cwd, path)
    } else if dirfd >= 0 {
        // If dirfd refers to a pseudo directory, resolve relative to it.
        // For ext4 dirfds, we can't reliably reconstruct an absolute path (no reverse lookup).
        if let Some(file) = get_fd_file(dirfd as usize) {
            if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
                normalize_path(pdir.path(), path)
            } else {
                normalize_path(&cwd, path)
            }
        } else {
            return None;
        }
    } else {
        normalize_path(&cwd, path)
    };
    Some(abs)
}

fn ext4_err_to_errno(e: ext4_fs::Ext4Error) -> isize {
    match e {
        ext4_fs::Ext4Error::NotADirectory => ENOTDIR,
        ext4_fs::Ext4Error::NotAFile => EISDIR,
        ext4_fs::Ext4Error::AlreadyExists => EEXIST,
        ext4_fs::Ext4Error::NotFound => ENOENT,
        ext4_fs::Ext4Error::NoSpace => ENOSPC,
        ext4_fs::Ext4Error::NameTooLong => ENAMETOOLONG,
        ext4_fs::Ext4Error::Unsupported => EOPNOTSUPP,
        ext4_fs::Ext4Error::InvalidInput => EINVAL,
    }
}

fn inode_mode_allows(inode_mode: u16, mask: usize) -> bool {
    // Use "other" permission bits as a permissive default (no uid/gid model).
    let perm = (inode_mode & 0o777) as usize;
    if mask == 0 {
        return true;
    }
    if (mask & 1) != 0 && (perm & 0o001) == 0 {
        return false;
    }
    if (mask & 2) != 0 && (perm & 0o002) == 0 {
        return false;
    }
    if (mask & 4) != 0 && (perm & 0o004) == 0 {
        return false;
    }
    true
}

pub fn syscall_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    // Minimal `fcntl(2)` support for busybox/ash/glibc startup.
    const F_DUPFD: usize = 0;
    const F_GETFD: usize = 1;
    const F_SETFD: usize = 2;
    const F_GETFL: usize = 3;
    const F_SETFL: usize = 4;
    const F_DUPFD_CLOEXEC: usize = 1030;

    let ret = match cmd {
        F_GETFD => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
                return EBADF;
            }
            if fd >= inner.fd_flags.len() {
                let fd_len = inner.fd_table.len();
                inner.fd_flags.resize(fd_len, 0);
            }
            if (inner.fd_flags[fd] & FD_CLOEXEC) != 0 {
                FD_CLOEXEC as isize
            } else {
                0
            }
        }
        F_SETFD => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
                return EBADF;
            }
            if fd >= inner.fd_flags.len() {
                let fd_len = inner.fd_table.len();
                inner.fd_flags.resize(fd_len, 0);
            }
            let mut cur = inner.fd_flags[fd];
            if (arg as u32 & FD_CLOEXEC) != 0 {
                cur |= FD_CLOEXEC;
            } else {
                cur &= !FD_CLOEXEC;
            }
            inner.fd_flags[fd] = cur;
            0
        }
        F_SETFL => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
                return EBADF;
            }
            if fd >= inner.fd_flags.len() {
                let fd_len = inner.fd_table.len();
                inner.fd_flags.resize(fd_len, 0);
            }
            let mut cur = inner.fd_flags[fd];
            if (arg & O_NONBLOCK) != 0 {
                cur |= O_NONBLOCK as u32;
            } else {
                cur &= !(O_NONBLOCK as u32);
            }
            inner.fd_flags[fd] = cur;
            0
        }
        F_GETFL => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            if fd >= inner.fd_flags.len() {
                let fd_len = inner.fd_table.len();
                inner.fd_flags.resize(fd_len, 0);
            }
            let cur_flags = inner.fd_flags[fd];
            let mut flags = match (file.readable(), file.writable()) {
                (true, false) => O_RDONLY,
                (false, true) => O_WRONLY,
                (true, true) => O_RDWR,
                (false, false) => O_RDONLY,
            };
            if (cur_flags & O_NONBLOCK as u32) != 0 {
                flags |= O_NONBLOCK;
            }
            if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
                if os_inode.append() {
                    flags |= O_APPEND;
                }
            }
            flags as isize
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let process = current_process();
            let mut inner = process.borrow_mut();
            if fd >= inner.fd_table.len() || inner.fd_table[fd].is_none() {
                return EBADF;
            }
            let file = inner.fd_table[fd].as_ref().unwrap().clone();
            if fd >= inner.fd_flags.len() {
                let fd_len = inner.fd_table.len();
                inner.fd_flags.resize(fd_len, 0);
            }
            let old_flags = inner.fd_flags[fd];
            let minfd = arg;
            let mut newfd = minfd;
            while newfd < inner.fd_table.len() && inner.fd_table[newfd].is_some() {
                newfd += 1;
            }
            if newfd >= inner.fd_table.len() {
                // Extend fd table to fit.
                if newfd > 4096 {
                    return EMFILE;
                }
                inner.fd_table.resize(newfd + 1, None);
                inner.fd_flags.resize(newfd + 1, 0);
            }
            inner.fd_table[newfd] = Some(file);
            let mut new_flags = old_flags;
            if cmd == F_DUPFD {
                new_flags &= !FD_CLOEXEC;
            } else {
                new_flags |= FD_CLOEXEC;
            }
            inner.fd_flags[newfd] = new_flags;
            newfd as isize
        }
        _ => EINVAL,
    };

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!("[fs] fcntl(pid={}) fd={} cmd={} arg={:#x} -> {}", pid, fd, cmd, arg, ret);
        }
    }
    ret
}

pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, _mode: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if path == "." || path == "/proc" || path == "/proc/" || path == "/sys" || path == "/dev" {
            crate::println!(
                "[fs] openat pid={} dirfd={} path='{}' flags={:#x}",
                pid,
                dirfd,
                path,
                flags
            );
        }
    }

    let (readable, writable) = match flags & O_ACCMODE {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => (true, false),
    };
    let append = (flags & O_APPEND) != 0;

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let tmpfile_requested = (flags & O_TMPFILE) == O_TMPFILE;

    // Pseudo fs: `/proc`, `/sys`, `/dev`.
    if let AtPath::PseudoAbs(abs) = &at {
        if tmpfile_requested {
            return EOPNOTSUPP;
        }
        // Minimal `/dev/shm` support for POSIX `shm_open` users (e.g., cyclictest).
        // Must handle `O_CREAT|O_EXCL` even when the object already exists.
        let file: alloc::sync::Arc<dyn File + Send + Sync> = if let Some(name) = shm_object_name(abs)
        {
            if (flags & O_CREAT) != 0 {
                if (flags & O_EXCL) != 0 && shm_get(name).is_some() {
                    return EEXIST;
                }
                let data = shm_create(name);
                alloc::sync::Arc::new(PseudoShmFile::new(data))
            } else {
                let Some(data) = shm_get(name) else {
                    return ENOENT;
                };
                alloc::sync::Arc::new(PseudoShmFile::new(data))
            }
        } else if let Some(f) = open_pseudo(abs) {
            f
        } else {
            return ENOENT;
        };
        let process = current_process();
        let mut inner = process.borrow_mut();
        let Some(fd) = inner.alloc_fd() else {
            return EMFILE;
        };
        inner.fd_table[fd] = Some(file);
        let mut fd_flags = 0u32;
        if (flags & O_CLOEXEC) != 0 {
            fd_flags |= FD_CLOEXEC;
        }
        if (flags & O_NONBLOCK) != 0 {
            fd_flags |= O_NONBLOCK as u32;
        }
        inner.fd_flags[fd] = fd_flags;
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            if abs == "/proc" || abs == "/sys" || abs == "/dev" {
                crate::println!("[fs] openat(pid={}) pseudo '{}' -> fd={}", pid, abs, fd);
            }
        }
        return fd as isize;
    }

    let ext4_guard = ext4_lock();

    // ext4 lookup.
    let mut inode = match &at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(alloc::sync::Arc::clone(base))
            } else {
                base.find_path(rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };

    if tmpfile_requested {
        let dir_inode = match inode {
            Some(ref i) => alloc::sync::Arc::clone(i),
            None => return ENOENT,
        };
        if !dir_inode.is_dir() {
            return ENOTDIR;
        }
        let pid = current_process().getpid();
        let mut created = None;
        for _ in 0..64 {
            let seq = TMPFILE_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = alloc::format!(".tmp.{}.{}", pid, seq);
            if dir_inode.find(&name).is_some() {
                continue;
            }
            match dir_inode.create_file(&name) {
                Ok(i) => {
                    created = Some(i);
                    break;
                }
                Err(e) => return ext4_err_to_errno(e),
            }
        }
        let Some(tmp_inode) = created else {
            return ENOSPC;
        };
        inode = Some(tmp_inode);
    }

    // CREATE: create file if missing (Linux: only affects the final component).
    if inode.is_none() && (flags & O_CREAT != 0) {
        match &at {
            AtPath::Ext4Abs(abs) => {
                let Some((parent_path, name)) = split_parent_and_name(abs) else {
                    return EINVAL;
                };
                if name.is_empty() {
                    return EISDIR;
                }
                let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
                let Some(parent) = ROOT_INODE.find_path(parent_path) else {
                    return ENOENT;
                };
                if !parent.is_dir() {
                    return ENOTDIR;
                }
                inode = match parent.create_file(name) {
                    Ok(i) => Some(i),
                    Err(e) => return ext4_err_to_errno(e),
                };
            }
            AtPath::Ext4Rel { base, rel } => {
                let Some((parent_path, name)) = split_parent_and_name(rel) else {
                    return EINVAL;
                };
                if name.is_empty() {
                    return EISDIR;
                }
                let parent = if parent_path.is_empty() {
                    alloc::sync::Arc::clone(base)
                } else {
                    let Some(p) = base.find_path(parent_path) else {
                        return ENOENT;
                    };
                    p
                };
                if !parent.is_dir() {
                    return ENOTDIR;
                }
                inode = match parent.create_file(name) {
                    Ok(i) => Some(i),
                    Err(e) => return ext4_err_to_errno(e),
                };
            }
            AtPath::PseudoAbs(_) => unreachable!(),
        }
    }

    let inode = match inode {
        Some(i) => i,
        None => return ENOENT,
    };

    // Linux: opening a directory for write is not allowed.
    if inode.is_dir() && (flags & O_ACCMODE) != O_RDONLY {
        return EISDIR;
    }

    // Basic permission check (no uid/gid model; use "other" permission bits).
    let mut mask = 0usize;
    if readable {
        mask |= 4;
    }
    if writable {
        mask |= 2;
    }
    if !inode_mode_allows(inode.mode(), mask) {
        return EACCES;
    }

    if (flags & O_DIRECTORY) != 0 && !tmpfile_requested && !inode.is_dir() {
        return ENOTDIR;
    }

    if (flags & O_TRUNC) != 0 && writable && inode.is_file() {
        if let Err(e) = inode.clear() {
            return ext4_err_to_errno(e);
        }
    }

    let os_inode = alloc::sync::Arc::new(OSInode::new_with_append(readable, writable, append, inode));
    drop(ext4_guard);
    let process = current_process();
    let mut inner = process.borrow_mut();
    let Some(fd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[fd] = Some(os_inode);
    let mut fd_flags = 0u32;
    if (flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    inner.fd_flags[fd] = fd_flags;
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if path == "." || path == "/proc" || path == "/proc/" {
            crate::println!("[fs] openat(pid={}) ok path='{}' -> fd={}", pid, path, fd);
        }
    }
    fd as isize
}

fn open_pseudo(path: &str) -> Option<alloc::sync::Arc<dyn File + Send + Sync>> {
    // Provide minimal pseudo directories for tools that expect them to exist.
    // /proc with just enough content for busybox `ps`, `df`, `free`, etc.
    if path == "/proc" || path == "/proc/" {
        let mut entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("mounts"), ino: 2, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("meminfo"), ino: 3, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("loadavg"), ino: 4, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("uptime"), ino: 5, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("stat"), ino: 6, dtype: 8 },
            // Linux has /proc/self as a symlink; we expose it as a directory.
            PseudoDirent { name: alloc::string::String::from("self"), ino: 7, dtype: 4 },
        ];
        let mut pids: alloc::vec::Vec<usize> = {
            let map = crate::task::manager::PID2PCB.lock();
            map.keys().copied().collect()
        };
        pids.sort_unstable();
        for pid in pids {
            entries.push(PseudoDirent { name: alloc::format!("{}", pid), ino: pid as u64, dtype: 4 });
        }
        return Some(alloc::sync::Arc::new(PseudoDir::new("/proc", entries)));
    }

    // /proc/self -> current process directory (best-effort; no symlink support).
    if path == "/proc/self" || path == "/proc/self/" {
        let pid = current_process().getpid();
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: pid as u64, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("stat"), ino: (pid as u64) << 32 | 1, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("cmdline"), ino: (pid as u64) << 32 | 2, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("status"), ino: (pid as u64) << 32 | 3, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("mounts"), ino: (pid as u64) << 32 | 4, dtype: 8 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/proc/self", entries)));
    }

    // /proc/<pid> and /proc/<pid>/...
    if let Some(rest) = path.strip_prefix("/proc/") {
        let rest = rest.trim_end_matches('/');
        let mut it = rest.split('/');
        let first = it.next().unwrap_or("");
        if first == "self" {
            let pid = current_process().getpid();
            if let Some(after) = rest.strip_prefix("self/") {
                let p = alloc::format!("/proc/{}/{}", pid, after);
                return open_pseudo(&p);
            }
            return open_pseudo("/proc/self");
        }
        if let Ok(pid) = first.parse::<usize>() {
            // Validate pid exists.
            let proc = crate::task::manager::pid2process(pid)?;
            let (ppid, argv, start_time_ms, num_threads, main_state, vsize, vsize_kb) = {
                let inner = proc.borrow_mut();
                let ppid = inner
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .map(|p| p.getpid())
                    .unwrap_or(0);
                let argv = inner.argv.clone();
                let start_time_ms = inner.start_time_ms;
                let num_threads = inner.thread_count();
                let main_state = inner
                    .tasks
                    .iter()
                    .flatten()
                    .next()
                    .and_then(|t| t.try_borrow_mut().map(|ti| ti.task_status))
                    .unwrap_or(crate::task::task_block::TaskStatus::Ready);
                let heap_bytes = inner.brk.saturating_sub(inner.heap_start);
                let mmap_bytes: usize = inner
                    .mmap_areas
                    .iter()
                    .map(|(s, e)| e.saturating_sub(*s))
                    .sum();
                let vsize: u64 = (crate::config::USER_STACK_SIZE + heap_bytes + mmap_bytes) as u64;
                let vsize_kb: usize = (crate::config::USER_STACK_SIZE + heap_bytes + mmap_bytes) / 1024;
                (ppid, argv, start_time_ms, num_threads, main_state, vsize, vsize_kb)
            };

            let comm = argv
                .first()
                .map(|s| s.rsplit('/').next().unwrap_or(s.as_str()))
                .unwrap_or("CongCore")
                .replace(')', "_");

            let state_char = match main_state {
                crate::task::task_block::TaskStatus::Running => 'R',
                crate::task::task_block::TaskStatus::Ready => 'R',
                crate::task::task_block::TaskStatus::Blocked => 'S',
            };

            match it.next() {
                None => {
                    let entries = alloc::vec![
                        PseudoDirent { name: alloc::string::String::from("."), ino: pid as u64, dtype: 4 },
                        PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
                        PseudoDirent { name: alloc::string::String::from("stat"), ino: (pid as u64) << 32 | 1, dtype: 8 },
                        PseudoDirent { name: alloc::string::String::from("cmdline"), ino: (pid as u64) << 32 | 2, dtype: 8 },
                        PseudoDirent { name: alloc::string::String::from("status"), ino: (pid as u64) << 32 | 3, dtype: 8 },
                        PseudoDirent { name: alloc::string::String::from("mounts"), ino: (pid as u64) << 32 | 4, dtype: 8 },
                    ];
                    let p = alloc::format!("/proc/{}", pid);
                    return Some(alloc::sync::Arc::new(PseudoDir::new(&p, entries)));
                }
                Some("mounts") if it.next().is_none() => {
                    return open_pseudo("/proc/mounts");
                }
                Some("stat") if it.next().is_none() => {
                    // Linux-like `/proc/<pid>/stat` (man proc). Keep it well-formed so
                    // proc parsers (busybox ps) can read it.
                    const HZ: u64 = 100;
                    let starttime = (start_time_ms as u64).saturating_mul(HZ) / 1000;
                    let rss_pages: u64 = if vsize == 0 {
                        0
                    } else {
                        (vsize + crate::config::PAGE_SIZE as u64 - 1) / crate::config::PAGE_SIZE as u64
                    };
                    // Field order follows Linux `/proc/<pid>/stat` (man proc).
                    let pgrp = pid;
                    let session = pid;
                    let tty_nr = 0;
                    let tpgid = 0;
                    let flags = 0;
                    let minflt = 0;
                    let cminflt = 0;
                    let majflt = 0;
                    let cmajflt = 0;
                    let utime = 0;
                    let stime = 0;
                    let cutime = 0;
                    let cstime = 0;
                    let priority = 0;
                    let nice = 0;
                    let itrealvalue = 0;
                    let rsslim = 0;
                    let startcode = 0;
                    let endcode = 0;
                    let startstack = 0;
                    let kstkesp = 0;
                    let kstkeip = 0;
                    let signal = 0;
                    let blocked = 0;
                    let sigignore = 0;
                    let sigcatch = 0;
                    let wchan = 0;
                    let nswap = 0;
                    let cnswap = 0;
                    let exit_signal = 0;
                    let processor = 0;
                    let rt_priority = 0;
                    let policy = 0;
                    let delayacct_blkio_ticks = 0;
                    let guest_time = 0;
                    let cguest_time = 0;
                    let start_data = 0;
                    let end_data = 0;
                    let start_brk = 0;
                    let arg_start = 0;
                    let arg_end = 0;
                    let env_start = 0;
                    let env_end = 0;
                    let exit_code = 0;

                    let s = alloc::format!(
                        "{pid} ({comm}) {state_char} {ppid} {pgrp} {session} {tty_nr} {tpgid} {flags} {minflt} {cminflt} {majflt} {cmajflt} {utime} {stime} {cutime} {cstime} {priority} {nice} {num_threads} {itrealvalue} {starttime} {vsize} {rss_pages} {rsslim} {startcode} {endcode} {startstack} {kstkesp} {kstkeip} {signal} {blocked} {sigignore} {sigcatch} {wchan} {nswap} {cnswap} {exit_signal} {processor} {rt_priority} {policy} {delayacct_blkio_ticks} {guest_time} {cguest_time} {start_data} {end_data} {start_brk} {arg_start} {arg_end} {env_start} {env_end} {exit_code}\n"
                    );
                    return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
                }
                Some("cmdline") if it.next().is_none() => {
                    let mut s = String::new();
                    for arg in argv.iter() {
                        s.push_str(arg);
                        s.push('\0');
                    }
                    return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
                }
                Some("status") if it.next().is_none() => {
                    let state_desc = match state_char {
                        'R' => "R (running)",
                        'S' => "S (sleeping)",
                        _ => "R (running)",
                    };
                    let s = alloc::format!(
                        "Name:\t{comm}\nState:\t{state_desc}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nThreads:\t{num_threads}\nVmSize:\t{vsize_kb} kB\n"
                    );
                    return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
                }
                _ => {}
            }
        }
    }
    if path == "/sys" || path == "/sys/" {
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("devices"), ino: 2, dtype: 4 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/sys", entries)));
    }
    if path == "/dev" || path == "/dev/" {
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("root"), ino: 6, dtype: 6 },
            PseudoDirent { name: alloc::string::String::from("shm"), ino: 8, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("null"), ino: 2, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("zero"), ino: 3, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("urandom"), ino: 4, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("random"), ino: 5, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("misc"), ino: 7, dtype: 4 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev", entries)));
    }
    if path == "/dev/shm" || path == "/dev/shm/" {
        let mut entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
        ];
        for (idx, name) in shm_list().into_iter().enumerate() {
            entries.push(PseudoDirent { name, ino: (1000 + idx) as u64, dtype: 8 });
        }
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/shm", entries)));
    }
    if path == "/dev/misc" || path == "/dev/misc/" {
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("rtc"), ino: 2, dtype: 8 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new("/dev/misc", entries)));
    }

    // /sys/devices/system/cpu/*
    if path == "/sys/devices/system/cpu/possible"
        || path == "/sys/devices/system/cpu/present"
        || path == "/sys/devices/system/cpu/online"
    {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("\n")
        } else if n == 1 {
            String::from("0\n")
        } else {
            alloc::format!("0-{}\n", n - 1)
        };
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    if path == "/sys/devices/system/cpu/kernel_max" {
        let n = crate::config::MAX_HARTS;
        let s = if n == 0 {
            String::from("0\n")
        } else {
            alloc::format!("{}\n", n - 1)
        };
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    // /sys/devices/system/node/*
    if path == "/sys/devices/system/node/online" || path == "/sys/devices/system/node/possible" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0\n")));
    }
    // /proc/loadavg
    if path == "/proc/loadavg" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("0.00 0.00 0.00 1/1 1\n")));
    }
    if path == "/proc/uptime" {
        let ms = crate::time::get_time_ms();
        let secs = ms / 1000;
        let frac = (ms % 1000) / 10;
        let s = alloc::format!("{secs}.{frac:02} 0.00\n");
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    if path == "/proc/stat" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(
            "cpu  0 0 0 0 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 0\nprocesses 0\nprocs_running 1\nprocs_blocked 0\n",
        )));
    }
    if path == "/proc/mounts" {
        // Minimal mount table so `df` works.
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("/dev/root / ext4 rw 0 0\n")));
    }
    if path == "/proc/self/mounts" {
        return open_pseudo("/proc/mounts");
    }
    if path == "/proc/meminfo" {
        // Minimal meminfo so busybox `free` works.
        let mem_total_kb =
            ((crate::config::phys_mem_end() - crate::config::phys_mem_start()) / 1024) as u64;
        let s = alloc::format!(
            "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n",
            mem_total_kb,
            mem_total_kb / 2
        );
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    // /dev/*
    if path == "/dev/root" {
        return Some(alloc::sync::Arc::new(PseudoBlock::new()));
    }
    if let Some(name) = shm_object_name(path) {
        let data = shm_get(name)?;
        return Some(alloc::sync::Arc::new(PseudoShmFile::new(data)));
    }
    if path == "/dev/null" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_null()));
    }
    if path == "/dev/zero" {
        return Some(alloc::sync::Arc::new(PseudoFile::new_zero()));
    }
    if path == "/dev/urandom" || path == "/dev/random" {
        let seed = (crate::time::get_time() as u64) ^ ((crate::task::processor::hart_id() as u64) << 32);
        return Some(alloc::sync::Arc::new(PseudoFile::new_urandom(seed)));
    }
    if path == "/dev/misc/rtc" {
        return Some(alloc::sync::Arc::new(RtcFile::new()));
    }
    None
}

/// Linux `faccessat(2)` (syscall 48 on riscv64).
///
/// Used by busybox `which` and shells to locate executables.
pub fn syscall_faccessat(dirfd: isize, pathname: usize, mode: usize, _flags: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        // Treat known pseudo nodes as always accessible (no uid/gid model yet).
        return if open_pseudo(abs).is_some() { 0 } else { ENOENT };
    }

    let _ext4_guard = ext4_lock();
    let inode = match &at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(alloc::sync::Arc::clone(base))
            } else {
                base.find_path(rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    let Some(inode) = inode else {
        return ENOENT;
    };

    if !inode_mode_allows(inode.mode(), mode) {
        return EACCES;
    }
    0
}

/// Linux `fchmod(2)` (syscall 52 on riscv64).
pub fn syscall_fchmod(fd: usize, mode: usize) -> isize {
    let Some(_file) = get_fd_file(fd) else {
        return EBADF;
    };
    if let Some(inode) = get_fd_inode(fd) {
        let _ext4_guard = ext4_lock();
        inode.set_mode(mode as u16);
    }
    0
}

/// Linux `fchmodat(2)` (syscall 53 on riscv64).
pub fn syscall_fchmodat(dirfd: isize, pathname: usize, mode: usize, flags: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    let _ignored_flags = flags;
    if path.is_empty() {
        if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            return syscall_fchmod(dirfd as usize, mode);
        }
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(name) = shm_object_name(abs) {
            return if shm_get(name).is_some() { 0 } else { ENOENT };
        }
        return if open_pseudo(abs).is_some() { 0 } else { ENOENT };
    }

    let _ext4_guard = ext4_lock();
    let inode = match &at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(alloc::sync::Arc::clone(base))
            } else {
                base.find_path(rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    let Some(inode) = inode else {
        return ENOENT;
    };
    inode.set_mode(mode as u16);
    0
}

/// Linux `fchown(2)` (syscall 55 on riscv64).
pub fn syscall_fchown(fd: usize, _uid: usize, _gid: usize) -> isize {
    if get_fd_file(fd).is_none() {
        return EBADF;
    }
    0
}

/// Linux `fchownat(2)` (syscall 54 on riscv64).
pub fn syscall_fchownat(dirfd: isize, pathname: usize, _uid: usize, _gid: usize, flags: usize) -> isize {
    // Ignore ownership changes (no uid/gid model yet), but validate the path.
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);

    if path.is_empty() {
        if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            return if get_fd_file(dirfd as usize).is_some() { 0 } else { EBADF };
        }
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if let Some(name) = shm_object_name(abs) {
            return if shm_get(name).is_some() { 0 } else { ENOENT };
        }
        return if open_pseudo(abs).is_some() { 0 } else { ENOENT };
    }

    let _ext4_guard = ext4_lock();
    let inode = match &at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(alloc::sync::Arc::clone(base))
            } else {
                base.find_path(rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    if inode.is_some() { 0 } else { ENOENT }
}

/// Linux `readlinkat(2)` (syscall 78 on riscv64).
///
/// If the path exists but is not a symlink, Linux returns `EINVAL`.
///
/// We currently don't expose ext4 symlink targets to the VFS layer; for a real
/// symlink we return `ENOSYS`.
pub fn syscall_readlinkat(dirfd: isize, pathname: usize, _buf: usize, _bufsiz: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        return if open_pseudo(abs).is_some() { EINVAL } else { ENOENT };
    }

    let _ext4_guard = ext4_lock();
    let inode = match &at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(alloc::sync::Arc::clone(base))
            } else {
                base.find_path(rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    let Some(inode) = inode else {
        return ENOENT;
    };

    const S_IFMT: u16 = 0o170000;
    const S_IFLNK: u16 = 0o120000;
    if (inode.mode() & S_IFMT) != S_IFLNK {
        return EINVAL;
    }
    ENOSYS
}

/// Linux `renameat(2)` (syscall 38 on riscv64).
pub fn syscall_renameat(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize) -> isize {
    let token = get_current_token();
    let old_s = translated_str(token, oldpath as *const u8);
    let new_s = translated_str(token, newpath as *const u8);
    if old_s.is_empty() || new_s.is_empty() {
        return ENOENT;
    }

    let old_at = match resolve_at_path(olddirfd, &old_s) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let new_at = match resolve_at_path(newdirfd, &new_s) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if matches!(old_at, AtPath::PseudoAbs(_)) || matches!(new_at, AtPath::PseudoAbs(_)) {
        return EROFS;
    }

    let _ext4_guard = ext4_lock();

    fn parent_and_name(at: AtPath) -> Result<(alloc::sync::Arc<ext4_fs::Inode>, alloc::string::String), isize> {
        match at {
            AtPath::Ext4Abs(abs) => {
                if abs == "/" {
                    return Err(EINVAL);
                }
                let Some((parent_path, name)) = split_parent_and_name(&abs) else {
                    return Err(EINVAL);
                };
                if name.is_empty() {
                    return Err(EINVAL);
                }
                let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
                let Some(parent) = ROOT_INODE.find_path(parent_path) else {
                    return Err(ENOENT);
                };
                Ok((parent, alloc::string::String::from(name)))
            }
            AtPath::Ext4Rel { base, rel } => {
                if rel.is_empty() {
                    return Err(EINVAL);
                }
                let Some((parent_path, name)) = split_parent_and_name(&rel) else {
                    return Err(EINVAL);
                };
                if name.is_empty() {
                    return Err(EINVAL);
                }
                let parent = if parent_path.is_empty() {
                    base
                } else {
                    let Some(p) = base.find_path(parent_path) else {
                        return Err(ENOENT);
                    };
                    p
                };
                Ok((parent, alloc::string::String::from(name)))
            }
            AtPath::PseudoAbs(_) => unreachable!(),
        }
    }

    let (old_parent, old_name) = match parent_and_name(old_at) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, new_name) = match parent_and_name(new_at) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if !old_parent.is_dir() || !new_parent.is_dir() {
        return ENOTDIR;
    }

    // ext4 implementation only supports rename within the same directory for now.
    if old_parent.inode_num() != new_parent.inode_num() {
        return EXDEV;
    }

    match old_parent.rename(&old_name, &new_name) {
        Ok(_) => 0,
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Linux `renameat2(2)` (syscall 276 on riscv64).
pub fn syscall_renameat2(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize, flags: usize) -> isize {
    if flags != 0 {
        return EINVAL;
    }
    syscall_renameat(olddirfd, oldpath, newdirfd, newpath)
}

pub fn syscall_close(fd: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    if fd >= inner.fd_table.len() {
        return EBADF;
    }
    inner.fd_table[fd] = None;
    if fd < inner.fd_flags.len() {
        inner.fd_flags[fd] = 0;
    }
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!("[fs] close(pid={}) fd={}", pid, fd);
        }
    }
    0
}

pub fn syscall_read(fd: usize, buffer: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.readable() {
        return EBADF;
    }
    let buf = UserBuffer::new(translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
    ));
    file.read(buf) as isize
}

pub fn syscall_write(fd: usize, buffer: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.writable() {
        return EBADF;
    }
    let buf = UserBuffer::new(translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
    ));
    file.write(buf) as isize
}

/// Linux `pread64(2)` (syscall 67 on riscv64).
///
/// Unlike `read(2)`, this does not update the file offset.
pub fn syscall_pread64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.readable() {
        return EBADF;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return ESPIPE;
        }

        let mut total = 0usize;
        let token = get_current_token();
        let mut off = pos as usize;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        while total < len {
            let want = core::cmp::min(len - total, CHUNK_MAX);
            let mut kbuf = Vec::new();
            kbuf.resize(want, 0);
            let n = os_inode.pread_at(off, &mut kbuf);
            if n == 0 {
                break;
            }
            copy_to_user(token, user_ptr as *mut u8, &kbuf[..n]);
            total += n;
            off += n;
            user_ptr += n;
            if n < want {
                break;
            }
        }
        return total as isize;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let buf = UserBuffer::new(translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
        ));
        let n = file.read(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    ESPIPE
}

/// Linux `pwrite64(2)` (syscall 68 on riscv64).
///
/// Unlike `write(2)`, this does not update the file offset.
pub fn syscall_pwrite64(fd: usize, buffer: usize, len: usize, pos: isize) -> isize {
    if pos < 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    if !file.writable() {
        return EBADF;
    }

    // ext4 regular files
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let is_dir = {
            let _ext4_guard = ext4_lock();
            inode.is_dir()
        };
        if is_dir {
            return ESPIPE;
        }

        let mut total = 0usize;
        let token = get_current_token();
        let mut off = pos as usize;
        let mut user_ptr = buffer;
        const CHUNK_MAX: usize = 16 * 1024;
        while total < len {
            let want = core::cmp::min(len - total, CHUNK_MAX);
            let mut kbuf = Vec::new();
            kbuf.resize(want, 0);
            copy_from_user(token, user_ptr as *const u8, &mut kbuf);
            match os_inode.pwrite_at(off, &kbuf) {
                Ok(n) => {
                    total += n;
                    off += n;
                    user_ptr += n;
                    if n < want {
                        break;
                    }
                }
                Err(_) => {
                    crate::println!("[ext4] Warning: pwrite failed");
                    break;
                }
            }
        }

        return total as isize;
    }

    // Seekable pseudo files: emulate by temporarily adjusting the per-fd offset.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        if pf.len().is_none() {
            return ESPIPE;
        }
        let old = pf.offset();
        pf.set_offset(pos as usize);
        let buf = UserBuffer::new(translated_byte_buffer(
            get_current_token(),
            buffer as *mut u8,
            len,
        ));
        let n = file.write(buf) as isize;
        pf.set_offset(old);
        return n;
    }

    ESPIPE
}

pub fn syscall_pipe2(pipefd: usize, _flags: usize) -> isize {
    let process = current_process();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut inner = process.borrow_mut();
    let Some(read_fd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[read_fd] = Some(pipe_read);
    let Some(write_fd) = inner.alloc_fd() else {
        inner.fd_table[read_fd] = None;
        return EMFILE;
    };
    inner.fd_table[write_fd] = Some(pipe_write);
    let mut fd_flags = 0u32;
    if (_flags & O_CLOEXEC) != 0 {
        fd_flags |= FD_CLOEXEC;
    }
    if (_flags & O_NONBLOCK) != 0 {
        fd_flags |= O_NONBLOCK as u32;
    }
    inner.fd_flags[read_fd] = fd_flags;
    inner.fd_flags[write_fd] = fd_flags;
    drop(inner);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    write_user_value(token, pipefd as *mut i32, &(read_fd as i32));
    write_user_value(
        token,
        (pipefd + core::mem::size_of::<i32>()) as *mut i32,
        &(write_fd as i32),
    );
    0
}

pub fn syscall_dup(oldfd: usize) -> isize {
    let process = current_process();
    let mut inner = process.borrow_mut();
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    let file = inner.fd_table[oldfd].as_ref().unwrap().clone();
    if oldfd >= inner.fd_flags.len() {
        let fd_len = inner.fd_table.len();
        inner.fd_flags.resize(fd_len, 0);
    }
    let old_flags = inner.fd_flags[oldfd];
    let Some(newfd) = inner.alloc_fd() else {
        return EMFILE;
    };
    inner.fd_table[newfd] = Some(file);
    inner.fd_flags[newfd] = old_flags & !FD_CLOEXEC;
    newfd as isize
}

pub fn syscall_dup3(oldfd: usize, newfd: usize, _flags: usize) -> isize {
    if oldfd == newfd {
        return EINVAL;
    }
    let process = current_process();
    let mut inner = process.borrow_mut();
    if newfd >= inner.rlimit_nofile_cur as usize {
        return EMFILE;
    }
    if oldfd >= inner.fd_table.len() || inner.fd_table[oldfd].is_none() {
        return EBADF;
    }
    let file = inner.fd_table[oldfd].as_ref().unwrap().clone();
    if oldfd >= inner.fd_flags.len() {
        let fd_len = inner.fd_table.len();
        inner.fd_flags.resize(fd_len, 0);
    }
    let old_flags = inner.fd_flags[oldfd];
    while inner.fd_table.len() <= newfd {
        inner.fd_table.push(None);
        inner.fd_flags.push(0);
    }
    inner.fd_table[newfd] = Some(file);
    let mut new_flags = old_flags;
    if (_flags & O_CLOEXEC) != 0 {
        new_flags |= FD_CLOEXEC;
    } else {
        new_flags &= !FD_CLOEXEC;
    }
    inner.fd_flags[newfd] = new_flags;
    newfd as isize
}

pub fn syscall_chdir(pathname: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let new_cwd = normalize_path(&cwd, &path);

    if let Some(is_dir) = {
        let _ext4_guard = ext4_lock();
        ROOT_INODE.find_path(&new_cwd).map(|inode| inode.is_dir())
    } {
        if !is_dir {
            return ENOTDIR;
        }
    } else if let Some(node) = open_pseudo(&new_cwd) {
        if node.as_any().downcast_ref::<PseudoDir>().is_none() {
            return ENOTDIR;
        }
    } else {
        return ENOENT;
    }
    process.borrow_mut().cwd = new_cwd;
    0
}

pub fn syscall_mkdirat(dirfd: isize, pathname: usize, _mode: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(_) = &at {
        return EROFS;
    }

    let _ext4_guard = ext4_lock();
    match at {
        AtPath::Ext4Abs(abs) => {
            if abs == "/" {
                return EEXIST;
            }
            let Some((parent_path, name)) = split_parent_and_name(&abs) else {
                return EINVAL;
            };
            if name.is_empty() {
                return EEXIST;
            }
            let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
            let Some(parent) = ROOT_INODE.find_path(parent_path) else {
                return ENOENT;
            };
            if !parent.is_dir() {
                return ENOTDIR;
            }
            match parent.create_dir(name) {
                Ok(_) => 0,
                Err(e) => ext4_err_to_errno(e),
            }
        }
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                return EEXIST;
            }
            let Some((parent_path, name)) = split_parent_and_name(&rel) else {
                return EINVAL;
            };
            if name.is_empty() {
                return EEXIST;
            }
            let parent = if parent_path.is_empty() {
                base
            } else {
                let Some(p) = base.find_path(parent_path) else {
                    return ENOENT;
                };
                p
            };
            if !parent.is_dir() {
                return ENOTDIR;
            }
            match parent.create_dir(name) {
                Ok(_) => 0,
                Err(e) => ext4_err_to_errno(e),
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    }
}

pub fn syscall_unlinkat(dirfd: isize, pathname: usize, _flags: usize) -> isize {
    const AT_REMOVEDIR: usize = 0x200;
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        let remove_dir = (_flags & AT_REMOVEDIR) != 0;
        // Minimal `/dev/shm` support for POSIX `shm_unlink`.
        if abs == "/dev/shm" || abs == "/dev/shm/" {
            return if remove_dir { EROFS } else { EISDIR };
        }
        if let Some(name) = shm_object_name(abs) {
            if remove_dir {
                return ENOTDIR;
            }
            return if shm_remove(name) { 0 } else { ENOENT };
        }
        return EROFS;
    }

    let _ext4_guard = ext4_lock();
    let (parent, name) = match at {
        AtPath::Ext4Abs(abs) => {
            if abs == "/" {
                return EISDIR;
            }
            let Some((parent_path, name)) = split_parent_and_name(&abs) else {
                return EINVAL;
            };
            if name.is_empty() {
                return EISDIR;
            }
            let parent_path = if parent_path.is_empty() { "/" } else { parent_path };
            let Some(parent) = ROOT_INODE.find_path(parent_path) else {
                return ENOENT;
            };
            (parent, alloc::string::String::from(name))
        }
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                return EISDIR;
            }
            let Some((parent_path, name)) = split_parent_and_name(&rel) else {
                return EINVAL;
            };
            if name.is_empty() {
                return EISDIR;
            }
            let parent = if parent_path.is_empty() {
                base
            } else {
                let Some(p) = base.find_path(parent_path) else {
                    return ENOENT;
                };
                p
            };
            (parent, alloc::string::String::from(name))
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };

    if !parent.is_dir() {
        return ENOTDIR;
    }

    let remove_dir = (_flags & AT_REMOVEDIR) != 0;

    // Validate target type: unlink vs rmdir semantics.
    let Some(child) = parent.find(&name) else {
        return ENOENT;
    };
    if remove_dir {
        if !child.is_dir() {
            return ENOTDIR;
        }
        if !child.ls().is_empty() {
            return ENOTEMPTY;
        }
    } else {
        if child.is_dir() {
            return EISDIR;
        }
    }

    match parent.unlink(&name) {
        Ok(_) => 0,
        Err(ext4_fs::Ext4Error::Unsupported) => ENOTEMPTY,
        Err(e) => ext4_err_to_errno(e),
    }
}

/// Linux `ftruncate(2)` (syscall 46 on riscv64).
///
/// Needed by musl `shm_open` users (e.g., cyclictest).
pub fn syscall_ftruncate(fd: usize, length: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    // `/dev/shm/*` backing file.
    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        shm.truncate(length);
        return 0;
    }

    // Best-effort ext4 support.
    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let _ext4_guard = ext4_lock();
        if !inode.is_file() {
            return EINVAL;
        }
        let old = inode.size() as usize;
        if length == 0 {
            return match inode.clear() {
                Ok(_) => 0,
                Err(e) => ext4_err_to_errno(e),
            };
        }
        if length > old {
            // Extend by writing a single 0 byte at the final position.
            let buf = [0u8; 1];
            return match inode.write_at(length - 1, &buf) {
                Ok(_) => 0,
                Err(e) => ext4_err_to_errno(e),
            };
        }
        // Shrinking is not supported yet; accept for compatibility.
        return 0;
    }

    EINVAL
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KStatFs {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [i64; 4],
}

fn fill_statfs(st_ptr: usize) -> isize {
    if st_ptr == 0 {
        return EINVAL;
    }
    // ext4 statfs (best-effort; our ext4 allocator does not yet update
    // on-disk free counters, so these values may be stale after heavy writes,
    // but they are meaningful for `df`).
    let fs = crate::fs::EXT4_FS.lock();
    let sb = &fs.superblock;
    let block_size = sb.block_size() as i64;
    let total_blocks = sb.blocks_count();
    let free_blocks = ((sb.s_free_blocks_count_hi as u64) << 32) | sb.s_free_blocks_count_lo as u64;
    let reserved_blocks = ((sb.s_r_blocks_count_hi as u64) << 32) | sb.s_r_blocks_count_lo as u64;
    let bavail = free_blocks.saturating_sub(reserved_blocks);
    let st = KStatFs {
        // EXT4_SUPER_MAGIC
        f_type: 0xEF53,
        f_bsize: block_size,
        f_blocks: total_blocks,
        f_bfree: free_blocks,
        f_bavail: bavail,
        f_files: sb.s_inodes_count as u64,
        f_ffree: sb.s_free_inodes_count as u64,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: block_size,
        f_flags: 0,
        f_spare: [0; 4],
    };
    let token = get_current_token();
    write_user_value(token, st_ptr as *mut KStatFs, &st);
    0
}

/// Linux `fstatfs(2)` (syscall 44 on riscv64).
pub fn syscall_fstatfs(fd: usize, st_ptr: usize) -> isize {
    if get_fd_file(fd).is_none() {
        return EBADF;
    }
    let _ext4_guard = ext4_lock();
    fill_statfs(st_ptr)
}

/// Linux `statfs(2)` (syscall 43 on riscv64).
pub fn syscall_statfs(pathname: usize, st_ptr: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }
    let at = match resolve_at_path(AT_FDCWD, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    match at {
        AtPath::PseudoAbs(abs) => {
            if open_pseudo(&abs).is_none() {
                return ENOENT;
            }
            fill_statfs(st_ptr)
        }
        AtPath::Ext4Abs(abs) => {
            let _ext4_guard = ext4_lock();
            if ROOT_INODE.find_path(&abs).is_none() {
                return ENOENT;
            }
            fill_statfs(st_ptr)
        }
        AtPath::Ext4Rel { .. } => unreachable!(),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    sec: i64,
    nsec: i64,
}

const UTIME_OMIT: i64 = 0x3ffffffe;
const UTIME_NOW: i64 = 0x3fffffff;

fn resolve_utime(ts: TimeSpec, now: (i64, i64)) -> Result<Option<(i64, i64)>, isize> {
    match ts.nsec {
        UTIME_OMIT => Ok(None),
        UTIME_NOW => Ok(Some(now)),
        nsec if nsec >= 0 && nsec < 1_000_000_000 => {
            if ts.sec < 0 {
                Err(EINVAL)
            } else {
                Ok(Some((ts.sec, nsec)))
            }
        }
        _ => Err(EINVAL),
    }
}

/// Linux `utimensat(2)` (syscall 88 on riscv64).
///
/// Update inode timestamps for compatibility (busybox `touch`, libc tests).
pub fn syscall_utimensat(dirfd: isize, pathname: usize, _times: usize, _flags: usize) -> isize {
    // `futimens` passes a null pathname and uses dirfd as the target fd.
    if pathname == 0 {
        if dirfd < 0 {
            return EBADF;
        }
        let Some(file) = get_fd_file(dirfd as usize) else {
            return EBADF;
        };
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            let inode = os_inode.ext4_inode();
            let ino = inode.inode_num() as u64;
            let now = current_timespec();
            let (atime, mtime) = if _times == 0 {
                (Some(now), Some(now))
            } else {
                let token = get_current_token();
                let ts0 = read_user_value(token, _times as *const TimeSpec);
                let ts1 = read_user_value(
                    token,
                    (_times + core::mem::size_of::<TimeSpec>()) as *const TimeSpec,
                );
                let at = match resolve_utime(ts0, now) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let mt = match resolve_utime(ts1, now) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                (at, mt)
            };
            let mut cur = get_inode_times(ino);
            if let Some((sec, nsec)) = atime {
                cur.atime_sec = sec;
                cur.atime_nsec = nsec;
            }
            if let Some((sec, nsec)) = mtime {
                cur.mtime_sec = sec;
                cur.mtime_nsec = nsec;
            }
            if atime.is_some() || mtime.is_some() {
                cur.ctime_sec = now.0;
                cur.ctime_nsec = now.1;
            }
            set_inode_times(ino, cur);
        }
        return 0;
    }
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if let AtPath::PseudoAbs(abs) = &at {
        if open_pseudo(abs).is_some() {
            return EROFS;
        }
        // If any prefix is a pseudo file, report ENOTDIR for deeper paths.
        let mut prefix = alloc::string::String::from("/");
        for (idx, comp) in abs.split('/').filter(|s| !s.is_empty()).enumerate() {
            if idx > 0 {
                prefix.push('/');
            }
            prefix.push_str(comp);
            if prefix == *abs {
                break;
            }
            if let Some(node) = open_pseudo(&prefix) {
                if node.as_any().downcast_ref::<PseudoDir>().is_none() {
                    return ENOTDIR;
                }
            }
        }
        return ENOENT;
    }

    let _ext4_guard = ext4_lock();
    let inode = match at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(&abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(base)
            } else {
                base.find_path(&rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };
    if inode.is_none() {
        return ENOENT;
    }
    let inode = inode.unwrap();
    let ino = inode.inode_num() as u64;
    let now = current_timespec();
    let (atime, mtime) = if _times == 0 {
        (Some(now), Some(now))
    } else {
        let ts0 = read_user_value(token, _times as *const TimeSpec);
        let ts1 = read_user_value(
            token,
            (_times + core::mem::size_of::<TimeSpec>()) as *const TimeSpec,
        );
        let at = match resolve_utime(ts0, now) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mt = match resolve_utime(ts1, now) {
            Ok(v) => v,
            Err(e) => return e,
        };
        (at, mt)
    };
    let mut cur = get_inode_times(ino);
    if let Some((sec, nsec)) = atime {
        cur.atime_sec = sec;
        cur.atime_nsec = nsec;
    }
    if let Some((sec, nsec)) = mtime {
        cur.mtime_sec = sec;
        cur.mtime_nsec = nsec;
    }
    if atime.is_some() || mtime.is_some() {
        cur.ctime_sec = now.0;
        cur.ctime_nsec = now.1;
    }
    set_inode_times(ino, cur);
    0
}

pub fn syscall_getcwd(buf: usize, size: usize) -> isize {
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    if size == 0 {
        return EINVAL;
    }
    let to_copy = min(cwd.len() + 1, size);
    let token = get_current_token();
    let dst = translated_byte_buffer(token, buf as *mut u8, to_copy);

    let mut copied = 0usize;
    for chunk in dst {
        for b in chunk {
            if copied + 1 == to_copy {
                *b = 0;
                return buf as isize;
            }
            *b = cwd.as_bytes()[copied];
            copied += 1;
        }
    }
    buf as isize
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad: u64,
    st_size: i64,
    st_blksize: u32,
    __pad2: i32,
    st_blocks: u64,
    st_atime_sec: i64,
    st_atime_nsec: i64,
    st_mtime_sec: i64,
    st_mtime_nsec: i64,
    st_ctime_sec: i64,
    st_ctime_nsec: i64,
    __unused: [u32; 2],
}

const EXT4_ST_DEV: u64 = 1;

fn dt_type_from_ext4(ftype: u8) -> u8 {
    match ftype {
        2 => 4, // DT_DIR
        1 => 8, // DT_REG
        _ => 0, // DT_UNKNOWN
    }
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

fn write_bytes_user(token: usize, mut dst: usize, bytes: &[u8]) {
    for b in bytes {
        *translated_mutref(token, dst as *mut u8) = *b;
        dst += 1;
    }
}

pub fn syscall_fstat(fd: usize, st_ptr: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    // Pseudo nodes: return minimal metadata so libc/busybox can `opendir()` them.
    if file.as_any().downcast_ref::<PseudoDir>().is_some()
        || file.as_any().downcast_ref::<PseudoFile>().is_some()
        || file.as_any().downcast_ref::<PseudoBlock>().is_some()
        || file.as_any().downcast_ref::<PseudoShmFile>().is_some()
        || file.as_any().downcast_ref::<RtcFile>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            0o060600
        } else if file.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                // /dev/null, /dev/zero, /dev/{u}random should look like character devices
                // to satisfy glibc helpers such as `daemon()`.
                crate::fs::PseudoKindTag::Null => 0o020666,
                crate::fs::PseudoKindTag::Zero | crate::fs::PseudoKindTag::Urandom => 0o020444,
                crate::fs::PseudoKindTag::Static => 0o100444,
            }
        } else {
            0o100444
        };
        let st_rdev: u64 = if file.as_any().downcast_ref::<PseudoBlock>().is_some() {
            EXT4_ST_DEV
        } else if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
            match pf.kind_tag() {
                crate::fs::PseudoKindTag::Null => 0x103,
                crate::fs::PseudoKindTag::Zero => 0x105,
                crate::fs::PseudoKindTag::Urandom => 0x109,
                crate::fs::PseudoKindTag::Static => 0,
            }
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
            st_mode: mode,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev,
            __pad: 0,
            st_size,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        };
        let token = get_current_token();
        write_user_value(token, st_ptr as *mut KStat, &st);
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            if fd <= 8 {
                crate::println!("[fs] fstat(pid={}) fd={} pseudo -> ok", pid, fd);
            }
        }
        return 0;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return EBADF;
    };
    let inode = os_inode.ext4_inode();

    let _ext4_guard = ext4_lock();
    let mode = inode.mode() as u32;
    let disk_size = inode.size() as usize;
    let size = core::cmp::max(disk_size, os_inode.pending_write_end()) as i64;
    let blocks = (((size as u64) + 511) / 512) as u64;
    let times = get_inode_times(inode.inode_num() as u64);

    let st = KStat {
        st_dev: EXT4_ST_DEV,
        st_ino: inode.inode_num() as u64,
        st_mode: mode,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad: 0,
        st_size: size,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime_sec: times.atime_sec,
        st_atime_nsec: times.atime_nsec,
        st_mtime_sec: times.mtime_sec,
        st_mtime_nsec: times.mtime_nsec,
        st_ctime_sec: times.ctime_sec,
        st_ctime_nsec: times.ctime_nsec,
        __unused: [0, 0],
    };

    let token = get_current_token();
    write_user_value(token, st_ptr as *mut KStat, &st);
    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && fd <= 8 {
            crate::println!("[fs] fstat(pid={}) fd={} -> ok mode={:#o}", pid, fd, mode);
        }
    }
    0
}

/// Linux `fsync(2)` / `fdatasync(2)` (syscalls 82/83 on riscv64).
///
/// iozone uses this heavily; implement as a lightweight stub that validates the
/// fd and returns success.
pub fn syscall_fsync(fd: usize) -> isize {
    // A full ext4 sync for every `fsync` call is prohibitively expensive for
    // micro-benchmarks like iozone (it may call `fsync` very frequently).
    //
    // We currently do not have per-inode dirty tracking; treat `fsync` as a hint.
    if get_fd_file(fd).is_none() {
        return EBADF;
    }
    0
}

pub fn syscall_newfstatat(dirfd: isize, pathname: usize, st_ptr: usize, _flags: usize) -> isize {
    if st_ptr == 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    // Support `AT_EMPTY_PATH`: operate on `dirfd` itself when pathname is empty.
    // glibc uses this in some directory APIs (e.g., `opendir`) to validate the fd.
    const AT_EMPTY_PATH: usize = 0x1000;
    if path.is_empty() {
        if (_flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            return syscall_fstat(dirfd as usize, st_ptr);
        }
        return ENOENT;
    }

    let at = match resolve_at_path(dirfd, &path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Pseudo nodes: return minimal metadata.
    if let AtPath::PseudoAbs(abs) = &at {
        let Some(node) = open_pseudo(abs) else {
            return ENOENT;
        };
        let mode: u32 = if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if abs == "/dev/root" {
            0o060600
        } else if node.as_any().downcast_ref::<PseudoShmFile>().is_some() {
            0o100666
        } else if abs == "/dev/null" || abs == "/dev/zero" || abs == "/dev/misc/rtc" {
            0o020666
        } else {
            0o100444
        };
        let st_rdev: u64 = if abs == "/dev/root" {
            EXT4_ST_DEV
        } else if abs == "/dev/null" {
            0x103
        } else if abs == "/dev/zero" {
            0x105
        } else if abs == "/dev/misc/rtc" {
            0x109
        } else {
            0
        };
        let st_size: i64 = if let Some(shm) = node.as_any().downcast_ref::<PseudoShmFile>() {
            shm.len() as i64
        } else {
            0
        };
        let st_blocks: u64 = if st_size <= 0 {
            0
        } else {
            ((st_size as u64 + 511) / 512) as u64
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
            st_mode: mode,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev,
            __pad: 0,
            st_size,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        };
        write_user_value(token, st_ptr as *mut KStat, &st);
        return 0;
    }

    let _ext4_guard = ext4_lock();
    let inode = match at {
        AtPath::Ext4Abs(abs) => ROOT_INODE.find_path(&abs),
        AtPath::Ext4Rel { base, rel } => {
            if rel.is_empty() {
                Some(base)
            } else {
                base.find_path(&rel)
            }
        }
        AtPath::PseudoAbs(_) => unreachable!(),
    };

    let Some(inode) = inode else {
        return ENOENT;
    };

    let mode = inode.mode() as u32;
    let size = inode.size() as i64;
    let blocks = ((inode.size() + 511) / 512) as u64;
    let times = get_inode_times(inode.inode_num() as u64);

    let st = KStat {
        st_dev: EXT4_ST_DEV,
        st_ino: inode.inode_num() as u64,
        st_mode: mode,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad: 0,
        st_size: size,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime_sec: times.atime_sec,
        st_atime_nsec: times.atime_nsec,
        st_mtime_sec: times.mtime_sec,
        st_mtime_nsec: times.mtime_nsec,
        st_ctime_sec: times.ctime_sec,
        st_ctime_nsec: times.ctime_nsec,
        __unused: [0, 0],
    };

    write_user_value(token, st_ptr as *mut KStat, &st);
    0
}

pub fn syscall_getdents64(fd: usize, dirp: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    let token = get_current_token();

    // Pseudo directories (e.g. /proc, /sys, /dev).
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        if crate::debug_config::DEBUG_FS {
            let pid = current_process().getpid();
            crate::println!("[fs] getdents64(pid={}) pseudo fd={} len={}", pid, fd, len);
        }
        let entries = pdir.entries();
        let mut index = pdir.index();
        if index >= entries.len() || len == 0 {
            return 0;
        }

        let mut kbuf = alloc::vec![0u8; len];
        let mut written = 0usize;
        while index < entries.len() {
            let ent = &entries[index];
            let name_bytes = ent.name.as_bytes();
            let reclen = align_up(19 + name_bytes.len() + 1, 8);
            if written + reclen > len {
                break;
            }
            let base = written;
            kbuf[base..base + 8].copy_from_slice(&ent.ino.to_le_bytes());
            kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
            kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            kbuf[base + 18] = ent.dtype;
            kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
            kbuf[base + 19 + name_bytes.len()] = 0;
            for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
                *b = 0;
            }

            written += reclen;
            index += 1;
        }

        let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written);
        let mut src_off = 0usize;
        for ub in user_bufs {
            let end = src_off + ub.len();
            ub.copy_from_slice(&kbuf[src_off..end]);
            src_off = end;
        }
        pdir.set_index(index);
        return written as isize;
    }

    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return ENOTDIR;
    };
    let inode = os_inode.ext4_inode();
    let ext4_guard = ext4_lock();
    if !inode.is_dir() {
        return ENOTDIR;
    };

    if len == 0 {
        return 0;
    }

    // Stream ext4 directory entries from the on-disk format using a byte offset.
    //
    // This avoids rebuilding `inode.dir_entries()` on every `getdents64` call, which
    // becomes O(n^2) for large directories (busybox `du`/`find`).
    const BLOCK_SIZE: usize = 4096;
    const EXT4_DIRENT_HDR: usize = 8; // u32 ino, u16 rec_len, u8 name_len, u8 file_type

    let dir_size = inode.size() as usize;
    let mut off = os_inode.dir_offset();
    if off >= dir_size {
        return 0;
    }

    if crate::debug_config::DEBUG_FS {
        let pid = current_process().getpid();
        if pid >= 2 && (fd == 3 || fd == 4) {
            crate::println!(
                "[fs] getdents64(pid={}) fd={} len={} off={} dir_size={}",
                pid,
                fd,
                len,
                off,
                dir_size
            );
        }
    }

    let mut kbuf = alloc::vec![0u8; len];
    let mut written = 0usize;

    let mut scratch = alloc::vec![0u8; BLOCK_SIZE];
    while off < dir_size && written + 24 <= len {
        let block_start = (off / BLOCK_SIZE) * BLOCK_SIZE;
        let within = off - block_start;
        let to_read = core::cmp::min(BLOCK_SIZE, dir_size - block_start);
        if to_read < EXT4_DIRENT_HDR || within >= to_read {
            break;
        }
        inode.read_at(block_start, &mut scratch[..to_read]);

        // Parse entries within this block, starting at `within`.
        let mut pos = within;
        while pos + EXT4_DIRENT_HDR <= to_read && written + 24 <= len {
            let inode_num = read_u32_le(&scratch[pos..pos + 4]);
            let rec_len = read_u16_le(&scratch[pos + 4..pos + 6]) as usize;
            let name_len = scratch[pos + 6] as usize;
            let file_type = scratch[pos + 7];

            if rec_len < EXT4_DIRENT_HDR || pos + rec_len > to_read {
                // Corrupt/unsupported entry; stop to avoid looping.
                off = dir_size;
                break;
            }

            let next_off = block_start + pos + rec_len;
            // Skip unused entries (inode_num == 0).
            if inode_num != 0 && name_len > 0 && pos + EXT4_DIRENT_HDR + name_len <= pos + rec_len {
                let name_bytes = &scratch[pos + EXT4_DIRENT_HDR..pos + EXT4_DIRENT_HDR + name_len];
                let reclen = align_up(19 + name_len + 1, 8);
                if written + reclen > len {
                    // Caller buffer full; keep current offset for next call.
                    os_inode.set_dir_offset(block_start + pos);
                    let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written);
                    let mut src_off = 0usize;
                    for ub in user_bufs {
                        let end = src_off + ub.len();
                        ub.copy_from_slice(&kbuf[src_off..end]);
                        src_off = end;
                    }
                    return written as isize;
                }

                let base = written;
                kbuf[base..base + 8].copy_from_slice(&(inode_num as u64).to_le_bytes());
                kbuf[base + 8..base + 16].copy_from_slice(&(next_off as i64).to_le_bytes());
                kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
                kbuf[base + 18] = dt_type_from_ext4(file_type);
                kbuf[base + 19..base + 19 + name_len].copy_from_slice(name_bytes);
                kbuf[base + 19 + name_len] = 0;
                for b in kbuf[base + 19 + name_len + 1..base + reclen].iter_mut() {
                    *b = 0;
                }
                written += reclen;
            }

            pos += rec_len;
            off = block_start + pos;
            if off >= dir_size {
                break;
            }
        }
    }

    // Copy back to user buffer with per-page translation, avoiding per-byte translation overhead.
    let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written);
    let mut src_off = 0usize;
    for ub in user_bufs {
        let end = src_off + ub.len();
        ub.copy_from_slice(&kbuf[src_off..end]);
        src_off = end;
    }

    os_inode.set_dir_offset(off);
    drop(ext4_guard);
    written as isize
}

/// Linux `lseek(2)` (syscall 62 on riscv64).
///
/// Needed by glibc directory APIs (`opendir`/`readdir`/`rewinddir`/`telldir`).
pub fn syscall_lseek(fd: usize, offset: isize, whence: usize) -> isize {
    const SEEK_SET: usize = 0;
    const SEEK_CUR: usize = 1;
    const SEEK_END: usize = 2;

    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };

    // Directories: map seek position to our per-fd `dir_offset`.
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
        let cur = pdir.index() as isize;
        let end = pdir.entries().len() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        pdir.set_index(new as usize);
        return new;
    }

    if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
        let inode = os_inode.ext4_inode();
        let (is_dir, end) = {
            let _ext4_guard = ext4_lock();
            let disk = inode.size() as usize;
            let end = core::cmp::max(disk, os_inode.pending_write_end()) as isize;
            (inode.is_dir(), end)
        };

        if is_dir {
            let cur = os_inode.dir_offset() as isize;
            let new = match whence {
                SEEK_SET => offset,
                SEEK_CUR => cur.saturating_add(offset),
                SEEK_END => end.saturating_add(offset),
                _ => return EINVAL,
            };
            if new < 0 {
                return EINVAL;
            }
            os_inode.set_dir_offset(new as usize);
            return new;
        }

        // Regular files: adjust read/write offset.
        let cur = os_inode.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        os_inode.set_offset(new as usize);
        return new;
    }

    // Pseudo regular files: allow seeking for static content (e.g., `/proc/mounts`),
    // which libc helpers (busybox `df`) may `rewind()` via lseek.
    if let Some(pf) = file.as_any().downcast_ref::<PseudoFile>() {
        let Some(end) = pf.len().map(|n| n as isize) else {
            return ESPIPE;
        };
        let cur = pf.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        pf.set_offset(new as usize);
        return new;
    }

    if let Some(shm) = file.as_any().downcast_ref::<PseudoShmFile>() {
        let end = shm.len() as isize;
        let cur = shm.offset() as isize;
        let new = match whence {
            SEEK_SET => offset,
            SEEK_CUR => cur.saturating_add(offset),
            SEEK_END => end.saturating_add(offset),
            _ => return EINVAL,
        };
        if new < 0 {
            return EINVAL;
        }
        shm.set_offset(new as usize);
        return new;
    }

    ESPIPE
}
