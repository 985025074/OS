use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::min;

use crate::{
    fs::{File, OSInode, PseudoDir, PseudoDirent, PseudoFile, RtcFile, ROOT_INODE, make_pipe},
    mm::{UserBuffer, translated_byte_buffer, translated_mutref, translated_str},
    task::processor::current_process,
    trap::get_current_token,
};

const AT_FDCWD: isize = -100;

const O_ACCMODE: usize = 0x3;
const O_RDONLY: usize = 0x0;
const O_WRONLY: usize = 0x1;
const O_RDWR: usize = 0x2;
const O_CREAT: usize = 0x40;
const O_DIRECTORY: usize = 0x10000;

// Linux errno (negative return in kernel ABI).
const EBADF: isize = -9;
const ENOENT: isize = -2;
const EINVAL: isize = -22;
const EMFILE: isize = -24;
const ENOTDIR: isize = -20;
const EACCES: isize = -13;
const EXDEV: isize = -18;
const ESPIPE: isize = -29;

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
        // We don't have reverse lookup from inode -> absolute path; best-effort use cwd.
        normalize_path(&cwd, path)
    } else {
        normalize_path(&cwd, path)
    };
    Some(abs)
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

    match cmd {
        F_GETFD | F_SETFD | F_GETFL | F_SETFL => {
            // We don't track per-fd flags yet; pretend success.
            if get_fd_file(fd).is_none() {
                return EBADF;
            }
            if cmd == F_GETFD || cmd == F_GETFL {
                return 0;
            }
            0
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let Some(file) = get_fd_file(fd) else {
                return EBADF;
            };
            let minfd = arg;
            let process = current_process();
            let mut inner = process.borrow_mut();
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
            }
            inner.fd_table[newfd] = Some(file);
            newfd as isize
        }
        _ => EINVAL,
    }
}

pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, _mode: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    // Pseudo files for minimal proc/sys/dev compatibility.
    // Use the resolved absolute path so callers like `openat(AT_FDCWD, "proc", ...)`
    // also hit the pseudo filesystem.
    if let Some(abs) = resolve_abs_path(dirfd, &path) {
        if abs == "/sys"
            || abs.starts_with("/sys/")
            || abs == "/proc"
            || abs.starts_with("/proc/")
            || abs == "/dev"
            || abs.starts_with("/dev/")
        {
            if let Some(file) = open_pseudo(&abs) {
                let process = current_process();
                let mut inner = process.borrow_mut();
                let fd = inner.alloc_fd();
                inner.fd_table[fd] = Some(file);
                return fd as isize;
            }
        }
    }

    let (readable, writable) = match flags & O_ACCMODE {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => (true, false),
    };

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };

    // Resolve base directory.
    let base_inode = if path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        ROOT_INODE.find_path(&cwd)
    } else if dirfd >= 0 {
        get_fd_inode(dirfd as usize)
    } else {
        None
    };

    let base_inode = base_inode.unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE));

    // Resolve target.
    let mut inode = if path.starts_with('/') {
        let abs = normalize_path("/", &path);
        ROOT_INODE.find_path(&abs)
    } else if dirfd == AT_FDCWD {
        let abs = normalize_path(&cwd, &path);
        ROOT_INODE.find_path(&abs)
    } else {
        // dirfd-based relative lookup (best-effort, without an absolute cwd string).
        let rel = normalize_relative_path(&path);
        if rel.is_empty() {
            Some(alloc::sync::Arc::clone(&base_inode))
        } else {
            base_inode.find_path(&rel)
        }
    };

    // CREATE: create file if missing.
    if inode.is_none() && (flags & O_CREAT != 0) {
        if path.starts_with('/') || dirfd == AT_FDCWD {
            let abs = if path.starts_with('/') {
                normalize_path("/", &path)
            } else {
                normalize_path(&cwd, &path)
            };
            let (parent_path, name) = match split_parent_and_name(&abs) {
                Some(v) => v,
                None => return EINVAL,
            };
            let parent = if parent_path.is_empty() {
                alloc::sync::Arc::clone(&ROOT_INODE)
            } else {
                ROOT_INODE.find_path(parent_path).unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE))
            };
            inode = parent.create_file(name).ok();
        } else {
            let rel = normalize_relative_path(&path);
            let (parent_path, name) = match split_parent_and_name(&rel) {
                Some(v) => v,
                None => return EINVAL,
            };
            let parent = if parent_path.is_empty() {
                alloc::sync::Arc::clone(&base_inode)
            } else {
                base_inode
                    .find_path(parent_path)
                    .unwrap_or_else(|| alloc::sync::Arc::clone(&base_inode))
            };
            inode = parent.create_file(name).ok();
        }
    }

    let inode = match inode {
        Some(i) => i,
        None => return ENOENT,
    };

    if (flags & O_DIRECTORY) != 0 && !inode.is_dir() {
        return ENOTDIR;
    }

    let os_inode = alloc::sync::Arc::new(OSInode::new(readable, writable, inode));
    let mut inner = process.borrow_mut();
    let fd = inner.alloc_fd();
    inner.fd_table[fd] = Some(os_inode);
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
        ];
        let mut pids: alloc::vec::Vec<usize> = {
            let map = crate::task::manager::PID2PCB.lock();
            map.keys().copied().collect()
        };
        pids.sort_unstable();
        for pid in pids {
            entries.push(PseudoDirent { name: alloc::format!("{}", pid), ino: pid as u64, dtype: 4 });
        }
        return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
    }

    // /proc/self -> current process directory (best-effort; no symlink support).
    if path == "/proc/self" || path == "/proc/self/" {
        let pid = current_process().getpid();
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: pid as u64, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("stat"), ino: (pid as u64) << 32 | 1, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("cmdline"), ino: (pid as u64) << 32 | 2, dtype: 8 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
    }

    // /proc/<pid> and /proc/<pid>/...
    if let Some(rest) = path.strip_prefix("/proc/") {
        let rest = rest.trim_end_matches('/');
        let mut it = rest.split('/');
        let first = it.next().unwrap_or("");
        if first == "self" {
            return open_pseudo("/proc/self");
        }
        if let Ok(pid) = first.parse::<usize>() {
            // Validate pid exists.
            let proc = crate::task::manager::pid2process(pid)?;
            let ppid = proc
                .borrow_mut()
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.getpid())
                .unwrap_or(0);
            let comm = "CongCore";

            match it.next() {
                None => {
                    let entries = alloc::vec![
                        PseudoDirent { name: alloc::string::String::from("."), ino: pid as u64, dtype: 4 },
                        PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
                        PseudoDirent { name: alloc::string::String::from("stat"), ino: (pid as u64) << 32 | 1, dtype: 8 },
                        PseudoDirent { name: alloc::string::String::from("cmdline"), ino: (pid as u64) << 32 | 2, dtype: 8 },
                    ];
                    return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
                }
                Some("stat") if it.next().is_none() => {
                    // Provide a Linux-like `/proc/<pid>/stat` line with many fields.
                    // Most tools (busybox ps) only need a subset but expect a long line.
                    let s = alloc::format!(
                        "{pid} ({comm}) R {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                    );
                    return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
                }
                Some("cmdline") if it.next().is_none() => {
                    let s = alloc::format!("{comm}\0");
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
        return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
    }
    if path == "/dev" || path == "/dev/" {
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("null"), ino: 2, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("zero"), ino: 3, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("urandom"), ino: 4, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("random"), ino: 5, dtype: 8 },
            PseudoDirent { name: alloc::string::String::from("misc"), ino: 6, dtype: 4 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
    }
    if path == "/dev/misc" || path == "/dev/misc/" {
        let entries = alloc::vec![
            PseudoDirent { name: alloc::string::String::from("."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from(".."), ino: 1, dtype: 4 },
            PseudoDirent { name: alloc::string::String::from("rtc"), ino: 2, dtype: 8 },
        ];
        return Some(alloc::sync::Arc::new(PseudoDir::new(entries)));
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
    if path == "/proc/mounts" {
        // Minimal mount table so `df` works.
        return Some(alloc::sync::Arc::new(PseudoFile::new_static("rootfs / ext4 rw 0 0\n")));
    }
    if path == "/proc/meminfo" {
        // Minimal meminfo so busybox `free` works.
        let mem_total_kb = ((crate::config::MEMORY_END - 0x8000_0000) / 1024) as u64;
        let s = alloc::format!(
            "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\nSwapTotal:      0 kB\nSwapFree:       0 kB\n",
            mem_total_kb,
            mem_total_kb / 2
        );
        return Some(alloc::sync::Arc::new(PseudoFile::new_static(&s)));
    }
    // /dev/*
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
    let Some(abs) = resolve_abs_path(dirfd, &path) else {
        return ENOENT;
    };

    // Treat known pseudo nodes as always accessible (no uid/gid model yet).
    if open_pseudo(&abs).is_some() {
        return 0;
    }

    let Some(inode) = ROOT_INODE.find_path(&abs) else {
        return ENOENT;
    };
    if !inode_mode_allows(inode.mode(), mode) {
        return EACCES;
    }
    0
}

/// Linux `readlinkat(2)` (syscall 78 on riscv64).
///
/// Our ext4 implementation currently does not expose symlinks; return `EINVAL`
/// for non-symlink paths as Linux does.
pub fn syscall_readlinkat(_dirfd: isize, _pathname: usize, _buf: usize, _bufsiz: usize) -> isize {
    EINVAL
}

/// Linux `renameat(2)` (syscall 38 on riscv64).
pub fn syscall_renameat(olddirfd: isize, oldpath: usize, newdirfd: isize, newpath: usize) -> isize {
    let token = get_current_token();
    let old_s = translated_str(token, oldpath as *const u8);
    let new_s = translated_str(token, newpath as *const u8);
    let Some(old_abs) = resolve_abs_path(olddirfd, &old_s) else {
        return ENOENT;
    };
    let Some(new_abs) = resolve_abs_path(newdirfd, &new_s) else {
        return ENOENT;
    };
    let Some((old_parent, old_name)) = split_parent_and_name(&old_abs) else {
        return EINVAL;
    };
    let Some((new_parent, new_name)) = split_parent_and_name(&new_abs) else {
        return EINVAL;
    };
    if old_parent != new_parent {
        return EXDEV;
    }
    let parent_path = if old_parent.is_empty() { "/" } else { old_parent };
    let Some(parent) = ROOT_INODE.find_path(parent_path) else {
        return ENOENT;
    };
    match parent.rename(old_name, new_name) {
        Ok(_) => 0,
        Err(_) => -1,
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
        return -1;
    }
    inner.fd_table[fd] = None;
    0
}

pub fn syscall_read(fd: usize, buffer: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return -1;
    };
    if !file.readable() {
        return -1;
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
        return -1;
    };
    if !file.writable() {
        return -1;
    }
    let buf = UserBuffer::new(translated_byte_buffer(
        get_current_token(),
        buffer as *mut u8,
        len,
    ));
    file.write(buf) as isize
}

pub fn syscall_pipe2(pipefd: usize, _flags: usize) -> isize {
    let process = current_process();
    let token = get_current_token();
    let (pipe_read, pipe_write) = make_pipe();

    let mut inner = process.borrow_mut();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(pipe_read);
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(pipe_write);
    drop(inner);

    // Linux ABI: pipefd points to `int pipefd[2]` (i32).
    let p0 = translated_mutref(token, pipefd as *mut i32);
    let p1 = translated_mutref(token, (pipefd + core::mem::size_of::<i32>()) as *mut i32);
    *p0 = read_fd as i32;
    *p1 = write_fd as i32;
    0
}

pub fn syscall_dup(oldfd: usize) -> isize {
    let Some(file) = get_fd_file(oldfd) else {
        return -1;
    };
    let process = current_process();
    let mut inner = process.borrow_mut();
    let newfd = inner.alloc_fd();
    inner.fd_table[newfd] = Some(file);
    newfd as isize
}

pub fn syscall_dup3(oldfd: usize, newfd: usize, _flags: usize) -> isize {
    if oldfd == newfd {
        return -1;
    }
    let Some(file) = get_fd_file(oldfd) else {
        return -1;
    };
    let process = current_process();
    let mut inner = process.borrow_mut();
    while inner.fd_table.len() <= newfd {
        inner.fd_table.push(None);
    }
    inner.fd_table[newfd] = Some(file);
    newfd as isize
}

pub fn syscall_chdir(pathname: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return -1;
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let new_cwd = normalize_path(&cwd, &path);
    let Some(inode) = ROOT_INODE.find_path(&new_cwd) else {
        return -1;
    };
    if !inode.is_dir() {
        return -1;
    }
    process.borrow_mut().cwd = new_cwd;
    0
}

pub fn syscall_mkdirat(dirfd: isize, pathname: usize, _mode: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return -1;
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let base = if path.starts_with('/') {
        alloc::sync::Arc::clone(&ROOT_INODE)
    } else if dirfd == AT_FDCWD {
        ROOT_INODE
            .find_path(&cwd)
            .unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE))
    } else if dirfd >= 0 {
        get_fd_inode(dirfd as usize).unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE))
    } else {
        alloc::sync::Arc::clone(&ROOT_INODE)
    };

    let (parent_path, name) = match split_parent_and_name(&path) {
        Some(v) => v,
        None => return -1,
    };
    let parent = if parent_path.is_empty() {
        base
    } else {
        base.find_path(parent_path).unwrap_or(base)
    };

    match parent.create_dir(name) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

pub fn syscall_unlinkat(dirfd: isize, pathname: usize, _flags: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return -1;
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let base = if path.starts_with('/') {
        alloc::sync::Arc::clone(&ROOT_INODE)
    } else if dirfd == AT_FDCWD {
        ROOT_INODE
            .find_path(&cwd)
            .unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE))
    } else if dirfd >= 0 {
        get_fd_inode(dirfd as usize).unwrap_or_else(|| alloc::sync::Arc::clone(&ROOT_INODE))
    } else {
        alloc::sync::Arc::clone(&ROOT_INODE)
    };

    let (parent_path, name) = match split_parent_and_name(&path) {
        Some(v) => v,
        None => return -1,
    };
    let parent = if parent_path.is_empty() {
        base
    } else {
        base.find_path(parent_path).unwrap_or(base)
    };

    match parent.unlink(name) {
        Ok(_) => 0,
        Err(_) => -1,
    }
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
    // EXT4_SUPER_MAGIC
    let st = KStatFs {
        f_type: 0xEF53,
        f_bsize: 4096,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: 4096,
        f_flags: 0,
        f_spare: [0; 4],
    };
    let token = get_current_token();
    *translated_mutref(token, st_ptr as *mut KStatFs) = st;
    0
}

/// Linux `fstatfs(2)` (syscall 83 on riscv64).
pub fn syscall_fstatfs(fd: usize, st_ptr: usize) -> isize {
    if get_fd_file(fd).is_none() {
        return EBADF;
    }
    fill_statfs(st_ptr)
}

/// Linux `statfs(2)` (syscall 84 on riscv64).
pub fn syscall_statfs(pathname: usize, st_ptr: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }
    // Best-effort: if path exists, report ext4-like stats.
    let Some(abs) = resolve_abs_path(AT_FDCWD, &path) else {
        return ENOENT;
    };
    if ROOT_INODE.find_path(&abs).is_none() {
        return ENOENT;
    }
    fill_statfs(st_ptr)
}

/// Linux `utimensat(2)` (syscall 88 on riscv64).
///
/// We don't track timestamps; accept the call for compatibility (busybox `touch`).
pub fn syscall_utimensat(dirfd: isize, pathname: usize, _times: usize, _flags: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    let Some(abs) = resolve_abs_path(dirfd, &path) else {
        return ENOENT;
    };
    if ROOT_INODE.find_path(&abs).is_none() {
        return ENOENT;
    }
    0
}

pub fn syscall_getcwd(buf: usize, size: usize) -> isize {
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    if size == 0 {
        return -1;
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
        || file.as_any().downcast_ref::<RtcFile>().is_some()
    {
        let mode: u32 = if file.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if file.as_any().downcast_ref::<RtcFile>().is_some() {
            0o100666
        } else {
            0o100444
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
            st_mode: mode,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            __pad: 0,
            st_size: 0,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks: 0,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        };
        let token = get_current_token();
        *translated_mutref(token, st_ptr as *mut KStat) = st;
        return 0;
    }

    let Some(inode) = file
        .as_any()
        .downcast_ref::<OSInode>()
        .map(|o| o.ext4_inode()) else {
        return EBADF;
    };

    let mode = inode.mode() as u32;
    let size = inode.size() as i64;
    let blocks = ((inode.size() + 511) / 512) as u64;

    let st = KStat {
        st_dev: 0,
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
        st_atime_sec: 0,
        st_atime_nsec: 0,
        st_mtime_sec: 0,
        st_mtime_nsec: 0,
        st_ctime_sec: 0,
        st_ctime_nsec: 0,
        __unused: [0, 0],
    };

    let token = get_current_token();
    *translated_mutref(token, st_ptr as *mut KStat) = st;
    0
}

pub fn syscall_newfstatat(dirfd: isize, pathname: usize, st_ptr: usize, _flags: usize) -> isize {
    if st_ptr == 0 {
        return EINVAL;
    }
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return ENOENT;
    }

    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = if path.starts_with('/') {
        normalize_path("/", &path)
    } else if dirfd == AT_FDCWD {
        normalize_path(&cwd, &path)
    } else if dirfd >= 0 {
        // Resolve relative to an open directory fd if possible; fallback to cwd.
        if let Some(inode) = get_fd_inode(dirfd as usize) {
            // Best-effort: derive a path-like context is hard without reverse lookup;
            // just resolve relative to cwd for now.
            let _ = inode;
            normalize_path(&cwd, &path)
        } else {
            return EBADF;
        }
    } else {
        normalize_path(&cwd, &path)
    };

    // Pseudo nodes: return minimal metadata.
    if let Some(node) = open_pseudo(&abs) {
        let mode: u32 = if node.as_any().downcast_ref::<PseudoDir>().is_some() {
            0o040555
        } else if abs == "/dev/null"
            || abs == "/dev/zero"
            || abs == "/dev/misc/rtc"
        {
            0o100666
        } else {
            0o100444
        };
        let st = KStat {
            st_dev: 0,
            st_ino: 1,
            st_mode: mode,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            __pad: 0,
            st_size: 0,
            st_blksize: 4096,
            __pad2: 0,
            st_blocks: 0,
            st_atime_sec: 0,
            st_atime_nsec: 0,
            st_mtime_sec: 0,
            st_mtime_nsec: 0,
            st_ctime_sec: 0,
            st_ctime_nsec: 0,
            __unused: [0, 0],
        };
        *translated_mutref(token, st_ptr as *mut KStat) = st;
        return 0;
    }

    let Some(inode) = ROOT_INODE.find_path(&abs) else {
        return ENOENT;
    };

    let mode = inode.mode() as u32;
    let size = inode.size() as i64;
    let blocks = ((inode.size() + 511) / 512) as u64;

    let st = KStat {
        st_dev: 0,
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
        st_atime_sec: 0,
        st_atime_nsec: 0,
        st_mtime_sec: 0,
        st_mtime_nsec: 0,
        st_ctime_sec: 0,
        st_ctime_nsec: 0,
        __unused: [0, 0],
    };

    *translated_mutref(token, st_ptr as *mut KStat) = st;
    0
}

pub fn syscall_getdents64(fd: usize, dirp: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return EBADF;
    };
    let token = get_current_token();

    // Pseudo directories (e.g. /proc, /sys, /dev).
    if let Some(pdir) = file.as_any().downcast_ref::<PseudoDir>() {
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
        return -1;
    };
    let inode = os_inode.ext4_inode();
    if !inode.is_dir() {
        return -1;
    };

    // Keep a separate per-fd index to avoid interfering with file read offsets.
    let entries = inode.dir_entries();
    let mut index = os_inode.dir_offset();
    if index >= entries.len() {
        return 0;
    }

    if len == 0 {
        return 0;
    }

    let mut kbuf = alloc::vec![0u8; len];
    let mut written = 0usize;
    while index < entries.len() {
        let (name, ino, ftype) = &entries[index];
        let name_bytes = name.as_bytes();
        let reclen = align_up(19 + name_bytes.len() + 1, 8);
        if written + reclen > len {
            break;
        }

        let base = written;
        kbuf[base..base + 8].copy_from_slice(&(*ino as u64).to_le_bytes());
        kbuf[base + 8..base + 16].copy_from_slice(&((index + 1) as i64).to_le_bytes());
        kbuf[base + 16..base + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        kbuf[base + 18] = dt_type_from_ext4(*ftype);
        kbuf[base + 19..base + 19 + name_bytes.len()].copy_from_slice(name_bytes);
        kbuf[base + 19 + name_bytes.len()] = 0;
        for b in kbuf[base + 19 + name_bytes.len() + 1..base + reclen].iter_mut() {
            *b = 0;
        }

        written += reclen;
        index += 1;
    }

    // Copy back to user buffer with per-page translation, avoiding per-byte translation overhead.
    let user_bufs = translated_byte_buffer(token, dirp as *mut u8, written);
    let mut src_off = 0usize;
    for ub in user_bufs {
        let end = src_off + ub.len();
        ub.copy_from_slice(&kbuf[src_off..end]);
        src_off = end;
    }

    os_inode.set_dir_offset(index);
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
        if inode.is_dir() {
            let cur = os_inode.dir_offset() as isize;
            let end = inode.dir_entries().len() as isize;
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
        let end = inode.size() as isize;
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

    // Other pseudo nodes: best-effort.
    if file.as_any().downcast_ref::<PseudoFile>().is_some() || file.as_any().downcast_ref::<RtcFile>().is_some() {
        // These nodes are not seekable in our model.
        return ESPIPE;
    }

    ESPIPE
}
