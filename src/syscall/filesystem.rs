use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::min;

use crate::{
    fs::{File, OSInode, ROOT_INODE, make_pipe},
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

pub fn syscall_openat(dirfd: isize, pathname: usize, flags: usize, _mode: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, pathname as *const u8);
    if path.is_empty() {
        return -1;
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
    let mut inode = base_inode.find_path(&path);

    // CREATE: create file if missing.
    if inode.is_none() && (flags & O_CREAT != 0) {
        let (parent_path, name) = match split_parent_and_name(&path) {
            Some(v) => v,
            None => return -1,
        };
        let parent = if parent_path.is_empty() {
            alloc::sync::Arc::clone(&base_inode)
        } else {
            base_inode.find_path(parent_path).unwrap_or_else(|| alloc::sync::Arc::clone(&base_inode))
        };
        inode = parent.create_file(name).ok();
    }

    let inode = match inode {
        Some(i) => i,
        None => return -1,
    };

    if (flags & O_DIRECTORY) != 0 && !inode.is_dir() {
        return -1;
    }

    let os_inode = alloc::sync::Arc::new(OSInode::new(readable, writable, inode));
    let mut inner = process.borrow_mut();
    let fd = inner.alloc_fd();
    inner.fd_table[fd] = Some(os_inode);
    fd as isize
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
    let Some(inode) = get_fd_inode(fd) else {
        return -1;
    };

    let mode = if inode.is_dir() { 0x040000 } else { 0x100000 };
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

pub fn syscall_getdents64(fd: usize, dirp: usize, len: usize) -> isize {
    let Some(file) = get_fd_file(fd) else {
        return -1;
    };
    let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() else {
        return -1;
    };
    let inode = os_inode.ext4_inode();
    if !inode.is_dir() {
        return -1;
    };

    let entries = inode.dir_entries();
    let token = get_current_token();

    let mut index = os_inode.offset();
    if index >= entries.len() {
        return 0;
    }
    let mut written = 0usize;
    while index < entries.len() {
        let (name, ino, ftype) = &entries[index];
        let name_bytes = name.as_bytes();
        let reclen = align_up(19 + name_bytes.len() + 1, 8);
        if written + reclen > len {
            break;
        }

        let base = dirp + written;
        write_bytes_user(token, base, &(*ino as u64).to_le_bytes());
        write_bytes_user(token, base + 8, &((index + 1) as i64).to_le_bytes());
        write_bytes_user(token, base + 16, &(reclen as u16).to_le_bytes());
        write_bytes_user(token, base + 18, &[dt_type_from_ext4(*ftype)]);
        write_bytes_user(token, base + 19, name_bytes);
        write_bytes_user(token, base + 19 + name_bytes.len(), &[0]);

        let pad = reclen - (19 + name_bytes.len() + 1);
        if pad > 0 {
            let zeros = [0u8; 8];
            let mut off = 0usize;
            while off < pad {
                let n = min(pad - off, zeros.len());
                write_bytes_user(token, base + 19 + name_bytes.len() + 1 + off, &zeros[..n]);
                off += n;
            }
        }

        written += reclen;
        index += 1;
    }

    os_inode.set_offset(index);
    if written == 0 && index < entries.len() {
        return -1;
    }
    written as isize
}
