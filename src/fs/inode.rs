//! Inode abstraction for ext4 filesystem

use super::File;
use crate::drivers::{BLOCK_DEVICE, USER_BLOCK_DEVICE};
use crate::mm::UserBuffer;
use crate::println;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use ext4_fs::{Ext4FileSystem, Inode};
use lazy_static::*;
use spin::Mutex;

/// Serialize ext4 operations across harts.
static EXT4_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn ext4_lock() -> spin::MutexGuard<'static, ()> {
    EXT4_LOCK.lock()
}

/// A wrapper around a filesystem inode to implement File trait
pub struct OSInode {
    readable: bool,
    writable: bool,
    append: bool,
    readonly_fs: bool,
    inner: Mutex<OSInodeInner>,
}

/// The OS inode inner
pub struct OSInodeInner {
    offset: usize,
    dir_offset: usize,
    inode: Arc<Inode>,
    write_buf_off: usize,
    write_buf: Vec<u8>,
    read_buf_off: usize,
    read_buf_valid: usize,
    read_buf: Vec<u8>,
}

impl OSInode {
    /// Construct an OS inode from an inode
    pub fn new(readable: bool, writable: bool, inode: Arc<Inode>) -> Self {
        Self::new_with_append(readable, writable, false, inode)
    }

    pub fn new_with_append(readable: bool, writable: bool, append: bool, inode: Arc<Inode>) -> Self {
        Self::new_with_append_rofs(readable, writable, append, inode, false)
    }

    pub fn new_with_append_rofs(
        readable: bool,
        writable: bool,
        append: bool,
        inode: Arc<Inode>,
        readonly_fs: bool,
    ) -> Self {
        Self {
            readable,
            writable,
            append,
            readonly_fs,
            inner: Mutex::new(OSInodeInner {
                offset: 0,
                dir_offset: 0,
                inode,
                write_buf_off: 0,
                write_buf: Vec::new(),
                read_buf_off: 0,
                read_buf_valid: 0,
                read_buf: Vec::new(),
            }),
        }
    }

    pub fn append(&self) -> bool {
        self.append
    }

    pub fn readonly_fs(&self) -> bool {
        self.readonly_fs
    }

    /// Read all data inside an inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        let _ = self.flush();
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        let file_size = inner.inode.size() as usize;

        let mut buffer = [0u8; 4096]; // Use larger buffer for ext4 (4K blocks)
        let mut v: Vec<u8> = Vec::new();
        let mut total_read = 0usize;

        loop {
            let len = inner.inode.read_at(inner.offset, &mut buffer);
            if len == 0 {
                break;
            }
            inner.offset += len;
            total_read += len;
            v.extend_from_slice(&buffer[..len]);

            if total_read >= file_size {
                break;
            }
        }

        v
    }

    pub fn ext4_inode(&self) -> Arc<Inode> {
        self.inner.lock().inode.clone()
    }

    /// Return the end offset of buffered (not-yet-flushed) writes.
    ///
    /// This is used to report a correct file size to userspace (`fstat`, `lseek(SEEK_END)`)
    /// even when we are buffering writes in memory.
    pub fn pending_write_end(&self) -> usize {
        let inner = self.inner.lock();
        inner.write_buf_off.saturating_add(inner.write_buf.len())
    }

    /// Read from this inode at the given offset without updating the file offset.
    pub fn pread_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let _ = self.flush();
        let _fs_guard = EXT4_LOCK.lock();
        let inner = self.inner.lock();
        inner.inode.read_at(offset, buf)
    }

    /// Write to this inode at the given offset without updating the file offset.
    pub fn pwrite_at(&self, offset: usize, buf: &[u8]) -> Result<usize, ()> {
        let _ = self.flush();
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        // Writes via pwrite/pwritev must invalidate the buffered read cache.
        inner.read_buf_valid = 0;
        inner.inode.write_at(offset, buf).map_err(|_| ())
    }

    pub fn flush(&self) -> Result<(), ()> {
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        if inner.write_buf.is_empty() {
            return Ok(());
        }
        let off = inner.write_buf_off;
        let data = core::mem::take(&mut inner.write_buf);
        match inner.inode.write_at(off, &data) {
            Ok(n) if n == data.len() => Ok(()),
            Ok(_) | Err(_) => {
                // Restore buffer best-effort (so we don't silently drop data).
                inner.write_buf_off = off;
                inner.write_buf = data;
                Err(())
            }
        }
    }

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        let _ = self.flush();
        let mut inner = self.inner.lock();
        inner.offset = offset;
        inner.read_buf_valid = 0;
    }

    pub fn dir_offset(&self) -> usize {
        self.inner.lock().dir_offset
    }

    pub fn set_dir_offset(&self, offset: usize) {
        self.inner.lock().dir_offset = offset;
    }
}

lazy_static! {
    /// ext4 filesystem handle (shared by all inodes).
    pub static ref EXT4_FS: Arc<spin::Mutex<Ext4FileSystem>> = {
        Ext4FileSystem::open(BLOCK_DEVICE.clone())
    };

    /// Root inode of the filesystem
    pub static ref ROOT_INODE: Arc<Inode> = {
        Arc::new(Ext4FileSystem::root_inode(&EXT4_FS))
    };

    /// Optional secondary filesystem (e.g., disk.img).
    pub static ref USER_EXT4_FS: Option<Arc<spin::Mutex<Ext4FileSystem>>> = {
        USER_BLOCK_DEVICE
            .as_ref()
            .map(|dev| Ext4FileSystem::open(dev.clone()))
    };

    /// Root inode of the secondary filesystem.
    pub static ref USER_ROOT_INODE: Option<Arc<Inode>> = {
        USER_EXT4_FS
            .as_ref()
            .map(|fs| Arc::new(Ext4FileSystem::root_inode(fs)))
    };

    /// User directory inode (for ext4, apps are in /user)
    pub static ref USER_INODE: Arc<Inode> = {
        if let Some(root) = USER_ROOT_INODE.as_ref() {
            root.find("user")
                .expect("[ext4] /user directory not found on user disk!")
        } else {
            ROOT_INODE.find("user").expect("[ext4] /user directory not found!")
        }
    };
}

pub(crate) fn root_inode_for_path(path: &str) -> Arc<Inode> {
    let use_user = (path == "/user" || path.starts_with("/user/")) && USER_ROOT_INODE.is_some();
    if use_user {
        USER_ROOT_INODE.as_ref().unwrap().clone()
    } else {
        ROOT_INODE.clone()
    }
}

/// List all files in the filesystem
pub fn list_apps() {
    let _fs_guard = EXT4_LOCK.lock();
    println!("/**** APPS ****");
    for app in USER_INODE.ls() {
        println!("{}", app);
    }
    println!("**************/");
}

bitflags! {
    /// Open file flags
    pub struct OpenFlags: u32 {
        /// Read only
        const RDONLY = 0;
        /// Write only
        const WRONLY = 1 << 0;
        /// Read & Write
        const RDWR = 1 << 1;
        /// Allow create
        const CREATE = 1 << 9;
        /// Clear file and return an empty one
        const TRUNC = 1 << 10;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

/// Open file with flags (read-only for ext4)
/// Files are located in /user directory
pub fn open_file(name: &str, flags: OpenFlags) -> Option<Arc<OSInode>> {
    let (readable, writable) = flags.read_write();
    let _fs_guard = EXT4_LOCK.lock();

    let raw = name.trim_matches('\0');
    if raw.is_empty() {
        return None;
    }

    // Default: resolve relative paths from /user to keep exec() behavior.
    let base_dir: Arc<Inode> = if raw.starts_with('/') {
        root_inode_for_path(raw)
    } else {
        Arc::clone(&USER_INODE)
    };

    let mut inode = base_dir.find_path(raw);

    // Keep compatibility: exec("foo") can omit ".bin".
    if inode.is_none() && !raw.contains('/') && !raw.ends_with(".bin") {
        let name_with_bin = alloc::format!("{}.bin", raw);
        inode = base_dir.find_path(&name_with_bin);
    }

    // CREATE: create the file if it does not exist.
    if inode.is_none() && flags.contains(OpenFlags::CREATE) {
        let (parent_path, file_name) = split_parent_and_name(raw)?;
        let parent = if parent_path.is_empty() {
            Arc::clone(&base_dir)
        } else {
            base_dir.find_path(parent_path)?
        };
        inode = parent.create_file(file_name).ok();
    }

    let inode = inode?;

    // TRUNC: clear file contents.
    if flags.contains(OpenFlags::TRUNC) {
        let _ = inode.clear();
    }

    Some(Arc::new(OSInode::new(readable, writable, inode)))
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        let _ = self.flush();
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        let mut total_read_size = 0usize;
        const READBUF_MAX: usize = 64 * 1024;

        if inner.read_buf.len() < READBUF_MAX {
            inner.read_buf.resize(READBUF_MAX, 0);
            inner.read_buf_off = 0;
            inner.read_buf_valid = 0;
        }

        for slice in buf.buffers.iter_mut() {
            let mut out: &mut [u8] = *slice;
            while !out.is_empty() {
                let need_refill = inner.read_buf_valid == 0
                    || inner.offset < inner.read_buf_off
                    || inner.offset >= inner.read_buf_off + inner.read_buf_valid;

                if need_refill {
                    inner.read_buf_off = inner.offset;
                    let inode = inner.inode.clone();
                    let off = inner.read_buf_off;
                    let n = inode.read_at(off, &mut inner.read_buf[..READBUF_MAX]);
                    inner.read_buf_valid = n;
                    if n == 0 {
                        return total_read_size;
                    }
                }

                let buf_off = inner.offset - inner.read_buf_off;
                let avail = inner.read_buf_valid.saturating_sub(buf_off);
                if avail == 0 {
                    inner.read_buf_valid = 0;
                    continue;
                }

                let n = core::cmp::min(avail, out.len());
                out[..n].copy_from_slice(&inner.read_buf[buf_off..buf_off + n]);
                inner.offset += n;
                total_read_size += n;
                out = &mut out[n..];
            }
        }
        total_read_size
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        if self.append {
            if !inner.write_buf.is_empty() {
                let _ = inner.inode.write_at(inner.write_buf_off, &inner.write_buf);
                inner.write_buf.clear();
            }
            inner.offset = inner.inode.size() as usize;
        }
        let mut total_write_size = 0usize;
        const WRITEBUF_MAX: usize = 64 * 1024;

        for slice in _buf.buffers.iter() {
            // Flush on non-sequential writes.
            if !inner.write_buf.is_empty()
                && inner.offset != inner.write_buf_off.saturating_add(inner.write_buf.len())
            {
                if inner
                    .inode
                    .write_at(inner.write_buf_off, &inner.write_buf)
                    .is_err()
                {
                    println!("[ext4] Warning: write failed");
                    break;
                }
                inner.write_buf.clear();
            }

            if inner.write_buf.is_empty() {
                inner.write_buf_off = inner.offset;
            }

            inner.write_buf.extend_from_slice(slice);
            inner.offset += slice.len();
            total_write_size += slice.len();
            inner.read_buf_valid = 0;

            if inner.write_buf.len() >= WRITEBUF_MAX {
                if inner
                    .inode
                    .write_at(inner.write_buf_off, &inner.write_buf)
                    .is_err()
                {
                    println!("[ext4] Warning: write failed");
                    break;
                }
                inner.write_buf.clear();
                inner.read_buf_valid = 0;
            }
        }
        total_write_size
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Drop for OSInode {
    fn drop(&mut self) {
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        if inner.write_buf.is_empty() {
            return;
        }
        let off = inner.write_buf_off;
        let data = core::mem::take(&mut inner.write_buf);
        let _ = inner.inode.write_at(off, &data);
    }
}

fn split_parent_and_name(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => {
            let (parent, name) = trimmed.split_at(pos);
            let name = &name[1..];
            Some((parent, name))
        }
        None => Some(("", trimmed)),
    }
}
