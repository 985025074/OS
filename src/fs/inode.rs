//! Inode abstraction for ext4 filesystem

use super::File;
use crate::drivers::BLOCK_DEVICE;
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
    inner: Mutex<OSInodeInner>,
}

/// The OS inode inner
pub struct OSInodeInner {
    offset: usize,
    dir_offset: usize,
    inode: Arc<Inode>,
}

impl OSInode {
    /// Construct an OS inode from an inode
    pub fn new(readable: bool, writable: bool, inode: Arc<Inode>) -> Self {
        Self {
            readable,
            writable,
            inner: Mutex::new(OSInodeInner {
                offset: 0,
                dir_offset: 0,
                inode,
            }),
        }
    }

    /// Read all data inside an inode into vector
    pub fn read_all(&self) -> Vec<u8> {
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

    pub fn offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn dir_offset(&self) -> usize {
        self.inner.lock().dir_offset
    }

    pub fn set_dir_offset(&self, offset: usize) {
        self.inner.lock().dir_offset = offset;
    }
}

lazy_static! {
    /// Root inode of the filesystem
    pub static ref ROOT_INODE: Arc<Inode> = {
        let efs = Ext4FileSystem::open(BLOCK_DEVICE.clone());
        Arc::new(Ext4FileSystem::root_inode(&efs))
    };

    /// User directory inode (for ext4, apps are in /user)
    pub static ref USER_INODE: Arc<Inode> = {
        ROOT_INODE.find("user").expect("[ext4] /user directory not found!")
    };
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
    let base_dir: &Arc<Inode> = if raw.starts_with('/') {
        &ROOT_INODE
    } else {
        &USER_INODE
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
            Arc::clone(base_dir)
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
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        let mut total_read_size = 0usize;
        for slice in buf.buffers.iter_mut() {
            let read_size = inner.inode.read_at(inner.offset, *slice);
            if read_size == 0 {
                break;
            }
            inner.offset += read_size;
            total_read_size += read_size;
        }
        total_read_size
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        let _fs_guard = EXT4_LOCK.lock();
        let mut inner = self.inner.lock();
        let mut total_write_size = 0usize;
        for slice in _buf.buffers.iter() {
            match inner.inode.write_at(inner.offset, &*slice) {
                Ok(write_size) => {
                    if write_size == 0 {
                        break;
                    }
                    inner.offset += write_size;
                    total_write_size += write_size;
                    if write_size < slice.len() {
                        break;
                    }
                }
                Err(_) => {
                    println!("[ext4] Warning: write failed");
                    break;
                }
            }
        }
        total_write_size
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
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
