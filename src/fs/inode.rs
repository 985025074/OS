//! Inode abstraction for ext4 filesystem

use super::File;
use crate::drivers::BLOCK_DEVICE;
use crate::mm::UserBuffer;
use crate::println;
use crate::utils::RefCellSafe;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use ext4_fs::{Ext4FileSystem, Inode};
use lazy_static::*;
use riscv::register::sstatus;

/// Disable interrupts and return previous state
fn disable_interrupts() -> bool {
    let was_enabled = sstatus::read().sie();
    unsafe {
        sstatus::clear_sie();
    }
    was_enabled
}

/// Restore interrupt state
fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        unsafe {
            sstatus::set_sie();
        }
    }
}

/// A wrapper around a filesystem inode to implement File trait
pub struct OSInode {
    readable: bool,
    writable: bool,
    inner: RefCellSafe<OSInodeInner>,
}

/// The OS inode inner in 'RefCellSafe'
pub struct OSInodeInner {
    offset: usize,
    inode: Arc<Inode>,
}

impl OSInode {
    /// Construct an OS inode from an inode
    pub fn new(readable: bool, writable: bool, inode: Arc<Inode>) -> Self {
        Self {
            readable,
            writable,
            inner: unsafe { RefCellSafe::new(OSInodeInner { offset: 0, inode }) },
        }
    }

    /// Read all data inside an inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        // Disable interrupts while accessing ext4
        let int_enabled = disable_interrupts();

        let mut inner = self.inner.borrow_mut();
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

        drop(inner);
        restore_interrupts(int_enabled);
        v
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

    // ext4 is read-only, so CREATE is not supported
    if flags.contains(OpenFlags::CREATE) {
        return None;
    }

    // Disable interrupts while accessing ext4 to prevent deadlock with spin::Mutex
    let int_enabled = disable_interrupts();

    // Look for file in /user directory
    let inode = USER_INODE.find(name).or_else(|| {
        // Try adding .bin suffix if not found
        let name_with_bin = alloc::format!("{}.bin", name);
        USER_INODE.find(&name_with_bin)
    });

    // Restore interrupts
    restore_interrupts(int_enabled);

    inode.map(|inode| Arc::new(OSInode::new(readable, writable, inode)))
}

impl File for OSInode {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writable
    }

    fn read(&self, mut buf: UserBuffer) -> usize {
        // Disable interrupts while accessing ext4
        let int_enabled = disable_interrupts();

        let mut inner = self.inner.borrow_mut();
        let mut total_read_size = 0usize;
        for slice in buf.buffers.iter_mut() {
            let read_size = inner.inode.read_at(inner.offset, *slice);
            if read_size == 0 {
                break;
            }
            inner.offset += read_size;
            total_read_size += read_size;
        }
        drop(inner);
        restore_interrupts(int_enabled);
        total_read_size
    }

    fn write(&self, _buf: UserBuffer) -> usize {
        // ext4 is read-only
        println!("[ext4] Warning: write not supported (read-only fs)");
        0
    }
}
