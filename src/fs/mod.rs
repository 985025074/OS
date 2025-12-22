//! File system in os
mod inode;
mod pipe;
mod stdio;
mod pseudo;
use crate::mm::UserBuffer;
use core::any::Any;

/// File trait
pub trait File: Send + Sync {
    /// If readable
    fn readable(&self) -> bool;
    /// If writable
    fn writable(&self) -> bool;
    /// Read file to `UserBuffer`
    fn read(&self, buf: UserBuffer) -> usize;
    /// Write `UserBuffer` to file
    fn write(&self, buf: UserBuffer) -> usize;
    fn as_any(&self) -> &dyn Any;
}

pub use inode::{OSInode, OpenFlags, ROOT_INODE, USER_INODE, list_apps, open_file};
pub(crate) use inode::ext4_lock;
pub use pipe::{Pipe, make_pipe};
pub use stdio::{Stdin, Stdout};
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, RtcFile};
