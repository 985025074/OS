//! File system in os
mod inode;
mod pipe;
mod socketpair;
mod net_socket;
mod stdio;
mod pseudo;
mod dummy;
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

pub use inode::{EXT4_FS, OSInode, OpenFlags, ROOT_INODE, USER_INODE, list_apps, open_file};
pub(crate) use inode::ext4_lock;
pub use pipe::{Pipe, make_pipe};
pub use socketpair::{SocketPairEnd, make_socketpair};
pub use net_socket::{NetSocketFile, NetSocketKind};
pub use stdio::{Stdin, Stdout};
pub use pseudo::{PseudoDir, PseudoDirent, PseudoFile, PseudoKindTag, PseudoShmFile, RtcFile};
pub use pseudo::PseudoBlock;
pub use dummy::DummyFile;
pub(crate) use pseudo::{shm_create, shm_get, shm_list, shm_remove};
