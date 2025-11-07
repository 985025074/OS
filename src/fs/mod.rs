//! File system in os
mod inode;
mod stdio;

use crate::{mm::UserBuffer, println};
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
}

use easy_fs::debug::Logger;
pub use inode::{OSInode, OpenFlags, list_apps, open_file};
pub use stdio::{Stdin, Stdout};
struct PrintlnLogger;
impl Logger for PrintlnLogger {
    fn log(&self, record: &str) {
        println!("[EFS DEBUG]: {}", record);
    }
}
pub fn init_fs_debuger() {
    println!("init fs debuger");
    easy_fs::debug::set_logger(&PrintlnLogger);
}
