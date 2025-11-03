#![no_std]
#![feature(alloc_error_handler)]
pub mod utils;
extern crate alloc;
use crate::syscall::syscall;
mod config;
mod console;
mod lang_items;
mod mm;
mod sbi;
mod syscall;
mod task;
mod time;
mod trap;
pub fn test() -> i32 {
    1
}
