#![no_std]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
pub mod utils;
extern crate alloc;
mod config;
mod console;
pub mod debug_config;
mod drivers;
mod fs;
mod lang_items;
mod log;
mod mm;
mod sbi;
mod syscall;
mod task;
mod time;
mod trap;
