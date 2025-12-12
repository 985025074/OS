#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(str_from_raw_parts)]
#![allow(unreachable_code)]
use core::{arch::global_asm, panic};
extern crate alloc;
use crate::{fs::list_apps, syscall::syscall};
mod config;
mod console;
mod debug_config;
mod drivers;
mod fs;
mod lang_items;
mod mm;
mod sbi;
mod syscall;
mod task;
mod time;
mod trap;
mod utils;

global_asm!(include_str!("entry.asm"));
global_asm!(include_str!("link_app.asm"));
#[unsafe(no_mangle)]
fn rust_main() {
    unsafe extern "C" {
        fn num_user_apps();
        safe fn sbss();
        safe fn ebss();
    }
    unsafe {
        //clear bss
        let bss_start = sbss as usize;
        let bss_end = ebss as usize;
        let bss_size = bss_end - bss_start;
        core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);

        //一个word是4字节
        let num_of_apps = *(num_user_apps as *const i64);
        println!(
            "Number of user apps: {}, from adress {}",
            num_of_apps, num_user_apps as usize
        );
    }
    println!("Hello, CongCore!");
    mm::init();
    mm::remap_test();
    println!("[kernel] memory management initialized.");
    trap::init_trap();
    trap::trap::enable_timer_interrupt();
    time::set_next_trigger();
    list_apps();
    task::task_start();
    panic!("shouldn't be here");
}
