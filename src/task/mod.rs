#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    fs::{OpenFlags, open_file},
    println,
    task::{
        manager::{TASK_MANAGER, add_task},
        process_block::ProcessControlBlock,
        processor::{current_task, go_to_first_task},
        task_context::TaskContext,
    },
    trap::{context::TrapContext, trap::restore},
    utils::RefCellSafe,
};
use alloc::sync::Arc;
use lazy_static::lazy_static;
use riscv::{
    interrupt::Trap,
    register::{sepc, sstatus::Sstatus},
};
pub mod block_sleep;
pub mod condvar;
mod id;
pub mod manager;
pub mod mutex;
mod process_block;
pub mod processor;
pub mod semaphore;
pub mod signal;
mod switch;
pub mod task_block;
pub mod task_context;
lazy_static! {
    pub static ref INITPROC: Arc<ProcessControlBlock> = {
        let inode = open_file("init_proc.bin", OpenFlags::RDONLY).unwrap();
        let data = inode.read_all();
        ProcessControlBlock::new(&data)
    };
}
pub fn task_init() {
    // Force INITPROC initialization in release builds.
    lazy_static::initialize(&INITPROC);
    crate::println!("[kernel] INITPROC initialized and enqueued");
}
pub fn task_start() {
    task_init();
    go_to_first_task();
}
/// Start scheduler on secondary harts without re-initializing initproc.
pub fn task_start_secondary() -> ! {
    go_to_first_task();
}
