#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    fs::{OpenFlags, open_file},
    println,
    task::{
        manager::{TASK_MANAGER, add_task},
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
pub mod manager;
mod pid;
pub mod processor;
pub mod signal;
mod stack;
mod switch;
pub mod task_block;
pub mod task_context;
use task_block::{TaskBlock, TaskState};
lazy_static! {
    pub static ref INITPROC: Arc<TaskBlock> = {
        let inode = open_file("init_proc", OpenFlags::RDONLY).unwrap();
        Arc::new(TaskBlock::new(
            &inode.read_all(),
            "init_proc".as_ptr() as usize,
        ))
    };
}

pub fn task_init() {
    add_task(INITPROC.clone());
    println!("[kernel] Task initialized.");
}
pub fn task_start() {
    go_to_first_task();
}
