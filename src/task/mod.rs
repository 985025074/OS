#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    println,
    task::{manager::TASK_MANAGER, processor::go_to_first_task, task_context::TaskContext},
    trap::{context::TrapContext, trap::restore},
    utils::RefCellSafe,
};
use lazy_static::lazy_static;
use riscv::{
    interrupt::Trap,
    register::{sepc, sstatus::Sstatus},
};
pub mod manager;
mod pid;
pub mod processor;
mod stack;
mod switch;
pub mod task_block;
pub mod task_context;
use task_block::{TaskBlock, TaskState};
pub fn task_init() {
    let mut inner = TASK_MANAGER.borrow_mut();
    inner.load_app_by_name("00shell\0");
    drop(inner);
    println!("[kernel] Task initialized.");
}
pub fn task_start() {
    go_to_first_task();
}
