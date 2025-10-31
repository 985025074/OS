#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    println,
    task::task_context::TaskContext,
    trap::{context::TrapContext, trap::restore},
    utils::RefCellSafe,
};
use lazy_static::lazy_static;
use riscv::{
    interrupt::Trap,
    register::{sepc, sstatus::Sstatus},
};
mod pid;
mod stack;
mod switch;
mod task_block;
mod task_context;
use task_block::{TaskBlock, TaskState};

const MAX_TASKS: usize = 8;
const TARGET_LOC: usize = 0x8040_0000;

pub struct TaskManager {
    pub current_task: isize,
    pub task_blocks: [TaskBlock; MAX_TASKS],
    pub num_tasks: RefCell<usize>,
}
impl TaskManager {
    fn new() -> Self {
        let task_blocks: [TaskBlock; MAX_TASKS] = unsafe { core::mem::zeroed() };
        Self {
            current_task: -1,
            task_blocks: task_blocks,
            num_tasks: RefCell::new(0),
        }
    }
    fn current_task(&self) -> &TaskBlock {
        &self.task_blocks[self.current_task as usize]
    }
    fn load_apps(&mut self) {
        unsafe extern "C" {
            fn num_user_apps();
        }
        unsafe {
            let num_of_apps = *(num_user_apps as *const i64);
            self.num_tasks.replace(num_of_apps as usize);
            println!(
                "[kernel] Loading {} apps...,from adress {}",
                num_of_apps, num_user_apps as usize
            );
            let mut ptr = num_user_apps as *const usize;
            ptr = ptr.add(1); // skip the num_of_apps and the first app start
            for i in 0..num_of_apps {
                let now_app_start = *ptr;
                let now_app_end = *ptr.add(1);
                let now_app_name = *ptr.add(2);
                println!("{:x},{:x},{:x}", now_app_start, now_app_end, now_app_name);
                ptr = ptr.add(3);
                println!(
                    "[kernel] Loading app {} from {:#x} to {:#x}",
                    i, now_app_start, now_app_end
                );
                self.task_blocks[i as usize] =
                    TaskBlock::new(now_app_start, now_app_end, now_app_name, i as usize);
                // code::load_code(i as usize, now_app_start, now_app_end);
                // the above one is handled by new now.
                println!("[kernel] Loaded app {}.", self.task_blocks[i as usize]);
                // println!("{}", self.task_blocks[i as usize].task_context);
            }
        }
    }
}
lazy_static! {
    pub static ref TASK_MANAGER: RefCellSafe<TaskManager> = RefCellSafe::new(TaskManager::new());
}
pub fn task_init() {
    let mut inner = TASK_MANAGER.borrow_mut();
    inner.load_apps();
    drop(inner);
    println!("[kernel] Task initialized.");
}
fn suspend_current_task() {}
fn exit_current_task() {}
fn get_next_task(now: isize) -> isize {
    let now = if now == -1 { 0 } else { now as usize };
    let inner = TASK_MANAGER.borrow();
    let num_apps = *inner.num_tasks.borrow();
    for i in 0..num_apps {
        let index = (now + i + 1) % num_apps;
        if inner.task_blocks[index].state == TaskState::Suspended
            || inner.task_blocks[index].state == TaskState::Ready
        {
            return index as isize;
        }
    }
    return -1;
}

pub fn go_to_first_task() -> ! {
    println!("[kernel] Jumping to first task...");
    go_to_next_task();
    panic!("Unreachable in go_to_first_task!");
}
pub fn go_to_next_task() {
    let inner = TASK_MANAGER.borrow();
    let current = inner.current_task;
    drop(inner);
    let next = get_next_task(current);
    if next == -1 {
        panic!("No more tasks to run!");
    }
    println!("[kernel] Switching to task {}", next);

    let mut inner = TASK_MANAGER.borrow_mut();
    let current = inner.current_task;
    inner.current_task = next;
    inner.task_blocks[next as usize].state = TaskState::Running;
    let new_task_cx_ptr =
        &inner.task_blocks[next as usize].task_context as *const TaskContext as *const usize;
    let old_task_cx_ptr = if current == -1 {
        &TaskContext::new() as *const TaskContext as *mut usize
    } else {
        &mut inner.task_blocks[current as usize].task_context as *mut TaskContext as *mut usize
    };
    drop(inner);
    unsafe { switch::switch(old_task_cx_ptr, new_task_cx_ptr) }
}
pub fn suspend_and_go_to_next() {
    let mut inner = TASK_MANAGER.borrow_mut();
    let current = inner.current_task;
    inner.task_blocks[current as usize].state = TaskState::Suspended;
    drop(inner);
    go_to_next_task();
}
pub fn exit_and_go_to_next() {
    let mut inner = TASK_MANAGER.borrow_mut();
    let current = inner.current_task;
    inner.task_blocks[current as usize].state = TaskState::Exited;
    println!("[kernel] task {} exited!", current);
    drop(inner);
    go_to_next_task();
}
