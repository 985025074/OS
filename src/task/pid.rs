use alloc::{sync::Arc, task, vec::Vec};
use lazy_static::lazy_static;

use crate::{
    println,
    task::{manager::TASK_MANAGER, processor::current_task, task_block::TaskBlock},
    utils::RefCellSafe,
};

pub struct Pid(pub usize);
pub struct PidAllocator {
    recycle: Vec<usize>,
    next: usize,
}
impl PidAllocator {
    fn new() -> Self {
        Self {
            recycle: Vec::new(),
            next: 0,
        }
    }
    fn alloc(&mut self) -> Pid {
        if let Some(pid) = self.recycle.pop() {
            Pid(pid)
        } else {
            let pid = self.next;
            self.next += 1;
            Pid(pid)
        }
    }
    fn dealloc(&mut self, pid: usize) {
        self.recycle.push(pid);
    }
}

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref PID_ALLOCATOR: RefCellSafe<PidAllocator> =
        unsafe { RefCellSafe::new(PidAllocator::new()) };
}
pub fn alloc_pid() -> Pid {
    PID_ALLOCATOR.borrow_mut().alloc()
}
pub fn dealloc_pid(pid: usize) {
    PID_ALLOCATOR.borrow_mut().dealloc(pid);
}
pub fn get_task_by_pid(pid: usize) -> Option<Arc<TaskBlock>> {
    if let Some(task) = current_task() {
        if task.pid.0 == pid {
            return Some(task);
        }
    }
    let task_manager = TASK_MANAGER.borrow();
    for task in task_manager.task_blocks.iter() {
        if task.pid.0 == pid {
            return Some(task.clone());
        }
    }
    None
}
impl Drop for Pid {
    fn drop(&mut self) {
        dealloc_pid(self.0);
    }
}
