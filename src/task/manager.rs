use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

use crate::task::process_block::ProcessControlBlock;
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use crate::utils::RefCellSafe;

pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.ready_queue.pop_front()
    }
    pub fn remove(&mut self, task: Arc<TaskControlBlock>) {
        if let Some((id, _)) = self
            .ready_queue
            .iter()
            .enumerate()
            .find(|(_, t)| Arc::as_ptr(t) == Arc::as_ptr(&task))
        {
            self.ready_queue.remove(id);
        }
    }
}

lazy_static! {
    pub static ref TASK_MANAGER: RefCellSafe<TaskManager> =
        unsafe { RefCellSafe::new(TaskManager::new()) };
    pub static ref PID2PCB: RefCellSafe<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        unsafe { RefCellSafe::new(BTreeMap::new()) };
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.borrow_mut().add(task);
}

pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    let mut task_inner = task.borrow_mut();
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    add_task(task);
}

pub fn remove_task(task: Arc<TaskControlBlock>) {
    TASK_MANAGER.borrow_mut().remove(task);
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    TASK_MANAGER.borrow_mut().fetch()
}

pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.borrow_mut();
    map.get(&pid).map(Arc::clone)
}

pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    PID2PCB.borrow_mut().insert(pid, process);
}

pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.borrow_mut();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
    }
}

pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    // 这里可能会加入 todo
    remove_task(task);
}
