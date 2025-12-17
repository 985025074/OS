use alloc::collections::binary_heap::BinaryHeap;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use lazy_static::*;

use crate::debug_config::DEBUG_SCHED;
use crate::task::block_sleep::{TIMERS, TimeWrap};
use crate::task::process_block::ProcessControlBlock;
use crate::task::task_block::{TaskControlBlock, TaskStatus};
use spin::Mutex;

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
        // Avoid enqueueing the same task multiple times; this can happen if we
        // preempt a task that is already sitting in the ready queue (e.g., due to
        // rapid timer interrupts).
        if self
            .ready_queue
            .iter()
            .any(|t| Arc::ptr_eq(t, &task))
        {
            if DEBUG_SCHED {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                crate::println!(
                    "[sched] skip add duplicate tid={} ready_queue_len={}",
                    tid,
                    self.ready_queue.len()
                );
            }
            return;
        }
        if DEBUG_SCHED {
            let tid = task
                .borrow_mut()
                .res
                .as_ref()
                .map(|r| r.tid)
                .unwrap_or(usize::MAX);
            crate::println!(
                "[sched] add_task tid={} ready_queue_len_before={}",
                tid,
                self.ready_queue.len()
            );
        }
        self.ready_queue.push_back(task);
        if DEBUG_SCHED {
            crate::println!("[sched] ready_queue_len_after={}", self.ready_queue.len());
        }
    }
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        let t = self.ready_queue.pop_front();
        if DEBUG_SCHED {
            if let Some(ref task) = t {
                let tid = task
                    .borrow_mut()
                    .res
                    .as_ref()
                    .map(|r| r.tid)
                    .unwrap_or(usize::MAX);
                crate::println!(
                    "[sched] fetch_task -> Some(tid={}) remaining_len={}",
                    tid,
                    self.ready_queue.len()
                );
            } else {
                crate::println!("[sched] fetch_task -> None (len=0)");
            }
        }
        t
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
    pub static ref TASK_MANAGER: Mutex<TaskManager> = Mutex::new(TaskManager::new());
    pub static ref PID2PCB: Mutex<BTreeMap<usize, Arc<ProcessControlBlock>>> =
        Mutex::new(BTreeMap::new());
}

pub fn add_task(task: Arc<TaskControlBlock>) {
    // Protect the ready queue from timer interrupt re-entrancy, but restore the previous SIE state.
    let prev_sie = riscv::register::sstatus::read().sie();
    unsafe { riscv::register::sstatus::clear_sie() };
    TASK_MANAGER.lock().add(task);
    if prev_sie {
        unsafe { riscv::register::sstatus::set_sie() };
    }
}

pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    let mut task_inner = task.borrow_mut();
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    add_task(task);
}

pub fn remove_task(task: Arc<TaskControlBlock>) {
    let prev_sie = riscv::register::sstatus::read().sie();
    unsafe { riscv::register::sstatus::clear_sie() };
    TASK_MANAGER.lock().remove(task);
    if prev_sie {
        unsafe { riscv::register::sstatus::set_sie() };
    }
}

pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    let prev_sie = riscv::register::sstatus::read().sie();
    unsafe { riscv::register::sstatus::clear_sie() };
    let t = TASK_MANAGER.lock().fetch();
    if prev_sie {
        unsafe { riscv::register::sstatus::set_sie() };
    }
    t
}

pub fn pid2process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let map = PID2PCB.lock();
    map.get(&pid).map(Arc::clone)
}

pub fn insert_into_pid2process(pid: usize, process: Arc<ProcessControlBlock>) {
    PID2PCB.lock().insert(pid, process);
}

pub fn remove_from_pid2process(pid: usize) {
    let mut map = PID2PCB.lock();
    if map.remove(&pid).is_none() {
        panic!("cannot find pid {} in pid2task!", pid);
    }
}

pub fn remove_timer(task: Arc<TaskControlBlock>) {
    let mut timers = TIMERS.lock();
    let mut temp = BinaryHeap::<TimeWrap>::new();
    for condvar in timers.drain() {
        if Arc::as_ptr(&task) != Arc::as_ptr(&condvar.task) {
            temp.push(condvar);
        }
    }
    timers.clear();
    timers.append(&mut temp);
}

pub fn remove_inactive_task(task: Arc<TaskControlBlock>) {
    // 这里可能会加入 todo
    remove_timer(task.clone());
    remove_task(task.clone());
}
