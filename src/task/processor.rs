use crate::{
    println,
    task::{
        manager::{TASK_MANAGER, add_task, fetch_task},
        switch,
        task_block::{TaskBlock, TaskState},
        task_context::{self, TaskContext},
    },
    utils::RefCellSafe,
};

use alloc::{sync::Arc, task};
use lazy_static::lazy_static;
pub struct Processor {
    now_task_block: Option<Arc<TaskBlock>>,
    idle_task_context: TaskContext,
}
impl Processor {
    pub fn new() -> Self {
        Self {
            now_task_block: None,
            idle_task_context: TaskContext::new(),
        }
    }
    pub fn get_idle_task_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_context as *mut _
    }

    pub fn take_current_task(&mut self) -> Option<Arc<TaskBlock>> {
        self.now_task_block.take()
    }
    pub fn current(&self) -> Option<Arc<TaskBlock>> {
        self.now_task_block.as_ref().cloned()
    }
}
fn take_current_task() -> Option<Arc<TaskBlock>> {
    let mut processor = PROCESSOR.borrow_mut();
    let task = processor.take_current_task();
    drop(processor);
    task
}
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.borrow_mut();
    let idle_task_cx_ptr = processor.get_idle_task_ptr();
    drop(processor);
    // println!(
    //     "schedule: switch from {:x} to {:x}",
    //     switched_task_cx_ptr as usize, idle_task_cx_ptr as usize
    // );
    unsafe {
        switch::switch(
            switched_task_cx_ptr as *const usize,
            idle_task_cx_ptr as *const usize,
        );
    }
}
pub fn idle_task() {
    loop {
        let mut processor = PROCESSOR.borrow_mut();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.get_inner();
            let next_task_cx_ptr = &task_inner.task_context as *const TaskContext;
            task_inner.state = TaskState::Running;
            drop(task_inner);
            // release coming task TCB manually
            processor.now_task_block = Some(task);
            // release processor manually
            drop(processor);
            println!(
                "switch from {:x} to {:x}",
                idle_task_cx_ptr as usize, next_task_cx_ptr as usize
            );
            unsafe {
                switch::switch(
                    idle_task_cx_ptr as *const usize,
                    next_task_cx_ptr as *const usize,
                );
            }
        } else {
            panic!("all tasks done!");
        }
    }
}
lazy_static! {
    pub static ref PROCESSOR: RefCellSafe<Processor> = RefCellSafe::new(Processor::new());
}

pub fn go_to_first_task() -> ! {
    idle_task();
    panic!("Unreachable in go_to_first_task!");
}
pub fn suspend_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.get_inner();
    let task_cx_ptr = &mut task_inner.task_context as *mut TaskContext;
    // Change status to Ready
    task_inner.state = TaskState::Ready;
    drop(task_inner);
    // ---- release current PCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

/// pid of usertests app in make run TEST=1
pub const IDLE_PID: usize = 0;

/// Exit the current 'Running' task and run the next task in task list.
pub fn exit_current_and_run_next(exit_code: i32) {
    println!("[kernel] Exiting current task with exit code {}", exit_code);
    // take from Processor
    let task = take_current_task().unwrap();

    // **** access current TCB exclusively
    let mut inner = task.get_inner();
    // Change status to Zombie
    inner.state = TaskState::Exited;
    // ++++++ release parent PCB

    drop(inner);
    // **** release current PCB
    // drop task manually to maintain rc correctly
    drop(task);
    // we do not have to save task context
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}
