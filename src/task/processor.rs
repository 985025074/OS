use crate::{
    println,
    task::{
        INITPROC,
        manager::{TASK_MANAGER, add_task, fetch_task},
        switch,
        task_block::{self, TaskBlock, TaskState},
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
pub fn current_task() -> Option<Arc<TaskBlock>> {
    let processor = PROCESSOR.borrow();
    let task = processor.current();
    drop(processor);
    task
}
pub fn current_task_has_child(pid_or_negative: isize, exit_code: &mut i32) -> Option<usize> {
    // 获取当前任务（当前正在运行的进程）
    let pid = pid_or_negative;
    if let Some(current) = current_task() {
        // 获取当前任务的内部可变数据
        let mut inner = current.get_inner();

        // 遍历当前任务的所有子任务
        let mut possible_index: Option<usize> = None;
        for (index, child) in inner.children_task.iter().enumerate() {
            let child_inner = child.get_inner();

            // 匹配 pid 且子进程已退出
            if (pid == -1 || child.pid.0 == pid as usize) && child_inner.state == TaskState::Exited
            {
                // 将退出码写入 exit_code
                *exit_code = child_inner.exit_code;
                possible_index = Some(index);
                break;
            }
            drop(child_inner);
        }
        if let Some(pid_index) = possible_index {
            let child = inner.children_task.remove(pid_index);
            return Some(child.pid.0);
        }
        drop(inner);
    }
    None

    // 没有找到匹配的子任务
}

pub fn take_current_task() -> Option<Arc<TaskBlock>> {
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
        // println!("[idle] trying to fetch next task");
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
    // move the child to init_proc
    let mut init_proc_inner = INITPROC.get_inner();
    for child in &inner.children_task {
        let child_target = child.clone();
        child.get_inner().father_task = Some(Arc::downgrade(&INITPROC));
        init_proc_inner.children_task.push(child.clone());
    }
    drop(init_proc_inner);
    //todo : is it necessary to claer here ??
    drop(inner);
    // **** release current PCB
    // drop task manually to maintain rc correctly
    drop(task);
    // we do not have to save task context
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}
