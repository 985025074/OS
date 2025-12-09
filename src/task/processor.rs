use crate::{
    println,
    sbi::shutdown,
    task::{
        INITPROC,
        id::TaskUserRes,
        manager::{
            TASK_MANAGER, add_task, fetch_task, remove_from_pid2process, remove_inactive_task,
        },
        process_block::ProcessControlBlock,
        switch,
        task_block::{TaskControlBlock, TaskStatus},
        task_context::{self, TaskContext},
    },
    utils::RefCellSafe,
};

use alloc::{sync::Arc, task, vec::Vec};
use lazy_static::lazy_static;
pub struct Processor {
    now_task_block: Option<Arc<TaskControlBlock>>,
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

    pub fn take_current_task(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.take()
    }
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.now_task_block.as_ref().cloned()
    }
}
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    let processor = PROCESSOR.borrow();
    let task = processor.current();
    drop(processor);
    task
}
pub fn current_process() -> Arc<ProcessControlBlock> {
    current_task().unwrap().process.upgrade().unwrap()
}

// todo
pub fn current_process_has_child(pid_or_negative: isize, exit_code: &mut i32) -> Option<usize> {
    // 获取当前任务（当前正在运行的进程）
    let pid = pid_or_negative;

    let cur_process = current_process();
    // Clone children_vec in a separate scope to release the borrow immediately
    let children_vec = {
        let process_inner = cur_process.borrow_mut();
        process_inner.children.clone()
    }; // process_inner is dropped here, releasing the borrow

    // 遍历当前任务的所有子任务
    let mut possible_index: Option<usize> = None;
    let mut found_pid: Option<usize> = None;

    for (index, child) in children_vec.iter().enumerate() {
        // 匹配 pid 且子进程已退出
        let child_inner = child.borrow_mut();
        if (pid == -1 || child.pid.0 == pid as usize) && child_inner.is_zombie {
            // 将退出码写入 exit_code
            *exit_code = child_inner.exit_code;
            possible_index = Some(index);
            found_pid = Some(child.pid.0);
            drop(child_inner);
            break;
        }
        drop(child_inner);
    }

    if let Some(pid_index) = possible_index {
        // Remove the child from parent's children list
        let mut process_inner = cur_process.borrow_mut();
        let child = process_inner.children.remove(pid_index);
        drop(process_inner);
        // The child process will be deallocated when Arc count reaches 0
        return found_pid;
    }
    None
}

pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
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
            let mut task_inner = task.borrow_mut();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;

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
            // No ready tasks - just release lock and continue loop
            drop(processor);
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
    let mut task_inner = task.borrow_mut();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- release current PCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}
pub fn block_current_and_run_next() {
    // There must be an application running.
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.borrow_mut();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Blocked;
    drop(task_inner);
    // ---- release current PCB

    // we dont need to add block task here;
    // add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}
pub fn wakeup_task(task: Arc<TaskControlBlock>) {
    let mut task_inner = task.borrow_mut();
    assert_eq!(task_inner.task_status, TaskStatus::Blocked);
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    add_task(task);
}

/// pid of usertests app in make run TEST=1
pub const IDLE_PID: usize = 0;

// 线程(task)  单位的推出
pub fn exit_current_and_run_next(exit_code: i32) {
    // 标记线程状态,
    let task = take_current_task().unwrap();
    let process = task.process.upgrade().unwrap();

    // Extract tid in a separate scope to release the borrow early
    let tid = {
        let mut task_inner = task.borrow_mut();
        task_inner.exit_code = Some(exit_code);
        let tid = task_inner
            .res
            .as_ref()
            .expect("task user resource should exist before exit")
            .tid;
        // drop 自动释放
        task_inner.res = None;
        tid
    }; // task_inner is dropped here, releasing the borrow

    // 已经从current_task拿走了 所以 对于一般的 线程,可以了.
    //  对于主线程,我们需要处理一些 清理工作
    // 对于系统进程,直接推出
    // 一般进程
    // 1.将 进程标记为推出(主线程推出,进程推出)
    // 2.将 子进程 交给 initproc 进程
    // 3.回收资源
    //      回收资源的思路是: 将所有子线程的资源拿走,放到一个临时的 vec 中,通过 drop 进行回收
    //      然后回收 进程的内存空间,文件描述符
    // 对于主线程,需要进行更多的清理工作
    if tid == 0 {
        let pid = process.getpid();
        if pid == IDLE_PID {
            println!(
                "[kernel] Idle process exit with exit_code {} ...",
                exit_code
            );
            if exit_code != 0 {
                //crate::sbi::shutdown(255); //255 == -1 for err hint
                shutdown();
            } else {
                //crate::sbi::shutdown(0); //0 for success hint
                shutdown();
            }
        }
        remove_from_pid2process(pid);
        let mut process_inner = process.borrow_mut();
        // mark this process as a zombie process
        process_inner.is_zombie = true;
        // record exit code of main process
        process_inner.exit_code = exit_code;

        // 非 系统进程,执行之前的 将 子进程 交给 initproc 进程  过程
        {
            // move all child processes under init process
            let mut initproc_inner = INITPROC.borrow_mut();
            for child in process_inner.children.iter() {
                child.borrow_mut().parent = Some(Arc::downgrade(&INITPROC));
                initproc_inner.children.push(child.clone());
            }
        }

        // deallocate user res (including tid/trap_cx/ustack) of all threads
        // it has to be done before we dealloc the whole memory_set
        // otherwise they will be deallocated twice
        // 接下来,处理 线程资源回收
        // 首先先将 所有子线程的资源 载入
        let mut recycle_res = Vec::<TaskUserRes>::new();
        for task in process_inner.tasks.iter().filter(|t| t.is_some()) {
            let task = task.as_ref().unwrap();
            // if other tasks are Ready in TaskManager or waiting for a timer to be
            // expired, we should remove them.
            //
            // Mention that we do not need to consider Mutex/Semaphore since they
            // are limited in a single process. Therefore, the blocked tasks are
            // removed when the PCB is deallocated.
            remove_inactive_task(Arc::clone(&task));
            let mut task_inner = task.borrow_mut();
            if let Some(res) = task_inner.res.take() {
                recycle_res.push(res);
            }
        }
        // dealloc_tid and dealloc_user_res require access to PCB inner, so we
        // need to collect those user res first, then release process_inner
        // for now to avoid deadlock/double borrow problem.
        drop(process_inner);
        recycle_res.clear();

        let mut process_inner = process.borrow_mut();
        process_inner.children.clear();
        // deallocate other data in user space i.e. program code/data section
        process_inner.memory_set.recycle_data_pages();
        // drop file descriptors
        process_inner.fd_table.clear();
        // Remove all tasks except for the main thread itself.
        // This is because we are still using the kstack under the TCB
        // of the main thread. This TCB, including its kstack, will be
        // deallocated when the process is reaped via waitpid.
        //
        while process_inner.tasks.len() > 1 {
            process_inner.tasks.pop();
        }
    }

    drop(process);
    // we do not have to save task context
    // println!(
    //     "[DEBUG] exit_current_and_run_next: about to schedule, tid={}",
    //     tid
    // );
    let mut _unused = TaskContext::new();
    schedule(&mut _unused as *mut _);
}
