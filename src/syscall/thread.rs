// os/src/syscall/thread.rs

use alloc::sync::Arc;

use crate::{
    mm::kernel_token,
    time::get_time_ms,
    task::{
        block_sleep::add_timer,
        manager::add_task,
        processor::{block_current_and_run_next, current_task},
        task_block::TaskControlBlock,
    },
    trap::{context::TrapContext, trap_handler},
};
use crate::debug_config::DEBUG_TIMER;

pub fn sys_thread_create(entry: usize, arg: usize) -> isize {
    let task = current_task().unwrap();
    let process = task.process.upgrade().unwrap();
    // create a new thread
    let new_task = Arc::new(TaskControlBlock::new(
        Arc::clone(&process),
        task.borrow_mut().res.as_ref().unwrap().ustack_base,
        true,
    ));
    // add new task to scheduler
    add_task(Arc::clone(&new_task));
    let new_task_inner = new_task.borrow_mut();
    let new_task_res = new_task_inner.res.as_ref().unwrap();
    let new_task_tid = new_task_res.tid;
    let mut process_inner = process.borrow_mut();
    // add new thread to current process
    let tasks = &mut process_inner.tasks;
    while tasks.len() < new_task_tid + 1 {
        tasks.push(None);
    }
    tasks[new_task_tid] = Some(Arc::clone(&new_task));
    let new_task_trap_cx = new_task_inner.get_trap_cx();
    *new_task_trap_cx = TrapContext::app_init_context(
        entry,
        new_task_res.ustack_top(),
        kernel_token(),
        new_task.kstack.get_top(),
        trap_handler as usize,
    );
    (*new_task_trap_cx).x[10] = arg;
    new_task_tid as isize
}

pub fn sys_gettid() -> isize {
    current_task()
        .unwrap()
        .borrow_mut()
        .res
        .as_ref()
        .unwrap()
        .tid as isize
}

/// thread does not exist, return -1
/// thread has not exited yet, return -2
/// otherwise, return thread's exit code
pub fn sys_waittid(tid: usize) -> i32 {
    let task = current_task().unwrap();
    let process = task.process.upgrade().unwrap();
    let task_inner = task.borrow_mut();
    let mut process_inner = process.borrow_mut();
    // a thread cannot wait for itself
    if task_inner.res.as_ref().unwrap().tid == tid {
        return -1;
    }
    let mut exit_code: Option<i32> = None;
    let waited_task = process_inner.tasks[tid].as_ref();
    if let Some(waited_task) = waited_task {
        if let Some(waited_exit_code) = waited_task.borrow_mut().exit_code {
            exit_code = Some(waited_exit_code);
        }
    } else {
        // waited thread does not exist
        return -1;
    }
    if let Some(exit_code) = exit_code {
        // dealloc the exited thread
        process_inner.tasks[tid] = None;
        exit_code
    } else {
        // waited thread has not exited
        -2
    }
}

pub fn sys_sleep(time_ms: usize) -> isize {
    // Edge case: sleeping for 0ms should return immediately.
    // Blocking here can hang if no timer tick arrives and wakes us up
    // (or if the wakeup happens before we actually block).
    if time_ms == 0 {
        return 0;
    }
    let task = current_task().unwrap();
    if DEBUG_TIMER {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::println!(
            "[sleep] tid={} request_ms={} now_ms={}",
            tid,
            time_ms,
            get_time_ms()
        );
    }
    // Prevent "lost wakeup": make the enqueue+block sequence atomic w.r.t. timer interrupts.
    // If an interrupt fires after we enqueue but before we are actually blocked, the wakeup can
    // be lost and the task may sleep forever.
    unsafe {
        riscv::register::sstatus::clear_sie();
    }
    {
        let mut inner = task.borrow_mut();
        inner.task_status = crate::task::task_block::TaskStatus::Blocked;
    }
    add_timer(Arc::clone(&task), time_ms);
    // This will take the task out of PROCESSOR and switch to idle, letting the scheduler run.
    block_current_and_run_next();
    unsafe {
        riscv::register::sstatus::set_sie();
    }
    if DEBUG_TIMER {
        let tid = task
            .borrow_mut()
            .res
            .as_ref()
            .map(|r| r.tid)
            .unwrap_or(usize::MAX);
        crate::println!(
            "[sleep] tid={} woke now_ms={} slept_for~={}ms",
            tid,
            get_time_ms(),
            time_ms
        );
    }
    0
}
