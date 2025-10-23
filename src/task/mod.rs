#![allow(unused)]

use core::{arch::asm, cell::RefCell, fmt::Display, task};

use crate::{
    console::print,
    println,
    trap::{context::TrapContext, trap::restore},
    utils::RefCellSafe,
};
use lazy_static::lazy_static;
use riscv::{
    interrupt::Trap,
    register::{sepc, sstatus::Sstatus},
};
mod stack;
mod switch;
use stack::{STACK_SIZE, Stack};
mod task_context;
static KERNEL_STACK: Stack = Stack {
    data: [0; STACK_SIZE],
};
static USER_STACK: [Stack; MAX_TASKS] = [Stack {
    data: [0; STACK_SIZE],
}; MAX_TASKS];
const MAX_TASKS: usize = 8;
const TARGET_LOC: usize = 0x8040_0000;
const CODE_SIZE: usize = 4096 * 2; // 4KB
#[derive(Copy, Clone, PartialEq, Eq, Debug)]

enum TaskState {
    Ready = 1,
    Running = 2,
    Suspended = 3,
    Exited = 4,
}
impl Display for TaskState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state_str = match self {
            TaskState::Ready => "Ready",
            TaskState::Running => "Running",
            TaskState::Suspended => "Suspended",
            TaskState::Exited => "Exited",
        };
        write!(f, "{}", state_str)
    }
}
#[derive(Copy, Clone)]
struct TaskBlock {
    task_name: [u8; 32],
    state: TaskState,
    code_start: usize,
    code_end: usize,
    // TODO: 我认为不能写死大小??
}
impl TaskBlock {
    pub fn new_raw() -> Self {
        Self {
            task_name: [0; 32],

            state: TaskState::Exited,
            code_start: 0,
            code_end: 0,
        }
    }
    pub fn new(app_start: usize, app_end: usize, app_name: usize, no: usize) -> Self {
        // unsafe {
        //     let task_name_array =
        //     let app_code = core::slice::from_raw_parts(app_start as *const u8, app_end - app_start);

        // }
        unsafe {
            let _app_name: [u8; 32] = *(app_name as *const [u8; 32]);

            let mut result = Self {
                task_name: _app_name,
                code_start: app_start,
                code_end: app_end,

                state: TaskState::Ready,
            }; // set user stack pointer
            result
        }
    }
}
impl Display for TaskBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name_end = self
            .task_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.task_name.len());
        // .asciz makes sure there is a null terminator
        let name_str = core::str::from_utf8(&self.task_name[..name_end]).unwrap_or("Invalid UTF-8");
        write!(
            f,
            "TaskBlock {{ name: {}, state: {:?}}}",
            name_str, self.state,
        )
    }
}
struct TaskManager {
    current_task: isize,
    task_blocks: [TaskBlock; MAX_TASKS],
    num_tasks: RefCell<usize>,
}
impl TaskManager {
    fn new() -> Self {
        println!("[kernel] Initializing Task Manager.. .");
        Self {
            current_task: -1,
            task_blocks: [TaskBlock::new_raw(); MAX_TASKS],
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
                self.task_blocks[i as usize] =
                    TaskBlock::new(now_app_start, now_app_end, now_app_name, i as usize);
                println!("[kernel] Loaded app {}.", self.task_blocks[i as usize]);
            }
        }
    }
}
lazy_static! {
    static ref TASK_MANAGER: RefCellSafe<TaskManager> = RefCellSafe::new(TaskManager::new());
}
pub fn task_init() {
    let mut inner = TASK_MANAGER.borrow_mut();
    inner.load_apps();
    drop(inner);
    println!("[kernel] Task initialized.");
    load_next_task();
    go_to_first_task();
}
fn suspend_current_task() {}
fn exit_current_task() {}
fn get_next_task() -> isize {
    let inner = TASK_MANAGER.borrow();
    let next = (inner.current_task + 1) as usize;
    let num_apps: usize = *inner.num_tasks.borrow();
    drop(inner);
    if next >= num_apps { -1 } else { next as isize }
}

fn go_to_first_task() -> ! {
    println!("[kernel] Jumping to first task...");
    // here we should restore...
    // push the trap context of the first task

    let mut start_ptr = KERNEL_STACK.top();
    start_ptr -= core::mem::size_of::<TrapContext>();

    unsafe {
        let inner = TASK_MANAGER.borrow_mut();
        let target_place: *mut TrapContext = start_ptr as *mut TrapContext;
        let source_place: *const TrapContext =
            &TrapContext::app_init_context(TARGET_LOC, USER_STACK[0].top());
        drop(inner);

        target_place.copy_from(source_place, 1);

        restore(target_place)
    }

    panic!("Unreachable in go_to_first_task!");
}
pub fn load_next_task() {
    let next = get_next_task();
    if next == -1 {
        panic!("No more tasks to run!");
    }
    println!("[kernel] Switching to task {}", next);
    // load code to target destnation
    load_code(next as usize);
    let mut start_ptr = KERNEL_STACK.top();
    start_ptr -= core::mem::size_of::<TrapContext>();

    // load trap context
    unsafe {
        let inner = TASK_MANAGER.borrow();
        let target_place: *mut TrapContext = start_ptr as *mut TrapContext;
        let source_place: *const TrapContext =
            &TrapContext::app_init_context(TARGET_LOC, USER_STACK[next as usize].top());
        target_place.copy_from(source_place, 1);
    }
    // we dont need to call restore here. because we re in trap this time.
    // and restore will be called automaticly after we exit the trap handler.
}
fn load_code(which: usize) {
    // load the code to TARGET_LOC
    unsafe {
        let task_manager_ref = TASK_MANAGER.borrow();
        let ptr = task_manager_ref.task_blocks[which].code_start as *const u8;
        let end_ptr = task_manager_ref.task_blocks[which].code_end as *const u8;
        (TARGET_LOC as *mut u8).copy_from(ptr, end_ptr.offset_from(ptr) as usize);
        drop(task_manager_ref);
    }
    let mut inner = TASK_MANAGER.borrow_mut();
    inner.current_task = which as isize;
    drop(inner);
    unsafe {
        asm!("fence.i");
    }
}
