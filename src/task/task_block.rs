use alloc::rc::Weak;
use alloc::sync::Arc;
use alloc::vec::Vec;
use riscv::interrupt::Trap;

use crate::config::{TRAMPOLINE, TRAP_CONTEXT, kernel_stack_position};
use crate::mm::{KERNEL_SPACE, MapPermission, MemorySet, PhysPageNum, VirtAddr, VirtPageNum};
use crate::task::manager::TaskManager;
use crate::task::pid::{Pid, alloc_pid};
use crate::task::stack::KernelStack;
use crate::trap::context::{TrapContext, push_trap_context_at};
use crate::trap::{trap_handler, trap_return};
use crate::utils::RefCellSafe;
use crate::{println, trap};

use super::restore;
use super::task_context::TaskContext;
use core::cell::{Ref, RefMut};
use core::fmt::Display;
#[derive(Copy, Clone, PartialEq, Eq, Debug)]

pub enum TaskState {
    //if it is ready,it means the program has not been run
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

pub struct TaskBlock {
    pub pid: Pid,
    pub task_name: [u8; 32],

    // we hold this.. just because for RAII
    pub kernel_stack: KernelStack,
    // becuase we will use arc in the future, so if we want to change we need to use the Refcell
    task_block_inner: RefCellSafe<TaskBlockInner>,
}
pub struct TaskBlockInner {
    pub state: TaskState,

    // we just need task context for a task... trap context is held in the user space..
    pub task_context: TaskContext,
    pub code_memory_set: MemorySet,
    // becuase now the trap context is stored in the user memoryspace so we need to
    // store an adress here to make sure we can pass it to the restore
    // when we exit the trap handler...
    pub trap_context_loc: PhysPageNum,
    pub children_task: Vec<Arc<TaskBlock>>,
    pub father_task: Option<Weak<TaskBlock>>,
}
impl TaskBlock {
    pub fn new_raw() -> Self {
        Self {
            kernel_stack: KernelStack::new(99),
            pid: Pid(99),
            task_name: [0; 32],
            task_block_inner: RefCellSafe::new(TaskBlockInner {
                task_context: TaskContext::new(),
                state: TaskState::Exited,
                code_memory_set: MemorySet::new_bare(),
                trap_context_loc: PhysPageNum(0),
                children_task: Vec::new(),
                father_task: None,
            }),
        }
    }
    pub fn get_inner(&self) -> RefMut<'_, TaskBlockInner> {
        self.task_block_inner.borrow_mut()
    }
    pub fn new(elf_data: &[u8], app_name: usize) -> Self {
        // unsafe {
        //     let task_name_array =
        //     let app_code = core::slice::from_raw_parts(app_start as *const u8, app_end - app_start);

        // }
        // let trap_context_ptr = KERNEL_STACK[no].push_trap_context(
        //     crate::trap::context::TrapContext::app_init_context(
        //         the_code_start(no),
        //         USER_STACK[no].top(),
        //     ),
        // );
        //get pid
        let pid = alloc_pid();
        let (mem_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        // already insert the trampolitan area in memset so we only need to insert data;
        let kernel_stack = KernelStack::new(pid.0);
        let kernel_stack_top = kernel_stack.kernel_stack_top;
        let trap_page = mem_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // todo : make sure the top is what we want;
        // todo: draw a picture here.
        let token = KERNEL_SPACE.borrow().token();
        let trap_context = crate::trap::context::TrapContext::app_init_context(
            entry_point,
            user_sp,
            token,
            kernel_stack.kernel_stack_top,
            trap_handler as usize,
        );

        let trap_context_ref: &mut TrapContext = trap_page.get_mut();
        *trap_context_ref = trap_context;

        unsafe {
            let _app_name: [u8; 32] = *(app_name as *const [u8; 32]);

            let mut result = Self {
                pid,
                task_name: _app_name,

                kernel_stack,
                // fill this later
                task_block_inner: RefCellSafe::new(TaskBlockInner {
                    task_context: TaskContext::set_for_app(trap_return as usize, kernel_stack_top),
                    state: TaskState::Ready,
                    code_memory_set: mem_set,
                    trap_context_loc: trap_page,
                    father_task: None,
                    children_task: Vec::new(),
                }),
            }; // set user stack pointer
            result
        }
    }
}
// impl Display for TaskBlock {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         let name_end = self
//             .task_name
//             .iter()
//             .position(|&c| c == 0)
//             .unwrap_or(self.task_name.len());
//         // .asciz makes sure there is a null terminator
//         let name_str = core::str::from_utf8(&self.task_name[..name_end]).unwrap_or("Invalid UTF-8");
//         write!(
//             f,
//             "TaskBlock {{ name: {}, state: {:?}}}",
//             name_str, self.state,
//         )
//     }
// }
