use super::restore;
use super::task_context::TaskContext;
use crate::config::{TRAMPOLINE, TRAP_CONTEXT, kernel_stack_position};
use crate::fs::{File, Stdin, Stdout};
use crate::mm::{KERNEL_SPACE, MapPermission, MemorySet, PhysPageNum, VirtAddr, VirtPageNum};
use crate::task::manager::TaskManager;
use crate::task::pid::{Pid, alloc_pid};
use crate::task::stack::KernelStack;
use crate::trap::context::{TrapContext, push_trap_context_at};
use crate::trap::{trap_handler, trap_return};
use crate::utils::{RefCellSafe, get_app_data_by_name};
use crate::{println, trap};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Ref, RefMut};
use core::fmt::Display;
use riscv::interrupt::Trap;
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
    pub exit_code: i32,
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
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
                exit_code: 0,
                fd_table: Vec::new(),
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
                    exit_code: 0,
                    fd_table: vec![
                        Some(Arc::new(Stdin)),
                        // 1 -> stdout
                        Some(Arc::new(Stdout)),
                        // 2 -> stderr
                        Some(Arc::new(Stdout)),
                    ],
                }),
            }; // set user stack pointer
            result
        }
    }
    // ...existing code...
    pub fn exec(&self, name: usize) -> Result<(), &'static str> {
        unsafe extern "C" {
            fn num_user_apps();
        }
        let number_of_apps = unsafe { *(num_user_apps as *const i64) } as usize;
        let start_loc = (num_user_apps as usize) + core::mem::size_of::<usize>();
        let elf_data = get_app_data_by_name(name, number_of_apps, start_loc);
        let (mem_set, user_sp, entry_point) = MemorySet::from_elf(&elf_data);
        let kernel_stack_top = self.kernel_stack.kernel_stack_top;
        let trap_page = mem_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .ok_or("ERROR while get trap context")?
            .ppn();
        self.get_inner().code_memory_set = mem_set;
        let token = KERNEL_SPACE.borrow().token();
        let trap_context = crate::trap::context::TrapContext::app_init_context(
            entry_point,
            user_sp,
            token,
            kernel_stack_top,
            trap_handler as usize,
        );
        let trap_context_ref: &mut TrapContext = trap_page.get_mut();
        *trap_context_ref = trap_context;
        self.get_inner().trap_context_loc = trap_page;
        self.get_inner().task_context =
            TaskContext::set_for_app(trap_return as usize, kernel_stack_top);
        // self.get_inner().state = TaskState::Ready; // 确保任务准备运行
        Ok(())
    }
    // ...existing code...
    pub fn fork(now_task_block: Arc<TaskBlock>) -> Arc<TaskBlock> {
        let child_pid = alloc_pid();
        let kernel_stack = KernelStack::new(child_pid.0);
        let kernel_stack_top = kernel_stack.kernel_stack_top;
        let mem_set = now_task_block.get_inner().code_memory_set.clone(); // todo: clone the memory set
        // attention: we dont need to manually initialize the trap context it should be done
        // in the prior clone. since the trap context is stored in the user space
        // correct:we still need to change the trap_context's kernel_sp to the new one
        // and return value register
        let trap_page = mem_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();

        let mut result = Self {
            pid: child_pid,
            task_name: now_task_block.task_name,

            kernel_stack,
            // fill this later
            //todo there are some error!!
            task_block_inner: RefCellSafe::new(TaskBlockInner {
                task_context: TaskContext::set_for_app(trap_return as usize, kernel_stack_top),
                state: TaskState::Ready,
                code_memory_set: mem_set,
                trap_context_loc: trap_page,
                father_task: Some(Arc::downgrade(&now_task_block)),
                children_task: Vec::new(),
                exit_code: 0,
                fd_table: now_task_block
                    .get_inner()
                    .fd_table
                    .iter()
                    .map(|fd_option| fd_option.as_ref().map(|fd| Arc::clone(fd)))
                    .collect(),
            }),
        }; // set user stack pointer
        // we need to change the kernel stack here...
        let trap_context_ref: &mut TrapContext = trap_page.get_mut();
        trap_context_ref.kernel_sp = kernel_stack_top;
        trap_context_ref.x[10] = 0; // Child process return value

        let target_arc = Arc::new(result);

        now_task_block
            .get_inner()
            .children_task
            .push(target_arc.clone());
        target_arc
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
