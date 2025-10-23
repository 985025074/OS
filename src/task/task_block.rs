use crate::task::{KERNEL_STACK, USER_STACK};

use super::code::the_code_start;
use super::restore;
use super::task_context::TaskContext;
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
#[derive(Copy, Clone)]
pub struct TaskBlock {
    pub task_name: [u8; 32],
    pub state: TaskState,
    pub code_start: usize,
    pub code_end: usize,
    pub task_context: TaskContext,
}
impl TaskBlock {
    pub fn new_raw() -> Self {
        Self {
            task_name: [0; 32],
            task_context: TaskContext::new(),
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
        let trap_context_ptr = KERNEL_STACK[no].push_trap_context(
            crate::trap::context::TrapContext::app_init_context(
                the_code_start(no),
                USER_STACK[no].top(),
            ),
        );
        unsafe {
            let _app_name: [u8; 32] = *(app_name as *const [u8; 32]);

            let mut result = Self {
                task_name: _app_name,
                code_start: app_start,
                code_end: app_end,
                // fill this later
                task_context: TaskContext::set_for_app(restore as usize, trap_context_ptr),
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
