use core::arch::global_asm;

use crate::task::task_context::TaskContext;

global_asm!(include_str!("switch.asm"));
unsafe extern "C" {
    // you should pass the loc in the kernel stack
    pub fn switch(old_task_cx_ptr: *const usize, new_task_cx_ptr: *const usize);
}
