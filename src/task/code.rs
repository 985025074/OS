use core::arch::asm;

use crate::println;

// this file handle the logic of loading code to memory
use super::{TARGET_LOC, TASK_MANAGER};
const PER_TASK_CODE_SIZE: usize = 0x20000;
pub fn the_code_start(which: usize) -> usize {
    TARGET_LOC + which * PER_TASK_CODE_SIZE
}
pub fn load_code(which: usize, code_start: usize, code_end: usize) {
    // load the code to the specified location (basically it is from the top to the bottom)
    unsafe {
        let ptr = code_start as *const u8;
        let end_ptr = code_end as *const u8;
        let dst_ptr = the_code_start(which) as *mut u8;
        (dst_ptr as *mut u8).copy_from(ptr, end_ptr.offset_from(ptr) as usize);
    }
    unsafe {
        asm!("fence.i");
    }
}
