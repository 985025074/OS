use alloc::{string::String, vec::Vec};
use core::mem::size_of;

use crate::{
    mm::{translated_single_address, translated_str},
    println,
    task::{
        manager::add_task,
        processor::{current_task, current_task_has_child, suspend_current_and_run_next},
        task_block::TaskBlock,
    },
    trap::get_current_token,
};
pub fn syscall_fork() -> isize {
    let now_task = current_task().unwrap();
    let child_task = TaskBlock::fork(now_task.clone());
    let pid = child_task.pid.0;
    add_task(child_task);
    return pid as isize;
}

pub fn syscall_waitpid(pid_or_ne: isize, exit_code_ptr: *mut i32) -> isize {
    let mut temp_exit_code: i32 = 0;
    loop {
        if let Some(pid) = current_task_has_child(pid_or_ne, &mut temp_exit_code) {
            // no child process
            let target_ptr =
                translated_single_address(get_current_token(), exit_code_ptr as *const u8);
            unsafe {
                *(target_ptr as *mut u8 as *mut i32) = temp_exit_code;
            }

            return pid as isize;
        } else {
            suspend_current_and_run_next();
        }
    }
}

pub fn syscall_exec(path: usize, args_addr: usize) -> isize {
    let now_task = current_task().unwrap();
    let token = get_current_token();
    println!(
        "[kernel] Execing new program at path {:x} for PID {}",
        path, now_task.pid.0
    );

    let mut args_vec: Vec<String> = Vec::new();
    if args_addr != 0 {
        let mut argv_ptr = args_addr;
        let ptr_size = size_of::<usize>();
        loop {
            let mut raw = [0u8; size_of::<usize>()];
            for (i, byte) in raw.iter_mut().enumerate() {
                *byte = *translated_single_address(token, (argv_ptr + i) as *const u8);
            }
            let arg_ptr = usize::from_ne_bytes(raw);
            if arg_ptr == 0 {
                break;
            }
            args_vec.push(translated_str(token, arg_ptr as *const u8));
            // println!(
            //     "[kernel] Exec arg for PID {} : {}",
            //     now_task.pid.0,
            //     args_vec.last().unwrap()
            // );
            argv_ptr += ptr_size;
        }
    }
    let app_name = translated_single_address(token, path as *const u8);

    if let Err(_) = now_task.exec(app_name as *mut u8 as usize, args_vec) {
        println!("[kernel] Exec failed for PID {}", now_task.pid.0);
        return -1;
    } else {
        // println!("[kernel] Exec success for PID {}", now_task.pid.0);
    }
    0
}
