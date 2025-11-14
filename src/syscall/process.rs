use alloc::{string::String, vec::Vec};

use crate::{
    mm::{UserBuffer, translated_byte_buffer, translated_single_address, translated_str},
    println,
    task::{
        manager::add_task,
        processor::{
            current_task, current_task_has_child, suspend_current_and_run_next, take_current_task,
        },
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
    return -1;
}

pub fn syscall_exec(path: usize, args_addr: usize) -> isize {
    let now_task = current_task().unwrap();
    // get name from the path

    // todo : real path
    println!(
        "[kernel] Execing new program at path {:x} for PID {}",
        path, now_task.pid.0
    );
    // we get args first
    // we dont know the length so we dont do the below line
    // let user_args_buffer = translated_byte_buffer(get_current_token(), args_addr as , len)
    let mut args_vec: Vec<String> = Vec::new();
    let mut now_ptr = args_addr as *const usize;
    unsafe {
        loop {
            let now_str = translated_str(get_current_token(), now_ptr as *const u8);
            if now_str.is_empty() {
                break;
            } else {
                args_vec.push(now_str);
                now_ptr = now_ptr.add(1);
            }
        }
    }
    let app_name = translated_single_address(get_current_token(), path as *const u8);

    if let Err(_) = now_task.exec(app_name as *mut u8 as usize, args_vec) {
        println!("[kernel] Exec failed for PID {}", now_task.pid.0);
        return -1;
    } else {
        // println!("[kernel] Exec success for PID {}", now_task.pid.0);
    }
    0
}
