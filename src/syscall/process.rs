use alloc::{string::String, vec::Vec};
use core::mem::size_of;

use crate::{
    fs::{OpenFlags, open_file},
    mm::{translated_single_address, translated_str},
    task::processor::{
        current_process, current_process_has_child, current_task, suspend_current_and_run_next,
    },
    trap::get_current_token,
};
pub fn syscall_fork() -> isize {
    let now_process = current_process();
    let child_task = now_process.fork();
    let pid = child_task.pid.0;
    // task has been added into pid2process in fork function
    // add_task(child_task);

    return pid as isize;
}

pub fn syscall_waitpid(pid_or_ne: isize, exit_code_ptr: *mut i32) -> isize {
    let mut temp_exit_code: i32 = 0;
    loop {
        if let Some(pid) = current_process_has_child(pid_or_ne, &mut temp_exit_code) {
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
    let now_process = current_process();
    let token = get_current_token();
    // println!(
    //     "[kernel] Execing new program at path {:x} for PID {}",
    //     path, now_task.pid.0
    // );

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
    let app_name = translated_str(token, path as *const u8);
    let file = open_file(&app_name, OpenFlags::RDONLY);
    if file.is_none() {
        return -1;
    }
    let app_data = file.unwrap().read_all();
    now_process.exec(&app_data, args_vec);
    0
}
pub fn syscall_getpid() -> isize {
    let now_task = current_task().unwrap();
    now_task.process.upgrade().unwrap().getpid() as isize
}
