use alloc::{string::String, vec::Vec};
use core::mem::size_of;

use crate::{
    fs::{OpenFlags, open_file},
    mm::{translated_single_address, translated_str},
    task::processor::{
        current_process, current_task,
    },
    task::processor::block_current_and_run_next,
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
        // Check children status under the current process lock.
        let cur_process = current_process();
        let (has_any_child, zombie_pid) = {
            let mut process_inner = cur_process.borrow_mut();
            if process_inner.children.is_empty() {
                (false, None)
            } else {
                // Find a zombie child that matches pid_or_ne, remove it from the children list,
                // and return its pid/exit_code.
                let mut found: Option<(usize, usize)> = None; // (index, pid)
                for (index, child) in process_inner.children.iter().enumerate() {
                    let child_inner = child.borrow_mut();
                    let matches = pid_or_ne == -1 || child.pid.0 == pid_or_ne as usize;
                    if matches && child_inner.is_zombie {
                        temp_exit_code = child_inner.exit_code;
                        found = Some((index, child.pid.0));
                        break;
                    }
                }
                if let Some((index, pid)) = found {
                    process_inner.children.remove(index);
                    (true, Some(pid))
                } else {
                    (true, None)
                }
            }
        };

        if let Some(pid) = zombie_pid {
            let target_ptr =
                translated_single_address(get_current_token(), exit_code_ptr as *const u8);
            unsafe {
                *(target_ptr as *mut u8 as *mut i32) = temp_exit_code;
            }

            return pid as isize;
        }

        // No child at all.
        if !has_any_child {
            return -1;
        }

        // Block until a child exits, to avoid spinning in kernel with interrupts disabled.
        // The child exit path will wake tasks in this wait queue.
        {
            let task = current_task().unwrap();
            let mut process_inner = cur_process.borrow_mut();
            process_inner.wait_queue.push_back(task);
        }
        block_current_and_run_next();
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
