use alloc::{string::String, sync::Arc, vec::Vec};
use core::mem::size_of;

use crate::{
    fs::ROOT_INODE,
    mm::{translated_mutref, translated_single_address, translated_str},
    task::processor::{block_current_and_run_next, current_process, current_task},
    trap::get_current_token,
};

fn normalize_path(cwd: &str, path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');
    if !absolute {
        for seg in cwd.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                parts.pop();
                continue;
            }
            parts.push(seg);
        }
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    out
}

fn read_usize_user(token: usize, ptr: usize) -> usize {
    let mut raw = [0u8; size_of::<usize>()];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = *translated_single_address(token, (ptr + i) as *const u8);
    }
    usize::from_ne_bytes(raw)
}

fn load_elf_from_path(token: usize, path: &str) -> Option<Vec<u8>> {
    let process = current_process();
    let cwd = { process.borrow_mut().cwd.clone() };
    let abs = normalize_path(&cwd, path);

    if let Some(inode) = ROOT_INODE.find_path(&abs) {
        if inode.is_file() {
            return Some(inode.read_all());
        }
    }
    if !abs.ends_with(".bin") {
        let mut with_bin = abs.clone();
        with_bin.push_str(".bin");
        if let Some(inode) = ROOT_INODE.find_path(&with_bin) {
            if inode.is_file() {
                return Some(inode.read_all());
            }
        }
    }
    None
}

pub fn syscall_clone(flags: usize, stack: usize, _ptid: usize, _tls: usize, _ctid: usize) -> isize {
    let process = current_process();
    let child = process.fork();

    // If userspace provided a stack, set child's user sp to it.
    if stack != 0 {
        let task = child.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        trap_cx.x[2] = stack;
    }

    // TODO: support clone flags beyond fork-like behavior.
    let _ = flags;
    child.getpid() as isize
}

pub fn syscall_wait4(pid: isize, wstatus_ptr: usize, _options: usize, _rusage: usize) -> isize {
    let token = get_current_token();
    let mut temp_exit_code: i32 = 0;
    loop {
        let cur_process = current_process();
        let (has_any_child, zombie_pid) = {
            let mut process_inner = cur_process.borrow_mut();
            if process_inner.children.is_empty() {
                (false, None)
            } else {
                let mut found: Option<(usize, usize)> = None; // (index, pid)
                for (index, child) in process_inner.children.iter().enumerate() {
                    let child_inner = child.borrow_mut();
                    let matches = pid == -1 || child.pid.0 == pid as usize;
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
            if wstatus_ptr != 0 {
                *translated_mutref(token, wstatus_ptr as *mut i32) = temp_exit_code;
            }
            return pid as isize;
        }

        if !has_any_child {
            return -1;
        }

        // Block until a child exits.
        {
            let task = current_task().unwrap();
            let mut process_inner = cur_process.borrow_mut();
            process_inner.wait_queue.push_back(task);
        }
        block_current_and_run_next();
    }
}

pub fn syscall_execve(path_ptr: usize, argv_ptr: usize, _envp_ptr: usize) -> isize {
    let token = get_current_token();
    let path = translated_str(token, path_ptr as *const u8);

    let mut args_vec: Vec<String> = Vec::new();
    if argv_ptr != 0 {
        let mut i = 0usize;
        loop {
            let arg_ptr = read_usize_user(token, argv_ptr + i * size_of::<usize>());
            if arg_ptr == 0 {
                break;
            }
            args_vec.push(translated_str(token, arg_ptr as *const u8));
            i += 1;
        }
    }
    if args_vec.is_empty() {
        args_vec.push(path.clone());
    }

    let Some(app_data) = load_elf_from_path(token, &path) else {
        return -1;
    };

    let process = current_process();
    process.exec(&app_data, args_vec);
    0
}

pub fn syscall_getpid() -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .getpid() as isize
}
