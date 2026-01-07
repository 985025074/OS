use alloc::{string::String, sync::Arc, vec::Vec};
use core::mem::size_of;

use crate::{
    debug_config::DEBUG_PTHREAD,
    fs::ROOT_INODE,
    mm::{kernel_token, translated_single_address, translated_str, write_user_value},
    syscall::misc::encode_linux_tid,
    task::{
        manager::{add_task, select_hart_for_new_task},
        processor::{block_current_and_run_next, current_process, current_task},
        task_block::TaskControlBlock,
    },
    trap::{get_current_token, trap_handler},
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

fn load_file_from_path(path: &str) -> Option<Vec<u8>> {
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

fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F']
}

fn elf_interp_path(data: &[u8]) -> Option<String> {
    let elf = xmas_elf::ElfFile::new(data).ok()?;
    for i in 0..elf.header.pt2.ph_count() {
        let ph = elf.program_header(i).ok()?;
        if ph.get_type().ok()? == xmas_elf::program::Type::Interp {
            let off = ph.offset() as usize;
            let sz = ph.file_size() as usize;
            if off.checked_add(sz)? > elf.input.len() {
                return None;
            }
            let raw = &elf.input[off..off + sz];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            return core::str::from_utf8(&raw[..end]).ok().map(String::from);
        }
    }
    None
}

fn parse_shebang(data: &[u8]) -> Option<(String, Option<String>)> {
    if data.len() < 2 || &data[0..2] != b"#!" {
        return None;
    }
    let line_end = data
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(data.len());
    let mut line = &data[2..line_end];
    // Trim leading spaces/tabs.
    while !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
        line = &line[1..];
    }
    // Trim trailing CR/spaces.
    while !line.is_empty() && (line[line.len() - 1] == b'\r' || line[line.len() - 1] == b' ') {
        line = &line[..line.len() - 1];
    }
    let Ok(s) = core::str::from_utf8(line) else {
        return None;
    };
    let mut it = s.split_whitespace();
    let interp = String::from(it.next()?);
    let arg = it.next().map(String::from);
    Some((interp, arg))
}

pub fn syscall_clone(flags: usize, stack: usize, _ptid: usize, _tls: usize, _ctid: usize) -> isize {
    const CLONE_VM: usize = 0x0000_0100;
    const CLONE_SETTLS: usize = 0x0008_0000;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;

    // Thread-like clone: share address space (glibc pthreads).
    if (flags & CLONE_VM) != 0 {
        const ENOMEM: isize = -12;
        let task = current_task().unwrap();
        let parent_cx = {
            let inner = task.borrow_mut();
            *inner.get_trap_cx()
        };
        let process = current_process();
        let Some(new_task) = TaskControlBlock::try_new_linux_thread(Arc::clone(&process))
            .map(Arc::new) else {
            return ENOMEM;
        };
        new_task.set_cpu_id(select_hart_for_new_task());

        let (_tid_index, linux_tid) = {
            let mut new_inner = new_task.borrow_mut();
            let res = new_inner.res.as_ref().unwrap();
            let tid_index = res.tid;
            let linux_tid = encode_linux_tid(process.getpid(), tid_index);

            // Attach to process thread table.
            {
                let mut process_inner = process.borrow_mut();
                let tasks = &mut process_inner.tasks;
                while tasks.len() < tid_index + 1 {
                    tasks.push(None);
                }
                tasks[tid_index] = Some(Arc::clone(&new_task));
            }

            let trap_cx = new_inner.get_trap_cx();
            *trap_cx = parent_cx;
            trap_cx.x[10] = 0; // child returns 0 from syscall
            if stack != 0 {
                trap_cx.x[2] = stack;
            }
            if (flags & CLONE_SETTLS) != 0 {
                trap_cx.x[4] = _tls; // tp (TLS)
            }
            trap_cx.kernel_satp = kernel_token();
            trap_cx.kernel_sp = new_task.kstack.get_top();
            trap_cx.trap_handler = trap_handler as usize;
            if (flags & CLONE_CHILD_CLEARTID) != 0 && _ctid != 0 {
                new_inner.clear_child_tid = Some(_ctid);
            }
            (tid_index, linux_tid)
        };

        if DEBUG_PTHREAD {
            log::debug!(
                "[clone] vm flags={:#x} stack={:#x} ptid={:#x} tls={:#x} ctid={:#x} tid={} linux_tid={}",
                flags,
                stack,
                _ptid,
                _tls,
                _ctid,
                _tid_index,
                linux_tid
            );
        }

        // Parent/child tid pointers live in the shared address space.
        let token = get_current_token();
        if (flags & CLONE_PARENT_SETTID) != 0 && _ptid != 0 {
            write_user_value(token, _ptid as *mut i32, &(linux_tid as i32));
        }
        if (flags & CLONE_CHILD_SETTID) != 0 && _ctid != 0 {
            write_user_value(token, _ctid as *mut i32, &(linux_tid as i32));
        }

        add_task(new_task);
        return linux_tid as isize;
    }

    // Fork-like clone (process).
    let task = current_task().unwrap();
    let parent_cx = {
        let inner = task.borrow_mut();
        *inner.get_trap_cx()
    };
    let process = current_process();
    let Some(child) = process.fork() else {
        return -12;
    };

    {
        let task = child.borrow_mut().get_task(0);
        let mut task_inner = task.borrow_mut();
        let trap_cx = task_inner.get_trap_cx();
        *trap_cx = parent_cx;
        trap_cx.x[10] = 0; // child returns 0 from syscall
        if stack != 0 {
            trap_cx.x[2] = stack;
        }
        trap_cx.kernel_satp = kernel_token();
        trap_cx.kernel_sp = task.kstack.get_top();
        trap_cx.trap_handler = trap_handler as usize;
    }
    child.getpid() as isize
}

/// Linux `vfork(2)` compatibility.
///
/// For now, treat it as a normal `fork(2)` (copy address space). This is
/// sufficient for busybox/ash and many OSComp scripts, and avoids the strict
/// parent-blocking/VM-sharing semantics of true vfork.
pub fn syscall_vfork() -> isize {
    let process = current_process();
    match process.fork() {
        Some(child) => child.getpid() as isize,
        None => -12,
    }
}

pub fn syscall_wait4(pid: isize, wstatus_ptr: usize, _options: usize, _rusage: usize) -> isize {
    const WNOHANG: usize = 0x00000001;
    const ECHILD: isize = -10;
    let token = get_current_token();
    let mut temp_exit_code: i32 = 0;
    loop {
        let cur_process = current_process();
        let (has_matching_child, zombie_pid) = {
            let mut process_inner = cur_process.borrow_mut();
            if process_inner.children.is_empty() {
                (false, None)
            } else {
                let mut found: Option<(usize, usize)> = None; // (index, pid)
                let mut has_match = false;
                for (index, child) in process_inner.children.iter().enumerate() {
                    let child_inner = child.borrow_mut();
                    let matches = match pid {
                        -1 => true, // any child
                        0 => true,  // treat as any (pgid not modeled)
                        p if p > 0 => child.pid.0 == p as usize,
                        _ => true, // negative pgid not modeled; treat as any
                    };
                    if matches {
                        has_match = true;
                    }
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
                    (has_match, None)
                }
            }
        };

        if let Some(pid) = zombie_pid {
            // Keep exited processes visible (e.g., for `kill $!`) until they are reaped.
            // Reaping happens here (wait4), so remove it from the global PID table now.
            crate::task::manager::remove_from_pid2process(pid);
            if wstatus_ptr != 0 {
                // Linux wait status encoding:
                // - normal exit: (code & 0xff) << 8
                // - signaled: signal number in low 7 bits
                let status = if temp_exit_code >= 0 {
                    (temp_exit_code & 0xff) << 8
                } else {
                    (-temp_exit_code) & 0x7f
                };
                write_user_value(token, wstatus_ptr as *mut i32, &status);
            }
            return pid as isize;
        }

        if !has_matching_child {
            return ECHILD;
        }

        // Non-blocking wait: return immediately if no child has exited yet.
        if (_options & WNOHANG) != 0 {
            return 0;
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
    const ENOEXEC: isize = -8;
    const ENOENT: isize = -2;
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

    let Some(file_data) = load_file_from_path(&path) else {
        return ENOENT;
    };

    // ELF binary: normal exec.
    if is_elf(&file_data) {
        // Dynamic ELF: map both main program and interpreter, and start at the
        // interpreter entry with a Linux-like auxv (AT_PHDR/AT_ENTRY/AT_BASE).
        if let Some(interp) = elf_interp_path(&file_data) {
            let Some(interp_data) = load_file_from_path(&interp) else {
                return ENOENT;
            };
            if !is_elf(&interp_data) {
                return ENOEXEC;
            }
            let process = current_process();
            process.exec_dyn(&file_data, &interp_data, args_vec);
            return 0;
        }
        let process = current_process();
        process.exec(&file_data, args_vec);
        return 0;
    }

    // Script with shebang: emulate Linux `#!` handling in-kernel so that
    // busybox/ash can run `./script.sh` directly.
    if let Some((interp, opt_arg)) = parse_shebang(&file_data) {
        let Some(interp_data) = load_file_from_path(&interp) else {
            return ENOENT;
        };
        if !is_elf(&interp_data) {
            return ENOEXEC;
        }
        let mut new_args: Vec<String> = Vec::new();
        new_args.push(interp.clone());
        if let Some(a) = opt_arg {
            new_args.push(a);
        }
        // Pass script path as argv[1] (or argv[2] with opt arg), like Linux.
        new_args.push(path.clone());
        // Append original args after argv[0].
        for a in args_vec.iter().skip(1) {
            new_args.push(a.clone());
        }
        let process = current_process();
        process.exec(&interp_data, new_args);
        return 0;
    }

    // ExampleOs-style fallback for .sh files without shebangs.
    // Note: this diverges from Linux (which returns ENOEXEC) but keeps OSComp
    // scripts working when shells don't retry on ENOEXEC.
    if path.ends_with(".sh") {
        let mut interp: Option<(String, Vec<u8>, bool)> = None;
        if let Some(data) = load_file_from_path("/bin/busybox") {
            interp = Some((String::from("/bin/busybox"), data, true));
        } else if let Some(data) = load_file_from_path("/busybox") {
            interp = Some((String::from("/busybox"), data, true));
        } else if let Some(data) = load_file_from_path("/bin/sh") {
            interp = Some((String::from("/bin/sh"), data, false));
        }

        let Some((interp_path, interp_data, needs_sh_arg)) = interp else {
            return ENOENT;
        };
        if !is_elf(&interp_data) {
            return ENOEXEC;
        }
        let mut new_args: Vec<String> = Vec::new();
        new_args.push(interp_path.clone());
        if needs_sh_arg {
            new_args.push(String::from("sh"));
        }
        new_args.push(path.clone());
        for a in args_vec.iter().skip(1) {
            new_args.push(a.clone());
        }
        let process = current_process();
        process.exec(&interp_data, new_args);
        return 0;
    }

    // Non-ELF without shebang: let shells interpret it.
    return ENOEXEC;

    // unreachable
}

pub fn syscall_getpid() -> isize {
    current_task()
        .unwrap()
        .process
        .upgrade()
        .unwrap()
        .getpid() as isize
}
