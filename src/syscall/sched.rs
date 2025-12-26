use alloc::sync::Arc;

use crate::{
    config::MAX_HARTS,
    mm::{read_user_value, translated_byte_buffer, write_user_value},
    task::{manager::pid2process, processor::current_process, ProcessControlBlock},
    trap::get_current_token,
};

const ESRCH: isize = -3;
const EINVAL: isize = -22;

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;

// Keep in sync with `syscall::misc` TID encoding.
const LINUX_TID_MAGIC: usize = 1 << 30;
const LINUX_TID_PID_SHIFT: usize = 15;

#[repr(C)]
#[derive(Clone, Copy)]
struct SchedParam {
    sched_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    tv_sec: isize,
    tv_nsec: isize,
}

fn resolve_process(pid: usize) -> Option<Arc<ProcessControlBlock>> {
    let cur = current_process();
    if pid == 0 {
        Some(cur)
    } else {
        // glibc often passes a thread ID (TID) to sched_* syscalls.
        // Accept both:
        // - plain TGIDs (process PIDs), and
        // - encoded TIDs produced by our `gettid()` compatibility layer.
        let tgid = if (pid & LINUX_TID_MAGIC) != 0 {
            (pid & !LINUX_TID_MAGIC) >> LINUX_TID_PID_SHIFT
        } else {
            pid
        };
        if tgid == cur.getpid() {
            Some(cur)
        } else {
            pid2process(tgid)
        }
    }
}

fn check_policy(policy: i32) -> bool {
    matches!(policy, SCHED_OTHER | SCHED_FIFO | SCHED_RR)
}

pub fn syscall_sched_getscheduler(pid: usize) -> isize {
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let inner = process.borrow_mut();
    inner.sched_policy as isize
}

pub fn syscall_sched_getparam(pid: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let prio = {
        let inner = process.borrow_mut();
        inner.sched_priority
    };
    let token = get_current_token();
    let sp = SchedParam { sched_priority: prio };
    write_user_value(token, param_ptr as *mut SchedParam, &sp);
    0
}

pub fn syscall_sched_setparam(pid: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let token = get_current_token();
    let prio = read_user_value(token, param_ptr as *const SchedParam).sched_priority;
    let mut inner = process.borrow_mut();
    inner.sched_priority = prio;
    0
}

pub fn syscall_sched_setscheduler(pid: usize, policy: usize, param_ptr: usize) -> isize {
    if param_ptr == 0 {
        return EINVAL;
    }
    let Some(process) = resolve_process(pid) else {
        return ESRCH;
    };
    let policy = policy as i32;
    if !check_policy(policy) {
        return EINVAL;
    }
    let token = get_current_token();
    let prio = read_user_value(token, param_ptr as *const SchedParam).sched_priority;
    let mut inner = process.borrow_mut();
    inner.sched_policy = policy;
    inner.sched_priority = prio;
    0
}

pub fn syscall_sched_getaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return EINVAL;
    }
    let Some(_process) = resolve_process(pid) else {
        return ESRCH;
    };
    let mut tmp = alloc::vec![0u8; cpusetsize];
    let max_bits = cpusetsize * 8;
    for cpu in 0..MAX_HARTS {
        if cpu >= max_bits {
            break;
        }
        tmp[cpu / 8] |= 1u8 << (cpu % 8);
    }
    let token = get_current_token();
    let bufs = translated_byte_buffer(token, mask_ptr as *mut u8, cpusetsize);
    let mut off = 0usize;
    for b in bufs {
        let n = core::cmp::min(b.len(), cpusetsize - off);
        b[..n].copy_from_slice(&tmp[off..off + n]);
        off += n;
        if off == cpusetsize {
            break;
        }
    }
    // Linux `sched_getaffinity` syscall returns the number of bytes written.
    // musl uses this return value (not the wrapper) when implementing `sysconf(_SC_NPROCESSORS_*)`.
    cpusetsize as isize
}

pub fn syscall_sched_setaffinity(pid: usize, cpusetsize: usize, mask_ptr: usize) -> isize {
    if mask_ptr == 0 || cpusetsize == 0 {
        return EINVAL;
    }
    let Some(_process) = resolve_process(pid) else {
        return ESRCH;
    };
    // Best-effort: accept and ignore. The scheduler is FIFO and does not yet enforce affinity.
    0
}

pub fn syscall_sched_get_priority_max(policy: usize) -> isize {
    match policy as i32 {
        SCHED_FIFO | SCHED_RR => 99,
        SCHED_OTHER => 0,
        _ => EINVAL,
    }
}

pub fn syscall_sched_get_priority_min(policy: usize) -> isize {
    match policy as i32 {
        SCHED_FIFO | SCHED_RR => 1,
        SCHED_OTHER => 0,
        _ => EINVAL,
    }
}

pub fn syscall_sched_rr_get_interval(pid: usize, interval_ptr: usize) -> isize {
    if interval_ptr == 0 {
        return EINVAL;
    }
    let Some(_process) = resolve_process(pid) else {
        return ESRCH;
    };
    let token = get_current_token();
    let ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
    write_user_value(token, interval_ptr as *mut TimeSpec, &ts);
    0
}
