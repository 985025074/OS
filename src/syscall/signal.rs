use crate::{
    mm::translated_byte_buffer,
    task::signal::{SignalAction, kill, set_signal, set_signal_mask},
    trap::get_current_token,
};

// pub fn syscall_sigreturn() -> isize {
//     sigreturn()
// }

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    kill(pid, signum)
}

/// Linux `tgkill` (syscall 131).
///
/// Delivers a signal to a specific thread. We don't have Linux thread groups
/// yet; treat it as `kill(tgid, sig)` for compatibility.
pub fn syscall_tgkill(tgid: usize, _tid: usize, sig: i32) -> isize {
    kill(tgid, sig)
}
pub fn syscall_sigaction(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    set_signal(signum, action, old_action)
}
pub fn syscall_sigprocmask(how: u32) -> isize {
    set_signal_mask(how)
}

fn zero_user(ptr: usize, len: usize) {
    if ptr == 0 || len == 0 {
        return;
    }
    let token = get_current_token();
    let bufs = translated_byte_buffer(token, ptr as *mut u8, len);
    for b in bufs {
        b.fill(0);
    }
}

/// Linux `rt_sigaction` (syscall 134).
///
/// glibc expects this to exist very early during startup. We currently do not
/// deliver user signals for glibc programs, so we accept the call, optionally
/// zero the old action buffer, and return success.
pub fn syscall_rt_sigaction(_signum: usize, _act: usize, oldact: usize, sigsetsize: usize) -> isize {
    // On riscv64, Linux `struct sigaction` is 32 bytes.
    let _ = sigsetsize;
    zero_user(oldact, 32);
    0
}

/// Linux `rt_sigprocmask` (syscall 135).
pub fn syscall_rt_sigprocmask(_how: usize, _set: usize, oldset: usize, sigsetsize: usize) -> isize {
    zero_user(oldset, sigsetsize);
    0
}

/// Linux `rt_sigreturn` (syscall 139).
pub fn syscall_rt_sigreturn() -> isize {
    // No user signal delivery yet.
    0
}
