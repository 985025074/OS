use crate::task::signal::{SignalAction, kill, set_signal, set_signal_mask, sigreturn};

pub fn syscall_sigreturn() -> isize {
    sigreturn()
}

pub fn syscall_kill(pid: usize, signum: i32) -> isize {
    kill(pid, signum)
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
