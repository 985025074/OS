use core::panic;

use crate::{println, task::signal::SignalAction};
mod filesystem;

mod flow;
mod process;
mod signal;
mod thread;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXEC: usize = 221;
const SYSCALL_WAITPID: usize = 260;
const SYSCALL_OPEN: usize = 56;

const SYSCALL_CLOSE: usize = 57;
const SYSCALL_PIPE: usize = 59;
const SYSCALL_SIGACTION: usize = 134;
const SYSCALL_SIGPROCMASK: usize = 135;
const SYSCALL_SIGRETURN: usize = 139;
const SYSCALL_KILL: usize = 129;
// thread
const SYSCALL_THREAD_CREATE: usize = 1000;
const SYSCALL_GETTID: usize = 1001;
const SYSCALL_WAITTID: usize = 1002;
const SYSCALL_MUTEX_CREATE: usize = 1010;
const SYSCALL_MUTEX_LOCK: usize = 1011;
const SYSCALL_MUTEX_UNLOCK: usize = 1012;
const SYSCALL_SEMAPHORE_CREATE: usize = 1020;
const SYSCALL_SEMAPHORE_UP: usize = 1021;
const SYSCALL_SEMAPHORE_DOWN: usize = 1022;
const SYSCALL_CONDVAR_CREATE: usize = 1030;
const SYSCALL_CONDVAR_SIGNAL: usize = 1031;
const SYSCALL_CONDVAR_WAIT: usize = 1032;

pub fn syscall(id: usize, args: [usize; 3]) -> isize {
    // println!(
    //     "syscall id: {}, args: {},{},{}",
    //     id, args[0], args[1], args[2]
    // );
    match id {
        SYSCALL_READ => flow::syscall_read(args[0], args[1] as *mut u8, args[2]),
        SYSCALL_WRITE => flow::syscall_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_GET_TIME => flow::syscall_get_time(),
        SYSCALL_YIELD => flow::syscall_yield(),
        SYSCALL_WAITPID => process::syscall_waitpid(args[0] as isize, args[1] as *mut i32),
        SYSCALL_EXEC => process::syscall_exec(args[0], args[1]),
        SYSCALL_FORK => process::syscall_fork(),
        SYSCALL_GETPID => process::syscall_getpid(),
        SYSCALL_OPEN => filesystem::syscall_open(args[0], args[1], args[2]),

        SYSCALL_CLOSE => filesystem::syscall_close(args[0]),
        SYSCALL_PIPE => filesystem::syscall_pipe(args[0] as *mut usize),

        SYSCALL_KILL => signal::syscall_kill(args[0], args[1] as i32),

        // SYSCALL_SIGACTION => signal::syscall_sigaction(
        //     args[0] as i32,
        //     args[1] as *const SignalAction,
        //     args[2] as *mut SignalAction,
        // ),
        // SYSCALL_SIGPROCMASK => signal::syscall_sigprocmask(args[0] as u32),
        // SYSCALL_SIGRETURN => signal::syscall_sigreturn(),
        SYSCALL_THREAD_CREATE => thread::sys_thread_create(args[0], args[1]),
        SYSCALL_GETTID => thread::sys_gettid(),
        SYSCALL_WAITTID => thread::sys_waittid(args[0] as usize) as isize,

        _ => {
            panic!(
                "Unknown syscall id: {},with args: {},{},{}",
                id, args[0], args[1], args[2]
            );
        }
    }
}
