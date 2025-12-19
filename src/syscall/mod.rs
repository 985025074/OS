use core::panic;

use crate::{println, task::signal::SignalAction};
mod filesystem;

mod condvar;
mod flow;
mod mutex;
mod process;
mod semaphore;
mod smp;
mod signal;
mod thread;
mod memory;
mod misc;
mod time_sys;
const SYSCALL_GETCWD: usize = 17;
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_GETTIMEOFDAY: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_CLONE: usize = 220;
const SYSCALL_EXECVE: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_WAIT4: usize = 260;
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
const SYSCALL_GET_HARTID: usize = 998;

pub fn syscall(id: usize, args: [usize; 6]) -> isize {
    // println!(
    //     "syscall id: {}, args: {},{},{}",
    //     id, args[0], args[1], args[2]
    // );
    match id {
        SYSCALL_GETCWD => filesystem::syscall_getcwd(args[0], args[1]),
        SYSCALL_DUP => filesystem::syscall_dup(args[0]),
        SYSCALL_DUP3 => filesystem::syscall_dup3(args[0], args[1], args[2]),
        SYSCALL_MKDIRAT => filesystem::syscall_mkdirat(args[0] as isize, args[1], args[2]),
        SYSCALL_UNLINKAT => filesystem::syscall_unlinkat(args[0] as isize, args[1], args[2]),
        SYSCALL_UMOUNT2 => misc::syscall_umount2(args[0], args[1]),
        SYSCALL_MOUNT => misc::syscall_mount(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_CHDIR => filesystem::syscall_chdir(args[0]),
        SYSCALL_OPENAT => filesystem::syscall_openat(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_READ => flow::syscall_read(args[0], args[1] as *mut u8, args[2]),
        SYSCALL_WRITE => flow::syscall_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_GETDENTS64 => filesystem::syscall_getdents64(args[0], args[1], args[2]),
        SYSCALL_FSTAT => filesystem::syscall_fstat(args[0], args[1]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_NANOSLEEP => time_sys::syscall_nanosleep(args[0], args[1]),
        SYSCALL_YIELD => flow::syscall_yield(),
        SYSCALL_TIMES => time_sys::syscall_times(args[0]),
        SYSCALL_UNAME => misc::syscall_uname(args[0]),
        SYSCALL_GETTIMEOFDAY => time_sys::syscall_gettimeofday(args[0], args[1]),
        SYSCALL_WAIT4 => process::syscall_wait4(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_EXECVE => process::syscall_execve(args[0], args[1], args[2]),
        SYSCALL_CLONE => process::syscall_clone(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_GETPID => process::syscall_getpid(),
        SYSCALL_GETPPID => misc::syscall_getppid(),
        SYSCALL_BRK => memory::syscall_brk(args[0]),
        SYSCALL_MUNMAP => memory::syscall_munmap(args[0], args[1]),
        SYSCALL_MMAP => memory::syscall_mmap(args[0], args[1], args[2], args[3], args[4] as isize, args[5]),
        SYSCALL_CLOSE => filesystem::syscall_close(args[0]),
        SYSCALL_PIPE2 => filesystem::syscall_pipe2(args[0], args[1]),

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

        SYSCALL_MUTEX_CREATE => mutex::sys_mutex_create(args[0] == 1),
        SYSCALL_MUTEX_LOCK => mutex::sys_mutex_lock(args[0]),
        SYSCALL_MUTEX_UNLOCK => mutex::sys_mutex_unlock(args[0]),
        SYSCALL_SEMAPHORE_CREATE => semaphore::sys_semaphore_create(args[0]),
        SYSCALL_SEMAPHORE_UP => semaphore::sys_semaphore_up(args[0]),
        SYSCALL_SEMAPHORE_DOWN => semaphore::sys_semaphore_down(args[0]),
        // condvar
        SYSCALL_CONDVAR_CREATE => condvar::sys_condvar_create(),
        SYSCALL_CONDVAR_SIGNAL => condvar::sys_condvar_signal(args[0]),
        SYSCALL_CONDVAR_WAIT => condvar::sys_condvar_wait(args[0], args[1]),
        SYSCALL_GET_HARTID => smp::sys_get_hartid(),

        _ => {
            panic!(
                "Unknown syscall id: {},with args: {},{},{}",
                id, args[0], args[1], args[2]
            );
        }
    }
}
