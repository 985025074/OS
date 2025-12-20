use core::sync::atomic::{AtomicUsize, Ordering};
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
mod sched;
pub(crate) mod futex;
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
const SYSCALL_READV: usize = 65;
const SYSCALL_WRITEV: usize = 66;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_EXIT_GROUP: usize = 94;
const SYSCALL_SET_TID_ADDRESS: usize = 96;
const SYSCALL_FUTEX: usize = 98;
const SYSCALL_SET_ROBUST_LIST: usize = 99;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_SCHED_SETPARAM: usize = 118;
const SYSCALL_SCHED_SETSCHEDULER: usize = 119;
const SYSCALL_SCHED_GETSCHEDULER: usize = 120;
const SYSCALL_SCHED_GETPARAM: usize = 121;
const SYSCALL_SCHED_SETAFFINITY: usize = 122;
const SYSCALL_SCHED_GETAFFINITY: usize = 123;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_SCHED_GET_PRIORITY_MAX: usize = 125;
const SYSCALL_SCHED_GET_PRIORITY_MIN: usize = 126;
const SYSCALL_SCHED_RR_GET_INTERVAL: usize = 127;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_SETPGID: usize = 154;
const SYSCALL_GETSID: usize = 156;
const SYSCALL_SETSID: usize = 157;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_GETTIMEOFDAY: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_GETUID: usize = 174;
const SYSCALL_GETEUID: usize = 175;
const SYSCALL_GETGID: usize = 176;
const SYSCALL_GETEGID: usize = 177;
const SYSCALL_GETTID_LINUX: usize = 178;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_CLONE: usize = 220;
const SYSCALL_EXECVE: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_MPROTECT: usize = 226;
const SYSCALL_WAIT4: usize = 260;
const SYSCALL_SIGACTION: usize = 134; // rt_sigaction
const SYSCALL_SIGPROCMASK: usize = 135; // rt_sigprocmask
const SYSCALL_SIGRETURN: usize = 139; // rt_sigreturn
const SYSCALL_KILL: usize = 129;
const SYSCALL_TGKILL: usize = 131;
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
    // Lightweight syscall trace for debugging glibc/busybox startup.
    // Keep disabled for normal runs.
    static TRACE_LEFT: AtomicUsize = AtomicUsize::new(256);
    if crate::debug_config::DEBUG_SYSCALL && log::log_enabled!(log::Level::Info) {
        let pid = crate::task::processor::current_process().getpid();
        // Skip the interactive shell itself (pid=1) to avoid logging every keystroke.
        if pid >= 2 {
            let left = TRACE_LEFT.fetch_sub(1, Ordering::Relaxed);
            if left > 0 {
                log::info!(
                    "[syscall] pid={} id={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                    pid,
                    id,
                    args[0],
                    args[1],
                    args[2],
                    args[3],
                    args[4],
                    args[5]
                );
            }
        }
    }
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
        SYSCALL_READV => flow::syscall_readv(args[0], args[1], args[2]),
        SYSCALL_WRITEV => flow::syscall_writev(args[0], args[1], args[2]),
        SYSCALL_GETDENTS64 => filesystem::syscall_getdents64(args[0], args[1], args[2]),
        SYSCALL_FSTAT => filesystem::syscall_fstat(args[0], args[1]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_EXIT_GROUP => flow::syscall_exit(args[0]),
        SYSCALL_SET_TID_ADDRESS => misc::syscall_set_tid_address(args[0]),
        SYSCALL_FUTEX => futex::syscall_futex(args[0], args[1], args[2], args[3], args[4], args[5]),
        SYSCALL_SET_ROBUST_LIST => misc::syscall_set_robust_list(args[0], args[1]),
        SYSCALL_NANOSLEEP => time_sys::syscall_nanosleep(args[0], args[1]),
        SYSCALL_SCHED_SETPARAM => sched::syscall_sched_setparam(args[0], args[1]),
        SYSCALL_SCHED_SETSCHEDULER => sched::syscall_sched_setscheduler(args[0], args[1], args[2]),
        SYSCALL_SCHED_GETSCHEDULER => sched::syscall_sched_getscheduler(args[0]),
        SYSCALL_SCHED_GETPARAM => sched::syscall_sched_getparam(args[0], args[1]),
        SYSCALL_SCHED_SETAFFINITY => sched::syscall_sched_setaffinity(args[0], args[1], args[2]),
        SYSCALL_SCHED_GETAFFINITY => sched::syscall_sched_getaffinity(args[0], args[1], args[2]),
        SYSCALL_YIELD => flow::syscall_yield(),
        SYSCALL_SCHED_GET_PRIORITY_MAX => sched::syscall_sched_get_priority_max(args[0]),
        SYSCALL_SCHED_GET_PRIORITY_MIN => sched::syscall_sched_get_priority_min(args[0]),
        SYSCALL_SCHED_RR_GET_INTERVAL => sched::syscall_sched_rr_get_interval(args[0], args[1]),
        SYSCALL_TIMES => time_sys::syscall_times(args[0]),
        SYSCALL_SETPGID => misc::syscall_setpgid(args[0], args[1]),
        SYSCALL_GETSID => misc::syscall_getsid(args[0]),
        SYSCALL_SETSID => misc::syscall_setsid(),
        SYSCALL_UNAME => misc::syscall_uname(args[0]),
        SYSCALL_GETTIMEOFDAY => time_sys::syscall_gettimeofday(args[0], args[1]),
        SYSCALL_WAIT4 => process::syscall_wait4(args[0] as isize, args[1], args[2], args[3]),
        SYSCALL_EXECVE => process::syscall_execve(args[0], args[1], args[2]),
        SYSCALL_CLONE => process::syscall_clone(args[0], args[1], args[2], args[3], args[4]),
        SYSCALL_GETPID => process::syscall_getpid(),
        SYSCALL_GETPPID => misc::syscall_getppid(),
        SYSCALL_GETUID => misc::syscall_getuid(),
        SYSCALL_GETEUID => misc::syscall_geteuid(),
        SYSCALL_GETGID => misc::syscall_getgid(),
        SYSCALL_GETEGID => misc::syscall_getegid(),
        SYSCALL_GETTID_LINUX => misc::syscall_gettid_linux(),
        SYSCALL_BRK => memory::syscall_brk(args[0]),
        SYSCALL_MUNMAP => memory::syscall_munmap(args[0], args[1]),
        SYSCALL_MMAP => memory::syscall_mmap(args[0], args[1], args[2], args[3], args[4] as isize, args[5]),
        SYSCALL_MPROTECT => memory::syscall_mprotect(args[0], args[1], args[2]),
        SYSCALL_CLOSE => filesystem::syscall_close(args[0]),
        SYSCALL_PIPE2 => filesystem::syscall_pipe2(args[0], args[1]),

        SYSCALL_KILL => signal::syscall_kill(args[0], args[1] as i32),
        SYSCALL_TGKILL => signal::syscall_tgkill(args[0], args[1], args[2] as i32),

        SYSCALL_SIGACTION => signal::syscall_rt_sigaction(args[0], args[1], args[2], args[3]),
        SYSCALL_SIGPROCMASK => signal::syscall_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        SYSCALL_SIGRETURN => signal::syscall_rt_sigreturn(),
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

        // Unknown syscall: Linux returns -ENOSYS.
        _ => -38,
    }
}
