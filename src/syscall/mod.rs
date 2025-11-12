use core::panic;

use crate::println;
mod filesystem;

mod flow;
mod process;

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
pub const SYSCALL_FORTEST: usize = 1000;
pub fn syscall(id: usize, args: [usize; 3]) -> isize {
    // println!(
    //     "syscall id: {}, args: {},{},{}",
    //     id, args[0], args[1], args[2]
    // );
    match id {
        SYSCALL_READ => flow::syscall_read(args[0], args[1] as *mut u8, args[2]),
        SYSCALL_WRITE => flow::syscall_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_FORTEST => flow::syscall_fortest(args[0], args[1]),
        SYSCALL_YIELD => flow::syscall_yield(),
        SYSCALL_WAITPID => process::syscall_waitpid(args[0] as isize, args[1] as *mut i32),
        SYSCALL_EXEC => process::syscall_exec(args[0]),
        SYSCALL_FORK => process::syscall_fork(),
        SYSCALL_OPEN => filesystem::syscall_open(args[0], args[1], args[2]),

        SYSCALL_CLOSE => filesystem::syscall_close(args[0]),
        SYSCALL_PIPE => filesystem::syscall_pipe(args[0] as *mut usize),

        _ => {
            panic!(
                "Unknown syscall id: {},with args: {},{},{}",
                id, args[0], args[1], args[2]
            );
        }
    }
}
