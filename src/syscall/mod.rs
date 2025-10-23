use core::panic;

use crate::println;

mod flow;

pub const SYSCALL_WRITE: usize = 64;
pub const SYSCALL_EXIT: usize = 93;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_GET_TIME: usize = 169;
pub const SYSCALL_FORTEST: usize = 1000;
pub fn syscall(id: usize, args: [usize; 3]) -> isize {
    // println!(
    //     "syscall id: {}, args: {},{},{}",
    //     id, args[0], args[1], args[2]
    // );
    match id {
        SYSCALL_WRITE => flow::syscall_write(args[0], args[1], args[2]),
        SYSCALL_EXIT => flow::syscall_exit(args[0]),
        SYSCALL_FORTEST => flow::syscall_fortest(args[0], args[1]),
        SYSCALL_YIELD => flow::syscall_yield(),
        _ => {
            panic!(
                "Unknown syscall id: {},with args: {},{},{}",
                id, args[0], args[1], args[2]
            );
        }
    }
}
