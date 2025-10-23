use crate::{
    print, println,
    task::{exit_and_go_to_next, go_to_next_task, suspend_and_go_to_next},
};

pub fn syscall_write(_fd: usize, _buf: usize, _len: usize) -> isize {
    if _fd == 1 {
        //stdout
        let slice = unsafe { core::slice::from_raw_parts(_buf as *const u8, _len) };
        if let Ok(s) = core::str::from_utf8(slice) {
            print!("{}", s);
            return _len as isize;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}
pub fn syscall_exit(_code: usize) -> isize {
    exit_and_go_to_next();
    return 0;
}
// the below one is just for testing
pub fn syscall_fortest(a: usize, b: usize) -> isize {
    println!("[kernel] syscall_fortest called with args: {}, {}", a, b);
    0
}
pub fn syscall_yield() -> isize {
    suspend_and_go_to_next();
    0
}
