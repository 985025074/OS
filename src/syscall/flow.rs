use crate::{print, println, task::load_next_task};

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
    load_next_task();
    return 0;
}
// the below one is just for testing
pub fn syscall_fortest(a: usize, b: usize) -> isize {
    println!("[kernel] syscall_fortest called with args: {}, {}", a, b);
    0
}
