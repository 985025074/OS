use crate::{
    mm::translated_byte_buffer,
    print, println,
    task::processor::{exit_current_and_run_next, suspend_current_and_run_next},
    trap::get_current_token,
};
pub fn syscall_read(_fd: usize, buf: *mut u8, len: usize) -> isize {
    // use get char to get stdin 0
    match _fd {
        0 => {
            if len != 1 {
                panic!("sys_read only support len = 1 now!");
            }
            let c = crate::sbi::console_getchar();
            let mut buffers = translated_byte_buffer(get_current_token(), buf, len);
            buffers[0][0] = c as u8;
            1
        }
        _ => {
            panic!("Unsupported fd in sys_read!");
        }
    }
}
const FD_STDOUT: usize = 1;
pub fn syscall_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let buffers = translated_byte_buffer(get_current_token(), buf, len);
            for buffer in buffers {
                print!("{}", core::str::from_utf8(buffer).unwrap());
            }
            len as isize
        }
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}
pub fn syscall_exit(_code: usize) -> isize {
    exit_current_and_run_next(_code as i32);
    return 0;
}
// the below one is just for testing
pub fn syscall_fortest(a: usize, b: usize) -> isize {
    println!("[kernel] syscall_fortest called with args: {}, {}", a, b);
    0
}
pub fn syscall_yield() -> isize {
    suspend_current_and_run_next();
    0
}
