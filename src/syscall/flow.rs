use crate::{
    mm::translated_byte_buffer,
    print, println,
    task::processor::{exit_current_and_run_next, suspend_current_and_run_next},
    trap::get_current_token,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: usize,
    len: usize,
}

pub fn syscall_read(_fd: usize, buf: *mut u8, len: usize) -> isize {
    // use get char to get stdin 0
    match _fd {
        0 => {
            if len != 1 {
                panic!("sys_read only support len = 1 now!");
            }
            let c = crate::sbi::console_getchar();
            // SBI returns usize::MAX when no char is available; report 0 bytes read.
            if c == usize::MAX {
                return 0;
            }
            let mut buffers = translated_byte_buffer(get_current_token(), buf, len);
            buffers[0][0] = c as u8;
            1
        }
        file_fd => super::filesystem::syscall_read(file_fd, buf as usize, len),
    }
}
const FD_STDOUT: usize = 1;
pub fn syscall_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let buffers = translated_byte_buffer(get_current_token(), buf, len);
            for buffer in buffers {
                for &b in buffer.iter() {
                    crate::sbi::console_putchar(b as usize);
                }
            }
            len as isize
        }
        file_fd => super::filesystem::syscall_write(file_fd, buf as usize, len),
    }
}

pub fn syscall_writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    let token = get_current_token();
    let iov_size = core::mem::size_of::<IoVec>();
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iv = *crate::mm::translated_mutref(token, (iov_ptr + i * iov_size) as *mut IoVec);
        if iv.len == 0 {
            continue;
        }
        let n = syscall_write(fd, iv.base as *const u8, iv.len);
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if n as usize != iv.len {
            break;
        }
    }
    total
}

pub fn syscall_readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    let token = get_current_token();
    let iov_size = core::mem::size_of::<IoVec>();
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let iv = *crate::mm::translated_mutref(token, (iov_ptr + i * iov_size) as *mut IoVec);
        if iv.len == 0 {
            continue;
        }
        let n = syscall_read(fd, iv.base as *mut u8, iv.len);
        if n < 0 {
            return if total > 0 { total } else { n };
        }
        total += n;
        if n as usize != iv.len {
            break;
        }
    }
    total
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
pub fn syscall_get_time() -> isize {
    crate::time::get_time_ms() as isize
}
