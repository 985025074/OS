use core::mem::size_of;

use crate::{
    fs::make_socketpair,
    mm::translated_mutref,
    task::processor::current_process,
    trap::get_current_token,
};

// Linux errno (negative return in kernel ABI).
const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;

const AF_UNIX: usize = 1;
const SOCK_STREAM: usize = 1;
const SOCK_TYPE_MASK: usize = 0xf;

/// Linux `socketpair(2)` (syscall 199 on riscv64).
///
/// Minimal support for `AF_UNIX` + `SOCK_STREAM`, sufficient for rt-tests `hackbench`.
pub fn syscall_socketpair(domain: usize, type_: usize, protocol: usize, sv_ptr: usize) -> isize {
    if sv_ptr == 0 {
        return EFAULT;
    }
    if domain != AF_UNIX {
        return EAFNOSUPPORT;
    }
    if protocol != 0 {
        return EPROTONOSUPPORT;
    }
    let sock_type = type_ & SOCK_TYPE_MASK;
    if sock_type != SOCK_STREAM {
        return EINVAL;
    }

    let (end0, end1) = make_socketpair();

    let process = current_process();
    let token = get_current_token();
    let mut inner = process.borrow_mut();
    let fd0 = inner.alloc_fd();
    inner.fd_table[fd0] = Some(end0);
    let fd1 = inner.alloc_fd();
    inner.fd_table[fd1] = Some(end1);
    drop(inner);

    // ABI: `int sv[2]` (i32).
    let p0 = translated_mutref(token, sv_ptr as *mut i32);
    let p1 = translated_mutref(token, (sv_ptr + size_of::<i32>()) as *mut i32);
    *p0 = fd0 as i32;
    *p1 = fd1 as i32;
    0
}

