use crate::{
    mm::translated_mutref,
    task::processor::{current_process, current_task},
    trap::get_current_token,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

fn write_cstr(dst: &mut [u8; 65], s: &str) {
    dst.fill(0);
    let bytes = s.as_bytes();
    let n = bytes.len().min(64);
    dst[..n].copy_from_slice(&bytes[..n]);
}

pub fn syscall_uname(buf: usize) -> isize {
    if buf == 0 {
        return -1;
    }
    let mut un = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_cstr(&mut un.sysname, "CongCore");
    write_cstr(&mut un.nodename, "localhost");
    // glibc/busybox may abort early if the reported kernel release is "too old".
    // Report a modern Linux-like release string for compatibility.
    write_cstr(&mut un.release, "5.15.0");
    write_cstr(&mut un.version, "CongCore");
    write_cstr(&mut un.machine, "riscv64");
    write_cstr(&mut un.domainname, "localdomain");

    let token = get_current_token();
    *translated_mutref(token, buf as *mut UtsName) = un;
    0
}

pub fn syscall_mount(
    _special: usize,
    _dir: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    0
}

pub fn syscall_umount2(_special: usize, _flags: usize) -> isize {
    0
}

pub fn syscall_getppid() -> isize {
    let process = current_process();
    let parent = { process.borrow_mut().parent.as_ref().and_then(|p| p.upgrade()) };
    parent.map(|p| p.getpid() as isize).unwrap_or(0)
}

/// Linux `set_tid_address(2)` (syscall 96 on riscv64).
///
/// We currently run a single-threaded process model for glibc apps; we accept the
/// pointer and return a Linux-like TID (use PID as TID).
pub fn syscall_set_tid_address(_tidptr: usize) -> isize {
    let task = current_task().unwrap();
    if _tidptr != 0 {
        let mut inner = task.borrow_mut();
        inner.clear_child_tid = Some(_tidptr);
    }
    task.borrow_mut().res.as_ref().unwrap().tid as isize
}

pub fn syscall_getuid() -> isize {
    0
}
pub fn syscall_geteuid() -> isize {
    0
}
pub fn syscall_getgid() -> isize {
    0
}
pub fn syscall_getegid() -> isize {
    0
}

/// Linux `gettid(2)` (syscall 178 on riscv64).
pub fn syscall_gettid_linux() -> isize {
    current_task().unwrap().borrow_mut().res.as_ref().unwrap().tid as isize
}

/// Linux `set_robust_list(2)` (syscall 99 on riscv64).
///
/// glibc uses this for mutex robustness; we don't implement robust futexes yet,
/// but returning success keeps single-threaded apps progressing.
pub fn syscall_set_robust_list(_head: usize, _len: usize) -> isize {
    0
}
