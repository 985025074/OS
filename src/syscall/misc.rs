use crate::{
    mm::translated_mutref,
    task::processor::current_process,
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
    write_cstr(&mut un.release, "0.1");
    write_cstr(&mut un.version, "0.1");
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

