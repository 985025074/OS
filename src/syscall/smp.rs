pub fn sys_get_hartid() -> isize {
    let id: usize;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) id);
    }
    id as isize
}
