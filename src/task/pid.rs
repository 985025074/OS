use alloc::vec::Vec;
use lazy_static::lazy_static;

use crate::utils::RefCellSafe;

pub struct Pid(pub usize);
pub struct PidAllocator {
    recycle: Vec<usize>,
    next: usize,
}
impl PidAllocator {
    fn new() -> Self {
        Self {
            recycle: Vec::new(),
            next: 0,
        }
    }
    fn alloc(&mut self) -> Pid {
        if let Some(pid) = self.recycle.pop() {
            Pid(pid)
        } else {
            let pid = self.next;
            self.next += 1;
            Pid(pid)
        }
    }
    fn dealloc(&mut self, pid: Pid) {
        self.recycle.push(pid.0);
    }
}

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref PID_ALLOCATOR: RefCellSafe<PidAllocator> =
        unsafe { RefCellSafe::new(PidAllocator::new()) };
}
pub fn alloc_pid() -> Pid {
    PID_ALLOCATOR.borrow_mut().alloc()
}
pub fn dealloc_pid(pid: Pid) {
    PID_ALLOCATOR.borrow_mut().dealloc(pid);
}
impl Drop for Pid {
    fn drop(&mut self) {
        dealloc_pid(Pid(self.0));
    }
}
