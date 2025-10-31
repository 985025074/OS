use super::pid;
use crate::{
    config::kernel_stack_position,
    mm::{KERNEL_SPACE, MapPermission, VirtAddr},
    task::pid::Pid,
};
pub struct KernelStack {
    pid: usize,
    pub kernel_stack_top: usize,
    pub kernel_stack_bottom: usize,
}
impl KernelStack {
    pub fn new(pid: usize) -> Self {
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(pid);
        KERNEL_SPACE.borrow_mut().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );
        Self {
            pid: pid,
            kernel_stack_top,
            kernel_stack_bottom,
        }
    }
    pub fn get_bottom_and_top(&self) -> (usize, usize) {
        let (bottom, top) = kernel_stack_position(self.pid);
        return (bottom, top);
    }
}
// todo ...
impl Drop for KernelStack {
    // bottom is smaller ?
    fn drop(&mut self) {
        KERNEL_SPACE.borrow_mut().remove_area(
            VirtAddr::from(self.kernel_stack_bottom),
            VirtAddr::from(self.kernel_stack_top),
        );
    }
}
