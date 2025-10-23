use crate::trap::context::TrapContext;
pub const STACK_SIZE: usize = 4096 * 2;
#[derive(Copy, Clone)]
#[repr(align(4096))]
pub struct Stack {
    pub data: [u8; STACK_SIZE],
}
impl Stack {
    pub fn top(&self) -> usize {
        self.data.as_ptr() as usize + STACK_SIZE
    }
    pub fn push_trap_context(&self, trap_context: TrapContext) -> usize {
        let ptr = (self.top() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            ptr.copy_from(&trap_context, 1);
        }
        ptr as usize
    }
}
