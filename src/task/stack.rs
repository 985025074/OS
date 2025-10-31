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
}
