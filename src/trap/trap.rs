use core::arch::global_asm;

use crate::trap::context::TrapContext;

global_asm!(include_str!("trap.asm"));

unsafe extern "C" {
    pub fn alltraps();
    pub fn restore(TrapContextPtr: *const TrapContext) -> !;
}
