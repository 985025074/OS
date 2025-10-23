use core::arch::global_asm;

use riscv::register::sie;

use crate::trap::context::TrapContext;

global_asm!(include_str!("trap.asm"));

unsafe extern "C" {
    pub fn alltraps();
    pub fn restore(TrapContextPtr: *const TrapContext) -> !;
}
/// timer interrupt enabled
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}
