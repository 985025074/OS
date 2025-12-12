//! Implementation of [`TrapContext`]

use riscv::register::sstatus::{self, SPP, Sstatus};

#[derive(Clone, Copy)]
#[repr(C)]
/// trap context structure containing sstatus, sepc and registers
pub struct TrapContext {
    /// general regs[0..31]
    pub x: [usize; 32],
    /// CSR sstatus      
    pub sstatus: Sstatus,
    /// CSR sepc
    pub sepc: usize,
    /// Addr of Page Table
    pub kernel_satp: usize,
    /// kernel stack
    pub kernel_sp: usize,
    /// Addr of trap_handler function
    pub trap_handler: usize,
}

impl TrapContext {
    /// set stack pointer to x_2 reg (sp)
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    /// init app context
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_satp: usize,
        kernel_sp: usize,
        trap_handler: usize,
    ) -> Self {
        let mut sstatus = sstatus::read(); // CSR sstatus
        sstatus.set_spp(SPP::User); //previous privilege mode: user mode
        // Enable interrupts when we enter user mode for the first time.
        // Without setting SPIE, S-mode interrupts (timer) stay disabled in U-mode,
        // so sleeping tasks would never be woken if another runnable task spins.
        sstatus.set_spie(true);
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,  // entry point of app
            kernel_satp,  // addr of page table
            kernel_sp,    // kernel stack
            trap_handler, // addr of trap_handler function
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
}
pub fn push_trap_context_at(dst: usize, cx: &TrapContext) {
    unsafe {
        let dst_ptr = dst as *mut TrapContext;
        *dst_ptr = *cx;
    }
}
