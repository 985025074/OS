#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapContext {
    // general purpose registers
    pub x: [usize; 32],
    // where it is from?
    pub sstatus: Sstatus,
    // the next pc to run
    pub sepc: usize,
}
use core::fmt::Display;

use riscv::register::sstatus::{self, SPP, Sstatus};

impl TrapContext {
    /// set stack pointer to x_2 reg (sp)
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    /// init app context
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read(); // CSR sstatus
        sstatus.set_spp(SPP::User); //previous privilege mode: user mode
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry, // entry point of app
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
}

impl Display for TrapContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TrapContext {{ ")?;
        for i in 0..32 {
            write!(f, "x[{}]: {:#x}, ", i, self.x[i])?;
        }
        write!(
            f,
            "sstatus: {:#x}, sepc: {:#x} }}",
            self.sstatus.bits(),
            self.sepc
        )
    }
}
