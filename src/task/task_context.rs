use core::{fmt::Display, ptr::write};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TaskContext {
    pub ra: usize,
    pub sp: usize,
    pub s: [usize; 12],
}
impl TaskContext {
    pub fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }
    pub fn set_for_app(ra: usize, kernel_sp: usize) -> Self {
        return Self {
            ra,
            sp: kernel_sp,
            s: [0; 12],
        };
    }
}
impl Display for TaskContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TaskContext {{ ra: {:#x}, sp: {:#x} }}",
            self.ra, self.sp
        );
        // println the s registers too?
        for (i, reg) in self.s.iter().enumerate() {
            write!(f, ", s{}: {:#x}", i, reg)?;
        }
        write!(f, "\n")?;
        // ok next print the first 34 bytes of the sp,i need better format!
        for i in 0..34 {
            let ptr = (self.sp + i * 8) as *const usize;
            let val = unsafe { *ptr };
            write!(f, ", [sp+{}]: {:#x}", i * 8, val)?;
        }
        return Ok(());
    }
}
