//! RISC-V timer-related functionality

pub const CLOCK_FREQ: usize = 12500000;
use crate::sbi::set_timer;
use riscv::register::time;

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

/// read the `mtime` register
pub fn get_time() -> usize {
    time::read()
}

/// get current time in milliseconds
pub fn get_time_ms() -> usize {
    time::read() / (CLOCK_FREQ / MSEC_PER_SEC)
}

/// set the next timer interrupt
pub fn set_next_trigger() {
    let next = get_time() + CLOCK_FREQ / TICKS_PER_SEC;
    // Log only the first couple of times per hart to avoid spam.
    static SET_COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let c = SET_COUNTER.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    if c < 4 {
        let hart: usize;
        unsafe { core::arch::asm!("mv {}, tp", out(reg) hart) };
        // Safety: console is async-safe in this kernel.
        crate::println!(
            "[time] hart={} set_next_trigger -> {:#x} (now={:#x})",
            hart,
            next,
            get_time()
        );
    }
    set_timer(next);
}
