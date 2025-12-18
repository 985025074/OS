use crate::sbi::console_putchar;
use core::fmt::{self, Write};
use riscv::register::sstatus;
use spin::Mutex;

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            // QEMU's UART expects CRLF for proper newlines.
            if c == '\n' {
                console_putchar('\r' as usize);
            }
            console_putchar(c as usize);
        }
        Ok(())
    }
}

static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

pub fn print(args: fmt::Arguments) {
    // Make console output readable under SMP:
    // - Serialize writers across harts.
    // - Disable interrupts to avoid deadlocking on re-entrant printing (e.g. timer IRQ).
    let prev_sie = sstatus::read().sie();
    unsafe { sstatus::clear_sie() };
    {
        let _guard = CONSOLE_LOCK.lock();
        Stdout.write_fmt(args).unwrap();
    }
    if prev_sie {
        unsafe { sstatus::set_sie() };
    }
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
