#![no_std]
#![no_main]

use core::arch::global_asm;

mod lang_items;
mod sbi;
global_asm!(include_str!("entry.asm"));
#[unsafe(no_mangle)]
fn rust_main() {
    sbi::console_putchar('H' as usize);
}
