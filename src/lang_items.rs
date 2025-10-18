use core::panic::PanicInfo;

#[panic_handler]
#[allow(unused)]
fn panic<'b>(info: &PanicInfo<'b>) -> ! {
    loop {}
}
