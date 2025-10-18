.section .text.entry
.globl _start
_start:
    la sp,boot_stack_top 
    call rust_main
.section .bss.stack
boot_stack_top:
    .space 4096*16
boot_stack_bottom:

