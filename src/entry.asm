.section .text.entry
.globl _start
_start:
    # a0: hart id, a1: dtb / opaque
    li t0, 4096 * 16          # per-hart stack size (64KiB)
    la sp, boot_stack_top
    mul t0, t0, a0
    sub sp, sp, t0            # pick stack slice for this hart
    mv tp, a0                 # stash hart id in tp for S-mode use
    call rust_main
.section .bss.stack
boot_stack_top:
    .space 4096*64
boot_stack_bottom:
