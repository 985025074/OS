.section .rodata
.align 3
app_0_name:
    .asciz "00shell"
.align 3
.section .data
app_0_start:
    .incbin "./results/00shell.bin"
.align 3
app_0_end:
.section .rodata
.align 3
app_1_name:
    .asciz "02helloqiukaiyu"
.align 3
.section .data
app_1_start:
    .incbin "./results/02helloqiukaiyu.bin"
.align 3
app_1_end:
.section .rodata
.align 3
app_2_name:
    .asciz "03syscall_test"
.align 3
.section .data
app_2_start:
    .incbin "./results/03syscall_test.bin"
.align 3
app_2_end:
.section .rodata
.align 3
app_3_name:
    .asciz "04test"
.align 3
.section .data
app_3_start:
    .incbin "./results/04test.bin"
.align 3
app_3_end:
.section .rodata
.align 3
app_4_name:
    .asciz "05"
.align 3
.section .data
app_4_start:
    .incbin "./results/05.bin"
.align 3
app_4_end:
.section .rodata
.align 3
app_5_name:
    .asciz "06"
.align 3
.section .data
app_5_start:
    .incbin "./results/06.bin"
.align 3
app_5_end:
.section .rodata
.align 3
app_6_name:
    .asciz "07"
.align 3
.section .data
app_6_start:
    .incbin "./results/07.bin"
.align 3
app_6_end:
.section .rodata
.align 3
app_7_name:
    .asciz "123"
.align 3
.section .data
app_7_start:
    .incbin "./results/123.bin"
.align 3
app_7_end:
.section .rodata
.align 3
app_8_name:
    .asciz "all_tests"
.align 3
.section .data
app_8_start:
    .incbin "./results/all_tests.bin"
.align 3
app_8_end:
.section .rodata
.align 3
app_9_name:
    .asciz "init_proc"
.align 3
.section .data
app_9_start:
    .incbin "./results/init_proc.bin"
.align 3
app_9_end:
.section .rodata
.align 3
app_10_name:
    .asciz "pipe_test"
.align 3
.section .data
app_10_start:
    .incbin "./results/pipe_test.bin"
.align 3
app_10_end:
.section .rodata
.align 3
app_11_name:
    .asciz "fork_no_wait"
.align 3
.section .data
app_11_start:
    .incbin "./results/fork_no_wait.bin"
.align 3
app_11_end:
.section .rodata
.align 3
    .global num_user_apps
num_user_apps:
    .quad 12
    .quad app_0_start
    .quad app_0_end
    .quad app_0_name
    .quad app_1_start
    .quad app_1_end
    .quad app_1_name
    .quad app_2_start
    .quad app_2_end
    .quad app_2_name
    .quad app_3_start
    .quad app_3_end
    .quad app_3_name
    .quad app_4_start
    .quad app_4_end
    .quad app_4_name
    .quad app_5_start
    .quad app_5_end
    .quad app_5_name
    .quad app_6_start
    .quad app_6_end
    .quad app_6_name
    .quad app_7_start
    .quad app_7_end
    .quad app_7_name
    .quad app_8_start
    .quad app_8_end
    .quad app_8_name
    .quad app_9_start
    .quad app_9_end
    .quad app_9_name
    .quad app_10_start
    .quad app_10_end
    .quad app_10_name
    .quad app_11_start
    .quad app_11_end
    .quad app_11_name
